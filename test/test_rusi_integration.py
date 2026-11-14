"""Integration tests for rusi-powered Rust reachability.

These tests exercise the full adapter pipeline (binary discovery -> rusi run ->
report -> atom-slice converter -> FrameworkReachability) against real, tiny
Rust repositories checked in under ``test/data/rusi/repos/``:

  - ``reachable-app``: calls the external ``sqlx`` crate on a tainted
    file -> sql-query path. The reconciled ``pkg:cargo/sqlx@<v>`` MUST appear
    in ``reached_purls``.
  - ``unreachable-app``: the Cargo BOM lists ``sqlx`` as a dependency but the
    source never calls it. ``pkg:cargo/sqlx@<v>`` MUST NOT appear in
    ``reached_purls``.

Also covers:
  - determinism (rusi is byte-reproducible; two runs produce identical slices).
  - graceful degradation (no rusi binary -> warn + skip, never crash).

These tests require the rusi binary. They are skipped when it is not
discoverable (``DEPSCAN_RUSI_BINARY`` env or PATH) so CI without the binary
does not fail. The dev binary at
``thirdparty/rusi/target/release/rusi`` is auto-used when present.
"""

import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from analysis_lib import ReachabilityAnalysisKV
from analysis_lib.reachability import FrameworkReachability
from depscan.lib.bom import run_rusi_reachability
from xbom_lib import rusi as rusi_mod

REPO_ROOT = Path(__file__).resolve().parent.parent
RUSI_REPOS = REPO_ROOT / "test" / "data" / "rusi" / "repos"


def _resolve_rusi_binary():
    """Return the rusi binary path to use for this test run, or None.

    Resolution order: ``DEPSCAN_RUSI_BINARY`` env -> ``shutil.which("rusi")``.
    No hardcoded dev path: CI and local runs set the env var (or put rusi on
    PATH), and the suite skips cleanly when neither is present.
    """
    if os.environ.get(rusi_mod.RUSI_BINARY_ENV):
        return os.environ[rusi_mod.RUSI_BINARY_ENV]
    which = shutil.which("rusi")
    if which:
        return which
    return None


def _resolve_rusi_fixture():
    """Return the rusi ``vulnerable-web-app`` fixture dir, or None.

    Resolution order: ``DEPSCAN_RUSI_FIXTURE_DIR`` env -> derived from the
    resolved binary path when it is a dev build
    (``.../rusi/target/<profile>/rusi`` -> ``.../rusi/fixtures/vulnerable-web-app``).
    Returns None when neither applies; the smoke test then skips.
    """
    env_dir = os.environ.get("DEPSCAN_RUSI_FIXTURE_DIR", "").strip()
    if env_dir:
        return Path(env_dir)
    if RUSI_BIN:
        binary = Path(RUSI_BIN)
        # dev build layout: .../rusi/target/<profile>/rusi
        if binary.parent.name in ("release", "debug") and binary.parent.parent.name == "target":
            candidate = binary.parent.parent.parent / "fixtures" / "vulnerable-web-app"
            if candidate.is_dir():
                return candidate
    return None


RUSI_BIN = _resolve_rusi_binary()
pytestmark = pytest.mark.skipif(
    RUSI_BIN is None,
    reason="rusi binary not found (set DEPSCAN_RUSI_BINARY or install cdxgen-plugins-bin)",
)
RUSI_FIXTURE = _resolve_rusi_fixture()


@pytest.fixture
def rusi_env(monkeypatch):
    """Force ``find_rusi_binary`` to the resolved binary for this run."""
    monkeypatch.setenv(rusi_mod.RUSI_BINARY_ENV, RUSI_BIN)
    yield


def _write_cargo_bom(bom_file: Path, app_name: str, app_version: str = "0.1.0"):
    """Write a minimal Cargo BOM mirroring cdxgen output.

    The integration repos use symbolic external calls (no real crates.io deps)
    so the BOM is synthetic but realistic: an application root + the external
    crates the source calls, each with a versioned purl that the converter
    must reconcile onto.
    """
    components = [
        {
            "type": "application",
            "name": app_name,
            "version": app_version,
            "purl": f"pkg:cargo/{app_name}@{app_version}",
        },
        {
            "type": "library",
            "name": "sqlx",
            "version": "0.6.2",
            "purl": "pkg:cargo/sqlx@0.6.2",
        },
    ]
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"component": components[0]},
        "components": components,
    }
    bom_file.write_text(json.dumps(bom), encoding="utf-8")
    return str(bom_file)


def _reached_purls(bom_dir: Path) -> set:
    opts = ReachabilityAnalysisKV(
        project_types=["rust"], src_dir=str(bom_dir), bom_dir=str(bom_dir)
    )
    res = FrameworkReachability(opts).process()
    # success is False when BOTH direct_purls and reached_purls are empty (an
    # app with no reachable calls). That is a valid outcome for the
    # unreachable-app repo, so we do not assert success here -- we only care
    # about the reached SET.
    return set((res.reached_purls or {}).keys())


# ---------------------------------------------------------------------------
# primary path: consume the report cdxgen persists, WITHOUT spawning rusi
# ---------------------------------------------------------------------------


def test_consumes_cdxgen_semantics_report_without_spawning(tmp_path, rusi_env, monkeypatch):
    """depscan's primary path reads the raw rusi report cdxgen persists to
    ``<bomdir>/<type>-semantics.slices.json`` (under --profile research) and
    converts it -- with NO direct rusi invocation. Proves depscan need not run
    rusi itself when cdxgen + plugins are available.

    We first generate a real rusi report (as cdxgen would) into the semantics
    path, then force the rusi binary UNRESOLVABLE so any attempt to spawn would
    fail; reachability must still light up from the persisted report alone.
    """
    from xbom_lib import rusi as _rusi_mod

    bom_dir = tmp_path
    bom_file = bom_dir / "sbom-rust.cdx.json"
    _write_cargo_bom(bom_file, "reachable-app")
    src = RUSI_REPOS / "reachable-app"

    # Emulate cdxgen: persist the full raw rusi report to the semantics path.
    semantics_path = bom_dir / "rust-semantics.slices.json"
    res = _rusi_mod.run_rusi(str(src), str(semantics_path), logger=None)
    assert res.success and semantics_path.exists(), "setup: rusi report must be produced"

    # Now make the binary unresolvable so the fallback CANNOT run rusi.
    monkeypatch.setattr(_rusi_mod, "find_rusi_binary", lambda logger=None: None)

    ok = run_rusi_reachability(
        str(bom_file),
        str(src),
        options={
            "project_type": ["rust"],
            "reachability_analyzer": "FrameworkReachability",
        },
    )
    assert ok, "must consume the cdxgen-produced semantics report without spawning rusi"

    reached = _reached_purls(bom_dir)
    assert "pkg:cargo/sqlx@0.6.2" in reached
    assert "pkg:cargo/reachable-app@0.1.0" in reached


# ---------------------------------------------------------------------------
# (a) reachable-app
# ---------------------------------------------------------------------------


def test_reachable_app_marks_sqlx_reached(tmp_path, rusi_env):
    """A tainted file -> sqlx::query path must reconcile sqlx onto the BOM and
    mark ``pkg:cargo/sqlx@0.6.2`` as reached."""
    bom_file = tmp_path / "sbom-rust.cdx.json"
    _write_cargo_bom(bom_file, "reachable-app")
    src = RUSI_REPOS / "reachable-app"

    ok = run_rusi_reachability(
        str(bom_file),
        str(src),
        options={
            "project_type": ["rust"],
            "reachability_analyzer": "FrameworkReachability",
        },
    )
    assert ok, "rusi reachability should have run"

    slice_file = tmp_path / "rust-reachables.slices.json"
    assert slice_file.exists(), "slice file must be emitted next to the BOM"
    flows = json.loads(slice_file.read_text())
    assert flows, "at least one flow expected for a tainted call"

    reached = _reached_purls(tmp_path)
    assert "pkg:cargo/sqlx@0.6.2" in reached, (
        "sqlx MUST be reached when the app calls sqlx::query on a tainted path"
    )
    # the workspace app is on the path too
    assert "pkg:cargo/reachable-app@0.1.0" in reached


# ---------------------------------------------------------------------------
# (b) unreachable-app
# ---------------------------------------------------------------------------


def test_unreachable_app_does_not_mark_sqlx_reached(tmp_path, rusi_env):
    """Depending on sqlx in the BOM but never calling it MUST NOT mark it."""
    bom_file = tmp_path / "sbom-rust.cdx.json"
    _write_cargo_bom(bom_file, "unreachable-app")
    src = RUSI_REPOS / "unreachable-app"

    ok = run_rusi_reachability(
        str(bom_file),
        str(src),
        options={
            "project_type": ["rust"],
            "reachability_analyzer": "FrameworkReachability",
        },
    )
    # rusi will still run + emit a slice for the app's own code; we just assert
    # sqlx is NOT among the reached purls.
    assert ok, "rusi reachability should still run (the project is rust)"

    reached = _reached_purls(tmp_path)
    assert "pkg:cargo/sqlx@0.6.2" not in reached, (
        "sqlx MUST NOT be reached when the app only depends on it without calling"
    )


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------


def test_rusi_slice_is_deterministic(tmp_path, rusi_env):
    """Two independent rusi runs on the same repo produce byte-identical slices.

    rusi is documented as byte-reproducible (sorted collections); the converter
    sorts purls + flows, so the emitted slice file must be stable.
    """
    src = RUSI_REPOS / "reachable-app"

    def _run_once(work_dir: Path) -> str:
        bom_file = work_dir / "sbom-rust.cdx.json"
        _write_cargo_bom(bom_file, "reachable-app")
        assert run_rusi_reachability(
            str(bom_file),
            str(src),
            options={
                "project_type": ["rust"],
                "reachability_analyzer": "FrameworkReachability",
            },
        )
        return (work_dir / "rust-reachables.slices.json").read_text()

    d1 = tmp_path / "d1"
    d2 = tmp_path / "d2"
    d1.mkdir()
    d2.mkdir()
    s1 = _run_once(d1)
    s2 = _run_once(d2)
    assert s1 == s2, "rusi slice output must be deterministic across runs"


# ---------------------------------------------------------------------------
# graceful degradation
# ---------------------------------------------------------------------------


def test_rusi_reachability_skips_when_binary_missing(tmp_path, monkeypatch):
    """When the rusi binary cannot be found, run_rusi_reachability must return
    False (not crash) and leave no slice file behind."""
    # force resolution to fail on all paths
    monkeypatch.setattr(rusi_mod, "find_rusi_binary", lambda logger=None: None)
    bom_file = tmp_path / "sbom-rust.cdx.json"
    _write_cargo_bom(bom_file, "reachable-app")
    src = RUSI_REPOS / "reachable-app"

    result = run_rusi_reachability(
        str(bom_file),
        str(src),
        options={
            "project_type": ["rust"],
            "reachability_analyzer": "FrameworkReachability",
        },
    )
    assert result is False
    assert not (tmp_path / "rust-reachables.slices.json").exists()


def test_rusi_reachability_noop_for_non_rust(tmp_path, rusi_env):
    """Non-rust project types are a no-op even when the binary IS present."""
    bom_file = tmp_path / "sbom-js.cdx.json"
    bom_file.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": [
                    {"type": "library", "name": "express", "purl": "pkg:npm/express@4.22.2"}
                ],
            }
        ),
        encoding="utf-8",
    )
    result = run_rusi_reachability(
        str(bom_file),
        str(tmp_path),
        options={"project_type": ["js"], "reachability_analyzer": "FrameworkReachability"},
    )
    assert result is False
    assert not (tmp_path / "rust-reachables.slices.json").exists()


def test_rusi_reachability_noop_when_reachability_off(tmp_path, rusi_env):
    """Reachability off -> no rusi run even for rust."""
    bom_file = tmp_path / "sbom-rust.cdx.json"
    _write_cargo_bom(bom_file, "reachable-app")
    src = RUSI_REPOS / "reachable-app"
    result = run_rusi_reachability(
        str(bom_file),
        str(src),
        options={"project_type": ["rust"], "reachability_analyzer": "off"},
    )
    assert result is False


def test_rusi_reachability_accepts_cargo_alias(tmp_path, rusi_env):
    """The ``cargo``/``crates`` project-type aliases must trigger rusi just like
    the canonical ``rust`` token, so an alternate label never silently skips
    Rust reachability."""
    bom_file = tmp_path / "sbom-rust.cdx.json"
    _write_cargo_bom(bom_file, "reachable-app")
    src = RUSI_REPOS / "reachable-app"
    ok = run_rusi_reachability(
        str(bom_file),
        str(src),
        options={
            "project_type": ["cargo"],
            "reachability_analyzer": "FrameworkReachability",
        },
    )
    assert ok, "rusi reachability should run for the 'cargo' project-type alias"
    assert (tmp_path / "rust-reachables.slices.json").exists()


# ---------------------------------------------------------------------------
# smoke test against rusi's own vulnerable-web-app fixture
# ---------------------------------------------------------------------------


def test_smoke_rusi_vulnerable_web_app_fixture(tmp_path, rusi_env):
    """Smoke test against rusi's own fixtures/vulnerable-web-app.

    Its deps are symbolic (no real Cargo.lock versions), which is the exact
    scenario the unversioned-purl reconciler was built for: rusi emits
    ``pkg:cargo/sqlx`` (unversioned) and the converter must map it onto the
    versioned BOM purl.
    """
    if not RUSI_FIXTURE or not RUSI_FIXTURE.is_dir():
        pytest.skip("rusi vulnerable-web-app fixture not available")
    bom_file = tmp_path / "sbom-rust.cdx.json"
    # synthetic BOM: workspace + the three external crates the fixture calls
    components = [
        {
            "type": "application",
            "name": "vulnerable-web-app",
            "version": "0.1.0",
            "purl": "pkg:cargo/vulnerable-web-app@0.1.0",
        },
        {"type": "library", "name": "sqlx", "version": "0.6.2", "purl": "pkg:cargo/sqlx@0.6.2"},
        {"type": "library", "name": "warp", "version": "0.3.6", "purl": "pkg:cargo/warp@0.3.6"},
        {
            "type": "library",
            "name": "reqwest",
            "version": "0.11.27",
            "purl": "pkg:cargo/reqwest@0.11.27",
        },
    ]
    bom_file.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "metadata": {"component": components[0]},
                "components": components,
            }
        ),
        encoding="utf-8",
    )

    ok = run_rusi_reachability(
        str(bom_file),
        str(RUSI_FIXTURE),
        options={
            "project_type": ["rust"],
            "reachability_analyzer": "FrameworkReachability",
        },
    )
    assert ok

    reached = _reached_purls(tmp_path)
    # all three external crates must reconcile + light up
    assert "pkg:cargo/sqlx@0.6.2" in reached
    assert "pkg:cargo/warp@0.3.6" in reached
    assert "pkg:cargo/reqwest@0.11.27" in reached
    # stdlib fs must NOT leak
    assert not any(p.startswith("pkg:cargo/fs") for p in reached)


# ---------------------------------------------------------------------------
# Real RUSTSEC integration: slice -> reached_purls -> VDR insight (full loop)
# ---------------------------------------------------------------------------

RUSTSEC_APP = RUSI_REPOS / "rustsec-app"
# A committed CVE 5.2 fixture for RUSTSEC-2020-0071 carrying an exploit-db
# reference, used to exercise the "Reachable and Exploitable" insight arrow
# hermetically (no vdb download required).
RUSTSEC_TIME_VULN = REPO_ROOT / "test" / "data" / "rusi" / "rustsec-time-vuln.json"


def _write_rustsec_bom(bom_file: Path, app_name: str = "rustsec-app"):
    """BOM mirroring rustsec-app's Cargo.lock: app + time@0.1.45
    (RUSTSEC-2020-0071, called) + libc@0.2.189 (transitively present but NOT
    directly called by the app source, so it must NOT be reached)."""
    components = [
        {
            "type": "application",
            "name": app_name,
            "version": "0.1.0",
            "purl": f"pkg:cargo/{app_name}@0.1.0",
            "bom-ref": f"pkg:cargo/{app_name}@0.1.0",
        },
        {
            "type": "library",
            "name": "time",
            "version": "0.1.45",
            "purl": "pkg:cargo/time@0.1.45",
            "bom-ref": "pkg:cargo/time@0.1.45",
        },
        {
            "type": "library",
            "name": "libc",
            "version": "0.2.189",
            "purl": "pkg:cargo/libc@0.2.189",
            "bom-ref": "pkg:cargo/libc@0.2.189",
        },
    ]
    bom_file.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "metadata": {"component": components[0]},
                "components": components,
            }
        ),
        encoding="utf-8",
    )
    return str(bom_file)


def test_rustsec_time_reachable_in_vdr(tmp_path, rusi_env):
    """Full loop: rusi slice -> reached_purls -> VDR marks time Reachable.

    ``rustsec-app`` pins time 0.1.45 (RUSTSEC-2020-0071) and calls
    ``time::now()`` on a tainted path. The VDR produced by the real
    ``VDRAnalyzer`` (with the real vdb) MUST mark RUSTSEC-2020-0071
    ``Reachable`` for ``pkg:cargo/time@0.1.45``. ``libc`` is in the BOM
    (transitive dep) but never directly called, so it MUST NOT be reached.

    This is the phase-3 proof that the loop closes all the way to the VDR
    insight, which phase 1 only proved up to ``reached_purls``. Skipped when
    rusi cannot run (binary missing, or cargo cannot resolve ``time`` offline)
    or the vdb lacks RUSTSEC-2020-0071 data.
    """
    from analysis_lib import VdrAnalysisKV
    from analysis_lib.reachability import FrameworkReachability
    from analysis_lib.utils import get_pkg_list
    from analysis_lib.vdr import VDRAnalyzer

    bom_file = tmp_path / "sbom-rust.cdx.json"
    _write_rustsec_bom(bom_file)
    ok = run_rusi_reachability(
        str(bom_file),
        str(RUSTSEC_APP),
        options={
            "project_type": ["rust"],
            "reachability_analyzer": "FrameworkReachability",
        },
    )
    if not ok:
        pytest.skip(
            "rusi could not run on rustsec-app (binary missing or cargo cannot "
            "resolve 'time' offline)"
        )

    # --- slice -> reached_purls ---
    opts = ReachabilityAnalysisKV(
        project_types=["rust"], src_dir=str(tmp_path), bom_dir=str(tmp_path)
    )
    res = FrameworkReachability(opts).process()
    reached = dict(res.reached_purls or {})
    assert "pkg:cargo/time@0.1.45" in reached, (
        "time MUST be reached because the source calls time::now()"
    )
    assert not any(p.startswith("pkg:cargo/libc") for p in reached), (
        "libc is present-but-uncalled -> MUST NOT be reached"
    )

    # --- reached_purls -> VDR insight (real VDRAnalyzer + real vdb) ---
    pkg_list, _lifecycles = get_pkg_list(str(bom_file))
    vopts = VdrAnalysisKV(
        project_type="rust",
        init_results=[],
        pkg_aliases={},
        purl_aliases={},
        suggest_mode=False,
        scoped_pkgs={},
        no_vuln_table=True,
        bom_file=str(bom_file),
        pkg_list=pkg_list,
        reached_purls=reached,
    )
    vres = VDRAnalyzer(vdr_options=vopts).process()
    vulns = vres.pkg_vulnerabilities or []
    if not any(v.get("id") == "RUSTSEC-2020-0071" for v in vulns):
        pytest.skip(
            "vdb has no RUSTSEC-2020-0071 data cached; cannot assert the VDR "
            "insight without the vulnerability database"
        )
    time_vuln = next(v for v in vulns if v.get("id") == "RUSTSEC-2020-0071")
    affects = [a.get("ref") for a in (time_vuln.get("affects") or [])]
    assert "pkg:cargo/time@0.1.45" in affects, (
        "the VDR vulnerability must affect the versioned time purl"
    )
    insights = [
        p["value"]
        for p in (time_vuln.get("properties") or [])
        if p.get("name") == "depscan:insights"
    ]
    assert any("Reachable" in i for i in insights), (
        f"time must be Reachable in the VDR; got insights={insights}"
    )


def test_rustsec_exploitable_insight_gated_on_reached_purls():
    """The reached_purls -> VDR insight arrow, including the Exploitable
    variant, exercised through the REAL ``analyze_cve_vuln`` insight function
    used by the VDR pipeline.

    Uses the committed RUSTSEC-2020-0071 CVE fixture (which carries an
    exploit-db reference) so it is HERMETIC: no rusi binary and no vdb download
    are required. With the vulnerable purl in ``reached_purls`` the insight is
    ``Reachable and Exploitable``; with it absent the insight is ``Known
    Exploits`` (NOT Reachable), proving the insight is reachability-gated.
    """
    from types import SimpleNamespace

    from analysis_lib.utils import analyze_cve_vuln

    # vdb returns the CVE-5 record as a plain dict.
    cve_model = json.loads(RUSTSEC_TIME_VULN.read_text(encoding="utf-8"))

    def _counts():
        return SimpleNamespace(
            malicious_count=0,
            pkg_attention_count=0,
            fix_version_count=0,
            critical_count=0,
            has_reachable_poc_count=0,
            has_reachable_exploit_count=0,
            has_poc_count=0,
            has_exploit_count=0,
            wont_fix_version_count=0,
            distro_packages_count=0,
            has_os_packages=False,
            ids_seen={},
        )

    vuln = {
        "cve_id": "RUSTSEC-2020-0071",
        "matched_by": "pkg:cargo/time@0.1.45",
        "matching_vers": "(,0.2)",
        "purl_prefix": "pkg:cargo/time",
        "type": "cargo",
        "source_data": cve_model,
    }

    # reached -> "Reachable and Exploitable"
    _, vdict_reached, _, _ = analyze_cve_vuln(
        vuln,
        reached_purls={"pkg:cargo/time@0.1.45": 1},
        direct_purls={},
        reached_services={},
        endpoint_reached_purls={},
        optional_pkgs=[],
        required_pkgs=[],
        prebuild_purls={},
        build_purls={},
        postbuild_purls={},
        purl_identities={},
        bom_dependency_tree=[],
        counts=_counts(),
    )
    insights_reached = [
        p["value"]
        for p in (vdict_reached.get("properties") or [])
        if p.get("name") == "depscan:insights"
    ]
    assert any("Reachable and Exploitable" in i for i in insights_reached), (
        f"a reached vulnerable crate with an exploit ref must be Reachable and "
        f"Exploitable; got {insights_reached}"
    )

    # NOT reached -> NOT Reachable (insight is exploit-only, no Reachable)
    _, vdict_unreached, _, _ = analyze_cve_vuln(
        vuln,
        reached_purls={},
        direct_purls={},
        reached_services={},
        endpoint_reached_purls={},
        optional_pkgs=[],
        required_pkgs=[],
        prebuild_purls={},
        build_purls={},
        postbuild_purls={},
        purl_identities={},
        bom_dependency_tree=[],
        counts=_counts(),
    )
    insights_unreached = [
        p["value"]
        for p in (vdict_unreached.get("properties") or [])
        if p.get("name") == "depscan:insights"
    ]
    assert not any("Reachable" in i for i in insights_unreached), (
        f"a present-but-uncalled crate MUST NOT be Reachable; got {insights_unreached}"
    )


# ---------------------------------------------------------------------------
# Real cdxgen -> depscan end-to-end (requires cdxgen + rusi)
# ---------------------------------------------------------------------------


def _resolve_cdxgen_command():
    """Return the cdxgen invocation as an arg list, or None.

    Resolution order: ``DEPSCAN_CDXGEN_CMD`` env (a full command string, e.g.
    ``node /path/to/cdxgen.js``) -> ``shutil.which("cdxgen")``. Returns None
    when cdxgen is unavailable so the e2e test can skip cleanly. The dev tree
    is usable by setting ``DEPSCAN_CDXGEN_CMD="node /path/to/bin/cdxgen.js"``;
    no repo path is hardcoded.
    """
    env_cmd = os.environ.get("DEPSCAN_CDXGEN_CMD", "").strip()
    if env_cmd:
        return shlex.split(env_cmd)
    which = shutil.which("cdxgen")
    if which:
        return [which]
    return None


CDXGEN_CMD = _resolve_cdxgen_command()


def test_cdxgen_to_depscan_rustsec_app_end_to_end(tmp_path, rusi_env):
    """Full cdxgen -> depscan integration on a REAL vulnerable Rust repo.

    Runs the real cdxgen (dev tree via DEPSCAN_CDXGEN_CMD, or a PATH install)
    on rustsec-app under ``--profile research`` with
    ``--semantics-slices-file`` -- exactly what depscan's ``set_slices_args``
    passes -- so cdxgen runs rusi via evinse and PERSISTS the full raw report.
    depscan's ``run_rusi_reachability`` then consumes that persisted report
    (the primary path; no direct rusi spawn) and emits
    ``rust-reachables.slices.json``. We assert:

      - the persisted file has the rusi report SHAPE (so depscan can consume it),
      - ``pkg:cargo/time@0.1.45`` (RUSTSEC-2020-0071, called via time::now())
        is reached end-to-end,
      - ``pkg:cargo/libc`` (present in the real Cargo BOM but never called) is
        NOT reached,
      - RUSTSEC-2020-0071 is marked Reachable for time in the VDR when the vdb
        has the advisory cached.

    Skipped when cdxgen or the rusi binary is unavailable, or when cdxgen
    cannot complete (e.g. cargo cannot resolve deps offline).
    """
    if not CDXGEN_CMD:
        pytest.skip("cdxgen not found (set DEPSCAN_CDXGEN_CMD or put cdxgen on PATH)")
    assert RUSI_BIN, "rusi binary must be resolved (module skip should guard this)"
    src = str(RUSTSEC_APP)
    if not Path(src).is_dir():
        pytest.skip("rustsec-app fixture repo not present")

    bom_file = tmp_path / "bom.cdx.json"
    semantics_file = tmp_path / "rust-semantics.slices.json"

    # Mirror depscan's set_slices_args: pass --semantics-slices-file so cdxgen
    # persists the raw rusi report there. The report is only durable when this
    # path is explicitly provided; without it cdxgen writes a throwaway temp.
    cdxgen_args = CDXGEN_CMD + [
        src,
        "-t",
        "rust",
        "--profile",
        "research",
        "--semantics-slices-file",
        str(semantics_file),
        "-o",
        str(bom_file),
    ]
    env = os.environ.copy()
    # Hand cdxgen the SAME rusi binary depscan resolved so both sides agree.
    env["RUSI_CMD"] = RUSI_BIN
    cp = subprocess.run(
        cdxgen_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        timeout=240,
        check=False,
    )
    if cp.returncode != 0 or not bom_file.exists():
        pytest.skip(f"cdxgen did not produce a BOM (rc={cp.returncode}); skipping e2e")

    # cdxgen must persist the raw rusi report to the semantics-slices path.
    assert semantics_file.exists(), (
        "cdxgen must persist the raw rusi report under --profile research + "
        "--semantics-slices-file"
    )
    # ... and it must carry the rusi report SHAPE (the primary-path contract).
    from analysis_lib.rusi_slices import is_rusi_report

    persisted = json.loads(semantics_file.read_text())
    assert is_rusi_report(persisted), (
        "persisted file must have the rusi report shape (call_graph/data_flow + "
        "tool/runtime), not an atom semantics slice"
    )

    # depscan consumes the persisted report (primary path; no direct rusi spawn).
    ok = run_rusi_reachability(
        str(bom_file),
        src,
        options={
            "project_type": ["rust"],
            "reachability_analyzer": "FrameworkReachability",
        },
    )
    assert ok, "depscan must consume the cdxgen-persisted rusi report"
    assert (tmp_path / "rust-reachables.slices.json").exists()

    # the real Cargo BOM must carry versioned purls for time and libc.
    bom_data = json.loads(bom_file.read_text())
    bom_purls = {c.get("purl") for c in (bom_data.get("components") or [])}
    assert "pkg:cargo/time@0.1.45" in bom_purls
    assert any(p and p.startswith("pkg:cargo/libc@") for p in bom_purls)

    reached = _reached_purls(tmp_path)
    assert "pkg:cargo/time@0.1.45" in reached, (
        "time MUST be reached because the source calls time::now()"
    )
    assert not any(p.startswith("pkg:cargo/libc") for p in reached), (
        "libc is present-but-uncalled -> MUST NOT be reached"
    )

    # Close the loop to the VDR insight when the vdb has the advisory cached.
    from analysis_lib import VdrAnalysisKV
    from analysis_lib.utils import get_pkg_list
    from analysis_lib.vdr import VDRAnalyzer

    pkg_list, _lifecycles = get_pkg_list(str(bom_file))
    vopts = VdrAnalysisKV(
        project_type="rust",
        init_results=[],
        pkg_aliases={},
        purl_aliases={},
        suggest_mode=False,
        scoped_pkgs={},
        no_vuln_table=True,
        bom_file=str(bom_file),
        pkg_list=pkg_list,
        reached_purls={p: 1 for p in reached},
    )
    vres = VDRAnalyzer(vdr_options=vopts).process()
    vulns = vres.pkg_vulnerabilities or []
    time_vuln = next((v for v in vulns if v.get("id") == "RUSTSEC-2020-0071"), None)
    if not time_vuln:
        pytest.skip("vdb has no RUSTSEC-2020-0071 data cached; cannot assert the VDR insight")
    affects = [a.get("ref") for a in (time_vuln.get("affects") or [])]
    assert "pkg:cargo/time@0.1.45" in affects, (
        "the VDR vulnerability must affect the versioned time purl"
    )
    insights = [
        p["value"]
        for p in (time_vuln.get("properties") or [])
        if p.get("name") == "depscan:insights"
    ]
    assert any("Reachable" in i for i in insights), (
        f"RUSTSEC-2020-0071 must be Reachable for time in the VDR; got {insights}"
    )
