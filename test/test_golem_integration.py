"""Integration tests for golem-powered Go reachability.

These tests exercise the full adapter pipeline (binary discovery -> golem run ->
report -> atom-slice converter -> FrameworkReachability) against real, tiny
Go repositories checked in under ``test/data/golem/repos/``:

  - ``reachable-app``: calls ``vulnlib.ProcessQuery`` on a user-controlled
    HTTP path. The reconciled ``pkg:golang/github.com/example/vuln-lib@<v>``
    MUST appear in ``reached_purls``.
  - ``unreachable-app``: the go.mod lists ``vuln-lib`` as a dependency but
    the source never calls it. ``pkg:golang/github.com/example/vuln-lib@<v>``
    MUST NOT appear in ``reached_purls``.

These tests require the golem binary AND a Go toolchain. They are skipped when
either is not available so CI without them does not fail.
"""

import json
import os
import shutil
from pathlib import Path

import pytest

from analysis_lib import Counts, ReachabilityAnalysisKV
from analysis_lib.reachability import FrameworkReachability
from analysis_lib.utils import process_vuln_occ
from depscan.lib.bom import run_golem_reachability
from xbom_lib import golem as golem_mod

REPO_ROOT = Path(__file__).resolve().parent.parent
GOLEM_REPOS = REPO_ROOT / "test" / "data" / "golem" / "repos"


def _resolve_golem_binary():
    """Return the golem binary path to use for this test run, or None.

    Resolution order: ``DEPSCAN_GOLEM_BINARY`` env -> ``GOLEM_CMD`` env ->
    ``shutil.which("golem")``.
    """
    for env_name in (golem_mod.GOLEM_BINARY_ENV, golem_mod.GOLEM_CMD_ENV):
        val = os.environ.get(env_name, "").strip()
        if val and os.path.isfile(val):
            return val
    which = shutil.which("golem")
    if which:
        return which
    return None


def _go_available():
    """Return True if a Go toolchain is available."""
    return shutil.which("go") is not None


GOLEM_BIN = _resolve_golem_binary()
pytestmark = pytest.mark.skipif(
    GOLEM_BIN is None or not _go_available(),
    reason="golem binary or Go toolchain not found "
    "(set DEPSCAN_GOLEM_BINARY or install cdxgen-plugins-bin; ensure 'go' is on PATH)",
)


@pytest.fixture
def golem_env(monkeypatch):
    """Force ``find_golem_binary`` to the resolved binary for this run."""
    monkeypatch.setenv(golem_mod.GOLEM_BINARY_ENV, GOLEM_BIN)
    yield


def _write_go_bom(bom_file: Path, app_name: str, app_version: str = "v0.1.0"):
    """Write a minimal Go BOM mirroring cdxgen output.

    The integration repos use a local replace directive (no network), so the
    BOM is synthetic but realistic: an application root + the external
    dependency, each with a versioned purl that the converter must reconcile
    onto.
    """
    components = [
        {
            "type": "application",
            "name": f"github.com/example/{app_name}",
            "version": app_version,
            "purl": f"pkg:golang/github.com/example/{app_name}@{app_version}",
        },
        {
            "type": "library",
            "name": "github.com/example/vuln-lib",
            "version": "v0.0.0",
            "purl": "pkg:golang/github.com/example/vuln-lib@v0.0.0",
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
    opts = ReachabilityAnalysisKV(project_types=["go"], src_dir=str(bom_dir), bom_dir=str(bom_dir))
    res = FrameworkReachability(opts).process()
    return set((res.reached_purls or {}).keys())


# ---------------------------------------------------------------------------
# (a) reachable-app
# ---------------------------------------------------------------------------


def test_reachable_app_marks_vuln_lib_reached(tmp_path, golem_env):
    """A user-controlled HTTP path -> vulnlib.ProcessQuery must reconcile
    vuln-lib onto the BOM and mark it as reached."""
    bom_file = tmp_path / "sbom-go.cdx.json"
    _write_go_bom(bom_file, "reachable-app")
    src = GOLEM_REPOS / "reachable-app"

    ok = run_golem_reachability(
        str(bom_file),
        str(src),
        options={
            "project_type": ["go"],
            "reachability_analyzer": "FrameworkReachability",
        },
    )
    if not ok:
        pytest.skip(
            "golem could not run on reachable-app (binary missing, Go toolchain "
            "issue, or module resolution failure)"
        )

    slice_file = tmp_path / "go-reachables.slices.json"
    assert slice_file.exists(), "slice file must be emitted next to the BOM"
    flows = json.loads(slice_file.read_text())
    assert flows, "at least one flow expected for a reachable call"

    reached = _reached_purls(tmp_path)
    assert "pkg:golang/github.com/example/vuln-lib@v0.0.0" in reached, (
        "vuln-lib MUST be reached when the app calls vulnlib.ProcessQuery"
    )
    assert "pkg:golang/github.com/example/reachable-app@v0.1.0" in reached


# ---------------------------------------------------------------------------
# (b) unreachable-app
# ---------------------------------------------------------------------------


def test_unreachable_app_does_not_mark_vuln_lib_reached(tmp_path, golem_env):
    """Depending on vuln-lib in go.mod but never calling it MUST NOT mark it."""
    bom_file = tmp_path / "sbom-go.cdx.json"
    _write_go_bom(bom_file, "unreachable-app")
    src = GOLEM_REPOS / "unreachable-app"

    ok = run_golem_reachability(
        str(bom_file),
        str(src),
        options={
            "project_type": ["go"],
            "reachability_analyzer": "FrameworkReachability",
        },
    )
    if not ok:
        pytest.skip("golem could not run on unreachable-app")

    reached = _reached_purls(tmp_path)
    assert "pkg:golang/github.com/example/vuln-lib@v0.0.0" not in reached, (
        "vuln-lib MUST NOT be reached when the app only depends on it without calling"
    )


# ---------------------------------------------------------------------------
# determinism
# ---------------------------------------------------------------------------


def test_golem_slice_is_deterministic(tmp_path, golem_env):
    """Two independent golem runs on the same repo produce byte-identical
    slices."""
    src = GOLEM_REPOS / "reachable-app"

    def _run_once(work_dir: Path) -> str:
        bom_file = work_dir / "sbom-go.cdx.json"
        _write_go_bom(bom_file, "reachable-app")
        assert run_golem_reachability(
            str(bom_file),
            str(src),
            options={
                "project_type": ["go"],
                "reachability_analyzer": "FrameworkReachability",
            },
        )
        return (work_dir / "go-reachables.slices.json").read_text()

    d1 = tmp_path / "d1"
    d2 = tmp_path / "d2"
    d1.mkdir()
    d2.mkdir()
    s1 = _run_once(d1)
    s2 = _run_once(d2)
    assert s1 == s2, "golem slice output must be deterministic across runs"


# ---------------------------------------------------------------------------
# graceful degradation
# ---------------------------------------------------------------------------


def test_golem_reachability_skips_when_binary_missing(tmp_path, monkeypatch):
    """When the golem binary cannot be found, run_golem_reachability must
    return False (not crash) and leave no slice file behind."""
    monkeypatch.setattr(golem_mod, "find_golem_binary", lambda logger=None: None)
    bom_file = tmp_path / "sbom-go.cdx.json"
    _write_go_bom(bom_file, "reachable-app")
    src = GOLEM_REPOS / "reachable-app"

    result = run_golem_reachability(
        str(bom_file),
        str(src),
        options={
            "project_type": ["go"],
            "reachability_analyzer": "FrameworkReachability",
        },
    )
    assert result is False
    assert not (tmp_path / "go-reachables.slices.json").exists()


def test_golem_reachability_noop_for_non_go(tmp_path, golem_env):
    """Non-go project types are a no-op even when the binary IS present."""
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
    result = run_golem_reachability(
        str(bom_file),
        str(tmp_path),
        options={"project_type": ["js"], "reachability_analyzer": "FrameworkReachability"},
    )
    assert result is False
    assert not (tmp_path / "go-reachables.slices.json").exists()


def test_golem_reachability_noop_when_reachability_off(tmp_path, golem_env):
    """Reachability off -> no golem run even for go."""
    bom_file = tmp_path / "sbom-go.cdx.json"
    _write_go_bom(bom_file, "reachable-app")
    src = GOLEM_REPOS / "reachable-app"
    result = run_golem_reachability(
        str(bom_file),
        str(src),
        options={"project_type": ["go"], "reachability_analyzer": "off"},
    )
    assert result is False


def test_golem_reachability_accepts_golang_alias(tmp_path, golem_env):
    """The ``golang`` project-type alias must trigger golem just like ``go``."""
    bom_file = tmp_path / "sbom-go.cdx.json"
    _write_go_bom(bom_file, "reachable-app")
    src = GOLEM_REPOS / "reachable-app"
    ok = run_golem_reachability(
        str(bom_file),
        str(src),
        options={
            "project_type": ["golang"],
            "reachability_analyzer": "FrameworkReachability",
        },
    )
    assert ok, "golem reachability should run for the 'golang' project-type alias"
    assert (tmp_path / "go-reachables.slices.json").exists()


# ---------------------------------------------------------------------------
# primary path: consume the report cdxgen persists, WITHOUT spawning golem
# ---------------------------------------------------------------------------


def test_consumes_cdxgen_semantics_report_without_spawning(tmp_path, golem_env, monkeypatch):
    """depscan's primary path reads the raw golem report cdxgen persists to
    ``<bomdir>/<type>-semantics.slices.json`` and converts it -- with NO direct
    golem invocation. Proves depscan need not run golem itself when cdxgen +
    plugins are available.

    We first generate a real golem report (as cdxgen would) into the semantics
    path, then force the golem binary UNRESOLVABLE so any attempt to spawn would
    fail; reachability must still light up from the persisted report alone.
    """
    from xbom_lib import golem as _golem_mod

    bom_dir = tmp_path
    bom_file = bom_dir / "sbom-go.cdx.json"
    _write_go_bom(bom_file, "reachable-app")
    src = GOLEM_REPOS / "reachable-app"

    # Emulate cdxgen: persist the full raw golem report to the semantics path.
    semantics_path = bom_dir / "go-semantics.slices.json"
    res = _golem_mod.run_golem(str(src), str(semantics_path), logger=None)
    if not res.success or not semantics_path.exists():
        pytest.skip("golem could not produce a report for the semantics-path test")

    # Now make the binary unresolvable so the fallback CANNOT run golem.
    monkeypatch.setattr(_golem_mod, "find_golem_binary", lambda logger=None: None)

    ok = run_golem_reachability(
        str(bom_file),
        str(src),
        options={
            "project_type": ["go"],
            "reachability_analyzer": "FrameworkReachability",
        },
    )
    assert ok, "must consume the cdxgen-produced semantics report without spawning golem"

    reached = _reached_purls(bom_dir)
    assert "pkg:golang/github.com/example/vuln-lib@v0.0.0" in reached
    assert "pkg:golang/github.com/example/reachable-app@v0.1.0" in reached


# ---------------------------------------------------------------------------
# (d) real published CVE module (not a synthetic local-replace stub)
# ---------------------------------------------------------------------------

# The app under test/data/golem/repos/real-cve-app is a tiny Go module that:
#   - imports and CALLS github.com/satori/go.uuid@v1.2.0 NewV4() -- a real,
#     published module with a known advisory (GHSA-vc85-9fcg-rc3m). The call
#     path reaches the vulnerable package so it MUST be Reachable.
#   - blank-imports github.com/gorilla/mux@v1.8.1 but never calls it -- a real
#     dependency that is listed in go.mod yet MUST NOT be Reachable.
#
# Dependencies are vendored (vendor/) so the test is hermetic: no Go module
# proxy or network access is required once golem + a Go toolchain are present.
REAL_CVE_REPO = GOLEM_REPOS / "real-cve-app"
SATORI_PURL = "pkg:golang/github.com/satori/go.uuid@v1.2.0"
MUX_PURL = "pkg:golang/github.com/gorilla/mux@v1.8.1"


def _write_real_cve_bom(bom_file: Path) -> str:
    """Write a Go BOM with the real versioned purls cdxgen would emit."""
    components = [
        {
            "type": "application",
            "name": "github.com/example/real-cve-app",
            "version": "v0.1.0",
            "purl": "pkg:golang/github.com/example/real-cve-app@v0.1.0",
        },
        {
            "type": "library",
            "name": "github.com/satori/go.uuid",
            "version": "v1.2.0",
            "purl": SATORI_PURL,
        },
        {
            "type": "library",
            "name": "github.com/gorilla/mux",
            "version": "v1.8.1",
            "purl": MUX_PURL,
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


def _golem_reached_on_real_cve(tmp_path: Path) -> dict:
    """Run golem reachability on real-cve-app; return the reached_purls dict."""
    bom_file = tmp_path / "sbom-go.cdx.json"
    _write_real_cve_bom(bom_file)
    ok = run_golem_reachability(
        str(bom_file),
        str(REAL_CVE_REPO),
        options={
            "project_type": ["go"],
            "reachability_analyzer": "FrameworkReachability",
        },
    )
    if not ok:
        pytest.skip("golem could not run on real-cve-app (binary/Go/module issue)")
    opts = ReachabilityAnalysisKV(
        project_types=["go"], src_dir=str(tmp_path), bom_dir=str(tmp_path)
    )
    res = FrameworkReachability(opts).process()
    return res.reached_purls or {}


def test_real_cve_reached_vs_unused_dep(tmp_path, golem_env):
    """On a real published module, golem must reconcile the versioned purl and
    mark the CALLED dependency (satori/go.uuid) as reached while leaving the
    unused dependency (gorilla/mux) unreached."""
    reached = _golem_reached_on_real_cve(tmp_path)
    assert SATORI_PURL in reached, "satori/go.uuid MUST be reached -- the app calls uuid.NewV4()"
    assert MUX_PURL not in reached, (
        "gorilla/mux MUST NOT be reached -- it is imported but never called"
    )


@pytest.mark.parametrize("callgraph_mode", ["none", "static", "cha", "rta", "vta"])
def test_real_cve_verdict_independent_of_callgraph_mode(
    tmp_path, golem_env, monkeypatch, callgraph_mode
):
    """golem computes slice and package reachability on RTA whatever
    ``--callgraph`` builds, so the reached/unreached split must not move with
    the mode -- CHA alone used to put gorilla/mux back in the reached set."""
    import depscan.lib.bom as bom_mod

    monkeypatch.setattr(bom_mod, "GOLEM_DEFAULT_CALLGRAPH_MODE", callgraph_mode)
    reached = _golem_reached_on_real_cve(tmp_path)
    assert SATORI_PURL in reached, (
        f"satori/go.uuid must be reached under --callgraph {callgraph_mode}"
    )
    assert MUX_PURL not in reached, (
        f"gorilla/mux must stay unreached under --callgraph {callgraph_mode}"
    )


def _make_advisory_occurrence(vid, vendor, pkg, version):
    """Build a VulnerabilityOccurrence representing a real advisory for a Go
    module. Used to drive the VDR reachability mapping without the full vdb
    download (the reachability signal itself comes from a real golem run)."""
    from vdb.lib import VulnerabilityOccurrence

    return VulnerabilityOccurrence(
        oid=vid,
        problem_type="CWE-338",
        otype="library",
        severity="HIGH",
        cvss_score=7.5,
        cvss_v3={"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        package_issue={
            "affected_location": {
                "vendor": vendor,
                "package": pkg,
                "version": version,
            },
            "fixed_location": "",
        },
        short_description="Predictable UUID generation",
        long_description="The package generates predictable UUIDs.",
        related_urls=[],
        effective_severity="HIGH",
        source_update_time="2021-01-01T00:00:00",
        source_orig_time="2017-01-01T00:00:00",
        matched_by=f"pkg:golang/{vendor}/{pkg}@{version}|{version}",
    )


def test_real_cve_advisory_marked_reachable_in_vdr(tmp_path, golem_env):
    """A real advisory for a REACHED module must carry the 'Reachable' insight
    in the VDR, while the same advisory shape for an UNREACHED module must not.

    The reachability signal is a real golem run on the vendored real-cve-app;
    the advisory occurrences represent the published GHSA and are fed through
    the exact VDR builder (process_vuln_occ) that VDRAnalyzer uses.
    """
    reached = _golem_reached_on_real_cve(tmp_path)
    assert SATORI_PURL in reached, "precondition: satori must be reached"

    # purl_aliases mirror what find_vulns produces: mapping the VDB's internal
    # vendor:package:version key onto the BOM's versioned purl.
    from types import SimpleNamespace

    purl_aliases = {
        "github.com/satori:go.uuid:v1.2.0": SATORI_PURL,
        "github.com/gorilla:mux:v1.8.1": MUX_PURL,
    }
    opts = SimpleNamespace(project_type="go", pkg_aliases={}, purl_aliases=purl_aliases)

    satori_occ = _make_advisory_occurrence(
        "GHSA-vc85-9fcg-rc3m", "github.com/satori", "go.uuid", "v1.2.0"
    )
    mux_occ = _make_advisory_occurrence("GHSA-xxxx-mux0001", "github.com/gorilla", "mux", "v1.8.1")

    _, _, satori_vdr = process_vuln_occ(
        {}, {}, "", [], opts, reached, [], satori_occ.to_dict(), Counts()
    )
    _, _, mux_vdr = process_vuln_occ(
        {}, {}, "", [], opts, reached, [], mux_occ.to_dict(), Counts()
    )

    satori_insights = {p["name"]: p["value"] for p in satori_vdr.get("properties", [])}
    mux_insights = {p["name"]: p["value"] for p in mux_vdr.get("properties", [])}

    assert "Reachable" in satori_insights.get("depscan:insights", ""), (
        "the reached module's advisory MUST be marked Reachable in the VDR"
    )
    assert "Reachable" not in mux_insights.get("depscan:insights", ""), (
        "the unused module's advisory MUST NOT be marked Reachable in the VDR"
    )
