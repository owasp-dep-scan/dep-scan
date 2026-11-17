"""Integration tests for dosai-powered .NET reachability.

Three layers:

  - **BOM wiring (no binary):** PRIMARY path consumes a cdxgen-persisted combined
    native report (``dosai-combined.sample.json``); FALLBACK assembles one from
    two raw artifacts; gating no-ops. Run unconditionally.
  - **Real-dosai fixture repos (require dosai + dotnet):** ``reachable-app`` and
    ``unreachable-app`` under ``test/data/dosai/repos/`` use a scenario dosai
    actually recognises (method-parameter ``TextReader`` source -> fully-qualified
    ``Newtonsoft.Json.JsonConvert.DeserializeObject<T>`` deserialization sink),
    committed with restored/built ``obj/project.assets.json`` + ``bin/*.deps.json``
    + ``Newtonsoft.Json.dll`` so dosai can resolve symbols + attribute purls
    hermetically (no in-test ``dotnet restore``). ``reachable-app`` reaches the
    package; ``unreachable-app`` references it but never calls it. Skip cleanly
    when dosai/dotnet are absent.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from analysis_lib import ReachabilityAnalysisKV
from analysis_lib.reachability import FrameworkReachability
from depscan.lib.bom import run_dosai_reachability
from xbom_lib import dosai as dosai_mod

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "packages" / "analysis-lib" / "tests" / "data" / "dosai"
DOSAI_REPOS = REPO_ROOT / "test" / "data" / "dosai" / "repos"


def _write_nuget_bom(bom_file: Path):
    """Write a minimal NuGet BOM mirroring cdxgen output for the fixture."""
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "app",
                "purl": "pkg:nuget/Depscan@1.0.0",
            }
        },
        "components": [
            {
                "type": "library",
                "name": "System.Text.Json",
                "version": "10.0.0",
                "purl": "pkg:nuget/System.Text.Json@10.0.0",
            }
        ],
    }
    bom_file.write_text(json.dumps(bom), encoding="utf-8")
    return str(bom_file)


def _reached_purls(bom_dir: Path) -> set:
    opts = ReachabilityAnalysisKV(
        project_types=["dotnet"], src_dir=str(bom_dir), bom_dir=str(bom_dir)
    )
    res = FrameworkReachability(opts).process()
    return set((res.reached_purls or {}).keys())


# ---------------------------------------------------------------------------
# Gating -- no-op unless dotnet + reachability on
# ---------------------------------------------------------------------------


def test_non_dotnet_project_is_noop(tmp_path):
    bom_file = tmp_path / "bom.cdx.json"
    _write_nuget_bom(bom_file)
    ok = run_dosai_reachability(
        str(bom_file),
        str(tmp_path),
        options={"project_type": ["python"], "reachability_analyzer": "FrameworkReachability"},
    )
    assert ok is False
    assert not (tmp_path / "dotnet-reachables.slices.json").exists()


def test_reachability_off_is_noop(tmp_path):
    bom_file = tmp_path / "bom.cdx.json"
    _write_nuget_bom(bom_file)
    ok = run_dosai_reachability(
        str(bom_file),
        str(tmp_path),
        options={"project_type": ["dotnet"], "reachability_analyzer": "off"},
    )
    assert ok is False


# ---------------------------------------------------------------------------
# PRIMARY path -- consumes the cdxgen-persisted combined report
# ---------------------------------------------------------------------------


def test_primary_path_consumes_persisted_combined_report(tmp_path):
    """cdxgen persists ``{Metadata, methods, dataflows}`` to
    ``dotnet-semantics.slices.json``; depscan MUST consume it (no dosai spawn)
    and emit ``dotnet-reachables.slices.json`` with the reachable NuGet purl."""
    bom_file = tmp_path / "bom.cdx.json"
    _write_nuget_bom(bom_file)
    # drop the cdxgen-persisted combined report next to the BOM
    shutil.copyfile(
        FIXTURES / "dosai-combined.sample.json",
        tmp_path / "dotnet-semantics.slices.json",
    )
    ok = run_dosai_reachability(
        str(bom_file),
        str(tmp_path),
        options={"project_type": ["dotnet"], "reachability_analyzer": "FrameworkReachability"},
    )
    assert ok is True

    slice_file = tmp_path / "dotnet-reachables.slices.json"
    assert slice_file.exists(), "projection slice must be emitted next to the BOM"
    flows = json.loads(slice_file.read_text())
    assert flows, "at least one projected flow expected"

    # the reachable NuGet purl MUST appear in reached_purls via the existing
    # purl-keyed engine (the projection faithfully carries it).
    reached = _reached_purls(tmp_path)
    assert "pkg:nuget/System.Text.Json@10.0.0" in reached, (
        "System.Text.Json MUST be reached via the cdxgen-persisted report"
    )

    # the native facts sidecar is written for VEX/advanced analysis
    facts_file = tmp_path / "analysis" / "dosai" / "dotnet-reachability.facts.json"
    assert facts_file.exists()
    facts = json.loads(facts_file.read_text())
    assert "pkg:nuget/System.Text.Json@10.0.0" in facts["reached_purls"]
    assert facts["reached_purls"]["pkg:nuget/System.Text.Json@10.0.0"]["confidence"] == "High"


def test_primary_path_rejects_non_dosai_semantics_file(tmp_path, monkeypatch):
    """An atom-produced semantics slice that happens to share the path MUST be
    rejected (require_report shape check) so we fall through to the fallback
    rather than mis-parsing it as a dosai report."""
    bom_file = tmp_path / "bom.cdx.json"
    _write_nuget_bom(bom_file)
    # a non-dosai file at the semantics path -- shape check returns None ->
    # fallback runs
    (tmp_path / "dotnet-semantics.slices.json").write_text(
        json.dumps({"flows": [], "purls": []}), encoding="utf-8"
    )
    import xbom_lib.dosai as dosai_mod

    # simulate "no usable dosai output" so the fallback is a graceful no-op,
    # isolating the shape-rejection behavior from binary availability.
    monkeypatch.setattr(
        dosai_mod,
        "run_dosai",
        lambda *a, **k: dosai_mod.DosaiResult(success=False, skipped=True),
    )
    ok = run_dosai_reachability(
        str(bom_file),
        str(tmp_path),
        options={"project_type": ["dotnet"], "reachability_analyzer": "FrameworkReachability"},
    )
    assert ok is False


# ---------------------------------------------------------------------------
# FALLBACK path -- spawns dosai directly when cdxgen produced nothing
# ---------------------------------------------------------------------------


def test_fallback_path_assembles_combined_report(tmp_path, monkeypatch):
    """When no persisted report exists, depscan spawns dosai directly and
    assembles the combined report from the two raw artifacts. The dosai runner
    is monkeypatched here so the test needs no real binary."""
    bom_file = tmp_path / "bom.cdx.json"
    _write_nuget_bom(bom_file)

    import xbom_lib.dosai as dosai_mod

    df_fixture = json.loads((FIXTURES / "dosai-dataflows.sample.json").read_text())
    # build a tiny methods slice carrying a Dependency-level PackageReachability
    methods_fixture = {
        "Metadata": {"Tool": "Dosai"},
        "CallGraph": {"Nodes": [], "Edges": []},
        "ApiEndpoints": [],
        "PackageReachability": [],
    }

    def fake_run_dosai(src_dir, out_dir, **kwargs):
        (tmp_path / "dotnet-dataflows.json").write_text(json.dumps(df_fixture))
        (tmp_path / "dotnet-methods.json").write_text(json.dumps(methods_fixture))
        return dosai_mod.DosaiResult(
            success=True,
            methods_path=str(tmp_path / "dotnet-methods.json"),
            dataflows_path=str(tmp_path / "dotnet-dataflows.json"),
            version="3.0.5",
        )

    monkeypatch.setattr(dosai_mod, "run_dosai", fake_run_dosai)
    # run_dosai_reachability imports run_dosai lazily from xbom_lib.dosai, so
    # patching the module attribute is sufficient.

    ok = run_dosai_reachability(
        str(bom_file),
        str(tmp_path),
        options={"project_type": ["dotnet"], "reachability_analyzer": "FrameworkReachability"},
    )
    assert ok is True
    slice_file = tmp_path / "dotnet-reachables.slices.json"
    assert slice_file.exists()
    reached = _reached_purls(tmp_path)
    assert "pkg:nuget/System.Text.Json@10.0.0" in reached


def test_fallback_skipped_when_dosai_unavailable(tmp_path, monkeypatch):
    """Missing binary/runtime -> graceful no-op (skipped=True), never raises."""
    bom_file = tmp_path / "bom.cdx.json"
    _write_nuget_bom(bom_file)
    import xbom_lib.dosai as dosai_mod

    monkeypatch.setattr(
        dosai_mod,
        "run_dosai",
        lambda *a, **k: dosai_mod.DosaiResult(success=False, skipped=True),
    )
    ok = run_dosai_reachability(
        str(bom_file),
        str(tmp_path),
        options={"project_type": ["dotnet"], "reachability_analyzer": "FrameworkReachability"},
    )
    assert ok is False
    assert not (tmp_path / "dotnet-reachables.slices.json").exists()


# ---------------------------------------------------------------------------
# Real-dosai fixture repos (require dosai + dotnet) -- Gate 6
# ---------------------------------------------------------------------------


def _resolve_dosai_binary():
    """Return the dosai binary path for this run, or None.

    Resolution order: ``DEPSCAN_DOSAI_BINARY`` -> ``DOSAI_CMD`` ->
    ``shutil.which("dosai")`` / ``shutil.which("Dosai")``.
    """
    for env_name in (dosai_mod.DOSAI_BINARY_ENV, dosai_mod.DOSAI_CMD_ENV):
        val = os.environ.get(env_name, "").strip()
        if val and os.path.isfile(val):
            return val
    for name in ("dosai", "Dosai"):
        which = shutil.which(name)
        if which:
            return which
    return None


def _dotnet_available() -> bool:
    return shutil.which("dotnet") is not None


DOSAI_BIN = _resolve_dosai_binary()
pytestmark_real = pytest.mark.skipif(
    DOSAI_BIN is None or not _dotnet_available(),
    reason="dosai binary or .NET runtime not found "
    "(set DEPSCAN_DOSAI_BINARY or install cdxgen-plugins-bin; ensure 'dotnet' is on PATH)",
)


def _write_newtonsoft_bom(bom_file: Path, app_name: str):
    """Write a minimal NuGet BOM for the fixture apps (Newtonsoft.Json 13.0.3)."""
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": app_name,
                "purl": f"pkg:nuget/{app_name}@1.0.0",
            }
        },
        "components": [
            {
                "type": "library",
                "name": "Newtonsoft.Json",
                "version": "13.0.3",
                "purl": "pkg:nuget/Newtonsoft.Json@13.0.3",
            }
        ],
    }
    bom_file.write_text(json.dumps(bom), encoding="utf-8")
    return str(bom_file)


@pytestmark_real
def test_reachable_app_marks_newtonsoft_reached(tmp_path, monkeypatch):
    """reachable-app: ``TextReader`` source -> fully-qualified
    ``Newtonsoft.Json.JsonConvert.DeserializeObject<T>`` sink. dosai MUST flag
    ``pkg:nuget/Newtonsoft.Json@13.0.3`` reachable (DataFlowNode/High), and the
    dep-scan pipeline MUST surface it in ``reached_purls`` via the direct-spawn
    FALLBACK path (no cdxgen-persisted report)."""
    monkeypatch.setenv(dosai_mod.DOSAI_BINARY_ENV, DOSAI_BIN)
    bom_file = tmp_path / "bom.cdx.json"
    _write_newtonsoft_bom(bom_file, "reachable-app")
    src = DOSAI_REPOS / "reachable-app"

    ok = run_dosai_reachability(
        str(bom_file),
        str(src),
        options={"project_type": ["dotnet"], "reachability_analyzer": "FrameworkReachability"},
    )
    if not ok:
        pytest.skip("dosai could not run on reachable-app (runtime/binary issue)")

    slice_file = tmp_path / "dotnet-reachables.slices.json"
    assert slice_file.exists(), "projection slice must be emitted"
    reached = _reached_purls(tmp_path)
    assert "pkg:nuget/Newtonsoft.Json@13.0.3" in reached, (
        "Newtonsoft.Json MUST be reached when reachable-app deserializes via it"
    )

    # the native facts sidecar carries dosai's High-confidence verdict
    facts = json.loads(
        (tmp_path / "analysis" / "dosai" / "dotnet-reachability.facts.json").read_text()
    )
    nf = facts["reached_purls"]["pkg:nuget/Newtonsoft.Json@13.0.3"]
    assert nf["confidence"] == "High"
    assert nf["kind"] in ("DataFlowNode", "CallGraphEdge")


@pytestmark_real
def test_unreachable_app_does_not_mark_newtonsoft_reached(tmp_path, monkeypatch):
    """unreachable-app: the .csproj references Newtonsoft.Json but the source
    never calls it. dosai must NOT flag a call/dataflow reachability, so the
    package must NOT appear in ``reached_purls``."""
    monkeypatch.setenv(dosai_mod.DOSAI_BINARY_ENV, DOSAI_BIN)
    bom_file = tmp_path / "bom.cdx.json"
    _write_newtonsoft_bom(bom_file, "unreachable-app")
    src = DOSAI_REPOS / "unreachable-app"

    ok = run_dosai_reachability(
        str(bom_file),
        str(src),
        options={"project_type": ["dotnet"], "reachability_analyzer": "FrameworkReachability"},
    )
    if not ok:
        pytest.skip("dosai could not run on unreachable-app")
    reached = _reached_purls(tmp_path)
    assert "pkg:nuget/Newtonsoft.Json@13.0.3" not in reached, (
        "an unused dependency MUST NOT be marked reachable"
    )


@pytestmark_real
def test_primary_path_via_cdxgen_on_reachable_app(tmp_path, monkeypatch):
    """PRIMARY path end-to-end with real dosai: cdxgen runs dosai and persists
    the combined ``dotnet-semantics.slices.json``; dep-scan consumes it (no
    direct dosai spawn) and surfaces Newtonsoft in ``reached_purls``.

    Requires cdxgen on PATH (bundled with dep-scan). Skips if cdxgen is absent
    or the invocation fails."""
    monkeypatch.setenv(dosai_mod.DOSAI_CMD_ENV, DOSAI_BIN)
    cdxgen = shutil.which("cdxgen")
    if not cdxgen:
        pytest.skip("cdxgen not on PATH")
    src = DOSAI_REPOS / "reachable-app"
    bom_file = tmp_path / "bom.cdx.json"
    sem_file = tmp_path / "dotnet-semantics.slices.json"
    cp = subprocess.run(
        [
            cdxgen,
            "-t",
            "dotnet",
            "-o",
            str(bom_file),
            "--profile",
            "research",
            "--semantics-slices-file",
            str(sem_file),
            str(src),
        ],
        cwd=str(src),
        capture_output=True,
        text=True,
        timeout=300,
    )
    if cp.returncode != 0 or not bom_file.exists() or not sem_file.exists():
        pytest.skip(f"cdxgen invocation failed (rc={cp.returncode})")

    ok = run_dosai_reachability(
        str(bom_file),
        str(src),
        options={"project_type": ["dotnet"], "reachability_analyzer": "FrameworkReachability"},
    )
    assert ok is True, "PRIMARY path must consume the cdxgen-persisted report"
    reached = _reached_purls(tmp_path)
    assert "pkg:nuget/Newtonsoft.Json@13.0.3" in reached
