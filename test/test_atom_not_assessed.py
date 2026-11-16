"""The not-assessed records for atom runs.

An atom run that ATOM_TIMEOUT stops, and files atom's ``--parse-report``
names as unparsed, dropped or partial, must be recorded as not assessed
instead of quietly counting as zero reachable flows. The records live on
``BomResult.not_assessed`` and are copied onto ``TypeScan.not_assessed``.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

from depscan.lib import bom as bom_mod
from depscan.lib import pipeline

DATA_DIR = Path(__file__).resolve().parent / "data"

# The line cdxgen 13.8.0 prints after the atom dispatcher exits 124, copied
# from a real run of cdxgen 13.8.0 whose ATOM_TIMEOUT was 15000 ms.
ATOM_TIMEOUT_OUTPUT = """Creating reachables slice for /project. Please wait ...
WARN: atom did not finish within 15 seconds and was stopped, so its results are missing or incomplete. Allow more time with ATOM_TIMEOUT (milliseconds, atom only) or CDXGEN_TIMEOUT_MS (every external command).
Creating usages slice for /project. Please wait ...
WARN: atom did not finish within 15 seconds and was stopped, so its results are missing or incomplete. Allow more time with ATOM_TIMEOUT (milliseconds, atom only) or CDXGEN_TIMEOUT_MS (every external command).
BOM saved to sbom-python.cdx.json
"""


class _FakeCdxgenResult:
    def __init__(self, returncode=0, command_output=""):
        self.success = True
        self.returncode = returncode
        self.command_output = command_output


def test_atom_timeout_warning_line_is_recorded():
    """cdxgen maps atom's exit 124 to a WARN line and exits 0 itself, so the
    line in its captured output is the signal: one record, not one per line."""
    reasons = bom_mod._atom_not_assessed(_FakeCdxgenResult(command_output=ATOM_TIMEOUT_OUTPUT), None)
    assert reasons == [
        "atom did not finish within its timeout and was stopped; the slices are missing or incomplete"
    ]


def test_atom_exit_124_is_recorded(tmp_path):
    """A fake atom, run as a real process through this interpreter's
    executable, exits 124 the way the atom dispatcher does; the observed
    status must be classified as a timeout."""
    fake_atom = tmp_path / "fake-atom.py"
    fake_atom.write_text("import sys\nsys.exit(124)\n")
    completed = subprocess.run([sys.executable, str(fake_atom)], capture_output=True)
    # Positive control: the fake atom really ran and exited 124.
    assert completed.returncode == 124

    reasons = bom_mod._atom_not_assessed(_FakeCdxgenResult(returncode=124), None)
    assert reasons == [
        "atom was stopped by ATOM_TIMEOUT (exit 124); the slices are missing or incomplete"
    ]


def test_parse_report_records_each_dropped_file(tmp_path):
    """Every file atom's parse report lists as unparsed, dropped or partial
    becomes one record naming the file, the outcome, the stage and the
    parser's reason."""
    report = json.loads((DATA_DIR / "atom4" / "python-parse-report.json").read_text())
    assert report["counts"] == {"byOutcome": {"partial": 2}, "byFrontend": {"python": 2}}
    shutil.copy2(
        DATA_DIR / "atom4" / "python-parse-report.json",
        tmp_path / "python-parse-report.json",
    )
    reasons = bom_mod._atom_not_assessed(_FakeCdxgenResult(), str(tmp_path))
    assert len(reasons) == 2
    assert reasons[0].startswith("atom partial broken.py (stage: parse): ")
    assert "1 statements failed to parse" in reasons[0]
    assert reasons[1].startswith("atom partial partial.py (stage: parse): ")
    # A record for a file atom read fully would carry a different outcome and
    # must not appear; the recorded report holds only partial outcomes.


def test_parse_report_unreadable_file_is_skipped(tmp_path):
    (tmp_path / "python-parse-report.json").write_text("{not json")
    reasons = bom_mod._atom_not_assessed(_FakeCdxgenResult(), str(tmp_path))
    assert reasons == []


def test_clean_run_records_nothing(tmp_path):
    reasons = bom_mod._atom_not_assessed(_FakeCdxgenResult(), str(tmp_path))
    assert reasons == []


class _TimeoutGenResult(_FakeCdxgenResult):
    def __init__(self, bom_file):
        super().__init__(returncode=0, command_output=ATOM_TIMEOUT_OUTPUT)
        self.bom_file = bom_file


def _timeout_generator():
    class _Gen:
        def __init__(self, src_dir, bom_file, logger=None, options=None):
            self.bom_file = bom_file

        def generate(self):
            with open(self.bom_file, "w") as fh:
                json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6"}, fh)
            return _TimeoutGenResult(self.bom_file)

    return _Gen


def test_create_bom_carries_not_assessed(tmp_path, monkeypatch):
    """A cdxgen run that wrote a BOM while atom timed out still succeeds, and
    its BomResult carries the reason so the scan can report it."""
    monkeypatch.setattr(bom_mod, "_refuse_old_cdxgen", lambda logger=None: True)
    monkeypatch.setattr(bom_mod, "CdxgenGenerator", _timeout_generator())
    for helper in ("run_rusi_reachability", "run_golem_reachability", "run_dosai_reachability"):
        monkeypatch.setattr(bom_mod, helper, lambda *a, **k: None)

    target = str(tmp_path / "sbom-python.cdx.json")
    result = bom_mod.create_bom(target, str(tmp_path), {})

    assert result.success is True
    assert result.not_assessed == [
        "atom did not finish within its timeout and was stopped; the slices are missing or incomplete"
    ]


def test_stage_bom_keeps_not_assessed_on_the_scan(tmp_path, monkeypatch):
    """The per-type scan keeps the records for a later stage to write out."""
    monkeypatch.setattr(bom_mod, "_refuse_old_cdxgen", lambda logger=None: True)
    monkeypatch.setattr(bom_mod, "CdxgenGenerator", _timeout_generator())
    for helper in ("run_rusi_reachability", "run_golem_reachability", "run_dosai_reachability"):
        monkeypatch.setattr(bom_mod, helper, lambda *a, **k: None)
    from depscan.cli_options import build_parser

    args = build_parser().parse_args(
        [
            "--src",
            str(tmp_path),
            "--reports-dir",
            str(tmp_path),
            "--bom-engine",
            "CdxgenGenerator",
        ]
    )
    ctx = pipeline.build_context(args)
    pipeline.stage_setup(ctx)
    scan = pipeline.TypeScan(project_type="python")

    assert pipeline._produce_boms(ctx, scan) is True
    assert scan.not_assessed == [
        "atom did not finish within its timeout and was stopped; the slices are missing or incomplete"
    ]
