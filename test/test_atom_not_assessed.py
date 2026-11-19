"""The not-assessed records for atom runs.

An atom run that ATOM_TIMEOUT stops must be recorded as not assessed instead
of quietly counting as zero reachable flows. The records live on
``BomResult.not_assessed`` and are copied onto ``TypeScan.not_assessed``.
test_cdxgen_contract.py checks the same signal through a fake cdxgen process.
"""

import json

from depscan.lib import bom as bom_mod
from depscan.lib import pipeline

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
    reasons = bom_mod._atom_not_assessed(_FakeCdxgenResult(command_output=ATOM_TIMEOUT_OUTPUT))
    assert reasons == [bom_mod.ATOM_TIMEOUT_REASON]


def test_clean_run_records_nothing():
    reasons = bom_mod._atom_not_assessed(
        _FakeCdxgenResult(command_output="BOM saved to sbom-python.cdx.json\n")
    )
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


def test_stage_bom_keeps_not_assessed_on_the_scan(tmp_path, monkeypatch):
    """The per-type scan keeps the records for a later stage to write out."""
    monkeypatch.setattr(bom_mod, "_refuse_old_cdxgen", lambda logger=None: True)
    monkeypatch.setattr(bom_mod, "CdxgenGenerator", _timeout_generator())
    for helper in (
        "run_rusi_reachability",
        "run_golem_reachability",
        "run_kosi_reachability",
        "run_dosai_reachability",
    ):
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
    assert scan.not_assessed == [bom_mod.ATOM_TIMEOUT_REASON]
