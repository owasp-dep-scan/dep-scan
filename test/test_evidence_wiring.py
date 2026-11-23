"""The evidence store wiring, end to end.

The scans here run the real enrichment stage over the trimmed repotests
fixtures: an atom-only Python project and a .NET project whose dosai report
the pinned data carries. Everything around them (the database, the matching
stage, the rendering) is stubbed the way the scan-directory tests stub it, so
the tests assert exactly what the BOM step, the enrichment stage and the
finish stage write.

The evidence producers beside the reachability analyzers (the cdxgen BOM
adapter, the blint review adapter and the tracebom adapter) are exercised on
the committed adapter recordings under
``packages/analysis-lib/tests/data/``, placed into scan directories the way a
real scan's files lie.
"""

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from depscan import api
from depscan.lib import doctor as doctor_mod
from depscan.lib import pipeline, vdb_setup

DATA_DIR = Path(__file__).parent / "data"
FIXTURES = DATA_DIR / "repotests"

# The committed adapter recordings, reused as the scan-directory
# files of the evidence producers: the blint review reports and the SBOM its
# sbom mode writes, the cdxgen BOM with the introspection report beside it,
# and the tracebom trace BOM.
BLINT_DATA = (
    Path(__file__).parent.parent / "packages" / "analysis-lib" / "tests" / "data" / "blint"
)
CDXGEN_DATA = (
    Path(__file__).parent.parent / "packages" / "analysis-lib" / "tests" / "data" / "cdxgen"
)
TRACEBOM_DATA = (
    Path(__file__).parent.parent / "packages" / "analysis-lib" / "tests" / "data" / "tracebom"
)

# The reached purls the trimmed dejacode fixture carries: the atom adapter
# turns its reachables slices into reached-flow records, and the engine counts
# exactly these purls.
DEJACODE_REACHED_PURLS = {
    "pkg:pypi/defusedxml@0.7.1",
    "pkg:pypi/django-axes@8.3.1",
    "pkg:pypi/django-crispy-forms@2.7",
    "pkg:pypi/django-guardian@3.5.2",
    "pkg:pypi/django-otp@1.7.5",
    "pkg:pypi/django-registration@5.2.1",
    "pkg:pypi/django@6.1.2",
    "pkg:pypi/license-expression@30.4.4",
    "pkg:pypi/odfdo@3.27.3",
    "pkg:pypi/qrcode@8.2",
    "pkg:pypi/requests@2.34.2",
}

# Real cdxgen usage evidence of the dejacode project, cut to two entries per
# component. The committed repotests fixture carries the same components
# without their evidence blocks; the wiring tests attach these to four of
# them (occurrences, a callstack only, and both shapes) so a scan has usage
# evidence to read into its store. Every value is the pinned BOM's own, with
# nothing rewritten: the locations are relative paths and carry no machine
# traces.
DEJACODE_USAGE_EVIDENCE = {
    "pkg:pypi/defusedxml@0.7.1": {
        "occurrences": [
            {"location": "component_catalog/management/commands/collectcpes.py", "line": 17},
            {"location": "component_catalog/management/commands/collectcpes.py", "line": 40},
        ],
        "callstack": {
            "frames": [
                {
                    "package": "",
                    "module": "component_catalog.management.commands.collectcpes.Command",
                    "function": "handle",
                    "line": 40,
                    "column": 31,
                    "fullFilename": "component_catalog/management/commands/collectcpes.py",
                },
                {
                    "package": "",
                    "module": "component_catalog.management.commands.collectcpes.Command",
                    "function": "handle",
                    "line": 41,
                    "column": 33,
                    "fullFilename": "component_catalog/management/commands/collectcpes.py",
                },
            ]
        },
    },
    "pkg:pypi/django-axes@8.3.1": {
        "callstack": {
            "frames": [
                {
                    "package": "",
                    "module": "",
                    "function": "notify_on_user_locked_out",
                    "line": 177,
                    "column": 31,
                    "fullFilename": "dje/notification.py",
                },
                {
                    "package": "",
                    "module": "",
                    "function": "notify_on_user_locked_out",
                    "line": 184,
                    "column": 35,
                    "fullFilename": "dje/notification.py",
                },
            ]
        }
    },
    "pkg:pypi/django-registration@5.2.1": {
        "occurrences": [
            {"location": "dejacode/urls.py", "line": 184},
            {"location": "dejacode/urls.py", "line": 190},
        ]
    },
    "pkg:pypi/requests@2.34.2": {
        "occurrences": [
            {"location": "aboutcode/notifications/models.py", "line": 17},
            {"location": "aboutcode/notifications/models.py", "line": 79},
        ]
    },
}

# The presence values a BOM-directory scan of the dejacode fixture gives with
# the usage evidence above attached and reachability off. The aggregated
# loader keeps only the identity evidences of each component, so usage
# never proves presence on such a scan: the values are likely or unlikely
# only, and proven comes from reach alone. They are pinned as literals, not
# recomputed by the code under test, so a regression in what the wiring
# feeds the axis cannot redefine them.
BOM_DIR_PRESENCE_WITH_REACHABILITY_OFF = {
    "pkg:pypi/defusedxml@0.7.1": "likely",
    "pkg:pypi/django-axes@8.3.1": "unlikely",
    "pkg:pypi/django-crispy-forms@2.7": "unlikely",
    "pkg:pypi/django-guardian@3.5.2": "unlikely",
    "pkg:pypi/django-otp@1.7.5": "likely",
    "pkg:pypi/django-registration@5.2.1": "likely",
    "pkg:pypi/django@6.1.2": "likely",
    "pkg:pypi/license-expression@30.4.4": "likely",
    "pkg:pypi/odfdo@3.27.3": "likely",
    "pkg:pypi/qrcode@8.2": "likely",
    "pkg:pypi/requests@2.34.2": "likely",
}

# The three binary-hardening findings the committed blint recording's checks
# become. The values were recorded from the recording and then checked by
# hand against it: every rule id, title, severity, binary path, exe type and
# finding id is the report's own value, the producer version is the one the
# blint-written SBOM's metadata.tools names, the fingerprints were verified
# to differ per binary, and the coverage is assessed because the recording's
# coverage report names no failed or skipped unit.
RECORDED_BINARY_FINDINGS = [
    {
        "id": "dsf1:5e6f5b7a9f96031b3bb1a8c1312b6af7cf34fd7d8deef3b704ffd74bf78a69f1",
        "category": "binary-hardening",
        "rule": "CHECK_CANARY",
        "title": "Missing Canary Protection",
        "severity": "medium",
        "coverage": {"state": "assessed"},
        "producer": {"name": "blint", "version": "4.0.1"},
        "locations": [{"binary": "corpus/fortified-libc-demo.elf"}],
        "properties": [
            {"name": "blint:exeType", "value": "genericbinary"},
            {"name": "blint:findingId", "value": "0d534158c6e6430c7b58b4afd945e25b"},
            {"name": "blint:exeName", "value": "corpus/fortified-libc-demo.elf"},
        ],
    },
    {
        "id": "dsf1:fba6581dd6ebe8ff5ffce5735cacca8b9219e1c7f196441fd468a75176ef59f6",
        "category": "binary-hardening",
        "rule": "CHECK_ABI_FLOOR",
        "title": (
            "Requires a Newer Runtime Than the Deployment Baseline (GLIBC floor 2.34 exceeds "
            "the built-in default baseline 2.28; set --glibc-baseline or BLINT_GLIBC_BASELINE "
            "to your deployment target to make this a policy finding)"
        ),
        "severity": "info",
        "coverage": {"state": "assessed"},
        "producer": {"name": "blint", "version": "4.0.1"},
        "locations": [{"binary": "corpus/fortified-libc-demo.elf"}],
        "properties": [
            {"name": "blint:exeType", "value": "genericbinary"},
            {"name": "blint:findingId", "value": "27ef6a560f059a570deb3930892a0e59"},
            {"name": "blint:exeName", "value": "corpus/fortified-libc-demo.elf"},
        ],
    },
    {
        "id": "dsf1:8269c8793a5d4bd0190139d6783ff309efeb4bb4394fc1c1e49e072727a375f2",
        "category": "binary-hardening",
        "rule": "CHECK_ABI_FLOOR",
        "title": (
            "Requires a Newer Runtime Than the Deployment Baseline (GLIBC floor 2.34 exceeds "
            "the built-in default baseline 2.28; set --glibc-baseline or BLINT_GLIBC_BASELINE "
            "to your deployment target to make this a policy finding)"
        ),
        "severity": "info",
        "coverage": {"state": "assessed"},
        "producer": {"name": "blint", "version": "4.0.1"},
        # The plain binary is the blint-written SBOM's metadata component,
        # so its record reconciles to that component's purl; the fortified
        # binary has no component in the SBOM.
        "components": ["pkg:generic/plain-libc-demo.elf"],
        "locations": [{"binary": "corpus/plain-libc-demo.elf"}],
        "properties": [
            {"name": "blint:exeType", "value": "genericbinary"},
            {"name": "blint:findingId", "value": "7353638ece12802f2859c401cfa1ade6"},
            {"name": "blint:exeName", "value": "corpus/plain-libc-demo.elf"},
        ],
    },
]


# The tool versions the fake scripts print, exactly as the doctor tests and
# the scan-directory tests fake them.
FAKE_TOOLS = {
    "cdxgen": ("CDXGEN_CMD", "CycloneDX Generator 13.8.0"),
    "golem": ("GOLEM_CMD", "golem 9.9.9"),
    "rusi": ("RUSI_CMD", "rusi 9.9.9"),
    "dosai": ("DOSAI_CMD", "dosai 9.9.9+deadbeef"),
    "kosi": ("KOSI_CMD", '{"name": "kosi", "version": "9.9.9"}'),
    "go": (None, "go version go9.9.9 test"),
    "dotnet": (None, "9.9.100"),
}


@pytest.fixture
def fake_tools(tmp_path, monkeypatch):
    """Install one fake per tool the reachability capabilities name, so the
    capability table never explains a missing report: what the analyzers
    then say is what their adapters said. The fakes live on a PATH of their
    own; everything else stays unreachable there."""
    empty_path = tmp_path / "stripped-path"
    empty_path.mkdir()
    for var in (
        "CDXGEN_PLUGINS_DIR",
        "CDXGEN_CMD",
        "GOLEM_CMD",
        "DEPSCAN_GOLEM_BINARY",
        "RUSI_CMD",
        "DEPSCAN_RUSI_BINARY",
        "DOSAI_CMD",
        "DEPSCAN_DOSAI_BINARY",
        "KOSI_CMD",
        "DEPSCAN_KOSI_BINARY",
    ):
        monkeypatch.delenv(var, raising=False)

    real_version_command = doctor_mod._version_command

    def version_command(path, args):
        try:
            with open(path, encoding="utf-8", errors="replace") as fp:
                is_fake = fp.readline().startswith("#!/usr/bin/env python3")
        except OSError:
            is_fake = False
        if is_fake:
            import sys

            return [sys.executable, str(path), *args]
        return real_version_command(path, args)

    monkeypatch.setattr(doctor_mod, "_version_command", version_command)
    fake_paths = {}
    for name, (env_name, output) in FAKE_TOOLS.items():
        script = tmp_path / f"fake-{name}.py"
        script.write_text(
            "#!/usr/bin/env python3\nimport sys\nprint({!r})\n".format(output),
            encoding="utf-8",
        )
        script.chmod(0o755)
        fake_paths[name] = str(script)
        if env_name:
            monkeypatch.setenv(env_name, str(script))
    real_find = doctor_mod.find_executable

    def find(name):
        return fake_paths.get(name) or real_find(name)

    monkeypatch.setattr(doctor_mod, "find_executable", find)
    monkeypatch.setenv("PATH", str(empty_path))
    monkeypatch.setenv("APPDATA", str(empty_path))


#: The package the stubbed matching stage reports a finding for: one of the
#: purls the dejacode fixture reaches, so the finding joins its evidence.
STUB_FINDING_PURL = "pkg:pypi/requests@2.34.2"

#: The purls the stubbed matching stage reports findings for. The default
#: names one purl; a test that grades every component of a fixture replaces
#: it through monkeypatch on this module.
STUB_FINDING_PURLS = (STUB_FINDING_PURL,)


def install_scan_stubs(patch):
    """Stub the database, the matching stage and the rendering of a scan.

    ``patch(target, name, value)`` installs each stub: ``monkeypatch.setattr``
    inside a test, plain ``setattr`` in the subprocess scans of the
    determinism test.
    """
    patch(vdb_setup, "resolve_scan_vdb_image", lambda args: ("oras://vdb", False, "app-only"))
    patch(vdb_setup, "vdb_download_needed", lambda url, d: (False, ""))
    patch(vdb_setup, "configure_vdb_readonly", lambda: None)
    patch(vdb_setup, "ensure_vdb_usable", lambda: None)
    patch(pipeline, "get_pkgs_by_scope", lambda pkg_list: {})

    class StubResult:
        success = True
        prioritized_pkg_vuln_trees = {}
        exploitability = None

        def __init__(self, pkg_vulnerabilities):
            self.pkg_vulnerabilities = pkg_vulnerabilities

    class StubVDRAnalyzer:
        def __init__(self, vdr_options):
            self.vdr_options = vdr_options

        def process(self):
            from analysis_lib.findings.exploitability import annotate_exploitability

            vulns = [
                {
                    "id": "CVE-2024-1111",
                    "bom-ref": f"CVE-2024-1111/{STUB_FINDING_PURLS[0]}",
                    "affects": [{"ref": purl} for purl in STUB_FINDING_PURLS],
                    "ratings": [{"severity": "high", "score": 8.1, "method": "CVSSv31"}],
                }
            ]
            result = StubResult(vulns)
            result.exploitability = annotate_exploitability(
                vulns, self.vdr_options.exploitability_inputs
            )
            return result

    patch(pipeline, "VDRAnalyzer", StubVDRAnalyzer)
    patch(pipeline.ReportGenerator, "parse_and_generate_report", lambda self: None)
    patch(pipeline.console, "save_html", lambda *a, **k: None)
    patch(pipeline.console, "save_text", lambda *a, **k: None)
    patch(doctor_mod, "_vdb_status", lambda: dict(_FULL_VDB_DATA))


@pytest.fixture
def scan_stubs(monkeypatch):
    """Stub the database, the matching stage and the rendering of a scan."""
    install_scan_stubs(monkeypatch.setattr)


_FULL_VDB_DATA = {
    "present": True,
    "directory": "/tmp/vdb",
    "image": "ghcr.io/appthreat/vdb7-app-only:v7.0.x-xz",
    "flavor": "app-only",
    "shards": {"enabled": False, "present": []},
    "createdUtc": "2026-11-01T00:00:00+00:00",
    "ageHours": 10.0,
    "stale": False,
    "maxAgeHours": 48,
    "cveDataCount": 100,
    "cveIndexCount": 100,
    "extendedMetadataPresent": False,
    "cveMetadataRows": 0,
}


def _scan_fixture(tmp_path, name, **overrides):
    """Copy one fixture project into a temporary BOM directory and scan it.

    The BOM directory copy is also the reports directory, the way a scan
    without an explicit reports directory treats its single BOM directory
    target, so the scan directory holds the VDR and can be loaded back.
    """
    bom_dir = tmp_path / name
    bom_dir.mkdir()
    for entry in (FIXTURES / name).iterdir():
        if entry.is_file():
            shutil.copy2(entry, bom_dir / entry.name)
    options = {
        "bom_dir": str(bom_dir),
        "reports_dir": str(bom_dir),
        "no_banner": True,
        "reachability_analyzer": "SemanticReachability",
    }
    options.update(overrides)
    return api.scan(api.scan_options(**options), render=False)


def _manifest_of(reports_dir):
    return json.loads((Path(reports_dir) / "depscan.manifest.json").read_text())


def _enrichment_stage(manifest):
    return next(stage for stage in manifest["stages"] if stage["name"] == "enrichment")


def _dejacode_with_evidence(tmp_path, name="dejacode"):
    """The dejacode fixture copied into a BOM directory, with the real usage
    evidence of ``DEJACODE_USAGE_EVIDENCE`` attached to its components, the
    shape the full pinned dejacode BOM carries and the committed trim drops."""
    bom_dir = tmp_path / name
    bom_dir.mkdir()
    for entry in (FIXTURES / "dejacode").iterdir():
        if entry.is_file():
            shutil.copy2(entry, bom_dir / entry.name)
    bom_path = bom_dir / "sbom-python.cdx.json"
    bom = json.loads(bom_path.read_text())
    for component in bom["components"]:
        evidence = DEJACODE_USAGE_EVIDENCE.get(component["purl"])
        if evidence is not None:
            component["evidence"] = evidence
    bom_path.write_text(json.dumps(bom))
    return bom_dir


def _evidence_producers_dir(tmp_path):
    """A BOM directory holding one report of each evidence producer: the
    cdxgen recording (a BOM with occurrences, callstacks and annotations,
    and the introspection report beside it), the blint review recordings
    under ``analysis/blint/`` with the blint-written SBOM, and the tracebom
    recording under ``analysis/tracebom/``."""
    bom_dir = tmp_path / "producers"
    (bom_dir / "analysis" / "blint").mkdir(parents=True)
    (bom_dir / "analysis" / "tracebom").mkdir(parents=True)
    shutil.copy2(CDXGEN_DATA / "sbom-python.cdx.json", bom_dir / "sbom-python.cdx.json")
    shutil.copy2(
        CDXGEN_DATA / "sbom-python.cdx.json.introspection.json",
        bom_dir / "sbom-python.cdx.json.introspection.json",
    )
    shutil.copy2(BLINT_DATA / "sbom-blint.json", bom_dir / "sbom-postbuild-binary.cdx.json")
    for name in ("findings.json", "reviews.json", "analysis-coverage.json"):
        shutil.copy2(BLINT_DATA / name, bom_dir / "analysis" / "blint" / name)
    shutil.copy2(
        TRACEBOM_DATA / "tracebom.json", bom_dir / "analysis" / "tracebom" / "tracebom.json"
    )
    return bom_dir


def _store_records(reports_dir):
    return [
        json.loads(line)
        for line in (Path(reports_dir) / "evidence.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]


def test_a_bom_dir_scan_writes_the_evidence_store_and_lists_it(scan_stubs, tmp_path):
    result = _scan_fixture(tmp_path, "dejacode")
    reports = Path(result.reports_dir)
    store = reports / "evidence.jsonl"
    index = reports / "evidence.index.json"
    assert store.is_file(), "the enrichment stage writes the store even before the findings exist"
    assert index.is_file(), "the finish stage writes the index after the findings exist"
    lines = store.read_text(encoding="utf-8").splitlines()
    assert lines, "the atom adapter produced records for the atom-only project"
    records = [json.loads(line) for line in lines]
    assert records == sorted(records, key=lambda r: r["id"]), "the store is sorted by id"
    index_document = json.loads(index.read_text())
    assert index_document["schemaVersion"] == "1"
    manifest = result.manifest
    assert manifest is not None
    digests = {entry["path"]: entry for entry in manifest["files"]}
    assert digests["evidence.jsonl"]["role"] == "evidence"
    assert digests["evidence.index.json"]["role"] == "evidence"
    assert digests["evidence.jsonl"]["producer"] == "dep-scan"
    for name in ("evidence.jsonl", "evidence.index.json"):
        expected = hashlib.sha256((reports / name).read_bytes()).hexdigest()
        assert digests[name]["sha256"] == expected
    enrichment = _enrichment_stage(manifest)
    assert enrichment["outputs"] == [{"file": "evidence.jsonl", "status": "completed"}]


def test_a_stale_converted_slice_in_a_bom_dir_is_never_atom_evidence(scan_stubs, tmp_path):
    """A BOM directory that an earlier dep-scan version scanned may still
    carry a converted language-tool slice (rust-, go- or dotnet-). Those
    files are no longer written or read, and atom's adapter must not adopt
    one as atom evidence: the stems filter excludes them, so the store holds
    no record sourced from the stale file and its purls stay unreached."""
    bom_dir = tmp_path / "dejacode"
    bom_dir.mkdir()
    for entry in (FIXTURES / "dejacode").iterdir():
        if entry.is_file():
            shutil.copy2(entry, bom_dir / entry.name)
    (bom_dir / "rust-reachables.slices.json").write_text(
        json.dumps(
            [
                {
                    "flows": [{"tags": "pkg:cargo/stale@9.9.9, rust"}],
                    "purls": ["pkg:cargo/stale@9.9.9"],
                }
            ]
        ),
        encoding="utf-8",
    )
    result = api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            reachability_analyzer="SemanticReachability",
            no_banner=True,
        )
    )
    records = [
        json.loads(line)
        for line in (Path(result.reports_dir) / "evidence.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert records, "the atom adapter produced records for the atom-only project"
    assert not any(r["source"] == "rust-reachables.slices.json" for r in records), (
        "a stale converted slice must not be read as atom's own output"
    )
    assert not any("pkg:cargo/stale@9.9.9" in r["subject"]["purls"] for r in records)


def test_a_rescan_of_a_reused_bom_dir_drops_deleted_reports_records(scan_stubs, tmp_path):
    """A reused BOM directory must not keep a previous scan's records for a
    report this scan no longer finds: the store is written from this scan's
    adapters alone, so deleting a slice file (or truncating it, which the
    atom adapter refuses) removes its records and its purls stop counting,
    exactly as the stale converted slices are cleared, never read."""
    bom_dir = tmp_path / "dejacode"
    bom_dir.mkdir()
    for entry in (FIXTURES / "dejacode").iterdir():
        if entry.is_file():
            shutil.copy2(entry, bom_dir / entry.name)
    options = {
        "bom_dir": str(bom_dir),
        "reports_dir": str(bom_dir),
        "reachability_analyzer": "SemanticReachability",
        "no_banner": True,
    }
    api.scan(api.scan_options(**options))
    store = json.loads(
        "["
        + ",".join(line for line in (bom_dir / "evidence.jsonl").read_text().splitlines() if line)
        + "]"
    )
    assert any(r["source"] == "python-usages.slices.json" for r in store)
    usages = bom_dir / "python-usages.slices.json"
    usages.unlink()
    api.scan(api.scan_options(**options))
    store = json.loads(
        "["
        + ",".join(line for line in (bom_dir / "evidence.jsonl").read_text().splitlines() if line)
        + "]"
    )
    assert not any(r["source"] == "python-usages.slices.json" for r in store), (
        "a deleted report's records must not survive the rescan"
    )
    # A report this scan cannot read is refused by the adapter; its records
    # must not survive either, so the engine cannot count stale evidence.
    (bom_dir / "python-reachables.slices.json").write_text("{ truncated")
    api.scan(api.scan_options(**options))
    store = json.loads(
        "["
        + ",".join(line for line in (bom_dir / "evidence.jsonl").read_text().splitlines() if line)
        + "]"
    )
    assert not any(r["source"] == "python-reachables.slices.json" for r in store), (
        "a report the adapter refused must leave no records behind"
    )


def test_the_same_scan_twice_writes_byte_identical_stores(scan_stubs, tmp_path):
    """Two scans of the same BOM directory produce the same evidence.jsonl
    and evidence.index.json byte for byte: the record ids are hashes of what
    the producers stated, so nothing run-dependent may leak into the store."""
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    for target in (first_dir, second_dir):
        target.mkdir()
        for entry in (FIXTURES / "dotnet-podcasts").iterdir():
            if entry.is_file():
                shutil.copy2(entry, target / entry.name)
    options = {
        "bom_dir": str(first_dir),
        "reports_dir": str(first_dir),
        "reachability_analyzer": "SemanticReachability",
        "no_banner": True,
    }
    api.scan(api.scan_options(**options))
    options.update(bom_dir=str(second_dir), reports_dir=str(second_dir))
    api.scan(api.scan_options(**options))
    for name in ("evidence.jsonl", "evidence.index.json"):
        first = (first_dir / name).read_bytes()
        second = (second_dir / name).read_bytes()
        assert first and first == second, f"{name} differs between two scans of the same input"


def test_the_engine_counts_the_fixture_purls_from_the_records(scan_stubs, tmp_path):
    from analysis_lib import ReachabilityAnalysisKV
    from analysis_lib.reachability import SemanticReachability

    result = _scan_fixture(tmp_path, "dejacode")
    opts = ReachabilityAnalysisKV(
        project_types=["bom"], src_dir=str(tmp_path), bom_dir=result.reports_dir
    )
    res = SemanticReachability(opts).process()
    assert set((res.reached_purls or {}).keys()) == DEJACODE_REACHED_PURLS


def test_analyzer_entries_come_from_the_adapter_results(scan_stubs, fake_tools, tmp_path):
    result = _scan_fixture(tmp_path, "dejacode")
    analyzers = {entry["name"]: entry for entry in _enrichment_stage(result.manifest)["analyzers"]}
    assert set(analyzers) == {"atom", "rusi", "golem", "kosi", "dosai"}
    assert analyzers["atom"]["status"] == "completed", "the adapter read the atom slices"
    assert analyzers["atom"]["capability"] == "reachability"
    for name in ("rusi", "golem", "kosi", "dosai"):
        assert analyzers[name]["status"] == "not-assessed", name
        assert f"no {name} report was found in the BOM directory" in analyzers[name]["reason"], (
            f"{name}: {analyzers[name]['reason']}"
        )


def test_a_dosai_bom_dir_scan_completes_dosai_from_the_raw_report(scan_stubs, tmp_path):
    result = _scan_fixture(tmp_path, "dotnet-podcasts")
    analyzers = {entry["name"]: entry for entry in _enrichment_stage(result.manifest)["analyzers"]}
    assert analyzers["dosai"]["status"] == "completed", (
        "the adapter found and read the dosai report in the BOM directory"
    )
    assert analyzers["atom"]["status"] == "not-assessed", "the .NET project carries no atom slices"
    # dosai's raw report and the record kinds it supports.
    store = Path(result.reports_dir) / "evidence.jsonl"
    kinds = {}
    for line in store.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if record["producer"]["name"] == "dosai":
            kinds[record["kind"]] = kinds.get(record["kind"], 0) + 1
    assert kinds.get("reached-flow"), "dosai's reachability became reached-flow records"
    assert kinds.get("entry-point"), "dosai's attack surface became entry-point records"
    assert kinds.get("exploit-chain"), "dosai's exploit chains became exploit-chain records"
    index_document = json.loads((Path(result.reports_dir) / "evidence.index.json").read_text())
    assert index_document["byComponent"], "the index maps the dosai purls to their records"


def test_a_just_scanned_directory_loads_and_reports(scan_stubs, tmp_path, capsys):
    from depscan.lib import report as report_lib

    result = _scan_fixture(tmp_path, "dejacode")
    loaded = api.load_scan(result.reports_dir)
    assert loaded.manifest is not None
    assert loaded.manifest["layoutVersion"] == "2.0"
    assert report_lib.run_report_command([str(result.reports_dir)]) == 0
    output = capsys.readouterr().out
    assert "layout" in output and "2.0" in output


def test_a_layout_1_scan_directory_of_a_just_scanned_dir_is_refused(scan_stubs, tmp_path):
    result = _scan_fixture(tmp_path, "dejacode")
    manifest_path = Path(result.reports_dir) / "depscan.manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["layoutVersion"] = "1.0"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    with pytest.raises(api.ScanError) as excinfo:
        api.load_scan(result.reports_dir)
    message = str(excinfo.value)
    assert "1.0" in message and "2.0" in message


def test_reachability_off_still_writes_a_store_without_reachability_records(scan_stubs, tmp_path):
    bom_dir = _dejacode_with_evidence(tmp_path)
    result = api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            no_banner=True,
            reachability_analyzer="off",
        ),
        render=False,
    )
    store = Path(result.reports_dir) / "evidence.jsonl"
    assert store.is_file()
    records = [json.loads(line) for line in store.read_text(encoding="utf-8").splitlines() if line]
    assert records, "the BOM's own usage records are still collected"
    assert {record["producer"]["name"] for record in records} == {"cdxgen"}, (
        "no reachability producer's records may appear with reachability off"
    )
    index = Path(result.reports_dir) / "evidence.index.json"
    assert index.is_file()
    index_document = json.loads(index.read_text())
    assert index_document["byComponent"], "the usage records are indexed"
    enrichment = _enrichment_stage(result.manifest)
    assert enrichment["status"] == "skipped"
    assert enrichment["analyzers"] == []


@pytest.mark.parametrize(
    "left_behind", [("evidence.jsonl", "evidence.index.json"), ("evidence.index.json",)]
)
def test_a_scan_that_never_reaches_enrichment_lists_no_earlier_evidence(
    scan_stubs, tmp_path, left_behind
):
    """A BOM directory scan whose BOM has no packages stops before the
    enrichment stage, so it writes no store. The store and index an earlier
    scan left in that directory must not be indexed and listed in the
    manifest as this scan's evidence, and an index left without its store
    must not survive either."""
    bom_dir = tmp_path / "empty"
    bom_dir.mkdir()
    (bom_dir / "sbom-python.cdx.json").write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []})
    )
    stale = {
        "schemaVersion": "1",
        "id": "ev-0000000000000001",
        "producer": {"name": "atom", "version": "x", "reportSchemaVersion": "unknown"},
        "kind": "reached-flow",
        "polarity": "positive",
        "subject": {"purls": ["pkg:pypi/stale@1.0"]},
        "source": "old.json",
        "locations": [],
        "caveats": [],
    }
    if "evidence.jsonl" in left_behind:
        (bom_dir / "evidence.jsonl").write_text(json.dumps(stale) + "\n")
    (bom_dir / "evidence.index.json").write_text(
        json.dumps({"schemaVersion": "1", "byComponent": {"pkg:pypi/stale@1.0": [stale["id"]]}})
    )
    result = api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            no_banner=True,
            reachability_analyzer="SemanticReachability",
        ),
        render=False,
    )
    assert result.manifest is not None
    stages = {stage["name"]: stage["status"] for stage in result.manifest["stages"]}
    assert stages["inventory"] == "skipped"
    assert "enrichment" not in stages
    listed = {entry["path"] for entry in result.manifest["files"]}
    assert "evidence.jsonl" not in listed and "evidence.index.json" not in listed
    assert not (bom_dir / "evidence.jsonl").exists()
    assert not (bom_dir / "evidence.index.json").exists()


def test_the_finding_joins_its_evidence_and_names_a_witness(scan_stubs, tmp_path):
    """The stubbed matching stage reports one finding for a package the
    fixture reaches. The finding must be graded on that package's records:
    the index maps the finding to them, and its exploitability names one of
    them, a reached-counted atom record with a path, as the witness."""
    result = _scan_fixture(tmp_path, "dejacode")
    assert len(result.findings) == 1, "the stubbed matching stage ran"
    finding = result.findings[0]
    assert finding["components"] == [STUB_FINDING_PURL]
    reports = Path(result.reports_dir)
    index = json.loads((reports / "evidence.index.json").read_text())
    joined = index["byFinding"][finding["id"]]
    assert joined, "the index joins the finding to the records of its package"
    records = {
        record["id"]: record
        for record in map(json.loads, (reports / "evidence.jsonl").read_text().splitlines())
    }
    assert set(joined) <= set(records)
    exploitability = finding["exploitability"]
    assert exploitability["axes"]["reach"] == "likely"
    witness = exploitability.get("witness")
    assert witness in joined, "the witness is one of the finding's own records"
    record = records[witness]
    assert record["producer"]["name"] == "atom"
    assert record["kind"] in ("reached-flow", "usage", "entry-point")
    assert record.get("path"), "a witness carries a path"
    assert STUB_FINDING_PURL in record["subject"]["purls"]


_SUBPROCESS_SCAN = """
import sys
sys.path.insert(0, sys.argv[1])
from test.test_evidence_wiring import install_scan_stubs
from depscan import api
install_scan_stubs(setattr)
for target in sys.argv[2:]:
    api.scan(
        api.scan_options(
            bom_dir=target,
            reports_dir=target,
            no_banner=True,
            reachability_analyzer="SemanticReachability",
        ),
        render=False,
    )
"""


def test_two_processes_with_different_hash_seeds_write_identical_stores(tmp_path):
    """Two scans of the same inputs in two interpreter processes, each with
    its own string hash seed, write byte-identical stores and indexes, so
    nothing in the record ids or the file order depends on set or dict
    iteration that hashing could reorder."""
    import os
    import subprocess
    import sys

    repo_root = Path(__file__).resolve().parent.parent
    runs = {}
    for seed in ("1", "2"):
        targets = []
        for name in ("dejacode", "dotnet-podcasts"):
            target = tmp_path / seed / name
            target.mkdir(parents=True)
            for entry in (FIXTURES / name).iterdir():
                if entry.is_file():
                    shutil.copy2(entry, target / entry.name)
            targets.append(str(target))
        env = {**os.environ, "PYTHONHASHSEED": seed}
        completed = subprocess.run(
            [sys.executable, "-c", _SUBPROCESS_SCAN, str(repo_root), *targets],
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr[-4000:]
        runs[seed] = targets
    for first, second in zip(runs["1"], runs["2"]):
        for name in ("evidence.jsonl", "evidence.index.json"):
            one = (Path(first) / name).read_bytes()
            two = (Path(second) / name).read_bytes()
            assert one and one == two, f"{name} of {Path(first).name} differs between processes"


def _is_absolute(path):
    return bool(path) and (path.startswith("/") or (len(path) > 1 and path[1] == ":"))


@pytest.mark.parametrize("name", ["dejacode", "dotnet-podcasts"])
def test_a_scans_records_carry_no_absolute_path(scan_stubs, tmp_path, name):
    """Every record of a real scan names its files relative to the scanned
    source and its source relative to the scan directory, so the store reads
    the same wherever the scan ran."""
    result = _scan_fixture(tmp_path, name)
    reports = Path(result.reports_dir)
    records = [json.loads(line) for line in (reports / "evidence.jsonl").read_text().splitlines()]
    assert records
    for record in records:
        assert not _is_absolute(record["source"]), record["source"]
        assert (reports / record["source"]).is_file(), record["source"]
        files = [location["file"] for location in record["locations"]]
        files += [node.get("file") for node in record.get("path") or [] if node.get("file")]
        for file_name in files:
            assert not _is_absolute(file_name), (record["id"], file_name)


def test_atom_sources_and_locations_follow_the_scan_and_source_directories(scan_stubs, tmp_path):
    """atom's records name their slices file relative to the BOM directory the
    scan read it from, subdirectory included, and a file name atom wrote as
    an absolute path under the scanned source becomes relative to it."""
    source = tmp_path / "project"
    bom_dir = tmp_path / "boms"
    (bom_dir / "sub").mkdir(parents=True)
    shutil.copy2(FIXTURES / "dejacode" / "sbom-python.cdx.json", bom_dir / "sbom-python.cdx.json")
    nodes = [
        {
            "id": index,
            "parentFileName": str(source / "app" / "views.py"),
            "parentMethodName": "view",
            "lineNumber": 10 + index,
            "fullName": f"step{index}",
        }
        for index in range(5)
    ]
    (bom_dir / "sub" / "python-reachables.slices.json").write_text(
        json.dumps([{"flows": nodes, "purls": [STUB_FINDING_PURL]}])
    )
    result = api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            src_dir_image=str(source),
            no_banner=True,
            reachability_analyzer="SemanticReachability",
        ),
        render=False,
    )
    records = [
        json.loads(line)
        for line in (Path(result.reports_dir) / "evidence.jsonl").read_text().splitlines()
    ]
    (record,) = [r for r in records if r["producer"]["name"] == "atom"]
    assert record["source"] == "sub/python-reachables.slices.json"
    assert record["locations"][0]["file"] == "app/views.py"
    assert {node["file"] for node in record["path"]} == {"app/views.py"}


def _absolute_slice_dir(tmp_path, name):
    """A BOM directory whose one atom flow names files by absolute paths
    under ``tmp_path/project``, the way a slice of an earlier run on another
    machine might."""
    source = tmp_path / "project"
    bom_dir = tmp_path / name
    bom_dir.mkdir(parents=True)
    shutil.copy2(FIXTURES / "dejacode" / "sbom-python.cdx.json", bom_dir / "sbom-python.cdx.json")
    nodes = [
        {
            "id": index,
            "parentFileName": str(source / "app" / "views.py"),
            "parentMethodName": "view",
            "lineNumber": 10 + index,
            "fullName": f"step{index}",
        }
        for index in range(5)
    ]
    (bom_dir / "python-reachables.slices.json").write_text(
        json.dumps([{"flows": nodes, "purls": [STUB_FINDING_PURL]}])
    )
    return source, bom_dir


def test_a_bom_dir_scan_without_src_does_not_depend_on_the_working_directory(
    scan_stubs, tmp_path, monkeypatch
):
    """The source option defaults to the working directory, which says
    nothing about where stored slices were generated. Two scans of the same
    BOM directory, one run from inside the tree the slices name and one
    from elsewhere, must write the same store."""
    source, bom_dir = _absolute_slice_dir(tmp_path, "boms")
    source.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    stores = []
    for cwd in (source, elsewhere):
        monkeypatch.chdir(cwd)
        api.scan(
            api.scan_options(
                bom_dir=str(bom_dir),
                reports_dir=str(bom_dir),
                no_banner=True,
                reachability_analyzer="SemanticReachability",
            ),
            render=False,
        )
        stores.append((bom_dir / "evidence.jsonl").read_bytes())
    assert stores[0] and stores[0] == stores[1]
    for line in stores[0].decode("utf-8").splitlines():
        record = json.loads(line)
        for location in record["locations"]:
            assert not _is_absolute(location["file"]), location["file"]


def test_stored_slices_are_not_gated_on_the_local_atom(scan_stubs, tmp_path, monkeypatch):
    """A BOM directory's slices were written by the atom of the run that
    produced them, not the one installed here. A local atom of another major
    must not refuse them: without a version in the BOM the records carry a
    schema-unknown caveat, and with one the BOM's version is the producer."""
    monkeypatch.setattr(pipeline, "_doctor_analyzer_version", lambda analyzer, ctx: "9.9.9")
    _source, bom_dir = _absolute_slice_dir(tmp_path, "unversioned")
    options = dict(no_banner=True, reachability_analyzer="SemanticReachability")
    api.scan(
        api.scan_options(bom_dir=str(bom_dir), reports_dir=str(bom_dir), **options), render=False
    )
    (record,) = [
        json.loads(line) for line in (bom_dir / "evidence.jsonl").read_text().splitlines()
    ]
    assert record["producer"]["version"] == "unknown"
    assert "schema-unknown" in {caveat["kind"] for caveat in record["caveats"]}

    _source, versioned = _absolute_slice_dir(tmp_path / "second", "versioned")
    bom_path = versioned / "sbom-python.cdx.json"
    bom = json.loads(bom_path.read_text())
    for tool in bom["metadata"]["tools"]["components"]:
        if tool.get("name") == "atom":
            tool["version"] = "4.0.2"
    bom_path.write_text(json.dumps(bom))
    api.scan(
        api.scan_options(bom_dir=str(versioned), reports_dir=str(versioned), **options),
        render=False,
    )
    (record,) = [
        json.loads(line) for line in (versioned / "evidence.jsonl").read_text().splitlines()
    ]
    assert record["producer"]["version"] == "4.0.2"
    assert record["producer"]["reportSchemaVersion"] == "4"
    assert "schema-unknown" not in {caveat["kind"] for caveat in record["caveats"]}


# --- the evidence producers beside the reachability analyzers -----------------------


def test_the_store_holds_records_of_every_evidence_producer(scan_stubs, tmp_path):
    """One BOM directory holding a report of each evidence producer writes a
    store with records from all three: the blint review's presence records
    (the checks negative, the capability reviews positive), the cdxgen BOM's
    occurrence, callstack, annotation and introspection records, and the
    tracebom runtime-trace records. Every record's source names a file of the
    scan directory, and the manifest lists the raw reports they came from."""
    bom_dir = _evidence_producers_dir(tmp_path)
    result = api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            no_banner=True,
            reachability_analyzer="SemanticReachability",
            techniques=["binary-analysis"],
        ),
        render=False,
    )
    records = _store_records(bom_dir)
    kinds_by_producer = {}
    for record in records:
        kinds_by_producer.setdefault(record["producer"]["name"], set()).add(record["kind"])
    assert kinds_by_producer.get("blint") == {"presence"}, "the review's two document kinds"
    assert {r["polarity"] for r in records if r["producer"]["name"] == "blint"} == {
        "negative",
        "positive",
    }, "a check is negative evidence, a capability review positive"
    assert {"occurrence", "callstack", "annotation", "introspection"} <= kinds_by_producer.get(
        "cdxgen", set()
    ), "the BOM's own evidence shapes and the introspection report beside it"
    assert kinds_by_producer.get("tracebom") == {"runtime-trace"}
    introspections = [r for r in records if r["kind"] == "introspection"]
    assert introspections and introspections[0]["producer"]["version"] == "13.9.0", (
        "the introspection record is versioned from the report's own cdxgen block"
    )
    for record in records:
        assert not _is_absolute(record["source"]), record["source"]
        assert (bom_dir / record["source"]).is_file(), record["source"]
    assert result.manifest is not None
    listed = {entry["path"] for entry in result.manifest["files"]}
    assert {"analysis/blint/findings.json", "analysis/tracebom/tracebom.json"} <= listed


def test_the_index_joins_a_finding_to_its_cdxgen_occurrence_record(scan_stubs, tmp_path):
    """A finding whose component carries usage evidence must join to the
    occurrence records of exactly that component: the index entry names the
    specific record ids, not merely a non-empty list."""
    bom_dir = _dejacode_with_evidence(tmp_path)
    result = api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            no_banner=True,
            reachability_analyzer="SemanticReachability",
        ),
        render=False,
    )
    (finding,) = result.findings
    assert finding["components"] == [STUB_FINDING_PURL]
    occurrence_ids = {
        record["id"]
        for record in _store_records(bom_dir)
        if record["producer"]["name"] == "cdxgen"
        and record["kind"] == "occurrence"
        and STUB_FINDING_PURL in record["subject"]["purls"]
    }
    assert occurrence_ids, "the store holds the cdxgen occurrence records of the finding's package"
    index = json.loads((bom_dir / "evidence.index.json").read_text())
    assert occurrence_ids <= set(index["byFinding"][finding["id"]]), (
        "the join must reach the specific occurrence records of the component"
    )


def test_bom_dir_presence_equals_the_recorded_stripped_values(scan_stubs, tmp_path, monkeypatch):
    """A BOM-directory scan of the dejacode fixture with usage evidence
    attached gives every component the values pinned in
    BOM_DIR_PRESENCE_WITH_REACHABILITY_OFF: the aggregated package list
    keeps only the identity evidences, so usage proves nothing there and
    presence is likely or unlikely, with proven reserved for reach. The
    BOM's usage records still reach the store (they are additive); only the
    grading skips them, so a wiring that fed them to the axis cannot pass
    this test, and neither can one that skipped the cdxgen adapter."""
    monkeypatch.setattr(
        sys.modules[__name__], "STUB_FINDING_PURLS", tuple(BOM_DIR_PRESENCE_WITH_REACHABILITY_OFF)
    )
    bom_dir = _dejacode_with_evidence(tmp_path)
    result = api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            no_banner=True,
            reachability_analyzer="off",
        ),
        render=False,
    )
    values = {
        finding["components"][0]: finding["exploitability"]["axes"]["presence"]
        for finding in result.findings
    }
    assert values == BOM_DIR_PRESENCE_WITH_REACHABILITY_OFF
    records = _store_records(bom_dir)
    assert any(
        record["kind"] == "occurrence"
        for record in records
        if record["producer"]["name"] == "cdxgen"
    ), "the usage records are still written to the store"

    # With reachability on, every component of this fixture is reached, and
    # presence is proven by reach alone: the stripped usage view costs
    # nothing there.
    reach_result = api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            no_banner=True,
            reachability_analyzer="SemanticReachability",
        ),
        render=False,
    )
    values = {
        finding["components"][0]: finding["exploitability"]["axes"]["presence"]
        for finding in reach_result.findings
    }
    assert set(values.values()) == {"proven"}


def test_source_scan_presence_proves_usage_from_the_records(scan_stubs, tmp_path, monkeypatch):
    """A source scan's package list keeps the components' evidence blocks,
    so its usage records grade: the component with occurrences is proven
    with reachability off, the optional component without evidence is
    unlikely and the required one without evidence stays likely. This is
    the other half of the asymmetry the BOM-directory test pins."""
    from depscan.lib.bom import BomResult

    src = tmp_path / "src"
    src.mkdir()
    reports = tmp_path / "reports"

    def fake_create_bom(bom_file, src_dir, options=None):
        document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "metadata": {"tools": {"components": [{"name": "cdxgen", "version": "13.9.0"}]}},
            "components": [
                {
                    "type": "library",
                    "name": "used",
                    "purl": "pkg:pypi/used@1.0",
                    "bom-ref": "pkg:pypi/used@1.0",
                    "scope": "required",
                    "evidence": {"occurrences": [{"location": "app.py", "line": 3}]},
                },
                {
                    "type": "library",
                    "name": "unused-optional",
                    "purl": "pkg:pypi/unused-optional@1.0",
                    "bom-ref": "pkg:pypi/unused-optional@1.0",
                    "scope": "optional",
                },
                {
                    "type": "library",
                    "name": "unused",
                    "purl": "pkg:pypi/unused@1.0",
                    "bom-ref": "pkg:pypi/unused@1.0",
                    "scope": "required",
                },
            ],
        }
        with open(bom_file, "w", encoding="utf-8") as fp:
            json.dump(document, fp)
        return BomResult(success=True, bom_files=[bom_file], primary=bom_file)

    monkeypatch.setattr(pipeline, "create_bom", fake_create_bom)
    monkeypatch.setattr(
        sys.modules[__name__],
        "STUB_FINDING_PURLS",
        ("pkg:pypi/used@1.0", "pkg:pypi/unused-optional@1.0", "pkg:pypi/unused@1.0"),
    )
    result = api.scan(
        api.scan_options(
            src_dir_image=str(src),
            reports_dir=str(reports),
            project_type=["python"],
            no_banner=True,
            reachability_analyzer="off",
        ),
        render=False,
    )
    values = {
        finding["components"][0]: finding["exploitability"]["axes"]["presence"]
        for finding in result.findings
    }
    assert values == {
        "pkg:pypi/used@1.0": "proven",
        "pkg:pypi/unused-optional@1.0": "unlikely",
        "pkg:pypi/unused@1.0": "likely",
    }


def test_the_binary_findings_equal_the_recorded_findings(scan_stubs, tmp_path):
    """The binary-hardening findings a scan writes from the blint records
    equal, id for id and field for field, the findings recorded from the
    blint recording and checked against it by hand: the fingerprints,
    severities, locations and properties are the report's own, and the
    producer version is the one the blint-written BOM's metadata.tools
    names. The same three findings are pinned field by field at the unit
    level in packages/analysis-lib/tests/test_blint_convert.py."""
    bom_dir = _evidence_producers_dir(tmp_path)
    result = api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            no_banner=True,
            reachability_analyzer="SemanticReachability",
            techniques=["binary-analysis"],
        ),
        render=False,
    )
    binary = [finding for finding in result.findings if finding["category"] == "binary-hardening"]
    expected = {finding["id"]: finding for finding in RECORDED_BINARY_FINDINGS}
    assert len(expected) == 3
    assert {finding["id"] for finding in binary} == set(expected)
    for finding in binary:
        assert finding == expected[finding["id"]], finding["id"]


def test_a_rescan_drops_the_records_of_reports_that_are_gone(scan_stubs, tmp_path):
    """A reused BOM directory must not keep the previous scan's records for a
    report this scan no longer finds: the store is written from this scan's
    adapters alone, so removing the blint and tracebom reports removes their
    records and the binary findings built from them."""
    bom_dir = _evidence_producers_dir(tmp_path)
    options = dict(
        bom_dir=str(bom_dir),
        reports_dir=str(bom_dir),
        no_banner=True,
        reachability_analyzer="SemanticReachability",
        techniques=["binary-analysis"],
    )
    first = api.scan(api.scan_options(**options), render=False)
    records = _store_records(bom_dir)
    assert any(record["producer"]["name"] == "blint" for record in records)
    assert any(record["producer"]["name"] == "tracebom" for record in records)
    assert any(f["category"] == "binary-hardening" for f in first.findings)
    shutil.rmtree(bom_dir / "analysis" / "blint")
    shutil.rmtree(bom_dir / "analysis" / "tracebom")
    second = api.scan(api.scan_options(**options), render=False)
    records = _store_records(bom_dir)
    assert not any(record["producer"]["name"] in ("blint", "tracebom") for record in records), (
        "a removed report's records must not survive the rescan"
    )
    assert any(record["producer"]["name"] == "cdxgen" for record in records), (
        "the BOM documents are still read"
    )
    assert not any(f["category"] == "binary-hardening" for f in second.findings), (
        "no binary findings may survive the records they were built from"
    )


def test_a_two_type_scan_keeps_each_types_records_and_caveats(scan_stubs, tmp_path, monkeypatch):
    """A scan of two project types collects each type's BOM evidence, and the
    second type's store write keeps the first type's records with their own
    caveats: the python type's BOM names a newer schema minor than the
    adapter knows, and its records keep that caveat after the java type's
    clean records are added."""
    from depscan.lib.bom import BomResult

    src = tmp_path / "src"
    src.mkdir()
    reports = tmp_path / "reports"

    def fake_create_bom(bom_file, src_dir, options=None):
        project_type = ((options or {}).get("project_type") or ["unknown"])[0]
        spec_version = "1.8" if project_type == "python" else "1.7"
        purl = (
            "pkg:pypi/idna@3.10"
            if project_type == "python"
            else "pkg:maven/io/netty/netty-common@4.2.5"
        )
        document = {
            "bomFormat": "CycloneDX",
            "specVersion": spec_version,
            "metadata": {"tools": {"components": [{"name": "cdxgen", "version": "13.9.0"}]}},
            "components": [
                {
                    "type": "library",
                    "name": purl.rsplit("/", 1)[-1],
                    "purl": purl,
                    "bom-ref": purl,
                    "evidence": {
                        "occurrences": [{"location": f"src/{project_type}/Main.java", "line": 3}]
                    },
                }
            ],
        }
        with open(bom_file, "w", encoding="utf-8") as fp:
            json.dump(document, fp)
        return BomResult(success=True, bom_files=[bom_file], primary=bom_file)

    monkeypatch.setattr(pipeline, "create_bom", fake_create_bom)
    api.scan(
        api.scan_options(
            src_dir_image=str(src),
            reports_dir=str(reports),
            project_type=["python", "java"],
            no_banner=True,
            reachability_analyzer="off",
        ),
        render=False,
    )
    records = _store_records(reports)
    assert {record["source"] for record in records} == {
        "sbom-python.cdx.json",
        "sbom-java.cdx.json",
    }, "each type's BOM evidence is collected"
    python_records = [r for r in records if r["source"] == "sbom-python.cdx.json"]
    java_records = [r for r in records if r["source"] == "sbom-java.cdx.json"]
    assert python_records and all(
        "schema-minor" in {caveat["kind"] for caveat in record["caveats"]}
        for record in python_records
    ), "the drifted BOM's records keep their schema-minor caveat"
    assert java_records and all(
        "schema-minor" not in {caveat["kind"] for caveat in record["caveats"]}
        for record in java_records
    )


def test_a_damaged_blint_report_is_reported_and_costs_its_records(scan_stubs, tmp_path, caplog):
    """A review report the blint adapter cannot read is reported as not
    assessed with the reason, contributes no records, and neither stops the
    scan nor the findings file: the binary findings are absent because there
    is nothing to build them from, never because the file was skipped."""
    bom_dir = _evidence_producers_dir(tmp_path)
    (bom_dir / "analysis" / "blint" / "findings.json").write_text("{not json")
    with caplog.at_level("WARNING", logger=pipeline.LOG.name):
        result = api.scan(
            api.scan_options(
                bom_dir=str(bom_dir),
                reports_dir=str(bom_dir),
                no_banner=True,
                reachability_analyzer="SemanticReachability",
                techniques=["binary-analysis"],
            ),
            render=False,
        )
    messages = [record.getMessage() for record in caplog.records]
    assert any("blint" in message and "not assessed" in message for message in messages), messages
    assert not any(record["producer"]["name"] == "blint" for record in _store_records(bom_dir)), (
        "a report the adapter refused leaves no records"
    )
    assert not any(f["category"] == "binary-hardening" for f in result.findings)
    assert (bom_dir / "depscan.findings.json").is_file()


def test_records_without_a_review_request_write_no_binary_findings(scan_stubs, tmp_path):
    """A BOM directory scan discovers the blint reports an earlier run left
    and records their evidence, but the findings document builds binary
    findings only when this scan requested the review: the gate is the
    request, exactly where it always was."""
    bom_dir = _evidence_producers_dir(tmp_path)
    result = api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            no_banner=True,
            reachability_analyzer="SemanticReachability",
        ),
        render=False,
    )
    assert any(record["producer"]["name"] == "blint" for record in _store_records(bom_dir)), (
        "the BOM directory's review reports are recorded"
    )
    assert not any(f["category"] == "binary-hardening" for f in result.findings)


def test_a_non_utf8_json_in_a_bom_dir_does_not_stop_the_scan(scan_stubs, tmp_path):
    """A .json file with non-UTF-8 bytes at the top level of a BOM directory
    is read by the trace BOM discovery before any adapter guards it, so the
    read itself must degrade: the file is reported as unreadable, and the
    scan completes with the healthy BOM's records."""
    bom_dir = tmp_path / "boms"
    bom_dir.mkdir()
    shutil.copy2(CDXGEN_DATA / "sbom-python.cdx.json", bom_dir / "sbom-python.cdx.json")
    (bom_dir / "notes.json").write_bytes(b'\xff\xfe{"not": "utf-8 text"}')
    result = api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            no_banner=True,
            reachability_analyzer="SemanticReachability",
        ),
        render=False,
    )
    assert result.manifest is not None, "the scan completed"
    assert any(record["producer"]["name"] == "cdxgen" for record in _store_records(bom_dir)), (
        "the healthy BOM's records are still collected"
    )


def test_a_deeply_nested_json_in_a_bom_dir_does_not_stop_the_scan(scan_stubs, tmp_path):
    """A .json file at the top level of a BOM directory that nests deeper
    than the JSON parser reaches is read by the trace BOM discovery: it is
    not a trace BOM, and the discovery goes on, so the trace BOM the
    directory does hold and the healthy BOM are both recorded."""
    bom_dir = tmp_path / "boms"
    (bom_dir / "analysis" / "tracebom").mkdir(parents=True)
    shutil.copy2(CDXGEN_DATA / "sbom-python.cdx.json", bom_dir / "sbom-python.cdx.json")
    shutil.copy2(
        TRACEBOM_DATA / "tracebom.json", bom_dir / "analysis" / "tracebom" / "tracebom.json"
    )
    # Deep enough to exhaust the parser's stack on every supported Python:
    # the C decoder of 3.15 guards its stack rather than the recursion limit.
    depth = 200_000
    (bom_dir / "deep.json").write_text("[" * depth + "]" * depth, encoding="utf-8")
    result = api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            no_banner=True,
            reachability_analyzer="SemanticReachability",
        ),
        render=False,
    )
    assert result.manifest is not None, "the scan completed"
    producers = {record["producer"]["name"] for record in _store_records(bom_dir)}
    assert {"cdxgen", "tracebom"} <= producers


def test_one_damaged_bom_does_not_cost_the_healthy_boms_records(scan_stubs, tmp_path):
    """A BOM document the cdxgen adapter refuses (truncated JSON) costs its
    own records alone: the healthy document's records survive, each carrying
    a record-skipped caveat naming the refused file and the reason, so a
    damaged BOM in a directory of healthy ones never zeroes the usage
    evidence."""
    bom_dir = tmp_path / "boms"
    bom_dir.mkdir()
    shutil.copy2(CDXGEN_DATA / "sbom-python.cdx.json", bom_dir / "sbom-python.cdx.json")
    (bom_dir / "sbom-broken.cdx.json").write_text("{ truncated")
    api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            no_banner=True,
            reachability_analyzer="SemanticReachability",
        ),
        render=False,
    )
    records = [record for record in _store_records(bom_dir)]
    sources = {record["source"] for record in records}
    assert "sbom-python.cdx.json" in sources, "the healthy BOM's records survive"
    assert "sbom-broken.cdx.json" not in sources, "the damaged BOM leaves no records"
    healthy = [record for record in records if record["source"] == "sbom-python.cdx.json"]
    assert healthy
    skipped = [
        caveat
        for record in healthy
        for caveat in record["caveats"]
        if caveat["kind"] == "record-skipped"
    ]
    assert skipped and all("sbom-broken.cdx.json" in caveat["detail"] for caveat in skipped), (
        "the surviving records name the refused file and the reason"
    )


def test_a_source_scan_without_a_review_request_ignores_stale_blint_reports(
    scan_stubs, tmp_path, monkeypatch
):
    """A source scan that did not ask for the binary review must not read the
    analysis/blint/ reports an earlier binary scan left in the reused reports
    directory: no blint records enter the store and no binary findings are
    written, however fresh the files look."""
    from depscan.lib.bom import BomResult

    src = tmp_path / "src"
    src.mkdir()
    reports = tmp_path / "reports"
    stale = reports / "analysis" / "blint"
    stale.mkdir(parents=True)
    for name in ("findings.json", "reviews.json"):
        shutil.copy2(BLINT_DATA / name, stale / name)
    shutil.copy2(BLINT_DATA / "sbom-blint.json", reports / "sbom-postbuild-binary.cdx.json")

    def fake_create_bom(bom_file, src_dir, options=None):
        document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "metadata": {"tools": {"components": [{"name": "cdxgen", "version": "13.9.0"}]}},
            "components": [
                {
                    "type": "library",
                    "name": "used",
                    "purl": "pkg:pypi/used@1.0",
                    "bom-ref": "pkg:pypi/used@1.0",
                    "scope": "required",
                }
            ],
        }
        with open(bom_file, "w", encoding="utf-8") as fp:
            json.dump(document, fp)
        return BomResult(success=True, bom_files=[bom_file], primary=bom_file)

    monkeypatch.setattr(pipeline, "create_bom", fake_create_bom)
    result = api.scan(
        api.scan_options(
            src_dir_image=str(src),
            reports_dir=str(reports),
            project_type=["python"],
            no_banner=True,
            reachability_analyzer="off",
        ),
        render=False,
    )
    assert not any(record["producer"]["name"] == "blint" for record in _store_records(reports)), (
        "an earlier scan's review reports must not become this scan's evidence"
    )
    assert not any(f["category"] == "binary-hardening" for f in result.findings)
    assert (reports / "analysis" / "blint" / "findings.json").is_file(), "the files stay put"


# ---------------------------------------------------------------------------
# Usage provenance, refused BOMs, review findings and trace inputs
# ---------------------------------------------------------------------------

#: A cdxgen BOM whose components carry each usage shape the presence axis
#: reads, plus the components the package loader leaves out: a nested
#: ``application`` and a top-level ``data`` twin of a library, both with
#: occurrences of their own.
USAGE_COMPONENTS = [
    {
        "type": "library",
        "name": "occ",
        "purl": "pkg:pypi/occ@1.0",
        "bom-ref": "pkg:pypi/occ@1.0",
        "evidence": {"occurrences": [{"location": "app.py", "line": 3}]},
    },
    {
        "type": "library",
        "name": "cs",
        "purl": "pkg:pypi/cs@1.0",
        "bom-ref": "pkg:pypi/cs@1.0",
        "evidence": {
            "callstack": {"frames": [{"fullFilename": "app.py", "line": 4, "function": "f"}]}
        },
    },
    {"type": "library", "name": "plain", "purl": "pkg:pypi/plain@1.0", "bom-ref": "plain"},
    {
        "type": "library",
        "name": "parent",
        "purl": "pkg:pypi/parent@1.0",
        "bom-ref": "pkg:pypi/parent@1.0",
        "components": [
            {
                "type": "application",
                "name": "napp",
                "purl": "pkg:pypi/napp@1.0",
                "bom-ref": "pkg:pypi/napp@1.0",
                "evidence": {"occurrences": [{"location": "app.py", "line": 13}]},
            }
        ],
    },
    {
        "type": "data",
        "name": "dd",
        "purl": "pkg:pypi/dd@1.0",
        "bom-ref": "dd-data",
        "evidence": {"occurrences": [{"location": "app.py", "line": 15}]},
    },
    {"type": "library", "name": "dd", "purl": "pkg:pypi/dd@1.0", "bom-ref": "dd-lib"},
]

#: The presence values these components grade to on every scan whose
#: package list keeps their evidence: a source scan, a ``--bom`` scan, and
#: a user BOM appended to an aggregating scan. The excluded components'
#: usage proves nothing, so ``napp`` and ``dd`` stay likely. The values were
#: checked against a run that read the components' evidence blocks directly
#: and are pinned as literals, not recomputed by the code under test.
USAGE_PRESENCE = {
    "pkg:pypi/occ@1.0": "proven",
    "pkg:pypi/cs@1.0": "proven",
    "pkg:pypi/plain@1.0": "likely",
    "pkg:pypi/napp@1.0": "likely",
    "pkg:pypi/dd@1.0": "likely",
}


def _usage_bom(spec_version="1.7"):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "metadata": {"tools": {"components": [{"name": "cdxgen", "version": "13.9.0"}]}},
        "components": json.loads(json.dumps(USAGE_COMPONENTS)),
    }


def _source_scan_of(document, tmp_path, monkeypatch, **options):
    """A source scan whose BOM generation writes ``document``."""
    from depscan.lib.bom import BomResult

    src = tmp_path / "src"
    src.mkdir(exist_ok=True)

    def fake_create_bom(bom_file, src_dir, options=None):
        with open(bom_file, "w", encoding="utf-8") as fp:
            json.dump(document, fp)
        return BomResult(success=True, bom_files=[bom_file], primary=bom_file)

    monkeypatch.setattr(pipeline, "create_bom", fake_create_bom)
    settings = {
        "src_dir_image": str(src),
        "reports_dir": str(tmp_path / "reports"),
        "project_type": ["python"],
        "no_banner": True,
        "reachability_analyzer": "off",
    }
    settings.update(options)
    return api.scan(api.scan_options(**settings), render=False)


def _presence(result):
    return {
        finding["components"][0]: finding["exploitability"]["axes"]["presence"]
        for finding in result.findings
        if finding["category"] == "vulnerability"
    }


@pytest.mark.parametrize(
    "analyzers",
    [
        {"reachability_analyzer": "off"},
        {"reachability_analyzer": "SemanticReachability"},
        {"reachability_analyzer": "off", "vuln_analyzer": "LifecycleAnalyzer"},
    ],
    ids=["plain", "semantic", "lifecycle"],
)
def test_a_user_bom_keeps_its_usage_proof_on_every_analyzer(
    scan_stubs, tmp_path, monkeypatch, analyzers
):
    """A ``--bom`` scan proves usage from the BOM's records whichever
    analyzer runs. SemanticReachability and the LifecycleAnalyzer aggregate
    the reports directory and append the user BOM, which lies outside it,
    with its components whole; those components keep their usage proof
    exactly as a plain ``--bom`` scan does."""
    monkeypatch.setattr(sys.modules[__name__], "STUB_FINDING_PURLS", tuple(USAGE_PRESENCE))
    bom = tmp_path / "given" / "user.cdx.json"
    bom.parent.mkdir()
    bom.write_text(json.dumps(_usage_bom()), encoding="utf-8")
    result = api.scan(
        api.scan_options(
            bom=str(bom), reports_dir=str(tmp_path / "reports"), no_banner=True, **analyzers
        ),
        render=False,
    )
    assert _presence(result) == USAGE_PRESENCE


def test_a_source_scan_grades_only_the_loaded_components_usage(scan_stubs, tmp_path, monkeypatch):
    """The usage records of components the package loader leaves out (a
    nested application, a top-level data twin) prove nothing, even though
    the adapter records them: the finding of a loaded package with the same
    purl reads the loaded component alone."""
    monkeypatch.setattr(sys.modules[__name__], "STUB_FINDING_PURLS", tuple(USAGE_PRESENCE))
    result = _source_scan_of(_usage_bom(), tmp_path, monkeypatch)
    assert _presence(result) == USAGE_PRESENCE
    occurrences = {
        record["subject"]["purls"][0]
        for record in _store_records(tmp_path / "reports")
        if record["kind"] == "occurrence"
    }
    assert {"pkg:pypi/napp@1.0", "pkg:pypi/dd@1.0"} <= occurrences, (
        "the excluded components' records still reach the store"
    )


def test_a_bom_the_adapter_refuses_names_the_reason_on_the_findings(
    scan_stubs, tmp_path, monkeypatch
):
    """A BOM whose spec major cdxgen's adapter does not read loads its
    packages, but its usage evidence is not assessed: presence stays at the
    database match, and each finding whose presence is not proven names the
    adapter's reason in its coverage, so likely never reads as usage
    measured and not found."""
    monkeypatch.setattr(sys.modules[__name__], "STUB_FINDING_PURLS", tuple(USAGE_PRESENCE))
    result = _source_scan_of(_usage_bom(spec_version="2.0"), tmp_path, monkeypatch)
    assert set(_presence(result).values()) == {"likely"}
    reasons = {}
    for finding in result.findings:
        assert finding["coverage"]["state"] == "assessed"
        reasons[finding["components"][0]] = finding["coverage"].get("reasons")
    # The nested application is not a package the loader kept from that
    # BOM, so its usage could never have proven anything there.
    assert reasons.pop("pkg:pypi/napp@1.0") is None
    for ref, found in reasons.items():
        assert found is not None, ref
        (reason,) = found
        assert reason["capability"] == "presence:usage"
        assert reason["reason"] == "report-not-assessed"
        assert "sbom-python.cdx.json" in reason["detail"] and "2.0" in reason["detail"]


def test_a_bom_the_adapter_reads_names_no_usage_reason(scan_stubs, tmp_path, monkeypatch):
    """The same BOM at a spec version the adapter reads carries no coverage
    reason on any finding."""
    monkeypatch.setattr(sys.modules[__name__], "STUB_FINDING_PURLS", tuple(USAGE_PRESENCE))
    result = _source_scan_of(_usage_bom(), tmp_path, monkeypatch)
    assert all("reasons" not in finding["coverage"] for finding in result.findings)


def test_a_source_scan_reads_no_trace_bom_left_in_its_reports_dir(
    scan_stubs, tmp_path, monkeypatch
):
    """dep-scan never runs tracebom, so a trace BOM in a source scan's
    reports directory was left by an earlier run or another tool: the scan
    records nothing from it."""
    stale = tmp_path / "reports" / "analysis" / "tracebom"
    stale.mkdir(parents=True)
    shutil.copy2(TRACEBOM_DATA / "tracebom.json", stale / "old-run.json")
    _source_scan_of(_usage_bom(), tmp_path, monkeypatch)
    producers = {record["producer"]["name"] for record in _store_records(tmp_path / "reports")}
    assert "tracebom" not in producers
    assert "cdxgen" in producers


def _blint_writing_bom(components, prefix):
    """A BOM generation that writes the blint recording the way a binary
    scan's review leaves it: the blint-written SBOM (with ``components``
    replaced) and the three review reports under ``analysis/blint/``, their
    binary paths spelled under ``prefix(src_dir)``."""
    from depscan.lib.bom import BomResult

    def fake_create_bom(bom_file, src_dir, options=None):
        sbom = json.loads((BLINT_DATA / "sbom-blint.json").read_text(encoding="utf-8"))
        if components is not None:
            sbom["components"] = components
        Path(bom_file).write_text(json.dumps(sbom), encoding="utf-8")
        reviews = Path(bom_file).parent / "analysis" / "blint"
        reviews.mkdir(parents=True, exist_ok=True)
        for name in ("findings.json", "reviews.json", "analysis-coverage.json"):
            text = (BLINT_DATA / name).read_text(encoding="utf-8")
            text = text.replace('"corpus/', '"' + prefix(src_dir) + "corpus/")
            (reviews / name).write_text(text, encoding="utf-8")
        return BomResult(success=True, bom_files=[bom_file], primary=bom_file)

    return fake_create_bom


def _binary_findings(result):
    return [finding for finding in result.findings if finding["category"] == "binary-hardening"]


def test_review_findings_survive_a_blint_bom_without_components(scan_stubs, tmp_path, monkeypatch):
    """A blint-written BOM that lists no components (a static or stripped
    binary) leaves the type with no packages, so it never reaches the
    enrichment stage. The review still ran: its records are collected where
    the review ran and its findings are the recorded ones."""
    src = tmp_path / "src"
    src.mkdir()
    monkeypatch.setattr(
        pipeline,
        "create_bom",
        _blint_writing_bom([], lambda src_dir: os.path.abspath(src_dir) + "/"),
    )
    result = api.scan(
        api.scan_options(
            src_dir_image=str(src),
            reports_dir=str(tmp_path / "reports"),
            project_type=["binary"],
            no_banner=True,
            reachability_analyzer="off",
        ),
        render=False,
    )
    assert result.manifest is not None
    stages = {stage["name"]: stage["status"] for stage in result.manifest["stages"]}
    assert stages["inventory"] == "skipped" and "enrichment" not in stages
    expected = {finding["id"]: finding for finding in RECORDED_BINARY_FINDINGS}
    binary = _binary_findings(result)
    assert {finding["id"] for finding in binary} == set(expected)
    assert any(
        record["producer"]["name"] == "blint" for record in _store_records(tmp_path / "reports")
    ), "the review's records reach the store"


def test_a_relative_source_directory_keeps_the_binary_finding_ids(
    scan_stubs, tmp_path, monkeypatch
):
    """``-i bins`` relative to the working directory gives the same binary
    finding ids as the absolute path: the scan root is resolved before any
    adapter relativizes the review's paths, which name the binaries under
    the absolute directory the review walked."""
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        pipeline,
        "create_bom",
        _blint_writing_bom(None, lambda src_dir: os.path.abspath(src_dir) + "/"),
    )
    result = api.scan(
        api.scan_options(
            src_dir_image="src",
            reports_dir="reports",
            project_type=["binary"],
            no_banner=True,
            reachability_analyzer="off",
        ),
        render=False,
    )
    expected = {finding["id"] for finding in RECORDED_BINARY_FINDINGS}
    assert {finding["id"] for finding in _binary_findings(result)} == expected


def test_each_bom_is_read_once_by_the_evidence_producers(scan_stubs, tmp_path, monkeypatch):
    """The BOM documents of a type are read and parsed once however many
    evidence producers need them: cdxgen's adapter, the blint version and
    root component lookups, atom's version lookup and the trace BOM
    detection all share the parse."""
    bom_dir = _evidence_producers_dir(tmp_path)
    reads = []
    real_read = pipeline._read_report_text

    def counting_read(path):
        reads.append(os.path.basename(str(path)))
        return real_read(path)

    monkeypatch.setattr(pipeline, "_read_report_text", counting_read)
    api.scan(
        api.scan_options(
            bom_dir=str(bom_dir),
            reports_dir=str(bom_dir),
            no_banner=True,
            reachability_analyzer="SemanticReachability",
            techniques=["binary-analysis"],
        ),
        render=False,
    )
    assert reads.count("sbom-python.cdx.json") == 1
    assert reads.count("sbom-postbuild-binary.cdx.json") == 1
