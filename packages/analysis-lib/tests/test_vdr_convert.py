"""Tests for the VDR-to-findings conversion in analysis_lib.findings."""

import pytest
from jsonschema import Draft202012Validator

from analysis_lib.findings.fingerprint import finding_fingerprint
from analysis_lib.findings.model import Finding
from analysis_lib.findings.schemas import load_schema, validate
from analysis_lib.findings.vdr_convert import (
    finding_from_vdr,
    findings_from_vdr,
    highest_severity,
)

VULN = {
    "id": "CVE-2024-1111",
    "bom-ref": "CVE-2024-1111/pkg:pypi/requests@2.32.1",
    "affects": [{"ref": "pkg:pypi/requests@2.32.1"}],
    "ratings": [
        {"severity": "low", "score": 3.1, "method": "CVSSv31"},
        {"severity": "high", "score": 8.1, "method": "CVSSv31"},
    ],
    "fixed_location": "2.32.2",
    "advisories": [
        {"title": "NVD entry", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1111"}
    ],
    "cwes": [400, 400, "not-a-number"],
    "properties": [{"name": "depscan:prioritized", "value": "true"}],
}


def test_one_finding_per_advisory_and_component():
    vuln = dict(VULN)
    vuln["affects"] = [{"ref": "pkg:pypi/requests@2.32.1"}, {"ref": "pkg:pypi/urllib3@2.2.0"}]
    findings = findings_from_vdr([vuln], producer_version="7.0.0.dev0")
    assert len(findings) == 2
    components = [finding.components for finding in findings]
    assert components == [
        ["pkg:pypi/requests@2.32.1"],
        ["pkg:pypi/urllib3@2.2.0"],
    ]
    # Each id is the fingerprint of the (advisory, component) pair.
    for finding in findings:
        pair_components = finding.components
        assert pair_components is not None
        assert finding.id == finding_fingerprint("vulnerability", "CVE-2024-1111", pair_components)


def test_entry_without_affects_produces_no_finding():
    assert findings_from_vdr([{"id": "CVE-1"}], producer_version="1") == []
    assert findings_from_vdr([], producer_version="1") == []


def test_finding_validates_against_the_schema():
    finding = finding_from_vdr(VULN, "pkg:pypi/requests@2.32.1", producer_version="7.0.0.dev0")
    validate("finding", finding.to_dict())


def test_fields_carry_the_entry_knowledge():
    finding = finding_from_vdr(VULN, "pkg:pypi/requests@2.32.1", producer_version="7.0.0.dev0")
    assert isinstance(finding, Finding)
    assert finding.category == "vulnerability"
    assert finding.rule == "CVE-2024-1111"
    assert finding.severity == "high"
    assert finding.coverage.state == "assessed"
    assert finding.producer.name == "dep-scan"
    assert finding.producer.version == "7.0.0.dev0"
    fix = finding.fix
    assert fix is not None and fix.fixed_versions == ["2.32.2"]
    references = finding.references
    assert references is not None
    assert references[0].url == "https://nvd.nist.gov/vuln/detail/CVE-2024-1111"
    assert references[0].type == "advisory"
    assert finding.cwes == [400]
    properties = finding.properties
    assert properties is not None and properties[0].name == "depscan:prioritized"
    assert finding.title == "CVE-2024-1111 affects pkg:pypi/requests@2.32.1"


def test_two_entries_differing_only_in_component_version_share_the_fingerprint():
    other = dict(VULN)
    other["affects"] = [{"ref": "pkg:pypi/requests@2.30.0"}]
    findings = findings_from_vdr([VULN, other], producer_version="7.0.0.dev0")
    assert findings[0].id == findings[1].id, "the fingerprint leaves the version out"
    assert [f.components for f in findings] == [
        ["pkg:pypi/requests@2.32.1"],
        ["pkg:pypi/requests@2.30.0"],
    ], "each version the project ships keeps its own finding"


def test_a_repeated_advisory_and_component_pair_collapses():
    findings = findings_from_vdr([VULN, dict(VULN)], producer_version="7.0.0.dev0")
    assert len(findings) == 1


def test_fixed_versions_come_from_the_unaffected_versions_too():
    vuln = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "affects": [
            {
                "ref": "pkg:npm/lodash@4.17.20",
                "versions": [
                    {"range": "< 4.17.21", "status": "affected"},
                    {"version": "4.17.21", "status": "unaffected"},
                ],
            }
        ],
    }
    fixed = finding_from_vdr(vuln, "pkg:npm/lodash@4.17.20", producer_version="1")
    assert fixed.fix is not None
    assert fixed.fix.fixed_versions == ["4.17.21"]
    unresolved = finding_from_vdr(
        {"id": "CVE-1", "affects": []}, "pkg:npm/lodash@4.17.20", producer_version="1"
    )
    assert unresolved.fix is None


def test_unresolved_finding_fields_stay_out_of_the_json():
    vuln = {"id": "CVE-1", "affects": [{"ref": "pkg:npm/a@1"}]}
    document = finding_from_vdr(vuln, "pkg:npm/a@1", producer_version="1").to_dict()
    assert set(document) == {
        "id",
        "category",
        "rule",
        "title",
        "severity",
        "coverage",
        "producer",
        "components",
    }
    assert document["severity"] == "unknown"
    assert "fix" not in document and "references" not in document


def test_entries_without_an_advisory_id_are_rejected():
    with pytest.raises(ValueError) as excinfo:
        findings_from_vdr([{"id": "", "affects": [{"ref": "pkg:npm/a@1"}]}], producer_version="1")
    assert "advisory id" in str(excinfo.value)


def test_invalid_component_refs_are_rejected():
    with pytest.raises(ValueError) as excinfo:
        findings_from_vdr(
            [{"id": "CVE-1", "affects": [{"ref": "not-a-purl"}]}], producer_version="1"
        )
    assert "not-a-purl" in str(excinfo.value)


@pytest.mark.parametrize(
    "ratings,expected",
    [
        ([{"severity": "critical", "score": 9.8}], "critical"),
        ([{"severity": "LOW", "score": 3.1}], "low"),
        ([{"severity": "none"}], "info"),
        ([{"severity": "unspecified"}], "unknown"),
        ([], "unknown"),
        ([{"severity": "high", "score": 8.1}, {"severity": "medium", "score": 9.0}], "high"),
        ([{"severity": "medium"}, {"severity": "medium", "score": 5.0}], "medium"),
    ],
)
def test_highest_severity(ratings, expected):
    assert highest_severity({"ratings": ratings}) == expected


def test_finding_schema_publishes_the_severity_names_the_conversion_emits():
    published = load_schema("finding")["properties"]["severity"]["enum"]
    for name in ("critical", "high", "medium", "low", "info", "unknown"):
        assert name in published


def test_every_produced_document_validates_with_the_published_validator():
    validator = Draft202012Validator(load_schema("finding"))
    cases = [
        ("pkg:pypi/requests@2.32.1", VULN),
        ("pkg:npm/a@1", {"id": "CVE-1", "affects": [{"ref": "pkg:npm/a@1"}]}),
    ]
    for ref, vuln in cases:
        finding = finding_from_vdr(vuln, ref, producer_version="1")
        errors = list(validator.iter_errors(finding.to_dict()))
        assert not errors


# ---------------------------------------------------------------------------
# exploitability from the scan's graded evidence
# ---------------------------------------------------------------------------

from analysis_lib.evidence import EvidenceProducer  # noqa: E402
from analysis_lib.evidence.adapters import build_record  # noqa: E402
from analysis_lib.findings.exploitability import (  # noqa: E402
    ExploitabilityInputs,
    exploitability_for,
    load_rules,
)
from analysis_lib.findings.vdr_convert import (  # noqa: E402
    ReachScope,
    reach_axis,
    reached_by_analyzer,
)

REF = "pkg:pypi/requests@2.32.1"
OTHER = "pkg:pypi/urllib3@2.2.0"

ATOM_PYPI = {"atom": {"pypi"}}

RULES = load_rules()


def _exploitability(finding):
    assert finding.exploitability is not None
    return finding.exploitability


def _reach(finding):
    return _exploitability(finding).axes.reach


def _inputs(scope, ref=REF, **kwargs):
    return ExploitabilityInputs(rules=RULES, scope=scope, **kwargs)


def _graded_findings(scope, ref=REF, **kwargs):
    """The findings a scan writes when it graded ``ref`` under ``scope``."""
    inputs = _inputs(scope, ref, **kwargs)
    graded = exploitability_for(inputs.evidence_for(ref), RULES)
    return findings_from_vdr(
        [_vuln_for(ref)],
        producer_version="1",
        exploitability={("CVE-2024-1111", ref): graded},
    )


def test_findings_without_a_grading_record_no_exploitability():
    (finding,) = findings_from_vdr([VULN], producer_version="1")
    assert finding.exploitability is None


def test_reached_package_is_likely_and_names_the_analyzer_in_sources():
    scope = ReachScope(analyzers=["atom"], reached={REF}, succeeded=True, analyzer_types=ATOM_PYPI)
    (finding,) = _graded_findings(scope)
    assert _reach(finding) == "likely"
    # No BOM component was handed in, so cdxgen is not a presence producer;
    # the analyzer that reached the package is.
    assert _exploitability(finding).sources == {
        "presence": ["vdb", "atom"],
        "reach": ["atom"],
    }
    # The rule names the table row that graded the axes, not the analyzers.
    assert _exploitability(finding).rule == "reached"
    validate("finding", finding.to_dict())


def test_bom_usage_evidence_proves_presence_and_names_cdxgen():
    scope = ReachScope(
        analyzers=["atom"],
        reached=set(),
        succeeded=True,
        analyzer_types=ATOM_PYPI,
    )
    inputs = _inputs(
        scope,
        bom_components=[
            {"purl": REF, "scope": "required", "evidence": {"occurrences": [{"location": "a.py"}]}}
        ],
        # The occurrence record the evidence adapter built from that BOM's
        # usage evidence; presence reads the records, not the components.
        records=[
            _evidence_record(
                [REF], producer_name="cdxgen", kind="occurrence", source="sbom-python.cdx.json"
            )
        ],
    )
    exploitability = exploitability_for(inputs.evidence_for(REF), RULES)
    assert exploitability.axes.presence == "proven"
    assert exploitability.sources == {"presence": ["vdb", "cdxgen"]}


def test_absent_from_a_non_empty_reached_set_is_unknown_never_refuted():
    scope = ReachScope(
        analyzers=["atom"],
        reached={OTHER},
        succeeded=True,
        analyzer_types=ATOM_PYPI,
    )
    (finding,) = _graded_findings(scope)
    assert _reach(finding) == "unknown"


@pytest.mark.parametrize(
    "scope",
    [
        ReachScope(analyzers=[], reached={REF}, succeeded=True),
        ReachScope(
            analyzers=["atom"],
            reached={REF},
            succeeded=False,
            analyzer_types=ATOM_PYPI,
        ),
        ReachScope(analyzers=["atom"], reached=set(), succeeded=True, analyzer_types=ATOM_PYPI),
    ],
    ids=["no-analyzer-ran", "engine-failed", "nothing-observed"],
)
def test_no_usable_reachability_is_not_assessed(scope):
    (finding,) = _graded_findings(scope)
    assert _reach(finding) == "not_assessed"
    # The database match still proves presence, so the fixed rules cap the
    # grade at moderate instead of grading the finding unassessed.
    assert _exploitability(finding).grade == "moderate"
    assert _exploitability(finding).unassessed == ["reach", "exposure", "barrier"]
    validate("finding", finding.to_dict())


def test_purl_spelling_differences_still_match():
    scope = ReachScope(
        analyzers=["atom"],
        reached={"pkg:pypi/requests@2.32.1?type=jar"},
        succeeded=True,
        analyzer_types=ATOM_PYPI,
    )
    assert reach_axis(scope, REF) == "likely"
    assert reach_axis(scope, "pkg:pypi/requests%402.32.1") == "likely"


def test_only_reach_is_graded_by_the_scope_and_the_rest_listed_unassessed():
    scope = ReachScope(
        analyzers=["atom", "golem"],
        reached={REF},
        succeeded=True,
        analyzer_types=ATOM_PYPI,
    )
    exploitability = exploitability_for(_inputs(scope).evidence_for(REF), RULES)
    # A reached reach value proves presence on its own.
    assert exploitability.axes.presence == "proven"
    assert exploitability.unassessed == ["exposure", "barrier"]
    # golem covers golang only, so it is not named for a pypi package
    assert exploitability.sources == {"presence": ["vdb", "atom"], "reach": ["atom"]}


def _vuln_for(ref):
    return dict(VULN, affects=[{"ref": ref}])


def _reach_sources_of(ref, scope):
    exploitability = exploitability_for(_inputs(scope, ref).evidence_for(ref), RULES)
    return exploitability.axes.reach, (exploitability.sources or {}).get("reach")


NPM = "pkg:npm/lodash@4.17.20"
MAVEN = "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"


def test_java_and_npm_repo_with_only_java_slices_leaves_npm_not_assessed():
    scope = ReachScope(
        analyzers=["atom"],
        reached={MAVEN},
        succeeded=True,
        analyzer_types={"atom": {"maven"}},
        reached_by={"atom": {MAVEN}},
    )
    assert _reach_sources_of(MAVEN, scope) == ("likely", ["atom"])
    assert _reach_sources_of(NPM, scope) == ("not_assessed", None)


def test_golem_only_reached_set_leaves_pypi_not_assessed():
    scope = ReachScope(
        analyzers=["golem"],
        reached={"pkg:golang/github.com/x/y@1.0.0"},
        succeeded=True,
        reached_by={"golem": {"pkg:golang/github.com/x/y@1.0.0"}},
    )
    assert _reach_sources_of(REF, scope) == ("not_assessed", None)
    assert _reach_sources_of("pkg:golang/github.com/x/z@1.0.0", scope) == (
        "unknown",
        ["golem"],
    )


def test_kosi_covers_maven_and_is_named_with_atom_only_when_both_cover_it():
    scope = ReachScope(
        analyzers=["atom", "kosi"],
        reached={MAVEN},
        succeeded=True,
        analyzer_types={"atom": {"npm"}},
        reached_by={"atom": {NPM}, "kosi": {MAVEN}},
    )
    assert _reach_sources_of(MAVEN, scope) == ("likely", ["kosi"])
    both = ReachScope(
        analyzers=["atom", "kosi"],
        reached={MAVEN},
        succeeded=True,
        analyzer_types={"atom": {"maven"}},
        reached_by={"atom": set(), "kosi": {MAVEN}},
    )
    assert _reach_sources_of(MAVEN, both) == ("likely", ["atom", "kosi"])


def test_an_analyzer_that_reached_nothing_does_not_grade_its_ecosystem():
    scope = ReachScope(
        analyzers=["atom", "kosi"],
        reached={NPM},
        succeeded=True,
        analyzer_types={"atom": {"npm"}},
        reached_by={"atom": {NPM}, "kosi": set()},
    )
    assert _reach_sources_of(MAVEN, scope) == ("not_assessed", None)


# ---------------------------------------------------------------------------
# the per-analyzer reached sets, grouped from the evidence records
# ---------------------------------------------------------------------------


def _evidence_record(
    purls,
    *,
    producer_name,
    kind="reached-flow",
    polarity="positive",
    source=None,
    discriminator="d1",
):
    if source is None:
        source = f"{producer_name}-reachables.slices.json"
    return build_record(
        source=source,
        producer=EvidenceProducer(
            name=producer_name, version="1.0.0", report_schema_version="unknown"
        ),
        kind=kind,
        discriminator=discriminator,
        polarity=polarity,
        purls=tuple(purls),
    )


def test_reached_by_analyzer_groups_records_by_producer_and_keeps_shared_purls():
    """The grouping is built from every record in one pass, never
    deduplicated across producers: a purl two producers both reached stays
    in both of their reached sets."""
    records = [
        _evidence_record(["pkg:npm/shared@1"], producer_name="atom"),
        _evidence_record(["pkg:npm/shared@1"], producer_name="golem"),
        _evidence_record(["pkg:npm/atom-only@1"], producer_name="atom", discriminator="d2"),
    ]
    grouped = reached_by_analyzer(records)
    assert set(grouped) == {"atom", "golem"}
    assert grouped["atom"]["purls"] == {"pkg:npm/shared@1", "pkg:npm/atom-only@1"}
    assert grouped["golem"]["purls"] == {"pkg:npm/shared@1"}


def test_reached_by_analyzer_ignores_records_that_never_count_as_reached():
    """Callsite records, dependency notes and negative records say things
    about a package without putting it on an executed path; their purls
    stay out of every reached set."""
    records = [
        _evidence_record(["pkg:npm/reached@1"], producer_name="atom"),
        _evidence_record(
            ["pkg:npm/callsite@1"], producer_name="atom", kind="callsite", discriminator="d2"
        ),
        _evidence_record(
            ["pkg:npm/dependency@1"], producer_name="atom", kind="dependency", discriminator="d3"
        ),
        _evidence_record(
            ["pkg:npm/dead@1"], producer_name="atom", polarity="negative", discriminator="d4"
        ),
    ]
    grouped = reached_by_analyzer(records)
    assert grouped["atom"]["purls"] == {"pkg:npm/reached@1"}


def test_reached_by_analyzer_atom_types_come_from_the_source_prefix():
    """atom's purl types come from the reachables file prefix of its
    records' source; a prefix that is not known contributes the purl types
    its records carry."""
    records = [
        _evidence_record(
            ["pkg:maven/a/b@1"], producer_name="atom", source="java-reachables.slices.json"
        ),
        _evidence_record(
            ["pkg:npm/c/d@1"],
            producer_name="atom",
            source="js-reachables.slices.json",
            discriminator="d2",
        ),
        _evidence_record(
            ["pkg:hex/e@1"],
            producer_name="atom",
            source="mystery-reachables.slices.json",
            discriminator="d3",
        ),
    ]
    grouped = reached_by_analyzer(records)
    assert grouped["atom"]["types"] == {"maven", "npm", "hex"}


def test_reached_by_analyzer_language_tools_carry_no_types():
    """The language tools each cover one ecosystem; the scope resolves that
    from the tool table, so their entries carry no types here."""
    records = [
        _evidence_record(["pkg:golang/x/y@1"], producer_name="golem"),
        _evidence_record(["pkg:cargo/z@1"], producer_name="rusi", discriminator="d2"),
        _evidence_record(
            ["pkg:maven/c/d@1"], producer_name="kosi", kind="entry-point", discriminator="d3"
        ),
    ]
    grouped = reached_by_analyzer(records)
    assert grouped["golem"]["types"] == set()
    assert grouped["rusi"]["types"] == set()
    assert grouped["kosi"]["types"] == set()
    # An entry-point record counts as reached, so its handler purl is in
    # the kosi set.
    assert grouped["kosi"]["purls"] == {"pkg:maven/c/d@1"}


def test_reached_by_analyzer_atom_records_of_other_roles_add_no_types():
    """atom's usage, callsite and OpenAPI sources are not reachables files
    and their records carry no reached purls, so they leave the types and
    the set alone."""
    records = [
        _evidence_record(
            ["pkg:npm/a@1"], producer_name="atom", source="js-reachables.slices.json"
        ),
        _evidence_record(
            [],
            producer_name="atom",
            kind="usage",
            source="js-usages.slices.json",
            discriminator="d2",
        ),
        _evidence_record(
            [],
            producer_name="atom",
            kind="entry-point",
            source="js-openapi.json",
            discriminator="d3",
        ),
    ]
    grouped = reached_by_analyzer(records)
    assert grouped["atom"] == {"purls": {"pkg:npm/a@1"}, "types": {"npm"}}
