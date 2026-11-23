"""Conversion between CycloneDX VDR entries and dep-scan findings.

One function in each direction keeps the two shapes in step. This module
holds the VDR-to-findings direction the scan writes into
``depscan.findings.json``; the reverse, writing the VDR from findings, uses
the same field mapping inverted.

One finding per advisory and component. A VDR entry carries one advisory and
the ``affects`` refs of every component it hits; each (advisory, component)
pair becomes a finding of its own, so the fingerprint can key on the
component and suppressions stay per package. The fingerprint has no source
location because a vulnerable package is declared by a manifest, not by a
line of code; the declaring path is not recoverable from a VDR entry today,
so the id's file component stays empty, which the fingerprint documents as
the shared-id case for repeated copies of one package.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote

from analysis_lib.evidence import Evidence
from analysis_lib.findings.fingerprint import finding_fingerprint
from analysis_lib.findings.model import (
    Coverage,
    CoverageReason,
    Exploitability,
    Finding,
    FindingProperty,
    Fix,
    Producer,
    Reference,
)
from analysis_lib.reachability import ATOM_SLICE_PURL_TYPES, counts_as_reached

#: The capability a finding's coverage names when the usage evidence its
#: presence axis reads was not assessed.
PRESENCE_USAGE_CAPABILITY = "presence:usage"

#: CycloneDX severity names, most severe first, with the score as the tie
#: breaker of last resort.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "none", "unknown")

# The severity names the finding schema publishes. CycloneDX also has none,
# which means no impact; the schema's nearest value is info.
_SEVERITY_ALIASES = {"none": "info", "unspecified": "unknown", "": "unknown"}


def highest_severity(vuln: Dict[str, Any]) -> str:
    """The most severe rating of a VDR entry, greatest score among equals.

    Ratings the finding schema does not publish, CycloneDX ``none`` among
    them, map to their nearest published name; an entry without ratings is
    ``unknown``, never dropped.
    """
    best = None
    best_key = None
    for rating in vuln.get("ratings") or []:
        if not isinstance(rating, dict):
            continue
        name = str(rating.get("severity") or "").strip().lower()
        name = _SEVERITY_ALIASES.get(name, name)
        if name not in _SEVERITY_ORDER:
            name = "unknown"
        score = rating.get("score")
        numeric = (
            score if isinstance(score, (int, float)) and not isinstance(score, bool) else None
        )
        key = (
            -_SEVERITY_ORDER.index(name),
            numeric is not None,
            numeric if numeric is not None else -1.0,
        )
        if best_key is None or key > best_key:
            best, best_key = name, key
    return best or "unknown"


def _fixed_versions(vuln: Dict[str, Any]) -> List[str]:
    """The versions the VDR entry names as resolving the advisory.

    ``fixed_location`` is the recommendation the scan searched for; the
    ``unaffected`` versions on the affects entries repeat it, occasionally
    with more entries when several branches are patched.
    """
    versions: List[str] = []
    if fixed := vuln.get("fixed_location"):
        if fixed not in ("*", ""):
            versions.append(str(fixed))
    for affect in vuln.get("affects") or []:
        if not isinstance(affect, dict):
            continue
        for version in affect.get("versions") or []:
            if (
                isinstance(version, dict)
                and version.get("status") == "unaffected"
                and version.get("version")
                and version["version"] not in versions
                and version["version"] != "*"
            ):
                versions.append(str(version["version"]))
    return versions


def _properties(vuln: Dict[str, Any]) -> Optional[List[FindingProperty]]:
    """The dep-scan extension properties of the entry, carried over as is."""
    props = [
        FindingProperty(name=str(prop.get("name")), value=str(prop.get("value") or ""))
        for prop in vuln.get("properties") or []
        if isinstance(prop, dict) and prop.get("name")
    ]
    return props or None


def _references(vuln: Dict[str, Any]) -> Optional[List[Reference]]:
    """The advisory links of the entry, typed as advisories."""
    refs = []
    seen = set()
    for advisory in vuln.get("advisories") or []:
        if not isinstance(advisory, dict):
            continue
        url = str(advisory.get("url") or "").strip()
        if url and url not in seen:
            seen.add(url)
            refs.append(Reference(url=url, type="advisory"))
    return refs or None


def _cwes(vuln: Dict[str, Any]) -> Optional[List[int]]:
    cwes = []
    for cwe in vuln.get("cwes") or []:
        try:
            number = int(cwe)
        except (TypeError, ValueError):
            continue
        if number not in cwes:
            cwes.append(number)
    return cwes or None


#: Reach values for the three reachability outcomes. A reached package is
#: ``likely`` and not ``proven``: the analyzers show that code of the package
#: is on an executed path, not that the vulnerable function is. A package
#: absent from a reached set is ``unknown``; ``unlikely`` and ``refuted`` would
#: claim the code is not reached, which an analyzer that records only what it
#: observed cannot show.
REACH_REACHED = "likely"
REACH_NOT_OBSERVED = "unknown"
REACH_NOT_ASSESSED = "not_assessed"


def comparable_purl(purl: str) -> str:
    """A purl without percent-encoding, qualifiers or subpath, so a reached
    key and an ``affects`` ref spelled differently still compare equal.
    NuGet package ids and versions are case-insensitive, so a nuget purl is
    also lowercased."""
    plain = unquote(str(purl)).split("?", 1)[0].split("#", 1)[0]
    return plain.lower() if plain[:10].lower() == "pkg:nuget/" else plain


#: The purl type each language tool's reachables slice covers. atom's depend
#: on the slice files it produced and are carried by the scope.
TOOL_PURL_TYPES = {
    "golem": frozenset({"golang"}),
    "rusi": frozenset({"cargo"}),
    "dosai": frozenset({"nuget"}),
    "kosi": frozenset({"maven"}),
}


def _purl_type(ref: str) -> str:
    head = comparable_purl(ref).split("/", 1)[0]
    return head[4:].lower() if head.lower().startswith("pkg:") else ""


def reached_by_analyzer(records: Iterable[Evidence]) -> Dict[str, Dict[str, Set[str]]]:
    """What each producer's reached-counted records put on an executed path.

    The grouping is built from every record the caller holds, in one pass,
    and the records are never deduplicated against each other across
    producers: a purl two producers both reached stays in both of their
    sets, so a set that stands for a full read of the evidence store is
    built from all of it. Records that do not count as reached evidence per
    :func:`analysis_lib.reachability.counts_as_reached` (negative ones, the
    kinds outside :data:`analysis_lib.reachability.REACHED_COUNTED_KINDS`,
    and those stating Low confidence) never enter the sets.

    Each entry carries the purls under ``purls`` and the purl types the
    scope should treat the producer as covering under ``types``. The
    language tools cover one ecosystem each (:data:`TOOL_PURL_TYPES`) and
    carry no types here; atom's come from the reachables file prefix of its
    records' source (:data:`analysis_lib.reachability.ATOM_SLICE_PURL_TYPES`),
    and a prefix that is not known contributes the purl types the records
    with it carry.
    """
    result: Dict[str, Dict[str, Set[str]]] = {}
    for record in records:
        if not counts_as_reached(record):
            continue
        name = record.producer.name
        entry = result.setdefault(name, {"purls": set(), "types": set()})
        entry["purls"].update(record.subject.purls)
        if name == "atom":
            mapped = ATOM_SLICE_PURL_TYPES.get(record.source.split("-reachables", 1)[0].lower())
            if mapped:
                entry["types"].add(mapped)
            else:
                entry["types"] |= {t for t in map(_purl_type, record.subject.purls) if t}
    return result


@dataclass
class ReachScope:
    """What the reachability analysis said about the components of one
    project type's scan.

    ``analyzers`` are the names of the analyzers whose slices the scan read
    (status completed) and ``reached`` the purls those slices put on an
    executed path. ``succeeded`` is False when the reachability engine failed
    or never ran, whatever slices are on disk.

    A finding is graded only against analyzers that cover its purl type. The
    language tools each cover one ecosystem (:data:`TOOL_PURL_TYPES`);
    ``analyzer_types`` names the purl types of the other analyzers (atom's
    slice files decide them). ``reached_by`` holds the purls each analyzer
    reached: an analyzer it does not name, or names with an empty set,
    observed nothing. Only when ``reached_by`` is not given at all does the
    single ``reached`` set stand for every analyzer.
    """

    analyzers: List[str] = field(default_factory=list)
    reached: Set[str] = field(default_factory=set)
    succeeded: bool = False
    analyzer_types: Dict[str, Set[str]] = field(default_factory=dict)
    reached_by: Optional[Dict[str, Set[str]]] = None
    _reached_cmp: Optional[Dict[str, Set[str]]] = field(
        default=None, init=False, repr=False, compare=False
    )

    def covering_analyzers(self, ref: str) -> List[str]:
        """The completed analyzers that cover the purl type of ``ref``."""
        purl_type = _purl_type(ref)
        covering = []
        for name in self.analyzers:
            types = self.analyzer_types.get(name)
            if types is None:
                types = TOOL_PURL_TYPES.get(name, frozenset())
            if purl_type in types:
                covering.append(name)
        return sorted(covering)

    def _reached_of(self, name: str) -> Set[str]:
        if self._reached_cmp is None:
            self._reached_cmp = {}
        if name not in self._reached_cmp:
            if self.reached_by is None:
                source = self.reached
            else:
                source = self.reached_by.get(name) or set()
            self._reached_cmp[name] = {comparable_purl(p) for p in source}
        return self._reached_cmp[name]

    def reaches(self, ref: str, analyzers: Optional[List[str]] = None) -> bool:
        target = comparable_purl(ref)
        names = self.analyzers if analyzers is None else analyzers
        return any(target in self._reached_of(name) for name in names)

    def observed(self, analyzers: List[str]) -> bool:
        """Whether any of ``analyzers`` reached something at all."""
        return any(self._reached_of(name) for name in analyzers)


def assess_reach(scope: Optional[ReachScope], ref: str) -> Tuple[str, List[str]]:
    """The ``reach`` value for ``ref`` under ``scope``, with the covering
    analyzers whose reached set was consulted.

    ``not_assessed`` when no analyzer ran or the run failed, when no
    completed analyzer covers the purl type of ``ref``, or when the covering
    analyzers observed nothing at all (a run that found nothing cannot be
    told from one that saw nothing). ``likely`` when the ref is in a covering
    analyzer's reached set. ``unknown`` for a ref absent from a non-empty
    reached set: not observed, never refuted.
    """
    if scope is None or not scope.succeeded or not scope.analyzers:
        return REACH_NOT_ASSESSED, []
    covering = scope.covering_analyzers(ref)
    if not covering or not scope.observed(covering):
        return REACH_NOT_ASSESSED, []
    if scope.reaches(ref, covering):
        return REACH_REACHED, covering
    return REACH_NOT_OBSERVED, covering


def reach_axis(scope: Optional[ReachScope], ref: str) -> str:
    """The ``reach`` value for the component ``ref`` under ``scope``."""
    return assess_reach(scope, ref)[0]


def finding_from_vdr(
    vuln: Dict[str, Any],
    component_ref: str,
    *,
    producer_name: str = "dep-scan",
    producer_version: str,
    exploitability: Optional[Exploitability] = None,
    usage_not_assessed: Optional[str] = None,
) -> Finding:
    """One finding for one advisory of a VDR entry hitting one component.

    ``component_ref`` is the ``affects`` ref, a package URL with a version.
    The finding carries the advisory id as its rule, the entry's most severe
    rating, the versions named as fixes and the dep-scan extension
    properties; its id is the line-free fingerprint of the pair.
    ``usage_not_assessed`` is why usage evidence of the package in a BOM of
    the scan was not assessed. Whenever the map has an entry for the
    finding's purl, the coverage carries it, proven presence included: a
    finding that graded on another BOM's records still names the BOM that
    was not read, and a ``likely`` or ``unlikely`` presence never reads as
    usage measured and not found. The finding itself stays assessed: the
    database match ran.

    :raises ValueError: when ``component_ref`` is not a valid package URL.
    """
    rule = str(vuln.get("id") or "").strip()
    if not rule:
        raise ValueError("the VDR entry has no advisory id")
    finding_id = finding_fingerprint("vulnerability", rule, [component_ref])
    coverage = Coverage(state="assessed")
    if usage_not_assessed and exploitability is not None:
        coverage.reasons = [
            CoverageReason(
                capability=PRESENCE_USAGE_CAPABILITY,
                reason="report-not-assessed",
                detail=usage_not_assessed,
            )
        ]
    return Finding(
        id=finding_id,
        category="vulnerability",
        rule=rule,
        title=f"{rule} affects {component_ref}",
        severity=highest_severity(vuln),
        coverage=coverage,
        producer=Producer(name=producer_name, version=producer_version),
        cwes=_cwes(vuln),
        components=[component_ref],
        exploitability=exploitability,
        fix=Fix(fixed_versions=_fixed_versions(vuln)) if _fixed_versions(vuln) else None,
        references=_references(vuln),
        properties=_properties(vuln),
    )


def findings_from_vdr(
    vulnerabilities: List[Dict[str, Any]],
    *,
    producer_name: str = "dep-scan",
    producer_version: str,
    exploitability: Optional[Dict[Tuple[str, str], Exploitability]] = None,
    usage_not_assessed: Optional[Dict[str, str]] = None,
) -> List[Finding]:
    """One finding per advisory and component of the given VDR entries.

    Entries without ``affects`` refs produce no finding; a scan cannot name
    a component it did not record. A repeated (advisory, component) pair
    collapses onto one finding. Two versions of one package hit by the same
    advisory stay two findings: they share the fingerprint, which leaves the
    version out so suppressions survive upgrades, but each version is a
    package the project ships.

    ``exploitability`` maps an (advisory id, affects ref) pair to the
    assessment this scan graded for it (see
    :func:`analysis_lib.findings.exploitability.annotate_exploitability`);
    a pair the map does not carry records no exploitability.
    ``usage_not_assessed`` maps a comparable purl to the reason usage
    evidence of it in a BOM of the scan was not assessed (see
    :func:`finding_from_vdr`).

    :raises ValueError: when an entry has no advisory id or a ref that is
        not a valid package URL; a VDR the scan wrote always carries both.
    """
    findings: List[Finding] = []
    seen = set()
    for vuln in vulnerabilities or []:
        if not isinstance(vuln, dict):
            continue
        advisory = str(vuln.get("id") or "")
        for affect in vuln.get("affects") or []:
            if not isinstance(affect, dict):
                continue
            component_ref = affect.get("ref")
            if not component_ref:
                continue
            finding = finding_from_vdr(
                vuln,
                str(component_ref),
                producer_name=producer_name,
                producer_version=producer_version,
                exploitability=(
                    exploitability.get((advisory, str(component_ref)))
                    if exploitability is not None
                    else None
                ),
                usage_not_assessed=(
                    usage_not_assessed.get(comparable_purl(str(component_ref)))
                    if usage_not_assessed
                    else None
                ),
            )
            key = (finding.id, str(component_ref))
            if key not in seen:
                seen.add(key)
                findings.append(finding)
    return findings
