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
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import unquote

from analysis_lib.findings.fingerprint import finding_fingerprint
from analysis_lib.findings.model import (
    Coverage,
    Exploitability,
    ExploitabilityAxes,
    Finding,
    FindingProperty,
    Fix,
    Producer,
    Reference,
)

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


#: The exploitability axes, in the order the schema lists them.
_AXES = ("presence", "reach", "exposure", "barrier", "pressure")

#: Reach values for the three reachability outcomes. A reached package is
#: ``likely`` and not ``proven``: the analyzers show that code of the package
#: is on an executed path, not that the vulnerable function is. A package
#: absent from a reached set is ``unknown``; ``unlikely`` and ``refuted`` would
#: claim the code is not reached, which an analyzer that records only what it
#: observed cannot show.
REACH_REACHED = "likely"
REACH_NOT_OBSERVED = "unknown"
REACH_NOT_ASSESSED = "not_assessed"

#: Prefix of ``exploitability.rule`` when the reach axis came from analyzers;
#: the analyzer names follow, joined with ``+``.
REACH_RULE_PREFIX = "reachability:"


def _comparable(purl: str) -> str:
    """A purl without percent-encoding, qualifiers or subpath, so a reached
    key and an ``affects`` ref spelled differently still compare equal."""
    return unquote(str(purl)).split("?", 1)[0].split("#", 1)[0]


@dataclass
class ReachScope:
    """What the reachability analysis said about one group of components.

    ``refs`` are the ``affects`` refs the scan matched under this scope (one
    project type's vulnerabilities), ``analyzers`` the names of the analyzers
    whose slices the scan read (status completed) and ``reached`` the purls
    those slices put on an executed path. ``succeeded`` is False when the
    reachability engine failed or never ran, whatever slices are on disk.
    """

    refs: Set[str] = field(default_factory=set)
    analyzers: List[str] = field(default_factory=list)
    reached: Set[str] = field(default_factory=set)
    succeeded: bool = False
    _refs_cmp: Optional[Set[str]] = field(default=None, init=False, repr=False, compare=False)
    _reached_cmp: Optional[Set[str]] = field(default=None, init=False, repr=False, compare=False)

    def covers(self, ref: str) -> bool:
        if self._refs_cmp is None:
            self._refs_cmp = {_comparable(r) for r in self.refs}
        return _comparable(ref) in self._refs_cmp

    def reaches(self, ref: str) -> bool:
        if self._reached_cmp is None:
            self._reached_cmp = {_comparable(p) for p in self.reached}
        return _comparable(ref) in self._reached_cmp


def reach_axis(scope: Optional[ReachScope], ref: str) -> str:
    """The ``reach`` value for the component ``ref`` under ``scope``.

    ``not_assessed`` when no analyzer ran or the run failed, or when it
    observed nothing at all (a run that found nothing cannot be told from one
    that saw nothing). ``likely`` when the ref is in the reached set. ``unknown``
    for a ref absent from a non-empty reached set: not observed, never refuted.
    """
    if scope is None or not scope.succeeded or not scope.analyzers or not scope.reached:
        return REACH_NOT_ASSESSED
    if scope.reaches(ref):
        return REACH_REACHED
    return REACH_NOT_OBSERVED


def exploitability_from_reach(scope: Optional[ReachScope], ref: str) -> Exploitability:
    """The exploitability assessment a scan can make from reachability alone.

    Only ``reach`` is graded. The other four axes are ``not_assessed`` and
    listed in ``unassessed``; no grade is given unless every axis is
    unassessed, because a grade over one axis would claim more than the scan
    knows. ``rule`` names the analyzers the reach value came from.
    """
    reach = reach_axis(scope, ref)
    axes = {name: REACH_NOT_ASSESSED for name in _AXES}
    axes["reach"] = reach
    unassessed = [name for name in _AXES if axes[name] == REACH_NOT_ASSESSED]
    rule = None
    if reach != REACH_NOT_ASSESSED and scope is not None:
        rule = REACH_RULE_PREFIX + "+".join(sorted(scope.analyzers))
    return Exploitability(
        axes=ExploitabilityAxes(**axes),
        grade="unassessed" if len(unassessed) == len(_AXES) else None,
        rule=rule,
        unassessed=unassessed,
    )


def _scope_for(scopes: Iterable[ReachScope], ref: str) -> Optional[ReachScope]:
    """The scope that matched ``ref``, preferring one that assessed it."""
    covering = [scope for scope in scopes if scope.covers(ref)]
    for scope in covering:
        if reach_axis(scope, ref) != REACH_NOT_ASSESSED:
            return scope
    return covering[0] if covering else None


def finding_from_vdr(
    vuln: Dict[str, Any],
    component_ref: str,
    *,
    producer_name: str = "dep-scan",
    producer_version: str,
    exploitability: Optional[Exploitability] = None,
) -> Finding:
    """One finding for one advisory of a VDR entry hitting one component.

    ``component_ref`` is the ``affects`` ref, a package URL with a version.
    The finding carries the advisory id as its rule, the entry's most severe
    rating, the versions named as fixes and the dep-scan extension
    properties; its id is the line-free fingerprint of the pair.

    :raises ValueError: when ``component_ref`` is not a valid package URL.
    """
    rule = str(vuln.get("id") or "").strip()
    if not rule:
        raise ValueError("the VDR entry has no advisory id")
    finding_id = finding_fingerprint("vulnerability", rule, [component_ref])
    return Finding(
        id=finding_id,
        category="vulnerability",
        rule=rule,
        title=f"{rule} affects {component_ref}",
        severity=highest_severity(vuln),
        coverage=Coverage(state="assessed"),
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
    reach_scopes: Optional[List[ReachScope]] = None,
) -> List[Finding]:
    """One finding per advisory and component of the given VDR entries.

    Entries without ``affects`` refs produce no finding; a scan cannot name
    a component it did not record. A repeated (advisory, component) pair
    collapses onto one finding. Two versions of one package hit by the same
    advisory stay two findings: they share the fingerprint, which leaves the
    version out so suppressions survive upgrades, but each version is a
    package the project ships.

    With ``reach_scopes`` every finding carries an ``exploitability`` whose
    ``reach`` axis comes from the scan's reachability result (see
    :func:`exploitability_from_reach`); without it the finding records no
    exploitability.

    :raises ValueError: when an entry has no advisory id or a ref that is
        not a valid package URL; a VDR the scan wrote always carries both.
    """
    findings: List[Finding] = []
    seen = set()
    for vuln in vulnerabilities or []:
        if not isinstance(vuln, dict):
            continue
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
                    exploitability_from_reach(
                        _scope_for(reach_scopes, str(component_ref)), str(component_ref)
                    )
                    if reach_scopes is not None
                    else None
                ),
            )
            key = (finding.id, str(component_ref))
            if key not in seen:
                seen.add(key)
                findings.append(finding)
    return findings
