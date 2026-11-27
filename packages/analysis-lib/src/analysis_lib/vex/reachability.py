"""Map triage decisions and reachability results to CSAF VEX status.

A triage decision a person made or a VEX document stated is written into
the VDR per affected component, as a ``depscan:triage:component:<bom-ref>``
property holding the same winner the findings file records for that
component. That decision sets the status of that product only:

* ``not_affected`` (with a justification) and ``false_positive``
  -> ``known_not_affected``, with the CSAF justification flag that matches
* ``exploitable`` -> ``known_affected``
* ``in_triage`` -> ``under_investigation``
* ``resolved`` and ``resolved_with_pedigree`` -> ``fixed``

A ``not_affected`` decision with no justification has no CSAF flag to carry
it, and CSAF requires one, so the product falls back to reachability, as
does every product of the entry that no decision covers.

Without a decision, dep-scan's reachability analyzer records which purls
carry reachable flows (``vdr_result.reached_purls``), and this module turns
that into VEX semantics:

* reached     -> ``known_affected``
* not reached -> ``under_investigation``
* no reachability data -> ``under_investigation``

A package missing from a reached set is not evidence that its vulnerable code
is outside the execute path: the framework and semantic analyzers only record
what they observed, and a call through reflection, an interface, a callback or
a language the analyzer does not follow leaves no trace. No analyzer records
positive evidence that vulnerable code is not executed, so reachability alone
never asserts ``known_not_affected`` and never sets the
``vulnerable_code_not_in_execute_path`` flag; only a triage decision does.

Only product_ids that resolve in the product tree are emitted, so a status or
flag can never reference an undefined product.
"""

from typing import Dict, List, Optional, Tuple

from analysis_lib.findings.decisions import TRIAGE_PROPERTY_PREFIX, component_decisions
from analysis_lib.vex.product_tree import resolve_purl

# CSAF VEX status buckets.
KNOWN_AFFECTED = "known_affected"
KNOWN_NOT_AFFECTED = "known_not_affected"
UNDER_INVESTIGATION = "under_investigation"
FIXED = "fixed"

# CSAF flag label for code that is present but never executed. In CSAF the flag
# label is itself the VEX justification value (there is no separate field).
NOT_IN_PATH_LABEL = "vulnerable_code_not_in_execute_path"

#: The CSAF status a CycloneDX analysis state sets; not_affected and
#: false_positive set known_not_affected only with a justification flag.
_STATE_STATUS = {
    "exploitable": KNOWN_AFFECTED,
    "in_triage": UNDER_INVESTIGATION,
    "resolved": FIXED,
    "resolved_with_pedigree": FIXED,
}

#: The CSAF justification flag of each CycloneDX justification.
_JUSTIFICATION_FLAG = {
    "code_not_present": "vulnerable_code_not_present",
    "code_not_reachable": NOT_IN_PATH_LABEL,
    "requires_configuration": "vulnerable_code_cannot_be_controlled_by_adversary",
    "requires_dependency": "component_not_present",
    "requires_environment": "vulnerable_code_cannot_be_controlled_by_adversary",
    "protected_by_compiler": "inline_mitigations_already_exist",
    "protected_at_runtime": "inline_mitigations_already_exist",
    "protected_at_perimeter": "inline_mitigations_already_exist",
    "protected_by_mitigating_control": "inline_mitigations_already_exist",
}


def _status_of(analysis: Dict) -> Tuple[Optional[str], Optional[str]]:
    """The CSAF status and justification flag of one decision's analysis
    values, or ``(None, None)`` when CSAF cannot state it."""
    state = analysis.get("state")
    if state == "false_positive":
        # A false positive names a vulnerability that does not apply to the
        # component: its vulnerable code is not present.
        return KNOWN_NOT_AFFECTED, "vulnerable_code_not_present"
    if state == "not_affected":
        label = _JUSTIFICATION_FLAG.get(str(analysis.get("justification") or ""))
        return (KNOWN_NOT_AFFECTED, label) if label else (None, None)
    return _STATE_STATUS.get(str(state or "")), None


def _decisions(vuln: Dict) -> Dict[str, Tuple[Optional[str], Optional[str]]]:
    """The CSAF status and flag each affected component's triage decision
    sets, by bom-ref; a component without one is absent.

    The decisions come from the ``depscan:triage:component:<bom-ref>``
    properties, one per decided component. A VDR written before those
    properties existed carries only the entry's analysis object and the
    ``depscan:triage:*`` properties naming its author; that decision then
    covers every component. The analysis the matching stage writes on its
    own (``in_triage`` for a dependency tree, ``exploitable`` for a known
    exploit) is a hint, not a decision, and leaves the status to
    reachability.
    """
    per_component = component_decisions(vuln)
    if per_component:
        return {ref: _status_of(decision) for ref, decision in per_component.items()}
    analysis = vuln.get("analysis")
    decided = any(
        isinstance(prop, dict) and str(prop.get("name") or "").startswith(TRIAGE_PROPERTY_PREFIX)
        for prop in vuln.get("properties") or []
    )
    if not isinstance(analysis, dict) or not decided:
        return {}
    status = _status_of(analysis)
    return {ref: status for ref in _affected_purls(vuln)}


def _affected_purls(vuln: Dict) -> List[str]:
    """Return the purls of the products this vulnerability attaches to.

    ``affects[].versions[].status`` is intentionally ignored: it describes which
    version fixes the CVE, not whether the installed product is affected at
    runtime. The ``ref`` is the installed product's purl.
    """
    purls = []
    for a in vuln.get("affects", []) or []:
        ref = a.get("ref")
        if ref:
            purls.append(ref)
    return purls


def classify(
    vuln: Dict,
    purl_to_id: Dict[str, str],
    reached_purls: Dict[str, int],
) -> Tuple[Dict[str, List[str]], List[Dict], List[str]]:
    """Classify a vulnerability's affected products into VEX status buckets:
    each product by the triage decision about that component when it has
    one, else by reachability. A decision about one component never sets
    the status of another.

    :return: ``(product_status, flags, score_product_ids)`` where every id is
        guaranteed to resolve in the product tree.
    """
    status_buckets: Dict[str, List[str]] = {
        KNOWN_AFFECTED: [],
        KNOWN_NOT_AFFECTED: [],
        UNDER_INVESTIGATION: [],
        FIXED: [],
    }
    decisions = _decisions(vuln)
    flags_by_label: Dict[str, List[str]] = {}
    score_product_ids: List[str] = []

    for purl in _affected_purls(vuln):
        product_id = resolve_purl(purl_to_id, purl)
        if not product_id:
            # Unknown to the product tree -> skip so no status/flag references
            # an undefined product.
            continue
        score_product_ids.append(product_id)
        decided, label = decisions.get(purl, (None, None))
        if decided:
            status_buckets[decided].append(product_id)
            if label:
                flags_by_label.setdefault(label, []).append(product_id)
        elif reached_purls and (reached_purls.get(purl) or reached_purls.get(product_id)):
            status_buckets[KNOWN_AFFECTED].append(product_id)
        else:
            # Not observed is not "not in the execute path".
            status_buckets[UNDER_INVESTIGATION].append(product_id)

    flags: List[Dict] = [
        {"label": label, "product_ids": sorted(set(product_ids))}
        for label, product_ids in sorted(flags_by_label.items())
    ]

    # Drop empty buckets; callers serialize what remains.
    product_status = {k: sorted(set(v)) for k, v in status_buckets.items() if v}
    return product_status, flags, sorted(set(score_product_ids))
