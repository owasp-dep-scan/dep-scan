"""CSAF §6.1 mandatory-test semantic validator.

The JSON Schema only expresses structural constraints; CSAF §6.1 defines a set
of *mandatory tests* a conformant document must also pass. A tool that emits a
schema-valid document can still be non-conformant (issue #511 is exactly this:
missing vulnerability ids, duplicate scores and timezone-less timestamps all
pass the schema).

This module implements the mandatory tests that are reachable given the shape
of documents dep-scan produces (a ``csaf_vex`` document whose product tree is a
flat list of ``full_product_names`` -- no branches, relationships, product
groups, SSVC/EPSS, or sharing groups). Tests for structures we never emit are
intentionally omitted and enumerated below for traceability.

Each check appends human-readable messages of the form
``<test-id> <json-path>: <reason>`` and never raises: a validator must survive
any input so validation results are always complete.

Section numbers follow the CSAF v2.1 specification (csd01). The VEX profile
tests live under §6.1.27.x (e.g. §6.1.27.7 VEX Product Status, §6.1.27.8
Vulnerability ID, §6.1.27.9 Impact Statement, §6.1.27.10 Action Statement).

Mandatory tests that do not apply to dep-scan output (documented for audit):
§6.1.3 circular product id, §6.1.4/§6.1.5 product groups, §6.1.15 translator,
§6.1.24 involvements, §6.1.25 hashes, §6.1.28 translation, §6.1.34 branch
recursion, §6.1.38-§6.1.41 sharing groups, §6.1.42-§6.1.44 purl
qualifiers/model/serial, §6.1.45 inconsistent disclosure date, §6.1.46-§6.1.53
SSVC/EPSS/exploitation dates, §6.1.54/§6.1.55 licenses -- none of these
structures are ever produced by the VEX generator.
"""

import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Set

from analysis_lib.vex.dates import is_rfc3339

try:  # cvss is a hard dep of the package but keep validation crash-proof.
    import cvss as _cvss
except Exception:  # pragma: no cover
    _cvss = None

_CWE_RE = re.compile(r"^CWE-[1-9]\d*$")
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,7}$")
# purl type may start with '.', '-' or '+' per the CSAF purl pattern (§3.1.3).
_PURL_RE = re.compile(r"^pkg:[A-Za-z.\-+][A-Za-z0-9.\-+]*/.+")
# RFC 5646 language tag (primary subtag + optional subtags), plus the
# CSAF-permitted ``i-default``.
_LANG_RE = re.compile(r"^(?:[a-zA-Z]{2,3}(?:-[a-zA-Z0-9]{1,8})*|i-default)$")

_VALID_CATEGORIES = {
    "csaf_base",
    "csaf_security_incident_response",
    "csaf_informational_advisory",
    "csaf_security_advisory",
    "csaf_vex",
    "csaf_withdrawn",
    "csaf_superseded",
    "csaf_deprecated",
}
# The four "core" VEX statuses; §6.1.27.7 requires at least one to be present.
_VEX_STATUS = {"fixed", "known_affected", "known_not_affected", "under_investigation"}
# All nine product-status values defined in CSAF 2.1 §3.2.4.12.
_ALL_STATUS = _VEX_STATUS | {
    "first_affected",
    "first_fixed",
    "last_affected",
    "recommended",
    "unknown",
}
# ``recommended`` may legitimately overlap any other status (an issuer can
# recommend a version from any group), so it is excluded from the §6.1.6
# contradiction check.
_CONTRADICTION_STATUS = _ALL_STATUS - {"recommended"}
# VEX justification labels; §6.1.33 allows at most one per product.
_JUSTIFICATION_LABELS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}


def validate_semantic(doc: Dict[str, Any], csaf_version: str = "2.1") -> List[str]:
    """Return semantic-test error messages (empty == passes all §6.1 tests)."""
    errors: List[str] = []
    if not isinstance(doc, dict):
        return ["6.1 <doc>: document is not a JSON object"]
    document = doc.get("document") or {}
    product_tree = doc.get("product_tree") or {}
    vulns = doc.get("vulnerabilities") or []
    defined = _defined_product_ids(product_tree)
    group_map = _product_group_map(product_tree)
    category = document.get("category")

    _check_product_ids(doc, defined, errors)
    _check_dates(doc, csaf_version, errors)
    _check_revision_history(document, errors)
    _check_document(document, csaf_version, errors)
    _check_purls(product_tree, errors)
    _check_vulnerabilities(vulns, defined, category, group_map, csaf_version, errors)
    return errors


def _product_group_map(product_tree: Dict[str, Any]) -> Dict[str, Set[str]]:
    """Map each ``group_id`` to the set of product_ids it contains.

    Lets the profile tests resolve products referenced indirectly through a
    ``group_ids`` list (§4.5) instead of only through ``product_ids``.
    """
    groups: Dict[str, Set[str]] = {}
    for grp in product_tree.get("product_groups") or []:
        gid = grp.get("group_id")
        if gid:
            groups[gid] = set(grp.get("product_ids") or [])
    return groups


def _expand(product_ids, group_ids, group_map: Dict[str, Set[str]]) -> Set[str]:
    """Union of directly-referenced products and those reached via groups."""
    covered: Set[str] = set(product_ids or [])
    for gid in group_ids or []:
        covered |= group_map.get(gid, set())
    return covered


# --------------------------------------------------------------------------- #
# Product tree                                                                  #
# --------------------------------------------------------------------------- #
def _walk_full_product_names(node: Any):
    """Yield every ``full_product_name``-like object in the product tree."""
    if isinstance(node, dict):
        if "product_id" in node and "name" in node:
            yield node
        for value in node.values():
            yield from _walk_full_product_names(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_full_product_names(item)


def _defined_product_ids(product_tree: Dict[str, Any]) -> Set[str]:
    return {n["product_id"] for n in _walk_full_product_names(product_tree)}


def _check_product_ids(doc: Dict[str, Any], defined: Set[str], errors: List[str]) -> None:
    # 6.1.2 Multiple Definition of Product ID
    counts = Counter(
        n["product_id"] for n in _walk_full_product_names(doc.get("product_tree") or {})
    )
    for pid, c in sorted(counts.items()):
        if c > 1:
            errors.append(f"6.1.2 /product_tree: product_id {pid!r} defined {c} times")
    # 6.1.1 Missing Definition of Product ID (dangling references)
    for i, vuln in enumerate(doc.get("vulnerabilities") or []):
        for pid in sorted(_referenced_product_ids(vuln) - defined):
            errors.append(
                f"6.1.1 /vulnerabilities[{i}]: product_id {pid!r} referenced but not "
                f"defined in product_tree"
            )


def _referenced_product_ids(vuln: Dict[str, Any]) -> Set[str]:
    referenced: Set[str] = set()
    for pids in (vuln.get("product_status") or {}).values():
        referenced.update(pids or [])
    for metric in _metrics(vuln):
        referenced.update(metric.get("products") or [])
    for flag in vuln.get("flags") or []:
        referenced.update(flag.get("product_ids") or [])
    for rem in vuln.get("remediations") or []:
        referenced.update(rem.get("product_ids") or [])
    return referenced


def _check_purls(product_tree: Dict[str, Any], errors: List[str]) -> None:
    # 6.1.13 PURL
    for node in _walk_full_product_names(product_tree):
        helper = node.get("product_identification_helper")
        if not isinstance(helper, dict):
            continue
        purls = helper.get("purls")
        if isinstance(helper.get("purl"), str):
            purls = [helper["purl"]] + (purls or [])
        for purl in purls or []:
            if not _PURL_RE.match(str(purl)):
                errors.append(
                    f"6.1.13 /product_tree: invalid purl {purl!r} on product "
                    f"{node.get('product_id')!r}"
                )


# --------------------------------------------------------------------------- #
# Document / tracking                                                           #
# --------------------------------------------------------------------------- #
def _check_document(document: Dict[str, Any], version: str, errors: List[str]) -> None:
    # 6.1.26 Prohibited Document Category Name
    category = document.get("category")
    if category and category not in _VALID_CATEGORIES:
        errors.append(f"6.1.26 /document/category: unknown category {category!r}")
    # 6.1.12 Language
    for key in ("lang", "source_lang"):
        lang = document.get(key)
        if lang and not _LANG_RE.match(str(lang)):
            errors.append(f"6.1.12 /document/{key}: {lang!r} is not a valid language tag")


def _check_revision_history(document: Dict[str, Any], errors: List[str]) -> None:
    tracking = document.get("tracking") or {}
    history = tracking.get("revision_history") or []
    if not history:
        return
    numbers = [str(r.get("number")) for r in history]
    dates = [r.get("date") for r in history]

    # 6.1.14 Sorted Revision History (ascending by date)
    valid_dates = [d for d in dates if d]
    if valid_dates != sorted(valid_dates):
        errors.append("6.1.14 /document/tracking/revision_history: entries not sorted by date")

    # 6.1.22 Multiple Definition in Revision History (duplicate numbers)
    for num, c in Counter(numbers).items():
        if c > 1:
            errors.append(
                f"6.1.22 /document/tracking/revision_history: version {num!r} defined {c} times"
            )

    # 6.1.30 Mixed Integer and Semantic Versioning: every version (document +
    # revision numbers) must follow the same scheme.
    all_versions = numbers + [str(tracking.get("version"))]
    integers = [v for v in all_versions if v.isdigit()]
    if integers and len(integers) != len(all_versions):
        errors.append(
            "6.1.30 /document/tracking: mixed integer and semantic versioning "
            f"({sorted(set(all_versions))})"
        )

    # 6.1.21 Missing Item in Revision History: integer versions must be a
    # gap-free 1..n sequence when integer versioning is used.
    if all(n.isdigit() for n in numbers):
        ordered = sorted(int(n) for n in numbers)
        expected = list(range(1, len(ordered) + 1))
        if ordered != expected:
            errors.append(
                "6.1.21 /document/tracking/revision_history: integer versions are not a "
                f"gap-free 1..n sequence (got {ordered})"
            )

    # 6.1.16 Latest Document Version: document version tracks newest revision.
    doc_version = str(tracking.get("version"))
    latest = history[-1].get("number")
    if latest is not None and doc_version != str(latest):
        errors.append(
            f"6.1.16 /document/tracking/version: {doc_version!r} does not match latest "
            f"revision {str(latest)!r}"
        )

    # Draft/version consistency. "Pre-release" means integer version 0, a
    # 0.x.x semver, or a semver with a pre-release segment (``1.0.0-rc1``).
    #   6.1.17 Document Status Draft -> a pre-release document version must
    #          carry status 'draft' (§6.1.20 is the logical contrapositive of
    #          this same rule, so it is not reported separately to avoid
    #          double-counting one problem).
    #   6.1.18 Released Revision History -> when status is final/interim, no
    #          *revision-history entry* may have number 0 or 0.y.z.
    status = tracking.get("status")
    is_zero_version = doc_version in ("0", "") or doc_version.startswith("0.")
    # A '-' only denotes a pre-release when it is in the version core, not in
    # semver build metadata (the '+' segment), which is allowed for final docs.
    is_prerelease = is_zero_version or "-" in doc_version.split("+", 1)[0]
    if is_prerelease and status and status != "draft":
        errors.append(
            f"6.1.17 /document/tracking: version {doc_version!r} is a pre-release but status "
            f"is {status!r} (must be 'draft')"
        )
    if status in ("final", "interim"):
        for i, num in enumerate(numbers):
            if num in ("0", "") or num.startswith("0."):
                errors.append(
                    f"6.1.18 /document/tracking/revision_history[{i}]: status {status!r} must "
                    f"not include revision number {num!r}"
                )

    # 6.1.19 Revision History Entries for Pre-release Versions: no revision
    # number may carry a pre-release segment (e.g. ``1.0.0-rc1``).
    for i, num in enumerate(numbers):
        if "-" in num.split("+", 1)[0]:  # ignore semver build metadata
            errors.append(
                f"6.1.19 /document/tracking/revision_history[{i}]: revision number {num!r} "
                f"must not include pre-release information"
            )


def _check_dates(doc: Dict[str, Any], version: str, errors: List[str]) -> None:
    # 6.1.37 Date and Time -- RFC 3339 with an (upper-case) timezone.
    def dt(value: Optional[str], path: str) -> None:
        if value and not is_rfc3339(value):
            errors.append(f"6.1.37 {path}: {value!r} is not an RFC 3339 date-time with timezone")

    tracking = (doc.get("document") or {}).get("tracking") or {}
    dt(tracking.get("current_release_date"), "/document/tracking/current_release_date")
    dt(tracking.get("initial_release_date"), "/document/tracking/initial_release_date")
    for i, rev in enumerate(tracking.get("revision_history") or []):
        dt(rev.get("date"), f"/document/tracking/revision_history[{i}]/date")
    for i, vuln in enumerate(doc.get("vulnerabilities") or []):
        base = f"/vulnerabilities[{i}]"
        dt(vuln.get("disclosure_date"), f"{base}/disclosure_date")
        dt(vuln.get("discovery_date"), f"{base}/discovery_date")
        if version == "2.0":  # release_date only exists in CSAF 2.0
            dt(vuln.get("release_date"), f"{base}/release_date")
        for j, fl in enumerate(vuln.get("flags") or []):
            dt(fl.get("date"), f"{base}/flags[{j}]/date")
        for j, rem in enumerate(vuln.get("remediations") or []):
            dt(rem.get("date"), f"{base}/remediations[{j}]/date")
        for j, thr in enumerate(vuln.get("threats") or []):
            dt(thr.get("date"), f"{base}/threats[{j}]/date")


# --------------------------------------------------------------------------- #
# Vulnerabilities                                                              #
# --------------------------------------------------------------------------- #
def _metrics(vuln: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return score entries for either CSAF 2.0 (``scores``) or 2.1 (``metrics``)."""
    return list(vuln.get("metrics") or vuln.get("scores") or [])


def _cvss_body(metric: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    content = metric.get("content") if isinstance(metric.get("content"), dict) else metric
    return content.get("cvss_v4") or content.get("cvss_v3") or content.get("cvss_v2")


def _check_vulnerabilities(
    vulns: List[Dict[str, Any]],
    defined: Set[str],
    category: Optional[str],
    group_map: Dict[str, Set[str]],
    version: str,
    errors: List[str],
) -> None:
    # The §6.1.27.x tests are VEX-profile-specific; they must not fire for
    # other document categories (e.g. csaf_security_advisory legitimately uses
    # first_affected/last_affected and needs no VEX action statement).
    is_vex = category == "csaf_vex"
    cve_uses: Counter = Counter()
    for i, vuln in enumerate(vulns):
        base = f"/vulnerabilities[{i}]"
        product_status = vuln.get("product_status") or {}

        # 6.1.27.8 Vulnerability ID: at least one of cve/ids (VEX profile).
        if is_vex and not vuln.get("cve") and not vuln.get("ids"):
            errors.append(f"6.1.27.8 {base}: vulnerability has neither 'cve' nor 'ids'")
        if vuln.get("cve"):
            cve_uses[vuln["cve"]] += 1
            if not _CVE_RE.match(str(vuln["cve"])):
                # No dedicated §6.1 test for CVE format (the JSON Schema pattern
                # enforces it); report under the Vulnerability ID profile test.
                errors.append(f"6.1.27.8 {base}/cve: {vuln['cve']!r} is not a valid CVE id")

        # Every status name must be one of the nine defined values (a schema
        # enum constraint, not a §6.1 semantic test), and for VEX a core status
        # must be present (§6.1.27.7).
        pid_to_status: Dict[str, List[str]] = defaultdict(list)
        for status, pids in product_status.items():
            if version == "2.1" and status not in _ALL_STATUS:
                errors.append(f"schema {base}/product_status: unknown status {status!r}")
            for pid in pids or []:
                pid_to_status[pid].append(status)
        if is_vex and not (set(product_status) & _VEX_STATUS):
            errors.append(
                f"6.1.27.7 {base}/product_status: none of the core VEX statuses "
                f"({sorted(_VEX_STATUS)}) is present"
            )
        # 6.1.6 Contradicting Product Status (``recommended`` may overlap).
        for pid, statuses in pid_to_status.items():
            contradicting = [s for s in statuses if s in _CONTRADICTION_STATUS]
            if len(contradicting) > 1:
                errors.append(
                    f"6.1.6 {base}/product_status: product {pid!r} appears in multiple "
                    f"statuses {sorted(contradicting)}"
                )

        if is_vex:
            # 6.1.27.9 Impact Statement: each known_not_affected product needs a
            # flag or an ``impact`` threat.
            _check_impact_statement(vuln, product_status, group_map, base, errors)
            # 6.1.27.10 Action Statement: each known_affected product needs a
            # remediation.
            _check_action_statement(vuln, product_status, group_map, base, errors)

        # 6.1.7 Multiple Scores with same Version per Product.
        _check_scores(vuln, i, errors)

        # 6.1.11 CWE.
        _check_cwes(vuln, version, base, errors)

        # 6.1.32 Flag without Product Reference + 6.1.33 Multiple Justifications.
        prod_just: Counter = Counter()
        for j, flag in enumerate(vuln.get("flags") or []):
            pids = list(flag.get("product_ids") or [])
            if not (pids or flag.get("group_ids")):
                errors.append(f"6.1.32 {base}/flags[{j}]: flag references no products")
            if flag.get("label") in _JUSTIFICATION_LABELS:
                for pid in pids:
                    prod_just[pid] += 1
        for pid, c in prod_just.items():
            if c > 1:
                errors.append(
                    f"6.1.33 {base}/flags: product {pid!r} has {c} VEX justification flags"
                )

        # 6.1.29 Remediation without Product Reference.
        for j, rem in enumerate(vuln.get("remediations") or []):
            if not (rem.get("product_ids") or rem.get("group_ids")):
                errors.append(
                    f"6.1.29 {base}/remediations[{j}]: remediation references no products"
                )

    # 6.1.23 Multiple Use of Same CVE.
    for cve, c in cve_uses.items():
        if c > 1:
            errors.append(f"6.1.23 /vulnerabilities: CVE {cve!r} used in {c} vulnerability items")


def _check_impact_statement(
    vuln: Dict[str, Any],
    product_status: Dict[str, Any],
    group_map: Dict[str, Set[str]],
    base: str,
    errors: List[str],
) -> None:
    # 6.1.27.9: every known_not_affected product needs a flag or impact threat,
    # referenced directly or via a product group (§4.5).
    not_affected = set(product_status.get("known_not_affected") or [])
    if not not_affected:
        return
    covered: Set[str] = set()
    for flag in vuln.get("flags") or []:
        covered |= _expand(flag.get("product_ids"), flag.get("group_ids"), group_map)
    for threat in vuln.get("threats") or []:
        if threat.get("category") == "impact":
            covered |= _expand(threat.get("product_ids"), threat.get("group_ids"), group_map)
    for pid in sorted(not_affected - covered):
        errors.append(
            f"6.1.27.9 {base}: known_not_affected product {pid!r} has no impact statement "
            f"(flag or 'impact' threat)"
        )


def _check_action_statement(
    vuln: Dict[str, Any],
    product_status: Dict[str, Any],
    group_map: Dict[str, Set[str]],
    base: str,
    errors: List[str],
) -> None:
    # 6.1.27.10: every known_affected product needs a remediation, referenced
    # directly or via a product group (§4.5).
    affected = set(product_status.get("known_affected") or [])
    if not affected:
        return
    remediated: Set[str] = set()
    for rem in vuln.get("remediations") or []:
        remediated |= _expand(rem.get("product_ids"), rem.get("group_ids"), group_map)
    for pid in sorted(affected - remediated):
        errors.append(
            f"6.1.27.10 {base}: known_affected product {pid!r} has no remediation action statement"
        )


def _check_scores(vuln: Dict[str, Any], i: int, errors: List[str]) -> None:
    base = f"/vulnerabilities[{i}]"
    per_product_version: Counter = Counter()
    for metric in _metrics(vuln):
        body = _cvss_body(metric)
        if not isinstance(body, dict):
            continue
        cvss_version = str(body.get("version") or "")
        family = cvss_version.split(".")[0] if cvss_version else "?"
        # §6.1.7 forbids duplicates of the same version *and same source*;
        # scores from distinct sources are permitted.
        source = str(metric.get("source") or (metric.get("content") or {}).get("source") or "")
        for pid in metric.get("products") or []:
            per_product_version[(pid, family, source)] += 1
        _check_cvss_body(body, base, errors)
    for (pid, family, _source), c in per_product_version.items():
        if c > 1:
            errors.append(
                f"6.1.7 {base}/metrics: product {pid!r} has {c} CVSS v{family} scores "
                f"from the same source (only one per version+source per product is allowed)"
            )


def _severity_band(score: float, is_v2: bool) -> str:
    if is_v2:
        return "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH"
    if score == 0:
        return "NONE"
    return "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH" if score < 9 else "CRITICAL"


def _check_cvss_body(body: Dict[str, Any], base: str, errors: List[str]) -> None:
    vector = body.get("vectorString")
    version = str(body.get("version") or "")
    declared = body.get("baseScore")
    # 6.1.8/6.1.9 Invalid CVSS + computation: recompute base score from vector.
    if vector and _cvss is not None:
        computed = _recompute_base(vector, version)
        if computed is None:
            errors.append(f"6.1.8 {base}/metrics: unparseable CVSS vector {vector!r}")
        elif declared is not None and abs(float(declared) - computed) > 0.01:
            errors.append(
                f"6.1.9 {base}/metrics: baseScore {declared} does not match vector "
                f"{vector!r} (computed {computed})"
            )
    # 6.1.10 Inconsistent CVSS: baseSeverity must match the baseScore band.
    severity = str(body.get("baseSeverity") or "").upper()
    if declared is not None and severity:
        band = _severity_band(float(declared), is_v2=version.startswith("2"))
        if severity != band:
            errors.append(
                f"6.1.10 {base}/metrics: baseSeverity {severity!r} inconsistent with "
                f"baseScore {declared} (expected {band})"
            )


def _recompute_base(vector: str, version: str) -> Optional[float]:
    # cvss is a hard dependency; _cvss is None only in broken environments
    # (see the guarded import at the top of this module).
    if _cvss is None:
        return None
    try:
        if version.startswith("4"):
            score: Optional[float] = _cvss.CVSS4(vector).base_score
        elif version.startswith("3"):
            score = _cvss.CVSS3(vector).base_score
        elif version.startswith("2"):
            score = _cvss.CVSS2(vector).base_score
        else:
            return None
    except Exception:
        return None
    # base_score is Optional in the cvss API; None means the vector is
    # malformed, which the caller treats the same as an exception.
    return float(score) if score is not None else None


def _check_cwes(vuln: Dict[str, Any], version: str, base: str, errors: List[str]) -> None:
    entries: List[Dict[str, Any]] = []
    if isinstance(vuln.get("cwe"), dict):
        entries.append(vuln["cwe"])
    entries.extend(c for c in (vuln.get("cwes") or []) if isinstance(c, dict))
    for cwe in entries:
        if not _CWE_RE.match(str(cwe.get("id") or "")):
            errors.append(f"6.1.11 {base}: invalid CWE id {cwe.get('id')!r}")
        if not str(cwe.get("name") or "").strip():
            errors.append(f"6.1.11 {base}: CWE {cwe.get('id')!r} missing name")
