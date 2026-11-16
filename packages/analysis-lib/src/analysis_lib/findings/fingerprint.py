"""Stable, line-free fingerprints for dep-scan findings.

A finding id must survive unrelated edits to the scanned project, so it is
computed only from stable parts: the category, the rule or advisory id, the
affected component purls without versions, the file relative to the scan root,
the enclosing function and the symbol names on the evidence path. Line and
column numbers never enter the id, which is what lets baselines and
suppressions keep matching a finding after code moves around it.

The fingerprint matches the plugins memory-safety contract (rule, canonical
function, relative file, the API names in the flow); dep-scan adds the
component set, so findings in different packages never collide.

Monorepo copies. Findings that have no source location (vulnerability, malware,
license and health) would otherwise collapse onto one id for every copy of the
same vulnerable package in a monorepo, because all their other stable inputs
are identical. Those findings therefore take their file from the manifest or
lockfile that declared the component. Two copies of pkg:npm/lodash@4.17.20
declared by services/billing/package-lock.json and services/web/
package-lock.json get different ids, so suppressing one does not silence the
other. When the declaring path is unknown the file is empty and the copies do
share an id; producers are expected to record the declaring path so that stays
the uncommon case.

Encoding. The id is dsf1: followed by the SHA-256 hex digest of the UTF-8
serialisation of the JSON array ``["dsf", 1, category, rule, components, file,
function, symbols]`` written with ensure_ascii=False and no extra whitespace.
The leading "dsf", 1 pair versions the algorithm; a future change would
produce dsf2 ids and never alter a dsf1 id. The test vectors next to the
schema reproduce every id from their raw inputs alone, which is what a
TypeScript or Go implementation needs.
"""

import hashlib
import json
import re
from typing import Any, Iterable, List

from packageurl import PackageURL

FINGERPRINT_VERSION = 1

_ID_PREFIX = f"dsf{FINGERPRINT_VERSION}:"

# Mirrors the category enum in depscan-finding.schema.json; a test keeps the
# two in step.
CATEGORIES = (
    "vulnerability",
    "malware",
    "memory-safety",
    "supply-chain",
    "binary-hardening",
    "mobile",
    "code",
    "license",
    "crypto",
    "health",
)

_CVE_RULE = re.compile(r"^cve-", re.IGNORECASE)
_GHSA_RULE = re.compile(r"^ghsa-", re.IGNORECASE)
_DRIVE_PATH = re.compile(r"^[A-Za-z]:(/|$)")


def normalise_rule(rule: str) -> str:
    """Trim the rule and give advisory ids their canonical case.

    CVE ids come out upper case, GHSA ids keep the GHSA- prefix and lower-case
    groups, and every other rule id is kept as given.
    """
    trimmed = rule.strip()
    if _CVE_RULE.match(trimmed):
        return trimmed.upper()
    if _GHSA_RULE.match(trimmed):
        return "GHSA-" + trimmed[5:].lower()
    return trimmed


def normalise_purl(purl: str) -> str:
    """Reduce a purl to its type, namespace and name.

    Version, qualifiers and subpath are dropped because the fingerprint treats
    every affected version of a package as one finding. packageurl-python
    lower-cases the type and applies its per-type name normalisation, so
    pkg:NPM/Express@4.2.0 and pkg:npm/express@4.22.2 both reduce to
    pkg:npm/express.
    """
    try:
        parsed = PackageURL.from_string(purl)
    except ValueError as exc:
        raise ValueError(f"invalid purl {purl!r} in finding components") from exc
    stripped = PackageURL(
        type=parsed.type, namespace=parsed.namespace or None, name=parsed.name
    )
    return stripped.to_string()


def normalise_file(file: str) -> str:
    """Normalize a path for hashing: forward slashes and no leading ./.

    Case is kept, because on case-sensitive filesystems two paths that differ
    only in case are different files. The path must be relative to the scan
    root. An absolute path (POSIX, a Windows drive or a UNC share) raises
    ValueError, because it would tie the id to one machine's checkout location
    and carry that location into reports.
    """
    normalised = file.replace("\\", "/")
    if normalised.startswith("/") or _DRIVE_PATH.match(normalised):
        raise ValueError(f"file must be relative to the scan root, got {file!r}")
    while normalised.startswith("./"):
        normalised = normalised[2:]
    return normalised


def _canonical_payload(
    category: str,
    rule: str,
    components: Iterable[str],
    file: str = "",
    function: str = "",
    symbols: Iterable[str] = (),
) -> List[Any]:
    """Assemble the array that gets serialised and hashed.

    components are sorted and de-duplicated after normalisation, and symbols
    keep their first occurrence in path order. Both are collections, so a
    plain string would iterate one character at a time; the type checks below
    turn that mistake into an error instead of a silently wrong id.
    """
    if category not in CATEGORIES:
        raise ValueError(f"unknown finding category {category!r}")
    if not isinstance(rule, str) or not rule.strip():
        raise ValueError("rule must be a non-empty string")
    if isinstance(components, str):
        raise ValueError("components must be a sequence of purl strings, not one string")
    if isinstance(symbols, str):
        raise ValueError("symbols must be a sequence of names, not one string")
    component_set = sorted({normalise_purl(purl) for purl in components})
    seen_symbols: set = set()
    symbol_list = []
    for symbol in symbols:
        if symbol not in seen_symbols:
            seen_symbols.add(symbol)
            symbol_list.append(symbol)
    return [
        "dsf",
        FINGERPRINT_VERSION,
        category,
        normalise_rule(rule),
        component_set,
        normalise_file(file or ""),
        function or "",
        symbol_list,
    ]


def finding_fingerprint(
    category: str,
    rule: str,
    components: Iterable[str],
    file: str = "",
    function: str = "",
    symbols: Iterable[str] = (),
) -> str:
    """Compute the dsf1 fingerprint for a finding from its raw inputs.

    Callers pass the values as they have them: a rule in any case, purls with
    versions and qualifiers, a file path in any shape. Every input is
    normalised here, and the same inputs in any shape always produce the same
    id. An invalid purl or an empty category or rule raises ValueError.
    """
    payload = _canonical_payload(category, rule, components, file, function, symbols)
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return _ID_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
