#!/usr/bin/env python3
"""The corpus scorer: run dep-scan on the corpus, score it against the labels.

Every corpus item states what dep-scan must find and what it must not. This
script runs the item's scan (or reads a scan directory made earlier), scores
per item, per finding category and per join, and writes ``score.json`` with a
Markdown table beside it. A result dep-scan did not assess is its own column
with its reason; it is never a miss and never a clean pass.

Usage:
    # Run every item whose inputs are present, cloning what is missing; the
    # clones, scans and pulled data default to ~/.cache/depscan/corpus/
    python contrib/corpus/score.py --fetch

    # Score a few items, from scans made earlier
    python contrib/corpus/score.py --scan-dir /tmp/corpus-scans \
        --items js-express-realworld,py-vulpy

    # The CI subset, failing on a dropped floor or a fired negative control
    python contrib/corpus/score.py --subset ci --scans-root /tmp/corpus-scans \
        --testdata-root repotests-data --floors contrib/corpus/floors.json

Inputs are resolved without the network unless a repository clone is missing:
repository items are cloned at the pinned commit of the corpus root and
checked by the digest of ``git archive``; BOM items read the repo-test data
pulled by digest under ``--testdata-root``; fixture items are the committed
directories beside this manifest, checked by a digest over their contents.
contrib/corpus/inputs.py resolves them. The scorer never runs a scanned
repository's build tooling (a fixture's own build script runs in the
fixture's copy), never parses console output (it reads the scan directory
through :func:`depscan.api.load_scan`), and compares every purl through
``comparable_purl``.
"""

from __future__ import annotations

import argparse
import functools
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _src in (
    os.path.join(_REPO_ROOT, "packages", "analysis-lib", "src"),
    os.path.join(_REPO_ROOT, "packages", "xbom-lib", "src"),
):
    if os.path.isdir(_src):
        sys.path.insert(0, _src)

from analysis_lib.evidence.store import stream as stream_evidence  # noqa: E402
from analysis_lib.findings.vdr_convert import comparable_purl  # noqa: E402
from analysis_lib.reachability import get_reachability_impl  # noqa: E402
from analysis_lib.reachability import ReachabilityAnalysisKV  # noqa: E402

if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from contrib.corpus.inputs import cache_dir, fixture_digest, git, resolve_payload  # noqa: E402
from vdb.lib.utils import parse_purl  # noqa: E402

#: The analysers the reachability scores are reported for, in report order.
ANALYZERS = ("FrameworkReachability", "SemanticReachability")

#: Manifest stage name to the finding categories whose assessment depends on
#: it. A stage that did not complete turns the category's score into a
#: not-assessed entry with the stage's reason, never into a zero.
STAGE_CATEGORIES = {
    "risk": ("supply-chain",),
    "licenses": ("license",),
    "matching": ("vulnerability", "malware"),
    "binary-review": ("binary-hardening",),
}

#: The finding categories an advisory match produces.
ADVISORY_CATEGORIES = ("vulnerability", "malware")

#: Component properties that record the image layer a component was found
#: in: the field the draft upstream issue asks for, and the two trivy writes.
LAYER_PROPERTIES = (
    "cdx:image:layerDigest",
    "aquasecurity:trivy:LayerDigest",
    "aquasecurity:trivy:LayerDiffID",
)

#: Component properties that name the manifest or lock file a component was
#: read from; cdxgen writes internal:SrcFile.
DECLARING_PATH_PROPERTIES = ("SrcFile", "internal:SrcFile", "depscan:srcFile")

#: The lifecycle phase each BOM file-name prefix stands for.
PHASE_PREFIXES = {"prebuild-": "pre-build", "build-": "build", "postbuild-": "post-build"}


class ScoreError(RuntimeError):
    """The scorer could not produce a score; the message says why."""


def load_json(path: str):
    """Read one JSON document, or None when it cannot be read."""
    try:
        with open(path, encoding="utf-8") as fp:
            return json.load(fp)
    except (OSError, ValueError):
        return None


@functools.lru_cache(maxsize=None)
def split_purl(purl: str):
    """A purl's comparable_purl form split into (key, version), or
    (comparable form, None) when it has no version. The version comes from
    the parsed purl, so a version that holds a slash once decoded
    (``refs/heads/main``) and the ``@`` of an npm scope are both read right."""
    comparable = comparable_purl(str(purl))
    if comparable[:9].lower() == "pkg:pypi/":
        # PyPI names compare equal under PEP 503: case and runs of "-", "_"
        # and "." do not matter.
        name, sep, version = comparable[9:].partition("@")
        comparable = "pkg:pypi/" + re.sub(r"[-_.]+", "-", name).lower() + sep + version
    try:
        version = (parse_purl(str(purl)) or {}).get("version")
    except Exception:  # noqa: BLE001 - an unparsable purl has no version to split
        version = None
    if version and comparable.lower().endswith("@" + str(version).lower()):
        return comparable[: -len(str(version)) - 1], comparable[-len(str(version)) :]
    return comparable, None


def purl_key(purl: str) -> str:
    """The version-less comparable key of a purl."""
    return split_purl(purl)[0]


def label_key(purl: str) -> str:
    """The key a label matches on: the whole comparable purl when the label
    names a version, so it matches only that version, and the version-less
    key otherwise, so it matches any version."""
    key, version = split_purl(purl)
    return f"{key}@{version}" if version is not None else key


def label_keys(purls) -> set:
    """The match keys of several label purls."""
    return {label_key(p) for p in purls or []}


def keys_of(purls) -> set:
    """Every key a seen purl answers to: its version-less key, and its whole
    comparable form when it carries a version. A label key is in this set
    exactly when the label matches one of the purls."""
    keys = set()
    for purl in purls or []:
        keys |= {purl_key(purl), label_key(purl)}
    return keys


def rate(hit_count: int, total: int):
    """A recall or precision rate, or None when nothing is labelled."""
    return round(hit_count / total, 4) if total else None


# ---------------------------------------------------------------------------
# corpus and labels


def load_manifest(path: str) -> dict:
    """Read the corpus manifest, refusing an unknown schema version."""
    document = load_json(path)
    if not isinstance(document, dict) or not isinstance(document.get("items"), list):
        raise ScoreError(f"Cannot read the corpus manifest '{path}'.")
    if document.get("schemaVersion") != 1:
        raise ScoreError(
            f"The corpus manifest '{path}' has schemaVersion "
            f"{document.get('schemaVersion')!r}, which this scorer does not know."
        )
    return document


def load_labels(manifest_dir: str, item: dict):
    """Read an item's label file, or None when it is missing."""
    document = load_json(os.path.join(manifest_dir, item.get("labels", "")))
    if document is not None and document.get("item") != item["name"]:
        raise ScoreError(
            f"The label file '{item.get('labels')}' names item "
            f"'{document.get('item')}', but the manifest item is '{item['name']}'."
        )
    return document


def select_items(manifest: dict, args) -> list:
    """The items this run scores, in manifest order."""
    items = manifest["items"]
    if args.items:
        wanted = {name.strip() for name in args.items.split(",") if name.strip()}
        unknown = sorted(wanted - {item["name"] for item in items})
        if unknown:
            raise ScoreError("The manifest holds no item named: " + ", ".join(unknown))
        items = [item for item in items if item["name"] in wanted]
    if args.subset:
        items = [item for item in items if item.get("subset") == args.subset]
        if not items:
            raise ScoreError(f"The subset '{args.subset}' holds no items.")
    return items


# ---------------------------------------------------------------------------
# scanning


def build_scan_options(item: dict, payload, reports_dir: str):
    """The internal options of the item's scan command line: the payload,
    one ``-t`` with every type (a repeated ``-t`` replaces), then the item's
    arguments, converted the way the scan verb converts them."""
    from depscan.commands import build_parser
    from depscan.commands import checks as checks_table
    from depscan.commands.scan import _apply_target_options, detect_kind, scan_namespace

    tokens = ["scan", str(payload)]
    if item["scan"].get("types"):
        tokens += ["-t", *item["scan"]["types"]]
    tokens += ["--reports-dir", reports_dir, *(item["scan"].get("args") or [])]
    if item["scan"].get("lifecycles"):
        tokens += ["--lifecycle", *item["scan"]["lifecycles"]]
    args = build_parser().parse_args(tokens)
    resolution = checks_table.resolve(args)
    options = argparse.Namespace(**vars(scan_namespace(args, resolution=resolution)))
    kind, _ = detect_kind(str(payload))
    _apply_target_options(options, str(payload), kind, args, resolution)
    options.reports_dir = reports_dir
    options.no_banner = True
    return options, resolution


def run_item_scan(item: dict, payload, reports_dir: str):
    """Run the item's scan through :func:`depscan.api.scan` with rendering
    off, and return (result, None) or (None, reason). The scan runs to its
    end; the workflow's job timeout bounds a scan that hangs."""
    from depscan import api

    options, resolution = build_scan_options(item, payload, reports_dir)
    try:
        result = api.scan(
            options, render=False, checks_not_assessed=resolution.not_assessed or None
        )
    except api.ScanError as exc:
        return None, f"the scan stopped early: {exc}"
    except Exception as exc:  # noqa: BLE001 - a failed scan is the item's result
        return None, f"{type(exc).__name__}: {exc}"
    return result, None


# ---------------------------------------------------------------------------
# one item's scan directory, read once


class ItemScan:
    """One item's scan: the :class:`depscan.api.ScanResult` (or an object
    with its ``reports_dir``, ``findings``, ``manifest`` and
    ``project_types``), with the BOMs, evidence records and analyser results
    each read or computed once. ``src_dir`` is the scanned source, if any."""

    def __init__(self, item: dict, result, src_dir=None):
        self.item = item
        self.result = result
        self.reports_dir = result.reports_dir
        self.src_dir = src_dir if isinstance(src_dir, str) and os.path.isdir(src_dir) else None
        self._reach: dict = {}

    @property
    def findings(self) -> list:
        return list(getattr(self.result, "findings", None) or [])

    @property
    def stages(self) -> list:
        return (getattr(self.result, "manifest", None) or {}).get("stages") or []

    @property
    def project_types(self) -> list:
        return list(
            self.item.get("scan", {}).get("types")
            or getattr(self.result, "project_types", None)
            or []
        )

    @functools.cached_property
    def boms(self) -> dict:
        """Every ``sbom-*.cdx.json`` of the scan directory, by the file name's
        stem (``js``, ``build-js``, ``postbuild-python``)."""
        boms = {}
        try:
            names = sorted(os.listdir(self.reports_dir))
        except OSError:
            names = []
        for name in names:
            if name.startswith("sbom-") and name.endswith(".cdx.json"):
                bom = load_json(os.path.join(self.reports_dir, name))
                if isinstance(bom, dict):
                    boms[name[len("sbom-") : -len(".cdx.json")]] = bom
        return boms

    def components(self, phases=(None, "build")) -> list:
        """The component dicts of the BOMs of the given lifecycle phases,
        where a BOM without a phase prefix (a type BOM) is phase None."""
        return [
            component
            for stem, bom in self.boms.items()
            if next((p for pre, p in PHASE_PREFIXES.items() if stem.startswith(pre)), None)
            in phases
            for component in bom.get("components") or []
            if isinstance(component, dict)
        ]

    @functools.cached_property
    def evidence(self) -> list:
        """The scan directory's evidence records, or an empty list."""
        path = os.path.join(self.reports_dir, "evidence.jsonl")
        if not os.path.isfile(path):
            return []
        try:
            return list(stream_evidence(path))
        except (OSError, ValueError):
            return []

    def reach(self, analyzer: str):
        """One analyser's result over the scan directory, as (result, None),
        or (None, reason) when it produced nothing, which is a not-assessed
        entry, never a zero. Each analyser runs once per item."""
        if analyzer not in self._reach:
            evidence_file = os.path.join(self.reports_dir, "evidence.jsonl")
            options = ReachabilityAnalysisKV(
                project_types=self.project_types,
                src_dir=self.src_dir or self.reports_dir,
                bom_dir=self.reports_dir,
                evidence_file=evidence_file if os.path.isfile(evidence_file) else None,
            )
            res = get_reachability_impl(analyzer, options).process()
            if not res.success and not (res.direct_purls or res.reached_purls):
                self._reach[analyzer] = (
                    None,
                    "the analyzer produced no result over this scan directory",
                )
            else:
                self._reach[analyzer] = (res, None)
        return self._reach[analyzer]


# ---------------------------------------------------------------------------
# finding categories and reachability


def brief(finding: dict, **extra) -> dict:
    """The id, rule and purls of a finding, for a score's lists."""
    return {
        "rule": finding.get("rule"),
        "purls": finding.get("components") or [],
        "id": finding.get("id"),
        **extra,
    }


def finding_matches(finding: dict, entry: dict) -> bool:
    """Whether a finding is of a label entry's category, carries one of its
    rules (any rule when the entry names none) and sits on its purl (any
    purl when it names none)."""
    rules = {str(rule).lower() for rule in entry.get("rules") or []}
    return (
        finding.get("category") == entry["category"]
        and (not rules or str(finding.get("rule") or "").lower() in rules)
        and (
            not entry.get("purl") or label_key(entry["purl"]) in keys_of(finding.get("components"))
        )
    )


def score_findings(findings: list, expected: list, forbidden: list) -> dict:
    """Score the findings of one result against expected and forbidden
    label entries of one category.

    Recall counts the expected (category, purl, rules) entries the result
    matched. Precision counts, over the findings on labelled purls, how many
    an expected entry accounts for; findings on purls no label names are
    neither hits nor misses, because the labels do not pass judgement on
    them. A fired forbidden entry (a negative control) is reported with the
    finding's id.
    """
    matched_findings = set()
    missed = []
    for entry in expected:
        index = next((i for i, f in enumerate(findings) if finding_matches(f, entry)), None)
        if index is None:
            missed.append(entry)
        else:
            matched_findings.add(index)
    hits = len(expected) - len(missed)
    fired = [
        brief(finding, reason=control.get("reason"))
        for control in forbidden
        for finding in findings
        if finding_matches(finding, control)
    ]
    # A finding on a purl an expected entry names is a true positive of the
    # label even when its rule id differs: the rules list proves the
    # advisory, it does not bound it. Any other finding on a purl the same
    # category's controls name is unexpected; a forbidden purl is controlled
    # for its own category only.
    expected_keys = label_keys(e["purl"] for e in expected)
    controlled = {}
    for control in forbidden:
        if control.get("purl"):
            controlled.setdefault(control["category"], set()).add(label_key(control["purl"]))
    unexpected = [
        brief(finding)
        for index, finding in enumerate(findings)
        if index not in matched_findings
        and not keys_of(finding.get("components")) & expected_keys
        and keys_of(finding.get("components")) & controlled.get(finding.get("category"), set())
    ]
    return {
        "expected": len(expected),
        "hits": hits,
        "recall": rate(hits, len(expected)),
        "unexpected": len(unexpected),
        "precision": rate(hits, hits + len(unexpected)),
        "missed": missed,
        "unexpectedFindings": unexpected,
        "forbiddenFired": fired,
    }


def stage_outcome(scan: ItemScan, category: str):
    """Whether the stages behind a category ran, as (reason, skipped types).

    Stages are recorded per project type. A category is not assessed (a
    reason comes back) only when no stage that produces it completed for any
    project type; otherwise the reason is None and the types whose stage did
    not complete are listed beside the score.
    """
    names = [name for name, cats in STAGE_CATEGORIES.items() if category in cats]
    stages = [stage for stage in scan.stages if stage.get("name") in names]
    skipped = [
        {
            "projectType": stage.get("projectType") or "",
            "stage": stage.get("name"),
            "status": stage.get("status"),
            "reason": stage.get("reason")
            or f"the {stage.get('name')} stage {stage.get('status')}",
        }
        for stage in stages
        if stage.get("status") != "completed"
    ]
    if not stages or len(skipped) < len(stages):
        return None, skipped
    return "; ".join(
        f"{entry['projectType']}: {entry['reason']}" if entry["projectType"] else entry["reason"]
        for entry in skipped
    ), skipped


def score_categories(scan: ItemScan, labels: dict) -> dict:
    """Every category the findings or the labels name, plus every category
    whose stage did not complete: an unassessed check is its own column,
    never silence."""
    findings = scan.findings
    section = labels.get("findings") or {}
    expected = section.get("expected") or []
    forbidden = section.get("forbidden") or []
    names = {str(f.get("category")) for f in findings}
    names |= {e["category"] for e in expected + forbidden}
    names |= {
        category
        for cats in STAGE_CATEGORIES.values()
        for category in cats
        if stage_outcome(scan, category)[0]
    }
    categories = {}
    for category in sorted(names):
        reason, skipped = stage_outcome(scan, category)
        if reason:
            categories[category] = {
                "status": "not-assessed",
                "reason": reason,
                "recall": None,
                "precision": None,
            }
            continue
        own_expected = [e for e in expected if e["category"] == category]
        own_forbidden = [e for e in forbidden if e["category"] == category]
        scored = score_findings(findings, own_expected, own_forbidden)
        if own_expected or own_forbidden:
            scored["status"] = "assessed"
        else:
            scored["status"] = "unlabelled"
            scored["reason"] = "the item labels no expected or forbidden findings of this category"
        if skipped:
            scored["notAssessedTypes"] = skipped
        categories[category] = scored
    return categories


def score_purl_set(keys: set, used: set, unused: set, unmapped_used: int = 0) -> dict:
    """Recall and precision of one purl set against used and unused labels.

    Recall is the share of used packages the set holds, where the
    ``unmapped_used`` names the derivation could not turn into a purl count
    as used packages the set misses. Precision is the share of used packages
    among everything the set holds that a label covers; a purl no label
    names counts nowhere, because the labels do not pass judgement on it.
    """
    labelled = keys & (used | unused)
    true_positive = keys & used
    return {
        "recall": rate(len(true_positive), len(used) + unmapped_used),
        "unmappedUsed": unmapped_used,
        "precision": rate(len(true_positive), len(labelled)),
        "missed": sorted(used - keys),
        "wrong": sorted(keys & unused),
        "labelledSeen": len(labelled),
        "seen": len({purl_key(key) for key in keys}),
    }


def usage_labels(labels: dict):
    """The used and unused label keys of an item, and the number of used
    names the derivation left unmapped."""
    section = labels.get("reachability") or {}
    return (
        label_keys(e["purl"] for e in section.get("used") or []),
        label_keys(e["purl"] for e in section.get("unused") or []),
        len(section.get("unmapped") or {}),
    )


def score_reachability(scan: ItemScan, labels: dict) -> dict:
    """Both analysers scored against the reachability labels, per project."""
    used, unused, unmapped = usage_labels(labels)
    scores = {}
    for analyzer in ANALYZERS:
        res, reason = scan.reach(analyzer)
        if res is None:
            scores[analyzer] = {"status": "not-assessed", "reason": reason}
            continue
        scores[analyzer] = {
            "status": "assessed",
            "direct": score_purl_set(keys_of(res.direct_purls), used, unused, unmapped),
            "reached": score_purl_set(keys_of(res.reached_purls), used, unused, unmapped),
        }
    return scores


def analyzer_not_assessed(scan: ItemScan) -> list:
    """The reachability not-assessed reasons the manifest records."""
    for stage in scan.stages:
        if stage.get("name") == "enrichment":
            return [
                {"analyzer": entry.get("name"), "reason": entry.get("reason")}
                for entry in stage.get("analyzers") or []
                if entry.get("status") in ("not-assessed", "failed")
            ]
    return []


# ---------------------------------------------------------------------------
# joins


def _location_key(location):
    return (os.path.normpath(str(getattr(location, "file", ""))), getattr(location, "line", None))


def score_join_advisory_usage_reach(scan: ItemScan, labels: dict) -> dict:
    """Reached and not-reached advisory findings (vulnerability and malware,
    the categories a match produces) against the used and unused labels.

    ``reachedOnUsed`` counts the reached findings on a used package, the
    join working; a reached finding on an unused package is its false
    positive, and a reached finding on a package no label names is counted
    apart, because the labels do not pass judgement on it.
    """
    used, unused, _ = usage_labels(labels)
    if not used and not unused:
        return {"outcome": "partial", "reason": "the item carries no usage labels"}
    res, reason = scan.reach("SemanticReachability")
    if res is None:
        return {"outcome": "partial", "reason": reason}
    reached = keys_of(res.reached_purls)
    advisories = [f for f in scan.findings if f.get("category") in ADVISORY_CATEGORIES]
    reached_on_used = 0
    reached_unlabelled = 0
    not_reached_on_used = []
    reached_on_unused = []
    for finding in advisories:
        keys = keys_of(finding.get("components"))
        short = {"id": finding.get("id"), "rule": finding.get("rule")}
        if not keys & reached:
            if keys & used:
                not_reached_on_used.append(short)
        elif keys & used:
            reached_on_used += 1
        elif keys & unused:
            reached_on_unused.append(short)
        else:
            reached_unlabelled += 1
    return {
        "outcome": "measured",
        "findings": len(advisories),
        "reachedOnUsed": reached_on_used,
        "notReachedOnUsed": not_reached_on_used,
        "reachedOnUnused": reached_on_unused,
        "reachedUnlabelled": reached_unlabelled,
        "reachedPurls": len({purl_key(p) for p in res.reached_purls or []}),
    }


def score_join_route_package(scan: ItemScan, labels: dict) -> dict:
    """Each labelled route must name the packages its handlers use.

    Two producers carry route evidence. An OpenAPI specification maps every
    route to the files and lines its handlers occupy (``x-atom-usages``), and
    the evidence store says which packages those places use. dosai writes
    the .NET routes as entry-point records whose id names the method and
    path, and its flow records name the packages with the handler locations
    they run through; the handler's span ends at the next entry-point record
    of the same file. A route neither producer puts a package on is a miss.
    """
    routes = ((labels.get("joins") or {}).get("route-package") or {}).get("routes") or []
    if not routes:
        return {"outcome": "partial", "reason": "the item labels no routes"}
    by_route = _openapi_usage_locations(scan.reports_dir)
    entry_points = _dosai_entry_points(scan.evidence)
    matched = 0
    missed = []
    for route in routes:
        found = None
        method = str(route.get("method") or "GET").upper()
        locations = by_route.get((method, route["path"]))
        if locations is not None:
            mechanism = "openapi"
            found = _packages_where(scan.evidence, lambda key: key in locations)
        else:
            mechanism = "dosai"
            span = _handler_span(entry_points, route["path"], method)
            if span is not None:
                file_name, start, end = span
                found = _packages_where(
                    scan.evidence,
                    lambda key: (
                        key[0] == file_name and isinstance(key[1], int) and start <= key[1] < end
                    ),
                )
        if found is None:
            missed.append(
                {"path": route["path"], "reason": "no route evidence from either producer"}
            )
            continue
        missing = label_keys(route.get("packages")) - found
        wrong = label_keys(route.get("controls")) & found
        if missing or wrong:
            missed.append(
                {
                    "path": route["path"],
                    "via": mechanism,
                    "missing": sorted(missing),
                    "wrong": sorted(wrong),
                }
            )
        else:
            matched += 1
    return {
        "outcome": "partial" if missed else "measured",
        "routes": len(routes),
        "routesMatched": matched,
        "missed": missed,
    }


def _openapi_usage_locations(reports_dir: str) -> dict:
    """(method, path) to the (file, line) set the OpenAPI operation's
    handlers occupy, from the ``x-atom-usages`` maps of every spec."""

    def mapping(value):
        return value.items() if isinstance(value, dict) else ()

    by_route: dict = {}
    for name in sorted(glob.glob(os.path.join(reports_dir, "*openapi*.json"))):
        for path, operations in mapping((load_json(name) or {}).get("paths")):
            for method, operation in mapping(operations):
                usages = operation.get("x-atom-usages") if isinstance(operation, dict) else None
                for kind, by_file in mapping(usages):
                    for file_name, lines in mapping(by_file) if kind in ("call", "target") else ():
                        by_route.setdefault((method.upper(), path), set()).update(
                            (os.path.normpath(file_name), line)
                            for line in (lines if isinstance(lines, list) else ())
                            if isinstance(line, int)
                        )
    return by_route


def _dosai_entry_points(records: list) -> list:
    """dosai's HTTP entry-point records as (file, line, method, path)."""
    entries = []
    for record in records:
        if record.producer.name != "dosai" or record.kind != "entry-point" or not record.locations:
            continue
        entry_id = str((record.attributes or {}).get("entryPointId") or "")
        marker = entry_id.split("#")[-1] if "#" in entry_id else ""
        if ":" in marker:
            method, _, path = marker.partition(":")
            entries.append((*_location_key(record.locations[0]), method, path))
    return entries


def _handler_span(entry_points: list, path: str, method: str):
    """The (file, first line, next entry's line) span of one route's handler,
    or None when no dosai record names the route."""
    matches = sorted(
        (r for r in entry_points if r[3] == path and r[2] == method),
        key=lambda r: (r[0], r[1] or 0),
    )
    if not matches:
        return None
    file_name, line = matches[0][0], matches[0][1] or 0
    following = sorted(r[1] or 0 for r in entry_points if r[0] == file_name and (r[1] or 0) > line)
    return (file_name, line, following[0] if following else 10**9)


def _packages_where(records: list, wanted) -> set:
    """The purl keys of the evidence records with a location ``wanted``
    accepts."""
    found = set()
    for record in records:
        purls = keys_of(record.subject.purls)
        if purls and any(wanted(_location_key(loc)) for loc in record.locations or []):
            found |= purls
    return found


def development_marker(component: dict):
    """What marks a component as a development-only dependency in the BOM:
    cdxgen's ``cdx:npm:package:development`` property, or an optional or
    excluded scope; None when nothing does."""
    if any(
        isinstance(p, dict)
        and p.get("name") == "cdx:npm:package:development"
        and str(p.get("value")).lower() == "true"
        for p in component.get("properties") or []
    ):
        return "cdx:npm:package:development"
    if component.get("scope") in ("optional", "excluded"):
        return f"scope {component['scope']}"
    return None


def is_development(component: dict) -> bool:
    """Whether the BOM marks a component as a development-only dependency."""
    return development_marker(component) is not None


#: The lifecycle labels, in report order.
LIFECYCLE_PHASES = ("shipped", "build-only", "dev-only")


def score_join_lifecycle_phase(scan: ItemScan, labels: dict) -> dict:
    """Packages labelled shipped, build-only or dev-only against what the
    scan says ships, reported per label.

    A post-build BOM that holds components is the shipped state: a shipped
    package must be in it, a build-only or dev-only one must not. A source
    scan's post-build BOM is empty, since nothing was built, so the build
    BOM (or the type BOM of a scan without lifecycles) answers instead: a
    shipped package must be in it without a development marker, a
    build-only or dev-only one must carry the marker
    (:func:`development_marker`). cdxgen marks a package a build script runs
    and one only a linter runs with the same property, and no property names
    the packages a build script runs, so the score says per label which
    marker it saw, and ``buildOnlyDistinct`` stays false: a build-only
    package that holds is one that does not ship, not one the BOM told
    apart from a dev-only one.
    """
    entries = ((labels.get("joins") or {}).get("lifecycle-phase") or {}).get("packages") or []
    if not entries:
        return {"outcome": "partial", "reason": "the item labels no lifecycle packages"}
    shipped = scan.components(("post-build",))
    build = scan.components(("build",)) or scan.components((None,))
    if not shipped and not build:
        return {"outcome": "partial", "reason": "the scan directory holds no component BOM"}
    matched = 0
    missed = []
    by_phase: dict = {}
    for entry in entries:
        key = label_key(entry["purl"])
        marker = None
        if shipped:
            observed = any(key in keys_of([c.get("purl") or ""]) for c in shipped)
            state = "shipped" if observed else "not shipped"
        else:
            found = [c for c in build if key in keys_of([c.get("purl") or ""])]
            markers = [development_marker(c) for c in found]
            state = "absent" if not found else "development" if all(markers) else "shipped"
            marker = markers[0] if found and all(markers) else None
        expected = (
            {"shipped"} if entry.get("phase") == "shipped" else {"not shipped", "development"}
        )
        phase = by_phase.setdefault(
            entry.get("phase") or "shipped", {"packages": 0, "matched": 0, "observed": []}
        )
        phase["packages"] += 1
        observation = {"purl": entry["purl"], "state": state}
        if marker:
            observation["marker"] = marker
        phase["observed"].append(observation)
        if state in expected:
            matched += 1
            phase["matched"] += 1
        else:
            missed.append({**entry, "observed": state})
    return {
        "outcome": "partial" if missed else "measured",
        "measuredFrom": "post-build" if shipped else "build-scope",
        "packages": len(entries),
        "matched": matched,
        "byPhase": {p: by_phase[p] for p in LIFECYCLE_PHASES if p in by_phase},
        "buildOnlyDistinct": False,
        "missed": missed,
    }


def score_join_component_layer(scan: ItemScan, labels: dict) -> dict:
    """The image layer each labelled component is attributed to.

    A component's layer is the value of one of ``LAYER_PROPERTIES``. The
    labels say whether a package belongs to the OS base or the application
    layers; an attribution holds when no component of the other kind shares
    the layer. No labelled component with a layer property means the join is
    a gap today, and the draft issue names the producer.
    """
    entries = ((labels.get("joins") or {}).get("component-layer") or {}).get("packages") or []
    components = scan.components()
    if not components:
        return {"outcome": "partial", "reason": "the scan directory holds no component BOM"}
    layers = {}
    seen = set()
    for entry in entries:
        key = label_key(entry["purl"])
        for component in components:
            if key in keys_of([component.get("purl") or ""]):
                seen.add(entry["purl"])
                for prop in component.get("properties") or []:
                    if isinstance(prop, dict) and prop.get("name") in LAYER_PROPERTIES:
                        layers[entry["purl"]] = str(prop.get("value") or "")
    if not layers:
        return {
            "outcome": "gap",
            "labelledSeen": len(seen),
            "withLayer": 0,
            "reason": (
                "no labelled component of the image BOM carries a layer property: "
                "the join cannot be made from what the BOM records today"
            ),
        }
    by_kind: dict = {}
    for entry in entries:
        if entry["purl"] in layers:
            by_kind.setdefault(entry.get("layer"), set()).add(layers[entry["purl"]])
    missed = []
    for entry in entries:
        others = set().union(*(v for k, v in by_kind.items() if k != entry.get("layer")))
        if entry["purl"] not in layers or layers[entry["purl"]] in others:
            missed.append({**entry, "observedLayer": layers.get(entry["purl"], "")})
    return {
        "outcome": "partial" if missed else "measured",
        "labelledSeen": len(seen),
        "withLayer": len(layers),
        "matched": len(entries) - len(missed),
        "missed": missed,
    }


def score_join_component_runtime(scan: ItemScan, labels: dict) -> dict:
    """Components observed at runtime against the trace's labels: the
    evidence records of the tracebom producer name the components the run
    observed."""
    entries = ((labels.get("joins") or {}).get("component-runtime") or {}).get("packages") or []
    if not entries:
        return {"outcome": "partial", "reason": "the item labels no runtime packages"}
    records = [r for r in scan.evidence if r.producer.name == "tracebom"]
    if not records:
        return {
            "outcome": "partial",
            "reason": (
                "no tracebom record reached the evidence store: the scan "
                "read no trace BOM whose components the tracebom adapter "
                "could attribute"
            ),
        }
    observed = keys_of(p for r in records for p in r.subject.purls)
    wanted = label_keys(e["purl"] for e in entries)
    return {
        "outcome": "measured" if wanted <= observed else "partial",
        "observed": len(observed),
        "matched": len(wanted & observed),
        "missed": sorted(wanted - observed),
    }


#: The BOM producers the two-producers join tells apart, by the tool name a
#: BOM's metadata records. A toolchain listed beside them (cdxgen records
#: the ``go`` it ran) is not a producer.
BOM_PRODUCERS = ("cdxgen", "blint", "trivy", "syft", "dosai")


def bom_producer(stem: str, bom: dict) -> str:
    """The producer of one BOM: the first known producer among the tools of
    its metadata, or the BOM's file-name stem when it records none."""
    tools = (bom.get("metadata") or {}).get("tools") or {}
    entries = tools.get("components") if isinstance(tools, dict) else tools
    names = [str(t.get("name") or "") for t in entries or [] if isinstance(t, dict)]
    return next((name for name in names if name in BOM_PRODUCERS), f"unknown ({stem})")


def score_join_two_producers(scan: ItemScan, labels: dict) -> dict:
    """One component identity for the same package seen by two producers.

    Each BOM is attributed to the producer its metadata names (cdxgen for a
    source scan, blint for a binary), so a source BOM and its build-phase
    copy are one producer, not two. The join holds when the labelled
    package appears under at least two producers with the same comparable
    purl. A scan in which fewer than two producers wrote a BOM cannot
    measure the join and reports it not assessed.
    """
    package = ((labels.get("joins") or {}).get("two-producers") or {}).get("package")
    if not package:
        return {"outcome": "partial", "reason": "the item names no package"}
    key = label_key(package)
    boms: dict = {}
    by_producer: dict = {}
    for stem, bom in scan.boms.items():
        producer = bom_producer(stem, bom)
        boms.setdefault(producer, []).append(stem)
        purls = {
            comparable_purl(c["purl"])
            for c in bom.get("components") or []
            if isinstance(c, dict) and c.get("purl") and key in keys_of([c["purl"]])
        }
        if purls:
            by_producer[producer] = sorted(set(by_producer.get(producer, [])) | purls)
    if len(boms) < 2:
        return {
            "outcome": "not-assessed",
            "reason": f"{len(boms)} BOM producer ran ({', '.join(sorted(boms)) or 'none'}); "
            "the join needs two",
            "boms": boms,
        }
    if len(by_producer) < 2:
        return {
            "outcome": "partial",
            "reason": f"the package was found by {len(by_producer)} of the {len(boms)} producers",
            "byProducer": by_producer,
            "boms": boms,
        }
    identical = len({p for purls in by_producer.values() for p in purls}) == 1
    return {
        "outcome": "measured" if identical else "partial",
        "byProducer": by_producer,
        "boms": boms,
        "identical": identical,
        "producers": sorted({r.producer.name for r in scan.evidence}),
    }


def score_join_two_manifests(scan: ItemScan, labels: dict) -> dict:
    """One dependency declared at two versions must stay two components.

    The score counts the distinct versions the scan holds for the labelled
    package and how many of the components record which manifest declared
    them.
    """
    section = (labels.get("joins") or {}).get("two-manifests") or {}
    if not section.get("package"):
        return {"outcome": "partial", "reason": "the item names no package"}
    key = label_key(section["package"])
    expected_versions = set(section.get("versions") or [])
    components = []
    for component in scan.components():
        purl = component.get("purl")
        if not isinstance(purl, str) or key not in keys_of([purl]):
            continue
        declaring = [
            str(p.get("value") or "")
            for p in component.get("properties") or []
            if isinstance(p, dict) and p.get("name") in DECLARING_PATH_PROPERTIES
        ]
        components.append(
            {
                "version": split_purl(purl)[1] or "",
                "declaringPath": declaring[-1] if declaring else "",
            }
        )
    if not components:
        return {
            "outcome": "partial",
            "reason": "the scan holds no component for the labelled package",
        }
    distinct = {c["version"] for c in components if c["version"]}
    two = len(distinct) >= 2 if expected_versions else len(components) >= 2
    scored = {
        "outcome": "measured" if (expected_versions <= distinct and two) else "partial",
        "components": components,
        "distinctVersions": sorted(distinct),
        "distinctVersionCount": len(distinct),
        "withDeclaringPath": sum(1 for c in components if c["declaringPath"]),
    }
    if not two:
        scored["reason"] = (
            f"the scan holds {len(distinct)} version(s), not the two the labels name"
        )
    return scored


#: The join evaluators, in the report order of the vision's table.
JOIN_EVALUATORS = {
    "advisory-usage-reach": score_join_advisory_usage_reach,
    "route-package": score_join_route_package,
    "lifecycle-phase": score_join_lifecycle_phase,
    "component-layer": score_join_component_layer,
    "component-runtime": score_join_component_runtime,
    "two-producers": score_join_two_producers,
    "two-manifests": score_join_two_manifests,
}


# ---------------------------------------------------------------------------
# items, floors and the score document


def inventory_failed(scan: ItemScan):
    """The reason no inventory completed, when every one failed. A scan
    whose BOM generation failed for every project type assessed nothing, so
    the item reads as not assessed rather than as one with no findings; one
    failed type beside a completed one leaves the item scored."""
    inventories = [stage for stage in scan.stages if stage.get("name") == "inventory"]
    failed = [stage for stage in inventories if stage.get("status") == "failed"]
    if failed and not any(stage.get("status") == "completed" for stage in inventories):
        return "; ".join(stage.get("reason") or "the inventory stage failed" for stage in failed)
    return None


def score_item(scan: ItemScan, labels: dict) -> dict:
    """One item's score entry from its scan; a section the labels do not
    carry is left out, never written as null."""
    entry = {
        "item": scan.item["name"],
        "kind": scan.item.get("kind"),
        "state": "scored",
        "components": sum(len(bom.get("components") or []) for bom in scan.boms.values()),
        "findings": len(scan.findings),
        "categories": score_categories(scan, labels),
        "reachabilityNotAssessed": analyzer_not_assessed(scan),
        "joins": {
            join: evaluate(scan, labels)
            for join, evaluate in JOIN_EVALUATORS.items()
            if join in (labels.get("joins") or {})
        },
    }
    if labels.get("reachability"):
        entry["reachability"] = score_reachability(scan, labels)
    return entry


def score_one(item: dict, labels, args) -> dict:
    """Run or read one item's scan and score it, or say why it was not
    assessed."""

    def not_assessed(reason):
        return {
            "item": item["name"],
            "kind": item.get("kind"),
            "state": "not-assessed",
            "reason": reason,
        }

    from depscan import api

    if labels is None:
        return not_assessed(f"no label file {item.get('labels')}")
    if item.get("notProduced"):
        # A join no producer can feed yet: the item states the gap and why,
        # and nothing is scanned.
        gap = item["notProduced"]
        entry = not_assessed(gap["reason"])
        entry["joins"] = {gap["join"]: {"outcome": "gap", "reason": gap["reason"]}}
        return entry
    if args.scan_dir:
        reports_dir = os.path.abspath(os.path.join(args.scan_dir, item["name"]))
        if not os.path.isdir(reports_dir):
            return not_assessed(f"no scan directory at {reports_dir}")
        try:
            result = api.load_scan(reports_dir)
        except api.ScanError as exc:
            return not_assessed(str(exc))
        # The analysers spell OpenAPI usage targets against the scanned
        # source, so a repository item reads its clone when one is present.
        payload = os.path.join(args.corpus_root, item["name"])
        if item.get("kind") != "repository" or not os.path.isdir(payload):
            payload = reports_dir
    else:
        payload, reason = resolve_payload(item, args)
        if payload is None:
            return not_assessed(reason)
        reports_dir = os.path.abspath(os.path.join(args.scans_root, item["name"]))
        result, reason = run_item_scan(item, payload, reports_dir)
        if result is None:
            return not_assessed(reason)
    scan = ItemScan(item, result, payload)
    reason = inventory_failed(scan)
    return not_assessed(reason) if reason else score_item(scan, labels)


def score_guarded(item: dict, manifest_dir: str, args) -> dict:
    """:func:`score_one`, with an unexpected exception (a broken label file,
    a tool the host lacks) recorded as the item's error instead of ending
    the run, so the other items are still scored and exit 1 keeps meaning a
    dropped floor or a fired control."""
    try:
        return score_one(item, load_labels(manifest_dir, item), args)
    except Exception as exc:  # noqa: BLE001 - one item's failure is its result
        return {
            "item": item["name"],
            "kind": item.get("kind"),
            "state": "error",
            "reason": f"{type(exc).__name__}: {exc}",
        }


def selected_floors(floors_doc: dict, score_doc: dict) -> list:
    """The floors of the items this run scored: a run over a few items
    (``--items``) checks their floors and skips the others'."""
    names = {entry["item"] for entry in score_doc.get("items", [])}
    return [floor for floor in floors_doc.get("floors") or [] if floor.get("item") in names]


def check_floors(floors_doc: dict, score_doc: dict) -> list:
    """The recorded floors of the run's items that dropped, each with its
    current value.

    A floor names an item and a dotted path into its score entry, such as
    ``reachability.SemanticReachability.reached.recall``. A missing value
    (an item not scored, a None rate) is a violation too. Floors of items
    the run did not select are not checked.
    """
    violations = []
    by_item = {entry["item"]: entry for entry in score_doc.get("items", [])}
    for floor in selected_floors(floors_doc, score_doc):
        node = by_item.get(floor["item"])
        if not node or node.get("state") != "scored":
            node = None
        for part in floor["path"].split("."):
            node = node.get(part) if isinstance(node, dict) else None
        value = node if isinstance(node, (int, float)) and not isinstance(node, bool) else None
        if value is None or value < floor["minimum"]:
            violations.append(
                {**{k: floor[k] for k in ("item", "path", "minimum")}, "value": value}
            )
    return violations


def rates(score: dict) -> str:
    """A score's recall and precision as ``recall/precision``, with ``-``
    for a rate nothing was labelled for."""
    return "/".join(
        "-" if score.get(k) is None else str(score[k]) for k in ("recall", "precision")
    )


def render_markdown(score_doc: dict) -> str:
    """The Markdown table of one run."""
    lines = [
        "# Corpus score",
        "",
        f"Generated {score_doc.get('generatedAt') or 'at an unknown time'} at commit "
        f"{score_doc.get('commit') or 'unknown'} with dep-scan "
        f"{score_doc.get('depscanVersion') or 'of an unknown version'}.",
        "",
        "| Item | State | Reachability recall/precision | Categories | Joins |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in score_doc["items"]:
        if entry["state"] != "scored":
            reason = (entry.get("reason") or "").replace("|", "/")
            state = "error" if entry["state"] == "error" else "not assessed"
            lines.append(f"| {entry['item']} | {state} | | | {reason[:120]} |")
            continue
        assessed = {
            analyzer: scores
            for analyzer, scores in (entry.get("reachability") or {}).items()
            if scores.get("status") == "assessed"
        }
        reach_cells = [
            f"{analyzer.replace('Reachability', '')} {bucket} {rates(scores[bucket])}"
            for analyzer, scores in assessed.items()
            for bucket in ("direct", "reached")
        ]
        unmapped = max((s["reached"].get("unmappedUsed", 0) for s in assessed.values()), default=0)
        if unmapped:
            reach_cells.append(f"{unmapped} unmapped used names counted as misses")
        category_cells = [
            f"{category}: not assessed"
            if score.get("status") == "not-assessed"
            else f"{category}: {rates(score)}"
            for category, score in sorted((entry.get("categories") or {}).items())
            if score.get("status") != "unlabelled"
        ]
        join_cells = [
            f"{join}: {score['outcome']}" for join, score in (entry.get("joins") or {}).items()
        ]
        lines.append(
            f"| {entry['item']} | scored | {'; '.join(reach_cells)} | "
            f"{'; '.join(category_cells)} | {'; '.join(join_cells)} |"
        )
    lines += ["", "## Joins", "", "| Join | Outcome |", "| --- | --- |"]
    for join in JOIN_EVALUATORS:
        outcomes = sorted(
            {
                entry["joins"][join]["outcome"]
                for entry in score_doc["items"]
                if join in (entry.get("joins") or {})
            }
        )
        lines.append(f"| {join} | {', '.join(outcomes) or 'not labelled'} |")
    lines += ["", "## Categories dep-scan does not produce yet", ""]
    lines += [
        f"- {e['category']}: tracked by {e['issue']}" for e in score_doc.get("notProduced") or []
    ]
    return "\n".join(lines + [""])


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    add = parser.add_argument
    add("--manifest", default=os.path.join(_HERE, "depscan.corpus.json"), help="The manifest.")
    add("--items", help="Comma-separated item names.")
    add("--subset", choices=("ci",), help="Score only the items a pull-request job can run.")
    add("--scan-dir", help="Score the scan directories under this root instead of scanning.")
    add(
        "--scans-root",
        default=cache_dir("scans"),
        help="Where run mode writes the scans and fixture copies, outside the dep-scan "
        "checkout (default: %(default)s).",
    )
    add("--corpus-root", default=cache_dir("clones"), help="Clones (default: %(default)s).")
    add(
        "--testdata-root",
        default=cache_dir("repotests-data"),
        help="Pulled repo-test data (default: %(default)s).",
    )
    add("--floors", help="Floors file; exit 1 when a floor drops or a negative control fires.")
    add("--output", default=".", help="Directory for score.json and score.md.")
    add("--fetch", action="store_true", help="Clone missing repository items first.")
    add("--digest-fixture", help="Print the digest of one fixture directory and exit.")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    """Score the selected items. Exit 0 when the run held, 1 when a floor
    dropped or a negative control fired, and 2 on a usage error (an unknown
    item, an unreadable manifest, labels or floors file)."""
    args = parse_args(argv)
    if args.digest_fixture:
        print(fixture_digest(args.digest_fixture))
        return 0
    try:
        return run(args)
    except ScoreError as exc:
        print(str(exc), file=sys.stderr)
        return 2


def run(args) -> int:
    manifest_path = os.path.abspath(args.manifest)
    manifest = load_manifest(manifest_path)
    items = select_items(manifest, args)
    floors_doc = load_json(args.floors) if args.floors else None
    if args.floors and not isinstance(floors_doc, dict):
        raise ScoreError(f"Cannot read the floors file '{args.floors}'.")

    from depscan import get_version

    entries = [score_guarded(item, os.path.dirname(manifest_path), args) for item in items]
    commit = git(_REPO_ROOT, "rev-parse", "HEAD").stdout.strip() or "unknown"
    scored = [entry for entry in entries if entry["state"] == "scored"]
    errors = [entry for entry in entries if entry["state"] == "error"]
    fired = [
        {"item": entry["item"], **control}
        for entry in scored
        for category in entry["categories"].values()
        for control in category.get("forbiddenFired") or []
    ]
    summary: dict = {
        "items": len(entries),
        "scored": len(scored),
        "notAssessed": len(entries) - len(scored) - len(errors),
        "errors": len(errors),
        "forbiddenFired": fired,
    }
    score_doc = {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "commit": commit,
        "depscanVersion": get_version(),
        "subset": args.subset,
        "items": entries,
        "notProduced": manifest.get("notProduced") or [],
        "summary": summary,
    }
    if floors_doc is not None:
        checked = len(selected_floors(floors_doc, score_doc))
        summary["floors"] = {
            "commit": floors_doc.get("commit"),
            "checked": checked,
            "skipped": len(floors_doc.get("floors") or []) - checked,
            "violations": check_floors(floors_doc, score_doc),
        }
    os.makedirs(args.output, exist_ok=True)
    score_path = os.path.join(args.output, "score.json")
    table_path = os.path.join(args.output, "score.md")
    for path, text in (
        (score_path, json.dumps(score_doc, indent=2, ensure_ascii=False) + "\n"),
        (table_path, render_markdown(score_doc)),
    ):
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(text)
    print(f"Wrote {score_path} and {table_path}")
    print(
        f"{len(scored)} of {len(entries)} items scored"
        + (f", {len(errors)} items errored" if errors else "")
        + (f", {len(fired)} negative controls fired" if fired else "")
    )
    for entry in errors:
        print(f"  {entry['item']}: {entry['reason']}", file=sys.stderr)
    if floors_doc is None:
        return 0
    floors = summary["floors"]
    print(
        f"Floors: {floors['checked']} checked at commit {floors['commit']}, "
        f"{floors['skipped']} of unselected items skipped, "
        f"{len(floors['violations'])} violations"
    )
    for violation in floors["violations"]:
        print(
            f"  {violation['item']} {violation['path']}: {violation['value']} < {violation['minimum']}"
        )
    return 1 if (fired or floors["violations"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
