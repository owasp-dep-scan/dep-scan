#!/usr/bin/env python3
"""The corpus scorer: run dep-scan on the corpus, score it against the labels.

Every corpus item states what dep-scan must find and what it must not. This
script runs the item's scan (or reads a scan directory made earlier), scores
per item, per finding category and per join, and writes ``score.json`` with a
Markdown table beside it. A result dep-scan did not assess is its own column
with its reason; it is never a miss and never a clean pass.

Usage:
    # Run every item whose inputs are present under the corpus root
    python contrib/corpus/score.py --scans-root ~/sandbox/p23-corpus/scans

    # Score a few items, from scans made earlier
    python contrib/corpus/score.py --scan-dir ~/sandbox/p23-corpus/scans \
        --items js-express-realworld,py-vulpy

    # The CI subset, failing on a dropped floor or a fired negative control
    python contrib/corpus/score.py --subset ci \
        --floors contrib/corpus/floors.json --output score/

Inputs are resolved without the network unless a repository clone is missing:
repository items are cloned at the pinned commit of the corpus root and
checked by the digest of ``git archive``; BOM items read the repo-test data
pulled by digest under ``--testdata-root``; fixture items are the committed
directories beside this manifest, checked by a digest over their contents.
The scorer never runs a scanned project's build tooling, never parses console
output (it reads the scan directory through :func:`depscan.api.load_scan`),
and compares every purl through ``comparable_purl``.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import subprocess
import sys
import time
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

#: The analysers the reachability scores are reported for, in report order.
ANALYZERS = ("FrameworkReachability", "SemanticReachability")

#: The join keys of the vision's table, in report order. An item's labels may
#: carry any of them; the score table shows every join with at least one
#: labelled item.
JOINS = (
    "advisory-usage-reach",
    "route-package",
    "lifecycle-phase",
    "component-layer",
    "component-runtime",
    "two-producers",
    "two-manifests",
)

#: Manifest stage name to the finding categories whose assessment depends on
#: it. A stage that did not complete turns the category's score into a
#: not-assessed entry with the stage's reason, never into a zero.
STAGE_CATEGORIES = {
    "risk": ("supply-chain",),
    "licenses": ("license",),
    "matching": ("vulnerability",),
}


class ScoreError(RuntimeError):
    """The scorer could not produce a score; the message says why."""


def load_json(path: str):
    """Read one JSON document, or None when it cannot be read."""
    try:
        with open(path, encoding="utf-8") as fp:
            return json.load(fp)
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# purl helpers


def purl_key(purl: str) -> str:
    """The comparable key of a purl: comparable_purl without the version, so
    a label without a version and a finding that names one compare equal."""
    comparable = comparable_purl(str(purl))
    return comparable.rsplit("@", 1)[0] if "@" in comparable else comparable


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
    labels_path = os.path.join(manifest_dir, item.get("labels", ""))
    document = load_json(labels_path)
    if document is None:
        return None
    if document.get("item") != item["name"]:
        raise ScoreError(
            f"The label file '{item.get('labels')}' names item "
            f"'{document.get('item')}', but the manifest item is "
            f"'{item['name']}'."
        )
    return document


def select_items(manifest: dict, args) -> list:
    """The items this run scores, in manifest order."""
    items = manifest["items"]
    if args.items:
        wanted = [name.strip() for name in args.items.split(",") if name.strip()]
        known = {item["name"] for item in items}
        unknown = [name for name in wanted if name not in known]
        if unknown:
            raise ScoreError(
                "The manifest holds no item named: " + ", ".join(unknown)
            )
        items = [item for item in items if item["name"] in set(wanted)]
    if args.subset:
        items = [item for item in items if item.get("subset") == args.subset]
        if not items:
            raise ScoreError(f"The subset '{args.subset}' holds no items.")
    return items


# ---------------------------------------------------------------------------
# inputs


def fixture_digest(directory: str) -> str:
    """The digest of a fixture directory: SHA-256 over every file's relative
    path with forward slashes and its bytes, in sorted path order."""
    digest = hashlib.sha256()
    entries = []
    for base, _dirs, files in os.walk(directory):
        for name in files:
            path = os.path.join(base, name)
            rel = os.path.relpath(path, directory).replace(os.sep, "/")
            entries.append((rel, path))
    for rel, path in sorted(entries):
        digest.update(rel.encode("utf-8"))
        digest.update(b"\x00")
        with open(path, "rb") as fp:
            digest.update(fp.read())
    return digest.hexdigest()


def git_archive_digest(clone: str, commit: str) -> str:
    """The SHA-256 of the commit's ``git archive`` tar, the digest a
    repository item pins."""
    tar = subprocess.run(
        ["git", "-C", clone, "archive", "--format=tar", commit],
        capture_output=True,
        check=True,
    ).stdout
    return hashlib.sha256(tar).hexdigest()


def resolve_repository(item: dict, corpus_root: str, timeout: float, fetch: bool = False):
    """The clone of a repository item at its pinned commit, digest-checked.

    With ``fetch`` a missing clone is fetched first: a blob-less clone of the
    pinned commit, then a checkout, then the digest check. Returns the clone
    directory, or a not-assessed reason entry (a (None, reason) pair) when
    the clone is missing and fetching is off, or when the digest fails,
    which is never scored.
    """
    clone = os.path.join(corpus_root, item["name"])
    source, commit = item["source"].rsplit("@", 1)
    if not os.path.isdir(os.path.join(clone, ".git")):
        if not fetch:
            return None, (
                f"no clone at {clone}; clone {item['source']} there first, or "
                "run the scorer with --fetch"
            )
        parent = os.path.dirname(clone)
        os.makedirs(parent, exist_ok=True)
        try:
            subprocess.run(
                ["git", "clone", "-q", "--filter=blob:none", source, clone],
                check=True,
                timeout=timeout,
                capture_output=True,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            return None, f"cloning {source} failed: {exc}"
    head = subprocess.run(
        ["git", "-C", clone, "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if head.returncode != 0 or head.stdout.strip() != commit:
        if fetch:
            subprocess.run(
                ["git", "-C", clone, "fetch", "-q", "--filter=blob:none", "origin", commit],
                capture_output=True,
                timeout=timeout,
            )
            subprocess.run(
                ["git", "-C", clone, "checkout", "-q", "--detach", commit],
                capture_output=True,
                timeout=timeout,
            )
            head = subprocess.run(
                ["git", "-C", clone, "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
    if head.returncode != 0 or head.stdout.strip() != commit:
        return None, (
            f"the clone at {clone} is at {head.stdout.strip()[:12] or 'an unknown commit'}, "
            f"not the pinned {commit[:12]}"
        )
    try:
        digest = git_archive_digest(clone, commit)
    except (subprocess.SubprocessError, OSError) as exc:
        return None, f"git archive failed for {item['name']}: {exc}"
    if digest != item["sha256"]:
        note = item.get("digestNote", "")
        return None, (
            f"digest mismatch for {item['name']}: computed {digest}, "
            f"the manifest pins {item['sha256']}"
            + (f" ({note})" if note else "")
        )
    return clone, None


def resolve_testdata(item: dict, testdata_root: str):
    """The pulled repo-test data of a BOM item, verified against its digest.

    The data root holds one directory per artifact plus the OCI manifest copy
    the pull keeps under ``.manifests``, the layout the repotests action
    pulls into. Returns (data_dir, reason); data_dir is None when the item
    cannot run.
    """
    testdata = item.get("testdata") or {}
    artifact = testdata.get("artifact")
    data_dir = os.path.join(testdata_root, artifact or "")
    if not artifact or not os.path.isdir(data_dir):
        return None, (
            f"the repo-test data for '{artifact or item['name']}' is not pulled "
            f"under {testdata_root}; pull it by digest with oras first"
        )
    manifest_copy = os.path.join(testdata_root, ".manifests", f"{artifact}.json")
    if not os.path.isfile(manifest_copy):
        return None, (
            f"the manifest copy of '{artifact}' is missing under {testdata_root}; "
            "pull the artifact the way .github/actions/repotests-data does"
        )
    sys.path.insert(0, os.path.join(_REPO_ROOT, "contrib"))
    from repotests import validate as repotests_validate

    try:
        repotests_validate.check_digests(
            data_dir, manifest_copy, manifest_digest=testdata["digest"]
        )
    except repotests_validate.ValidationFailure as exc:
        return None, f"the pulled data for '{artifact}' failed its digest check: {exc}"
    return data_dir, None


def resolve_fixture(item: dict, scans_root: str, timeout: float):
    """The committed fixture of a fixture or binary item, digest-checked.

    The fixture is scanned from a copy under ``scans_root``, never from the
    repository tree: the corpus sits inside dep-scan's own uv workspace, and
    a scan of the committed directory would pick the workspace's environment
    up. The digest check runs over the committed original.
    """
    name = item["source"].split(":", 1)[1] if ":" in item["source"] else item["name"]
    directory = os.path.join(_HERE, "fixtures", name)
    if not os.path.isdir(directory):
        return None, f"the fixture '{name}' is not committed under contrib/corpus/fixtures."
    digest = fixture_digest(directory)
    if digest != item["sha256"]:
        note = item.get("digestNote", "")
        return None, (
            f"digest mismatch for fixture '{name}': computed {digest}, "
            f"the manifest pins {item['sha256']}"
            + (f" ({note})" if note else "")
        )
    if not scans_root:
        return None, "run mode needs --scans-root to copy the fixture into"
    import shutil

    copy_dir = os.path.abspath(os.path.join(scans_root, item["name"], "payload"))
    if os.path.isdir(copy_dir):
        shutil.rmtree(copy_dir)
    os.makedirs(os.path.dirname(copy_dir), exist_ok=True)
    shutil.copytree(
        directory,
        copy_dir,
        ignore=shutil.ignore_patterns(".venv-trace", "node_modules"),
    )
    return copy_dir, None


def resolve_payload(item: dict, args, timeout: float):
    """The input an item's scan reads, digest-checked where possible.

    Returns (payload, reason). A reason with a None payload turns the item
    into a not-assessed entry.
    """
    kind = item.get("kind")
    if kind == "repository":
        return resolve_repository(item, args.corpus_root, timeout, args.fetch)
    if kind == "bom":
        return resolve_testdata(item, args.testdata_root)
    if kind in ("fixture", "binary"):
        return resolve_fixture(item, args.scans_root, timeout)
    if kind == "image":
        reference = item["source"]
        digest = item["sha256"]
        if f"sha256:{digest}" not in reference:
            return None, (
                f"the image reference '{reference}' does not carry the digest "
                f"the item pins (sha256:{digest})"
            )
        return reference, None
    return None, f"unknown item kind '{kind}'"


# ---------------------------------------------------------------------------
# scanning


def build_scan_options(item: dict, payload, reports_dir: str):
    """The internal options of the item's scan command line.

    The manifest's ``scan`` object is the command line: the payload as the
    target, one ``-t`` flag with every type, then the item's own arguments.
    The parsed command line goes through the same conversion the scan verb
    runs (checks and profile resolution onto the internal namespace, the
    target onto the inventory paths), so the manifest and the run stay in
    step with what the CLI itself would do.
    """
    import argparse

    from depscan.commands import checks as checks_table
    from depscan.commands import build_parser
    from depscan.commands.scan import _apply_target_options, detect_kind, scan_namespace

    tokens = ["scan", str(payload)]
    # One -t flag with every type: -t repeats replace, not extend. A BOM
    # directory scan names no type; the BOMs carry their own.
    if item["scan"].get("types"):
        tokens += ["-t", *item["scan"]["types"]]
    tokens += ["--reports-dir", reports_dir]
    tokens += list(item["scan"].get("args") or [])
    lifecycles = item["scan"].get("lifecycles")
    if lifecycles:
        tokens += ["--lifecycle", *lifecycles]
    args = build_parser().parse_args(tokens)
    resolution = checks_table.resolve(args)
    options = argparse.Namespace(**vars(scan_namespace(args, resolution=resolution)))
    kind, _ = detect_kind(str(payload))
    _apply_target_options(options, str(payload), kind, args, resolution)
    options.reports_dir = reports_dir
    options.no_banner = True
    return options, resolution


def run_item_scan(item: dict, payload, reports_dir: str, timeout: float):
    """Run the item's scan and return (result, error-message).

    The scan goes through :func:`depscan.api.scan` with rendering off; a
    stopped stage or a timeout becomes the error message, never a result.
    """
    from depscan import api

    options, resolution = build_scan_options(item, payload, reports_dir)
    started = time.time()
    try:
        result = api.scan(
            options,
            render=False,
            checks_not_assessed=resolution.not_assessed or None,
        )
    except api.ScanError as exc:
        return None, f"the scan stopped early: {exc}"
    except Exception as exc:  # noqa: BLE001 - a failed scan is the item's result
        return None, f"{type(exc).__name__}: {exc}"
    elapsed = time.time() - started
    if timeout and elapsed > timeout:
        return None, f"the scan took {elapsed:.0f}s, over the {timeout:.0f}s budget"
    return result, None


# ---------------------------------------------------------------------------
# scoring


def rate(hit_count: int, total: int):
    """A recall or precision rate, or None when nothing is labelled."""
    return round(hit_count / total, 4) if total else None


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
    hits = 0
    matched_findings = set()
    missed = []
    for entry in expected:
        rules = {str(rule).lower() for rule in entry.get("rules") or []}
        key = purl_key(entry["purl"])
        matched = False
        for index, finding in enumerate(findings):
            if finding.get("category") != entry["category"]:
                continue
            if str(finding.get("rule") or "").lower() not in rules:
                continue
            if any(purl_key(p) == key for p in finding.get("components") or []):
                matched = True
                matched_findings.add(index)
                break
        if matched:
            hits += 1
        else:
            missed.append(entry)
    fired = []
    for control in forbidden:
        rules = {str(rule).lower() for rule in control.get("rules") or []}
        control_key = purl_key(control["purl"]) if control.get("purl") else None
        for finding in findings:
            if finding.get("category") != control["category"]:
                continue
            if rules and str(finding.get("rule") or "").lower() not in rules:
                continue
            components = [purl_key(p) for p in finding.get("components") or []]
            if control_key is not None and control_key not in components:
                continue
            fired.append(
                {
                    "rule": finding.get("rule"),
                    "purls": finding.get("components") or [],
                    "id": finding.get("id"),
                    "reason": control.get("reason"),
                }
            )
    unexpected = []
    expected_purls = {purl_key(e["purl"]) for e in expected if e.get("purl")}
    # Labels pass judgement per category: a forbidden purl is controlled for
    # its own category only, so an advisory of another category on it is a
    # true finding, not noise.
    forbidden_purls = {
        control["category"]: {
            purl_key(c["purl"])
            for c in forbidden
            if c.get("purl") and c.get("category") == control["category"]
        }
        for control in forbidden
        if control.get("purl")
    }
    for index, finding in enumerate(findings):
        if index in matched_findings:
            continue
        keys = {purl_key(p) for p in finding.get("components") or []}
        # A finding on a purl an expected entry names is a true positive of
        # the label even when its rule id differs: the rules list proves the
        # advisory, it does not bound it. Any other finding on a purl the
        # same category's labels control is unexpected.
        if keys & expected_purls:
            continue
        if keys & forbidden_purls.get(finding.get("category"), set()):
            unexpected.append(
                {"rule": finding.get("rule"), "purls": finding.get("components") or []}
            )
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


def score_category(findings: list, findings_labels: dict, category: str) -> dict:
    """One category's score, from the label entries of that category."""
    expected = [
        e for e in findings_labels.get("expected") or [] if e["category"] == category
    ]
    forbidden = [
        e for e in findings_labels.get("forbidden") or [] if e["category"] == category
    ]
    scored = score_findings(findings, expected, forbidden)
    if not expected and not forbidden:
        scored["status"] = "unlabelled"
        scored["reason"] = "the item labels no expected or forbidden findings of this category"
    else:
        scored["status"] = "assessed"
    return scored


def analyzer_reach(reports_dir: str, src_dir, project_types: list, analyzer: str):
    """One analyser's direct and reached purl maps over a scan directory.

    Returns (result, reason); the reason says why the analyser produced
    nothing, which is a not-assessed entry, never a zero.
    """
    evidence_file = os.path.join(reports_dir, "evidence.jsonl")
    options = ReachabilityAnalysisKV(
        project_types=project_types,
        src_dir=src_dir if isinstance(src_dir, str) else reports_dir,
        bom_dir=reports_dir,
        evidence_file=evidence_file if os.path.isfile(evidence_file) else None,
    )
    res = get_reachability_impl(analyzer, options).process()
    if not res.success and not (res.direct_purls or res.reached_purls):
        return None, "the analyzer produced no result over this scan directory"
    return res, None


def score_purl_set(keys: set, used: set, unused: set) -> dict:
    """Recall and precision of one purl set against used and unused labels.

    Recall is the share of used packages the set holds. Precision is the
    share of used packages among everything the set holds that a label
    covers; a purl no label names counts nowhere, because the labels do not
    pass judgement on it.
    """
    labelled = keys & (used | unused)
    true_positive = keys & used
    return {
        "recall": rate(len(true_positive), len(used)),
        "precision": rate(len(true_positive), len(labelled)),
        "missed": sorted(used - keys),
        "wrong": sorted(keys & unused),
        "labelledSeen": len(labelled),
        "seen": len(keys),
    }


def score_reachability(item: dict, result, labels: dict, payload) -> dict:
    """Both analysers scored against the reachability labels, per project."""
    reach_labels = labels.get("reachability") or {}
    used = {purl_key(entry["purl"]) for entry in reach_labels.get("used") or []}
    unused = {purl_key(entry["purl"]) for entry in reach_labels.get("unused") or []}
    project_types = item["scan"].get("types") or _types_from_boms(result.reports_dir)
    scores = {}
    for analyzer in ANALYZERS:
        res, reason = analyzer_reach(result.reports_dir, payload, project_types, analyzer)
        if res is None:
            scores[analyzer] = {"status": "not-assessed", "reason": reason}
            continue
        scores[analyzer] = {
            "status": "assessed",
            "direct": score_purl_set(
                {purl_key(p) for p in (res.direct_purls or {})}, used, unused
            ),
            "reached": score_purl_set(
                {purl_key(p) for p in (res.reached_purls or {})}, used, unused
            ),
        }
    return scores


def _types_from_boms(reports_dir: str) -> list:
    """The project types a scan directory's BOM names carry, for items whose
    manifest names none (a BOM directory scan)."""
    types = []
    for bom_file in sorted(glob.glob(os.path.join(reports_dir, "sbom-*.cdx.json"))):
        stem = os.path.basename(bom_file)[len("sbom-") : -len(".cdx.json")]
        if stem.startswith("build-") or stem.startswith("prebuild-"):
            stem = stem.split("-", 1)[1]
        if stem and stem not in types:
            types.append(stem)
    return types


def item_scan_types(item: dict, result) -> list:
    """The project types of an item's scan, falling back to the types its
    BOM names carry."""
    return item["scan"].get("types") or _types_from_boms(result.reports_dir)


def stage_not_assessed(result, category: str):
    """The reason a category was not assessed, from the manifest's stages."""
    stage_names = [
        name for name, categories in STAGE_CATEGORIES.items() if category in categories
    ]
    for stage in (result.manifest or {}).get("stages") or []:
        if stage.get("name") not in stage_names:
            continue
        status = stage.get("status")
        if status in ("not-assessed", "failed", "skipped"):
            reason = stage.get("reason")
            return {
                "status": status,
                "reason": reason or f"the {stage.get('name')} stage {status}",
            }
    return None


def analyzer_not_assessed(result):
    """The reachability not-assessed reasons the manifest records."""
    for stage in (result.manifest or {}).get("stages") or []:
        if stage.get("name") != "enrichment":
            continue
        return [
            {"analyzer": entry.get("name"), "reason": entry.get("reason")}
            for entry in stage.get("analyzers") or []
            if entry.get("status") in ("not-assessed", "failed")
        ]
    return []


# ---------------------------------------------------------------------------
# joins


def read_evidence(reports_dir: str) -> list:
    """The scan directory's evidence records, or an empty list."""
    path = os.path.join(reports_dir, "evidence.jsonl")
    if not os.path.isfile(path):
        return []
    records = []
    try:
        for record in stream_evidence(path):
            records.append(record)
    except (OSError, ValueError):
        return []
    return records


def score_join_advisory_usage_reach(item: dict, result, labels: dict, payload) -> dict:
    """Reached and not-reached vulnerability findings against used and
    unused labels."""
    reach_labels = labels.get("reachability") or {}
    used = {purl_key(e["purl"]) for e in reach_labels.get("used") or []}
    unused = {purl_key(e["purl"]) for e in reach_labels.get("unused") or []}
    if not used and not unused:
        return {"outcome": "partial", "reason": "the item carries no usage labels"}
    res, reason = analyzer_reach(
        result.reports_dir, payload, item_scan_types(item, result), "SemanticReachability"
    )
    if res is None:
        return {"outcome": "partial", "reason": reason}
    reached = {purl_key(p) for p in (res.reached_purls or {})}
    vulns = [f for f in result.findings if f.get("category") == "vulnerability"]
    reached_on_used = 0
    not_reached_on_used = []
    reached_on_unused = []
    for finding in vulns:
        keys = {purl_key(p) for p in finding.get("components") or []}
        if keys & reached:
            if keys & unused:
                reached_on_unused.append({"id": finding.get("id"), "rule": finding.get("rule")})
            reached_on_used += 1
        elif keys & used:
            not_reached_on_used.append({"id": finding.get("id"), "rule": finding.get("rule")})
    return {
        "outcome": "measured",
        "findings": len(vulns),
        "reachedFindings": reached_on_used,
        "notReachedOnUsed": not_reached_on_used,
        "reachedOnUnused": reached_on_unused,
        "reachedPurls": len(reached),
    }


def score_join_route_package(item: dict, result, labels: dict, payload) -> dict:
    """Each labelled route must name the packages its handlers use.

    Two producers carry route evidence, and the evaluator reads both. An
    OpenAPI specification maps every route to the files and lines its
    handlers occupy (``x-atom-usages``), and the evidence store says which
    packages those places use. dosai writes the .NET routes as entry-point
    records whose id names the method and path, and its flow records name
    the packages with the handler locations they run through; the handler's
    span ends at the next entry-point record of the same file. A route whose
    handler usage the labels name but neither producer puts a package on is
    a miss.
    """
    section = (labels.get("joins") or {}).get("route-package") or {}
    routes = section.get("routes") or []
    if not routes:
        return {"outcome": "partial", "reason": "the item labels no routes"}
    by_location = _usage_locations_by_path(result.reports_dir)
    handler_records = _dosai_entry_points(result.reports_dir)
    measured = 0
    missed_routes = []
    for route in routes:
        wanted = {purl_key(p) for p in route.get("packages") or []}
        forbidden = {purl_key(p) for p in route.get("controls") or []}
        found = set()
        mechanism = None
        if route["path"] in by_location:
            mechanism = "openapi"
            found = _packages_at(result.reports_dir, by_location[route["path"]])
        else:
            span = _handler_span(handler_records, route["path"], route.get("method", "GET"))
            if span is not None:
                mechanism = "dosai"
                found = _packages_in_span(result.reports_dir, span)
        if mechanism is None:
            missed_routes.append(
                {"path": route["path"], "reason": "no route evidence from either producer"}
            )
            continue
        missing = wanted - found
        wrong = forbidden & found
        if missing or wrong:
            missed_routes.append(
                {
                    "path": route["path"],
                    "via": mechanism,
                    "missing": sorted(missing),
                    "wrong": sorted(wrong),
                }
            )
        else:
            measured += 1
    outcome = "measured" if not missed_routes else "partial"
    return {
        "outcome": outcome,
        "routes": len(routes),
        "routesMatched": measured,
        "missed": missed_routes,
    }


def _usage_locations_by_path(reports_dir: str) -> dict:
    """Route path to the (file, line) set its OpenAPI operations occupy."""
    usage_by_path = {}
    for spec_file in sorted(glob.glob(os.path.join(reports_dir, "*openapi*.json"))):
        spec = load_json(spec_file) or {}
        for path, operations in (spec.get("paths") or {}).items():
            if not isinstance(operations, dict):
                continue
            for operation in operations.values():
                if not isinstance(operation, dict):
                    continue
                usages = operation.get("x-atom-usages") or {}
                if not isinstance(usages, dict):
                    continue
                for kind in ("call", "target"):
                    by_file = usages.get(kind)
                    if not isinstance(by_file, dict):
                        continue
                    for file_name, lines in by_file.items():
                        if not isinstance(lines, list):
                            continue
                        for line in lines:
                            if isinstance(line, int):
                                usage_by_path.setdefault(path, set()).add((file_name, line))
    return usage_by_path


def _dosai_entry_points(reports_dir: str) -> list:
    """dosai's HTTP entry-point records as (file, line, method, path)."""
    entries = []
    for record in read_evidence(reports_dir):
        if record.producer.name != "dosai" or record.kind != "entry-point":
            continue
        entry_id = str((record.attributes or {}).get("entryPointId") or "")
        marker = entry_id.split("#")[-1] if "#" in entry_id else ""
        if not marker or ":" not in marker:
            continue
        method, _, path = marker.partition(":")
        if not record.locations:
            continue
        location = record.locations[0]
        entries.append(
            (
                os.path.normpath(str(getattr(location, "file", ""))),
                getattr(location, "line", None),
                method,
                path,
            )
        )
    return entries


def _handler_span(handler_records: list, path: str, method: str):
    """The (file, first line, next entry's line) span of one route's handler,
    or None when no dosai record names the route."""
    matches = sorted(
        (r for r in handler_records if r[3] == path and r[2] == method),
        key=lambda r: (r[0], r[1] or 0),
    )
    if not matches:
        return None
    file_name, line = matches[0][0], matches[0][1] or 0
    same_file = sorted(r[1] or 0 for r in handler_records if r[0] == file_name)
    following = [entry_line for entry_line in same_file if entry_line > line]
    end = following[0] if following else 10**9
    return (file_name, line, end)


def _packages_at(reports_dir: str, locations: set) -> set:
    """The purls the evidence puts on any of the (file, line) locations."""
    found = set()
    for record in read_evidence(reports_dir):
        purls = {purl_key(p) for p in record.subject.purls}
        if not purls:
            continue
        for location in record.locations or []:
            key = (os.path.normpath(str(getattr(location, "file", ""))), getattr(location, "line", None))
            if key in locations:
                found |= purls
                break
    return found


def _packages_in_span(reports_dir: str, span: tuple) -> set:
    """The purls the evidence puts inside a handler's (file, start, end) span."""
    file_name, start, end = span
    found = set()
    for record in read_evidence(reports_dir):
        purls = {purl_key(p) for p in record.subject.purls}
        if not purls:
            continue
        for location in record.locations or []:
            if os.path.normpath(str(getattr(location, "file", ""))) != file_name:
                continue
            line = getattr(location, "line", None)
            if isinstance(line, int) and start <= line < end:
                found |= purls
                break
    return found


def _phase_bom_components(reports_dir: str) -> dict:
    """The components of each lifecycle BOM in the scan directory, as
    comparable keys keyed by phase name."""
    phases = {}
    patterns = {
        "pre-build": "sbom-prebuild-*.cdx.json",
        "build": "sbom-build-*.cdx.json",
        "post-build": "sbom-postbuild-*.cdx.json",
    }
    for phase, pattern in patterns.items():
        components = set()
        for bom_file in sorted(glob.glob(os.path.join(reports_dir, pattern))):
            bom = load_json(bom_file) or {}
            for component in bom.get("components") or []:
                purl = component.get("purl")
                if isinstance(purl, str):
                    components.add(purl_key(purl))
        phases[phase] = components
    return phases


def score_join_lifecycle_phase(item: dict, result, labels: dict, payload) -> dict:
    """Packages labelled per lifecycle phase against the phase BOMs.

    A shipped package must be in the post-build BOM; a build-only or
    dev-only package must not ship, so it must stay out of the post-build
    BOM. When the post-build BOM holds no components (a source scan with no
    built environment), the shipped state was not observed: those labels are
    not-assessed with that reason, never passes and never misses.
    """
    section = (labels.get("joins") or {}).get("lifecycle-phase") or {}
    entries = section.get("packages") or []
    if not entries:
        return {"outcome": "partial", "reason": "the item labels no lifecycle packages"}
    phases = _phase_bom_components(result.reports_dir)
    if not any(phases.values()):
        return {
            "outcome": "partial",
            "reason": "the scan directory holds no lifecycle BOMs",
        }
    shipped_components = phases.get("post-build") or set()
    postbuild_empty = not shipped_components
    matched = 0
    missed = []
    not_assessed = []
    for entry in entries:
        key = purl_key(entry["purl"])
        phase = entry.get("phase")
        present = {name for name, components in phases.items() if key in components}
        if phase == "shipped":
            if postbuild_empty:
                not_assessed.append({**entry, "reason": "the post-build BOM holds no components"})
                continue
            if "post-build" in present:
                matched += 1
            else:
                missed.append({**entry, "observed": sorted(present)})
        else:
            if postbuild_empty:
                not_assessed.append({**entry, "reason": "the post-build BOM holds no components"})
            elif key in shipped_components:
                missed.append({**entry, "observed": sorted(present)})
            else:
                matched += 1
    outcome = "measured" if (not missed and not not_assessed) else "partial"
    return {
        "outcome": outcome,
        "packages": len(entries),
        "matched": matched,
        "missed": missed,
        "notAssessed": not_assessed,
    }


def _bom_components_with_properties(reports_dir: str) -> list:
    """Every component of the scan directory's BOM files with its
    properties, for the layer attribution check."""
    components = []
    for bom_file in sorted(glob.glob(os.path.join(reports_dir, "sbom-*.cdx.json"))):
        if "prebuild" in bom_file or "postbuild" in bom_file:
            continue
        bom = load_json(bom_file) or {}
        for component in bom.get("components") or []:
            if isinstance(component, dict):
                components.append(component)
    return components


def score_join_component_layer(item: dict, result, labels: dict, payload) -> dict:
    """The layer dep-scan assigns a component of an image, or none.

    A BOM that records per-layer attribution carries it on the component:
    a property or evidence entry naming the layer it was found in. The check
    counts the components of the labelled packages and how many of them
    carry any layer-naming property. No such property anywhere means the
    join is a gap today, and the draft issue names the producer.
    """
    section = (labels.get("joins") or {}).get("component-layer") or {}
    entries = section.get("packages") or []
    components = _bom_components_with_properties(result.reports_dir)
    if not components:
        return {"outcome": "partial", "reason": "the scan directory holds no component BOM"}
    wanted = {purl_key(e["purl"]) for e in entries}
    layer_words = ("layer", "layerid", "diffid")
    layer_props = set()
    with_layer = 0
    labelled_seen = 0
    for component in components:
        key = purl_key(component.get("purl") or "")
        props = [
            str(p.get("name") or "").lower()
            for p in component.get("properties") or []
            if isinstance(p, dict)
        ]
        layer_props |= {p for p in props if any(word in p for word in layer_words)}
        if key in wanted:
            labelled_seen += 1
            if any(word in p for p in props for word in layer_words):
                with_layer += 1
    if layer_props or with_layer:
        return {
            "outcome": "measured",
            "labelledSeen": labelled_seen,
            "withLayer": with_layer,
            "layerProperties": sorted(layer_props),
        }
    return {
        "outcome": "gap",
        "labelledSeen": labelled_seen,
        "withLayer": 0,
        "reason": (
            "no component of the image BOM carries layer attribution: "
            "the join cannot be made from what cdxgen records today"
        ),
    }


def score_join_component_runtime(item: dict, result, labels: dict, payload) -> dict:
    """Components observed at runtime against the trace's labels.

    The scan reads a tracebom trace from ``analysis/tracebom/``; the evidence
    records of the tracebom producer name the components the run observed.
    """
    section = (labels.get("joins") or {}).get("component-runtime") or {}
    entries = section.get("packages") or []
    if not entries:
        return {"outcome": "partial", "reason": "the item labels no runtime packages"}
    records = read_evidence(result.reports_dir)
    observed = set()
    ran = False
    for record in records:
        if record.producer.name == "tracebom":
            ran = True
            observed |= {purl_key(p) for p in record.subject.purls}
    if not ran:
        return {
            "outcome": "partial",
            "reason": "the evidence store holds no tracebom records; the trace was not read",
        }
    wanted = {purl_key(e["purl"]) for e in entries}
    matched = wanted & observed
    return {
        "outcome": "measured" if matched == wanted else "partial",
        "observed": len(observed),
        "matched": len(matched),
        "missed": sorted(wanted - observed),
    }


def _bom_component_versions(reports_dir: str, key: str) -> list:
    """The distinct versions a scan directory's BOMs record for one package
    key, each with the declaring path when a property names one."""
    versions = []
    for component in _bom_components_with_properties(reports_dir):
        purl = component.get("purl")
        if not isinstance(purl, str) or purl_key(purl) != key:
            continue
        comparable = comparable_purl(purl)
        version = comparable.rsplit("@", 1)[1] if "@" in comparable else ""
        declaring = ""
        for prop in component.get("properties") or []:
            if isinstance(prop, dict) and prop.get("name") in ("SrcFile", "depscan:srcFile"):
                declaring = str(prop.get("value") or "")
        versions.append({"version": version, "declaringPath": declaring})
    return versions


def _bom_components_by_type(reports_dir: str) -> dict:
    """Every scan directory BOM's components, keyed by the project type the
    file name carries (``sbom-<type>.cdx.json``)."""
    by_type = {}
    for bom_file in sorted(glob.glob(os.path.join(reports_dir, "sbom-*.cdx.json"))):
        if "prebuild" in bom_file or "postbuild" in bom_file:
            continue
        stem = os.path.basename(bom_file)[len("sbom-") : -len(".cdx.json")]
        bom = load_json(bom_file) or {}
        by_type[stem] = bom.get("components") or []
    return by_type


def score_join_two_producers(item: dict, result, labels: dict, payload) -> dict:
    """One component identity for the same package seen by two producers.

    The scan ran one producer per project type; the join holds when the
    labelled package appears in both types' BOMs under the same comparable
    purl and the evidence store keeps each producer's own records.
    """
    section = (labels.get("joins") or {}).get("two-producers") or {}
    package = section.get("package")
    if not package:
        return {"outcome": "partial", "reason": "the item names no package"}
    key = purl_key(package)
    by_type = {}
    for project_type, components in _bom_components_by_type(result.reports_dir).items():
        purls = sorted(
            {
                comparable_purl(c["purl"])
                for c in components
                if isinstance(c, dict) and c.get("purl") and purl_key(c["purl"]) == key
            }
        )
        if purls:
            by_type[project_type] = purls
    producers = sorted({r.producer.name for r in read_evidence(result.reports_dir)})
    if len(by_type) < 2:
        return {
            "outcome": "partial",
            "reason": f"the package was found in {len(by_type)} of the "
            f"{len(item['scan']['types'])} scans",
            "byType": by_type,
        }
    identical = len({p for components in by_type.values() for p in components}) == 1
    return {
        "outcome": "measured" if identical else "partial",
        "byType": by_type,
        "identical": identical,
        "producers": producers,
    }


def score_join_two_manifests(item: dict, result, labels: dict, payload) -> dict:
    """One dependency declared at two versions must stay two components.

    The score counts the distinct versions the scan holds for the labelled
    package and how many of the components record which manifest declared
    them; the declaring path is the field the vision names as the gap.
    """
    section = (labels.get("joins") or {}).get("two-manifests") or {}
    package = section.get("package")
    expected_versions = set(section.get("versions") or [])
    if not package:
        return {"outcome": "partial", "reason": "the item names no package"}
    key = purl_key(package)
    components = _bom_component_versions(result.reports_dir, key)
    distinct = {c["version"] for c in components if c["version"]}
    with_declaring = sum(1 for c in components if c["declaringPath"])
    if not components:
        return {
            "outcome": "partial",
            "reason": "the scan holds no component for the labelled package",
        }
    versions_ok = not expected_versions or expected_versions <= distinct
    two_components = len(distinct) >= 2 if expected_versions else len(components) >= 2
    outcome = "measured" if (versions_ok and two_components) else "partial"
    return {
        "outcome": outcome,
        "components": components,
        "distinctVersions": sorted(distinct),
        "withDeclaringPath": with_declaring,
        "reason": None
        if two_components
        else f"the scan holds {len(distinct)} version(s), not the two the labels name",
    }


JOIN_EVALUATORS = {
    "advisory-usage-reach": score_join_advisory_usage_reach,
    "route-package": score_join_route_package,
    "lifecycle-phase": score_join_lifecycle_phase,
    "component-layer": score_join_component_layer,
    "component-runtime": score_join_component_runtime,
    "two-producers": score_join_two_producers,
    "two-manifests": score_join_two_manifests,
}


def score_item_joins(item: dict, result, labels: dict, payload) -> dict:
    """Every join the item labels, with its outcome."""
    scores = {}
    for join in JOINS:
        if join in ((labels.get("joins") or {})):
            scores[join] = JOIN_EVALUATORS[join](item, result, labels, payload)
    return scores


# ---------------------------------------------------------------------------
# floors


def check_floors(floors_doc: dict, score_doc: dict) -> list:
    """The recorded floors that dropped, each with its current value.

    A floor names an item and a dotted path into that item's score entry,
    for example ``reachability.SemanticReachability.reached.recall`` or
    ``joins.two-manifests.distinctVersions`` with a count minimum. A floor
    whose value is missing (an item not scored, a None rate) is a violation
    too: a floor recorded for an item the run cannot score has dropped in
    the only sense that matters.
    """
    violations = []
    by_item = {entry["item"]: entry for entry in score_doc.get("items", [])}
    for floor in floors_doc.get("floors") or []:
        entry = by_item.get(floor["item"])
        value = None
        if entry and entry.get("state") == "scored":
            node = entry
            ok = True
            for part in floor["path"].split("."):
                if isinstance(node, dict) and part in node:
                    node = node[part]
                else:
                    ok = False
                    break
            if ok and isinstance(node, (int, float)) and not isinstance(node, bool):
                value = node
        if value is None or value < floor["minimum"]:
            violations.append(
                {
                    "item": floor["item"],
                    "path": floor["path"],
                    "minimum": floor["minimum"],
                    "value": value,
                }
            )
    return violations


# ---------------------------------------------------------------------------
# the score document and its table


def inventory_failed(result):
    """The reason the inventory stage failed, when it did. A scan whose BOM
    generation failed assessed nothing, so the item reads as not assessed
    rather than as one with no findings."""
    for stage in (result.manifest or {}).get("stages") or []:
        if stage.get("name") == "inventory" and stage.get("status") == "failed":
            return stage.get("reason") or "the inventory stage failed"
    return None


def score_item(item: dict, labels: dict, result, payload) -> dict:
    """One item's score entry from its result."""
    from depscan import get_version

    findings = result.findings or []
    categories = {}
    findings_labels = (labels.get("findings") or {}) if labels else {}
    category_names = sorted({str(f.get("category")) for f in findings})
    for entry in findings_labels.get("expected") or []:
        if entry["category"] not in category_names:
            category_names.append(entry["category"])
    for control in findings_labels.get("forbidden") or []:
        if control["category"] not in category_names:
            category_names.append(control["category"])
    # A stage that did not complete turns its categories into not-assessed
    # entries even when no label names them: an unassessed check is its own
    # column, never silence.
    stage_backed_categories = {
        category for categories in STAGE_CATEGORIES.values() for category in categories
    }
    for category in stage_backed_categories:
        if category in category_names:
            continue
        if stage_not_assessed(result, category):
            category_names.append(category)
    for category in sorted(set(category_names)):
        stage = stage_not_assessed(result, category)
        if stage:
            categories[category] = {
                "status": "not-assessed",
                "reason": stage["reason"],
                "recall": None,
                "precision": None,
            }
        else:
            categories[category] = score_category(findings, findings_labels, category)
    components = 0
    for bom_file in glob.glob(os.path.join(result.reports_dir, "sbom-*.cdx.json")):
        bom = load_json(bom_file) or {}
        components += len(bom.get("components") or [])
    return {
        "item": item["name"],
        "kind": item.get("kind"),
        "state": "scored",
        "components": components,
        "findings": len(findings),
        "categories": categories,
        "reachability": score_reachability(item, result, labels, payload)
        if labels and labels.get("reachability")
        else None,
        "reachabilityNotAssessed": analyzer_not_assessed(result),
        "joins": score_item_joins(item, result, labels, payload) if labels else {},
        "depscanVersion": get_version(),
    }


def render_markdown(score_doc: dict) -> str:
    """The Markdown table of one run."""
    lines = ["# Corpus score", ""]
    meta = (
        f"Generated {score_doc.get('generatedAt')} at commit "
        f"{score_doc.get('commit') or 'unknown'} with dep-scan "
        f"{score_doc.get('depscanVersion')}."
    )
    lines += [meta, ""]
    lines += [
        "| Item | State | Reachability recall/precision | Categories | Joins |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in score_doc["items"]:
        if entry["state"] != "scored":
            reason = (entry.get("reason") or "").replace("|", "/")
            lines.append(f"| {entry['item']} | not assessed | | | {reason[:120]} |")
            continue
        reach = entry.get("reachability") or {}
        reach_cells = []
        for analyzer in ANALYZERS:
            scores = reach.get(analyzer) or {}
            if scores.get("status") != "assessed":
                continue
            for bucket in ("direct", "reached"):
                cell = scores.get(bucket) or {}
                recall = cell.get("recall")
                precision = cell.get("precision")
                reach_cells.append(
                    f"{analyzer.replace('Reachability', '')} {bucket} "
                    f"{recall if recall is not None else '-'}/"
                    f"{precision if precision is not None else '-'}"
                )
        category_cells = []
        for category, score in sorted((entry.get("categories") or {}).items()):
            if score.get("status") == "not-assessed":
                category_cells.append(f"{category}: not assessed")
            elif score.get("status") == "unlabelled":
                continue
            else:
                category_cells.append(
                    f"{category}: {score.get('recall')}/{score.get('precision')}"
                )
        join_cells = [
            f"{join}: {score['outcome']}" for join, score in sorted((entry.get("joins") or {}).items())
        ]
        lines.append(
            f"| {entry['item']} | scored | {'; '.join(reach_cells)} | "
            f"{'; '.join(category_cells)} | {'; '.join(join_cells)} |"
        )
    lines += ["", "## Joins", ""]
    lines += ["| Join | Outcome |", "| --- | --- |"]
    for join in JOINS:
        outcomes = sorted(
            {
                (entry.get("joins") or {}).get(join, {}).get("outcome", "not labelled")
                for entry in score_doc["items"]
                if entry.get("joins") and join in (entry.get("joins") or {})
            }
        )
        lines.append(f"| {join} | {', '.join(outcomes) or 'not labelled'} |")
    lines += ["", "## Categories dep-scan does not produce yet", ""]
    for entry in score_doc.get("notProduced") or []:
        lines.append(f"- {entry['category']}: tracked by {entry['issue']}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# main


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        default=os.path.join(_HERE, "depscan.corpus.json"),
        help="The corpus manifest (default: beside this script).",
    )
    parser.add_argument("--items", default=None, help="Comma-separated item names.")
    parser.add_argument(
        "--subset",
        default=None,
        choices=("ci",),
        help="Score only the items a pull-request job can run.",
    )
    parser.add_argument(
        "--scan-dir",
        default=None,
        help="Score existing scan directories under this root instead of running.",
    )
    parser.add_argument(
        "--scans-root",
        default=None,
        help="Directory the scans are written to (run mode).",
    )
    parser.add_argument(
        "--corpus-root",
        default=os.path.expanduser("~/sandbox/p23-corpus"),
        help="Directory holding the corpus clones (run mode).",
    )
    parser.add_argument(
        "--testdata-root",
        default=os.path.expanduser("~/sandbox/p23-testdata"),
        help="Directory holding the pulled repo-test data.",
    )
    parser.add_argument(
        "--floors",
        default=None,
        help="Floors file; the run exits 1 when a floor drops or a negative control fires.",
    )
    parser.add_argument(
        "--output",
        default=".",
        help="Directory score.json and the Markdown table are written to.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3600.0,
        help="Per-item scan budget in seconds (default: 3600).",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Clone missing repository items at their pinned commits first.",
    )
    parser.add_argument(
        "--digest-fixture",
        default=None,
        help="Print the digest of one fixture directory and exit.",
    )
    args = parser.parse_args()

    if args.digest_fixture:
        print(fixture_digest(args.digest_fixture))
        return 0

    manifest_path = os.path.abspath(args.manifest)
    manifest = load_manifest(manifest_path)
    manifest_dir = os.path.dirname(manifest_path)
    items = select_items(manifest, args)
    floors_doc = load_json(args.floors) if args.floors else None
    if args.floors and floors_doc is None:
        raise ScoreError(f"Cannot read the floors file '{args.floors}'.")

    from depscan import api, get_version

    entries = []
    for item in items:
        labels = load_labels(manifest_dir, item)
        entry = {"item": item["name"], "kind": item.get("kind"), "state": None}
        if labels is None:
            entry.update(state="not-assessed", reason=f"no label file {item.get('labels')}")
            entries.append(entry)
            continue
        if args.scan_dir:
            reports_dir = os.path.abspath(os.path.join(args.scan_dir, item["name"]))
            if not os.path.isdir(reports_dir):
                entry.update(
                    state="not-assessed",
                    reason=f"no scan directory at {reports_dir}",
                )
                entries.append(entry)
                continue
            try:
                result = api.load_scan(reports_dir)
            except api.ScanError as exc:
                entry.update(state="not-assessed", reason=str(exc))
                entries.append(entry)
                continue
            inventory_reason = inventory_failed(result)
            if inventory_reason:
                entry.update(state="not-assessed", reason=inventory_reason)
                entries.append(entry)
                continue
            entries.append(score_item(item, labels, result, reports_dir))
            continue
        payload, reason = resolve_payload(item, args, args.timeout)
        if payload is None:
            entry.update(state="not-assessed", reason=reason)
            entries.append(entry)
            continue
        scans_root = args.scan_dir or args.scans_root
        if not scans_root:
            entry.update(
                state="not-assessed",
                reason="run mode needs --scans-root (or score scans with --scan-dir)",
            )
            entries.append(entry)
            continue
        reports_dir = os.path.abspath(os.path.join(scans_root, item["name"]))
        result, error = run_item_scan(item, payload, reports_dir, args.timeout)
        if result is None:
            entry.update(state="not-assessed", reason=error)
            entries.append(entry)
            continue
        inventory_reason = inventory_failed(result)
        if inventory_reason:
            entry.update(state="not-assessed", reason=inventory_reason)
            entries.append(entry)
            continue
        entries.append(score_item(item, labels, result, payload))
        continue

    commit = "unknown"
    try:
        commit = (
            subprocess.run(
                ["git", "-C", _REPO_ROOT, "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
            or "unknown"
        )
    except (OSError, subprocess.SubprocessError):
        pass
    scored = [entry for entry in entries if entry.get("state") == "scored"]
    forbidden_fired = [
        {"item": entry["item"], **fired}
        for entry in entries
        for category in (entry.get("categories") or {}).values()
        for fired in category.get("forbiddenFired") or []
    ]
    score_doc = {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "commit": commit,
        "depscanVersion": get_version(),
        "subset": args.subset,
        "items": entries,
        "notProduced": manifest.get("notProduced") or [],
        "summary": {
            "items": len(entries),
            "scored": len(scored),
            "notAssessed": len(entries) - len(scored),
            "forbiddenFired": forbidden_fired,
        },
    }
    if floors_doc is not None:
        violations = check_floors(floors_doc, score_doc)
        score_doc["summary"]["floors"] = {
            "commit": floors_doc.get("commit"),
            "checked": len(floors_doc.get("floors") or []),
            "violations": violations,
        }
    os.makedirs(args.output, exist_ok=True)
    score_path = os.path.join(args.output, "score.json")
    with open(score_path, "w", encoding="utf-8") as fp:
        json.dump(score_doc, fp, indent=2, ensure_ascii=False)
        fp.write("\n")
    table_path = os.path.join(args.output, "score.md")
    with open(table_path, "w", encoding="utf-8") as fp:
        fp.write(render_markdown(score_doc))
    print(f"Wrote {score_path} and {table_path}")
    print(
        f"{len(scored)} of {len(entries)} items scored"
        + (f", {len(forbidden_fired)} negative controls fired" if forbidden_fired else "")
    )
    if floors_doc is not None:
        summary = score_doc["summary"]["floors"]
        print(
            f"Floors: {summary['checked']} checked at commit {summary.get('commit')}, "
            f"{len(summary['violations'])} violations"
        )
        if summary["violations"]:
            for violation in summary["violations"]:
                print(
                    f"  {violation['item']} {violation['path']}: "
                    f"{violation['value']} < {violation['minimum']}"
                )
        if forbidden_fired or summary["violations"]:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
