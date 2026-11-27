#!/usr/bin/env python3
"""The corpus scorer: run dep-scan on the corpus, score it against the labels.

Every corpus item states what dep-scan must find and what it must not. This
script runs the item's scan (or reads a scan directory made earlier), scores
per item, per finding category and per join, and writes ``score.json`` with a
Markdown table beside it. A result dep-scan did not assess is its own column
with its reason; it is never a miss and never a clean pass.

Usage:
    # Run every item whose inputs are present
    python contrib/corpus/score.py --scans-root /tmp/corpus-scans \
        --corpus-root ~/corpus --testdata-root ~/repotests-data

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
The scorer never runs a scanned project's build tooling, never parses console
output (it reads the scan directory through :func:`depscan.api.load_scan`),
and compares every purl through ``comparable_purl``.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import shutil
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


def split_purl(purl: str):
    """A purl's comparable_purl form split into (key, version). The version
    separator is the last ``@`` that no ``/`` follows, so the ``@`` of an npm
    scope never reads as one; the version is None when the purl has none."""
    comparable = comparable_purl(str(purl))
    head, sep, tail = comparable.rpartition("@")
    if not sep or "/" in tail or not head.partition("/")[2]:
        return comparable, None
    return head, tail


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
# corpus, labels and inputs


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


def fixture_digest(directory: str) -> str:
    """The digest of a fixture directory: SHA-256 over every file's relative
    path with forward slashes and its bytes, in sorted path order."""
    digest = hashlib.sha256()
    entries = []
    for base, _dirs, files in os.walk(directory):
        for name in files:
            path = os.path.join(base, name)
            entries.append((os.path.relpath(path, directory).replace(os.sep, "/"), path))
    for rel, path in sorted(entries):
        digest.update(rel.encode("utf-8") + b"\x00")
        with open(path, "rb") as fp:
            digest.update(fp.read())
    return digest.hexdigest()


def _git(clone: str, *args, text=True):
    return subprocess.run(["git", "-C", clone, *args], capture_output=True, text=text)


def resolve_repository(item: dict, corpus_root: str, fetch: bool = False):
    """The clone of a repository item at its pinned commit, digest-checked.

    With ``fetch`` a missing clone is fetched first: a blob-less clone, then
    a checkout of the pinned commit. Returns (clone, None), or (None, reason)
    when the clone is missing and fetching is off or the digest fails.
    """
    clone = os.path.join(corpus_root, item["name"])
    source, commit = item["source"].rsplit("@", 1)
    if not os.path.isdir(os.path.join(clone, ".git")):
        if not fetch:
            return None, (
                f"no clone at {clone}; clone {item['source']} there first, or "
                "run the scorer with --fetch"
            )
        os.makedirs(os.path.dirname(clone), exist_ok=True)
        cloned = subprocess.run(
            ["git", "clone", "-q", "--filter=blob:none", source, clone], capture_output=True
        )
        if cloned.returncode != 0:
            return None, f"cloning {source} failed: {cloned.stderr.decode(errors='replace')}"
    head = _git(clone, "rev-parse", "HEAD").stdout.strip()
    if head != commit and fetch:
        _git(clone, "fetch", "-q", "--filter=blob:none", "origin", commit)
        _git(clone, "checkout", "-q", "--detach", commit)
        head = _git(clone, "rev-parse", "HEAD").stdout.strip()
    if head != commit:
        return None, (
            f"the clone at {clone} is at {head[:12] or 'an unknown commit'}, "
            f"not the pinned {commit[:12]}"
        )
    tar = _git(clone, "archive", "--format=tar", commit, text=False)
    if tar.returncode != 0:
        return None, f"git archive failed for {item['name']}"
    return _digest_checked(item, hashlib.sha256(tar.stdout).hexdigest(), clone)


def _digest_checked(item: dict, digest: str, payload):
    if digest == item["sha256"]:
        return payload, None
    note = item.get("digestNote", "")
    return None, (
        f"digest mismatch for {item['name']}: computed {digest}, the manifest pins "
        f"{item['sha256']}" + (f" ({note})" if note else "")
    )


def resolve_testdata(item: dict, testdata_root: str):
    """The pulled repo-test data of a BOM item, verified against its digest.

    The data root holds one directory per artifact plus the OCI manifest copy
    the pull keeps under ``.manifests``, the layout the repotests action
    pulls into.
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


def resolve_fixture(item: dict, scans_root: str):
    """The committed fixture of a fixture item, digest-checked and copied.

    The fixture is scanned from a copy under ``scans_root``, never from the
    repository tree: the corpus sits inside dep-scan's own uv workspace, and
    a scan of the committed directory would pick the workspace's environment
    up. The copy lands beside the scan directory, never inside it: a BOM
    directory scan reads its BOMs from the target, and a target inside the
    reports directory would have its BOMs skipped as scan outputs.
    """
    name = item["source"].split(":", 1)[1] if ":" in item["source"] else item["name"]
    directory = os.path.join(_HERE, "fixtures", name)
    if not os.path.isdir(directory):
        return None, f"the fixture '{name}' is not committed under contrib/corpus/fixtures."
    checked, reason = _digest_checked(item, fixture_digest(directory), directory)
    if checked is None:
        return None, reason
    if not scans_root:
        return None, "run mode needs --scans-root to copy the fixture into"
    copy_dir = os.path.abspath(os.path.join(scans_root, "payloads", item["name"]))
    shutil.rmtree(copy_dir, ignore_errors=True)
    os.makedirs(os.path.dirname(copy_dir), exist_ok=True)
    shutil.copytree(
        directory, copy_dir, ignore=shutil.ignore_patterns(".venv-trace", "node_modules")
    )
    return copy_dir, None


def resolve_payload(item: dict, args):
    """The input an item's scan reads, as (payload, None) or (None, reason)."""
    kind = item.get("kind")
    if kind == "repository":
        return resolve_repository(item, args.corpus_root, args.fetch)
    if kind == "bom":
        return resolve_testdata(item, args.testdata_root)
    if kind in ("fixture", "binary"):
        return resolve_fixture(item, args.scans_root)
    if kind == "image":
        if f"sha256:{item['sha256']}" not in item["source"]:
            return None, (
                f"the image reference '{item['source']}' does not carry the digest "
                f"the item pins (sha256:{item['sha256']})"
            )
        return item["source"], None
    return None, f"unknown item kind '{kind}'"


# ---------------------------------------------------------------------------
# scanning


def build_scan_options(item: dict, payload, reports_dir: str):
    """The internal options of the item's scan command line.

    The manifest's ``scan`` object is the command line: the payload as the
    target, one ``-t`` flag with every type (a repeated ``-t`` replaces, it
    does not extend), then the item's own arguments. The parsed command line
    goes through the same conversion the scan verb runs, so the manifest and
    the run stay in step with what the CLI itself would do.
    """
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


def run_item_scan(item: dict, payload, reports_dir: str, timeout: float):
    """Run the item's scan through :func:`depscan.api.scan` with rendering
    off, and return (result, None) or (None, reason)."""
    from depscan import api

    options, resolution = build_scan_options(item, payload, reports_dir)
    started = time.time()
    try:
        result = api.scan(
            options, render=False, checks_not_assessed=resolution.not_assessed or None
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
# one item's scan directory, read once


class ItemScan:
    """One item's scan, with the scan directory's BOMs, evidence records and
    analyser results each read or computed once and shared by every score.

    ``result`` is the :class:`depscan.api.ScanResult` (or any object with
    ``reports_dir``, ``findings``, ``manifest`` and ``project_types``);
    ``src_dir`` is the scanned source, when it exists on this machine.
    """

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

    def phase_boms(self) -> dict:
        """The BOMs by lifecycle phase; a BOM without a phase prefix is a
        type BOM, under None."""
        phases: dict = {}
        for stem, bom in self.boms.items():
            phase = next(
                (p for prefix, p in PHASE_PREFIXES.items() if stem.startswith(prefix)), None
            )
            phases.setdefault(phase, []).append(bom)
        return phases

    def components(self, phases=(None, "build")) -> list:
        """The component dicts of the BOMs of the given phases."""
        return [
            component
            for phase, boms in self.phase_boms().items()
            if phase in phases
            for bom in boms
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
        rules = {str(rule).lower() for rule in entry.get("rules") or []}
        key = label_key(entry["purl"])
        index = next(
            (
                i
                for i, finding in enumerate(findings)
                if finding.get("category") == entry["category"]
                and str(finding.get("rule") or "").lower() in rules
                and key in keys_of(finding.get("components"))
            ),
            None,
        )
        if index is None:
            missed.append(entry)
        else:
            matched_findings.add(index)
    hits = len(expected) - len(missed)
    fired = []
    for control in forbidden:
        rules = {str(rule).lower() for rule in control.get("rules") or []}
        for finding in findings:
            if finding.get("category") != control["category"]:
                continue
            if rules and str(finding.get("rule") or "").lower() not in rules:
                continue
            if control.get("purl") and label_key(control["purl"]) not in keys_of(
                finding.get("components")
            ):
                continue
            fired.append(
                {
                    "rule": finding.get("rule"),
                    "purls": finding.get("components") or [],
                    "id": finding.get("id"),
                    "reason": control.get("reason"),
                }
            )
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
    unexpected = []
    for index, finding in enumerate(findings):
        keys = keys_of(finding.get("components"))
        if index in matched_findings or keys & expected_keys:
            continue
        if keys & controlled.get(finding.get("category"), set()):
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
        "seen": len({purl_key(key) for key in keys}),
    }


def usage_labels(labels: dict):
    """The used and unused label keys of an item."""
    section = labels.get("reachability") or {}
    return (
        label_keys(e["purl"] for e in section.get("used") or []),
        label_keys(e["purl"] for e in section.get("unused") or []),
    )


def score_reachability(scan: ItemScan, labels: dict) -> dict:
    """Both analysers scored against the reachability labels, per project."""
    used, unused = usage_labels(labels)
    scores = {}
    for analyzer in ANALYZERS:
        res, reason = scan.reach(analyzer)
        if res is None:
            scores[analyzer] = {"status": "not-assessed", "reason": reason}
            continue
        scores[analyzer] = {
            "status": "assessed",
            "direct": score_purl_set(keys_of(res.direct_purls), used, unused),
            "reached": score_purl_set(keys_of(res.reached_purls), used, unused),
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
    used, unused = usage_labels(labels)
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
        brief = {"id": finding.get("id"), "rule": finding.get("rule")}
        if not keys & reached:
            if keys & used:
                not_reached_on_used.append(brief)
        elif keys & used:
            reached_on_used += 1
        elif keys & unused:
            reached_on_unused.append(brief)
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
    handlers occupy."""
    by_route: dict = {}
    try:
        names = sorted(
            n for n in os.listdir(reports_dir) if "openapi" in n and n.endswith(".json")
        )
    except OSError:
        names = []
    for name in names:
        spec = load_json(os.path.join(reports_dir, name)) or {}
        for path, operations in (spec.get("paths") or {}).items():
            for method, operation in (
                (operations or {}).items() if isinstance(operations, dict) else ()
            ):
                usages = operation.get("x-atom-usages") if isinstance(operation, dict) else None
                for kind in ("call", "target"):
                    by_file = (usages or {}).get(kind) if isinstance(usages, dict) else None
                    for file_name, lines in (
                        (by_file or {}).items() if isinstance(by_file, dict) else ()
                    ):
                        for line in lines if isinstance(lines, list) else ():
                            if isinstance(line, int):
                                by_route.setdefault((method.upper(), path), set()).add(
                                    (os.path.normpath(file_name), line)
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


def score_join_lifecycle_phase(scan: ItemScan, labels: dict) -> dict:
    """Packages labelled per lifecycle phase against the phase BOMs.

    A shipped package must be in the post-build BOM; a build-only or
    dev-only package must not ship, so it must stay out of the post-build
    BOM. When the post-build BOM holds no components (a source scan with no
    built environment), the shipped state was not observed: those labels are
    not-assessed with that reason, never passes and never misses.
    """
    entries = ((labels.get("joins") or {}).get("lifecycle-phase") or {}).get("packages") or []
    if not entries:
        return {"outcome": "partial", "reason": "the item labels no lifecycle packages"}
    phases = {
        phase: keys_of(
            c.get("purl") for c in scan.components((phase,)) if isinstance(c.get("purl"), str)
        )
        for phase in ("pre-build", "build", "post-build")
    }
    if not any(phases.values()):
        return {"outcome": "partial", "reason": "the scan directory holds no lifecycle BOMs"}
    shipped = phases["post-build"]
    matched = 0
    missed = []
    not_assessed = []
    for entry in entries:
        key = label_key(entry["purl"])
        present = sorted(name for name, components in phases.items() if key in components)
        if not shipped:
            not_assessed.append({**entry, "reason": "the post-build BOM holds no components"})
        elif (entry.get("phase") == "shipped") == (key in shipped):
            matched += 1
        else:
            missed.append({**entry, "observed": present})
    return {
        "outcome": "partial" if (missed or not_assessed) else "measured",
        "packages": len(entries),
        "matched": matched,
        "missed": missed,
        "notAssessed": not_assessed,
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


def score_join_two_producers(scan: ItemScan, labels: dict) -> dict:
    """One component identity for the same package seen by two producers.

    The scan ran one producer per project type; the join holds when the
    labelled package appears in both types' BOMs under the same comparable
    purl and the evidence store keeps each producer's own records.
    """
    package = ((labels.get("joins") or {}).get("two-producers") or {}).get("package")
    if not package:
        return {"outcome": "partial", "reason": "the item names no package"}
    key = label_key(package)
    by_type = {}
    for stem, bom in scan.boms.items():
        if stem.startswith(("prebuild-", "postbuild-")):
            continue
        purls = sorted(
            {
                comparable_purl(c["purl"])
                for c in bom.get("components") or []
                if isinstance(c, dict) and c.get("purl") and key in keys_of([c["purl"]])
            }
        )
        if purls:
            by_type[stem] = purls
    if len(by_type) < 2:
        return {
            "outcome": "partial",
            "reason": f"the package was found in {len(by_type)} of the "
            f"{len(scan.project_types)} scans",
            "byType": by_type,
        }
    identical = len({p for purls in by_type.values() for p in purls}) == 1
    return {
        "outcome": "measured" if identical else "partial",
        "byType": by_type,
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
    return {
        "outcome": "measured" if (expected_versions <= distinct and two) else "partial",
        "components": components,
        "distinctVersions": sorted(distinct),
        "distinctVersionCount": len(distinct),
        "withDeclaringPath": sum(1 for c in components if c["declaringPath"]),
        "reason": None
        if two
        else f"the scan holds {len(distinct)} version(s), not the two the labels name",
    }


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
    """One item's score entry from its scan."""
    joins = labels.get("joins") or {}
    return {
        "item": scan.item["name"],
        "kind": scan.item.get("kind"),
        "state": "scored",
        "components": sum(len(bom.get("components") or []) for bom in scan.boms.values()),
        "findings": len(scan.findings),
        "categories": score_categories(scan, labels),
        "reachability": score_reachability(scan, labels) if labels.get("reachability") else None,
        "reachabilityNotAssessed": analyzer_not_assessed(scan),
        "joins": {
            join: evaluate(scan, labels)
            for join, evaluate in JOIN_EVALUATORS.items()
            if join in joins
        },
    }


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
    if args.scan_dir:
        reports_dir = os.path.abspath(os.path.join(args.scan_dir, item["name"]))
        if not os.path.isdir(reports_dir):
            return not_assessed(f"no scan directory at {reports_dir}")
        try:
            result = api.load_scan(reports_dir)
        except api.ScanError as exc:
            return not_assessed(str(exc))
        payload = reports_dir
    else:
        payload, reason = resolve_payload(item, args)
        if payload is None:
            return not_assessed(reason)
        if not args.scans_root:
            return not_assessed("run mode needs --scans-root (or score scans with --scan-dir)")
        reports_dir = os.path.abspath(os.path.join(args.scans_root, item["name"]))
        result, reason = run_item_scan(item, payload, reports_dir, args.timeout)
        if result is None:
            return not_assessed(reason)
    scan = ItemScan(item, result, payload)
    reason = inventory_failed(scan)
    return not_assessed(reason) if reason else score_item(scan, labels)


def check_floors(floors_doc: dict, score_doc: dict) -> list:
    """The recorded floors that dropped, each with its current value.

    A floor names an item and a dotted path into that item's score entry,
    for example ``reachability.SemanticReachability.reached.recall``. A
    floor whose value is missing (an item not scored, a None rate) is a
    violation too: a floor recorded for an item the run cannot score has
    dropped in the only sense that matters.
    """
    violations = []
    by_item = {entry["item"]: entry for entry in score_doc.get("items", [])}
    for floor in floors_doc.get("floors") or []:
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


def render_markdown(score_doc: dict) -> str:
    """The Markdown table of one run."""
    lines = [
        "# Corpus score",
        "",
        f"Generated {score_doc.get('generatedAt')} at commit {score_doc.get('commit') or 'unknown'} "
        f"with dep-scan {score_doc.get('depscanVersion')}.",
        "",
        "| Item | State | Reachability recall/precision | Categories | Joins |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in score_doc["items"]:
        if entry["state"] != "scored":
            reason = (entry.get("reason") or "").replace("|", "/")
            lines.append(f"| {entry['item']} | not assessed | | | {reason[:120]} |")
            continue
        reach_cells = [
            f"{analyzer.replace('Reachability', '')} {bucket} "
            + "/".join(
                "-" if cell.get(k) is None else str(cell.get(k)) for k in ("recall", "precision")
            )
            for analyzer, scores in (entry.get("reachability") or {}).items()
            if scores.get("status") == "assessed"
            for bucket, cell in ((b, scores.get(b) or {}) for b in ("direct", "reached"))
        ]
        category_cells = [
            f"{category}: not assessed"
            if score.get("status") == "not-assessed"
            else f"{category}: {score.get('recall')}/{score.get('precision')}"
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
        "--scans-root", default=None, help="Directory the scans are written to (run mode)."
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
        "--output", default=".", help="Directory score.json and the Markdown table are written to."
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
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.digest_fixture:
        print(fixture_digest(args.digest_fixture))
        return 0
    manifest_path = os.path.abspath(args.manifest)
    manifest = load_manifest(manifest_path)
    items = select_items(manifest, args)
    floors_doc = load_json(args.floors) if args.floors else None
    if args.floors and floors_doc is None:
        raise ScoreError(f"Cannot read the floors file '{args.floors}'.")

    from depscan import get_version

    entries = [
        score_one(item, load_labels(os.path.dirname(manifest_path), item), args) for item in items
    ]
    commit = _git(_REPO_ROOT, "rev-parse", "HEAD").stdout.strip() or "unknown"
    scored = [entry for entry in entries if entry["state"] == "scored"]
    fired = [
        {"item": entry["item"], **control}
        for entry in scored
        for category in entry["categories"].values()
        for control in category.get("forbiddenFired") or []
    ]
    summary: dict = {
        "items": len(entries),
        "scored": len(scored),
        "notAssessed": len(entries) - len(scored),
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
        summary["floors"] = {
            "commit": floors_doc.get("commit"),
            "checked": len(floors_doc.get("floors") or []),
            "violations": check_floors(floors_doc, score_doc),
        }
    os.makedirs(args.output, exist_ok=True)
    score_path = os.path.join(args.output, "score.json")
    table_path = os.path.join(args.output, "score.md")
    with open(score_path, "w", encoding="utf-8") as fp:
        json.dump(score_doc, fp, indent=2, ensure_ascii=False)
        fp.write("\n")
    with open(table_path, "w", encoding="utf-8") as fp:
        fp.write(render_markdown(score_doc))
    print(f"Wrote {score_path} and {table_path}")
    print(
        f"{len(scored)} of {len(entries)} items scored"
        + (f", {len(fired)} negative controls fired" if fired else "")
    )
    if floors_doc is None:
        return 0
    floors = summary["floors"]
    print(
        f"Floors: {floors['checked']} checked at commit {floors['commit']}, {len(floors['violations'])} violations"
    )
    for violation in floors["violations"]:
        print(
            f"  {violation['item']} {violation['path']}: {violation['value']} < {violation['minimum']}"
        )
    return 1 if (fired or floors["violations"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
