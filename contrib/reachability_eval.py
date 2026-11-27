#!/usr/bin/env python3
"""Reachability evaluation: real labels by default, a snapshot for refactors.

The default mode scores dep-scan's reachability against the labelled corpus
(contrib/corpus/): for every item with reachability labels and a scan
directory under ``--scan-dir``, both analysers run over the scan directory
the way a scan does, and their ``direct_purls`` and reached purls are scored
against the ``used`` and ``unused`` labels. The numbers are recall and
precision per project and per analyser, reproducible from the corpus
manifest, the pinned commits, the repo-test data and the scorer.

The old snapshot mode stays as ``--check-snapshot`` for a refactor that must
not change output: it compares the reached sets of one or more reports
directories with the baseline recorded in ``reachability_eval.baseline.json``
(``--snapshot`` rewrites it), so a change that moves a reached purl without
a documented fix fails.

Usage:
    # Score the corpus items with reachability labels
    python contrib/reachability_eval.py

    # Score two items only
    python contrib/reachability_eval.py --items py-vulpy,js-express-realworld

    # Snapshot mode: diff a reports directory against the baseline
    python contrib/reachability_eval.py --check-snapshot /path/to/repo
    python contrib/reachability_eval.py --check-snapshot --snapshot /path/to/repo
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import resource
import sys
import time
from typing import Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, ".."))
for _src in (
    os.path.join(_REPO_ROOT, "packages", "analysis-lib", "src"),
    os.path.join(_REPO_ROOT, "packages", "xbom-lib", "src"),
):
    if os.path.isdir(_src):
        sys.path.insert(0, _src)

from analysis_lib import ReachabilityAnalysisKV  # noqa: E402
from analysis_lib.reachability import (  # noqa: E402
    _iter_json_list,
    get_reachability_impl,
)

_REPO_ROOT = os.path.abspath(os.path.join(_HERE, ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# The comparable key the scorer defines: comparable_purl without the
# version, so a version-less label and a reached purl that names one
# compare equal. One definition, shared with contrib/corpus/score.py.
from contrib.corpus.score import purl_key  # noqa: E402

BASELINE_FILE = os.path.join(_HERE, "reachability_eval.baseline.json")

ANALYZERS = ("FrameworkReachability", "SemanticReachability")

CORPUS_DIR = os.path.join(_HERE, "corpus")


def _peak_rss_mb() -> float:
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS reports bytes, Linux reports kilobytes.
    return rss / (1024 * 1024) if sys.platform == "darwin" else rss / 1024


def _slice_stats(reports_dir: str) -> Dict[str, int]:
    """Count reachables flow-objects and unique flow-objects across all files.

    Independent of the analyzer, so a refactor that changes how slices are read
    can be compared against ground truth. Streams each file element-by-element
    (mirrors the analyzer path) so the harness itself does not inflate the
    process peak RSS with a full parsed tree and obscure the analyzer's RSS
    improvement.
    """
    files = sorted(glob.glob(os.path.join(reports_dir, "*reachables.slices*.json")))
    total = 0
    unique = set()
    for f in files:
        for flow in _iter_json_list(f):
            if not isinstance(flow, dict):
                continue
            total += 1
            unique.add(hashlib.md5(json.dumps(flow, sort_keys=True).encode()).hexdigest())
    return {
        "reachables_files": len(files),
        "flows_total": total,
        "flows_unique": len(unique),
    }


def _find_vdr(reports_dir: str) -> Optional[str]:
    for pattern in ("*.vdr.json", "*.vdr", "bom.vdr.json"):
        hits = sorted(glob.glob(os.path.join(reports_dir, pattern)))
        if hits:
            return hits[0]
    return None


def _vuln_purls(vdr_file: str) -> List[str]:
    try:
        with open(vdr_file, encoding="utf-8") as fp:
            vdr = json.load(fp)
    except Exception:
        return []
    purls = set()
    for v in vdr.get("vulnerabilities", []) or []:
        for aff in v.get("affects", []) or []:
            ref = aff.get("ref")
            if ref and ref.startswith("pkg:"):
                purls.add(ref)
    return sorted(purls)


def _sorted_set(d: Optional[Dict]) -> List[str]:
    return sorted(d.keys()) if d else []


def evaluate_repo(repo: str) -> Dict:
    """The snapshot-mode evaluation of one reports directory."""
    reports_dir = os.path.join(repo, "reports") if os.path.isdir(
        os.path.join(repo, "reports")
    ) else repo
    result: Dict = {"repo": repo, "reports_dir": reports_dir}
    if not os.path.isdir(reports_dir):
        result["error"] = "no reports dir"
        return result
    result["slices"] = _slice_stats(reports_dir)
    vdr_file = _find_vdr(reports_dir)
    vuln_purls = _vuln_purls(vdr_file) if vdr_file else []
    result["vdr_file"] = os.path.basename(vdr_file) if vdr_file else None

    per_analyzer: Dict = {}
    for analyzer in ANALYZERS:
        options = ReachabilityAnalysisKV(
            project_types=["js"],
            src_dir=repo,
            bom_dir=reports_dir,
        )
        t0 = time.time()
        res = get_reachability_impl(analyzer, options).process()
        elapsed = time.time() - t0
        reached = _sorted_set(res.reached_purls)
        services = _sorted_set(res.reached_services)
        endpoints = _sorted_set(res.endpoint_reached_purls)
        direct = _sorted_set(res.direct_purls)
        entry = {
            "success": bool(res.success),
            "wall_clock_s": round(elapsed, 3),
            "peak_rss_mb_after": round(_peak_rss_mb()),
            "counts": {
                "direct_purls": len(direct),
                "reached_purls": len(reached),
                "reached_services": len(services),
                "endpoint_reached_purls": len(endpoints),
            },
            # The sorted sets are the correctness contract (what a check diffs).
            "sets": {
                "reached_purls": reached,
                "reached_services": services,
                "endpoint_reached_purls": endpoints,
            },
        }
        if vuln_purls:
            reached_set = set(reached)
            endpoint_set = set(endpoints)
            reached_vulns = sorted(p for p in vuln_purls if p in reached_set)
            endpoint_vulns = sorted(p for p in vuln_purls if p in endpoint_set)
            not_reached_vulns = sorted(p for p in vuln_purls if p not in reached_set)
            entry["vuln_cross_ref"] = {
                "vulnerable_purls": len(vuln_purls),
                "reached": len(reached_vulns),
                "endpoint_reached": len(endpoint_vulns),
                "not_reached": len(not_reached_vulns),
                "reached_set": reached_vulns,
                "endpoint_reached_set": endpoint_vulns,
                "not_reached_set": not_reached_vulns,
            }
        per_analyzer[analyzer] = entry
    result["analyzers"] = per_analyzer
    return result


# ---------------------------------------------------------------------------
# the labelled score


def _load_json(path: str):
    try:
        with open(path, encoding="utf-8") as fp:
            return json.load(fp)
    except (OSError, ValueError):
        return None


def corpus_items(manifest_path: str, wanted: List[str]):
    """The manifest items with reachability labels, optionally filtered."""
    manifest = _load_json(manifest_path)
    if not isinstance(manifest, dict):
        print(f"Cannot read the corpus manifest '{manifest_path}'.", file=sys.stderr)
        return []
    items = []
    for item in manifest.get("items") or []:
        if wanted and item.get("name") not in set(wanted):
            continue
        labels = _load_json(os.path.join(os.path.dirname(manifest_path), item.get("labels", "")))
        if not labels or not labels.get("reachability"):
            continue
        items.append((item, labels["reachability"]))
    return items


def score_purl_set(keys: set, used: set, unused: set) -> Dict:
    """Recall and precision of one purl set against the labels."""
    def rate(hit: int, total: int):
        return round(hit / total, 4) if total else None

    labelled = keys & (used | unused)
    true_positive = keys & used
    return {
        "recall": rate(len(true_positive), len(used)),
        "precision": rate(len(true_positive), len(labelled)),
        "missed": sorted(used - keys),
        "wrong": sorted(keys & unused),
    }


def evaluate_labelled(item: dict, reach_labels: dict, scan_dir: str, corpus_root: str) -> Dict:
    """The labelled score of one item's scan directory.

    The analysers read the scan directory's BOMs, slices and evidence the way
    a scan's enrichment stage does, with the item's own source directory for
    a repository item and the scan directory for data that arrives as BOMs.
    """
    name = item["name"]
    result: Dict = {"item": name, "scan_dir": scan_dir}
    if not os.path.isdir(scan_dir):
        result["error"] = "no scan directory"
        return result
    used = {purl_key(e["purl"]) for e in reach_labels.get("used") or []}
    unused = {purl_key(e["purl"]) for e in reach_labels.get("unused") or []}
    evidence_file = os.path.join(scan_dir, "evidence.jsonl")
    src_dir = (
        os.path.join(corpus_root, name) if item.get("kind") == "repository" else scan_dir
    )
    per_analyzer: Dict = {}
    for analyzer in ANALYZERS:
        options = ReachabilityAnalysisKV(
            project_types=item["scan"]["types"],
            src_dir=src_dir if os.path.isdir(src_dir) else scan_dir,
            bom_dir=scan_dir,
            evidence_file=evidence_file if os.path.isfile(evidence_file) else None,
        )
        t0 = time.time()
        res = get_reachability_impl(analyzer, options).process()
        elapsed = time.time() - t0
        if not res.success and not (res.direct_purls or res.reached_purls):
            per_analyzer[analyzer] = {
                "status": "not-assessed",
                "reason": "the analyzer produced no result over this scan directory",
            }
            continue
        entry = {
            "status": "assessed",
            "wall_clock_s": round(elapsed, 3),
            "direct": score_purl_set(
                {purl_key(p) for p in (res.direct_purls or {})}, used, unused
            ),
            "reached": score_purl_set(
                {purl_key(p) for p in (res.reached_purls or {})}, used, unused
            ),
        }
        per_analyzer[analyzer] = entry
    result["analyzers"] = per_analyzer
    return result


def _print_labelled(report: List[Dict]) -> None:
    for r in report:
        print(f"\n{'=' * 72}\n{r['item']}")
        if r.get("error"):
            print(f"  ERROR: {r['error']}")
            continue
        for analyzer, e in r["analyzers"].items():
            if e.get("status") != "assessed":
                print(f"  {analyzer:24} not assessed: {e.get('reason')}")
                continue
            for bucket in ("direct", "reached"):
                c = e[bucket]
                recall = c["recall"] if c["recall"] is not None else "-"
                precision = c["precision"] if c["precision"] is not None else "-"
                print(
                    f"  {analyzer:24} {bucket:8} recall={recall} precision={precision} "
                    f"missed={len(c['missed'])} wrong={len(c['wrong'])}"
                )


# ---------------------------------------------------------------------------
# the snapshot mode


def _print_report(report: List[Dict]) -> None:
    for r in report:
        print(f"\n{'=' * 72}\n{r['repo']}")
        if r.get("error"):
            print(f"  ERROR: {r['error']}")
            continue
        s = r["slices"]
        print(
            f"  slices: {s['reachables_files']} files, "
            f"{s['flows_total']} flows ({s['flows_unique']} unique, "
            f"{s['flows_total'] - s['flows_unique']} dup)"
        )
        print(f"  vdr: {r.get('vdr_file')}")
        for analyzer, e in r["analyzers"].items():
            c = e["counts"]
            print(
                f"  {analyzer:22} {e['wall_clock_s']:6.2f}s  RSS~{e['peak_rss_mb_after']:5}MB  "
                f"direct={c['direct_purls']:4} reached={c['reached_purls']:4} "
                f"services={c['reached_services']:4} endpoint={c['endpoint_reached_purls']:4}"
            )
            if "vuln_cross_ref" in e:
                x = e["vuln_cross_ref"]
                reached_n = c["reached_purls"]
                precision = (x["reached"] / reached_n) if reached_n else 0.0
                recall = (x["reached"] / x["vulnerable_purls"]) if x["vulnerable_purls"] else 0.0
                print(
                    f"    {'':20}   vulns={x['vulnerable_purls']} reached={x['reached']} "
                    f"endpoint={x['endpoint_reached']} not_reached={x['not_reached']} "
                    f"precision={precision:.2f} recall={recall:.2f}"
                )


def _sets_only(report: List[Dict]) -> Dict:
    """Extract the correctness contract (repo -> analyzer -> sets + cross-ref)."""
    out = {}
    for r in report:
        if r.get("error"):
            continue
        per_analyzer: Dict = {}
        for a, e in r["analyzers"].items():
            per_analyzer[a] = {"sets": e["sets"]}
            xref = e.get("vuln_cross_ref")
            if xref:
                per_analyzer[a]["vuln_cross_ref"] = {
                    "reached_set": xref["reached_set"],
                    "endpoint_reached_set": xref["endpoint_reached_set"],
                    "not_reached_set": xref["not_reached_set"],
                }
        out[r["repo"]] = per_analyzer
    return out


def _diff_set(repo: str, analyzer: str, key: str, baseline_list, current_list) -> None:
    """Print a unified-style diff for one set contract (no-op if equal)."""
    bs, cs = set(baseline_list or []), set(current_list or [])
    if bs == cs:
        return
    added, removed = sorted(cs - bs), sorted(bs - cs)
    print(
        f"  {repo} / {analyzer} / {key}: +{len(added)} -{len(removed)}",
        file=sys.stderr,
    )
    for p in added[:10]:
        print(f"      + {p}", file=sys.stderr)
    for p in removed[:10]:
        print(f"      - {p}", file=sys.stderr)


def _run_snapshot(args) -> int:
    """The old behaviour: diff reached sets against the recorded baseline."""
    repos = args.repos or []
    if not repos:
        print(
            "Snapshot mode needs at least one repository whose reports/ to read; "
            "the labelled score (the default) reads the corpus instead.",
            file=sys.stderr,
        )
        return 2
    report = [evaluate_repo(r) for r in repos]
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_report(report)
    if args.snapshot:
        with open(BASELINE_FILE, "w", encoding="utf-8") as fp:
            json.dump(_sets_only(report), fp, indent=2, sort_keys=True)
        print(f"\nBaseline written to {BASELINE_FILE}")
        return 0
    if args.check:
        if not os.path.exists(BASELINE_FILE):
            print("\nNo baseline; run with --snapshot first.", file=sys.stderr)
            return 2
        with open(BASELINE_FILE, encoding="utf-8") as fp:
            baseline = json.load(fp)
        current = _sets_only(report)
        if current == baseline:
            print("\n[check] reached sets + vuln_cross_ref match baseline. OK")
            return 0
        print("\n[check] sets DIFFER from baseline:", file=sys.stderr)
        for repo in sorted(set(baseline) | set(current)):
            for analyzer in ANALYZERS:
                b = baseline.get(repo, {}).get(analyzer, {})
                c = current.get(repo, {}).get(analyzer, {})
                b_sets = b.get("sets", {})
                c_sets = c.get("sets", {})
                for key in ("reached_purls", "reached_services", "endpoint_reached_purls"):
                    _diff_set(repo, analyzer, key, b_sets.get(key, []), c_sets.get(key, []))
                b_xref = b.get("vuln_cross_ref", {})
                c_xref = c.get("vuln_cross_ref", {})
                for key in ("reached_set", "endpoint_reached_set", "not_reached_set"):
                    _diff_set(
                        f"{repo} [vuln_cross_ref]",
                        analyzer,
                        key,
                        b_xref.get(key, []),
                        c_xref.get(key, []),
                    )
        return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "repos",
        nargs="*",
        default=None,
        help="snapshot mode: repositories whose reports/ directories to read",
    )
    ap.add_argument(
        "--manifest",
        default=os.path.join(CORPUS_DIR, "depscan.corpus.json"),
        help="the corpus manifest (default: contrib/corpus/depscan.corpus.json)",
    )
    ap.add_argument(
        "--scan-dir",
        default=os.path.expanduser("~/sandbox/p23-corpus/scans"),
        help="root holding the corpus scan directories, one per item",
    )
    ap.add_argument("--items", default=None, help="comma-separated item names")
    ap.add_argument(
        "--corpus-root",
        default=os.path.expanduser("~/sandbox/p23-corpus"),
        help="directory holding the corpus clones, one per repository item",
    )
    ap.add_argument(
        "--check-snapshot",
        action="store_true",
        help="run the snapshot mode instead of the labelled score",
    )
    ap.add_argument(
        "--snapshot",
        action="store_true",
        help="snapshot mode: write the baseline instead of comparing",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="snapshot mode: diff reached sets vs baseline; exit 1 on change",
    )
    ap.add_argument("--json", action="store_true", help="print the full JSON report")
    args = ap.parse_args()

    if args.check_snapshot:
        return _run_snapshot(args)
    wanted = [n.strip() for n in (args.items or "").split(",") if n.strip()]
    items = corpus_items(args.manifest, wanted)
    if not items:
        print(
            "No corpus item with reachability labels to score; pass --items or "
            "check the manifest.",
            file=sys.stderr,
        )
        return 2
    report = [
        evaluate_labelled(item, labels, os.path.join(args.scan_dir, item["name"]), args.corpus_root)
        for item, labels in items
    ]
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_labelled(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
