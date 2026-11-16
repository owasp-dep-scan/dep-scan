"""Merge and de-duplicate CycloneDX VDR entries.

When several components are affected by the same vulnerability, the matching
stage emits one entry per component. dedupe_vdrs collapses them into a single
VDR entry whose affects and references cover every component, preferring the
bom-ref of a prioritized entry so console grouping keeps attributing the merge
correctly.

This module only combines finished VDR dicts. It does not create entries from
vdb records (see analysis_lib.advisory) and does not strip private keys from
them beyond remove_extra_metadata.
"""

from datetime import datetime

from analysis_lib.config import TIME_FMT


def remove_extra_metadata(vdrs):
    new_vdrs = []
    exclude = {
        "insights",
        "matched_by",
        "purl_prefix",
        "p_rich_tree",
        "fixed_location",
    }
    for vdr in vdrs:
        new_vdr = {}
        for key, value in vdr.items():
            if key not in exclude:
                new_vdr |= {key: value}
        new_vdrs.append(new_vdr)
    return new_vdrs


def dedupe_vdrs(vdrs):
    # Issue #504: key primarily by vulnerability id so that multiple components
    # affected by the same CVE merge into a single VDR entry with multiple
    # affects[].ref. Falls back to bom-ref (exact duplicate) and then to the
    # original index (never collapse unrelated entries).
    new_vdrs = {}
    order = []
    for idx, vdr in enumerate(vdrs):
        vuln_id = vdr.get("id")
        if vuln_id:
            key = ("id", vuln_id)
        elif vdr.get("bom-ref"):
            key = ("bom-ref", vdr["bom-ref"])
        else:
            key = ("idx", idx)
        if key in new_vdrs:
            new_vdrs[key] = combine_vdrs(new_vdrs[key], vdr)
        else:
            new_vdrs[key] = vdr
            order.append(key)
    return [new_vdrs[k] for k in order]


def choose_date(d1, d2, choice):
    if not d1 or not d2 or choice not in {"max", "min"}:
        return d1 or d2
    try:
        d1 = datetime.fromisoformat(d1)
        d2 = datetime.fromisoformat(d2)
        d3 = max(d1, d2) if choice == "max" else min(d1, d2)
        return d3.strftime(TIME_FMT)
    except ValueError:
        return d1 or d2
    except TypeError:
        d3 = max(d1.date(), d2.date()) if choice == "max" else min(d1.date(), d2.date())
        return d3.strftime(TIME_FMT)


def combine_affects(v1, v2):
    affects = {}
    seen_refs = set()
    if not v1 or not v2:
        return v1 or v2
    v1.extend(v2)
    for i in v1:
        ref = i.get("ref", "")
        for vers in i.get("versions", []):
            version = vers.get("version", "") or vers.get("range", "")
            status = vers.get("status", "")
            vers_ref = f"{ref}/{version}/{status}"
            if vers_ref not in seen_refs:
                if ref in affects:
                    affects[ref]["versions"].append(vers)
                else:
                    affects[ref] = {"ref": ref, "versions": [vers]}
                seen_refs.add(vers_ref)
    return list(affects.values())


def combine_generic(v1, v2, keys):
    """Combines two lists of flat dicts"""
    if not v1 or not v2:
        return v1 or v2
    seen_keys = set()
    v3 = []
    for i in v1 + v2:
        seen_id = "".join([str(i.get(k, "")) for k in keys])
        if seen_id not in seen_keys:
            v3.append(i)
            seen_keys.add(seen_id)
    return v3


def combine_values(v1, v2):
    """Combine two lists of scalar values preserving order and dropping dups"""
    if not v1 and not v2:
        return []
    seen = set()
    v3 = []
    for item in list(v1 or []) + list(v2 or []):
        if item not in seen:
            v3.append(item)
            seen.add(item)
    return v3


def _is_prioritized(vdr):
    for prop in vdr.get("properties", []) or []:
        if prop.get("name") == "depscan:prioritized" and prop.get("value") == "true":
            return True
    return False


def combine_references(v1, v2):
    if not v1 and not v2:
        return []
    seen_urls = set()
    v3 = []
    for i in v1 + v2:
        url = i.get("url") or f"{i.get('id', '')}.{i.get('source', {}).get('url', '')}"
        if url and url not in seen_urls:
            v3.append(i)
            seen_urls.add(url)
    return v3


def combine_vdrs(v1, v2):
    # Prefer the bom-ref of the prioritized entry so console grouping
    # (include_pkg_group_rows) still attributes the merged entry correctly
    # when only one of two versions was reachable/prioritized. See #504.
    preferred = v2 if _is_prioritized(v2) and not _is_prioritized(v1) else v1
    return {
        "advisories": combine_references(v1.get("advisories", []), v2.get("advisories", [])),
        "affects": combine_affects(v1.get("affects", []), v2.get("affects", [])),
        "analysis": v1.get("analysis", "") or v2.get("analysis", ""),
        "bom-ref": preferred.get("bom-ref"),
        # Issue #519: matched_by was missing here
        "matched_by": preferred.get("matched_by") or v1.get("matched_by") or v2.get("matched_by"),
        "cwes": list(set((v1.get("cwes") or []) + (v2.get("cwes") or []))),
        "detail": v1.get("detail", "") or v2.get("detail", ""),
        "description": v1.get("description", "") or v2.get("description", ""),
        "id": v1.get("id"),
        "properties": combine_generic(
            v1.get("properties", []), v2.get("properties", []), ["name", "value"]
        ),
        "published": choose_date(v1.get("published"), v2.get("published"), "min"),
        "ratings": combine_generic(
            v1.get("ratings", []),
            v2.get("ratings", []),
            ["method", "score", "severity", "vector"],
        ),
        "recommendation": v1.get("recommendation", "") or v2.get("recommendation", ""),
        "references": combine_references(v1.get("references", []), v2.get("references", [])),
        "source": v1.get("source", "") or v2.get("source", ""),
        "updated": choose_date(v1.get("updated"), v2.get("updated"), "max"),
        "p_rich_tree": preferred.get("p_rich_tree")
        or v1.get("p_rich_tree")
        or v2.get("p_rich_tree"),
        "insights": combine_values(v1.get("insights"), v2.get("insights")),
        "purl_prefix": v1.get("purl_prefix") or v2.get("purl_prefix"),
        "fixed_location": v1.get("fixed_location") or v2.get("fixed_location"),
    }


def choose_source(v1, v2):
    if v1.get("name", "") >= v2.get("name", ""):
        return v1
    return v2
