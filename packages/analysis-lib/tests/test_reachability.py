"""Tests for the reachability analyzers.

Covers:
  - R3a (REACHABILITY_EVAL.md Finding 1): atom 2.5.x reachables slices store
    ``tags`` as a comma-separated string on each NODE inside
    ``flow["flows"]``, not at the flow level. The analyzers must split and
    collect those tags so ``reached_services`` and the framework branch of
    ``endpoint_reached_purls`` actually fire.
  - R3b (Finding 2): flows are duplicated across the split slice files.
    Counts (but not the reached SET) must reflect deduplication.
"""

import json

from analysis_lib import ReachabilityAnalysisKV
from analysis_lib.reachability import (
    FrameworkReachability,
    SemanticReachability,
    _flow_identity,
    _flow_service_purls,
    _flow_tags,
    _iter_json_list,
    _iter_unique_reachable_flows,
)


def _write(path, obj):
    with open(path, mode="w", encoding="utf-8") as fp:
        json.dump(obj, fp)
    return path


def _make_options(bom_dir):
    return ReachabilityAnalysisKV(
        project_types=["js"],
        src_dir=bom_dir,
        bom_dir=bom_dir,
    )


# --- _flow_tags unit tests ---------------------------------------------


def test_flow_tags_splits_node_level_comma_string():
    """The atom 2.5.x shape: tags live on each node as a comma string."""
    flow = {
        "flows": [
            {"id": "n1", "tags": "pkg:npm/express@4.22.2, framework, web"},
            {"id": "n2", "tags": "framework-output"},
            {"id": "n3"},  # missing tags key is fine
        ],
        "purls": ["pkg:npm/express@4.22.2"],
    }
    # Order preserved, whitespace stripped, no duplicates, no empty strings.
    assert _flow_tags(flow) == [
        "pkg:npm/express@4.22.2",
        "framework",
        "web",
        "framework-output",
    ]


def test_flow_tags_strips_whitespace_and_skips_blank_entries():
    flow = {"flows": [{"tags": "  web , , api  "}]}
    assert _flow_tags(flow) == ["web", "api"]


def test_flow_tags_handles_empty_string_node_tags():
    flow = {"flows": [{"tags": ""}, {"tags": None}]}
    assert _flow_tags(flow) == []


def test_flow_tags_accepts_list_form_for_future_compat():
    flow = {"flows": [{"tags": ["web", "api"]}, {"tags": "framework"}]}
    assert _flow_tags(flow) == ["web", "api", "framework"]


def test_flow_tags_falls_back_to_flow_level_tags():
    """Older/non-atom envelopes that put tags at the flow level still work."""
    flow = {"tags": "web, api", "flows": []}
    assert _flow_tags(flow) == ["web", "api"]


def test_flow_tags_deduplicates_across_nodes():
    flow = {
        "flows": [
            {"tags": "web"},
            {"tags": "web, api"},
            {"tags": "api"},
        ]
    }
    assert _flow_tags(flow) == ["web", "api"]


def test_flow_tags_safe_on_non_dict_nodes():
    flow = {"flows": [{"tags": "web"}, "junk", None, 42]}
    assert _flow_tags(flow) == ["web"]


# --- _flow_service_purls (R4a: positional purl<->tag association) -----


def test_flow_service_purls_single_purl_with_service_tag():
    """A node whose only purl carries a SERVICE_TAG attributes correctly."""
    flow = {
        "flows": [{"id": "n1", "tags": "pkg:npm/express@4.22.2, framework, web"}],
        "purls": ["pkg:npm/express@4.22.2"],
    }
    assert _flow_service_purls(flow) == {"pkg:npm/express@4.22.2"}


def test_flow_service_purls_does_not_leak_across_purls_in_same_node():
    """R4a regression (the measured bug): the real juice-shop node string
    ``pkg:npm/jsonwebtoken@0.4.0, token, web, pkg:npm/%40codemirror/lang-json@6.0.2``
    must NOT attribute ``web`` to codemirror — the service tags belong to the
    NEAREST preceding purl (jsonwebtoken)."""
    flow = {
        "flows": [
            {
                "id": "n1",
                "tags": "pkg:npm/jsonwebtoken@0.4.0, token, web, pkg:npm/%40codemirror/lang-json@6.0.2",
            }
        ],
        "purls": [
            "pkg:npm/jsonwebtoken@0.4.0",
            "pkg:npm/%40codemirror/lang-json@6.0.2",
        ],
    }
    assert _flow_service_purls(flow) == {"pkg:npm/jsonwebtoken@0.4.0"}


def test_flow_service_purls_express_ipfilter_pattern():
    """R4a: the real pattern
    ``pkg:npm/express-ipfilter@1.4.0, framework, pkg:npm/express@4.22.2, web``
    attributes ``web`` only to express, NOT to express-ipfilter (which only has
    ``framework``)."""
    flow = {
        "flows": [
            {
                "id": "n1",
                "tags": "pkg:npm/express-ipfilter@1.4.0, framework, pkg:npm/express@4.22.2, web",
            }
        ],
        "purls": [
            "pkg:npm/express-ipfilter@1.4.0",
            "pkg:npm/express@4.22.2",
        ],
    }
    assert _flow_service_purls(flow) == {"pkg:npm/express@4.22.2"}


def test_flow_service_purls_node_with_purl_but_no_service_tag():
    """A purl whose own positional tags contain NO SERVICE_TAG is not marked
    service, even if another node in the same flow has one."""
    flow = {
        "flows": [
            {"id": "n1", "tags": "pkg:npm/%40tufjs/models@4.1.0"},
            {"id": "n2", "tags": "pkg:npm/jsonwebtoken@0.4.0, token, web"},
        ],
        "purls": ["pkg:npm/%40tufjs/models@4.1.0", "pkg:npm/jsonwebtoken@0.4.0"],
    }
    # tufjs has NO tags after it -> not service. jsonwebtoken has web -> service.
    assert _flow_service_purls(flow) == {"pkg:npm/jsonwebtoken@0.4.0"}


def test_flow_service_purls_falls_back_to_flow_purls_for_purlless_service_node():
    """A node that carries a SERVICE_TAG but names NO purl falls back to the
    flow-level purls (R3a behavior scoped to that one node)."""
    flow = {
        "flows": [
            {"id": "n1", "tags": "web"},
        ],
        "purls": ["pkg:npm/express@4.22.2", "pkg:npm/lodash@4.17.21"],
    }
    assert _flow_service_purls(flow) == {
        "pkg:npm/express@4.22.2",
        "pkg:npm/lodash@4.17.21",
    }


def test_flow_service_purls_empty_when_no_service_tags():
    """No SERVICE_TAG anywhere -> empty set (mirrors cdxgen eval repo)."""
    flow = {
        "flows": [
            {"id": "n1", "tags": "pkg:npm/semver@7.8.5, framework-input, flow-summary"},
        ],
        "purls": ["pkg:npm/semver@7.8.5"],
    }
    assert _flow_service_purls(flow) == set()


def test_flow_service_purls_flow_level_tags_fallback():
    """Older envelope with a flow-level ``tags`` string applies to all purls."""
    flow = {"tags": "web, api", "flows": [], "purls": ["pkg:npm/x@1", "pkg:npm/y@2"]}
    assert _flow_service_purls(flow) == {"pkg:npm/x@1", "pkg:npm/y@2"}


def test_flow_service_purls_accepts_list_form():
    flow = {
        "flows": [{"id": "n1", "tags": ["pkg:npm/express@4.22.2", "web"]}],
        "purls": ["pkg:npm/express@4.22.2"],
    }
    assert _flow_service_purls(flow) == {"pkg:npm/express@4.22.2"}


def test_flow_service_purls_safe_on_garbage():
    assert _flow_service_purls({"flows": [{"tags": "web"}, "junk", None, 42]}) == set()
    assert _flow_service_purls({}) == set()


# --- SemanticReachability.process end-to-end --------------------------


def test_semantic_reachability_populates_reached_services_from_node_tags(tmp_path):
    """R3a regression: node-level service tags must drive reached_services.

    Mirrors the real atom 2.5.x reachables slice shape. Before R3a the
    analyzer read flow.get("tags") which is always empty, so reached_services
    was always 0 even though the data clearly contained "web" tags.
    """
    # reachables slice: express has a service tag ("web"), lodash does not.
    _write(
        tmp_path / "js-reachables.slices.json",
        [
            {
                "flows": [
                    {"id": "n1", "tags": "pkg:npm/express@4.22.2, framework, web"},
                    {"id": "n2", "tags": "framework-output"},
                ],
                "purls": ["pkg:npm/express@4.22.2"],
            },
            {
                "flows": [
                    {"id": "n3", "tags": "pkg:npm/lodash@4.17.21"},
                ],
                "purls": ["pkg:npm/lodash@4.17.21"],
            },
        ],
    )
    # Minimal BOM so the SemanticReachability setup loop has something to walk.
    _write(
        tmp_path / "bom.cdx.json",
        {
            "components": [
                {
                    "type": "library",
                    "purl": "pkg:npm/express@4.22.2",
                    "evidence": {"occurrences": [{"location": "app.js"}]},
                },
                {
                    "type": "library",
                    "purl": "pkg:npm/lodash@4.17.21",
                    "evidence": {"occurrences": [{"location": "util.js"}]},
                },
            ]
        },
    )

    res = SemanticReachability(_make_options(str(tmp_path))).process()

    assert res.success
    # reached_purls: both packages were observed in the reachables slices.
    assert set((res.reached_purls or {}).keys()) == {
        "pkg:npm/express@4.22.2",
        "pkg:npm/lodash@4.17.21",
    }
    # reached_services: ONLY the flow whose node tags include a SERVICE_TAG.
    assert set((res.reached_services or {}).keys()) == {"pkg:npm/express@4.22.2"}
    assert (res.reached_services or {})["pkg:npm/express@4.22.2"] >= 1


def test_semantic_reachability_no_service_tags_keeps_reached_services_empty(tmp_path):
    """If no node carries a SERVICE_TAG, reached_services stays empty.

    This mirrors the cdxgen eval repo where node tags are present but none are
    in SERVICE_TAGS (e.g. "framework-input", "parse", "flow-summary").
    """
    _write(
        tmp_path / "js-reachables.slices.json",
        [
            {
                "flows": [
                    {"id": "n1", "tags": "framework-input, flow-summary"},
                ],
                "purls": ["pkg:npm/semver@7.8.5"],
            }
        ],
    )
    _write(
        tmp_path / "bom.cdx.json",
        {
            "components": [
                {
                    "type": "library",
                    "purl": "pkg:npm/semver@7.8.5",
                    "evidence": {"occurrences": [{"location": "package.json"}]},
                }
            ]
        },
    )

    res = SemanticReachability(_make_options(str(tmp_path))).process()
    assert set((res.reached_purls or {}).keys()) == {"pkg:npm/semver@7.8.5"}
    assert res.reached_services == {}


def test_semantic_reachability_r4a_no_cross_purl_service_leak(tmp_path):
    """R4a regression: the real juice-shop node string
    ``pkg:npm/jsonwebtoken@0.4.0, token, web, pkg:npm/%40codemirror/lang-json@6.0.2``
    must not leak ``web`` onto codemirror. Both purls are reached, but only
    jsonwebtoken is a service.

    Before R4a, ``_flow_tags`` flattened all node tags and applied them to
    every flow purl, producing false ``reached_services`` entries for
    codemirror/tufjs and 8 others on juice-shop.
    """
    _write(
        tmp_path / "js-reachables.slices.json",
        [
            {
                "flows": [
                    {
                        "id": "n1",
                        "tags": "pkg:npm/jsonwebtoken@0.4.0, token, web, pkg:npm/%40codemirror/lang-json@6.0.2",
                    }
                ],
                "purls": [
                    "pkg:npm/jsonwebtoken@0.4.0",
                    "pkg:npm/%40codemirror/lang-json@6.0.2",
                ],
            }
        ],
    )
    _write(
        tmp_path / "bom.cdx.json",
        {"components": []},
    )
    res = SemanticReachability(_make_options(str(tmp_path))).process()
    # reached_purls: both purls are in the flow.
    assert set((res.reached_purls or {}).keys()) == {
        "pkg:npm/jsonwebtoken@0.4.0",
        "pkg:npm/%40codemirror/lang-json@6.0.2",
    }
    # reached_services: ONLY jsonwebtoken carries a positional SERVICE_TAG.
    assert set((res.reached_services or {}).keys()) == {"pkg:npm/jsonwebtoken@0.4.0"}


def test_framework_reachability_ignores_tags(tmp_path):
    """FrameworkReachability must keep its existing (tag-agnostic) behavior."""
    _write(
        tmp_path / "js-reachables.slices.json",
        [
            {
                "flows": [{"id": "n1", "tags": "pkg:npm/express@4.22.2, web"}],
                "purls": ["pkg:npm/express@4.22.2"],
            }
        ],
    )
    _write(
        tmp_path / "bom.cdx.json",
        {"components": []},
    )

    res = FrameworkReachability(_make_options(str(tmp_path))).process()
    assert set((res.reached_purls or {}).keys()) == {"pkg:npm/express@4.22.2"}
    # FrameworkReachability does not return a services dict at all.
    assert res.reached_services is None or res.reached_services == {}


# --- _track_usage_targets shape tolerance (AppThreat/atom#221) --------


def test_track_usage_targets_list_lines():
    """The classic shape: per-file value is a list of line numbers."""
    usage_targets = {}
    SemanticReachability._track_usage_targets(usage_targets, {"GET /x": {"Foo.java": [10, 20]}})
    assert usage_targets == {"Foo.java": True, "Foo.java#10": True, "Foo.java#20": True}


def test_track_usage_targets_int_line_does_not_crash():
    """Newer atom slices may emit a bare int for the lines value. This must
    not raise ``TypeError: 'int' object is not iterable`` (dep-scan#459)."""
    usage_targets = {}
    SemanticReachability._track_usage_targets(usage_targets, {"GET /x": {"Foo.java": 42}})
    assert usage_targets == {"Foo.java": True, "Foo.java#42": True}


def test_track_usage_targets_ignores_non_dict_values():
    """Garbage shapes are skipped rather than crashing."""
    usage_targets = {}
    SemanticReachability._track_usage_targets(usage_targets, {"GET /x": ["not", "a", "dict"]})
    SemanticReachability._track_usage_targets(usage_targets, "not a dict")
    assert usage_targets == {}


# --- R3b: cross-file dedup --------------------------------------------


def test_flow_identity_is_stable_across_dict_order():
    """Two flows with identical content hash equal regardless of key order."""
    a = {"purls": ["pkg:npm/x@1"], "flows": [{"id": "n1", "tags": "web"}]}
    # Same content, different insertion order of top-level keys.
    b = {"flows": [{"id": "n1", "tags": "web"}], "purls": ["pkg:npm/x@1"]}
    assert _flow_identity(a) == _flow_identity(b)


def test_flow_identity_differs_when_content_differs():
    a = {"purls": ["pkg:npm/x@1"], "flows": [{"id": "n1", "tags": "web"}]}
    b = {"purls": ["pkg:npm/x@1"], "flows": [{"id": "n1", "tags": "api"}]}
    assert _flow_identity(a) != _flow_identity(b)


def test_reachability_dedups_flows_across_split_slice_files(tmp_path):
    """R3b regression: a flow that appears in both the unsplit slices.json and
    a numbered split must count ONCE per purl, not twice.

    The unsplit slices.json is NOT simply a prefix of the splits (14-33%
    disjoint), so we must keep reading every file. But identical flows must
    not inflate reached_purls[purl] += 1.
    """
    # A flow that will appear in BOTH files (verbatim duplicate).
    dup_flow = {
        "flows": [{"id": "n1", "tags": "pkg:npm/express@4.22.2, web"}],
        "purls": ["pkg:npm/express@4.22.2"],
    }
    # A flow that only appears in the unsplit file.
    only_main = {
        "flows": [{"id": "n2", "tags": "pkg:npm/lodash@4.17.21"}],
        "purls": ["pkg:npm/lodash@4.17.21"],
    }
    # A flow that only appears in the numbered split.
    only_split = {
        "flows": [{"id": "n3", "tags": "pkg:npm/semver@7.8.5"}],
        "purls": ["pkg:npm/semver@7.8.5"],
    }
    _write(
        tmp_path / "js-reachables.slices.json",
        [dup_flow, only_main],
    )
    _write(
        tmp_path / "js-reachables.slices_1.json",
        [dup_flow, only_split],
    )
    _write(
        tmp_path / "bom.cdx.json",
        {"components": []},
    )

    res = FrameworkReachability(_make_options(str(tmp_path))).process()
    # Set is preserved: all three purls reached.
    assert set((res.reached_purls or {}).keys()) == {
        "pkg:npm/express@4.22.2",
        "pkg:npm/lodash@4.17.21",
        "pkg:npm/semver@7.8.5",
    }
    # Counts reflect dedup: each purl counted exactly once, even though
    # `express` appeared in two files.
    assert (res.reached_purls or {})["pkg:npm/express@4.22.2"] == 1
    assert (res.reached_purls or {})["pkg:npm/lodash@4.17.21"] == 1
    assert (res.reached_purls or {})["pkg:npm/semver@7.8.5"] == 1


def test_semantic_reachability_dedups_service_counts(tmp_path):
    """R3b regression for SemanticReachability: reached_services[apurl] must
    not be double-counted when a service-tagged flow is duplicated across
    files."""
    dup_flow = {
        "flows": [{"id": "n1", "tags": "pkg:npm/express@4.22.2, web"}],
        "purls": ["pkg:npm/express@4.22.2"],
    }
    _write(tmp_path / "js-reachables.slices.json", [dup_flow])
    _write(tmp_path / "js-reachables.slices_1.json", [dup_flow])
    _write(tmp_path / "bom.cdx.json", {"components": []})

    res = SemanticReachability(_make_options(str(tmp_path))).process()
    assert set((res.reached_services or {}).keys()) == {"pkg:npm/express@4.22.2"}
    # Counted exactly once despite the cross-file duplicate.
    assert (res.reached_services or {})["pkg:npm/express@4.22.2"] == 1
    assert (res.reached_purls or {})["pkg:npm/express@4.22.2"] == 1


def test_reachability_dedup_treats_distinct_flows_separately(tmp_path):
    """R3b negative case: two flows with the same purls but different node
    tags are distinct evidence trails and must each count once.
    """
    _write(
        tmp_path / "js-reachables.slices.json",
        [
            {
                "flows": [{"id": "n1", "tags": "web"}],
                "purls": ["pkg:npm/express@4.22.2"],
            },
            {
                "flows": [{"id": "n2", "tags": "api"}],
                "purls": ["pkg:npm/express@4.22.2"],
            },
        ],
    )
    _write(tmp_path / "bom.cdx.json", {"components": []})
    res = FrameworkReachability(_make_options(str(tmp_path))).process()
    assert (res.reached_purls or {})["pkg:npm/express@4.22.2"] == 2


# --- R3c: streaming JSON parser ---------------------------------------


def _write_raw(path, text):
    with open(path, mode="w", encoding="utf-8") as fp:
        fp.write(text)
    return path


def test_iter_json_list_yields_each_element():
    """A top-level JSON list is streamed one parsed element at a time."""
    text = '[{"id": 1}, {"id": 2}, {"id": 3}]'
    assert list(_iter_json_list(_write_raw("/tmp/_r3c_test_1.json", text))) == [
        {"id": 1},
        {"id": 2},
        {"id": 3},
    ]


def test_iter_json_list_tolerates_whitespace_between_elements():
    text = '[\n  {"a": 1},\n  {"b": 2},\n\n  {"c": 3}\n]'
    out = list(_iter_json_list(_write_raw("/tmp/_r3c_test_2.json", text)))
    assert out == [{"a": 1}, {"b": 2}, {"c": 3}]


def test_iter_json_list_empty_list_yields_nothing():
    assert list(_iter_json_list(_write_raw("/tmp/_r3c_test_3.json", "[]"))) == []
    # With whitespace
    assert list(_iter_json_list(_write_raw("/tmp/_r3c_test_4.json", "[  ]"))) == []


def test_iter_json_list_handles_nested_objects_and_strings_with_commas():
    """Commas inside strings or nested objects must not break element scan."""
    text = '[{"tags": "a, b, c", "nested": {"x": 1, "y": [1, 2, 3]}}, {"id": 2}]'
    out = list(_iter_json_list(_write_raw("/tmp/_r3c_test_5.json", text)))
    assert out == [
        {"tags": "a, b, c", "nested": {"x": 1, "y": [1, 2, 3]}},
        {"id": 2},
    ]


def test_iter_json_list_returns_nothing_for_non_list_top_level(tmp_path):
    """A wrapped envelope (e.g. {"reachables": [...]}) is not streamed by
    _iter_json_list; the caller falls back to json_load for that shape."""
    f = tmp_path / "wrapped.json"
    _write_raw(f, '{"reachables": [{"id": 1}]}')
    assert list(_iter_json_list(str(f))) == []


def test_iter_json_list_missing_file_yields_nothing():
    assert list(_iter_json_list("/nonexistent/path/to/file.json")) == []


def test_iter_json_list_matches_json_load_on_real_slices(tmp_path):
    """Streaming parser must produce identical elements to json.load on a
    realistic reachables slice (atom 2.5.x shape)."""
    payload = [
        {
            "flows": [
                {
                    "id": f"node-{i}-a",
                    "tags": f"pkg:npm/express@4.22.2, framework, web, marker-{i}",
                    "code": "function() { return arg + 1; }",
                    "signature": "L: int -> int",
                    "fullName": f"module.fn{i}a",
                    "lineNumber": i * 10,
                    "columnNumber": i,
                },
                {
                    "id": f"node-{i}-b",
                    "tags": "framework-output",
                    "code": "return value;",
                },
            ],
            "purls": ["pkg:npm/express@4.22.2", f"pkg:npm/pkg{i}@1.{i}.0"],
        }
        for i in range(50)
    ]
    f = tmp_path / "js-reachables.slices.json"
    _write(f, payload)
    streamed = list(_iter_json_list(str(f)))
    import json as _json

    with open(f) as fp:
        loaded = _json.load(fp)
    assert streamed == loaded


def test_iter_unique_reachable_flows_streams_lazy(tmp_path):
    """The unique-flow iterator must work when the file is a bare JSON list
    (R3c streaming path) and produce the same dedup behavior as the legacy
    json_load path."""
    dup = {
        "flows": [{"id": "n1", "tags": "web"}],
        "purls": ["pkg:npm/express@4.22.2"],
    }
    other = {
        "flows": [{"id": "n2", "tags": "api"}],
        "purls": ["pkg:npm/lodash@4.17.21"],
    }
    main_file = tmp_path / "js-reachables.slices.json"
    split_file = tmp_path / "js-reachables.slices_1.json"
    _write(main_file, [dup, other])
    _write(split_file, [dup])
    # Single file: two unique flows.
    flows = list(_iter_unique_reachable_flows([str(main_file)]))
    assert len(flows) == 2
    # Cross-file dedup: the dup is only yielded once.
    flows2 = list(_iter_unique_reachable_flows([str(main_file), str(split_file)]))
    assert len(flows2) == 2
