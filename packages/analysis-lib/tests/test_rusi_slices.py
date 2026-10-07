"""Unit tests for the rusi -> atom-slice converter and purl reconciler.

The reconciler is the single most important correctness detail in the rusi
integration (see rusi-reachability-plan.md §2.2). These tests lock down:

  - unversioned rusi ``pkg:cargo/sqlx`` -> BOM versioned ``pkg:cargo/sqlx@0.6.2``
  - versioned workspace purls pass through via name match
  - stdlib/pseudo purls (``pkg:cargo/fs``, ``std``, ``core`` ...) are dropped
  - ``-`` vs ``_`` normalization (cargo manifest vs rust module path)
  - the emitted slice JSON is atom-shaped and deterministic (golden file)
"""

import json
from pathlib import Path

import pytest

from analysis_lib import ReachabilityAnalysisKV
from analysis_lib.config import SERVICE_TAGS
from analysis_lib.reachability import FrameworkReachability, SemanticReachability
from analysis_lib.reachability import _flow_service_purls
from analysis_lib.rusi_slices import (
    RUST_STDLIB_PSEUDO_CRATES,
    RUSI_ENDPOINT_SERVICE_TAG,
    build_bom_purl_index,
    convert_rusi_report,
    is_rusi_report,
    reconcile_purl,
    reconcile_purls,
    write_slices_file,
)


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def _cargo_bom_components():
    """A minimal Cargo BOM component list mirroring cdxgen output."""
    return [
        {
            "type": "application",
            "name": "vulnerable-web-app",
            "version": "0.1.0",
            "purl": "pkg:cargo/vulnerable-web-app@0.1.0",
            "bom-ref": "pkg:cargo/vulnerable-web-app@0.1.0",
        },
        {
            "type": "library",
            "name": "sqlx",
            "version": "0.6.2",
            "purl": "pkg:cargo/sqlx@0.6.2",
            "bom-ref": "pkg:cargo/sqlx@0.6.2",
        },
        {
            "type": "library",
            "name": "warp",
            "version": "0.3.6",
            "purl": "pkg:cargo/warp@0.3.6",
            "bom-ref": "pkg:cargo/warp@0.3.6",
        },
        {
            "type": "library",
            "name": "reqwest",
            "version": "0.11.27",
            "purl": "pkg:cargo/reqwest@0.11.27",
            "bom-ref": "pkg:cargo/reqwest@0.11.27",
        },
    ]


@pytest.fixture
def bom_index():
    return build_bom_purl_index(_cargo_bom_components())


# ---------------------------------------------------------------------------
# reconciler
# ---------------------------------------------------------------------------


def test_reconcile_unversioned_external_maps_to_bom_versioned(bom_index):
    """THE critical assertion: rusi ``pkg:cargo/sqlx`` -> BOM versioned purl."""
    assert reconcile_purl("pkg:cargo/sqlx", bom_index) == "pkg:cargo/sqlx@0.6.2"
    assert reconcile_purl("pkg:cargo/warp", bom_index) == "pkg:cargo/warp@0.3.6"
    assert reconcile_purl("pkg:cargo/reqwest", bom_index) == "pkg:cargo/reqwest@0.11.27"


def test_reconcile_versioned_workspace_maps_to_bom(bom_index):
    assert (
        reconcile_purl("pkg:cargo/vulnerable-web-app@0.1.0", bom_index)
        == "pkg:cargo/vulnerable-web-app@0.1.0"
    )


def test_reconcile_versioned_external_overwrites_to_bom_version(bom_index):
    """Even if rusi emitted a (wrong) version, the BOM version wins by name."""
    assert reconcile_purl("pkg:cargo/sqlx@9.9.9", bom_index) == "pkg:cargo/sqlx@0.6.2"


def test_reconcile_stdlib_pseudo_dropped(bom_index):
    """stdlib / pseudo crates are dropped unconditionally."""
    for pseudo in ("pkg:cargo/fs", "pkg:cargo/std", "pkg:cargo/core", "pkg:cargo/alloc"):
        assert reconcile_purl(pseudo, bom_index) is None


def test_reconcile_unknown_external_dropped(bom_index):
    """A rusi external crate NOT in the BOM cannot match -> drop (no noise)."""
    assert reconcile_purl("pkg:cargo/nonexistent-crate", bom_index) is None


def test_reconcile_non_cargo_purl_dropped(bom_index):
    assert reconcile_purl("pkg:npm/express@4.22.2", bom_index) is None
    assert reconcile_purl("not-a-purl", bom_index) is None
    assert reconcile_purl("", bom_index) is None
    assert reconcile_purl(None, bom_index) is None


def test_reconcile_dash_underscore_normalization():
    """Cargo ``-`` in manifest == ``_`` in rust code; rusi indexes both.

    A BOM component ``vulnerable-web-app`` must match a rusi purl that uses
    the module-path form ``vulnerable_web_app``.
    """
    idx = build_bom_purl_index(
        [{"purl": "pkg:cargo/vulnerable-web-app@0.1.0", "name": "vulnerable-web-app"}]
    )
    assert reconcile_purl("pkg:cargo/vulnerable_web_app@0.1.0", idx) == (
        "pkg:cargo/vulnerable-web-app@0.1.0"
    )
    # and the reverse direction
    idx2 = build_bom_purl_index([{"purl": "pkg:cargo/some_lib@1.0.0", "name": "some_lib"}])
    assert reconcile_purl("pkg:cargo/some-lib", idx2) == "pkg:cargo/some_lib@1.0.0"


def test_reconcile_is_case_insensitive():
    idx = build_bom_purl_index([{"purl": "pkg:cargo/SQLx@0.6.2", "name": "SQLx"}])
    assert reconcile_purl("pkg:cargo/sqlx", idx) == "pkg:cargo/SQLx@0.6.2"


def test_reconcile_handles_percent_encoding():
    """purl names with reserved chars are percent-encoded; decode before match."""
    idx = build_bom_purl_index([{"purl": "pkg:cargo/foo-bar@1.0.0"}])
    # rusi would never percent-encode a plain cargo name, but ensure decode
    # does not corrupt a normal name
    assert reconcile_purl("pkg:cargo/foo-bar", idx) == "pkg:cargo/foo-bar@1.0.0"


def test_reconcile_purls_dedupes_and_sorts(bom_index):
    out = reconcile_purls(
        ["pkg:cargo/sqlx", "pkg:cargo/fs", "pkg:cargo/sqlx", "pkg:cargo/warp"],
        bom_index,
    )
    assert out == ["pkg:cargo/sqlx@0.6.2", "pkg:cargo/warp@0.3.6"]


def test_build_bom_index_ignores_non_cargo_components():
    idx = build_bom_purl_index(
        [
            {"purl": "pkg:cargo/keep@1.0.0", "name": "keep"},
            {"purl": "pkg:npm/skip@2.0.0", "name": "skip"},
            {"purl": "", "name": "orphan", "bom-ref": "pkg:cargo/orphan@0.1.0"},
        ]
    )
    assert "keep" in idx
    assert "skip" not in idx
    # orphan has no purl but its bom-ref reveals cargo -- indexed by name
    assert "orphan" in idx


def test_stdlib_pseudo_set_contains_expected_entries():
    for name in ("std", "core", "alloc", "fs"):
        assert name in RUST_STDLIB_PSEUDO_CRATES


# ---------------------------------------------------------------------------
# converter: golden slice JSON (real-shape rusi report, synthetic BOM)
# ---------------------------------------------------------------------------


def _rusi_report_fixture():
    """A trimmed-but-faithful rusi report based on the real
    fixtures/vulnerable-web-app output (schema_version, call_graph, data_flow).

    Critical realism points captured here:
      - workspace package emits a versioned purl; external crates emit
        UNVERSIONED purls (sqlx/warp/reqwest) and a pseudo ``pkg:cargo/fs``.
      - the dataflow slice that sinks into sqlx::query only carries the
        WORKSPACE purl in its own purls list; the external crate attribution
        must come from matching the node name ``sqlx::query`` against the
        call-graph external symbol index.
    """
    return {
        "schema_version": "https://appthreat.github.io/rusi/schema/report-0.1",
        "tool": {"name": "rusi", "version": "2.5.2"},
        "packages": [
            {
                "name": "vulnerable-web-app",
                "package_path": "vulnerable_web_app",
                "purl": "pkg:cargo/vulnerable-web-app@0.1.0",
            }
        ],
        "call_graph": {
            "mode": "static",
            "nodes": [
                {
                    "id": "cg-sqlx",
                    "name": "query",
                    "qualified_name": "sqlx::query",
                    "kind": "external-function",
                    "package_path": "sqlx",
                    "purl": "pkg:cargo/sqlx",
                    "external": True,
                    "position": {"filename": "src/main.rs", "line": 11, "column": 13},
                },
                {
                    "id": "cg-warp",
                    "name": "param",
                    "qualified_name": "warp::path::param",
                    "package_path": "warp",
                    "purl": "pkg:cargo/warp",
                    "external": True,
                    "position": {"filename": "src/main.rs", "line": 13, "column": 17},
                },
                {
                    "id": "cg-fs",
                    "name": "read_to_string",
                    "qualified_name": "fs::read_to_string",
                    "package_path": "fs",
                    "purl": "pkg:cargo/fs",
                    "external": True,
                    "position": {"filename": "src/main.rs", "line": 9, "column": 18},
                },
                {
                    "id": "cg-reqwest",
                    "name": "new",
                    "qualified_name": "reqwest::Client::new",
                    "package_path": "reqwest",
                    "purl": "pkg:cargo/reqwest",
                    "external": True,
                    "position": {"filename": "src/main.rs", "line": 14, "column": 17},
                },
                {
                    "id": "decl-main",
                    "name": "main",
                    "qualified_name": "vulnerable_web_app::main",
                    "package_path": "vulnerable_web_app",
                    "purl": "pkg:cargo/vulnerable-web-app@0.1.0",
                    "external": False,
                    "position": {"filename": "src/main.rs", "line": 7, "column": 0},
                },
            ],
            "edges": [
                {
                    "id": "e1",
                    "source_id": "decl-main",
                    "target_id": "cg-sqlx",
                    "source_name": "vulnerable_web_app::main",
                    "target_name": "sqlx::query",
                    "purls": ["pkg:cargo/vulnerable-web-app@0.1.0", "pkg:cargo/sqlx"],
                    "call_type": "external",
                    "position": {"filename": "src/main.rs", "line": 11, "column": 13},
                },
                {
                    "id": "e2",
                    "source_id": "decl-main",
                    "target_id": "cg-warp",
                    "source_name": "vulnerable_web_app::main",
                    "target_name": "warp::path::param",
                    "purls": ["pkg:cargo/vulnerable-web-app@0.1.0", "pkg:cargo/warp"],
                    "call_type": "external",
                    "position": {"filename": "src/main.rs", "line": 13, "column": 17},
                },
                {
                    "id": "e3",
                    "source_id": "decl-main",
                    "target_id": "cg-fs",
                    "source_name": "vulnerable_web_app::main",
                    "target_name": "fs::read_to_string",
                    "purls": ["pkg:cargo/vulnerable-web-app@0.1.0", "pkg:cargo/fs"],
                    "call_type": "external",
                    "position": {"filename": "src/main.rs", "line": 9, "column": 18},
                },
                {
                    "id": "e4",
                    "source_id": "decl-main",
                    "target_id": "cg-reqwest",
                    "source_name": "vulnerable_web_app::main",
                    "target_name": "reqwest::Client::new",
                    "purls": ["pkg:cargo/vulnerable-web-app@0.1.0", "pkg:cargo/reqwest"],
                    "call_type": "external",
                    "position": {"filename": "src/main.rs", "line": 14, "column": 17},
                },
            ],
        },
        "data_flow": {
            "mode": "security",
            "nodes": [
                {
                    "id": "df-source",
                    "name": "fs::read_to_string",
                    "function": "vulnerable_web_app::main",
                    "purl": "pkg:cargo/vulnerable-web-app@0.1.0",
                    "category": "file",
                    "position": {"filename": "src/main.rs", "line": 9, "column": 18},
                },
                {
                    "id": "df-sqlx",
                    "name": "sqlx::query",
                    "function": "vulnerable_web_app::main",
                    "purl": "pkg:cargo/vulnerable-web-app@0.1.0",
                    "category": "",
                    "position": {"filename": "src/main.rs", "line": 11, "column": 13},
                },
                {
                    "id": "df-sink",
                    "name": "fetch_one",
                    "function": "vulnerable_web_app::main",
                    "purl": "pkg:cargo/vulnerable-web-app@0.1.0",
                    "category": "sql-query",
                    "position": {"filename": "src/main.rs", "line": 11, "column": 13},
                },
            ],
            "slices": [
                {
                    "id": "slice-1",
                    "source_id": "df-source",
                    "sink_id": "df-sink",
                    "source_name": "fs::read_to_string",
                    "sink_name": "fetch_one",
                    "source_function": "vulnerable_web_app::main",
                    "sink_function": "vulnerable_web_app::main",
                    "sourcePurl": "pkg:cargo/vulnerable-web-app@0.1.0",
                    "targetPurl": "pkg:cargo/vulnerable-web-app@0.1.0",
                    "purls": ["pkg:cargo/vulnerable-web-app@0.1.0"],
                    "source_category": "file",
                    "sink_category": "sql-query",
                    "node_ids": ["df-source", "df-sqlx", "df-sink"],
                    "rule_name": "file-to-sql-query",
                    "description": "file data can flow from fs::read_to_string to fetch_one",
                }
            ],
        },
    }


def test_converter_emits_atom_shape(bom_index):
    flows = convert_rusi_report(_rusi_report_fixture(), bom_index)
    assert isinstance(flows, list)
    assert all(isinstance(f, dict) for f in flows)
    for f in flows:
        assert "flows" in f and isinstance(f["flows"], list)
        assert "purls" in f and isinstance(f["purls"], list)
        for node in f["flows"]:
            assert "id" in node and "tags" in node


def test_converter_dataflow_slice_picks_up_external_sqlx_via_call_graph(bom_index):
    """The slice's own purls only carry the workspace purl; the external
    ``sqlx`` crate must be attributed via the call-graph symbol index so the
    reconciled versioned ``pkg:cargo/sqlx@0.6.2`` ends up on the flow.
    """
    flows = convert_rusi_report(_rusi_report_fixture(), bom_index)
    slice_flows = [
        f for f in flows if any("file-to-sql-query" in n.get("tags", "") for n in f["flows"])
    ]
    assert slice_flows, "dataflow slice flow must be emitted"
    all_slice_purls = set()
    for f in slice_flows:
        all_slice_purls.update(f["purls"])
    assert "pkg:cargo/sqlx@0.6.2" in all_slice_purls, (
        "sqlx must be reconciled onto the slice flow (this is the integration crux)"
    )
    assert "pkg:cargo/vulnerable-web-app@0.1.0" in all_slice_purls


def test_converter_emits_call_graph_flows_for_all_externals(bom_index):
    """Every external crate in the BOM that rusi observed a call to gets its
    own call-graph flow (pure-call reachability, not just taint)."""
    flows = convert_rusi_report(_rusi_report_fixture(), bom_index)
    reached = set()
    for f in flows:
        reached.update(f["purls"])
    assert {"pkg:cargo/sqlx@0.6.2", "pkg:cargo/warp@0.3.6", "pkg:cargo/reqwest@0.11.27"} <= reached


def test_converter_drops_stdlib_fs(bom_index):
    """``pkg:cargo/fs`` must never appear in any emitted flow purl."""
    flows = convert_rusi_report(_rusi_report_fixture(), bom_index)
    for f in flows:
        for p in f["purls"]:
            assert not p.startswith("pkg:cargo/fs"), "stdlib fs leaked into output"


def test_converter_is_deterministic(bom_index):
    """Two conversions of the same report produce byte-identical output."""
    a = convert_rusi_report(_rusi_report_fixture(), bom_index)
    b = convert_rusi_report(_rusi_report_fixture(), bom_index)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_converter_golden_file(tmp_path, bom_index):
    """Golden-file the emitted slice JSON so future changes are reviewable."""
    flows = convert_rusi_report(_rusi_report_fixture(), bom_index)
    out_file = tmp_path / "rust-reachables.slices.json"
    write_slices_file(str(out_file), flows)
    assert out_file.exists()
    loaded = json.loads(out_file.read_text())
    assert loaded == flows
    # the file is a top-level JSON array (atom shape consumed by the engine)
    assert isinstance(loaded, list)
    assert len(loaded) >= 4  # 1 dataflow slice + >=3 call-graph external flows

    # golden snapshot -- update deliberately
    golden_dir = Path(__file__).parent / "data" / "rusi"
    golden_dir.mkdir(parents=True, exist_ok=True)
    golden_file = golden_dir / "vulnerable-web-app.golden.json"
    if not golden_file.exists():
        golden_file.write_text(json.dumps(loaded, sort_keys=True, indent=2), encoding="utf-8")
    else:
        golden = json.loads(golden_file.read_text())
        assert loaded == golden, (
            f"rusi slice output changed; if intentional, delete {golden_file} "
            "and re-run to regenerate."
        )


def test_converter_handles_empty_report(bom_index):
    assert convert_rusi_report({}, bom_index) == []
    assert convert_rusi_report({"call_graph": None, "data_flow": None}, bom_index) == []


def test_converter_handles_missing_dataflow_but_callgraph_present(bom_index):
    """A repo with calls but no taint slices still emits call-graph flows."""
    report = _rusi_report_fixture()
    report["data_flow"]["slices"] = []
    flows = convert_rusi_report(report, bom_index)
    reached = set()
    for f in flows:
        reached.update(f["purls"])
    assert "pkg:cargo/sqlx@0.6.2" in reached


def test_is_rusi_report_detects_by_shape():
    """Detection is structural: producer (tool/runtime) + section
    (call_graph/data_flow). It must NOT depend on schema_version at all, so a
    schema bump or a missing schema_version field still recognises the report."""
    # full report (tool + call_graph + data_flow)
    assert is_rusi_report({"tool": {"name": "rusi"}, "call_graph": {"nodes": []}, "data_flow": {}})
    # runtime alone is a valid producer signal
    assert is_rusi_report({"runtime": {"rustc_version": "1.75"}, "data_flow": {"slices": []}})
    # call_graph alone (no data_flow) is still enough
    assert is_rusi_report({"tool": {"name": "rusi"}, "call_graph": {"nodes": []}})
    # schema_version is irrelevant to detection (even a bogus/missing one)
    assert is_rusi_report(
        {"tool": {"name": "rusi"}, "call_graph": {}, "schema_version": "anything"}
    )
    assert is_rusi_report({"tool": {}, "data_flow": {}})


def test_is_rusi_report_rejects_non_rusi_shapes():
    """An atom semantics slice or arbitrary JSON sharing the path must NOT be
    mistaken for a rusi report -- this is the disambiguation that lets depscan
    consume cdxgen's persisted report at ``<type>-semantics.slices.json``."""
    # no producer identity
    assert not is_rusi_report({"call_graph": {"nodes": []}, "data_flow": {}})
    # no analysis section
    assert not is_rusi_report({"tool": {"name": "rusi"}, "runtime": {}})
    # atom-style semantics slice (list / frames) -- wrong shape entirely
    assert not is_rusi_report([{"flows": [], "purls": []}])
    assert not is_rusi_report({"frames": [], "data flows": []})
    # empty / wrong type
    assert not is_rusi_report({})
    assert not is_rusi_report(None)
    assert not is_rusi_report("not-a-report")
    # schema_version alone (previously the signal) is no longer sufficient
    assert not is_rusi_report(
        {"schema_version": "https://appthreat.github.io/rusi/schema/report-0.1"}
    )


# ---------------------------------------------------------------------------
# end-to-end through FrameworkReachability (no rusi binary required)
# ---------------------------------------------------------------------------


def test_slice_feeds_into_framework_reachability(tmp_path, bom_index):
    """The emitted slice + Cargo BOM, when read by FrameworkReachability,
    must mark sqlx/warp/reqwest as reached. This proves the integration works
    without touching the reachability engine.
    """
    flows = convert_rusi_report(_rusi_report_fixture(), bom_index)
    slices_path = tmp_path / "rust-reachables.slices.json"
    slices_path.write_text(json.dumps(flows), encoding="utf-8")

    bom_path = tmp_path / "bom.cdx.json"
    bom_path.write_text(json.dumps({"components": _cargo_bom_components()}), encoding="utf-8")

    opts = ReachabilityAnalysisKV(
        project_types=["rust"],
        src_dir=str(tmp_path),
        bom_dir=str(tmp_path),
    )
    res = FrameworkReachability(opts).process()
    assert res.success
    reached = set((res.reached_purls or {}).keys())
    assert "pkg:cargo/sqlx@0.6.2" in reached
    assert "pkg:cargo/warp@0.3.6" in reached
    assert "pkg:cargo/reqwest@0.11.27" in reached
    # the workspace app is also reached (its own functions are on the path)
    assert "pkg:cargo/vulnerable-web-app@0.1.0" in reached


# ---------------------------------------------------------------------------
# phase 2: SemanticReachability enrichment (reached_services + endpoints)
# ---------------------------------------------------------------------------


def test_dataflow_slice_attributes_service_to_dependency_purl(bom_index):
    """The sql-query sink service tag MUST land on the sqlx dependency purl
    (via its OWN external-symbol node), not just the workspace app. This is
    the positional-association guarantee that makes ``reached_services``
    attribute the service to the right crate.
    """
    flows = convert_rusi_report(_rusi_report_fixture(), bom_index)
    slice_flows = [
        f for f in flows if any("file-to-sql-query" in n.get("tags", "") for n in f["flows"])
    ]
    assert slice_flows, "dataflow slice flow must be emitted"
    service_purls: set = set()
    for f in slice_flows:
        service_purls |= _flow_service_purls(f)
    assert "pkg:cargo/sqlx@0.6.2" in service_purls, (
        "sql service must be positionally attributed to sqlx, the dependency"
    )


def _endpoint_report_fixture():
    """A rusi report with ``api_endpoints[]`` (axum handler) + a call-graph edge
    to the axum framework crate, mirroring the real api-discovery-app output.
    """
    return {
        "schema_version": "https://appthreat.github.io/rusi/schema/report-0.1",
        "tool": {"name": "rusi", "version": "2.5.2"},
        "packages": [
            {
                "name": "endpoint-app",
                "package_path": "endpoint_app",
                "purl": "pkg:cargo/endpoint-app@0.1.0",
            }
        ],
        "call_graph": {
            "nodes": [
                {
                    "id": "cg-axum-router",
                    "name": "router",
                    "qualified_name": "axum::Router::route",
                    "kind": "external-function",
                    "package_path": "axum",
                    "purl": "pkg:cargo/axum",
                    "external": True,
                    "position": {"filename": "src/main.rs", "line": 10, "column": 5},
                },
                {
                    "id": "decl-main",
                    "name": "main",
                    "qualified_name": "endpoint_app::main",
                    "package_path": "endpoint_app",
                    "purl": "pkg:cargo/endpoint-app@0.1.0",
                    "external": False,
                    "position": {"filename": "src/main.rs", "line": 5, "column": 0},
                },
            ],
            "edges": [
                {
                    "id": "e1",
                    "source_id": "decl-main",
                    "target_id": "cg-axum-router",
                    "source_name": "endpoint_app::main",
                    "target_name": "axum::Router::route",
                    "purls": ["pkg:cargo/endpoint-app@0.1.0", "pkg:cargo/axum"],
                    "call_type": "external",
                    "position": {"filename": "src/main.rs", "line": 10, "column": 5},
                }
            ],
        },
        "data_flow": {"nodes": [], "edges": [], "slices": []},
        "api_endpoints": [
            {
                "id": "ep-1",
                "method": "POST",
                "path": "/api/v1/users",
                "framework": "axum",
                "handler": "endpoint_app::create_user",
                "package_path": "endpoint_app",
                "purl": "pkg:cargo/axum",
                "file_path": "src/main.rs",
                "position": {"filename": "src/main.rs", "line": 10, "column": 5},
            }
        ],
    }


def _endpoint_bom_components():
    return [
        {
            "type": "application",
            "name": "endpoint-app",
            "version": "0.1.0",
            "purl": "pkg:cargo/endpoint-app@0.1.0",
            "bom-ref": "pkg:cargo/endpoint-app@0.1.0",
        },
        # axum typed as ``framework`` so SemanticReachability lights up
        # endpoint_reached_purls for it.
        {
            "type": "framework",
            "name": "axum",
            "version": "0.7.5",
            "purl": "pkg:cargo/axum@0.7.5",
            "bom-ref": "pkg:cargo/axum@0.7.5",
        },
    ]


def test_converter_emits_endpoint_flow_with_framework_purl():
    """Each api_endpoint becomes a flow whose purls carry the framework crate
    (reconciled onto the BOM version) and the handler's home crate."""
    idx = build_bom_purl_index(_endpoint_bom_components())
    flows = convert_rusi_report(_endpoint_report_fixture(), idx)
    ep_flows = [f for f in flows if any("endpoint" in n.get("tags", "") for n in f["flows"])]
    assert ep_flows, "an endpoint flow must be emitted for api_endpoints[]"
    reached: set = set()
    for f in ep_flows:
        reached.update(f["purls"])
    assert "pkg:cargo/axum@0.7.5" in reached, "framework crate must be on the endpoint flow"
    assert "pkg:cargo/endpoint-app@0.1.0" in reached, "handler home crate must be reached"


def test_converter_endpoint_node_carries_api_service_tag():
    """The endpoint framework node is tagged with the ``api`` service tag
    immediately after the framework purl so the service is positionally
    attributed to the framework crate."""
    assert RUSI_ENDPOINT_SERVICE_TAG in SERVICE_TAGS
    idx = build_bom_purl_index(_endpoint_bom_components())
    flows = convert_rusi_report(_endpoint_report_fixture(), idx)
    ep_nodes = [n for f in flows for n in f["flows"] if n.get("code") == "POST /api/v1/users"]
    assert ep_nodes, "endpoint node must be emitted"
    tags = ep_nodes[0]["tags"]
    pieces = [p.strip() for p in tags.split(",")]
    # purl immediately followed by the api service tag
    assert "pkg:cargo/axum@0.7.5" in pieces
    api_idx = pieces.index("pkg:cargo/axum@0.7.5")
    assert pieces[api_idx + 1] == RUSI_ENDPOINT_SERVICE_TAG


def test_semantic_reachability_lights_up_services_and_endpoints(tmp_path):
    """End-to-end through SemanticReachability: the dataflow slice populates
    ``reached_services`` for sqlx, and the endpoint flow populates
    ``endpoint_reached_purls`` for the framework crate. Phase 1 only proved up
    to reached_purls; this proves the phase-2 enrichment reaches the engine.
    """
    # --- sqlx dataflow fixture: reached_services ---
    sqlx_flows = convert_rusi_report(
        _rusi_report_fixture(), build_bom_purl_index(_cargo_bom_components())
    )
    (tmp_path / "rust-reachables.slices.json").write_text(json.dumps(sqlx_flows), encoding="utf-8")
    (tmp_path / "bom.cdx.json").write_text(
        json.dumps({"components": _cargo_bom_components()}), encoding="utf-8"
    )
    opts = ReachabilityAnalysisKV(
        project_types=["rust"], src_dir=str(tmp_path), bom_dir=str(tmp_path)
    )
    res = SemanticReachability(opts).process()
    reached_services = set((res.reached_services or {}).keys())
    assert "pkg:cargo/sqlx@0.6.2" in reached_services, (
        "sqlx must be marked as a reached service via the sql-query sink"
    )

    # --- endpoint fixture: endpoint_reached_purls ---
    ep_dir = tmp_path / "ep"
    ep_dir.mkdir()
    ep_flows = convert_rusi_report(
        _endpoint_report_fixture(), build_bom_purl_index(_endpoint_bom_components())
    )
    (ep_dir / "rust-reachables.slices.json").write_text(json.dumps(ep_flows), encoding="utf-8")
    (ep_dir / "bom.cdx.json").write_text(
        json.dumps({"components": _endpoint_bom_components()}), encoding="utf-8"
    )
    ep_opts = ReachabilityAnalysisKV(
        project_types=["rust"], src_dir=str(ep_dir), bom_dir=str(ep_dir)
    )
    ep_res = SemanticReachability(ep_opts).process()
    endpoint_reached = set((ep_res.endpoint_reached_purls or {}).keys())
    assert "pkg:cargo/axum@0.7.5" in endpoint_reached, (
        "axum (typed framework) must be endpoint-reachable via the endpoint flow"
    )


# ---------------------------------------------------------------------------
# phase 2: qualified-name matching (no cross-crate mis-attribution)
# ---------------------------------------------------------------------------


def test_symbol_matching_is_qualified_name_only_not_short_name(bom_index):
    """Two crates expose a same-named fn ``query``; only the QUALIFIED name
    (``sqlx::query``) must match, never the bare short name ``query``. This
    stops cross-crate mis-attribution."""
    report = {
        "schema_version": "https://appthreat.github.io/rusi/schema/report-0.1",
        "tool": {"name": "rusi", "version": "2.5.2"},
        "call_graph": {
            "nodes": [
                {
                    "id": "cg-sqlx",
                    "name": "query",
                    "qualified_name": "sqlx::query",
                    "purl": "pkg:cargo/sqlx",
                    "external": True,
                    "position": {"filename": "a.rs", "line": 1, "column": 0},
                },
                {
                    "id": "cg-other",
                    "name": "query",
                    "qualified_name": "other_crate::query",
                    "purl": "pkg:cargo/other-crate",
                    "external": True,
                    "position": {"filename": "b.rs", "line": 2, "column": 0},
                },
            ],
            "edges": [
                {
                    "id": "e1",
                    "source_id": "s",
                    "target_id": "cg-sqlx",
                    "source_name": "app::f",
                    "target_name": "sqlx::query",
                    "position": {"filename": "a.rs", "line": 1, "column": 0},
                },
                {
                    "id": "e2",
                    "source_id": "s",
                    "target_id": "cg-other",
                    "source_name": "app::f",
                    "target_name": "other_crate::query",
                    "position": {"filename": "b.rs", "line": 2, "column": 0},
                },
            ],
        },
        "data_flow": {
            "nodes": [
                {
                    "id": "dn",
                    "name": "query",  # bare short name -- ambiguous
                    "function": "app::f",
                    "purl": "pkg:cargo/vulnerable-web-app@0.1.0",
                    "category": "sql-query",
                    "position": {"filename": "a.rs", "line": 1, "column": 0},
                }
            ],
            "slices": [
                {
                    "id": "sl",
                    "source_name": "env",
                    "sink_name": "query",
                    "sourcePurl": "pkg:cargo/vulnerable-web-app@0.1.0",
                    "targetPurl": "pkg:cargo/vulnerable-web-app@0.1.0",
                    "purls": ["pkg:cargo/vulnerable-web-app@0.1.0"],
                    "source_category": "env",
                    "sink_category": "sql-query",
                    "node_ids": ["dn"],
                    "rule_name": "env-to-sql",
                }
            ],
        },
    }
    flows = convert_rusi_report(report, bom_index)
    reached: set = set()
    for f in flows:
        reached.update(f["purls"])
    # The bare ``query`` node name MUST NOT match either external crate, so
    # neither sqlx nor other-crate is attributed to the slice via the ambiguous
    # short name. (They are still reached via their own call-graph flows.)
    slice_flow = [f for f in flows if any("env-to-sql" in n.get("tags", "") for n in f["flows"])]
    if slice_flow:
        slice_purls = set()
        for f in slice_flow:
            slice_purls.update(f["purls"])
        # The slice should carry only the workspace purl, NOT mis-attributed
        # externals from the ambiguous short name.
        assert "pkg:cargo/sqlx@0.6.2" not in slice_purls, (
            "bare short name 'query' must not mis-attribute sqlx onto the slice"
        )
