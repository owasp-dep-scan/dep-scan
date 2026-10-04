"""Unit tests for the golem -> atom-slice converter and purl reconciler.

The reconciler is the single most important correctness detail in the golem
integration (see golem-reachability-plan.md §3). These tests lock down:

  - versioned module purls pass through
  - package-level ``pkg:golang/<module>@<ver>#<subpath>`` reconciles to the
    BOM's versioned module purl
  - version-stripped purls reconcile
  - stdlib nodes (empty purl, ``standard:true``) are dropped
  - the emitted slice JSON is atom-shaped and deterministic
  - the full pipeline lights up FrameworkReachability with zero engine changes

Golem JSON uses **lowerCamelCase** keys (``callGraph``, ``dataFlow``,
``apiEndpoints``, ``nodeIds``, ``sourceName``, ``sinkPurl``). These tests
verify the converter reads camelCase, NOT rusi's snake_case.
"""

import json
from pathlib import Path

import pytest

from analysis_lib.golem_slices import (
    GOLEM_CATEGORY_TO_SERVICE_TAG,
    GOLEM_ENDPOINT_SERVICE_TAG,
    build_bom_purl_index,
    convert_golem_report,
    is_golem_report,
    reconcile_purl,
    reconcile_purls,
    write_slices_file,
)


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def _go_bom_components():
    """A minimal Go BOM component list mirroring cdxgen output."""
    return [
        {
            "type": "application",
            "name": "github.com/example/vuln-app",
            "version": "v0.1.0",
            "purl": "pkg:golang/github.com/example/vuln-app@v0.1.0",
            "bom-ref": "pkg:golang/github.com/example/vuln-app@v0.1.0",
        },
        {
            "type": "library",
            "name": "github.com/jackc/pgx/v4",
            "version": "v4.18.1",
            "purl": "pkg:golang/github.com/jackc/pgx/v4@v4.18.1",
            "bom-ref": "pkg:golang/github.com/jackc/pgx/v4@v4.18.1",
        },
        {
            "type": "library",
            "name": "github.com/gin-gonic/gin",
            "version": "v1.9.1",
            "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
            "bom-ref": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
        },
        {
            "type": "library",
            "name": "github.com/unused/dep",
            "version": "v0.0.1",
            "purl": "pkg:golang/github.com/unused/dep@v0.0.1",
            "bom-ref": "pkg:golang/github.com/unused/dep@v0.0.1",
        },
    ]


@pytest.fixture
def bom_index():
    return build_bom_purl_index(_go_bom_components())


# ---------------------------------------------------------------------------
# reconciler
# ---------------------------------------------------------------------------


def test_reconcile_exact_versioned_matches(bom_index):
    """Exact versioned module purl passes through."""
    assert (
        reconcile_purl("pkg:golang/github.com/jackc/pgx/v4@v4.18.1", bom_index)
        == "pkg:golang/github.com/jackc/pgx/v4@v4.18.1"
    )


def test_reconcile_subpath_purl_matches_module(bom_index):
    """THE critical assertion: package-level purl with subpath
    ``pkg:golang/<module>@<ver>#<subpath>`` must reconcile to the BOM's
    versioned module purl via the version+subpath-stripped form."""
    assert (
        reconcile_purl("pkg:golang/github.com/jackc/pgx/v4@v4.18.1#pgxpool", bom_index)
        == "pkg:golang/github.com/jackc/pgx/v4@v4.18.1"
    )


def test_reconcile_version_stripped_matches(bom_index):
    """Version-stripped module purl matches the BOM."""
    assert (
        reconcile_purl("pkg:golang/github.com/jackc/pgx/v4", bom_index)
        == "pkg:golang/github.com/jackc/pgx/v4@v4.18.1"
    )


def test_reconcile_unknown_module_dropped(bom_index):
    """A module NOT in the BOM -> None (no noise)."""
    assert reconcile_purl("pkg:golang/github.com/nonexistent/pkg@v1.0.0", bom_index) is None


def test_reconcile_non_golang_purl_dropped(bom_index):
    assert reconcile_purl("pkg:cargo/sqlx@0.6.2", bom_index) is None
    assert reconcile_purl("pkg:npm/express@4.22.2", bom_index) is None
    assert reconcile_purl("not-a-purl", bom_index) is None
    assert reconcile_purl("", bom_index) is None
    assert reconcile_purl(None, bom_index) is None


def test_reconcile_no_dash_underscore_normalization():
    """Go module paths are literal: NO ``-``/``_`` normalization (unlike
    cargo). ``github.com/foo-bar`` and ``github.com/foo_bar`` are DIFFERENT
    modules."""
    idx = build_bom_purl_index([{"purl": "pkg:golang/github.com/foo-bar@v1.0.0"}])
    assert reconcile_purl("pkg:golang/github.com/foo_bar@v1.0.0", idx) is None
    assert reconcile_purl("pkg:golang/github.com/foo-bar", idx) == (
        "pkg:golang/github.com/foo-bar@v1.0.0"
    )


def test_reconcile_purls_dedupes_and_sorts(bom_index):
    out = reconcile_purls(
        [
            "pkg:golang/github.com/jackc/pgx/v4@v4.18.1#pgxpool",
            "pkg:golang/github.com/jackc/pgx/v4",
            "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
        ],
        bom_index,
    )
    assert out == [
        "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
        "pkg:golang/github.com/jackc/pgx/v4@v4.18.1",
    ]


def test_build_bom_index_ignores_non_golang_components():
    idx = build_bom_purl_index(
        [
            {"purl": "pkg:golang/github.com/keep@v1.0.0", "name": "keep"},
            {"purl": "pkg:npm/skip@2.0.0", "name": "skip"},
        ]
    )
    assert "pkg:golang/github.com/keep@v1.0.0" in idx
    assert "pkg:golang/github.com/keep" in idx
    assert len(idx) == 2  # only golang entries


# ---------------------------------------------------------------------------
# converter: golden slice JSON (real-shape golem report, synthetic BOM)
# ---------------------------------------------------------------------------


def _golem_report_fixture():
    """A trimmed-but-faithful golem report based on the real model.go schema.

    Critical realism points:
      - Golem JSON is **lowerCamelCase** (callGraph, dataFlow, nodeIds,
        sourcePurl, sinkPurl, ruleName, etc.).
      - callgraph nodes have NO ``qualifiedName`` (unlike rusi) — use ``label``/
        ``name`` + ``packagePath`` + ``module``.
      - Module purls are versioned ``pkg:golang/<path>@<version>`` and
        package-level purls carry ``#<subpath>``.
      - The dataflow slice sinks into pgx.Connect; the slice's own purls only
        carry the app purl, so the external attribution must come from the
        node's module purl / packagePath resolution.
      - Stdlib nodes (``standard:true``, empty purl) must be dropped.
    """
    return {
        "schemaVersion": "0.1",
        "tool": {"name": "golem", "version": "2.5.2"},
        "runtime": {"goos": "linux", "goarch": "amd64", "goVersion": "go1.22.0"},
        "modules": [
            {
                "path": "github.com/example/vuln-app",
                "version": "v0.1.0",
                "main": True,
                "purl": "pkg:golang/github.com/example/vuln-app@v0.1.0",
            },
            {
                "path": "github.com/jackc/pgx/v4",
                "version": "v4.18.1",
                "main": False,
                "purl": "pkg:golang/github.com/jackc/pgx/v4@v4.18.1",
            },
            {
                "path": "github.com/gin-gonic/gin",
                "version": "v1.9.1",
                "main": False,
                "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
            },
        ],
        "callGraph": {
            "mode": "static",
            "nodes": [
                {
                    "id": "cg-pgx-connect",
                    "name": "Connect",
                    "label": "pgx.Connect",
                    "kind": "function",
                    "packagePath": "github.com/jackc/pgx/v4",
                    "moduleName": "pgx",
                    "module": {
                        "path": "github.com/jackc/pgx/v4",
                        "version": "v4.18.1",
                        "main": False,
                        "purl": "pkg:golang/github.com/jackc/pgx/v4@v4.18.1",
                    },
                    "purl": "pkg:golang/github.com/jackc/pgx/v4@v4.18.1",
                    "standard": False,
                    "external": True,
                    "local": False,
                    "position": {"filename": "main.go", "line": 25, "column": 10},
                },
                {
                    "id": "cg-gin-handle",
                    "name": "Handle",
                    "label": "gin.Engine.Handle",
                    "kind": "function",
                    "packagePath": "github.com/gin-gonic/gin",
                    "module": {
                        "path": "github.com/gin-gonic/gin",
                        "version": "v1.9.1",
                        "main": False,
                        "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                    },
                    "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                    "standard": False,
                    "external": True,
                    "local": False,
                    "position": {"filename": "main.go", "line": 15, "column": 5},
                },
                {
                    "id": "cg-stdlib-fmt",
                    "name": "Println",
                    "label": "fmt.Println",
                    "kind": "function",
                    "packagePath": "fmt",
                    "module": None,
                    "purl": "",
                    "standard": True,
                    "external": False,
                    "local": False,
                    "position": {"filename": "main.go", "line": 30, "column": 5},
                },
                {
                    "id": "cg-app-main",
                    "name": "main",
                    "label": "main.main",
                    "kind": "function",
                    "packagePath": "github.com/example/vuln-app",
                    "module": {
                        "path": "github.com/example/vuln-app",
                        "version": "v0.1.0",
                        "main": True,
                        "purl": "pkg:golang/github.com/example/vuln-app@v0.1.0",
                    },
                    "purl": "pkg:golang/github.com/example/vuln-app@v0.1.0",
                    "standard": False,
                    "external": False,
                    "local": True,
                    "position": {"filename": "main.go", "line": 10, "column": 0},
                },
            ],
            "edges": [
                {
                    "id": "e1",
                    "sourceId": "cg-app-main",
                    "targetId": "cg-pgx-connect",
                    "sourceName": "main.main",
                    "targetName": "pgx.Connect",
                    "sourcePurl": "pkg:golang/github.com/example/vuln-app@v0.1.0",
                    "sinkPurl": "pkg:golang/github.com/jackc/pgx/v4@v4.18.1",
                    "purls": [
                        "pkg:golang/github.com/example/vuln-app@v0.1.0",
                        "pkg:golang/github.com/jackc/pgx/v4@v4.18.1",
                    ],
                    "callType": "static",
                    "position": {"filename": "main.go", "line": 25, "column": 10},
                },
                {
                    "id": "e2",
                    "sourceId": "cg-app-main",
                    "targetId": "cg-gin-handle",
                    "sourceName": "main.main",
                    "targetName": "gin.Engine.Handle",
                    "sourcePurl": "pkg:golang/github.com/example/vuln-app@v0.1.0",
                    "sinkPurl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                    "purls": [
                        "pkg:golang/github.com/example/vuln-app@v0.1.0",
                        "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                    ],
                    "callType": "static",
                    "position": {"filename": "main.go", "line": 15, "column": 5},
                },
            ],
        },
        "dataFlow": {
            "mode": "all",
            "nodes": [
                {
                    "id": "df-source",
                    "kind": "source",
                    "name": "PostForm",
                    "symbol": "gin.Context.PostForm",
                    "packagePath": "github.com/gin-gonic/gin",
                    "module": {
                        "path": "github.com/gin-gonic/gin",
                        "version": "v1.9.1",
                        "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                    },
                    "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                    "function": "main.handleRequest",
                    "category": "http-parameter",
                    "position": {"filename": "main.go", "line": 20, "column": 15},
                },
                {
                    "id": "df-pgx",
                    "kind": "sink",
                    "name": "Connect",
                    "symbol": "pgx.Connect",
                    "packagePath": "github.com/jackc/pgx/v4",
                    "module": {
                        "path": "github.com/jackc/pgx/v4",
                        "version": "v4.18.1",
                        "purl": "pkg:golang/github.com/jackc/pgx/v4@v4.18.1",
                    },
                    "purl": "pkg:golang/github.com/jackc/pgx/v4@v4.18.1",
                    "function": "main.handleRequest",
                    "category": "sql-query",
                    "position": {"filename": "main.go", "line": 25, "column": 10},
                },
            ],
            "slices": [
                {
                    "id": "slice-1",
                    "sourceId": "df-source",
                    "sinkId": "df-pgx",
                    "flowKey": "http-param-to-sql",
                    "nodeIds": ["df-source", "df-pgx"],
                    "sourceCategory": "http-parameter",
                    "sinkCategory": "sql-query",
                    "sourceName": "PostForm",
                    "sinkName": "Connect",
                    "sourceFunction": "main.handleRequest",
                    "sinkFunction": "main.handleRequest",
                    "sourcePackagePath": "github.com/gin-gonic/gin",
                    "sinkPackagePath": "github.com/jackc/pgx/v4",
                    "sourcePurl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                    "sinkPurl": "pkg:golang/github.com/jackc/pgx/v4@v4.18.1",
                    "purls": [
                        "pkg:golang/github.com/example/vuln-app@v0.1.0",
                    ],
                    "ruleId": "go-sql-injection",
                    "ruleName": "HTTP parameter to SQL query",
                    "severity": "high",
                    "confidence": "high",
                    "description": "HTTP parameter can flow into SQL query via pgx.Connect",
                }
            ],
            "stats": {
                "truncated": False,
                "truncationReasons": [],
            },
        },
        "apiEndpoints": [
            {
                "id": "ep-1",
                "kind": "http",
                "framework": "gin",
                "method": "POST",
                "path": "/api/users",
                "handler": "main.handleRequest",
                "packagePath": "github.com/example/vuln-app",
                "range": {"start": {"filename": "main.go", "line": 15, "column": 5}},
            }
        ],
    }


def test_converter_emits_atom_shape(bom_index):
    flows = convert_golem_report(_golem_report_fixture(), bom_index)
    assert isinstance(flows, list)
    assert all(isinstance(f, dict) for f in flows)
    for f in flows:
        assert "flows" in f and isinstance(f["flows"], list)
        assert "purls" in f and isinstance(f["purls"], list)
        for node in f["flows"]:
            assert "id" in node and "tags" in node


def test_converter_dataflow_slice_picks_up_pgx(bom_index):
    """The dataflow slice carries pgx via the node's module purl. The
    reconciled ``pkg:golang/github.com/jackc/pgx/v4@v4.18.1`` MUST appear on
    the flow."""
    flows = convert_golem_report(_golem_report_fixture(), bom_index)
    # Find flows that carry the pgx purl (the dataflow slice + call-graph flows)
    pgx_flows = [
        f for f in flows if "pkg:golang/github.com/jackc/pgx/v4@v4.18.1" in f.get("purls", [])
    ]
    assert pgx_flows, "at least one flow with pgx must be emitted"
    # The dataflow slice flow specifically should carry the ruleName in tags
    slice_flows = [
        f
        for f in flows
        if any("HTTP parameter to SQL query" in n.get("tags", "") for n in f["flows"])
    ]
    assert slice_flows, "dataflow slice flow must be emitted"
    all_slice_purls = set()
    for f in slice_flows:
        all_slice_purls.update(f["purls"])
    assert "pkg:golang/github.com/jackc/pgx/v4@v4.18.1" in all_slice_purls, (
        "pgx must be reconciled onto the slice flow (this is the integration crux)"
    )


def test_converter_emits_call_graph_flows_for_externals(bom_index):
    """Every external module in the BOM that golem observed a call to gets its
    own call-graph flow (pure-call reachability, not just taint)."""
    flows = convert_golem_report(_golem_report_fixture(), bom_index)
    reached = set()
    for f in flows:
        reached.update(f["purls"])
    assert {
        "pkg:golang/github.com/jackc/pgx/v4@v4.18.1",
        "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
    } <= reached


def test_converter_drops_stdlib(bom_index):
    """Stdlib nodes (``standard:true``, empty purl) must never appear in any
    emitted flow purl."""
    flows = convert_golem_report(_golem_report_fixture(), bom_index)
    for f in flows:
        for p in f["purls"]:
            assert not p.endswith("/fmt"), "stdlib fmt leaked into output"
            # empty purl should never appear
            assert p != ""


def test_converter_unused_dep_not_reached(bom_index):
    """``github.com/unused/dep`` is in the BOM but never called -> it must
    NOT appear in any reached flow."""
    flows = convert_golem_report(_golem_report_fixture(), bom_index)
    reached = set()
    for f in flows:
        reached.update(f["purls"])
    assert not any("github.com/unused/dep" in p for p in reached), "unused dep must not be reached"


# ---------------------------------------------------------------------------
# root-reachability gating (golem >= 3.2 stamps reachableFromRoots)
# ---------------------------------------------------------------------------


def _reached_purls(flows):
    reached = set()
    for f in flows:
        reached.update(f["purls"])
    return reached


def _with_reachability(fixture, nodes):
    """Attach a callGraph.reachability section mapping node id -> bool."""
    fixture = json.loads(json.dumps(fixture))  # deep copy
    fixture["callGraph"]["reachability"] = {
        "nodes": [{"nodeId": nid, "reachableFromRoots": val} for nid, val in nodes.items()]
    }
    return fixture


def test_converter_skips_unrooted_slices(bom_index):
    """A slice golem stamped ``reachableFromRoots: false`` lives entirely in
    code the application never drives into; it must not become a flow. The
    pgx purl still arrives through the (rooted) call-graph edge -- the slice
    itself is what disappears."""
    report = _golem_report_fixture()
    report["dataFlow"]["slices"][0]["reachableFromRoots"] = False
    flows = convert_golem_report(report, bom_index)
    for f in flows:
        node_ids = {n.get("id") for n in f["flows"]}
        assert "df-source" not in node_ids and "df-pgx" not in node_ids, (
            "an unrooted slice must not be emitted as a flow"
        )


def test_converter_rooted_slice_is_kept(bom_index):
    """A slice stamped ``reachableFromRoots: true`` flows exactly as an
    unflagged one does."""
    report = _golem_report_fixture()
    report["dataFlow"]["slices"][0]["reachableFromRoots"] = True
    flows = convert_golem_report(report, bom_index)
    assert any(
        any(n.get("id") == "df-pgx" for n in f["flows"]) for f in flows
    ), "a rooted slice must survive"


def test_converter_keeps_slice_without_reachability_flag(bom_index):
    """Older golem reports carry no ``reachableFromRoots`` at all; their
    slices must keep flowing (absent is unknown, not unreachable)."""
    report = _golem_report_fixture()
    assert "reachableFromRoots" not in report["dataFlow"]["slices"][0]
    flows = convert_golem_report(report, bom_index)
    assert any(
        any(n.get("id") == "df-pgx" for n in f["flows"]) for f in flows
    ), "unflagged slice must survive"


def test_converter_drops_edges_into_unreachable_targets(bom_index):
    """Call-graph edges between two functions the roots never reach are
    library self-analysis; with reachability reported they must not mark the
    package reached. The data-flow section is dropped so the edges under test
    are the only purl carriers."""
    report = _with_reachability(
        _golem_report_fixture(),
        {
            "cg-app-main": True,
            "cg-pgx-connect": True,
            # gin's Handle is never reached from the roots...
            "cg-gin-handle": False,
            "cg-stdlib-fmt": True,
        },
    )
    del report["dataFlow"]
    reached = _reached_purls(convert_golem_report(report, bom_index))
    assert "pkg:golang/github.com/gin-gonic/gin@v1.9.1" not in reached
    assert "pkg:golang/github.com/jackc/pgx/v4@v4.18.1" in reached


def _with_gin_init_edge(report, gin_init_reachable, gin_code_reachable):
    """Retarget the gin edge at gin's package init, mirroring a blank import,
    and optionally give gin a reachable non-init node."""
    report["callGraph"]["nodes"][1]["id"] = "github.com/gin-gonic/gin.init"
    report["callGraph"]["nodes"][1]["name"] = "init"
    report["callGraph"]["edges"][1]["targetId"] = "github.com/gin-gonic/gin.init"
    report["callGraph"]["edges"][1]["targetName"] = "github.com/gin-gonic/gin.init"
    report["callGraph"]["reachability"]["nodes"].append(
        {"nodeId": "github.com/gin-gonic/gin.init", "reachableFromRoots": gin_init_reachable}
    )
    if gin_code_reachable:
        report["callGraph"]["nodes"].append(
            {
                "id": "github.com/gin-gonic/gin.Engine.Render",
                "name": "Render",
                "label": "gin.Engine.Render",
                "kind": "function",
                "packagePath": "github.com/gin-gonic/gin",
                "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                "standard": False,
                "external": True,
                "local": False,
            }
        )
        report["callGraph"]["reachability"]["nodes"].append(
            {"nodeId": "github.com/gin-gonic/gin.Engine.Render", "reachableFromRoots": True}
        )
    del report["dataFlow"]
    return report


def test_converter_init_only_package_stays_unreached(bom_index):
    """A blank import runs the package init, so the app->init edge is
    reachable -- but when init is the ONLY reachable node of the package the
    import is the whole story and the package must stay unreached."""
    report = _with_reachability(
        _golem_report_fixture(),
        {
            "cg-app-main": True,
            "cg-pgx-connect": True,
            "cg-gin-handle": False,
            "cg-stdlib-fmt": True,
        },
    )
    report = _with_gin_init_edge(report, gin_init_reachable=True, gin_code_reachable=False)
    reached = _reached_purls(convert_golem_report(report, bom_index))
    assert "pkg:golang/github.com/gin-gonic/gin@v1.9.1" not in reached
    assert "pkg:golang/github.com/jackc/pgx/v4@v4.18.1" in reached


def test_converter_init_edge_kept_when_package_has_reachable_code(bom_index):
    """When other nodes of the package ARE reachable the package is genuinely
    used and its init edge is ordinary evidence, not an import artifact."""
    report = _with_reachability(
        _golem_report_fixture(),
        {
            "cg-app-main": True,
            "cg-pgx-connect": True,
            "cg-gin-handle": False,
            "cg-stdlib-fmt": True,
        },
    )
    report = _with_gin_init_edge(report, gin_init_reachable=True, gin_code_reachable=True)
    reached = _reached_purls(convert_golem_report(report, bom_index))
    assert "pkg:golang/github.com/gin-gonic/gin@v1.9.1" in reached


def test_converter_without_reachability_section_keeps_everything(bom_index):
    """No reachability section (older golem / --callgraph none): the converter
    must behave exactly as before -- both external edges flow."""
    report = _golem_report_fixture()
    assert "reachability" not in report["callGraph"]
    reached = _reached_purls(convert_golem_report(report, bom_index))
    assert "pkg:golang/github.com/gin-gonic/gin@v1.9.1" in reached
    assert "pkg:golang/github.com/jackc/pgx/v4@v4.18.1" in reached


def test_converter_is_deterministic(bom_index):
    """Two conversions of the same report produce byte-identical output."""
    a = convert_golem_report(_golem_report_fixture(), bom_index)
    b = convert_golem_report(_golem_report_fixture(), bom_index)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_converter_golden_file(tmp_path, bom_index):
    """Golden-file the emitted slice JSON so future changes are reviewable."""
    flows = convert_golem_report(_golem_report_fixture(), bom_index)
    out_file = tmp_path / "go-reachables.slices.json"
    write_slices_file(str(out_file), flows)
    assert out_file.exists()
    loaded = json.loads(out_file.read_text())
    assert loaded == flows
    assert isinstance(loaded, list)
    assert len(loaded) >= 3  # 1 dataflow slice + 2 call-graph external flows

    golden_dir = Path(__file__).parent / "data" / "golem"
    golden_dir.mkdir(parents=True, exist_ok=True)
    golden_file = golden_dir / "vuln-app.golden.json"
    if not golden_file.exists():
        golden_file.write_text(json.dumps(loaded, sort_keys=True, indent=2), encoding="utf-8")
    else:
        golden = json.loads(golden_file.read_text())
        assert loaded == golden, (
            f"golem slice output changed; if intentional, delete {golden_file} "
            "and re-run to regenerate."
        )


def test_converter_handles_empty_report(bom_index):
    assert convert_golem_report({}, bom_index) == []
    assert convert_golem_report({"callGraph": None, "dataFlow": None}, bom_index) == []


def test_converter_handles_missing_dataflow_but_callgraph_present(bom_index):
    """A repo with calls but no taint slices still emits call-graph flows."""
    report = _golem_report_fixture()
    report["dataFlow"]["slices"] = []
    flows = convert_golem_report(report, bom_index)
    reached = set()
    for f in flows:
        reached.update(f["purls"])
    assert "pkg:golang/github.com/jackc/pgx/v4@v4.18.1" in reached


def test_converter_subpath_purl_reconciles(bom_index):
    """A node carrying a package-level ``#subpath`` purl must reconcile to the
    BOM's versioned module purl."""
    report = _golem_report_fixture()
    # Change the pgx node purl to a package-level subpath form
    for n in report["callGraph"]["nodes"]:
        if n["id"] == "cg-pgx-connect":
            n["purl"] = "pkg:golang/github.com/jackc/pgx/v4@v4.18.1#pgxpool"
    flows = convert_golem_report(report, bom_index)
    reached = set()
    for f in flows:
        reached.update(f["purls"])
    assert "pkg:golang/github.com/jackc/pgx/v4@v4.18.1" in reached


# ---------------------------------------------------------------------------
# shape detection (camelCase keys, not snake_case)
# ---------------------------------------------------------------------------


def test_is_golem_report_detects_by_shape():
    """Detection is structural: producer (tool/runtime) + section
    (callGraph/dataFlow). Uses **camelCase** keys (golem), NOT snake_case
    (rusi)."""
    # full report (tool + callGraph + dataFlow)
    assert is_golem_report({"tool": {"name": "golem"}, "callGraph": {"nodes": []}, "dataFlow": {}})
    # runtime alone is a valid producer signal
    assert is_golem_report({"runtime": {"goVersion": "1.22"}, "dataFlow": {"slices": []}})
    # callGraph alone (no dataFlow) is still enough
    assert is_golem_report({"tool": {"name": "golem"}, "callGraph": {"nodes": []}})
    assert is_golem_report({"tool": {}, "dataFlow": {}})


def test_is_golem_report_rejects_non_golem_shapes():
    """An atom semantics slice, a rusi report (snake_case), or arbitrary JSON
    must NOT be mistaken for a golem report."""
    # no producer identity
    assert not is_golem_report({"callGraph": {"nodes": []}, "dataFlow": {}})
    # no analysis section
    assert not is_golem_report({"tool": {"name": "golem"}, "runtime": {}})
    # rusi report (snake_case keys) must NOT match golem detection
    assert not is_golem_report({"tool": {"name": "rusi"}, "call_graph": {}})
    assert not is_golem_report({"tool": {"name": "rusi"}, "data_flow": {}})
    # atom-style semantics slice (list / frames) -- wrong shape entirely
    assert not is_golem_report([{"flows": [], "purls": []}])
    assert not is_golem_report({"frames": [], "data flows": []})
    # empty / wrong type
    assert not is_golem_report({})
    assert not is_golem_report(None)
    assert not is_golem_report("not-a-report")
    # schemaVersion alone is not sufficient
    assert not is_golem_report({"schemaVersion": "0.1"})


# ---------------------------------------------------------------------------
# end-to-end through FrameworkReachability (no golem binary required)
# ---------------------------------------------------------------------------


def test_slice_feeds_into_framework_reachability(tmp_path, bom_index):
    """The emitted slice + Go BOM, when read by FrameworkReachability, must
    mark pgx and gin as reached. This proves the integration works without
    touching the reachability engine or the golem binary."""
    from analysis_lib import ReachabilityAnalysisKV
    from analysis_lib.reachability import FrameworkReachability

    flows = convert_golem_report(_golem_report_fixture(), bom_index)
    slices_path = tmp_path / "go-reachables.slices.json"
    slices_path.write_text(json.dumps(flows), encoding="utf-8")

    bom_path = tmp_path / "bom.cdx.json"
    bom_path.write_text(json.dumps({"components": _go_bom_components()}), encoding="utf-8")

    opts = ReachabilityAnalysisKV(
        project_types=["go"],
        src_dir=str(tmp_path),
        bom_dir=str(tmp_path),
    )
    res = FrameworkReachability(opts).process()
    assert res.success
    reached = set((res.reached_purls or {}).keys())
    assert "pkg:golang/github.com/jackc/pgx/v4@v4.18.1" in reached
    assert "pkg:golang/github.com/gin-gonic/gin@v1.9.1" in reached
    # the workspace app is also reached (its own functions are on the path)
    assert "pkg:golang/github.com/example/vuln-app@v0.1.0" in reached
    # unused dep must NOT be reached
    assert not any("github.com/unused/dep" in p for p in reached)


# ---------------------------------------------------------------------------
# SemanticReachability: service attribution
# ---------------------------------------------------------------------------


def test_dataflow_slice_attributes_service_to_dependency_purl(bom_index):
    """The sql-query sink service tag MUST land on the pgx dependency purl,
    not just the workspace app. This is the positional-association guarantee
    that makes ``reached_services`` attribute the service to the right module.
    """
    from analysis_lib.reachability import _flow_service_purls

    flows = convert_golem_report(_golem_report_fixture(), bom_index)
    slice_flows = [
        f
        for f in flows
        if any("HTTP parameter to SQL query" in n.get("tags", "") for n in f["flows"])
    ]
    assert slice_flows, "dataflow slice flow must be emitted"
    service_purls: set = set()
    for f in slice_flows:
        service_purls |= _flow_service_purls(f)
    assert "pkg:golang/github.com/jackc/pgx/v4@v4.18.1" in service_purls, (
        "sql service must be positionally attributed to pgx, the dependency"
    )


def test_endpoint_service_tag_in_service_tags():
    """The ``api`` endpoint service tag must be a valid SERVICE_TAG."""
    from analysis_lib.config import SERVICE_TAGS

    assert GOLEM_ENDPOINT_SERVICE_TAG in SERVICE_TAGS


def test_category_to_service_tag_mapping_is_conservative():
    """The category mapping only includes categories that clearly map to
    existing SERVICE_TAGS."""
    from analysis_lib.config import SERVICE_TAGS

    for cat, tag in GOLEM_CATEGORY_TO_SERVICE_TAG.items():
        assert tag in SERVICE_TAGS, f"category {cat} maps to unknown tag {tag}"
