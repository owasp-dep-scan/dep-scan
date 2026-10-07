import inspect

import vdb.lib.db6 as vdb6
import vdb.lib.search as vsearch

from analysis_lib import search


def test_get_pkg_vendor_name():
    vendor, name = search.get_pkg_vendor_name({"vendor": "angular", "name": "cdk"})
    assert vendor == "angular"
    assert name == "cdk"

    vendor, name = search.get_pkg_vendor_name(
        {"vendor": "", "purl": "pkg:npm/parse5@5.1.0", "name": "parse5"}
    )
    assert vendor == "npm"
    assert name == "parse5"


def test_get_pkgs_by_scope():
    scoped_pkgs = search.get_pkgs_by_scope([{"vendor": "angular", "name": "cdk"}])
    assert not scoped_pkgs

    scoped_pkgs = search.get_pkgs_by_scope(
        [
            {"vendor": "angular", "name": "cdk"},
            {
                "vendor": "",
                "purl": "pkg:npm/parse5@5.1.0",
                "name": "parse5",
                "scope": "required",
            },
        ],
    )
    assert scoped_pkgs == {"required": ["pkg:npm/parse5@5.1.0"]}

    scoped_pkgs = search.get_pkgs_by_scope(
        [
            {"vendor": "angular", "name": "cdk"},
            {
                "vendor": "",
                "purl": "pkg:npm/parse5@5.1.0",
                "name": "parse5",
                "scope": "required",
            },
            {"vendor": "angular-devkit", "name": "build-webpack", "scope": "optional"},
        ],
    )
    assert scoped_pkgs == {
        "required": ["pkg:npm/parse5@5.1.0"],
        "optional": ["angular-devkit:build-webpack"],
    }


def test_pkg_to_locator_prefers_purl():
    loc, orig = search._pkg_to_locator({"purl": "pkg:npm/a@1.0.0", "cpe": "cpe:2.3:a:x:a:1.0.0"})
    assert loc == {"purl": "pkg:npm/a@1.0.0"}
    assert orig == "pkg:npm/a@1.0.0"


def test_pkg_to_locator_falls_back_to_cpe_and_url():
    loc, _ = search._pkg_to_locator({"cpe": "cpe:2.3:a:x:a:1.0.0"})
    assert loc == {"cpe": "cpe:2.3:a:x:a:1.0.0"}
    loc, _ = search._pkg_to_locator({"url": "https://example.com"})
    assert loc == {"url": "https://example.com"}
    loc, _ = search._pkg_to_locator({"name": "lonely"})
    assert loc is None


def test_find_vulns_batched_skips_versionless_purls(monkeypatch):
    """The versionless-purl skip (#465) must be preserved in the batched path."""
    searched = []

    def fake_batched(locators, **kwargs):
        searched.extend(locators)
        return iter([])  # no results

    monkeypatch.setattr(search, "search_packages_batched", fake_batched)
    pkgs = [
        {"purl": "pkg:npm/hasversion@1.0.0", "version": "1.0.0"},
        {"purl": "pkg:npm/noversion", "version": None},
        {"cpe": "cpe:2.3:a:vendor:pkg:1.0.0"},
    ]
    search.find_vulns_batched(pkgs)
    # Only the versioned purl and cpe should reach the search layer
    assert len(searched) == 2
    assert {"purl": "pkg:npm/hasversion@1.0.0"} in searched
    assert {"cpe": "cpe:2.3:a:vendor:pkg:1.0.0"} in searched


# ---------------------------------------------------------------------------
# T4 — canonicalize purls before search
# ---------------------------------------------------------------------------


def test_canonicalize_search_purl_lowercases_npm():
    """npm purls are lowercased so mixed-case SBOM purls match vdb entries.
    Scoped packages have @ encoded as %40 per the purl spec."""
    assert search.canonicalize_search_purl("pkg:npm/Lodash@4.17.20") == "pkg:npm/lodash@4.17.20"
    assert (
        search.canonicalize_search_purl("pkg:npm/@Angular/Core@15.0.0")
        == "pkg:npm/%40angular/core@15.0.0"
    )


def test_canonicalize_search_purl_preserves_maven_case():
    """Maven artifact IDs are case-sensitive and must not be lowercased."""
    original = "pkg:maven/org.springframework/spring-core@5.3.20"
    assert search.canonicalize_search_purl(original) == original


def test_canonicalize_search_purl_preserves_os_qualifiers():
    """OS/container distro qualifiers survive canonicalisation untouched."""
    original = "pkg:deb/debian/curl@7.88.1?arch=amd64&distro=debian-12"
    assert search.canonicalize_search_purl(original) == original


def test_canonicalize_search_purl_lowercases_github():
    """GitHub purls: user/repo are case-insensitive and get lowercased."""
    assert (
        search.canonicalize_search_purl("pkg:github/User/Repo@v1.0.0")
        == "pkg:github/user/repo@v1.0.0"
    )


def test_canonicalize_search_purl_noop_for_already_canonical():
    """Already-canonical purls are returned as-is."""
    assert search.canonicalize_search_purl("pkg:npm/lodash@4.17.20") == "pkg:npm/lodash@4.17.20"


def test_find_vulns_batched_two_pass_hydration(monkeypatch):
    """Pass 1 (with_data=False) finds matches; pass 2 hydrates via
    get_cve_data_batched using the index hits from pass 1 (no re-query)."""
    hydrate_calls = []

    def fake_batched(locators, batch_size=50, with_data=False, **kwargs):
        assert with_data is False  # pass 1 is always lightweight
        yield [
            {
                "locator": locators[0],
                "result_count": 1,
                "results": [{"cve_id": "X", "vers": "1.0", "purl_prefix": "pkg:npm/a"}],
            },
            {"locator": locators[1], "result_count": 0, "results": []},
        ]

    def fake_hydrate(db_conn, hits, search_str):
        hydrate_calls.append((search_str, hits))
        return iter([{"cve_id": "CVE-2024-1", "matched_by": search_str}])

    monkeypatch.setattr(search, "search_packages_batched", fake_batched)
    monkeypatch.setattr(search, "get_cve_data_batched", fake_hydrate)
    monkeypatch.setattr(vsearch, "CUSTOM_DATA_CACHE", [])
    monkeypatch.setattr(vdb6, "get", lambda read_only=True: (None, None))

    pkgs = [
        {"purl": "pkg:npm/matched@1.0.0", "version": "1.0.0"},
        {"purl": "pkg:npm/nomatch@1.0.0", "version": "1.0.0"},
    ]
    results = search.find_vulns_batched(pkgs)
    assert results == [{"cve_id": "CVE-2024-1", "matched_by": "pkg:npm/matched@1.0.0"}]
    # Only the matched purl was hydrated, and the index hit was passed through
    assert len(hydrate_calls) == 1
    assert hydrate_calls[0][0] == "pkg:npm/matched@1.0.0"


def test_find_vulns_uses_batched_path_by_default(monkeypatch):
    """With the default search order, the batched path is used."""
    called = []

    def fake_batched(expanded_list, filters=None):
        called.append("batched")
        return []

    monkeypatch.setattr(search, "find_vulns_batched", fake_batched)
    search.find_vulns(None, [{"purl": "pkg:npm/a@1.0.0", "version": "1.0.0"}])
    assert called == ["batched"]


def test_find_vulns_falls_back_to_serial_for_fuzzy(monkeypatch):
    """Fuzzy search always uses the serial path, not the batched one."""
    serial_calls = []
    batched_calls = []

    def fake_search_expanded(pkg, fuzzy_search, search_order, filters=None):
        serial_calls.append(pkg)
        return []

    def fake_batched(expanded_list, filters=None):
        batched_calls.append(expanded_list)
        return []

    monkeypatch.setattr(search, "search_expanded", fake_search_expanded)
    monkeypatch.setattr(search, "find_vulns_batched", fake_batched)
    search.find_vulns(None, [{"purl": "pkg:npm/a@1.0.0", "version": "1.0.0"}], fuzzy_search=True)
    assert serial_calls  # serial path was used
    assert not batched_calls  # batched path was NOT used


# ---------------------------------------------------------------------------
# T6 — push-down filters (vdb filters= argument)
# ---------------------------------------------------------------------------


def test_build_search_filters_exclude_malware_unconditional():
    """exclude_malware works on the default DB and is always pushed down."""
    filters = search.build_search_filters({"exclude_malware": True})
    assert filters == {"exclude_malware": True}


def test_build_search_filters_malware_only_unconditional():
    filters = search.build_search_filters({"malware_only": True})
    assert filters == {"malware_only": True}


def test_build_search_filters_empty_when_nothing_set():
    """No options -> empty dict -> parity with the unfiltered path."""
    assert search.build_search_filters({}) == {}
    assert search.build_search_filters(None) == {}


def test_build_search_filters_severity_only_when_extended_metadata(monkeypatch):
    """severity_threshold is gated behind the extended-metadata check so the
    default DB is never silently under-reported."""
    monkeypatch.setattr(search, "_extended_metadata_available", lambda: True)
    filters = search.build_search_filters({"severity": "high"})
    assert filters == {"severity_threshold": "high"}


def test_build_search_filters_severity_omitted_without_extended_metadata(monkeypatch):
    """On the default DB, severity is NOT pushed down (safe no-op)."""
    monkeypatch.setattr(search, "_extended_metadata_available", lambda: False)
    filters = search.build_search_filters({"severity": "high"})
    assert filters == {}


def test_build_search_filters_reads_attributes_from_object(monkeypatch):
    """VdrAnalysisKV exposes attributes, not dict keys."""
    monkeypatch.setattr(search, "_extended_metadata_available", lambda: True)

    class Opts:
        severity = "critical"
        exclude_malware = True

    filters = search.build_search_filters(Opts())
    assert filters == {"exclude_malware": True, "severity_threshold": "critical"}


def test_filters_reach_search_packages_batched_not_hydration(monkeypatch):
    """filters must reach pass-1 search_packages_batched (and the custom-data
    search_by_purl_like) and must NEVER be passed to get_cve_data_batched."""
    batched_kwargs = {}
    hydrate_calls = []

    def fake_batched(locators, batch_size=50, with_data=False, **kwargs):
        batched_kwargs.update(kwargs)
        batched_kwargs.setdefault("calls", 0)
        batched_kwargs["calls"] += 1
        yield [
            {
                "locator": locators[0],
                "result_count": 1,
                "results": [{"cve_id": "MAL-1", "vers": "1.0", "purl_prefix": "pkg:npm/a"}],
            },
        ]

    def fake_hydrate(db_conn, hits, search_str):
        # get_cve_data_batched must take NO filters kwarg
        hydrate_calls.append(search_str)
        return iter([{"cve_id": "MAL-1", "matched_by": search_str}])

    monkeypatch.setattr(search, "search_packages_batched", fake_batched)
    monkeypatch.setattr(search, "get_cve_data_batched", fake_hydrate)
    monkeypatch.setattr(vsearch, "CUSTOM_DATA_CACHE", [])
    monkeypatch.setattr(vdb6, "get", lambda read_only=True: (None, None))

    filters = {"exclude_malware": True}
    search.find_vulns_batched([{"purl": "pkg:npm/a@1.0.0", "version": "1.0.0"}], filters)
    # filters reached pass 1
    assert batched_kwargs.get("filters") == filters
    # hydration was invoked without a filters argument (positional signature)
    assert hydrate_calls
    sig = inspect.signature(fake_hydrate)
    assert "filters" not in sig.parameters


def test_exclude_malware_filter_drops_malware_rows(monkeypatch):
    """With exclude_malware pushed down, a term whose only hit is malware yields
    result_count 0 and is therefore not hydrated."""
    hydrate_calls = []

    def fake_batched(locators, batch_size=50, with_data=False, **kwargs):
        # Simulate vdb filtering the malware hit out in pass 1.
        yield [
            {"locator": locators[0], "result_count": 0, "results": []},
        ]

    def fake_hydrate(db_conn, hits, search_str):
        hydrate_calls.append(search_str)
        return iter([])

    monkeypatch.setattr(search, "search_packages_batched", fake_batched)
    monkeypatch.setattr(search, "get_cve_data_batched", fake_hydrate)
    monkeypatch.setattr(vsearch, "CUSTOM_DATA_CACHE", [])
    monkeypatch.setattr(vdb6, "get", lambda read_only=True: (None, None))

    results = search.find_vulns_batched(
        [{"purl": "pkg:npm/a@1.0.0", "version": "1.0.0"}], {"exclude_malware": True}
    )
    assert results == []
    assert hydrate_calls == []  # nothing to hydrate after filtering


def test_no_filters_is_parity_with_none(monkeypatch):
    """An empty filters dict and None must behave identically (no kwargs reach
    get_cve_data_batched; pass 1 receives an empty/None filters value)."""
    seen_filters = []

    def fake_batched(locators, batch_size=50, with_data=False, **kwargs):
        seen_filters.append(kwargs.get("filters"))
        yield [
            {
                "locator": locators[0],
                "result_count": 1,
                "results": [{"cve_id": "CVE-1", "vers": "1.0", "purl_prefix": "pkg:npm/a"}],
            },
        ]

    def fake_hydrate(db_conn, hits, search_str):
        return iter([{"cve_id": "CVE-1", "matched_by": search_str}])

    monkeypatch.setattr(search, "search_packages_batched", fake_batched)
    monkeypatch.setattr(search, "get_cve_data_batched", fake_hydrate)
    monkeypatch.setattr(vsearch, "CUSTOM_DATA_CACHE", [])
    monkeypatch.setattr(vdb6, "get", lambda read_only=True: (None, None))

    pkgs = [{"purl": "pkg:npm/a@1.0.0", "version": "1.0.0"}]
    none_results = search.find_vulns_batched(pkgs)
    empty_results = search.find_vulns_batched(pkgs, {})
    assert none_results == empty_results
    assert seen_filters == [None, {}]


def test_filters_reach_search_expanded_search_logic(monkeypatch):
    """In the serial path, filters must reach each search_logic call."""
    logic_calls = []

    def fake_logic(term, with_data=False, filters=None, **kwargs):
        logic_calls.append({"term": term, "filters": filters})
        return []

    monkeypatch.setattr(search, "search_by_any", fake_logic)
    search.search_expanded(
        {"purl": "pkg:npm/a@1.0.0", "version": "1.0.0", "name": "a"},
        False,
        None,
        {"exclude_malware": True},
    )
    assert logic_calls
    assert all(c["filters"] == {"exclude_malware": True} for c in logic_calls)
