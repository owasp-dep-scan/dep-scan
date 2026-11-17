"""Tests for :mod:`depscan.commands.translate`, the v6 to v7 translator."""

import argparse

from depscan.cli_options import build_parser
from depscan.commands.translate import (
    OPTION_TABLE,
    option_table_markdown,
    translate,
)


def _parser_option_flags():
    """Every option flag the v6 parser registers, except help."""
    parser = build_parser()
    flags = set()
    for action in parser._actions:
        if "-h" in action.option_strings or "--help" in action.option_strings:
            continue
        flags.update(action.option_strings)
    return flags


def test_every_parser_option_has_a_row():
    table_flags = {flag for row in OPTION_TABLE for flag in row.v6_flags}
    parser_flags = _parser_option_flags()
    assert "--config" in parser_flags
    missing = sorted(parser_flags - table_flags)
    assert not missing, f"v6 options with no translator row: {missing}"


def test_table_rows_name_only_parser_options():
    table_flags = {flag for row in OPTION_TABLE for flag in row.v6_flags}
    stale = sorted(table_flags - _parser_option_flags())
    assert not stale, f"rows for options the parser does not register: {stale}"


def test_row_dests_match_the_parser():
    parser = build_parser()
    dests = {
        action.dest
        for action in parser._actions
        if action.dest is not argparse.SUPPRESS
    }
    for row in OPTION_TABLE:
        if row.dest is not None:
            assert row.dest in dests, row.v6_flags


def test_plain_src_scan_translates_to_scan_with_a_target():
    assert (
        translate(["--src", "/app", "--reports-dir", "/app/reports"])
        == "depscan scan /app --reports-dir /app/reports"
    )


def test_bom_dir_scan_moves_reports_dir_to_its_long_name():
    assert translate(["--bom-dir", "x", "-o", "y"]) == "depscan scan x --reports-dir y"


def test_purl_becomes_the_target():
    assert translate(["--purl", "pkg:pypi/requests@2.31.0"]) == (
        "depscan scan pkg:pypi/requests@2.31.0"
    )


def test_server_options_switch_the_verb_to_serve():
    assert translate(["--server", "--server-host", "0.0.0.0"]) == (
        "depscan serve --server-host 0.0.0.0"
    )


def test_server_alone_translates_to_the_serve_verb():
    assert translate(["--server"]) == "depscan serve"


def test_profile_is_renamed_and_flags_follow_v6_registration_order():
    assert translate(["--profile", "research", "-t", "java"]) == (
        "depscan scan --bom-profile research --type java"
    )


def test_risk_audit_becomes_the_supply_chain_check():
    assert translate(["--risk-audit"]) == "depscan scan --checks supply-chain"


def test_version_flag_becomes_the_version_verb():
    assert translate(["-v"]) == "depscan version"
    assert translate(["--version"]) == "depscan version"


def test_config_keeps_its_name_on_scan():
    assert translate(["--config", ".config/depscan-dev.toml"]) == (
        "depscan scan --config .config/depscan-dev.toml"
    )


def test_short_flags_emit_the_long_v7_name():
    assert translate(["-q"]) == "depscan scan --quiet"


def test_boolean_flag_emits_no_value():
    assert translate(["--no-suggest"]) == "depscan scan --no-suggest"


def test_multi_value_option_emits_every_value():
    assert translate(["-t", "java", "python", "--deep"]) == (
        "depscan scan --type java python --deep"
    )


def test_vdb_selection_flags_are_emitted_on_serve():
    assert translate(["--server", "--vdb-flavor", "app-only"]) == (
        "depscan serve --vdb-flavor app-only"
    )


def test_unknown_tokens_are_dropped_not_fatal():
    assert translate(["--src", ".", "downloads", "ghcr.io/x"]) == "depscan scan ."
    assert translate(["--src", ".", "--frobnicate", "value"]) == "depscan scan ."


def test_help_is_not_translated():
    assert translate(["-h"]) is None
    assert translate(["--help"]) is None


def test_argv_with_nothing_translatable_returns_none():
    assert translate([]) is None


def test_option_table_markdown_lists_every_option():
    markdown = option_table_markdown()
    for flag in _parser_option_flags():
        assert f"`{flag}`" in markdown


def test_option_table_markdown_is_a_well_formed_table():
    lines = option_table_markdown().splitlines()
    assert lines[0] == "| v6 option | v7 equivalent | note |"
    assert lines[1] == "| --- | --- | --- |"
    assert len(lines) == len(OPTION_TABLE) + 2
    for line in lines[2:]:
        assert line.startswith("| ") and line.endswith(" |")
        assert line.count("|") == 4
