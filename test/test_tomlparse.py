"""Tests for :mod:`depscan.lib.tomlparse` CLI/TOML argument precedence."""

from depscan.lib.tomlparse import ArgumentParser


def _parse_with_config(parser, toml_text, cli_args, tmp_path):
    """Parse ``cli_args`` with a TOML config written to ``tmp_path``."""
    config = tmp_path / "depscan.toml"
    config.write_text(toml_text)
    return parser.parse_args([*cli_args, "--config", str(config)])


def test_cli_overrides_hyphenated_toml_key(tmp_path):
    """Command-line must win over TOML even when the TOML key is hyphenated.

    ``changed_args`` holds argparse's underscore dest names, so a hyphenated
    TOML key mirroring the CLI flag (e.g. ``risk-audit``) must be normalized
    before the precedence check; otherwise it would override an explicit CLI
    value. Regression test for issue #513.
    """
    parser = ArgumentParser()
    parser.add_argument("--risk-audit", action="store_true")
    args = _parse_with_config(parser, "risk-audit = false\n", ["--risk-audit"], tmp_path)
    assert args.risk_audit is True


def test_hyphenated_toml_key_fills_when_absent_on_cli(tmp_path):
    """A hyphenated TOML key still populates the value when unset on the CLI."""
    parser = ArgumentParser()
    parser.add_argument("--risk-audit", action="store_true")
    args = _parse_with_config(parser, "risk-audit = true\n", [], tmp_path)
    assert args.risk_audit is True


def test_underscore_toml_key_fills_when_absent_on_cli(tmp_path):
    """Underscore TOML keys keep working unchanged."""
    parser = ArgumentParser()
    parser.add_argument("--foo-bar")
    args = _parse_with_config(parser, 'foo_bar = "fromtoml"\n', [], tmp_path)
    assert args.foo_bar == "fromtoml"


def test_cli_overrides_hyphenated_toml_string_key(tmp_path):
    """CLI wins for hyphenated string-valued keys as well."""
    parser = ArgumentParser()
    parser.add_argument("--bom-dir", default="/default")
    args = _parse_with_config(
        parser, 'bom-dir = "/fromtoml"\n', ["--bom-dir", "/fromcli"], tmp_path
    )
    assert args.bom_dir == "/fromcli"


def test_hyphenated_toml_string_key_fills_when_absent_on_cli(tmp_path):
    """A hyphenated string TOML key fills the value when unset on the CLI."""
    parser = ArgumentParser()
    parser.add_argument("--bom-dir", default="/default")
    args = _parse_with_config(parser, 'bom-dir = "/fromtoml"\n', [], tmp_path)
    assert args.bom_dir == "/fromtoml"


def test_cli_wins_when_explicit_value_equals_default(tmp_path):
    """CLI wins even when the value passed equals the argument's default.

    Detecting "changed" arguments by comparing against the default value
    misses a flag explicitly passed with its default value (e.g.
    ``--level info`` when ``info`` is the default). The TOML value then
    wrongly overrode the explicit CLI value. This checks the sentinel-based
    detection treats such arguments as explicitly supplied.
    """
    parser = ArgumentParser()
    parser.add_argument("--level", default="info")
    args = _parse_with_config(parser, 'level = "high"\n', ["--level", "info"], tmp_path)
    assert args.level == "info"


def test_store_true_default_true_cli_wins(tmp_path):
    """A store_true flag whose default is already True is still detected.

    Passing the flag leaves the value at its default (True), so a value
    comparison could not tell it apart from an unset flag. Sentinel
    detection recognizes it as supplied and keeps the CLI value.
    """
    parser = ArgumentParser()
    parser.add_argument("--deep", action="store_true", default=True)
    args = _parse_with_config(parser, "deep = false\n", ["--deep"], tmp_path)
    assert args.deep is True


def test_no_hyphenated_attribute_is_set(tmp_path):
    """TOML values are stored only under the normalized dest name."""
    parser = ArgumentParser()
    parser.add_argument("--bom-dir", default="/default")
    args = _parse_with_config(parser, 'bom-dir = "/fromtoml"\n', [], tmp_path)
    assert not hasattr(args, "bom-dir")
    assert args.bom_dir == "/fromtoml"
