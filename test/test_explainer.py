import json
import os

import pytest

from depscan.lib import explainer


@pytest.fixture
def test_data():
    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "data",
            "reachables.slices.json",
        ),
        mode="r",
        encoding="utf-8",
    ) as fp:
        return json.load(fp)


def test_explain_reachables(test_data, capsys):
    explainer.explain_reachables("auto", test_data, "java", {}, None)
    captured = capsys.readouterr()
    assert captured.err == ""


def test_print_endpoints_handles_invalid_spec(monkeypatch, capsys):
    monkeypatch.setattr(explainer, "json_load", lambda *_args, **_kwargs: None)

    pattern_methods = explainer.print_endpoints("invalid-openapi.json")

    assert dict(pattern_methods) == {}
    captured = capsys.readouterr()
    assert captured.err == ""


def test_explain_reachables_handles_non_list_input(capsys):
    has_explanation, has_crypto_flows, tips = explainer.explain_reachables(
        "auto", None, "python", None, {}
    )

    assert has_explanation is False
    assert has_crypto_flows is False
    assert tips == "## Secure Design Tips"
    captured = capsys.readouterr()
    assert captured.err == ""


def test_explain_flows_handles_non_string_code_and_list_tags(capsys):
    tree, added_ids, comment, source_sink_desc, source_code_str, sink_code_str, *_rest = (
        explainer.explain_flows(
            "auto",
            [
                {
                    "id": 1,
                    "label": "METHOD_PARAMETER_IN",
                    "name": "user_input",
                    "parentFileName": "src/app.py",
                    "parentMethodName": None,
                    "lineNumber": 10,
                    "code": None,
                    "tags": ["crypto", "RESOLVED_MEMBER"],
                },
                {
                    "id": 2,
                    "label": "RETURN",
                    "parentFileName": "src/app.py",
                    "parentMethodName": "handler",
                    "lineNumber": 22,
                    "code": 12345,
                    "tags": None,
                },
            ],
            None,
            "python",
            None,
            {},
        )
    )

    assert tree is not None
    assert added_ids == ["1", "2"]
    assert comment == ""
    assert source_sink_desc
    assert source_code_str == ""
    assert sink_code_str == "12345"
    captured = capsys.readouterr()
    assert captured.err == ""
