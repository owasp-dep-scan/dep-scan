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
    explainer.explain_reachables("auto", test_data, "java", None)
    captured = capsys.readouterr()
    assert captured.err == ""
