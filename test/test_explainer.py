import json
import os

import pytest

from depscan.lib import explainer


@pytest.fixture
def test_data():
    results = []
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


def test_explain_reachables(test_data):
    explainer.explain_reachables(test_data, {}, "java")
