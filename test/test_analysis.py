import json
import os

import pytest

from depscan.lib import analysis as analysis


@pytest.fixture
def test_data():
    results = []
    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "data", "depscan-java.json"
        ),
        mode="r",
    ) as fp:
        for line in fp:
            row = json.loads(line)
            results.append(row)
    return results


def test_suggestion(test_data):
    sug = analysis.suggest_version(test_data)
    assert sug == {
        "com.fasterxml.jackson.core:jackson-databind": "2.9.10.4",
    }


def test_best_fixed_location():
    assert analysis.best_fixed_location("1.0.0", "1.0.3", "1.0.2") == "1.0.3"
    assert analysis.best_fixed_location("1.0.0", "3.0.3", "1.0.2") == "1.0.2"
    assert analysis.best_fixed_location("1.0.0", None, "1.0.2") == "1.0.2"
    assert analysis.best_fixed_location("1.0.0", "4.0.0", None) == "4.0.0"
