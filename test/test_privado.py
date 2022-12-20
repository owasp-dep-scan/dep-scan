import os
import pytest

from depscan.lib import privado


@pytest.fixture
def test_data():
    return os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "crapi", "privado.json"
    )


def test_parse(test_data):
    service = privado.process_report(test_data)
    assert service
    assert service["name"]
    assert service["data"]
    assert len(service["data"]) == 11
    assert service["endpoints"]
    assert len(service["endpoints"]) == 11
