from depscan.lib import utils as utils


def test_cleanup_license_string():
    data = utils.cleanup_license_string("MIT")
    assert data == "MIT"
    data = utils.cleanup_license_string("MIT/GPL-3.0")
    assert data == "MIT OR GPL-3.0"
    data = utils.cleanup_license_string("MIT / GPL-3.0")
    assert data == "MIT OR GPL-3.0"
    data = utils.cleanup_license_string("MIT & GPL-3.0")
    assert data == "MIT OR GPL-3.0"
    data = utils.cleanup_license_string("MIT&GPL-3.0")
    assert data == "MIT OR GPL-3.0"
    data = utils.cleanup_license_string("(MIT)")
    assert data == "MIT"
    data = utils.cleanup_license_string("(MIT OR GPL-2.0")
    assert data == "MIT OR GPL-2.0"


def test_max_version():
    ret = utils.max_version("1.0.0")
    assert ret == "1.0.0"
    ret = utils.max_version(["1.0.0", "1.0.1", "2.0.0"])
    assert ret == "2.0.0"
    ret = utils.max_version(["1.1.0", "2.1.1", "2.0.0"])
    assert ret == "2.1.1"
    ret = utils.max_version(
        ["2.9.10.1", "2.9.10.4", "2.9.10", "2.8.11.5", "2.8.11", "2.8.11.2"]
    )
    assert ret == "2.9.10.4"
    ret = utils.max_version(["2.9.10", "2.9.10.4"])
    assert ret == "2.9.10.4"
