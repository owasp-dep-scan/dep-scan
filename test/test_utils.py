import depscan.lib.utils as utils


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
