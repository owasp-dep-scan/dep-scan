import pytest
from xbom_lib import plugins as plugins_mod


@pytest.fixture(autouse=True)
def no_cdxgen_install(monkeypatch):
    """Keep the plugin finder tests independent of the machine they run on.

    The finders also look in the plugins directory beside the cdxgen found on
    PATH. A developer machine usually has one, so without this a test that
    expects "not found" would pick up the real golem, rusi or kosi. Tests that
    exercise the discovery put the real lookup back.
    """
    monkeypatch.setattr(plugins_mod, "resolve_cdxgen_path", lambda: None)
