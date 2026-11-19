"""``--bom-engine auto`` runs a local cdxgen before the cdxgen container image.

No real docker or cdxgen runs: the generators are fakes, and the probes that
find and version a local cdxgen are monkeypatched.
"""

import pytest

from depscan.lib import bom as bom_mod
from xbom_lib import BOMResult


class _FakeGenerator:
    """Records that it was chosen and writes the requested BOM."""

    name = "fake"
    chosen = []

    def __init__(self, src_dir, bom_file, logger=None, options=None):
        self.bom_file = bom_file

    def generate(self):
        type(self).chosen.append(type(self).name)
        with open(self.bom_file, "w", encoding="utf-8") as fp:
            fp.write("{}")
        return BOMResult(success=True, returncode=0)


class _LocalGenerator(_FakeGenerator):
    name = "local"


class _ImageGenerator(_FakeGenerator):
    name = "image"


@pytest.fixture()
def engines(monkeypatch):
    """Fake generators, a docker that is on PATH, and no CDXGEN_CMD."""
    _FakeGenerator.chosen = []
    monkeypatch.setattr(bom_mod, "CdxgenGenerator", _LocalGenerator)
    monkeypatch.setattr(bom_mod, "CdxgenImageBasedGenerator", _ImageGenerator)
    monkeypatch.setattr(bom_mod.shutil, "which", lambda cmd: "/usr/bin/docker")
    monkeypatch.setattr(bom_mod.sys, "platform", "linux")
    monkeypatch.delenv("CDXGEN_CMD", raising=False)
    monkeypatch.setattr(bom_mod, "_has_bundled_cdxgen", lambda: False)
    monkeypatch.setattr(bom_mod, "_refuse_old_cdxgen", lambda logger=None: True)
    return _FakeGenerator


def _local_cdxgen(monkeypatch, command="/usr/local/bin/cdxgen", version="13.8.0", accepted=True):
    monkeypatch.setattr(bom_mod, "find_cdxgen_cmd", lambda use_bin=True, logger=None: command)
    monkeypatch.setattr(
        bom_mod, "check_cdxgen_version", lambda cmd, logger=None: (accepted, version)
    )


def _scan(tmp_path, **options):
    return bom_mod.create_bom(
        str(tmp_path / "sbom.cdx.json"),
        str(tmp_path),
        {"bom_engine": "auto", "project_type": ["java"], **options},
    )


def test_local_cdxgen_at_the_minimum_is_used_before_the_image(engines, monkeypatch, tmp_path):
    _local_cdxgen(monkeypatch)
    assert _scan(tmp_path).success
    assert engines.chosen == ["local"]


def test_explicit_cdxgen_cmd_wins_without_a_version_probe(engines, monkeypatch, tmp_path):
    monkeypatch.setenv("CDXGEN_CMD", "/opt/cdxgen/bin/cdxgen")

    def unexpected(cmd, logger=None):
        raise AssertionError("an explicit CDXGEN_CMD is not probed before the run")

    monkeypatch.setattr(bom_mod, "find_cdxgen_cmd", lambda use_bin=True, logger=None: None)
    monkeypatch.setattr(bom_mod, "check_cdxgen_version", unexpected)
    assert _scan(tmp_path).success
    assert engines.chosen == ["local"]


@pytest.mark.parametrize(
    "command, accepted, version",
    [
        (False, False, None),  # no local cdxgen at all
        ("/usr/local/bin/cdxgen", False, "13.7.0"),  # too old
        ("/usr/local/bin/cdxgen", False, None),  # version unreadable
    ],
)
def test_image_is_the_fallback_without_a_suitable_local_cdxgen(
    engines, monkeypatch, tmp_path, command, accepted, version
):
    _local_cdxgen(monkeypatch, command=command, version=version, accepted=accepted)
    assert _scan(tmp_path).success
    assert engines.chosen == ["image"]


def test_explicit_image_engine_is_unchanged_by_a_local_cdxgen(engines, monkeypatch, tmp_path):
    _local_cdxgen(monkeypatch)
    assert _scan(tmp_path, bom_engine="CdxgenImageBasedGenerator").success
    assert engines.chosen == ["image"]


def test_explicit_local_engine_is_unchanged(engines, monkeypatch, tmp_path):
    _local_cdxgen(monkeypatch, command=False, accepted=False, version=None)
    assert _scan(tmp_path, bom_engine="CdxgenGenerator").success
    assert engines.chosen == ["local"]


def test_no_docker_and_no_local_cdxgen_still_picks_the_local_generator(
    engines, monkeypatch, tmp_path
):
    _local_cdxgen(monkeypatch, command=False, accepted=False, version=None)
    monkeypatch.setattr(bom_mod.shutil, "which", lambda cmd: None)
    assert _scan(tmp_path).success
    assert engines.chosen == ["local"]


def test_local_cdxgen_preferred_decision(monkeypatch):
    _local_cdxgen(monkeypatch)
    monkeypatch.delenv("CDXGEN_CMD", raising=False)
    assert bom_mod._local_cdxgen_preferred() is True
    _local_cdxgen(monkeypatch, accepted=False, version="13.7.9")
    assert bom_mod._local_cdxgen_preferred() is False
    monkeypatch.setenv("CDXGEN_CMD", "  ")
    assert bom_mod._local_cdxgen_preferred() is False
    monkeypatch.setenv("CDXGEN_CMD", "cdxgen-next")
    assert bom_mod._local_cdxgen_preferred() is True
