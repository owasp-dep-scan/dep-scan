import os

from depscan.lib.binary import parse


def test_parse():
    if os.path.exists("/bin/ls"):
        metadata = parse("/bin/ls")
        print(metadata)
        assert metadata
