"""Commands that never touch binaries import none of the binary analysis stack.

Importing blint pulls in lief and costs a large part of a second, and every
dep-scan invocation starts from ``depscan.cli``, so the blint import waits
for the code paths that need it: binary BOM generation, and the blintdb
location, which reads blint's config module without the package. Each check
runs in a fresh interpreter, so an earlier import cannot hide the cost.
"""

import subprocess
import sys


def _run(code):
    return subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=180
    )


def test_importing_the_cli_does_not_import_blint_or_lief():
    result = _run(
        "import sys\n"
        "import depscan.cli\n"
        "def heavy():\n"
        "    return [n for n in ('blint', 'blint.api', 'blint.lib', 'lief') if n in sys.modules]\n"
        "assert not heavy(), f'imported {heavy()}'\n"
        "import depscan.lib.bom\n"
        "assert not heavy(), f'imported {heavy()}'\n"
    )
    assert result.returncode == 0, result.stderr


def test_blintdb_status_reads_the_path_without_importing_blint():
    result = _run(
        "import sys\n"
        "from depscan.lib import doctor\n"
        "status = doctor._blintdb_status()\n"
        "assert status.name == 'blintdb'\n"
        "assert 'blint' not in sys.modules, 'blint imported'\n"
        "assert 'lief' not in sys.modules, 'lief imported'\n"
        # The standalone config load must not leave a blint.config entry
        # without its package, which would break a later import blint.config.
        "assert 'blint.config' not in sys.modules, 'blint.config left behind'\n"
        "import blint.config\n"
        "assert blint.config.BLINTDB_LOC == doctor._BLINTDB_LOC_AT_IMPORT\n"
    )
    assert result.returncode == 0, result.stderr


def test_blint_generator_still_resolves_through_the_module_attribute():
    # Positive control for the lazy attribute: it hands out the real class,
    # not a stub, and the create_blint_bom caller sees the same object.
    result = _run(
        "from depscan.lib.bom import BlintGenerator\n"
        "from xbom_lib.blint import BlintGenerator as direct\n"
        "assert BlintGenerator is direct\n"
    )
    assert result.returncode == 0, result.stderr
