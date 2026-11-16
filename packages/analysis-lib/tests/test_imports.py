"""Import-order regression tests for analysis_lib (see issue #545).

prioritize imports output at module level, so output must not depend on
prioritize. Each module is imported first in a fresh interpreter so a
reintroduced cycle fails here regardless of the import order used by the rest
of the test suite.
"""

import ast
import subprocess
import sys

import pytest

import analysis_lib.helpers as helpers


@pytest.mark.parametrize(
    "module",
    [
        "analysis_lib.helpers",
        "analysis_lib.config",
        "analysis_lib.endpoints",
        "analysis_lib.merge",
        "analysis_lib.packages",
        "analysis_lib.suggestions",
        "analysis_lib.advisory",
        "analysis_lib.output",
        "analysis_lib.prioritize",
        "analysis_lib.reachability",
        "analysis_lib.vdr",
    ],
)
def test_module_imports_first_in_fresh_interpreter(module):
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_output_does_not_import_prioritize():
    import analysis_lib.output as output

    with open(output.__file__, encoding="utf-8") as fp:
        tree = ast.parse(fp.read())
    imported = {
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module
    }
    assert "analysis_lib.prioritize" not in imported


def test_helpers_is_a_leaf_module():
    with open(helpers.__file__, encoding="utf-8") as fp:
        tree = ast.parse(fp.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert not node.module.startswith("analysis_lib"), node.module
        elif isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("analysis_lib"), alias.name
