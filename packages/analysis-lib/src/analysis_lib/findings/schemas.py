"""Access to the published dep-scan finding schemas.

The JSON Schema files live in the schemas/ directory next to this module and
ship inside the wheel as package data. Other implementations read the same
files, so this module only loads and validates: the schema is the contract,
not this code.
"""

import json
import re
from importlib import resources
from typing import Any, Dict, List

from jsonschema import Draft202012Validator, FormatChecker

_SCHEMA_PACKAGE = "analysis_lib.findings"
_SCHEMA_DIR = "schemas"
_SCHEMA_FILES = {
    "finding": "depscan-finding.schema.json",
}

# jsonschema checks format: date-time only when a checker for it is
# registered; without one a timestamp missing its zone would pass silently.
# The pattern mirrors the lenient RFC 3339 check in analysis_lib.validation
# (case-insensitive T and Z per RFC 3339, timezone required).
_RFC3339_LENIENT = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)
FORMAT_CHECKER = FormatChecker()


@FORMAT_CHECKER.checks("date-time")
def _check_date_time(value: Any) -> bool:
    if not isinstance(value, str):
        return True
    return bool(_RFC3339_LENIENT.match(value))


class SchemaValidationError(ValueError):
    """A document did not satisfy the named schema."""


def schema_names() -> List[str]:
    """Names of the published schemas, in the order the CLI prints them."""
    return list(_SCHEMA_FILES)


def load_schema(name: str) -> Dict[str, Any]:
    """Parse the named schema from the bundled files.

    Raises ValueError for a name that is not published.
    """
    filename = _SCHEMA_FILES.get(name)
    if not filename:
        raise ValueError(
            f"unknown schema {name!r}; published schemas: {', '.join(schema_names())}"
        )
    schema_path = resources.files(_SCHEMA_PACKAGE).joinpath(_SCHEMA_DIR).joinpath(filename)
    return json.loads(schema_path.read_text(encoding="utf-8"))


def validate(name: str, document: Any) -> None:
    """Validate a document against the named schema.

    Returns when the document is valid and raises SchemaValidationError whose
    message lists every violation, so a caller sees all problems at once
    instead of fixing them one by one.
    """
    schema = load_schema(name)
    validator = Draft202012Validator(schema, format_checker=FORMAT_CHECKER)
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.path))
    if errors:
        lines = [
            f"{'/'.join(str(p) for p in error.path) or '<doc>'}: {error.message}"
            for error in errors
        ]
        raise SchemaValidationError(
            f"the {name} schema rejected the document:\n" + "\n".join(lines)
        )
