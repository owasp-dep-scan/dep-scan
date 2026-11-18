"""Access to the published dep-scan finding schemas.

The JSON Schema files live in the schemas/ directory next to this module and
ship inside the wheel as package data. Other implementations read the same
files, so this module only loads and validates: the schema is the contract,
not this code.

A schema's name is its file name without ``.json``: ``depscan-scan-output``
for ``depscan-scan-output.schema.json``, ``depscan-finding-fingerprint-vectors``
for the vectors file. The legacy short name ``finding`` stays accepted as an
alias so existing callers keep working. The published names are listed in
registration order: the document schemas first, then the output schemas verb
by verb, then the error schema.
"""

import json
import re
from importlib import resources
from typing import Any, Dict, List

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

_SCHEMA_PACKAGE = "analysis_lib.findings"
_SCHEMA_DIR = "schemas"

#: Every published schema file, in the order the CLI lists the names.
_SCHEMA_FILES = (
    # The document schemas: the shapes a scan directory publishes.
    "depscan-finding.schema.json",
    "depscan-doctor.schema.json",
    "depscan-manifest.schema.json",
    "depscan-finding-fingerprint-vectors.json",
    # The output schemas, verb by verb in the verb registry's order, each
    # verb's subcommands in the order the verb registers them.
    "depscan-scan-output.schema.json",
    "depscan-report-output.schema.json",
    "depscan-vdb-download-output.schema.json",
    "depscan-vdb-info-output.schema.json",
    "depscan-vdb-path-output.schema.json",
    "depscan-doctor-output.schema.json",
    "depscan-schema-output.schema.json",
    "depscan-config-show-output.schema.json",
    "depscan-config-init-output.schema.json",
    "depscan-serve-output.schema.json",
    "depscan-validate-output.schema.json",
    "depscan-version-output.schema.json",
    "depscan-help-output.schema.json",
    # The shared error document.
    "depscan-error.schema.json",
)

#: Names the published schemas keep answering to that are no longer file
#: stems. The short name of the finding schema predates the file-stem rule.
_ALIASES = {
    "finding": "depscan-finding",
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


def _schema_name(filename: str) -> str:
    """The published name of a schema file: its name without .json."""
    if filename.endswith(".schema.json"):
        return filename[: -len(".schema.json")]
    return filename[: -len(".json")]


#: Maps every published schema name (its file stem) to its file.
_STEM_TO_FILE = {_schema_name(filename): filename for filename in _SCHEMA_FILES}


def schema_names() -> List[str]:
    """Names of the published schemas, in the order the CLI prints them."""
    return [_schema_name(filename) for filename in _SCHEMA_FILES]


def published_files() -> List[str]:
    """The file names in the bundled schemas directory."""
    directory = resources.files(_SCHEMA_PACKAGE).joinpath(_SCHEMA_DIR)
    return sorted(item.name for item in directory.iterdir() if item.name.endswith(".json"))


def _resolve(name: str) -> str:
    """The file of a published schema name, aliases included."""
    filename = _STEM_TO_FILE.get(_ALIASES.get(name, name))
    if not filename:
        raise ValueError(
            f"unknown schema {name!r}; published schemas: {', '.join(schema_names())}"
        )
    return filename


def schema_summaries() -> List[Dict[str, str]]:
    """Every published schema as its name, $id and title.

    The document ``depscan schema --format json`` prints, in the order the
    text listing prints the names.
    """
    summaries = []
    for filename in _SCHEMA_FILES:
        schema = _read(filename)
        summaries.append(
            {"name": _schema_name(filename), "$id": schema["$id"], "title": schema["title"]}
        )
    return summaries


def _read(filename: str) -> Dict[str, Any]:
    schema_path = resources.files(_SCHEMA_PACKAGE).joinpath(_SCHEMA_DIR).joinpath(filename)
    return json.loads(schema_path.read_text(encoding="utf-8"))


def load_schema(name: str) -> Dict[str, Any]:
    """Parse the named schema from the bundled files.

    Raises ValueError for a name that is not published.
    """
    return _read(_resolve(name))


def _registry() -> Registry:
    """Every published schema, retrievable under its file name and its $id.

    A schema may reference a sibling schema by file name, as the manifest
    schema reuses the doctor definitions through
    ``depscan-doctor.schema.json#/$defs/...``. Because every schema carries an
    absolute ``$id``, such a reference resolves to ``$id`` of the target file,
    so each resource is registered under both names and the validator follows
    the reference without copying the definitions.
    """
    registry = Registry()
    for filename in published_files():
        schema = _read(filename)
        resource = Resource.from_contents(schema)
        registry = registry.with_resource(filename, resource)
        schema_id = schema.get("$id")
        if schema_id:
            registry = registry.with_resource(schema_id, resource)
    return registry


def validate(name: str, document: Any) -> None:
    """Validate a document against the named schema.

    Returns when the document is valid and raises SchemaValidationError whose
    message lists every violation, so a caller sees all problems at once
    instead of fixing them one by one.
    """
    schema = load_schema(name)
    validator = Draft202012Validator(schema, registry=_registry(), format_checker=FORMAT_CHECKER)
    errors = sorted(validator.iter_errors(document), key=lambda e: [str(p) for p in e.path])
    if errors:
        lines = [
            f"{'/'.join(str(p) for p in error.path) or '<doc>'}: {error.message}"
            for error in errors
        ]
        raise SchemaValidationError(
            f"the {name} schema rejected the document:\n" + "\n".join(lines)
        )
