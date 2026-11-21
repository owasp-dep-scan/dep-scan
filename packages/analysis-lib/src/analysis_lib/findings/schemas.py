"""Access to the published dep-scan finding schemas.

The JSON Schema files live in the schemas/ directory next to this module and
ship inside the wheel as package data. Other implementations read the same
files, so this module only loads and validates: the schema is the contract,
not this code.

A schema's name is its file name without ``.schema.json``:
``depscan-scan-output`` for ``depscan-scan-output.schema.json``. Each schema's
``$id`` is ``urn:owasp:depscan:schema:<name without depscan->:1``; the finding,
doctor and manifest identifiers predate the output schemas and are unchanged,
except the finding schema, which is at ``:2`` since its exploitability axes
dropped Pressure and gained sources, and the manifest schema, which is at
``:2`` since its analyzer entries gained their caveats array. The evidence
schema is the one file that lives outside this package: it ships with the
``analysis_lib.evidence`` package, whose ``schemas/`` directory it
documents, and the loader serves it from there without moving the others.
The fingerprint test vectors next to the schemas are data, not a schema, and
are not listed. The legacy short name ``finding`` and the short name
``evidence`` stay accepted as aliases so existing callers keep working. The
published names are listed in registration order: the document schemas
first, then the output schemas verb by verb, then the input and output
schemas of the ``depscan mcp`` tools, then the error schema.
"""

import json
import re
from importlib import resources
from typing import Any, Dict, List

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

_SCHEMA_PACKAGE = "analysis_lib.findings"
_SCHEMA_DIR = "schemas"

#: The evidence schema is served from the analysis_lib.evidence package,
#: whose schemas directory it documents.
_EVIDENCE_SCHEMA_FILE = "depscan-evidence.schema.json"
_EVIDENCE_SCHEMA_PACKAGE = "analysis_lib.evidence"

#: Every published schema file, in the order the CLI lists the names.
_SCHEMA_FILES = (
    # The document schemas: the shapes a scan directory publishes.
    "depscan-finding.schema.json",
    "depscan-doctor.schema.json",
    "depscan-manifest.schema.json",
    # The data-file schema: the shape of one line of the scan directory's
    # evidence store.
    "depscan-evidence.schema.json",
    # The data-file schema: the shape of the exploitability rule table a
    # scan grades with and an organisation may replace.
    "depscan-exploitability-rules.schema.json",
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
    # The `depscan mcp` tools, each tool's input schema then its output
    # schema, in the order the server registers the tools.
    "depscan-mcp-scan_summary-input.schema.json",
    "depscan-mcp-scan_summary-output.schema.json",
    "depscan-mcp-list_findings-input.schema.json",
    "depscan-mcp-list_findings-output.schema.json",
    "depscan-mcp-get_finding-input.schema.json",
    "depscan-mcp-get_finding-output.schema.json",
    "depscan-mcp-explain_finding-input.schema.json",
    "depscan-mcp-explain_finding-output.schema.json",
    "depscan-mcp-coverage-input.schema.json",
    "depscan-mcp-coverage-output.schema.json",
    "depscan-mcp-list_components-input.schema.json",
    "depscan-mcp-list_components-output.schema.json",
    "depscan-mcp-diff_scans-input.schema.json",
    "depscan-mcp-diff_scans-output.schema.json",
    "depscan-mcp-doctor-input.schema.json",
    "depscan-mcp-doctor-output.schema.json",
    "depscan-mcp-vdb_status-input.schema.json",
    "depscan-mcp-vdb_status-output.schema.json",
    "depscan-mcp-run_scan-input.schema.json",
    "depscan-mcp-run_scan-output.schema.json",
    # The shared error document.
    "depscan-error.schema.json",
)

#: Names the published schemas keep answering to that are no longer file
#: stems. The short name of the finding schema predates the file-stem rule;
#: the evidence schema's short name reads better on the command line.
_ALIASES = {
    "finding": "depscan-finding",
    "evidence": "depscan-evidence",
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
    """The published name of a schema file: its name without .schema.json."""
    return filename[: -len(".schema.json")]


#: Maps every published schema name (its file stem) to its file.
_STEM_TO_FILE = {_schema_name(filename): filename for filename in _SCHEMA_FILES}


def schema_names() -> List[str]:
    """Names of the published schemas, in the order the CLI prints them."""
    return [_schema_name(filename) for filename in _SCHEMA_FILES]


def published_files() -> List[str]:
    """The schema files the loader serves, from every bundled directory."""
    directory = resources.files(_SCHEMA_PACKAGE).joinpath(_SCHEMA_DIR)
    names = [item.name for item in directory.iterdir() if item.name.endswith(".schema.json")]
    names.append(_EVIDENCE_SCHEMA_FILE)
    return sorted(names)


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
    package = _EVIDENCE_SCHEMA_PACKAGE if filename == _EVIDENCE_SCHEMA_FILE else _SCHEMA_PACKAGE
    schema_path = resources.files(package).joinpath(_SCHEMA_DIR).joinpath(filename)
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
    ``depscan-doctor.schema.json#/$defs/...``, and the output schemas refer to
    the document schemas the same way. Each resource is registered under its
    file name and its ``$id``, so the validator follows either form of
    reference without copying the definitions.
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
