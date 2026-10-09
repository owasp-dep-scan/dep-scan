"""Generic document validation for the ``depscan-validate`` command.

Validates two kinds of documents dep-scan (and other tools) produce, with
auto-detection of which one a file is:

* **CSAF VEX** -- delegated to :func:`analysis_lib.vex.emit.validate`, which
  runs the bundled CSAF JSON Schema (with an RFC 3339 ``date-time`` check) plus
  the CSAF §6.1 mandatory *semantic* tests.
* **CycloneDX VDR/VEX** -- validated against the bundled CycloneDX JSON Schema
  matching the document's ``specVersion`` (1.4 through 1.7). Validation is fully
  offline: the schema's sibling ``$ref`` files (``spdx``, ``jsf-0.82`` and, for
  1.7, ``cryptography-defs``) are all resolved from bundled copies of the
  official CycloneDX schemas, so the full SPDX license enumeration is enforced.

All validation is offline and never touches the network.
"""

import json
import re
from importlib import resources
from typing import Any, Dict, List, Optional, Tuple

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

FORMAT_CSAF = "csaf"
FORMAT_CYCLONEDX = "cyclonedx"

# jsonschema only checks ``format: date-time`` when an optional RFC 3339 library
# is installed; without it the check is a silent no-op, so a CycloneDX timestamp
# missing its timezone would pass. We register our own RFC 3339 check (lenient
# on the case of ``T``/``Z`` per RFC 3339, unlike the stricter CSAF §2.3 rule).
_RFC3339_LENIENT = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)
CYCLONEDX_FORMAT_CHECKER = FormatChecker()


@CYCLONEDX_FORMAT_CHECKER.checks("date-time")
def _check_cdx_date_time(value: Any) -> bool:
    if not isinstance(value, str):
        return True
    return bool(_RFC3339_LENIENT.match(value))


_CYCLONEDX_SCHEMAS = {
    "1.4": "bom-1.4.schema.json",
    "1.5": "bom-1.5.schema.json",
    "1.6": "bom-1.6.schema.json",
    "1.7": "bom-1.7.schema.json",
}
_DEFAULT_CDX_VERSION = "1.6"
# Sibling schemas referenced by the CycloneDX bom schemas, bundled from the
# official CycloneDX specification so validation resolves them offline.
_CYCLONEDX_REFS = (
    "spdx.schema.json",
    "jsf-0.82.schema.json",
    "cryptography-defs.schema.json",
)


def detect_format(doc: Any) -> Optional[str]:
    """Best-effort detection of a document's format from its contents.

    Callers may pass unparsed input, hence the isinstance guard below.
    """
    if not isinstance(doc, dict):
        return None
    if str(doc.get("bomFormat", "")).lower() == "cyclonedx" or "specVersion" in doc:
        return FORMAT_CYCLONEDX
    document = doc.get("document")
    if isinstance(document, dict) and ("csaf_version" in document or "category" in document):
        return FORMAT_CSAF
    if "vulnerabilities" in doc and "product_tree" in doc:
        return FORMAT_CSAF
    return None


def _cyclonedx_data():
    return resources.files("analysis_lib.data").joinpath("cyclonedx")


def _cyclonedx_registry() -> Registry:
    """Resolve the CycloneDX schema's sibling ``$ref`` files from bundled copies.

    Each sibling schema is registered under both its own ``$id`` and its bare
    filename so the bom schema's relative ``$ref`` (e.g. ``spdx.schema.json``)
    resolves whether or not the base URI is applied.
    """
    resources_list = []
    data = _cyclonedx_data()
    for filename in _CYCLONEDX_REFS:
        ref_file = data.joinpath(filename)
        if not ref_file.is_file():
            continue
        with ref_file.open("r") as fh:
            contents = json.load(fh)
        resource = Resource.from_contents(contents, DRAFT7)
        resources_list.append((filename, resource))
        schema_id = contents.get("$id")
        if schema_id and schema_id != filename:
            resources_list.append((schema_id, resource))
    return Registry().with_resources(resources_list)


def validate_cyclonedx(doc: Dict[str, Any]) -> List[str]:
    """Validate a CycloneDX VDR/VEX document against the bundled schema."""
    spec_version = str(doc.get("specVersion") or _DEFAULT_CDX_VERSION)
    filename = _CYCLONEDX_SCHEMAS.get(spec_version)
    if not filename:
        return [
            f"<doc>: unsupported CycloneDX specVersion {spec_version!r} "
            f"(supported: {', '.join(sorted(_CYCLONEDX_SCHEMAS))})"
        ]
    with _cyclonedx_data().joinpath(filename).open("r") as fh:
        schema = json.load(fh)
    validator = Draft7Validator(
        schema, registry=_cyclonedx_registry(), format_checker=CYCLONEDX_FORMAT_CHECKER
    )
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    return [f"{'/'.join(str(p) for p in e.path) or '<doc>'}: {e.message}" for e in errors]


def validate_document(
    doc: Dict[str, Any],
    doc_format: str = "auto",
    csaf_version: Optional[str] = None,
) -> Tuple[Optional[str], List[str]]:
    """Validate ``doc``, auto-detecting the format unless one is forced.

    :param doc_format: ``"auto"`` (default), ``"csaf"`` or ``"cyclonedx"``.
    :param csaf_version: force a CSAF schema version; otherwise taken from the
        document (``document.csaf_version``), defaulting to ``"2.1"``.
    :return: ``(detected_format, errors)``. ``detected_format`` is ``None`` when
        the format could not be determined; ``errors`` then explains why.
    """
    resolved = doc_format if doc_format != "auto" else detect_format(doc)
    if resolved == FORMAT_CSAF:
        # Imported lazily so CycloneDX-only validation never pulls in the CSAF
        # schema machinery.
        from analysis_lib.vex.emit import validate as validate_csaf

        version = csaf_version or (doc.get("document") or {}).get("csaf_version") or "2.1"
        return FORMAT_CSAF, validate_csaf(doc, str(version))
    if resolved == FORMAT_CYCLONEDX:
        return FORMAT_CYCLONEDX, validate_cyclonedx(doc)
    return None, [
        "<doc>: could not detect document format; pass --format {csaf,cyclonedx} "
        "to force one (expected a CSAF or CycloneDX document)"
    ]
