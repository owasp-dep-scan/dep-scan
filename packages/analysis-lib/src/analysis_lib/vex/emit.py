"""CSAF emit: IO, path safety and schema validation.

This is the only module in :mod:`analysis_lib.vex` that touches the
filesystem. It guarantees two safety invariants:

* **Never overwrite the VDR/BOM.** The output path is derived as
  ``<base>.csaf.json`` and an assertion blocks generation when it would
  collide with the supplied BOM/VDR path.
* **Single-run generation.** A missing ``csaf.toml`` does not abort the run;
  a starter is written as ``csaf.toml.sample`` into the reports directory
  (never into the scanned project) and generation continues with sensible
  defaults.

Validation runs against the bundled official CSAF schema so a broken document
is loud rather than silent.
"""

import json
import logging
import os
from decimal import Decimal, InvalidOperation
from importlib import resources
from typing import Any, Dict, List, Optional, Tuple

import toml
from jsonschema import Draft202012Validator, FormatChecker, validators
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from analysis_lib import get_version
from analysis_lib.vex.csaf import build_csaf
from analysis_lib.vex.dates import is_rfc3339
from analysis_lib.vex.semantic import validate_semantic

LOG = logging.getLogger(__name__)


def _multiple_of(validator, divisor, instance, schema):
    """A ``multipleOf`` check that is exact for one-decimal numbers.

    The stock jsonschema check evaluates ``instance / divisor`` in binary
    floating point, so legitimate values such as a CVSS score of ``6.3`` fail
    against the CVSS ``multipleOf: 0.1`` constraint (``6.3 % 0.1 != 0`` in
    IEEE-754). Comparing via :class:`~decimal.Decimal` built from the string
    form validates such values correctly.
    """
    if isinstance(instance, bool) or not isinstance(instance, (int, float)):
        return
    try:
        quotient = Decimal(str(instance)) / Decimal(str(divisor))
    except (InvalidOperation, ZeroDivisionError):
        return
    if quotient != quotient.to_integral_value():
        yield ValidationError(f"{instance!r} is not a multiple of {divisor}")


# Validator that keeps CSAF's Draft 2020-12 semantics but uses the exact
# ``multipleOf`` above so valid CVSS scores are never rejected.
CsafValidator = validators.extend(Draft202012Validator, {"multipleOf": _multiple_of})

# jsonschema only checks ``format: date-time`` when an optional RFC 3339 library
# is installed; without it the check is a silent no-op (this is why timezone-less
# timestamps passed validation in issue #511). We register our own RFC 3339
# check so ``date-time`` is always enforced, with no extra dependency.
CSAF_FORMAT_CHECKER = FormatChecker()


@CSAF_FORMAT_CHECKER.checks("date-time")
def _check_date_time(value: Any) -> bool:
    if not isinstance(value, str):
        return True
    return is_rfc3339(value)


SCHEMA_FILES = {
    "2.0": "csaf_2.0_json_schema.json",
    "2.1": "csaf_2.1_json_schema.json",
}

# The CSAF schemas reference the official FIRST CVSS schemas by absolute URL.
# We bundle those schemas so validation is fully offline and reproducible
# instead of fetching them over the network at runtime.
_CVSS_SCHEMA_URIS = {
    "https://www.first.org/cvss/cvss-v2.0.json": "cvss-v2.0.json",
    "https://www.first.org/cvss/cvss-v3.0.json": "cvss-v3.0.json",
    "https://www.first.org/cvss/cvss-v3.1.json": "cvss-v3.1.json",
    "https://www.first.org/cvss/cvss-v4.0.json": "cvss-v4.0.json",
}


def _cvss_registry() -> Registry:
    """Registry that resolves the FIRST CVSS ``$ref`` URLs to bundled copies."""
    resources_list = []
    cvss_dir = resources.files("analysis_lib.vex.data").joinpath("cvss")
    for uri, filename in _CVSS_SCHEMA_URIS.items():
        with cvss_dir.joinpath(filename).open("r") as fh:
            # The FIRST CVSS schemas declare a custom ``$schema`` dialect, so we
            # pin the specification explicitly rather than letting it be detected.
            resources_list.append(
                (uri, Resource.from_contents(json.load(fh), default_specification=DRAFT202012))
            )
    return Registry().with_resources(resources_list)


# Default document/publisher metadata used when no csaf.toml is present so the
# tool produces a usable document on the first run.
DEFAULT_META: Dict[str, Any] = {
    "document": {"category": "csaf_vex", "title": "dep-scan VEX"},
    "publisher": {
        "category": "vendor",
        "name": "OWASP dep-scan",
        "namespace": "https://github.com/owasp-dep-scan/dep-scan",
        "contact_details": "",
    },
    "tracking": {"status": "draft", "version": "1"},
    "note": [],
    "reference": [],
}


def load_schema(csaf_version: str = "2.1") -> Dict[str, Any]:
    """Load the bundled official CSAF schema for ``csaf_version``."""
    filename = SCHEMA_FILES.get(csaf_version, SCHEMA_FILES["2.1"])
    with resources.files("analysis_lib.vex.data").joinpath(filename).open("r") as fh:
        return json.load(fh)


def validate(doc: Dict[str, Any], csaf_version: str = "2.1") -> List[str]:
    """Return human-readable validation error messages (empty == valid).

    Runs two layers so a document that merely satisfies the JSON Schema is not
    mistaken for a conformant one:

    * the bundled official CSAF JSON Schema (with an RFC 3339 ``date-time``
      format check and bundled CVSS ``$ref`` copies -- no network access), and
    * the CSAF §6.1 mandatory *semantic* tests the schema cannot express
      (see :mod:`analysis_lib.vex.semantic`).
    """
    schema = load_schema(csaf_version)
    validator = CsafValidator(
        schema, registry=_cvss_registry(), format_checker=CSAF_FORMAT_CHECKER
    )
    errors = sorted(
        validator.iter_errors(doc),
        key=lambda e: list(e.path),
    )
    messages = [f"{'/'.join(str(p) for p in e.path) or '<doc>'}: {e.message}" for e in errors]
    messages.extend(validate_semantic(doc, csaf_version))
    return messages


def output_path(bom_file: str, reports_dir: str) -> str:
    """Derive ``<reports_dir>/<base>.csaf.json`` and assert path safety.

    Strips any of ``.cdx.json`` / ``.vdr.json`` / ``.bom.json`` from the
    supplied path so the CSAF document is named after the project, then
    verifies it cannot collide with the BOM/VDR.
    """
    base = os.path.basename(bom_file or "")
    for suffix in (".cdx.json", ".vdr.json", ".bom.json"):
        if base.lower().endswith(suffix):
            base = base[: -len(suffix)]
            break
    if not base:
        base = "dep-scan"
    outfile = os.path.join(reports_dir, f"{base}.csaf.json")
    # Guarantee: the output is always a .csaf.json file and never the
    # BOM/VDR path, so generating a CSAF document cannot clobber the BOM/VDR.
    if not outfile.lower().endswith(".csaf.json"):
        raise AssertionError(
            f"CSAF output path must end with '.csaf.json', got '{outfile}' "
            f"(the CSAF output must be a standalone .csaf.json file)."
        )
    if os.path.abspath(outfile) == os.path.abspath(bom_file):
        raise AssertionError(
            f"Refusing to write CSAF output to the BOM/VDR path '{outfile}' "
            f"(the CSAF output must be a standalone .csaf.json file)."
        )
    return outfile


def load_meta(src_dir: str, reports_dir: str) -> Dict[str, Any]:
    """Load ``csaf.toml`` from ``src_dir`` (or ``$DEPSCAN_CSAF_TEMPLATE``).

    Falls back to :data:`DEFAULT_META` when absent and writes a starter toml
    for user editing -- without exiting (one-run UX). The starter lands as
    ``csaf.toml.sample`` in ``reports_dir``, the same convention as
    ``depscan.toml.sample``, because the scanned project is untrusted input
    a scan must not write into. Returns the metadata.
    """
    toml_file_path = os.getenv("DEPSCAN_CSAF_TEMPLATE") or os.path.join(src_dir, "csaf.toml")
    if not os.path.isfile(toml_file_path):
        sample_path = os.path.join(reports_dir, "csaf.toml.sample")
        write_toml(sample_path)
        LOG.info(
            "CSAF toml not found; wrote starter template to %s and continuing "
            "with defaults. Edit it to customize publisher/tracking.",
            sample_path,
        )
        return _meta_with_version(dict(DEFAULT_META))
    try:
        with open(toml_file_path, "r") as fh:
            meta = toml.load(fh)
    except toml.TomlDecodeError as exc:
        raise ValueError(f"Invalid CSAF toml at {toml_file_path}: {exc}") from exc
    return _meta_with_version(meta)


def _meta_with_version(meta: Dict[str, Any]) -> Dict[str, Any]:
    meta = dict(meta)
    meta["depscan_version"] = get_version()
    return meta


def write_toml(toml_file_path: str, metadata: Optional[Dict[str, Any]] = None) -> None:
    """Write a starter ``csaf.toml.sample`` for operator customization."""
    meta = metadata or DEFAULT_META
    meta = _meta_with_version(meta)
    try:
        parent = os.path.dirname(toml_file_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(toml_file_path, "w") as fh:
            fh.write(toml.dumps(meta))
    except OSError as exc:
        LOG.warning("Could not write CSAF toml to %s: %s", toml_file_path, exc)


def _split_vulns(vdr_result) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Extract pkg_vulnerabilities + reached_purls from a VDRResult-like obj."""
    pkg_vulns = getattr(vdr_result, "pkg_vulnerabilities", None) or []
    reached = getattr(vdr_result, "reached_purls", None) or {}
    return pkg_vulns, dict(reached)


def export_csaf(
    vdr_result,
    src_dir: str,
    reports_dir: str,
    bom_file: str,
    bom: Optional[Dict[str, Any]] = None,
    csaf_version: str = "2.1",
) -> Tuple[Optional[str], List[str]]:
    """Generate, validate and write a CSAF VEX document.

    :param vdr_result: ``VDRResult`` (or compatible) with ``pkg_vulnerabilities``
        and ``reached_purls``.
    :param src_dir: project source dir (used to locate ``csaf.toml``).
    :param reports_dir: where to write the CSAF document.
    :param bom_file: BOM/VDR path -- used only to name the output. The output
        is always ``<base>.csaf.json`` and never overwrites this file.
    :param bom: optional pre-loaded BOM dict; loaded from ``bom_file`` when
        omitted.
    :param csaf_version: ``"2.1"`` (default) or ``"2.0"``.
    :return: ``(outfile, validation_errors)`` where ``outfile`` is ``None`` on
        hard failure. Validation errors are returned (and logged) but do not
        suppress the write, so the document is still available for debugging.
    """
    meta = load_meta(src_dir, reports_dir)
    if bom is None:
        try:
            with open(bom_file, "r") as fh:
                bom = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            LOG.error("Could not load BOM %s for CSAF generation: %s", bom_file, exc)
            return None, [f"BOM load failure: {exc}"]
    if not isinstance(bom, dict):
        LOG.error("BOM %s is not a JSON object; cannot generate CSAF.", bom_file)
        return None, ["BOM is not a JSON object"]

    pkg_vulns, reached = _split_vulns(vdr_result)
    doc = build_csaf(
        bom=bom,
        pkg_vulnerabilities=pkg_vulns,
        reached_purls=reached,
        meta=meta,
        csaf_version=csaf_version,
    )

    outfile = output_path(bom_file, reports_dir)
    errors = validate(doc, csaf_version)
    if errors:
        LOG.warning(
            "CSAF document generated with %d schema validation error(s); first few: %s",
            len(errors),
            errors[:3],
        )
    else:
        LOG.info("CSAF document is valid against the CSAF %s schema.", csaf_version)

    os.makedirs(reports_dir, exist_ok=True)
    with open(outfile, "w") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
    LOG.info("CSAF report written to %s", outfile)
    return outfile, errors
