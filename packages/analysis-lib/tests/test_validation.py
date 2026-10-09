"""Tests for the generic (CSAF + CycloneDX) document validator."""

from typing import Any, Dict

from analysis_lib.validation import (
    FORMAT_CSAF,
    FORMAT_CYCLONEDX,
    detect_format,
    validate_cyclonedx,
    validate_document,
)


def _min_cyclonedx() -> Dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": "2026-07-24T00:00:00Z"},
        "components": [
            {
                "type": "library",
                "name": "express",
                "version": "4.22.2",
                "purl": "pkg:npm/express@4.22.2",
            }
        ],
    }


def _min_csaf():
    return {
        "document": {"csaf_version": "2.1", "category": "csaf_vex"},
        "vulnerabilities": [],
        "product_tree": {"full_product_names": []},
    }


def test_detect_format_cyclonedx():
    assert detect_format(_min_cyclonedx()) == FORMAT_CYCLONEDX
    assert detect_format({"specVersion": "1.5"}) == FORMAT_CYCLONEDX


def test_detect_format_csaf():
    assert detect_format(_min_csaf()) == FORMAT_CSAF
    assert detect_format({"document": {"csaf_version": "2.0"}}) == FORMAT_CSAF


def test_detect_format_unknown():
    assert detect_format({"foo": "bar"}) is None
    assert detect_format("not a dict") is None


def test_validate_cyclonedx_valid():
    assert validate_cyclonedx(_min_cyclonedx()) == []


def test_validate_cyclonedx_invalid_reports_error():
    doc = _min_cyclonedx()
    doc["components"][0]["type"] = "not-a-type"
    errors = validate_cyclonedx(doc)
    assert errors and any("type" in e for e in errors)


def test_validate_cyclonedx_unsupported_spec_version():
    doc = _min_cyclonedx()
    doc["specVersion"] = "1.2"
    errors = validate_cyclonedx(doc)
    assert errors and "unsupported CycloneDX specVersion" in errors[0]


def test_validate_cyclonedx_1_7_supported():
    doc = _min_cyclonedx()
    doc["specVersion"] = "1.7"
    assert validate_cyclonedx(doc) == []


def test_validate_cyclonedx_enforces_spdx_license_enum():
    doc = _min_cyclonedx()
    doc["components"][0]["licenses"] = [{"license": {"id": "MIT"}}]
    assert validate_cyclonedx(doc) == []
    doc["components"][0]["licenses"] = [{"license": {"id": "NOT-A-REAL-LICENSE"}}]
    assert validate_cyclonedx(doc)  # bogus SPDX id is rejected


def test_validate_document_auto_detects_and_delegates():
    fmt, errors = validate_document(_min_cyclonedx())
    assert fmt == FORMAT_CYCLONEDX and errors == []
    fmt, _ = validate_document(_min_csaf())
    assert fmt == FORMAT_CSAF


def test_validate_document_forced_format_overrides_detection():
    # A CycloneDX doc forced as CSAF is handled by the CSAF path, not detection.
    fmt, errors = validate_document(_min_cyclonedx(), doc_format=FORMAT_CSAF)
    assert fmt == FORMAT_CSAF


def test_validate_cyclonedx_flags_naive_timestamp():
    # A metadata timestamp missing its timezone must be caught by the
    # date-time format checker.
    doc = _min_cyclonedx()
    doc["metadata"]["timestamp"] = "2026-07-24T00:00:00"
    errors = validate_cyclonedx(doc)
    assert errors and any("timestamp" in e for e in errors)


def test_validate_document_unknown_format():
    fmt, errors = validate_document({"nothing": "useful"})
    assert fmt is None and errors and "could not detect" in errors[0]
