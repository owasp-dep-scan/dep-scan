"""Classify purls and tags for endpoint and service reachability.

Small predicates used while building and filtering the endpoint reachability
maps: which purls are safe to drop from endpoint filtering, which tags mark a
flow as service-like, and how to strip the version from a purl.

This module does not compute reachability itself (see analysis_lib.reachability
and the analyzers behind it).
"""

from analysis_lib.config import SAFE_ENDPOINT_REACHABLE_PURLS, SERVICE_TAGS


def strip_version(purl_str: str) -> str:
    """Remove the '@version' suffix if present."""
    purl_no_version, *_ = purl_str.split("@", 1)
    return purl_no_version


def is_service_like_tag(tags):
    if not tags:
        return False
    return any([t for t in tags if t in SERVICE_TAGS])


def is_endpoint_filterable(purl):
    for p in SAFE_ENDPOINT_REACHABLE_PURLS:
        if purl.startswith(p):
            return True
    return False
