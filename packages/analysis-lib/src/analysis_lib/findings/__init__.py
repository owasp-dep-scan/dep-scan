"""The dep-scan finding model: schema, fingerprint and Python types.

The JSON Schema under schemas/ is the published contract that every dep-scan
7 deliverable writes; schemas.py loads and validates documents against it.
fingerprint.py computes the line-free id the schema's id field carries, and
model.py mirrors the schema as dataclasses. Tests check the schema and the
model against each other so they cannot drift.
"""
