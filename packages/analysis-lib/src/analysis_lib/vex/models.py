"""Typed dataclasses for the CSAF VEX document.

Each dataclass serializes to a CSAF-compatible dict via ``to_dict``, which
recursively drops ``None`` values and empty containers. The models are the
single source of truth for the document; where the CSAF 2.0 and 2.1 schemas
diverge the ``to_dict`` methods take a ``version`` argument and emit the shape
that version requires.

Key differences handled here:

* 2.0 carries a single ``cwe`` object per vulnerability; 2.1 carries a ``cwes``
  array where every entry also has a catalog ``version``.
* 2.0 stores CVSS under ``scores``; 2.1 stores them under ``metrics`` with a
  ``content`` wrapper (and keeps CVSS v4).
* 2.0 uses ``release_date``; 2.1 uses ``disclosure_date``.
* Product identity helpers use ``purl`` (2.0) or ``purls`` (2.1).
* 2.1 requires a top-level ``$schema`` and a document ``distribution``.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

DEFAULT_VERSION = "2.1"

# Catalog version stamped onto every CWE entry in CSAF 2.1 (which requires it).
CWE_CATALOG_VERSION = "4.15"

# Canonical schema URI required at the root of a CSAF 2.1 document.
SCHEMA_URI = {
    "2.1": "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json",
}


def _is_empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _clean(value: Any) -> Any:
    """Recursively strip ``None``/empty containers so the output never carries
    fields the schema would reject (e.g. notes without ``text``)."""
    if isinstance(value, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in value.items():
            entry: Any = _clean(v)
            if not _is_empty(entry):
                cleaned[k] = entry
        return cleaned
    if isinstance(value, list):
        cleaned_list: List[Any] = []
        for item in value:
            entry = _clean(item)
            if not _is_empty(entry):
                cleaned_list.append(entry)
        return cleaned_list
    return value


@dataclass
class FullProductName:
    name: str
    product_id: str
    purl: Optional[str] = None
    cpe: Optional[str] = None

    def to_dict(self, version: str = DEFAULT_VERSION) -> Dict[str, Any]:
        helper: Dict[str, Any] = {}
        if self.purl:
            # 2.1 accepts a list of purls; 2.0 accepts a single purl string.
            helper["purls" if version == "2.1" else "purl"] = (
                [self.purl] if version == "2.1" else self.purl
            )
        if self.cpe:
            helper["cpe"] = self.cpe
        out: Dict[str, Any] = {"name": self.name, "product_id": self.product_id}
        if helper:
            out["product_identification_helper"] = helper
        return out


@dataclass
class RevisionEntry:
    date: str
    number: str
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {"date": self.date, "number": self.number, "summary": self.summary}


@dataclass
class Tracking:
    status: str
    version: str
    id: str
    current_release_date: str
    initial_release_date: str
    revision_history: List[RevisionEntry] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "version": self.version,
            "id": self.id,
            "current_release_date": self.current_release_date,
            "initial_release_date": self.initial_release_date,
            "revision_history": [r.to_dict() for r in self.revision_history],
        }


@dataclass
class Publisher:
    category: str
    name: str
    namespace: str
    contact_details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return _clean(asdict(self))


@dataclass
class Reference:
    summary: str
    url: str
    category: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return _clean(asdict(self))


@dataclass
class Note:
    category: str
    text: str
    title: Optional[str] = None
    audience: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return _clean(asdict(self))


@dataclass
class Flag:
    """A CSAF product flag.

    CSAF has no separate ``justification`` field on a flag: the ``label`` is
    itself one of the standard VEX justification values (e.g.
    ``vulnerable_code_not_in_execute_path``).
    """

    label: str
    product_ids: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {"label": self.label, "product_ids": sorted(set(self.product_ids))}


@dataclass
class Score:
    """A CVSS score for a set of products. Exactly one of
    ``cvss_v2``/``cvss_v3``/``cvss_v4`` is populated."""

    products: List[str]
    cvss_v2: Optional[Dict[str, Any]] = None
    cvss_v3: Optional[Dict[str, Any]] = None
    cvss_v4: Optional[Dict[str, Any]] = None

    def _content(self) -> Dict[str, Any]:
        content: Dict[str, Any] = {}
        if self.cvss_v2:
            content["cvss_v2"] = self.cvss_v2
        if self.cvss_v3:
            content["cvss_v3"] = self.cvss_v3
        if self.cvss_v4:
            content["cvss_v4"] = self.cvss_v4
        return content

    def to_dict(self, version: str = DEFAULT_VERSION) -> Dict[str, Any]:
        products = sorted(set(self.products))
        if version == "2.1":
            # 2.1 nests the CVSS body under ``content`` inside a metric entry.
            return {"products": products, "content": self._content()}
        out: Dict[str, Any] = {"products": products}
        out.update(self._content())
        return out


@dataclass
class Vulnerability:
    cve: Optional[str]
    title: str
    cwes: List[Dict[str, str]]
    notes: List[Note]
    product_status: Dict[str, List[str]]
    scores: List[Score]
    flags: List[Flag]
    references: List[Reference]
    ids: List[Dict[str, str]]
    acknowledgments: List[Dict[str, Any]] = field(default_factory=list)
    discovery_date: Optional[str] = None
    disclosure_date: Optional[str] = None
    threats: List[Dict[str, Any]] = field(default_factory=list)
    remediations: List[Dict[str, Any]] = field(default_factory=list)

    def _cwe_fields(self, version: str) -> Dict[str, Any]:
        if not self.cwes:
            return {}
        if version == "2.1":
            return {
                "cwes": [
                    {"id": c["id"], "name": c["name"], "version": CWE_CATALOG_VERSION}
                    for c in self.cwes
                ]
            }
        # 2.0 allows a single cwe object; keep the primary one.
        first = self.cwes[0]
        return {"cwe": {"id": first["id"], "name": first["name"]}}

    def to_dict(self, version: str = DEFAULT_VERSION) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "title": self.title,
            "notes": [n.to_dict() for n in self.notes if n.text],
            "product_status": {k: sorted(set(v)) for k, v in self.product_status.items() if v},
            "references": [r.to_dict() for r in self.references],
            "ids": self.ids,
        }
        out.update(self._cwe_fields(version))
        if self.scores:
            key = "metrics" if version == "2.1" else "scores"
            out[key] = [s.to_dict(version) for s in self.scores]
        if self.cve:
            out["cve"] = self.cve
        if self.flags:
            out["flags"] = [f.to_dict() for f in self.flags]
        if self.acknowledgments:
            out["acknowledgments"] = self.acknowledgments
        if self.discovery_date:
            out["discovery_date"] = self.discovery_date
        # 2.0 exposes this timestamp as ``release_date``; 2.1 renamed it to
        # ``disclosure_date`` and dropped ``release_date``.
        if self.disclosure_date:
            out["disclosure_date" if version == "2.1" else "release_date"] = self.disclosure_date
        if self.threats:
            out["threats"] = self.threats
        if self.remediations:
            out["remediations"] = self.remediations
        return _clean(out)


@dataclass
class Document:
    category: str
    csaf_version: str
    title: str
    publisher: Publisher
    tracking: Tracking
    notes: List[Note] = field(default_factory=list)
    references: List[Reference] = field(default_factory=list)
    aggregate_severity: Optional[str] = None
    tlp_label: Optional[str] = None
    distribution_text: Optional[str] = None
    lang: str = "en"

    def _distribution(self, version: str) -> Dict[str, Any]:
        # A distribution block is required in 2.1 and valid in 2.0. The TLP
        # label is taken from the operator's csaf.toml when set; otherwise we
        # default to the most-open label so the VEX is freely shareable --
        # named CLEAR in TLP 2.0 (CSAF 2.1) and WHITE in the TLP the CSAF 2.0
        # schema validates against.
        label = (self.tlp_label or "").upper().strip()
        if not label:
            label = "CLEAR" if version == "2.1" else "WHITE"
        elif label == "CLEAR" and version == "2.0":
            label = "WHITE"
        elif label == "WHITE" and version == "2.1":
            label = "CLEAR"
        return {
            "tlp": {"label": label},
            "text": self.distribution_text or "Shareable without restriction.",
        }

    def to_dict(self, version: str = DEFAULT_VERSION) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "category": self.category,
            "csaf_version": version,
            "title": self.title,
            "lang": self.lang,
            "publisher": self.publisher.to_dict(),
            "tracking": self.tracking.to_dict(),
            "distribution": self._distribution(version),
        }
        if self.notes:
            out["notes"] = [n.to_dict() for n in self.notes if n.text]
        if self.references:
            out["references"] = [r.to_dict() for r in self.references]
        if self.aggregate_severity:
            out["aggregate_severity"] = {"text": self.aggregate_severity}
        return _clean(out)


@dataclass
class CsafDoc:
    document: Document
    product_tree: Dict[str, Any]
    vulnerabilities: List[Vulnerability]

    def to_dict(self, version: str = DEFAULT_VERSION) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "document": self.document.to_dict(version),
            "product_tree": self.product_tree,
            "vulnerabilities": [v.to_dict(version) for v in self.vulnerabilities],
        }
        # 2.1 requires the schema URI at the document root.
        if version in SCHEMA_URI:
            out["$schema"] = SCHEMA_URI[version]
        return _clean(out)
