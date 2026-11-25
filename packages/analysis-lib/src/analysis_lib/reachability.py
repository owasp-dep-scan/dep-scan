"""The reachability analyzers over the evidence store.

The engine counts what the evidence records of the scan directory say:
positive records of the counted kinds put their subject purls on an
executed path, a record's ``servicePurls`` attribute and an entry point's
handler purls feed the reached-services set, and a reached purl typed
``framework`` in the BOM and not filterable is endpoint-reachable. The
records come from the store the enrichment stage wrote; the engine reads no
producer report itself. The direct purls are counted from cdxgen's
occurrence records of the top-level components of the BOM documents the
analysis was given, one per occurrence entry, and an occurrence whose file
is an ``x-atom-usages`` usage target of the OpenAPI documents makes its
package endpoint-reachable. The
BOMs are still read for their component types and lifecycles, which the
post-build binary reachability support uses.
"""

from analysis_lib import (
    ReachabilityAnalysisKV,
    ReachabilityAnalyzer,
    ReachabilityResult,
)
from analysis_lib.config import MIN_POSTBUILD_CONFIDENCE
from analysis_lib.endpoints import (
    strip_version,
    is_endpoint_filterable,
)
from analysis_lib.evidence import Evidence, EvidenceCaveat, EvidenceProducer
from analysis_lib.evidence.adapters import SourcePaths, build_record
from analysis_lib.evidence.store import stream as stream_evidence
from custom_json_diff.lib.utils import json_load
from collections import defaultdict
from typing import Dict, Iterable, Optional, Set
import dataclasses
import json
import os
import re

#: The record kinds whose positive records count as reached evidence. A
#: record of another kind (a callsite, a dependency note, a sanitizer, a
#: dead-code mark, a weakness candidate, a dangerous API call) is evidence
#: about the package, never reached evidence.
REACHED_COUNTED_KINDS = frozenset({"reached-flow", "usage", "entry-point"})

#: The stated confidence that never counts as reached, compared without
#: case: a producer that calls its own finding low confidence has not shown
#: the package is reached.
UNCOUNTED_CONFIDENCE = "low"


def counts_as_reached(record: Evidence) -> bool:
    """Whether one record counts as reached evidence: positive polarity, one
    of :data:`REACHED_COUNTED_KINDS`, and a stated confidence, when the
    record carries one, that is not Low. The rule is the same for every
    producer, and every reader of the reached sets applies it through this
    function."""
    if record.polarity != "positive" or record.kind not in REACHED_COUNTED_KINDS:
        return False
    confidence = record.confidence
    return not (isinstance(confidence, str) and confidence.strip().lower() == UNCOUNTED_CONFIDENCE)


def report_source(path: str, base: str) -> str:
    """A report file's record source: its path relative to ``base`` with
    forward slashes, or its base name when it sits outside ``base``, so no
    source is ever absolute or climbs out. The adapters' callers name each
    record's source this way, and the engine finds a document's records by
    the same spelling."""
    try:
        relative = os.path.relpath(os.path.abspath(path), os.path.abspath(base))
    except ValueError:
        relative = ""
    if relative and relative != "." and not relative.startswith(".."):
        return relative.replace(os.sep, "/").replace("\\", "/")
    return os.path.basename(path)


def _document_sources(bom_files: Optional[Iterable[str]], base: Optional[str]) -> Set[str]:
    """The record sources of the BOM documents the analysis was given."""
    if not bom_files:
        return set()
    return {report_source(str(path), base or ".") for path in bom_files}


def _is_direct_use(record: Evidence, sources: Set[str]) -> bool:
    """Whether the record is one direct use of its package: a cdxgen
    occurrence record of one of the documents whose record sources are
    ``sources``, of a top-level component of that BOM. Occurrences of
    nested components stay usage evidence for presence but are not direct
    uses of the project."""
    if not (
        record.producer.name == "cdxgen"
        and record.kind == "occurrence"
        and record.source in sources
    ):
        return False
    position = (record.attributes or {}).get("bomPosition", "top-level")
    return position == "top-level"


def _usage_target_files(usage_targets: Dict[str, bool], root: Optional[str]) -> Set[str]:
    """The ``x-atom-usages`` file keys spelled the way cdxgen's adapter
    spells an occurrence file: relative to the scan root with forward
    slashes, ``./`` dropped. Both sides then follow the one rule, whatever
    separator or prefix atom-tools and cdxgen wrote."""
    paths = SourcePaths(roots=[root] if root else [])
    files = set()
    for key in usage_targets:
        relative = paths.relative(key)
        if relative:
            files.add(relative)
    return files


def _iter_json_list(file_path: str):
    """Stream a top-level JSON array from ``file_path``, yielding one parsed
    element at a time.

    Materializing a large parsed list costs several times the file size in
    RSS, so this reader walks the array with ``JSONDecoder.raw_decode``:
    peak RSS is roughly the file text plus ONE parsed element instead of
    the full tree. The reachability engine itself counts evidence records
    and reads no report file; the reachability evaluation tooling under
    ``contrib/`` uses this reader over slice arrays, and the adapter tests
    use it to walk fixture slices.

    If the file is not a JSON list, the iterator yields nothing.
    """
    decoder = json.JSONDecoder()
    try:
        with open(file_path, encoding="utf-8") as fp:
            text = fp.read()
    except OSError:
        return
    n = len(text)
    idx = 0
    while idx < n and text[idx] in " \t\n\r":
        idx += 1
    if idx >= n or text[idx] != "[":
        return
    idx += 1
    while idx < n:
        while idx < n and text[idx] in " \t\n\r":
            idx += 1
        if idx >= n:
            return
        if text[idx] == "]":
            return
        try:
            obj, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            return
        yield obj
        idx = end
        while idx < n and text[idx] in " \t\n\r":
            idx += 1
        if idx < n and text[idx] == ",":
            idx += 1


#: The purl type each atom slice file prefix (``<prefix>-reachables.slices``)
#: covers, by cdxgen project type and its aliases.
ATOM_SLICE_PURL_TYPES = {
    **dict.fromkeys(
        ("java", "jar", "war", "kotlin", "kt", "android", "scala", "gradle", "maven", "jvm"),
        "maven",
    ),
    **dict.fromkeys(("js", "javascript", "ts", "typescript", "nodejs", "npm", "yarn"), "npm"),
    **dict.fromkeys(("python", "py", "pypi"), "pypi"),
    **dict.fromkeys(("php", "composer"), "composer"),
    **dict.fromkeys(("ruby", "gem"), "gem"),
}


def _inferred_version(component: dict) -> bool:
    """Whether the component's version was only inferred from source code.

    cdxgen resolves an import it found in the source to the newest release
    of the package when the project does not say which one it uses, and
    records that as a ``version`` identity reached by ``source-code-analysis``
    alone. A component with any other identity evidence, such as a manifest
    or lockfile entry, carries a version the project itself declares.
    """
    identities = (component.get("evidence") or {}).get("identity") or []
    if isinstance(identities, dict):
        identities = [identities]
    if not identities:
        return False
    for identity in identities:
        if not isinstance(identity, dict) or identity.get("field") != "version":
            return False
        methods = identity.get("methods") or []
        if not methods or any(
            not isinstance(method, dict) or method.get("technique") != "source-code-analysis"
            for method in methods
        ):
            return False
    return True


def version_aliases(documents: Iterable[dict]) -> Dict[str, str]:
    """Map each inferred-version purl to the declared version of its package.

    When the BOMs carry a package twice, once at the version the project
    declares and once at a version cdxgen inferred from an import (see
    :func:`_inferred_version`), the evidence recorded against the inferred
    purl is about the declared component: that is the one the findings name.
    The inferred purl maps to the declared one only when the declared one is
    unambiguous, that is, the BOMs hold exactly one declared version of the
    package.
    """
    declared: Dict[str, Set[str]] = defaultdict(set)
    inferred: Dict[str, Set[str]] = defaultdict(set)
    for document in documents:
        for component in document.get("components") or []:
            purl = component.get("purl") if isinstance(component, dict) else None
            if not (isinstance(purl, str) and purl):
                continue
            key = strip_version(purl).lower()
            (inferred if _inferred_version(component) else declared)[key].add(purl)
    aliases = {}
    for key, purls in inferred.items():
        if len(declared.get(key, ())) != 1:
            continue
        target = next(iter(declared[key]))
        for purl in purls:
            if purl != target and purl not in declared[key]:
                aliases[purl] = target
    return aliases


def load_documents(bom_files: Optional[Iterable[str]]) -> list:
    """The BOM files that parse to a CycloneDX-shaped object.

    The BOM file list is a name glob, so a report that is not a BOM (a
    license or risk report whose name contains "bom") reaches here as a list
    or string and is skipped.
    """
    documents = []
    for bom_file in bom_files or []:
        data = json_load(bom_file)
        if isinstance(data, dict):
            documents.append(data)
    return documents


def _direct_key(record: Evidence, purl: str):
    """The identity of one direct use: the package, the file and the line.

    Every lifecycle BOM of a scan (pre-build, build) lists the same
    occurrences, so the count keys a use by where it is, not by which
    document said so. A use listed twice by one document is two uses, as the
    document lists it; only another document's copy of it is dropped.
    """
    location = record.locations[0] if record.locations else None
    return (purl, location.file if location else None, location.line if location else None)


def alias_records(records: Iterable[Evidence], aliases: Dict[str, str]) -> list:
    """The records with every purl an inferred version names replaced by the
    declared version of that package (see :func:`version_aliases`).

    A record that names no aliased purl is returned as it is; one that does
    is copied, so the store's records are never changed.
    """
    result = []
    for record in records:
        purls = record.subject.purls
        if aliases and any(purl in aliases for purl in purls):
            mapped = list(dict.fromkeys(aliases.get(purl, purl) for purl in purls))
            subject = dataclasses.replace(record.subject, purls=mapped)
            record = dataclasses.replace(record, subject=subject)
        result.append(record)
    return result


def _module_names(purl: str) -> Set[str]:
    """The module names a package purl is imported as, as far as its name
    says: the name itself, lower case, with ``-`` and ``.`` read as ``_``."""
    name = strip_version(purl).rsplit("/", 1)[-1].lower()
    return {name, re.sub(r"[-.]", "_", name)}


#: The component properties cdxgen writes the module names of a package in.
#: ``internal:ImportedModules`` is comma-separated and holds what the source
#: imports (``flask.Flask`` is the module ``flask``); ``internal:Namespaces``
#: holds the top-level modules a PyPI distribution provides, one per line (the
#: alias map gives ``yaml`` for PyYAML), with ``cdx:pypi:modulesFrom`` naming
#: where they came from.
MODULE_PROPERTIES = ("internal:ImportedModules", "internal:Namespaces")


def declared_modules(
    documents: Iterable[dict], aliases: Optional[Dict[str, str]] = None
) -> Dict[str, Set[str]]:
    """The module names the BOM components declare, by purl.

    A purl an inferred version names is keyed by the declared purl of its
    package (see :func:`version_aliases`), so the names reach the purl the
    findings name. Only the first dotted segment of a name counts, in lower
    case.
    """
    aliases = aliases or {}
    result: Dict[str, Set[str]] = defaultdict(set)
    for document in documents:
        for component in document.get("components") or []:
            purl = component.get("purl") if isinstance(component, dict) else None
            if not (isinstance(purl, str) and purl):
                continue
            for prop in component.get("properties") or []:
                if not isinstance(prop, dict) or prop.get("name") not in MODULE_PROPERTIES:
                    continue
                for name in re.split(r"[,\n]", str(prop.get("value") or "")):
                    name = name.strip().split(".", 1)[0].lower()
                    if name:
                        result[aliases.get(purl, purl)].add(name)
    return result


def attribute_atom_usages(
    records: Iterable[Evidence], modules: Optional[Dict[str, Set[str]]] = None
) -> list:
    """New usage records that name the packages atom's usage records are about.

    atom's usage slices carry resolved method names such as
    ``flask.Flask.route`` and no purl. A usage record is about a package when
    cdxgen recorded an occurrence of the package in the record's file and the
    first segment of a method on the record's path is a module name of the
    package: one its purl name implies, or one the BOM component declares
    (``modules``, from :func:`declared_modules`), so PyYAML is found by
    ``yaml``. Each joined record becomes a new record of the same producer,
    with the original's locations and path, the attributed purls, a new id
    derived from the original's id and the purls, and an ``attributed`` caveat
    that says dep-scan made the join. The original is not changed. A record
    that already names purls, and one with no match, gives no new record.
    """
    records = list(records)
    by_file: Dict[str, Set[str]] = defaultdict(set)
    for record in records:
        if record.producer.name == "cdxgen" and record.kind == "occurrence" and record.locations:
            for purl in record.subject.purls:
                by_file[record.locations[0].file].add(purl)
    attributed = []
    for record in records:
        if not (
            record.producer.name == "atom"
            and record.kind == "usage"
            and record.polarity == "positive"
            and record.path
            and not record.subject.purls
            and record.locations
        ):
            continue
        file_name = record.locations[0].file
        modules_used = {
            node.method.split(".", 1)[0].lower() for node in record.path if node.method
        }
        joined = {}
        for purl in sorted(by_file.get(file_name, ())):
            by_name = _module_names(purl) & modules_used
            by_bom = (modules or {}).get(purl, set()) & modules_used
            if by_name:
                joined[purl] = (sorted(by_name)[0], "the package name")
            elif by_bom:
                joined[purl] = (
                    sorted(by_bom)[0],
                    "the module names cdxgen records for the component",
                )
        if not joined:
            continue
        detail = "; ".join(
            f"dep-scan joined this atom usage to {purl}: cdxgen recorded the package in "
            f"{file_name} and the call path starts with the module {module}, which {origin} gives"
            for purl, (module, origin) in joined.items()
        )
        attributed.append(
            build_record(
                source=record.source,
                producer=EvidenceProducer(
                    name=record.producer.name,
                    version=record.producer.version,
                    report_schema_version=record.producer.report_schema_version,
                ),
                kind=record.kind,
                discriminator=f"attributed:{record.id}",
                polarity=record.polarity,
                purls=tuple(joined),
                locations=tuple(record.locations),
                path=tuple(record.path),
                confidence=record.confidence,
                attributes=record.attributes,
                caveats=(*record.caveats, EvidenceCaveat(kind="attributed", detail=detail)),
            )
        )
    return attributed


def get_reachability_impl(
    reachability_analyzer: str, reachability_options: Optional[ReachabilityAnalysisKV]
):
    if not reachability_options:
        return NullReachability(reachability_options)
    if reachability_analyzer == "FrameworkReachability":
        return FrameworkReachability(reachability_options)
    if reachability_analyzer == "SemanticReachability":
        return SemanticReachability(reachability_options)
    return NullReachability(reachability_options)


class NullReachability(ReachabilityAnalyzer):
    """
    Dummy Reachability Analyzer
    """

    def process(self) -> ReachabilityResult:
        return ReachabilityResult(success=True)


class FrameworkReachability(ReachabilityAnalyzer):
    """
    Framework Forward Reachability Analyzer
    """

    def process(self) -> ReachabilityResult:
        analysis_options = self.analysis_options
        if not analysis_options:
            return ReachabilityResult(success=False)
        direct_purls = defaultdict(int)
        reached_purls = defaultdict(int)
        seen_uses: Dict[tuple, str] = {}
        status = True
        sources = _document_sources(analysis_options.bom_files, analysis_options.bom_dir)
        aliases = version_aliases(load_documents(analysis_options.bom_files))
        # Count the direct purls from the BOMs' occurrence records and the
        # reached purls from the reached-counted records.
        if analysis_options.evidence_file and os.path.isfile(analysis_options.evidence_file):
            for record in stream_evidence(analysis_options.evidence_file):
                if _is_direct_use(record, sources):
                    for apurl in (aliases.get(p, p) for p in record.subject.purls):
                        if (
                            seen_uses.setdefault(_direct_key(record, apurl), record.source)
                            != record.source
                        ):
                            continue
                        direct_purls[apurl] += 1
                if not counts_as_reached(record):
                    continue
                for apurl in record.subject.purls:
                    reached_purls[aliases.get(apurl, apurl)] += 1
        if not direct_purls and not reached_purls:
            status = False
        return ReachabilityResult(
            success=status,
            direct_purls=direct_purls,
            reached_purls=reached_purls,
        )


class SemanticReachability(FrameworkReachability):
    """
    Semantic Reachability Analyzer
    """

    @staticmethod
    def _track_usage_targets(usage_targets, usages_object):
        # x-atom-usages values are per-file lists of line numbers: atom-tools
        # writes ``call`` and ``target`` in the same shape ("call": {file:
        # [lines]}, "target": {file: [lines]}). Anything else is ignored
        # rather than crashing the analyzer.
        if not isinstance(usages_object, dict):
            return
        for k, v in usages_object.items():
            if not isinstance(v, dict):
                continue
            for file, lines in v.items():
                usage_targets[file] = True
                if isinstance(lines, (list, tuple, set)):
                    for aline in lines:
                        usage_targets[f"{file}#{aline}"] = True

    @staticmethod
    def _track_binary_reachability(
        postbuild_purls: Dict,
        interesting_postbuild_purls: Dict[str, bool],
        reached_purls: Dict[str, int],
        endpoint_reached_purls: Optional[Dict[str, int]],
        typed_components: Dict[str, list],
    ):
        # Return early in we don't have post-build or component type information
        if not postbuild_purls or not typed_components:
            return
        frameworks = typed_components.get("framework", [])
        cryptos = typed_components.get("cryptographic-asset", [])
        # require at least one of framework or crypto to proceed
        if not frameworks and not cryptos:
            return
        versionless_purls = set()
        normalized_to_original_purl = {}
        for p in frameworks + cryptos:
            purl_no_version = strip_version(p)
            versionless_purls.add(purl_no_version)
            normalized_to_original_purl[purl_no_version] = p
        for purl in postbuild_purls:
            purl_no_version = strip_version(purl)
            if is_endpoint_filterable(purl_no_version):
                continue
            if purl_no_version in versionless_purls:
                reached_purls[normalized_to_original_purl[purl_no_version]] += 1
                # Could this be endpoint reachable.
                if endpoint_reached_purls:
                    endpoint_reached_purls[normalized_to_original_purl[purl_no_version]] += 1

    def process(self) -> ReachabilityResult:
        analysis_options = self.analysis_options
        if not analysis_options:
            return ReachabilityResult(success=False)
        direct_purls = defaultdict(int)
        reached_purls = defaultdict(int)
        reached_services = defaultdict(int)
        endpoint_reached_purls = defaultdict(int)
        postbuild_purls = {}
        seen_uses: Dict[tuple, str] = {}
        interesting_postbuild_purls = {}
        typed_components = defaultdict(list)
        status = True
        # Collect the endpoint usage information from the openapi files
        usage_targets = {}
        if analysis_options.openapi_spec_files:
            for ospec in analysis_options.openapi_spec_files:
                spec_data = json_load(ospec)
                if not isinstance(spec_data, dict):
                    continue
                paths = spec_data.get("paths") or {}
                if not isinstance(paths, dict):
                    continue
                for url_prefix, path_obj in paths.items():
                    if not isinstance(path_obj, dict):
                        continue
                    for k, v in path_obj.items():
                        # Java, JavaScript, Python etc
                        if k == "x-atom-usages":
                            self._track_usage_targets(usage_targets, v)
                        # Ruby, Scala etc
                        if isinstance(v, dict) and v.get("x-atom-usages"):
                            self._track_usage_targets(usage_targets, v.get("x-atom-usages"))
        # Collect the component types and lifecycles of the BOMs
        documents = load_documents(analysis_options.bom_files)
        # A package the BOMs hold at an inferred version and at the declared
        # one is counted under the declared purl, the one the findings name.
        aliases = version_aliases(documents)
        if documents:
            for data in documents:
                lifecycles = data.get("metadata", {}).get("lifecycles", []) or []
                is_post_build = any(
                    [aline for aline in lifecycles if aline.get("phase") == "post-build"]
                )
                for c in data.get("components", []):
                    purl = c.get("purl", "")
                    purl = aliases.get(purl, purl)
                    # Filter low confidence generic and file components
                    if is_post_build and (
                        purl.startswith("pkg:generic") or purl.startswith("pkg:file")
                    ):
                        confidence = None
                        identity_list_obj = c.get("evidence", {}).get("identity", [])
                        if isinstance(identity_list_obj, dict):
                            identity_list_obj = [identity_list_obj]
                        for aident in identity_list_obj:
                            if (
                                aident
                                and aident.get("confidence")
                                and aident.get("confidence") >= MIN_POSTBUILD_CONFIDENCE
                            ):
                                confidence = aident.get("confidence")
                                break
                        if confidence and confidence < MIN_POSTBUILD_CONFIDENCE:
                            continue
                    if is_post_build:
                        postbuild_purls[purl] = True
                    component_type = c.get("type")
                    typed_components[component_type].append(purl)
                    # Work harder to track frameworks. See https://github.com/CycloneDX/cdxgen/issues/1750
                    if (
                        component_type != "framework"
                        and c.get("tags")
                        and "framework" in c.get("tags")
                    ):
                        typed_components["framework"].append(purl)
                        # If this purl is also seen in a post-build SBOM, it is likely interesting
                        if postbuild_purls.get(purl):
                            interesting_postbuild_purls[purl] = True
        # Count the direct purls, reached purls, services and endpoint
        # reachability from the evidence records. Each occurrence record of
        # a top-level component of the given BOMs is one direct use of its
        # package. A package is endpoint-reachable from its occurrences only
        # when one of ITS OWN occurrence files is an atom usage target
        # (x-atom-usages, compared in the adapter's relative spelling), never
        # because usage_targets is globally non-empty; that would attribute
        # endpoints to packages whose own locations are never used. The
        # adapters own service attribution: a record's ``servicePurls``
        # attribute holds exactly the purls the producer marked as services,
        # so this walk never reads tags. An entry point's handler purls are
        # its subject purls and count as services without an attribute.
        sources = _document_sources(analysis_options.bom_files, analysis_options.bom_dir)
        target_files = _usage_target_files(
            usage_targets, analysis_options.source_root or analysis_options.src_dir
        )
        if analysis_options.evidence_file and os.path.isfile(analysis_options.evidence_file):
            for record in stream_evidence(analysis_options.evidence_file):
                if _is_direct_use(record, sources):
                    location = record.locations[0].file if record.locations else None
                    for purl in (aliases.get(p, p) for p in record.subject.purls):
                        if (
                            seen_uses.setdefault(_direct_key(record, purl), record.source)
                            != record.source
                        ):
                            continue
                        direct_purls[purl] += 1
                        if (
                            location
                            and location in target_files
                            and not is_endpoint_filterable(purl)
                        ):
                            endpoint_reached_purls[purl] += 1
                            if postbuild_purls.get(purl):
                                interesting_postbuild_purls[purl] = True
                if not counts_as_reached(record):
                    continue
                service_purls = set((record.attributes or {}).get("servicePurls") or [])
                for apurl in (aliases.get(p, p) for p in record.subject.purls):
                    reached_purls[apurl] += 1
                    # Could this be an external service
                    if apurl in service_purls or record.kind == "entry-point":
                        reached_services[apurl] += 1
                        if postbuild_purls.get(apurl):
                            interesting_postbuild_purls[apurl] = True
                    # Could this be endpoint reachable?
                    if apurl in typed_components.get(
                        "framework", []
                    ) and not is_endpoint_filterable(apurl):
                        endpoint_reached_purls[apurl] += 1
                        if postbuild_purls.get(apurl):
                            interesting_postbuild_purls[apurl] = True
        # Support for binary reachability
        self._track_binary_reachability(
            postbuild_purls,
            interesting_postbuild_purls,
            reached_purls,
            endpoint_reached_purls if usage_targets else None,
            typed_components,
        )
        if not direct_purls and not reached_purls:
            status = False
        return ReachabilityResult(
            success=status,
            direct_purls=direct_purls,
            reached_purls=reached_purls,
            reached_services=reached_services,
            endpoint_reached_purls=endpoint_reached_purls,
        )
