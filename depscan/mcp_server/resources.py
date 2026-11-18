"""The resources and prompts of the ``depscan mcp`` server.

Three resource templates expose a scan directory's documents by URI:
``depscan://scan/{scan_dir}/manifest`` is the scan directory's manifest
document, ``.../findings`` is its findings document, and
``.../findings/{finding_id}`` is one finding of it. ``{scan_dir}`` is the
scan directory's absolute path, percent-encoded, so the whole path stays in
one URI segment. A read is confined like every other access: the path must
resolve, with ``os.path.realpath``, inside the allowed roots, and a refusal
carries the confinement rule it broke.

A read that cannot produce the document says what is missing: a directory
that does not exist, a directory with no manifest or findings file, a
document that does not parse or parses without the fields the writer always
writes, and a finding id no finding carries are errors naming what was asked
for. No read returns an empty document in place of the truth.

The two prompts, ``triage_findings`` and ``plan_fixes``, are short
templates that name the tools to call, in the order to call them, and
promise nothing the tools do not return: the server records nothing, applies
no fix, and has no remediation plan, policy or triage store for the agent to
write to, and the prompt texts say so.
"""

import json
import os
from typing import Any, Dict, NamedTuple, Optional, Tuple
from urllib.parse import quote, unquote, urlsplit

from mcp import types
from mcp.shared.exceptions import MCPError

from depscan.lib import scan_directory
from depscan.mcp_server import confinement
from depscan.mcp_server import server as server_mod

#: The scheme and authority every resource URI of this server starts with.
URI_SCHEME = "depscan"
URI_AUTHORITY = "scan"

#: The three resource templates, with the scan directory percent-encoded.
MANIFEST_TEMPLATE = f"{URI_SCHEME}://{URI_AUTHORITY}/{{scan_dir}}/manifest"
FINDINGS_TEMPLATE = f"{URI_SCHEME}://{URI_AUTHORITY}/{{scan_dir}}/findings"
FINDING_TEMPLATE = f"{URI_SCHEME}://{URI_AUTHORITY}/{{scan_dir}}/findings/{{finding_id}}"

#: Resource contents are JSON documents.
RESOURCE_MIME_TYPE = "application/json"

#: The prompts this server defines, in listing order.
PROMPT_NAMES = ("triage_findings", "plan_fixes")

#: The prompt argument that carries the scan directory, optional in both
#: prompts so a client can render the template before it knows the path.
SCAN_DIR_ARGUMENT = "scan_dir"


class ParsedResourceUri(NamedTuple):
    """The parts one resource URI names.

    ``kind`` is ``manifest``, ``findings`` or ``finding``; ``finding_id`` is
    set only for the ``finding`` kind.
    """

    scan_dir: str
    kind: str
    finding_id: Optional[str] = None


def encode_scan_dir(path: str) -> str:
    """The percent-encoded form of a scan directory path for a resource URI.

    Every character that could end a URI segment is encoded, the path
    separators included, so one segment always carries the whole path and
    parsing can split on the raw separators alone.
    """
    return quote(str(path), safe="")


def scan_resource_uri(scan_dir: str, tail: str) -> str:
    """The resource URI for a scan directory and a tail such as ``manifest``,
    ``findings`` or ``findings/<id>``.

    Every segment of the tail is percent-encoded, so an id carrying a
    URI-reserved character builds a URI that parses back to itself instead
    of breaking at the first ``?`` or ``#``. A slash inside a segment
    cannot survive the split into structure and segment, so a tail built
    that way parses as an unsupported URI and is refused, loudly.
    """
    encoded_tail = "/".join(quote(segment, safe="") for segment in tail.split("/"))
    return f"{URI_SCHEME}://{URI_AUTHORITY}/{encode_scan_dir(scan_dir)}/{encoded_tail}"


def _invalid_uri_error(uri: str) -> MCPError:
    return MCPError(
        code=types.INVALID_PARAMS,
        message=(
            f"unsupported resource URI '{uri}': this server serves the "
            f"templates {MANIFEST_TEMPLATE}, {FINDINGS_TEMPLATE} and "
            f"{FINDING_TEMPLATE}, with the scan directory percent-encoded"
        ),
    )


def parse_scan_uri(uri: str) -> ParsedResourceUri:
    """The scan directory, kind and finding id one resource URI names.

    The scan directory is the first path segment, percent-encoded, and the
    segments after it must spell ``manifest``, ``findings`` or
    ``findings/<id>``; anything else is refused, naming the templates this
    server serves.
    """
    parts = urlsplit(str(uri))
    if parts.scheme.lower() != URI_SCHEME or parts.netloc.lower() != URI_AUTHORITY:
        raise _invalid_uri_error(str(uri))
    if parts.query or parts.fragment:
        raise _invalid_uri_error(str(uri))
    segments = parts.path.split("/")
    if not segments or segments[0] != "":
        raise _invalid_uri_error(str(uri))
    segments = segments[1:]
    if len(segments) < 2 or not segments[0] or segments[-1] == "":
        raise _invalid_uri_error(str(uri))
    tail = segments[1:]
    scan_dir = unquote(segments[0])
    if tail == ["manifest"]:
        return ParsedResourceUri(scan_dir=scan_dir, kind="manifest")
    if tail == ["findings"]:
        return ParsedResourceUri(scan_dir=scan_dir, kind="findings")
    if len(tail) == 2 and tail[0] == "findings" and tail[1]:
        return ParsedResourceUri(scan_dir=scan_dir, kind="finding", finding_id=unquote(tail[1]))
    raise _invalid_uri_error(str(uri))


def _startup_roots(ctx) -> Tuple[str, ...]:
    """The roots fixed when the server started, from the lifespan state.

    The state is the mapping the server's lifespan yields; a context
    without one confines nothing and every read is refused.
    """
    state = getattr(ctx, "lifespan_context", None)
    if isinstance(state, dict):
        return tuple(state.get("startup_roots") or ())
    return tuple(getattr(state, "startup_roots", ()) or ())


async def _effective_roots(ctx) -> Tuple[str, ...]:
    """The roots one read is confined by: the startup roots plus the roots
    the client announced."""
    return await server_mod.effective_roots_for(ctx, _startup_roots(ctx))


def _refused_error(exc: confinement.PathOutsideRootsError) -> MCPError:
    """The protocol error for a confinement refusal, carrying the rule."""
    return MCPError(code=types.INVALID_PARAMS, message=str(exc))


def _missing_document_error(scan_root: str, filename: str) -> MCPError:
    return MCPError(
        code=types.INVALID_PARAMS,
        message=(
            f"the scan directory '{scan_root}' holds no {filename}; the "
            "manifest and findings resources read a scan directory this "
            "version of dep-scan wrote"
        ),
    )


def _unreadable_document_error(scan_root: str, filename: str, missing: str) -> MCPError:
    return MCPError(
        code=types.INVALID_PARAMS,
        message=(
            f"the {filename} in '{scan_root}' is unreadable: it carries no "
            f"{missing}, so it is not a document this version of dep-scan "
            "wrote"
        ),
    )


def _document(scan_root: str, parsed: ParsedResourceUri) -> Any:
    """The document one resource URI names, or an error naming what is missing.

    A missing manifest, a missing findings file, a document that does not
    parse or parses without the fields the writer always writes (the
    manifest's ``layoutVersion``, the findings document's ``schemaVersion``
    and ``findings``), and an id no finding carries are errors, never empty
    documents: a resource read must not dress a missing or broken result up
    as a clean one.
    """
    if parsed.kind == "manifest":
        manifest = scan_directory.read_manifest(scan_root)
        if manifest is None:
            raise _missing_document_error(scan_root, scan_directory.MANIFEST_FILE)
        if not isinstance(manifest.get("layoutVersion"), str) or not manifest["layoutVersion"]:
            raise _unreadable_document_error(
                scan_root, scan_directory.MANIFEST_FILE, "layoutVersion"
            )
        return manifest
    # A findings file that is not valid JSON raises from the reader; the
    # reader's message names the file and the parse failure, which is the
    # refusal this layer passes on for that shape.
    try:
        findings_document = scan_directory.read_findings(scan_root)
    except ValueError as exc:
        raise MCPError(code=types.INVALID_PARAMS, message=str(exc)) from exc
    if findings_document is None:
        raise _missing_document_error(scan_root, scan_directory.FINDINGS_FILE)
    if not isinstance(findings_document.get("schemaVersion"), str) or not isinstance(
        findings_document.get("findings"), list
    ):
        raise _unreadable_document_error(
            scan_root, scan_directory.FINDINGS_FILE, "schemaVersion and findings array"
        )
    if parsed.kind == "findings":
        return findings_document
    for finding in findings_document.get("findings") or []:
        if isinstance(finding, dict) and str(finding.get("id") or "") == parsed.finding_id:
            return finding
    raise MCPError(
        code=types.INVALID_PARAMS,
        message=(
            f"no finding with id '{parsed.finding_id}' in "
            f"{scan_directory.FINDINGS_FILE} of '{scan_root}'"
        ),
    )


async def handle_list_resources(ctx, params) -> types.ListResourcesResult:
    """List the static resources of this server: there are none.

    Every resource of this server names a scan directory, so every resource
    comes through the templates of :func:`handle_list_resource_templates`.
    """
    return types.ListResourcesResult(resources=[])


async def handle_list_resource_templates(ctx, params) -> types.ListResourceTemplatesResult:
    """The three scan-directory templates, the scan directory percent-encoded
    and the read confined to the allowed roots."""
    return types.ListResourceTemplatesResult(
        resource_templates=[
            types.ResourceTemplate(
                uri_template=MANIFEST_TEMPLATE,
                name="Scan manifest",
                description=(
                    f"The scan directory's {scan_directory.MANIFEST_FILE} "
                    "document. {scan_dir} is the absolute path, "
                    "percent-encoded; the read is confined to the allowed "
                    "roots."
                ),
                mime_type=RESOURCE_MIME_TYPE,
            ),
            types.ResourceTemplate(
                uri_template=FINDINGS_TEMPLATE,
                name="Scan findings",
                description=(
                    f"The scan directory's {scan_directory.FINDINGS_FILE} "
                    "document, every finding of the scan. {scan_dir} is the "
                    "absolute path, percent-encoded; the read is confined to "
                    "the allowed roots."
                ),
                mime_type=RESOURCE_MIME_TYPE,
            ),
            types.ResourceTemplate(
                uri_template=FINDING_TEMPLATE,
                name="Scan finding",
                description=(
                    "One finding of the scan, the id from the findings "
                    "document. {scan_dir} is the absolute path, "
                    "percent-encoded; the read is confined to the allowed "
                    "roots."
                ),
                mime_type=RESOURCE_MIME_TYPE,
            ),
        ]
    )


async def handle_read_resource(ctx, params) -> types.ReadResourceResult:
    """Read the document one URI names and return it as JSON text.

    The URI is parsed, the scan directory it names is confined against the
    effective roots, and the manifest, the findings document or the one
    finding is returned as text. Every refusal names the rule it broke or
    the file or id that was missing. A failure outside that vocabulary,
    a file read error, keeps its own name and message, the way tool errors
    do, instead of the SDK's generic internal error that would drop the
    reason before it reaches the client.
    """
    roots = await _effective_roots(ctx)
    parsed = parse_scan_uri(params.uri)
    try:
        scan_root = confinement.confine(parsed.scan_dir, roots)
        confinement.confine_contents(scan_root, roots)
    except confinement.PathOutsideRootsError as exc:
        raise _refused_error(exc) from exc
    if not os.path.isdir(scan_root):
        raise MCPError(
            code=types.INVALID_PARAMS,
            message=(
                f"the scan directory '{parsed.scan_dir}' does not exist or "
                "is not a directory"
            ),
        )
    try:
        document = _document(scan_root, parsed)
        text = json.dumps(document, indent=2, sort_keys=True)
    except MCPError:
        raise
    except Exception as exc:  # noqa: BLE001 - an unexpected failure still names itself
        raise MCPError(
            code=types.INTERNAL_ERROR,
            message=f"{type(exc).__name__}: {exc}",
        ) from exc
    return types.ReadResourceResult(
        contents=[
            types.TextResourceContents(
                uri=str(params.uri),
                mime_type=RESOURCE_MIME_TYPE,
                text=text,
            )
        ]
    )


def _render_triage_findings(scan_dir: Optional[str]) -> str:
    """The triage_findings template text for a scan directory, or none."""
    directory = scan_dir or "<scan_dir>"
    preamble = ""
    if not scan_dir:
        preamble = (
            f"No {SCAN_DIR_ARGUMENT} argument was given. Ask for the "
            "absolute path of the dep-scan scan directory to triage, then "
            f"use that path as the {SCAN_DIR_ARGUMENT} argument of every "
            "call below.\n\n"
        )
    return (
        f"{preamble}"
        "Triage the security findings of the dep-scan scan directory at "
        f'"{directory}".\n'
        "\n"
        "Call the dep-scan MCP tools in this order:\n"
        "\n"
        f"1. Call scan_summary with {SCAN_DIR_ARGUMENT} \"{directory}\" to "
        "read the finding counts by category and severity.\n"
        f"2. Call list_findings with {SCAN_DIR_ARGUMENT} \"{directory}\", "
        "using its severity, category, purl, cwe, rule and reachable "
        "filters where they help, and follow nextCursor until no page "
        "remains.\n"
        "3. Call get_finding for each finding you consider serious, to "
        "read the details a list page leaves out.\n"
        "4. Call explain_finding when reachability matters; the text it "
        "returns covers the whole scan, not one finding.\n"
        f"5. Call coverage with {SCAN_DIR_ARGUMENT} \"{directory}\" to read "
        "the checks that were not assessed, so the triage can say where "
        "the scan is blind.\n"
        "\n"
        "Then write the triage here: for each finding you judge important, "
        "give its id, title, severity, the affected components, and the "
        "exploitability or reachability facts the finding itself carries. "
        "Base every statement on what the tools returned, and say so when "
        "a call failed or spilled to a file. The server records nothing; "
        "this triage is text for this conversation."
    )


def _render_plan_fixes(scan_dir: Optional[str]) -> str:
    """The plan_fixes template text for a scan directory, or none."""
    directory = scan_dir or "<scan_dir>"
    preamble = ""
    if not scan_dir:
        preamble = (
            f"No {SCAN_DIR_ARGUMENT} argument was given. Ask for the "
            "absolute path of the dep-scan scan directory to plan fixes "
            f"for, then use that path as the {SCAN_DIR_ARGUMENT} argument "
            "of every call below.\n\n"
        )
    return (
        f"{preamble}"
        "Plan fixes for the security findings of the dep-scan scan "
        f'directory at "{directory}".\n'
        "\n"
        "Call the dep-scan MCP tools in this order:\n"
        "\n"
        f"1. Call list_findings with {SCAN_DIR_ARGUMENT} \"{directory}\" "
        "and follow nextCursor until every page is read.\n"
        "2. Call get_finding for each finding the plan will cover, to "
        "read the fix field when the finding carries one, with its "
        "coverage and exploitability.\n"
        "3. Call explain_finding when reachability should shape the order; "
        "the text it returns covers the whole scan, not one finding.\n"
        f"4. Call coverage with {SCAN_DIR_ARGUMENT} \"{directory}\" to read "
        "the checks that were not assessed, and say in the plan where the "
        "scan is blind.\n"
        "\n"
        "Then write an ordered fix plan here, using only what the tools "
        "returned: the fix information each finding carries, its severity, "
        "and the affected components. The server does not apply fixes and "
        "records nothing; the plan is a proposal for this conversation to "
        "review."
    )


_PROMPTS: Dict[str, Dict[str, Any]] = {
    "triage_findings": {
        "description": (
            "Triage the findings of a dep-scan scan directory, from what "
            "the scan_summary, list_findings, get_finding, "
            "explain_finding and coverage tools return."
        ),
        "render": _render_triage_findings,
    },
    "plan_fixes": {
        "description": (
            "Draft a fix plan for the findings of a dep-scan scan "
            "directory, from what the list_findings, get_finding, "
            "explain_finding and coverage tools return."
        ),
        "render": _render_plan_fixes,
    },
}


async def handle_list_prompts(ctx, params) -> types.ListPromptsResult:
    """The two prompts, each with its optional scan_dir argument."""
    return types.ListPromptsResult(
        prompts=[
            types.Prompt(
                name=name,
                description=spec["description"],
                arguments=[
                    types.PromptArgument(
                        name=SCAN_DIR_ARGUMENT,
                        description=(
                            "The absolute path of the scan directory; "
                            "omit it to render the template with a "
                            "placeholder and ask for the path."
                        ),
                        required=False,
                    )
                ],
            )
            for name, spec in _PROMPTS.items()
        ]
    )


async def handle_get_prompt(ctx, params) -> types.GetPromptResult:
    """Render one prompt, with the scan directory interpolated when given.

    An unknown prompt name is refused, naming the prompts this server
    defines. The scan_dir argument is interpolated verbatim; it is confined
    when the tools the template names read it, not here.
    """
    name = str(params.name)
    spec = _PROMPTS.get(name)
    if spec is None:
        raise MCPError(
            code=types.INVALID_PARAMS,
            message=(
                f"unknown prompt '{name}'; this server defines: "
                f"{', '.join(PROMPT_NAMES)}"
            ),
        )
    arguments = params.arguments or {}
    scan_dir_value = arguments.get(SCAN_DIR_ARGUMENT)
    scan_dir = str(scan_dir_value).strip() if scan_dir_value is not None else None
    text = spec["render"](scan_dir or None)
    return types.GetPromptResult(
        description=spec["description"],
        messages=[
            types.PromptMessage(
                role="user",
                content=types.TextContent(type="text", text=text),
            )
        ],
    )
