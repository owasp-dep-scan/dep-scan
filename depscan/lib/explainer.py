"""The explanation rendering over the evidence store.

Every producer's records are rendered the same way: the reached modes show
the positive records that count as reached evidence and the exploit chains
that put them in context, with the witness path's file and line when the
producer walked one and the subject purls otherwise; the NonReachables mode
shows the negative records (dead code, no observed path, sanitizers) plus the
reached packages that carry no finding. Nothing here knows a report format:
the adapters already reduced each producer's report to records.

The section structure, the headings, the endpoint table and the LLM prompt
mode are the ones the explanation rendering has always had.
"""

import glob
import os
from collections import defaultdict

from custom_json_diff.lib.utils import json_load
from rich import box
from rich.markdown import Markdown
from rich.table import Table
from rich.tree import Tree

from analysis_lib.evidence.store import EVIDENCE_FILE, stream as stream_evidence
from analysis_lib.reachability import REACHED_COUNTED_KINDS
from depscan.lib.config import (
    max_flows_per_prompt,
    max_purl_per_flow,
    max_reachable_explanations,
)
from depscan.lib.logger import LOG, console

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "white",
    "UNKNOWN": "white",
}

#: The negative record kinds the NonReachables mode renders.
NON_REACHABLE_KINDS = ("dead-code", "no-path", "sanitizer")

#: What a record of each kind says, when nothing more specific applies.
_KIND_DESCRIPTIONS = {
    "reached-flow": "reachable data-flow",
    "usage": "identifiable usages of the package",
    "callsite": "call sites of the package",
    "entry-point": "an application entry point",
    "exploit-chain": "an exploit chain",
    "sanitizer": "a sanitization",
    "dead-code": "code with no path from any entry point",
    "no-path": "no path to the vulnerable function",
}


def _store_records(store_path: str) -> list:
    """The store's records, or an empty list when there is no store. A store
    that cannot be read is named on the log and reads as nothing, the way a
    slice file that could not be parsed always did."""
    if not os.path.isfile(store_path):
        return []
    try:
        return list(stream_evidence(store_path))
    except (OSError, ValueError) as e:
        LOG.warning("The evidence store %s could not be read: %s", store_path, e)
        return []


def explain(
    project_type,
    src_dir,
    bom_dir,
    vdr_file,
    vdr_result,
    explanation_mode,
    prompts_file=None,
    evidence_file=None,
):
    """
    Explain the analysis and findings based on the explanation mode.

    :param project_type: Project type
    :param src_dir: Source directory
    :param bom_dir: BOM directory
    :param vdr_file: VDR file
    :param vdr_result: VDR Result
    :param explanation_mode: Explanation mode
    :param prompts_file: File path to save LLM prompts
    :param evidence_file: The evidence store to render; the store at the top
        of the BOM directory when not given
    """
    pattern_methods = {}
    openapi_spec_files = None

    purl_vuln_map = defaultdict(list)
    if vdr_result and vdr_result.pkg_vulnerabilities:
        for vuln in vdr_result.pkg_vulnerabilities:
            ref = vuln.get("bom-ref") or vuln.get("purl")
            if ref:
                purl_vuln_map[ref].append(vuln)

    # Should we explain the endpoints and Code Hotspots
    if explanation_mode in ("Endpoints", "EndpointsAndReachables", "LLMPrompts"):
        openapi_spec_files = glob.glob(f"{bom_dir}/*openapi*.json", recursive=False)
        if not openapi_spec_files:
            openapi_spec_files = glob.glob(f"{src_dir}/*openapi*.json", recursive=False)
    if openapi_spec_files:
        rsection = Markdown("""## Service Endpoints

The following endpoints and code hotspots were identified by depscan. Verify that proper authentication and authorization mechanisms are in place to secure them.""")
        any_endpoints_shown = False
        for ospec in openapi_spec_files:
            pattern_methods = print_endpoints(ospec, rsection if not any_endpoints_shown else None)
            if not any_endpoints_shown and pattern_methods:
                any_endpoints_shown = True

    # Return early for endpoints only explanations
    if explanation_mode in ("Endpoints",):
        return
    store = evidence_file or os.path.join(str(bom_dir), EVIDENCE_FILE)
    records = _store_records(store)
    if not records:
        return
    section_title = (
        "Non-Reachable Flows" if explanation_mode in ("NonReachables",) else "Reachable Flows"
    )
    if pattern_methods:
        rsection = Markdown(
            f"""## {section_title}

Below are some reachable flows, including those accessible via endpoints, identified by depscan. Use the generated OpenAPI specification to evaluate these endpoints for vulnerabilities and risk.
            """
        )
    elif explanation_mode in ("NonReachables",):
        rsection = Markdown(
            f"""## {section_title}

Below are several data flows deemed safe and non-reachable. Use the provided tips to confirm this assessment.
            """
        )
    else:
        rsection = Markdown(
            f"""## {section_title}

Below are several data flows identified by depscan, including reachable ones. Use the tips provided to strengthen your application’s security posture.
            """
        )
    has_explanation, tips = explain_records(
        explanation_mode,
        records,
        project_type,
        vdr_result,
        purl_vuln_map,
        prompts_file,
        rsection,
    )
    if has_explanation:
        # The blank line closes the last flow table. The HTML report's parser
        # only carries a table's packages column into the report once a blank
        # line follows the table, so the section must not end on the caption.
        console.print()
    if has_explanation and tips:
        console.print(Markdown(tips))


def _track_usage_targets(usage_targets, usages_object):
    if not isinstance(usages_object, dict):
        return
    for k, v in usages_object.items():
        if not isinstance(v, dict):
            continue
        for file, lines in v.items():
            # x-atom-usages values are per-file lists of line numbers;
            # atom-tools writes "call" and "target" in the same shape.
            # Anything else is ignored rather than crashing the rendering.
            if isinstance(lines, (list, tuple, set)):
                for aline in lines:
                    usage_targets.add(f"{file}#{aline}")


def print_endpoints(ospec, header_section=None):
    if not ospec:
        return
    spec_data = json_load(ospec)
    if not isinstance(spec_data, dict):
        return defaultdict(list)
    paths = spec_data.get("paths") or {}
    if not isinstance(paths, dict):
        return defaultdict(list)
    pattern_methods = defaultdict(list)
    pattern_usage_targets = defaultdict(set)
    for pattern, path_obj in paths.items():
        if not isinstance(path_obj, dict):
            continue
        usage_targets = set()
        http_method_added = False
        for k, v in path_obj.items():
            if k == "parameters":
                continue
            # Java, JavaScript, Python etc
            if k == "x-atom-usages":
                _track_usage_targets(usage_targets, v)
                continue
            if isinstance(v, dict) and v.get("x-atom-usages"):
                _track_usage_targets(usage_targets, v.get("x-atom-usages"))
            pattern_methods[pattern].append(k)
            http_method_added = True
        pattern_usage_targets[pattern] = usage_targets
        # We see an endpoint, but do not know the HTTP methods.
        # Let's track them as empty
        if not http_method_added and usage_targets:
            pattern_methods[pattern].append("")
    caption = ""
    if pattern_methods:
        caption = f"Identified Endpoints: {len(pattern_methods.keys())}"
    rtable = Table(
        box=box.DOUBLE_EDGE,
        show_lines=True,
        title="Endpoints",
        caption=caption,
    )
    for c in ("URL Pattern", "HTTP Methods", "Code Hotspots"):
        rtable.add_column(header=c, vertical="top")
    for k, v in pattern_methods.items():
        v.sort()
        sorted_areas = list(pattern_usage_targets[k])
        sorted_areas.sort()
        rtable.add_row(k, ("\n".join(v)).upper(), "\n".join(sorted_areas))
    if pattern_methods:
        # Print the header section
        if header_section:
            console.print(header_section)
        console.print()
        console.print(rtable)
    return pattern_methods


def get_vulns_for_purls(purls, purl_vuln_map):
    """
    Finds the highest severity vulnerability among the given purls.
    Returns (max_severity, [list_of_vuln_ids])
    """
    if not purls or not purl_vuln_map:
        return None, []

    found_vulns = []
    max_severity_val = 100
    severity_order = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
        "INFO": 5,
        "UNKNOWN": 6,
    }

    current_max_severity = None

    for p in purls:
        vulns = purl_vuln_map.get(p, [])
        for v in vulns:
            v_id = v.get("id")
            v_sev = str(v.get("severity", "UNKNOWN")).upper()

            if v_id and v_id not in found_vulns:
                found_vulns.append(v_id)

            rank = severity_order.get(v_sev, 6)
            # current_max_severity starts as None before the first
            # vulnerability is seen; the "" fallback maps it to the 100 rank.
            current_rank = severity_order.get(current_max_severity or "", 100)

            if rank < current_rank:
                current_max_severity = v_sev

    return current_max_severity, found_vulns


def _record_locations_tree(record) -> Tree:
    """The witness path as a tree of ``file#line    method (symbol)`` rows,
    or the subject purls as one row when the producer walked no path."""
    tree = None
    last_row = None
    for node in record.path or []:
        file_name = getattr(node, "file", None)
        line = getattr(node, "line", None)
        method = getattr(node, "method", None)
        symbol = getattr(node, "symbol", None)
        location = ""
        if file_name and not str(file_name).startswith("unknown"):
            location = f"{file_name}#{line if line else ''}    "
        label = method or symbol or ""
        row = f"[gray37]{location}[/gray37]{label}".strip()
        if not row or row == last_row:
            continue
        last_row = row
        if tree is None:
            tree = Tree(row)
        else:
            tree.add(row)
    if tree is None:
        purls = record.subject.purls or []
        label = _KIND_DESCRIPTIONS.get(record.kind, record.kind)
        if record.locations:
            location = record.locations[0]
            place = f"{location.file}#{location.line if location.line else ''}"
            label = f"{label} at {place.strip()}"
        tree = Tree(label if not purls else f"{label}: {len(purls)} package(s)")
    return tree


def _record_description(record, vdr_result, purl_vuln_map):
    """What the record says, in the wording the flow rendering used: where it
    can reach the package from, and how exposed that way in."""
    endpoint_reached_purls = getattr(vdr_result, "endpoint_reached_purls", None) or {}
    reached_services = getattr(vdr_result, "reached_services", None) or {}
    purls = record.subject.purls or []
    attributes = record.attributes if isinstance(record.attributes, dict) else {}
    is_endpoint_reachable = any(p in endpoint_reached_purls for p in purls)
    is_reachable_service = any(p in reached_services for p in purls)
    kind = record.kind
    if kind == "exploit-chain":
        hops = attributes.get("hopCount")
        exposure = attributes.get("exposure") or "unknown"
        desc = f"An exploit chain of {hops} hop(s) from {exposure} entry points"
        entry_id = attributes.get("entryPointId")
        if entry_id:
            desc += f" (entry point {entry_id})"
        if is_endpoint_reachable:
            desc += ", reachable from certain endpoints"
        return desc + "."
    if kind == "sanitizer":
        sanitizer_kind = attributes.get("kind") or "sanitization"
        return f"A {sanitizer_kind} sanitization was identified along the flows to this package."
    if kind == "dead-code":
        fan_in = attributes.get("fanIn")
        fan_out = attributes.get("fanOut")
        desc = "This code has no path from any entry point"
        if fan_in is not None or fan_out is not None:
            desc += f" (fanIn={fan_in}, fanOut={fan_out})"
        return desc + "."
    if kind == "no-path":
        return "No path to the vulnerable function was observed in the traced execution."
    label = _KIND_DESCRIPTIONS.get(kind, kind)
    if attributes.get("route"):
        desc = f"Requests to {attributes['route']} reach this entry point"
    elif kind == "entry-point":
        desc = f"An entry point ({attributes.get('exposure') or attributes.get('kind') or 'unknown exposure'})"
    else:
        desc = label.capitalize() if label[:1].islower() else label
    if not purls:
        if is_endpoint_reachable:
            desc += ", reachable from certain endpoints"
        return desc + "."
    if len(purls) == 1:
        if is_endpoint_reachable:
            desc += ", reachable from certain endpoints"
        elif is_reachable_service:
            desc += ", reachable as an external service"
        return desc + "."
    if is_endpoint_reachable:
        desc = f"{desc} can be used to reach {len(purls)} packages from certain endpoints"
    else:
        desc = f"{desc} can be used to reach {len(purls)} packages"
    return desc + "."


def _record_comment(record, purl_vuln_map):
    """The caption under the table: the packages the record is about, each
    with the id of the finding it appears in.

    The label is the one the HTML report's parser looks for when it splits a
    flow table into its summary, flow and package columns.
    """
    comments = []
    purls = record.subject.purls or []
    negative = record.polarity == "negative"
    if len(purls) > max_purl_per_flow:
        comments.append(
            ":exclamation_mark: Refactor this flow to minimize the use of external libraries."
        )
    if purls:
        purls_display = []
        for p in purls:
            max_sev, vulns = get_vulns_for_purls([p], purl_vuln_map)
            if max_sev:
                style = SEVERITY_COLORS.get(max_sev, "white")
                purls_display.append(f"[{style}]{p} ({', '.join(vulns)})[/{style}]")
            else:
                purls_display.append(p)
        label = "Non-Reachable Packages:" if negative else "Reachable Packages:"
        comments.append(f"[info]{label}[/info]\n" + "\n".join(purls_display))
    return "\n".join(comments)


def explain_records(
    explanation_mode,
    records,
    project_type,
    vdr_result,
    purl_vuln_map,
    prompts_file=None,
    header_section=None,
):
    """Render the records the mode asks for, and return whether anything was
    rendered together with the design tips that follow it.

    The reached modes render the positive records that count as reached
    evidence and the exploit chains beside them. The NonReachables mode
    renders the negative records and the reached packages that carry no
    finding, the packages whose reach is not the reason to worry.
    """
    reachable_explanations = 0
    purls_reachable_explanations = defaultdict(int)
    has_explanation = False
    header_shown = False
    has_sanitizer = False
    explained_ids = {}
    purl_grouped_records = defaultdict(list)
    negative_only = explanation_mode in ("NonReachables",)

    for record in records:
        if reachable_explanations + 1 > max_reachable_explanations:
            break
        if record.polarity == "negative":
            wanted = negative_only and record.kind in NON_REACHABLE_KINDS
        else:
            counted = record.kind in REACHED_COUNTED_KINDS
            if negative_only:
                wanted = (
                    counted
                    and bool(record.subject.purls)
                    and not any(p in purl_vuln_map for p in record.subject.purls)
                )
            else:
                wanted = counted or record.kind == "exploit-chain"
        if not wanted:
            continue
        if record.kind == "sanitizer":
            has_sanitizer = True
        # Have we rendered this record already? The store is deduped by id,
        # so this only guards a caller-held list that was not.
        if explained_ids.get(record.id):
            continue
        explained_ids[record.id] = True
        max_severity, vuln_ids = get_vulns_for_purls(record.subject.purls, purl_vuln_map)
        desc = _record_description(record, vdr_result, purl_vuln_map)
        title_style = "bold"
        if max_severity and max_severity in SEVERITY_COLORS:
            title_style = SEVERITY_COLORS[max_severity]
            desc = (
                f"[{title_style}][{max_severity} {', '.join(vuln_ids)}][/{title_style}] {desc}"
            )
        rtable = Table(
            box=box.DOUBLE_EDGE,
            show_lines=True,
            caption=_record_comment(record, purl_vuln_map),
            show_header=False,
            title=(
                f"[bold]#{reachable_explanations + 1}[/bold] "
                f"{record.producer.name} {record.kind}: {desc}"
            ),
            title_justify="left",
            min_width=150,
            border_style=title_style if max_severity else "white",
        )
        rtable.add_column(header="Flow", vertical="top")
        rtable.add_row(_record_locations_tree(record))
        if not header_shown and header_section:
            console.print()
            console.print(header_section)
            header_shown = True
        console.print()
        console.print(rtable)
        has_explanation = True
        reachable_explanations += 1
        purls_str = ",".join(sorted(record.subject.purls))
        if purls_str:
            purls_reachable_explanations[purls_str] += 1
        if (
            explanation_mode in ("LLMPrompts",)
            and record.kind in REACHED_COUNTED_KINDS
            and record.path
        ):
            endpoint_reached_purls = getattr(vdr_result, "endpoint_reached_purls", None) or {}
            if any(p in endpoint_reached_purls for p in record.subject.purls):
                for p in record.subject.purls:
                    purl_grouped_records[p].append(record)

    tips = """## Secure Design Tips"""
    if negative_only:
        tips += """
- Automate tests (including fuzzing) to verify validation, sanitization, encoding, and encryption.
- Align the implementation with the original architecture and threat models to ensure security compliance.
- Extract reusable methods into a shared library for organization-wide use.
"""
    elif has_explanation:
        if has_sanitizer:
            tips += """
- Review the validation and sanitization methods used in the application.
- To enhance the security posture, implement a common validation middleware.
"""
        elif purls_reachable_explanations:
            tips += """
- Consider implementing a common validation and sanitization library to reduce the risk of exploitability.
"""
        else:
            tips += """
- Enhance your unit and integration tests to cover the flows listed above.
- Continuously fuzz the parser and validation functions with diverse payloads.
"""
    if purl_grouped_records:
        save_llm_prompts(purl_grouped_records, purl_vuln_map, project_type, prompts_file)
    return has_explanation, tips


def get_comment_symbol(filename):
    """
    Returns the appropriate comment symbol based on the file extension.
    """
    if filename.endswith((".py", ".rb", ".sh", ".pl", ".yaml", ".yml", ".dockerfile")):
        return "#"
    return "//"


def generate_grouped_llm_prompt(purl, records, purl_vuln_map, project_type):
    """
    Generates a consolidated prompt for a specific PURL and its reachable records.
    """
    max_sev, vulns = get_vulns_for_purls([purl], purl_vuln_map)
    vuln_text = f", associated with {', '.join(vulns)}" if vulns else ""

    prompt = f"## LLM Prompt for `{purl}`\n\n"
    prompt += f"Analyze the security risks for the package `{purl}`{vuln_text}. "
    prompt += f"depscan identified {len(records)} endpoint reachable data flows leading to this package.\n\n"

    count = 0
    for record in records:
        if count >= max_flows_per_prompt:
            prompt += f"... (and {len(records) - max_flows_per_prompt} more flows)\n"
            break

        attributes = record.attributes if isinstance(record.attributes, dict) else {}
        desc = attributes.get("route") or _record_description(record, None, purl_vuln_map)
        desc = desc.replace("[", "").replace("]", "")

        prompt += f"### Flow #{count + 1}: {desc}\n\n"
        last_symbol = ""
        for node in record.path or []:
            symbol = getattr(node, "symbol", None) or getattr(node, "method", None) or ""
            if last_symbol and last_symbol == symbol:
                continue
            last_symbol = symbol
            filename = getattr(node, "file", None) or ""
            lineno = getattr(node, "line", None) or ""
            if filename and len(symbol) < 8:
                continue
            if filename:
                comment_symbol = get_comment_symbol(filename)
                symbol = f"{comment_symbol} {symbol}"
            prompt += f"- Source: `{filename}:{lineno}`\n```\n{symbol}\n```\n"
        prompt += "\n"
        count += 1

    prompt += "Based on these data flows, explain how an attacker might exploit the vulnerabilities in this package and suggest secure code fixes or mitigations."
    return prompt


def save_llm_prompts(purl_grouped_records, purl_vuln_map, project_type, prompts_file):
    """
    Iterates through grouped records and saves consolidated LLM prompts to a file.
    """
    if not prompts_file:
        return
    with open(prompts_file, "w", encoding="utf-8") as f:
        f.write("# LLM Prompts generated by OWASP dep-scan\n\n")
        for purl, records in purl_grouped_records.items():
            prompt_text = generate_grouped_llm_prompt(
                purl, records, purl_vuln_map, project_type
            )
            f.write(prompt_text)
            f.write("\n---\n\n")
