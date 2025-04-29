import re
import glob
from collections import defaultdict
from custom_json_diff.lib.utils import json_load
from rich import box
from rich.markdown import Markdown
from rich.table import Table
from rich.tree import Tree

from depscan.lib.config import (
    COMMON_CHECK_TAGS,
    max_purl_per_flow,
    max_reachable_explanations,
    max_purls_reachable_explanations,
)
from depscan.lib.logger import console, LOG


def explain(project_type, src_dir, bom_dir, vdr_file, vdr_result, explanation_mode):
    """
    Explain the analysis and findings based on the explanation mode.

    :param project_type: Project type
    :param src_dir: Source directory
    :param bom_dir: BOM directory
    :param vdr_file: VDR file
    :param vdr_result: VDR Result
    :param explanation_mode: Explanation mode
    """
    pattern_methods = {}
    has_any_explanation = False
    has_any_crypto_flows = False
    slices_files = glob.glob(f"{bom_dir}/**/*reachables.slices.json", recursive=True)
    openapi_spec_files = None
    # Should we explain the endpoints and Code Hotspots
    if explanation_mode in (
        "Endpoints",
        "EndpointsAndReachables",
    ):
        openapi_spec_files = glob.glob(f"{bom_dir}/*openapi*.json", recursive=False)
        if not openapi_spec_files:
            openapi_spec_files = glob.glob(f"{src_dir}/*openapi*.json", recursive=False)
    if openapi_spec_files:
        rsection = Markdown("""## Service Endpoints

The following endpoints and code hotspots were identified by depscan. Verify that proper authentication and authorization mechanisms are in place to secure them.""")
        console.print(rsection)
        for ospec in openapi_spec_files:
            pattern_methods = print_endpoints(ospec)
    # Return early for endpoints only explanations
    if explanation_mode in ("Endpoints",):
        return
    section_title = (
        "Non-Reachable Flows"
        if explanation_mode in ("NonReachables",)
        else "Reachable Flows"
    )
    for sf in slices_files:
        if (reachables_data := json_load(sf, log=LOG)) and reachables_data.get(
            "reachables"
        ):
            if explanation_mode in ("NonReachables",):
                rsection = Markdown(
                    f"""## {section_title}

Below are several data flows deemed safe and non-reachable. Use the provided tips to confirm this assessment.
                """
                )
            elif pattern_methods:
                rsection = Markdown(
                    f"""## {section_title}

Below are some reachable flows, including those accessible via endpoints, identified by depscan. Use the generated OpenAPI specification to evaluate these endpoints for vulnerabilities and risk.
                """
                )
            else:
                rsection = Markdown(
                    f"""## {section_title}

Below are several data flows identified by depscan, including reachable ones. Use the tips provided to strengthen your application’s security posture.
                """
                )
            has_explanation, has_crypto_flows, tips = explain_reachables(
                explanation_mode,
                reachables_data,
                project_type,
                vdr_result,
                rsection if not has_any_explanation else None,
            )
            if not has_any_explanation and has_explanation:
                has_any_explanation = True
            if not has_any_crypto_flows and has_crypto_flows:
                has_any_crypto_flows = True


def _track_usage_targets(usage_targets, usages_object):
    for k, v in usages_object.items():
        for file, lines in v.items():
            for l in lines:
                usage_targets.add(f"{file}#{l}")


def print_endpoints(ospec):
    if not ospec:
        return
    paths = json_load(ospec).get("paths") or {}
    pattern_methods = defaultdict(list)
    pattern_usage_targets = defaultdict(set)
    for pattern, path_obj in paths.items():
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
        console.print()
        console.print(rtable)
    return pattern_methods


def is_cpp_flow(flows):
    if not flows:
        return False
    attempts = 0
    for idx, aflow in enumerate(flows):
        if aflow.get("parentFileName", "").endswith(".c") or aflow.get(
            "parentFileName", ""
        ).endswith(".cpp"):
            return True
        attempts += 1
        if attempts > 3:
            return False
    return False


def explain_reachables(
    explanation_mode, reachables, project_type, vdr_result, header_section=None
):
    """"""
    reachable_explanations = 0
    checked_flows = 0
    has_crypto_flows = False
    purls_reachable_explanations = defaultdict(int)
    has_explanation = False
    header_shown = False
    for areach in reachables.get("reachables", []):
        if (
            not areach.get("flows")
            or len(areach.get("flows")) < 2
            or (not areach.get("purls") and not is_cpp_flow(areach.get("flows")))
        ):
            continue
        # Focus only on the prioritized list if available
        # if project_type in ("java",) and pkg_group_rows:
        #     is_prioritized = False
        #     for apurl in areach.get("purls"):
        #         if pkg_group_rows.get(apurl):
        #             is_prioritized = True
        #     if not is_prioritized:
        #         continue
        (
            flow_tree,
            comment,
            source_sink_desc,
            has_check_tag,
            is_endpoint_reachable,
            is_crypto_flow,
        ) = explain_flows(
            explanation_mode,
            areach.get("flows"),
            areach.get("purls"),
            project_type,
            vdr_result,
        )
        if not source_sink_desc or not flow_tree:
            continue
        # In non-reachables mode, we are not interested in reachable flows.
        if (
            explanation_mode
            and explanation_mode in ("NonReachables",)
            and not has_check_tag
        ):
            continue
        purls_str = ",".join(sorted(areach.get("purls", [])))
        if (
            purls_str
            and purls_reachable_explanations[purls_str] + 1
            > max_purls_reachable_explanations
        ):
            continue
        if not has_explanation:
            has_explanation = True
        # Did we find any crypto flows
        if is_crypto_flow and not has_crypto_flows:
            has_crypto_flows = True
        rtable = Table(
            box=box.DOUBLE_EDGE,
            show_lines=True,
            caption=comment,
            show_header=False,
            title=f"[bold]#{reachable_explanations + 1}[/bold] {source_sink_desc}",
            title_justify="left",
            min_width=150,
        )
        rtable.add_column(header="Flow", vertical="top")
        rtable.add_row(flow_tree)
        # Print the header first in case we haven't
        if not header_shown and header_section:
            console.print()
            console.print(header_section)
            header_shown = True
        console.print()
        console.print(rtable)
        reachable_explanations += 1
        if purls_str:
            purls_reachable_explanations[purls_str] += 1
        if has_check_tag:
            checked_flows += 1
        if reachable_explanations + 1 > max_reachable_explanations:
            break
    tips = """## Secure Design Tips"""
    if explanation_mode in ("NonReachables",):
        tips += """
- Automate tests (including fuzzing) to verify validation, sanitization, encoding, and encryption.
- Align the implementation with the original architecture and threat models to ensure security compliance.
- Extract reusable methods into a shared library for organization-wide use.
"""
    elif has_explanation:
        if has_crypto_flows:
            tips += """
- Generate a Cryptographic BOM with cdxgen and monitor it in Dependency-Track.
"""
        elif checked_flows:
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
    if tips:
        rsection = Markdown(tips)
        console.print(rsection)
    return has_explanation, has_crypto_flows, tips


def flow_to_source_sink(idx, flow, purls, project_type, vdr_result):
    """ """
    endpoint_reached_purls = {}
    reached_services = {}
    if vdr_result:
        endpoint_reached_purls = vdr_result.endpoint_reached_purls
        reached_services = vdr_result.reached_services
    is_endpoint_reachable = False
    possible_reachable_service = False
    tags = flow.get("tags", [])
    is_crypto_flow = "crypto" in tags or "crypto-generate" in tags
    method_in_emoji = ":right_arrow_curving_left:"
    for p in purls:
        if endpoint_reached_purls and endpoint_reached_purls.get(p):
            is_endpoint_reachable = True
            method_in_emoji = ":heavy_large_circle: "
        if reached_services and reached_services.get(p):
            possible_reachable_service = True
    source_sink_desc = ""
    param_name = flow.get("name")
    method_str = "method"
    param_str = "Parameter"
    if param_name == "this":
        param_name = ""
    parent_file = flow.get("parentFileName", "")
    parent_method = flow.get("parentMethodName", "")
    # Improve the labels based on the language
    if re.search(".(js|ts|jsx|tsx|py|cs|php)$", parent_file):
        method_str = "function"
        param_str = "argument"
        if parent_method in ("handleRequest",):
            method_str = f"handler {method_str}"
        elif parent_method in ("__construct", "__init"):
            method_str = "constructor"
        elif project_type in ("php",) and parent_method.startswith("__"):
            method_str = f"magic {method_str}"
    if flow.get("label") == "METHOD_PARAMETER_IN":
        if param_name:
            source_sink_desc = f"""{param_str} [red]{param_name}[/red] {method_in_emoji} to the {method_str} [bold]{parent_method}[/bold]"""
        else:
            source_sink_desc = f"""{method_str.capitalize()} [red]{parent_method}[/red] {method_in_emoji}"""
    elif flow.get("label") == "CALL" and flow.get("isExternal"):
        method_full_name = flow.get("fullName", "")
        if not method_full_name.startswith("<"):
            source_sink_desc = f"Invocation: {method_full_name}"
    elif flow.get("label") == "RETURN" and flow.get("code"):
        source_sink_desc = flow.get("code").split("\n")[0]
    elif project_type not in ("java") and flow.get("label") == "IDENTIFIER":
        source_sink_desc = flow.get("code").split("\n")[0]
        if source_sink_desc.endswith("("):
            source_sink_desc = f":diamond_suit: {source_sink_desc})"
    # Try to understand the source a bit more
    if source_sink_desc.startswith("require("):
        source_sink_desc = "The flow originates from a module import."
    elif (
        ".use(" in source_sink_desc
        or ".subscribe(" in source_sink_desc
        or ".on(" in source_sink_desc
        or ".emit(" in source_sink_desc
        or " => {" in source_sink_desc
    ):
        source_sink_desc = "The flow originates from a callback function."
    elif (
        "middleware" in source_sink_desc.lower() or "route" in source_sink_desc.lower()
    ):
        source_sink_desc = "The flow originates from middleware."
    elif len(purls) == 0:
        if tags:
            source_sink_desc = (
                f"{source_sink_desc} can be used to reach packages with tags `{tags}`"
            )
    elif len(purls) == 1:
        if is_endpoint_reachable:
            source_sink_desc = f"{source_sink_desc} can be used to reach this package from certain endpoints."
        elif source_sink_desc:
            if is_crypto_flow:
                source_sink_desc = "Reachable crypto-flow."
            else:
                source_sink_desc = "Reachable data-flow."
    else:
        if is_endpoint_reachable:
            source_sink_desc = f"{source_sink_desc} can be used to reach {len(purls)} packages from certain endpoints."
        else:
            if source_sink_desc:
                source_sink_desc = (
                    f"{source_sink_desc} can be used to reach {len(purls)} packages."
                )
            elif is_crypto_flow:
                source_sink_desc = (
                    f"{len(purls)} packages reachable from this crypto-flow."
                )
            else:
                source_sink_desc = (
                    f"{len(purls)} packages reachable from this data-flow."
                )
    return source_sink_desc, is_endpoint_reachable, is_crypto_flow


def filter_tags(tags):
    if tags:
        tags = [
            atag
            for atag in tags.split(", ")
            if atag not in ("RESOLVED_MEMBER", "UNKNOWN_METHOD", "UNKNOWN_TYPE_DECL")
        ]
        return ", ".join(tags)
    return tags


def is_filterable_code(project_type, code):
    match project_type:
        case "js" | "ts" | "javascript" | "typescript" | "bom":
            for c in (
                "console.log",
                "thoughtLog(",
                "_tmp_",
                "LOG.debug(",
                "options.get(",
                "RET",
                "this.",
            ):
                if code and code.startswith(c):
                    return True
    return False


def flow_to_str(explanation_mode, flow, project_type):
    """"""
    has_check_tag = False
    file_loc = ""
    if (
        flow.get("parentFileName")
        and flow.get("lineNumber")
        and not flow.get("parentFileName").startswith("unknown")
    ):
        file_loc = f"{flow.get('parentFileName').replace('src/main/java/', '').replace('src/main/scala/', '')}#{flow.get('lineNumber')}    "
    node_desc = flow.get("code").split("\n")[0]
    if node_desc.endswith("("):
        node_desc = f":diamond_suit: {node_desc})"
    tags = filter_tags(flow.get("tags"))
    if flow.get("label") == "METHOD_PARAMETER_IN":
        param_name = flow.get("name")
        if param_name == "this":
            param_name = ""
        node_desc = f"{flow.get('parentMethodName')}([red]{param_name}[/red]) :right_arrow_curving_left:"
        if tags:
            node_desc = f"{node_desc}\n[bold]Tags:[/bold] [italic]{tags}[/italic]\n"
    elif flow.get("label") == "IDENTIFIER":
        if node_desc.startswith("<"):
            node_desc = flow.get("name")
        if tags:
            node_desc = f"{node_desc}\n[bold]Tags:[/bold] [italic]{tags}[/italic]\n"
    if tags and not is_filterable_code(project_type, node_desc):
        for ctag in COMMON_CHECK_TAGS:
            if ctag in tags:
                has_check_tag = True
                break
    if has_check_tag:
        if explanation_mode in ("NonReachables",):
            node_desc = f"[bold][green]{node_desc}[/green][/bold]"
        else:
            node_desc = f"[green]{node_desc}[/green]"
    flow_str = (
        f"""[gray37]{file_loc}[/gray37]{node_desc}"""
        if not is_filterable_code(project_type, node_desc)
        else ""
    )
    return (
        file_loc,
        flow_str,
        node_desc,
        has_check_tag,
    )


def explain_flows(explanation_mode, flows, purls, project_type, vdr_result):
    """"""
    tree = None
    comments = []
    if len(purls) > max_purl_per_flow:
        comments.append(
            ":exclamation_mark: Refactor this flow to minimize the use of external libraries."
        )
    if purls:
        purls_str = "\n".join(purls)
        comments.append(f"[info]Reachable Packages:[/info]\n{purls_str}")
    added_flows = []
    added_node_desc = []
    has_check_tag = False
    last_file_loc = None
    source_sink_desc = ""
    last_code = ""
    for idx, aflow in enumerate(flows):
        # For java, we are only interested in identifiers with tags to keep the flows simple to understand
        if (
            project_type in ("java", "jar", "android", "apk")
            and aflow.get("label") == "IDENTIFIER"
            and not aflow.get("tags")
        ):
            continue
        curr_code = aflow.get("code", "").split("\n")[0]
        if last_code and last_code == curr_code:
            continue
        last_code = curr_code
        if not source_sink_desc:
            source_sink_desc, is_endpoint_reachable, is_crypto_flow = (
                flow_to_source_sink(idx, aflow, purls, project_type, vdr_result)
            )
        file_loc, flow_str, node_desc, has_check_tag_flow = flow_to_str(
            explanation_mode, aflow, project_type
        )
        if last_file_loc == file_loc:
            continue
        last_file_loc = file_loc
        if flow_str in added_flows or node_desc in added_node_desc:
            continue
        added_flows.append(flow_str)
        added_node_desc.append(node_desc)
        if not tree:
            tree = Tree(flow_str)
        else:
            tree.add(flow_str)
        if has_check_tag_flow:
            has_check_tag = True
    if has_check_tag and explanation_mode not in ("NonReachables",):
        comments.insert(
            0,
            ":white_medium_small_square: Verify that the mitigation(s) used in this flow are valid and appropriate for your security requirements.",
        )
    return (
        tree,
        "\n".join(comments),
        source_sink_desc,
        has_check_tag,
        is_endpoint_reachable,
        is_crypto_flow,
    )
