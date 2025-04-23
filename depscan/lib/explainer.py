import re
import glob
from collections import defaultdict
from custom_json_diff.lib.utils import json_load
from rich import box
from rich.markdown import Markdown
from rich.table import Table
from rich.tree import Tree

from depscan.lib.config import max_purl_per_flow, max_reachable_explanations
from depscan.lib.logger import console, LOG


def explain(project_type, src_dir, bom_dir, vdr_result):
    """
    Explain the analysis and findings

    :param project_type: Project type
    :param bom_dir: BOM directory
    """
    pattern_methods = {}
    slices_files = glob.glob(f"{bom_dir}/**/*reachables.slices.json", recursive=True)
    openapi_spec_files = glob.glob(f"{bom_dir}/*openapi*.json", recursive=False)
    if not openapi_spec_files:
        openapi_spec_files = glob.glob(f"{src_dir}/*openapi*.json", recursive=False)
    if openapi_spec_files:
        rsection = Markdown("""## Service Endpoints

The following endpoints and code hotspots were identified by depscan. Ensure proper authentication and authorization mechanisms are implemented to secure them.""")
        console.print(rsection)
    for ospec in openapi_spec_files:
        pattern_methods = print_endpoints(ospec)
    for sf in slices_files:
        if (
            reachables_data := json_load(
                sf, error_msg=f"Could not load reachables from {sf}", log=LOG
            )
        ) and reachables_data.get("reachables"):
            if pattern_methods:
                rsection = Markdown(
                    """## Reachable Flows

Below are some reachable flows, including endpoint-reachable ones, identified by depscan. Use the generated OpenAPI specification file to assess these endpoints for vulnerabilities and risk.
                """
                )
            else:
                rsection = Markdown(
                    """## Reachable Flows

Below are some reachable flows identified by depscan. Use the provided tips to enhance your application's security posture.
                """
                )
            console.print(rsection)
            explain_reachables(reachables_data, project_type, vdr_result)


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
        pattern_usage_targets[pattern] = usage_targets
    caption = ""
    if pattern_methods:
        caption = f"Total Endpoints: {len(pattern_methods.keys())}"
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
    console.print()
    console.print(rtable)
    return pattern_methods


def explain_reachables(reachables, project_type, vdr_result):
    """"""
    reachable_explanations = 0
    checked_flows = 0
    has_crypto_flows = False
    for areach in reachables.get("reachables", []):
        if (
            not areach.get("flows")
            or len(areach.get("flows")) < 2
            or not areach.get("purls")
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
        flow_tree, comment, source_sink_desc, has_check_tag, is_endpoint_reachable, is_crypto_flow = explain_flows(
            areach.get("flows"), areach.get("purls"), project_type, vdr_result
        )
        if not source_sink_desc or not flow_tree:
            continue
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
        console.print()
        console.print(rtable)
        reachable_explanations += 1
        if has_check_tag:
            checked_flows += 1
        if reachable_explanations + 1 > max_reachable_explanations:
            break
    if reachable_explanations:
        tips = """## Secure Design Tips"""

        if has_crypto_flows:
            tips += """
- Generate a Cryptography Bill of Materials (CBOM) using tools such as cdxgen, and track it with platforms like Dependency-Track.
"""
        elif checked_flows:
            tips += """
- Review the validation and sanitization methods used in the application.
- To enhance the security posture, implement a common validation middleware.
"""
        else:
            tips += """
- Consider implementing a common validation and sanitization library to reduce the risk of exploitability.
"""
        rsection = Markdown(tips)
        console.print(rsection)


def flow_to_source_sink(idx, flow, purls, project_type, vdr_result):
    """ """
    endpoint_reached_purls = {}
    reached_services = {}
    if vdr_result:
        endpoint_reached_purls = vdr_result.endpoint_reached_purls
        reached_services = vdr_result.reached_services
    is_endpoint_reachable = False
    possible_reachable_service = False
    is_crypto_flow = "crypto" in flow.get("tags", []) or "crypto-generate" in flow.get("tags", [])
    method_in_emoji = ":right_arrow_curving_left:"
    for p in purls:
        if endpoint_reached_purls and endpoint_reached_purls.get(p):
            is_endpoint_reachable = True
            method_in_emoji = ":spider_web: "
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
                source_sink_desc = f"{len(purls)} packages reachable from this crypto-flow."
            else:
                source_sink_desc = f"{len(purls)} packages reachable from this data-flow."
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


def flow_to_str(flow, project_type):
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
    if tags:
        for ctag in (
            "validation",
            "encode",
            "encrypt",
            "sanitize",
            "authentication",
            "authorization",
        ):
            if ctag in tags:
                has_check_tag = True
                break
    if has_check_tag:
        node_desc = f"[green]{node_desc}[/green]"
    return (
        file_loc,
        f"""[gray37]{file_loc}[/gray37]{node_desc}""",
        has_check_tag,
    )


def explain_flows(flows, purls, project_type, vdr_result):
    """"""
    tree = None
    comments = []
    if len(purls) > max_purl_per_flow:
        comments.append(
            ":exclamation_mark: Refactor this flow to minimize the use of external libraries."
        )
    purls_str = "\n".join(purls)
    comments.append(f"[info]Reachable Packages:[/info]\n{purls_str}")
    added_flows = []
    has_check_tag = False
    last_file_loc = None
    source_sink_desc = ""
    for idx, aflow in enumerate(flows):
        # For java, we are only interested in identifiers with tags to keep the flows simple to understand
        if (
            project_type in ("java", "jar", "android", "apk")
            and aflow.get("label") == "IDENTIFIER"
            and not aflow.get("tags")
        ):
            continue
        if not source_sink_desc:
            source_sink_desc, is_endpoint_reachable, is_crypto_flow = flow_to_source_sink(
                idx, aflow, purls, project_type, vdr_result
            )
        file_loc, flow_str, has_check_tag_flow = flow_to_str(aflow, project_type)
        if last_file_loc == file_loc:
            continue
        last_file_loc = file_loc
        if flow_str in added_flows:
            continue
        added_flows.append(flow_str)
        if not tree:
            tree = Tree(flow_str)
        else:
            tree.add(flow_str)
        if has_check_tag_flow:
            has_check_tag = True
    if has_check_tag:
        comments.insert(
            0,
            ":white_medium_small_square: Verify that the mitigation(s) used in this flow are valid and appropriate for your security requirements.",
        )
    return tree, "\n".join(comments), source_sink_desc, has_check_tag, is_endpoint_reachable, is_crypto_flow
