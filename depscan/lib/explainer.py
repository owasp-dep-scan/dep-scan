import json
import os
import re

from rich import box
from rich.markdown import Markdown
from rich.table import Table
from rich.tree import Tree

from depscan.lib.config import max_purl_per_flow, max_reachable_explanations
from depscan.lib.logger import console


def explain(
    project_type,
    src_dir,
    reachables_slices_file,
    vdr_file,
    pkg_vulnerabilities,
    pkg_group_rows,
    direct_purls,
    reached_purls,
):
    """
    Explain the analysis and findings

    :param project_type: Project type
    :param src_dir: Source directory
    :param reachables_slices_file: Reachables slices file
    :param vdr_file: VDR file from the summariser
    :param pkg_vulnerabilities: Vulnerabilities from the analysis
    :param pkg_group_rows: Prioritized list of purls
    :param direct_purls: Dict containing packages used directly
    :param reached_purls: Dict containing packages identified via reachables slicing
    """
    if (
        not reachables_slices_file
        and src_dir
        and os.path.exists(os.path.join(src_dir, "reachables.slices.json"))
    ):
        reachables_slices_file = os.path.join(src_dir, "reachables.slices.json")
    if reachables_slices_file:
        with open(reachables_slices_file, "r", encoding="utf-8") as f:
            reachables_data = json.load(f)
            if reachables_data and reachables_data.get("reachables"):
                rsection = Markdown(
                    """## Reachable Flows

Below are some reachable flows identified by depscan. Use the provided tips to improve the securability of your application.
                """
                )
                console.print(rsection)
                explain_reachables(
                    reachables_data, pkg_group_rows, project_type
                )


def explain_reachables(reachables, pkg_group_rows, project_type):
    """"""
    reachable_explanations = 0
    checked_flows = 0
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
        flow_tree, comment, source_sink_desc, has_check_tag = explain_flows(
            areach.get("flows"), areach.get("purls"), project_type
        )
        if not source_sink_desc or not flow_tree:
            continue
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

        if checked_flows:
            tips += """
- Review the detected validation/sanitization methods in the application.
- To improve the security posture, implement a common validation middleware.
"""
        else:
            tips += """
- Consider implementing a common validation/sanitization library to reduce the exploitability risk.
"""
        rsection = Markdown(tips)
        console.print(rsection)


def flow_to_source_sink(idx, flow, purls, project_type):
    """ """
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
            method_str = f"constructor"
        elif project_type in ("php",) and parent_method.startswith("__"):
            method_str = f"magic {method_str}"
    if flow.get("label") == "METHOD_PARAMETER_IN":
        if param_name:
            source_sink_desc = f"""{param_str} [red]{param_name}[/red] :right_arrow_curving_left: to the {method_str} [bold]{parent_method}[/bold]"""
        else:
            source_sink_desc = f"""{method_str.capitalize()} [red]{parent_method}[/red] :right_arrow_curving_left:"""
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
        source_sink_desc = "Flow starts from a module import"
    elif (
        ".use(" in source_sink_desc
        or ".subscribe(" in source_sink_desc
        or ".on(" in source_sink_desc
        or ".emit(" in source_sink_desc
        or " => {" in source_sink_desc
    ):
        source_sink_desc = "Flow starts from a callback function"
    elif (
        "middleware" in source_sink_desc.lower()
        or "route" in source_sink_desc.lower()
    ):
        source_sink_desc = "Flow starts from a middlware"
    elif len(purls) == 1:
        source_sink_desc = (
            f"{source_sink_desc} can be used to reach this package."
        )
    else:
        source_sink_desc = (
            f"{source_sink_desc} can be used to reach {len(purls)} packages."
        )
    return source_sink_desc


def filter_tags(tags):
    if tags:
        tags = [
            atag
            for atag in tags.split(", ")
            if atag
            not in ("RESOLVED_MEMBER", "UNKNOWN_METHOD", "UNKNOWN_TYPE_DECL")
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
        file_loc = f'{flow.get("parentFileName").replace("src/main/java/", "").replace("src/main/scala/", "")}#{flow.get("lineNumber")}    '
    node_desc = flow.get("code").split("\n")[0]
    tags = filter_tags(flow.get("tags"))
    if flow.get("label") == "METHOD_PARAMETER_IN":
        param_name = flow.get("name")
        if param_name == "this":
            param_name = ""
        node_desc = f'{flow.get("parentMethodName")}([red]{param_name}[/red]) :right_arrow_curving_left:'
        if tags:
            node_desc = (
                f"{node_desc}\n[bold]Tags:[/bold] [italic]{tags}[/italic]\n"
            )
    elif flow.get("label") == "IDENTIFIER":
        if node_desc.startswith("<"):
            node_desc = flow.get("name")
        if tags:
            node_desc = (
                f"{node_desc}\n[bold]Tags:[/bold] [italic]{tags}[/italic]\n"
            )
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


def explain_flows(flows, purls, project_type):
    """"""
    tree = None
    comments = []
    if len(purls) > max_purl_per_flow:
        comments.append(
            ":exclamation_mark: Refactor this flow to reduce the number of external libraries used."
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
            source_sink_desc = flow_to_source_sink(
                idx, aflow, purls, project_type
            )
        file_loc, flow_str, has_check_tag_flow = flow_to_str(
            aflow, project_type
        )
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
            ":white_medium_small_square: Check if the mitigation(s) used in this flow is valid and appropriate for your security requirements.",
        )
    return tree, "\n".join(comments), source_sink_desc, has_check_tag
