import json
import os
import re

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from depscan.lib.config import max_reachable_explanations
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
            if reachables_data:
                console.rule(style="gray37")
                explain_reachables(reachables_data, pkg_group_rows, project_type)


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
        if not source_sink_desc:
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
        if checked_flows:
            console.print(
                Panel(
                    "Review the detected validation/sanitization methods. Refactor the application to centralize the common validation operations to improve the security posture.",
                    title="Recommendation",
                    expand=False,
                )
            )
        else:
            console.print(
                Panel(
                    "Consider implementing a common validation/sanitization library to reduce the exploitability risk.",
                    title="Recommendation",
                    expand=False,
                )
            )


def flow_to_source_sink(flow, purls, project_type):
    """ """
    source_sink_desc = ""
    param_name = flow.get("name")
    method_str = "method"
    param_str = "Parameter"
    if param_name == "this":
        param_name = ""
    # Improve the labels based on the language
    if re.search(".(js|ts|jsx|tsx|py|cs)$", flow.get("parentFileName", "")):
        method_str = "function"
        param_str = "argument"
    if flow.get("label") == "METHOD_PARAMETER_IN":
        if param_name:
            source_sink_desc = f"""{param_str} [red]{param_name}[/red] :right_arrow_curving_left: to the {method_str} [bold]{flow.get('parentMethodName')}[/bold]"""
        else:
            source_sink_desc = f"""{method_str.capitalize()} [red]{flow.get('parentMethodName')}[/red] :right_arrow_curving_left:"""
    elif flow.get("label") == "CALL" and flow.get("isExternal"):
        method_full_name = flow.get("fullName", "")
        if not method_full_name.startswith("<"):
            source_sink_desc = f"Invocation: {method_full_name}"
    elif flow.get("label") == "RETURN" and flow.get("code"):
        source_sink_desc = flow.get("code").split("\n")[0]
    elif project_type not in ("java") and flow.get("label") == "IDENTIFIER":
        source_sink_desc = flow.get("code").split("\n")[0]
    if len(purls) == 1:
        source_sink_desc = f"{source_sink_desc} can be used to reach this package."
    else:
        source_sink_desc = (
            f"{source_sink_desc} can be used to reach {len(purls)} packages."
        )
    return source_sink_desc


def flow_to_str(flow):
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
    tags = flow.get("tags")
    if flow.get("label") == "METHOD_PARAMETER_IN":
        param_name = flow.get("name")
        if param_name == "this":
            param_name = ""
        node_desc = f'{flow.get("parentMethodName")}([red]{param_name}[/red]) :right_arrow_curving_left:'
        if tags:
            node_desc = f"{node_desc}\n[bold]Tags:[/bold] [italic]{tags}[/italic]\n"
    elif flow.get("label") == "IDENTIFIER" and node_desc.startswith("<"):
        node_desc = flow.get("name")
    if flow.get("tags"):
        if (
            "validation" in tags
            or "encode" in tags
            or "encrypt" in tags
            or "sanitize" in tags
        ):
            has_check_tag = True
    elif flow.get("label") in ("CALL", "RETURN"):
        code = flow.get("code", "").lower()
        # Let's broaden and look for more check method patterns
        # This is not a great logic but since we're offering some ideas this should be ok
        # Hopefully, the tagger would improve to handle these cases in the future
        if (
            "escape(" in code
            or "encode(" in code
            or "encrypt(" in code
            or "validate" in code
        ):
            has_check_tag = True
    if has_check_tag:
        node_desc = f"[green]{node_desc}[/green]"
    return file_loc, f"""[gray37]{file_loc}[/gray37]{node_desc}""", has_check_tag


def explain_flows(flows, purls, project_type):
    """"""
    tree = None
    comments = []
    purls_str = "\n".join(purls)
    comments.append(f"Reachable Packages:\n{purls_str}")
    added_flows = []
    has_check_tag = False
    last_file_loc = None
    source_sink_desc = ""
    for aflow in flows:
        if project_type in ("java",) and aflow.get("label") not in (
            "METHOD_PARAMETER_IN",
            "CALL",
            "RETURN",
        ):
            continue
        if not source_sink_desc:
            source_sink_desc = flow_to_source_sink(aflow, purls, project_type)
        file_loc, flow_str, has_check_tag_flow = flow_to_str(aflow)
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
            ":white_medium_small_square: Check if the mitigation used in this flow is valid and appropriate for your security requirements.",
        )
    return tree, "\n".join(comments), source_sink_desc, has_check_tag
