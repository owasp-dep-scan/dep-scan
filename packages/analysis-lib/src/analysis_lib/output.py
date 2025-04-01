import json
from collections import OrderedDict, defaultdict

from custom_json_diff.lib.utils import file_write
from rich import box
from rich.markdown import Markdown
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.tree import Tree
from vdb.lib.utils import parse_purl

from analysis_lib import VdrOptions
from analysis_lib.config import *

NEWLINE = "\\n"


def get_pkg_display(tree_pkg, current_pkg, extra_text=None):
    """
    Construct a string that can be used for display

    :param tree_pkg: Package to display
    :param current_pkg: The package currently being processed
    :param extra_text: Additional text to append to the display string
    :return: Constructed display string
    """
    full_pkg_display = current_pkg
    highlightable = tree_pkg and (tree_pkg == current_pkg or tree_pkg in current_pkg)
    if tree_pkg:
        if current_pkg.startswith("pkg:"):
            purl_obj = parse_purl(current_pkg)
            if purl_obj:
                version_used = purl_obj.get("version")
                if version_used:
                    full_pkg_display = f"""{purl_obj.get("name")}@{version_used}"""
    if extra_text and highlightable:
        full_pkg_display = f"{full_pkg_display} {extra_text}"
    return full_pkg_display


def get_tree_style(purl, p):
    """
    Return a rich style to be used in a tree

    :param purl: Package purl to compare
    :param p: Package reference to check against purl
    :return: The rich style to be used in a tree visualization.
    """
    if purl and (purl == p or purl in p):
        return Style(color="#FF753D", bold=True, italic=False)
    return Style(color="#7C8082", bold=False, italic=True)


def pkg_sub_tree(
    purl,
    full_pkg,
    bom_dependency_tree,
    pkg_severity="unknown",
    as_tree=False,
    extra_text=None,
):
    """
    Method to locate and return a package tree from a dependency tree

    :param purl: The package purl to compare.
    :param full_pkg: The package reference to check against purl.
    :param bom_dependency_tree: The dependency tree.
    :param pkg_severity: The severity of the package vulnerability.
    :param as_tree: Flag indicating whether to return as a rich tree object.
    :param extra_text: Additional text to append to the display string.
    """
    pkg_tree = []
    if full_pkg and not purl:
        purl = full_pkg
    if not bom_dependency_tree:
        return [purl], Tree(
            get_pkg_display(purl, purl, extra_text=extra_text),
            style=Style(
                color="bright_red" if pkg_severity.upper() == "CRITICAL" else None
            ),
        )
    if len(bom_dependency_tree) > 1:
        for dep in bom_dependency_tree[1:]:
            ref = dep.get("ref")
            depends_on = dep.get("dependsOn", [])
            if purl in ref:
                if not pkg_tree or (pkg_tree and ref != pkg_tree[-1]):
                    pkg_tree.append(ref)
            elif purl in depends_on and purl not in pkg_tree:
                pkg_tree.append(ref)
                pkg_tree.append(purl)
                break
    # We need to iterate again to identify any parent for the parent
    if pkg_tree and len(bom_dependency_tree) > 1:
        for dep in bom_dependency_tree[1:]:
            if pkg_tree[0] in dep.get("dependsOn", []):
                if dep.get("ref") not in pkg_tree:
                    pkg_tree.insert(0, dep.get("ref"))
                break
        if as_tree and pkg_tree:
            tree = Tree(
                get_pkg_display(purl, pkg_tree[0], extra_text=extra_text),
                style=get_tree_style(purl, pkg_tree[0]),
            )
            if len(pkg_tree) > 1:
                subtree = tree
                for p in pkg_tree[1:]:
                    subtree = subtree.add(
                        get_pkg_display(purl, p, extra_text=extra_text),
                        style=get_tree_style(purl, p),
                    )
            return pkg_tree, tree
    return pkg_tree, Tree(
        get_pkg_display(purl, purl, extra_text=extra_text),
        style=Style(color="bright_red" if pkg_severity.upper() == "CRITICAL" else None),
    )


def generate_console_output(
    pkg_vulnerabilities,
    bom_dependency_tree,
    include_pkg_group_rows,
    options: VdrOptions,
):
    table = Table(
        title=f"Dependency Scan Results ({options.project_type.upper()})",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
        show_lines=True,
        min_width=150,
    )
    for h in [
        "Dependency Tree" if len(bom_dependency_tree) > 0 else "CVE",
        "Insights",
        "Fix Version",
        "Severity",
        "Score",
    ]:
        justify = "left"
        if h == "Score":
            justify = "right"
        table.add_column(header=h, justify=justify, vertical="top")
    pkg_group_rows = defaultdict(list)
    for vdr in pkg_vulnerabilities:
        if vdr["bom-ref"] in include_pkg_group_rows:
            pkg_group_rows[vdr["bom-ref"]].append(
                {
                    "id": vdr["id"],
                    "fixed_location": vdr["fixed_location"],
                    "p_rich_tree": vdr["p_rich_tree"],
                }
            )
        if rating := vdr.get("ratings", {}):
            rating = rating[0]
        table.add_row(
            vdr["p_rich_tree"],
            "\n".join(vdr["insights"]),
            vdr["fixed_location"],
            f"""{"[bright_red]" if rating.get("severity", "").upper() == "CRITICAL" else ""}{rating.get("severity", "").upper()}""",
            f"""{"[bright_red]" if rating.get("severity", "").upper() == "CRITICAL" else ""}{rating.get("score", "")}""",
        )
    return pkg_group_rows, table


def output_results(
    counts,
    direct_purls,
    options: VdrOptions,
    pkg_group_rows,
    pkg_vulnerabilities,
    reached_purls,
    table,
):
    console = options.console
    if not console:
        return
    if pkg_vulnerabilities:
        console.print()
        console.print(table)
    if pkg_group_rows:
        psection = Markdown(
            """
Next Steps
----------

The vulnerabilities below are prioritized by depscan. Follow your team's remediation workflow to address these findings.
        """,
            justify="left",
        )
        console.print(psection)
        utable = Table(
            title=f"Top Priority ({options.project_type.upper()})",
            box=box.DOUBLE_EDGE,
            header_style="bold magenta",
            show_lines=True,
            min_width=150,
        )
        for h in ("Package", "CVEs", "Fix Version", "Reachable"):
            utable.add_column(header=h, vertical="top")
        for k, v in pkg_group_rows.items():
            cve_list = []
            fv = None
            for c in v:
                cve_list.append(c.get("id"))
                if not fv:
                    fv = c.get("fixed_location")
            utable.add_row(
                v[0].get("p_rich_tree"),
                "\n".join(sorted(cve_list, reverse=True)),
                f"[bright_green]{fv}[/bright_green]",
                "[warning]Yes[/warning]" if reached_purls.get(k) else "",
            )
        console.print()
        console.print(utable)
        console.print()
    if counts.malicious_count:
        rmessage = ":stop_sign: Malicious package found! Treat this as a [bold]security incident[/bold] and follow your organization's playbook to remove this package from all affected applications."
        if counts.malicious_count > 1:
            rmessage = f":stop_sign: {counts.malicious_count} malicious packages found in this project! Treat this as a [bold]security incident[/bold] and follow your organization's playbook to remove the packages from all affected applications."
        console.print(
            Panel(
                rmessage,
                title="Action Required",
                expand=False,
            )
        )
    elif options.scoped_pkgs or counts.has_exploit_count:
        if not counts.pkg_attention_count and counts.has_exploit_count:
            if counts.has_reachable_exploit_count:
                rmessage = (
                    f":point_right: [magenta]{counts.has_reachable_exploit_count}"
                    f"[/magenta] out of {len(pkg_vulnerabilities)} vulnerabilities "
                    f"have [dark magenta]reachable[/dark magenta] exploits and requires your ["
                    f"magenta]immediate[/magenta] attention."
                )
            else:
                rmessage = (
                    f":point_right: [magenta]{counts.has_exploit_count}"
                    f"[/magenta] out of {len(pkg_vulnerabilities)} vulnerabilities "
                    f"have known exploits and requires your ["
                    f"magenta]immediate[/magenta] attention."
                )
            if not counts.has_os_packages:
                rmessage += (
                    "\nAdditional workarounds and configuration "
                    "changes might be required to remediate these "
                    "vulnerabilities."
                )
                if not options.scoped_pkgs:
                    rmessage += (
                        "\nNOTE: Package usage analysis was not "
                        "performed for this project."
                    )
            else:
                rmessage += (
                    "\n:scissors: Consider trimming this image by removing any "
                    "unwanted packages. Alternatively, use a slim "
                    "base image."
                )
                if counts.distro_packages_count and counts.distro_packages_count < len(
                    pkg_vulnerabilities
                ):
                    if len(pkg_vulnerabilities) > max_distro_vulnerabilities:
                        rmessage += "\nNOTE: Check if the base image or the kernel version used is End-of-Life (EOL)."
                    else:
                        rmessage += (
                            f"\nNOTE: [magenta]{counts.distro_packages_count}"
                            f"[/magenta] distro-specific vulnerabilities "
                            f"out of {len(pkg_vulnerabilities)} could be prioritized "
                            f"for updates."
                        )
                if counts.has_redhat_packages:
                    rmessage += """\nNOTE: Vulnerabilities in RedHat packages with status "out of support" or "won't fix" are excluded from this result."""
                if counts.has_ubuntu_packages:
                    rmessage += """\nNOTE: Vulnerabilities in Ubuntu packages with status "DNE" or "needs-triaging" are excluded from this result."""
            console.print(
                Panel(
                    rmessage,
                    title="Recommendation",
                    expand=False,
                )
            )
        elif counts.pkg_attention_count:
            if counts.has_reachable_exploit_count:
                rmessage = (
                    f":point_right: Prioritize the [magenta]{counts.has_reachable_exploit_count}"
                    f"[/magenta] [bold magenta]reachable[/bold magenta] vulnerabilities with known exploits."
                )
            elif counts.has_exploit_count:
                rmessage = (
                    f":point_right: Prioritize the [magenta]{counts.has_exploit_count}"
                    f"[/magenta] vulnerabilities with known exploits."
                )
            else:
                rmessage = (
                    f":point_right: [info]{counts.pkg_attention_count}"
                    f"[/info] out of {len(pkg_vulnerabilities)} vulnerabilities "
                    f"requires your attention."
                )
            if counts.fix_version_count:
                if counts.fix_version_count == counts.pkg_attention_count:
                    rmessage += (
                        "\n:white_heavy_check_mark: You can update ["
                        "bright_green]all[/bright_green] the "
                        "packages using the mentioned fix version to "
                        "remediate."
                    )
                else:
                    v_text = (
                        "vulnerability"
                        if counts.fix_version_count == 1
                        else "vulnerabilities"
                    )
                    rmessage += (
                        f"\nYou can remediate [bright_green]"
                        f"{counts.fix_version_count}[/bright_green] "
                        f"{v_text} "
                        f"by updating the packages using the fix "
                        f"version :thumbsup:"
                    )
            console.print(
                Panel(
                    rmessage,
                    title="Recommendation",
                    expand=False,
                )
            )
        elif counts.critical_count:
            console.print(
                Panel(
                    f":white_medium_small_square: Prioritize the [magenta]{counts.critical_count}"
                    f"[/magenta] critical vulnerabilities confirmed by the "
                    f"vendor.",
                    title="Recommendation",
                    expand=False,
                )
            )
        else:
            if counts.has_os_packages:
                rmessage = (
                    ":white_medium_small_square: Prioritize any vulnerabilities in libraries such "
                    "as glibc, openssl, or libcurl.\nAdditionally, "
                    "prioritize the vulnerabilities with 'Flagged weakness' under insights."
                )
                rmessage += (
                    "\nVulnerabilities in Linux Kernel packages can "
                    "be usually ignored in containerized "
                    "environments as long as the vulnerability "
                    "doesn't lead to any 'container-escape' type "
                    "vulnerabilities."
                )
                if counts.has_redhat_packages:
                    rmessage += """\nNOTE: Vulnerabilities in RedHat packages
                    with status "out of support" or "won't fix" are excluded
                    from this result."""
                if counts.has_ubuntu_packages:
                    rmessage += """\nNOTE: Vulnerabilities in Ubuntu packages
                    with status "DNE" or "needs-triaging" are excluded from
                    this result."""
                console.print(Panel(rmessage, title="Recommendation"))
            else:
                rmessage = None
                if reached_purls:
                    rmessage = ":white_check_mark: No package requires immediate attention since the major vulnerabilities are not reachable."
                elif direct_purls:
                    rmessage = ":white_check_mark: No package requires immediate attention since the major vulnerabilities are found only in dev packages and indirect dependencies."
                if rmessage:
                    console.print(
                        Panel(
                            rmessage,
                            title="Recommendation",
                            expand=False,
                        )
                    )
    elif counts.critical_count:
        console.print(
            Panel(
                f":white_medium_small_square: Prioritize the [magenta]{counts.critical_count}"
                f"[/magenta] critical vulnerabilities confirmed by the vendor.",
                title="Recommendation",
                expand=False,
            )
        )
    else:
        console.print(
            Panel(
                ":white_check_mark: No package requires immediate attention.",
                title="Recommendation",
                expand=False,
            )
        )
    if reached_purls:
        rsection, rtable = reached_purls_table(reached_purls)
        if rsection and rtable:
            console.print(rsection)
            console.print(rtable)


def summary_stats(results):
    """
    Generate summary stats

    :param results: List of scan results objects with severity attribute.
    :return: A dictionary containing the summary statistics for the severity
    levels of the vulnerabilities in the results list.
    """
    if not results:
        return {}
    summary = {
        "UNSPECIFIED": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for i in results:
        ratings = i.get("ratings")
        if ratings:
            sev = ratings[0].get("severity", "").upper()
            summary[sev] += 1

    return summary


def pkg_risks_table(project_type, scoped_pkgs, risk_results, pkg_max_risk_score=0.5, risk_report_file=None):
    """
    Identify package risk and write to a json file

    :param project_type: Project type
    :param scoped_pkgs: A dict of lists of required/optional/excluded packages.
    :param risk_results: A dict of the risk metrics and scope for each package.
    :param risk_report_file: Path to the JSON file for the risk audit findings.
    """
    if not risk_results:
        return None
    table = Table(
        title=f"Risk Audit Summary ({project_type})",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
        min_width=150,
    )
    report_data = []
    required_pkgs = scoped_pkgs.get("required", [])
    optional_pkgs = scoped_pkgs.get("optional", [])
    excluded_pkgs = scoped_pkgs.get("excluded", [])
    headers = ["Package", "Used?", "Risk Score", "Identified Risks"]
    for h in headers:
        justify = "left"
        if h == "Risk Score":
            justify = "right"
        table.add_column(header=h, justify=justify)
    for pkg, risk_obj in risk_results.items():
        if not risk_obj:
            continue
        risk_metrics = risk_obj.get("risk_metrics")
        scope = risk_obj.get("scope")
        project_type_pkg = f"{project_type}:{pkg}".lower()
        if project_type_pkg in required_pkgs:
            scope = "required"
        elif project_type_pkg in optional_pkgs:
            scope = "optional"
        elif project_type_pkg in excluded_pkgs:
            scope = "excluded"
        package_usage = "N/A"
        package_usage_simple = "N/A"
        if scope == "required":
            package_usage = "[bright_green][bold]Yes"
            package_usage_simple = "Yes"
        if scope == "optional":
            package_usage = "[magenta]No"
            package_usage_simple = "No"
        if not risk_metrics:
            continue
        # Some risks gets special treatment for display
        if risk_metrics.get("risk_score") and (
            risk_metrics.get("risk_score") > pkg_max_risk_score
            or risk_metrics.get("pkg_private_on_public_registry_risk")
            or risk_metrics.get("pkg_deprecated_risk")
            or risk_metrics.get("pkg_version_deprecated_risk")
            or risk_metrics.get("pkg_version_missing_risk")
            or risk_metrics.get("pkg_includes_binary_risk")
            or risk_metrics.get("pkg_attested_check")
        ):
            risk_score = f"""{round(risk_metrics.get("risk_score"), 2)}"""
            data = [
                pkg,
                package_usage,
                risk_score,
            ]
            edata = [
                pkg,
                package_usage_simple,
                risk_score,
            ]
            risk_categories = []
            risk_categories_simple = []
            for rk, rv in risk_metrics.items():
                if (rk.endswith("_risk") or rk.endswith("_check")) and rv is True:
                    rcat = rk.removesuffix("_risk").removesuffix("_check")
                    help_text = risk_help_text.get(rcat)
                    extra_info = risk_metrics.get(f"{rcat}_info")
                    if extra_info:
                        help_text = f"{help_text}\n{extra_info}"
                    # Only add texts that are available.
                    if help_text:
                        if rcat in (
                            "pkg_deprecated",
                            "pkg_version_deprecated",
                            "pkg_includes_binary",
                            "pkg_private_on_public_registry",
                        ):
                            risk_categories.append(f":cross_mark: {help_text}")
                        elif rk.endswith("_check"):
                            risk_categories.append(
                                f":white_heavy_check_mark: {help_text}"
                            )
                        else:
                            risk_categories.append(f":warning: {help_text}")
                        risk_categories_simple.append(help_text)
            data.append("\n".join(risk_categories))
            edata.append("~~".join(risk_categories_simple))
            table.add_row(*data)
            report_data.append(dict(zip(headers, edata)))
    if report_data:
        # Store the risk audit findings in jsonl format
        if risk_report_file:
            file_write(
                risk_report_file, "\n".join([json.dumps(row) for row in report_data])
            )
    return table


def licenses_risk_table(project_type, licenses_results, license_report_file=None):
    """
    Analyze package licenses

    :param project_type: Project type
    :param licenses_results: A dict with the license results for each package.
    :param license_report_file: Output filename for the license report.
    """
    if not licenses_results:
        return None
    table = Table(
        title=f"License Scan Summary ({project_type})",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
        min_width=150,
    )
    headers = ["Package", "Version", "License Id", "License conditions"]
    for h in headers:
        table.add_column(header=h)
    report_data = []
    for pkg, ll in licenses_results.items():
        pkg_ver = pkg.split("@")
        for lic in ll:
            if not lic:
                data = [*pkg_ver, "Unknown license"]
                table.add_row(*data)
                report_data.append(dict(zip(headers, data)))
            elif lic["condition_flag"]:
                conditions_str = ", ".join(lic["conditions"])
                if "http" not in conditions_str:
                    conditions_str = (
                        conditions_str.replace("--", " for ").replace("-", " ").title()
                    )
                data = [
                    *pkg_ver,
                    "{}{}".format(
                        (
                            "[cyan]"
                            if "GPL" in lic["spdx-id"]
                            or "CC-BY-" in lic["spdx-id"]
                            or "Facebook" in lic["spdx-id"]
                            or "WTFPL" in lic["spdx-id"]
                            else ""
                        ),
                        lic["spdx-id"],
                    ),
                    conditions_str,
                ]
                table.add_row(*data)
                report_data.append(dict(zip(headers, data)))
    if report_data:
        # Store the license scan findings in jsonl format
        if license_report_file:
            file_write(
                license_report_file, "\n".join([json.dumps(row) for row in report_data])
            )
    return table


def reached_purls_table(reached_purls):
    sorted_reached_purls = sorted(
        ((value, key) for (key, value) in reached_purls.items()),
        reverse=True,
    )[:3]
    sorted_reached_dict = OrderedDict((k, v) for v, k in sorted_reached_purls)
    rsection = Markdown(
        """
Proactive Measures
------------------

Below are the top reachable packages identified by depscan. Setup alerts and notifications to actively monitor these packages for new vulnerabilities and exploits.
    """,
        justify="left",
    )
    rtable = Table(
        title="Top Reachable Packages",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
        show_lines=True,
        min_width=150,
    )
    for h in ("Package", "Reachable Flows"):
        rtable.add_column(header=h, vertical="top")
    for k, v in sorted_reached_dict.items():
        rtable.add_row(k, str(v))
    return rsection, rtable
