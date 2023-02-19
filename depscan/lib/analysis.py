# -*- coding: utf-8 -*-

import json
from collections import defaultdict

from rich import box
from rich.panel import Panel
from rich.table import Table
from vdb.lib import CPE_FULL_REGEX
from vdb.lib.config import placeholder_fix_version
from vdb.lib.utils import parse_purl

from depscan.lib import config as config
from depscan.lib.logger import LOG, console
from depscan.lib.utils import max_version


def best_fixed_location(version_used, sug_version, orig_fixed_location):
    # Compare the major versions before suggesting an override
    # See: https://github.com/AppThreat/dep-scan/issues/72
    if (
        not orig_fixed_location
        and sug_version
        and sug_version != placeholder_fix_version
    ):
        return sug_version
    if sug_version and orig_fixed_location:
        if sug_version == placeholder_fix_version:
            return ""
        tmpA = sug_version.split(".")[0]
        tmpB = orig_fixed_location.split(".")[0]
        if tmpA == tmpB:
            return sug_version
    # Handle the placeholder version used by OS distros
    if orig_fixed_location == placeholder_fix_version:
        return ""
    return orig_fixed_location


def distro_package(package_issue):
    if package_issue:
        all_parts = CPE_FULL_REGEX.match(package_issue.affected_location.cpe_uri)
        if (
            all_parts
            and all_parts.group("vendor")
            and all_parts.group("vendor") in config.LINUX_DISTRO_WITH_EDITIONS
            and all_parts.group("edition")
            and all_parts.group("edition") != "*"
        ):
            return True
    return False


def prepare_vex(
    project_type,
    results,
    pkg_aliases,
    purl_aliases,
    sug_version_dict,
    scoped_pkgs,
    no_vuln_table,
):
    """Pretty print report summary"""
    if not results:
        return []
    table = Table(
        title=f"Dependency Scan Results ({project_type})",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
        show_lines=True,
    )
    ids_seen = {}
    required_pkgs = scoped_pkgs.get("required", [])
    optional_pkgs = scoped_pkgs.get("optional", [])
    pkg_attention_count = 0
    critical_count = 0
    has_poc_count = 0
    has_exploit_count = 0
    fix_version_count = 0
    wont_fix_version_count = 0
    has_os_packages = False
    has_redhat_packages = False
    has_ubuntu_packages = False
    distro_packages_count = 0
    pkg_group_rows = defaultdict(list)
    pkg_vulnerabilities = []
    for h in [
        "CVE",
        "Package",
        "Insights",
        "Version",
        "Fix Version",
        "Severity",
        "Score",
    ]:
        justify = "left"
        if h == "Score":
            justify = "right"
        table.add_column(header=h, justify=justify, no_wrap=False)
    for res in results:
        vuln_occ_dict = res.to_dict()
        id = vuln_occ_dict.get("id")
        problem_type = vuln_occ_dict.get("problem_type")
        package_issue = res.package_issue
        full_pkg = package_issue.affected_location.package
        project_type_pkg = "{}:{}".format(
            project_type, package_issue.affected_location.package
        )
        if package_issue.affected_location.vendor:
            full_pkg = "{}:{}".format(
                package_issue.affected_location.vendor,
                package_issue.affected_location.package,
            )
        # De-alias package names
        full_pkg = pkg_aliases.get(full_pkg, full_pkg)
        full_pkg_display = full_pkg
        version_used = package_issue.affected_location.version
        purl = purl_aliases.get(full_pkg, full_pkg)
        package_type = None
        if purl:
            try:
                purl_obj = parse_purl(purl)
                if purl_obj:
                    version_used = purl_obj.get("version")
                    package_type = purl_obj.get("type")
                    qualifiers = purl_obj.get("qualifiers", {})
                    if package_type == "redhat":
                        has_redhat_packages = True
                    if package_type in config.OS_PKG_TYPES:
                        has_os_packages = True
                    if "ubuntu" in qualifiers.get("distro", ""):
                        has_ubuntu_packages = True
                    if purl_obj.get("namespace"):
                        full_pkg_display = (
                            f"""{purl_obj.get("namespace")}/{purl_obj.get("name")}"""
                        )
                    else:
                        full_pkg_display = f"""{purl_obj.get("name")}"""
            except Exception:
                pass
        if ids_seen.get(id + full_pkg):
            continue
        ids_seen[id + full_pkg] = True
        fixed_location = best_fixed_location(
            version_used, sug_version_dict.get(full_pkg), package_issue.fixed_location
        )
        if (
            sug_version_dict.get(full_pkg) == placeholder_fix_version
            or package_issue.fixed_location == placeholder_fix_version
        ):
            wont_fix_version_count = wont_fix_version_count + 1
        package_usage = "N/A"
        insights = []
        plain_insights = []
        package_name_style = ""
        id_style = ""
        pkg_severity = vuln_occ_dict.get("severity")
        is_required = False
        pkg_requires_attn = False
        related_urls = vuln_occ_dict.get("related_urls")
        clinks = classify_links(
            id,
            full_pkg_display,
            vuln_occ_dict.get("type"),
            package_issue.affected_location.version,
            related_urls,
        )
        if full_pkg in required_pkgs or project_type_pkg in required_pkgs:
            is_required = True
        if pkg_severity in ("CRITICAL", "HIGH"):
            if is_required:
                id_style = ":point_right: "
                pkg_requires_attn = True
                pkg_attention_count = pkg_attention_count + 1
            if fixed_location:
                fix_version_count = fix_version_count + 1
            if (
                clinks.get("vendor") or package_type in config.OS_PKG_TYPES
            ) and pkg_severity == "CRITICAL":
                critical_count += 1
        if is_required and package_type not in config.OS_PKG_TYPES:
            package_usage = ":direct_hit: Direct usage"
            package_name_style = "[bold]"
        elif full_pkg in optional_pkgs or project_type_pkg in optional_pkgs:
            if package_type in config.OS_PKG_TYPES:
                package_usage = (
                    "[spring_green4]:notebook: Local install[/spring_green4]"
                )
                has_os_packages = True
            else:
                package_usage = (
                    "[spring_green4]:notebook: Indirect dependency[/spring_green4]"
                )
            package_name_style = "[italic]"
        if package_usage != "N/A":
            insights.append(package_usage)
            plain_insights.append(package_usage)
        if clinks.get("poc") or clinks.get("Bug Bounty"):
            insights.append("[yellow]:notebook_with_decorative_cover: Has PoC[/yellow]")
            plain_insights.append("Has PoC")
            has_poc_count = has_poc_count + 1
        if clinks.get("vendor") and package_type not in config.OS_PKG_TYPES:
            insights.append(":receipt: Vendor Confirmed")
            plain_insights.append("Vendor Confirmed")
        if clinks.get("exploit"):
            insights.append(
                "[bright_red]:exclamation_mark: Known Exploits[/bright_red]"
            )
            plain_insights.append("Known Exploits")
            has_exploit_count = has_exploit_count + 1
            pkg_requires_attn = True
        if distro_package(package_issue):
            insights.append(
                "[spring_green4]:direct_hit: Distro specific[/spring_green4]"
            )
            plain_insights.append("Distro specific")
            distro_packages_count = distro_packages_count + 1
            has_os_packages = True
        if pkg_requires_attn and fixed_location and purl:
            pkg_group_rows[purl].append({"id": id, "fixed_location": fixed_location})
        if not no_vuln_table:
            table.add_row(
                "{}{}{}{}".format(
                    id_style,
                    package_name_style,
                    "[bright_red]" if pkg_severity == "CRITICAL" else "",
                    id,
                ),
                "{}{}".format(package_name_style, full_pkg_display),
                "\n".join(insights),
                version_used,
                fixed_location,
                "{}{}".format(
                    "[bright_red]" if pkg_severity == "CRITICAL" else "",
                    vuln_occ_dict.get("severity"),
                ),
                "{}{}".format(
                    "[bright_red]" if pkg_severity == "CRITICAL" else "",
                    vuln_occ_dict.get("cvss_score"),
                ),
            )
        if purl:
            source = {}
            if id.startswith("CVE"):
                source = {
                    "name": "NVD",
                    "url": f"https://nvd.nist.gov/vuln/detail/{id}",
                }
            elif id.startswith("GHSA") or id.startswith("npm"):
                source = {
                    "name": "GitHub",
                    "url": f"https://github.com/advisories/{id}",
                }
            versions = [{"version": version_used, "status": "affected"}]
            recommendation = ""
            if fixed_location:
                versions.append({"version": fixed_location, "status": "unaffected"})
                recommendation = f"Update to {fixed_location} or later"
            affects = [{"ref": purl, "versions": versions}]
            analysis = {}
            if clinks.get("exploit"):
                analysis = {
                    "state": "exploitable",
                    "detail": f'See {clinks.get("exploit")}',
                }
            elif clinks.get("poc"):
                analysis = {"state": "in_triage", "detail": f'See {clinks.get("poc")}'}
            score = 2.0
            try:
                score = float(vuln_occ_dict.get("cvss_score"))
            except Exception:
                pass
            sev_to_use = pkg_severity.lower()
            if sev_to_use not in ("critical", "high", "medium", "low", "info", "none"):
                sev_to_use = "unknown"
            ratings = [
                {
                    "score": score,
                    "severity": sev_to_use,
                    "method": "CVSSv31",
                }
            ]
            advisories = []
            for k, v in clinks.items():
                advisories.append({"title": k, "url": v})
            cwes = []
            if problem_type:
                try:
                    acwe = int(problem_type.lower().replace("cwe-", ""))
                    cwes = [acwe]
                except Exception:
                    pass
            pkg_vulnerabilities.append(
                {
                    "bom-ref": f"{id}/{purl}",
                    "id": id,
                    "source": source,
                    "ratings": ratings,
                    "cwes": cwes,
                    "description": vuln_occ_dict.get("short_description"),
                    "recommendation": recommendation,
                    "advisories": advisories,
                    "analysis": analysis,
                    "affects": affects,
                    "properties": [
                        {
                            "name": "depscan:insights",
                            "value": "\\n".join(plain_insights),
                        },
                        {
                            "name": "depscan:prioritized",
                            "value": "true" if pkg_group_rows.get(purl) else "false",
                        },
                    ],
                }
            )
    if not no_vuln_table:
        console.print(table)
    if pkg_group_rows:
        console.print("")
        utable = Table(
            title=f"Top Priority ({project_type})",
            box=box.DOUBLE_EDGE,
            header_style="bold magenta",
            show_lines=True,
        )
        for h in ("Package", "CVEs", "Fix Version"):
            utable.add_column(header=h, justify="left", no_wrap=False)
        for k, v in pkg_group_rows.items():
            cve_list = []
            fv = None
            for c in v:
                cve_list.append(c.get("id"))
                if not fv:
                    fv = c.get("fixed_location")
            utable.add_row(
                k.split("#")[0].split("?")[0],
                "\n".join(sorted(cve_list, reverse=True)),
                f"[bright_green]{fv}[/bright_green]",
            )
        console.print(utable)
    if scoped_pkgs or has_exploit_count:
        if not pkg_attention_count and has_exploit_count:
            rmessage = f":point_right: [magenta]{has_exploit_count}[/magenta] out of {len(results)} vulnerabilities have known exploits and requires your [magenta]immediate[/magenta] attention."
            if not has_os_packages:
                rmessage += "\nAdditional workarounds and configuration changes might be required to remediate these vulnerabilities."
                if not scoped_pkgs:
                    rmessage += "\nNOTE: Package usage analysis was not performed for this project."
            else:
                rmessage += "\nConsider trimming this image by removing any unwanted packages. Alternatively, use a slim base image."
                if distro_packages_count and distro_packages_count < len(results):
                    rmessage += f"\nNOTE: [magenta]{distro_packages_count}[/magenta] distro-specific vulnerabilities out of {len(results)} could be prioritized for updates."
                if has_redhat_packages:
                    rmessage += """\nNOTE: Vulnerabilities in RedHat packages with status "out of support" or "won't fix" are excluded from this result."""
                if has_ubuntu_packages:
                    rmessage += """\nNOTE: Vulnerabilities in Ubuntu packages with status "DNE" or "needs-triaging" are excluded from this result."""
            console.print(
                Panel(
                    rmessage,
                    title="Recommendation",
                    expand=False,
                )
            )
        elif pkg_attention_count:
            rmessage = f":point_right: [magenta]{pkg_attention_count}[/magenta] out of {len(results)} vulnerabilities requires your attention."
            if has_exploit_count:
                rmessage += f"\nPrioritize the [magenta]{has_exploit_count}[/magenta] vulnerabilities with known exploits."
            if fix_version_count:
                if fix_version_count == pkg_attention_count:
                    rmessage += "\n:white_heavy_check_mark: You can update [bright_green]all[/bright_green] the packages using the mentioned fix version to remediate."
                else:
                    rmessage += f"\nYou can remediate [bright_green]{fix_version_count}[/bright_green] {'vulnerability' if fix_version_count == 1 else 'vulnerabilities'} by updating the packages using the fix version :thumbsup:"
            console.print(
                Panel(
                    rmessage,
                    title="Recommendation",
                    expand=False,
                )
            )
        elif critical_count:
            console.print(
                Panel(
                    f"Prioritize the [magenta]{critical_count}[/magenta] critical vulnerabilities confirmed by the vendor.",
                    title="Recommendation",
                    expand=False,
                )
            )
        else:
            if has_os_packages:
                rmessage = "Prioritize any vulnerabilities in libraries such as glibc, openssl, or libcurl.\nAdditionally, prioritize the vulnerabilities in packages that provide executable binaries when there is a Remote Code Execution or File Write vulnerability in the containerized application or service."
                rmessage += "\nVulnerabilities in Linux Kernel packages can be usually ignored in containerized environments as long as the vulnerability doesn't lead to any 'container-escape' type vulnerabilities."
                if has_redhat_packages:
                    rmessage += """\nNOTE: Vulnerabilities in RedHat packages with status "out of support" or "won't fix" are excluded from this result."""
                if has_ubuntu_packages:
                    rmessage += """\nNOTE: Vulnerabilities in Ubuntu packages with status "DNE" or "needs-triaging" are excluded from this result."""
                console.print(
                    Panel(
                        rmessage,
                        title="Recommendation",
                        expand=True,
                    )
                )
            else:
                console.print(
                    Panel(
                        ":white_check_mark: No package requires immediate attention since the major vulnerabilities are found only in dev packages and indirect dependencies.",
                        title="Recommendation",
                        expand=False,
                    )
                )
    elif critical_count:
        console.print(
            Panel(
                f"Prioritize the [magenta]{critical_count}[/magenta] critical vulnerabilities confirmed by the vendor.",
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
    return pkg_vulnerabilities


def analyse(project_type, results):
    if not results:
        LOG.info("No oss vulnerabilities detected ✅")
        return None
    summary = {"UNSPECIFIED": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for res in results:
        summary[res.severity] += 1
    return summary


def jsonl_report(
    project_type,
    results,
    pkg_aliases,
    purl_aliases,
    sug_version_dict,
    scoped_pkgs,
    out_file_name,
):
    """Produce vulnerability occurrence report in jsonl format

    :param project_type: Project type
    :param results: List of vulnerabilities found
    :param pkg_aliases: Package alias
    :param out_file_name: Output filename
    """
    ids_seen = {}
    required_pkgs = scoped_pkgs.get("required", [])
    optional_pkgs = scoped_pkgs.get("optional", [])
    excluded_pkgs = scoped_pkgs.get("excluded", [])
    with open(out_file_name, "w") as outfile:
        for data in results:
            vuln_occ_dict = data.to_dict()
            id = vuln_occ_dict.get("id")
            package_issue = data.package_issue
            full_pkg = package_issue.affected_location.package
            if package_issue.affected_location.vendor:
                full_pkg = "{}:{}".format(
                    package_issue.affected_location.vendor,
                    package_issue.affected_location.package,
                )
            # De-alias package names
            full_pkg = pkg_aliases.get(full_pkg, full_pkg)
            full_pkg_display = full_pkg
            version_used = package_issue.affected_location.version
            purl = purl_aliases.get(full_pkg, full_pkg)
            if purl:
                try:
                    purl_obj = parse_purl(purl)
                    if purl_obj:
                        version_used = purl_obj.get("version")
                        if purl_obj.get("namespace"):
                            full_pkg = f"""{purl_obj.get("namespace")}/{purl_obj.get("name")}@{purl_obj.get("version")}"""
                        else:
                            full_pkg = (
                                f"""{purl_obj.get("name")}@{purl_obj.get("version")}"""
                            )
                except Exception:
                    pass
            if ids_seen.get(id + full_pkg):
                continue
            # On occasions, this could still result in duplicates if the package exists with and without a purl
            ids_seen[id + full_pkg] = True
            project_type_pkg = "{}:{}".format(
                project_type, package_issue.affected_location.package
            )
            fixed_location = best_fixed_location(
                version_used,
                sug_version_dict.get(full_pkg),
                package_issue.fixed_location,
            )
            package_usage = "N/A"
            if full_pkg in required_pkgs or project_type_pkg in required_pkgs:
                package_usage = "required"
            elif full_pkg in optional_pkgs or project_type_pkg in optional_pkgs:
                package_usage = "optional"
            elif full_pkg in excluded_pkgs or project_type_pkg in excluded_pkgs:
                package_usage = "excluded"
            data_obj = {
                "id": id,
                "package": full_pkg_display,
                "purl": purl,
                "package_type": vuln_occ_dict.get("type"),
                "package_usage": package_usage,
                "version": version_used,
                "fix_version": fixed_location,
                "severity": vuln_occ_dict.get("severity"),
                "cvss_score": vuln_occ_dict.get("cvss_score"),
                "short_description": vuln_occ_dict.get("short_description"),
                "related_urls": vuln_occ_dict.get("related_urls"),
            }
            json.dump(data_obj, outfile)
            outfile.write("\n")


def analyse_pkg_risks(
    project_type, scoped_pkgs, private_ns, risk_results, risk_report_file=None
):
    if not risk_results:
        return
    table = Table(
        title=f"Risk Audit Summary ({project_type})",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
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
        project_type_pkg = "{}:{}".format(project_type, pkg).lower()
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
        if risk_metrics.get("risk_score") and (
            risk_metrics.get("risk_score") > config.pkg_max_risk_score
            or risk_metrics.get("pkg_private_on_public_registry_risk")
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
                if rk.endswith("_risk") and rv is True:
                    rcat = rk.replace("_risk", "")
                    help_text = config.risk_help_text.get(rcat)
                    # Only add texts that are available.
                    if help_text:
                        if rcat in ("pkg_deprecated", "pkg_private_on_public_registry"):
                            risk_categories.append(f":cross_mark: {help_text}")
                        else:
                            risk_categories.append(f":warning: {help_text}")
                        risk_categories_simple.append(help_text)
            data.append("\n".join(risk_categories))
            edata.append(", ".join(risk_categories_simple))
            table.add_row(*data)
            report_data.append(dict(zip(headers, edata)))
    if report_data:
        console.print(table)
        # Store the risk audit findings in jsonl format
        if risk_report_file:
            with open(risk_report_file, "w") as outfile:
                for row in report_data:
                    json.dump(row, outfile)
                    outfile.write("\n")
    else:
        LOG.info("No package risks detected ✅")


def analyse_licenses(project_type, licenses_results, license_report_file=None):
    if not licenses_results:
        return
    table = Table(
        title=f"License Scan Summary ({project_type})",
        box=box.DOUBLE_EDGE,
        header_style="bold magenta",
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
                        "[cyan]"
                        if "GPL" in lic["spdx-id"]
                        or "CC-BY-" in lic["spdx-id"]
                        or "Facebook" in lic["spdx-id"]
                        or "WTFPL" in lic["spdx-id"]
                        else "",
                        lic["spdx-id"],
                    ),
                    conditions_str,
                ]
                table.add_row(*data)
                report_data.append(dict(zip(headers, data)))
    if report_data:
        console.print(table)
        # Store the license scan findings in jsonl format
        if license_report_file:
            with open(license_report_file, "w") as outfile:
                for row in report_data:
                    json.dump(row, outfile)
                    outfile.write("\n")
    else:
        LOG.info("No license violation detected ✅")


def suggest_version(results, pkg_aliases={}):
    """Provide version suggestions"""
    pkg_fix_map = {}
    sug_map = {}
    if not pkg_aliases:
        pkg_aliases = {}
    for res in results:
        if isinstance(res, dict):
            full_pkg = res.get("package")
            fixed_location = res.get("fix_version")
        else:
            package_issue = res.package_issue
            full_pkg = package_issue.affected_location.package
            fixed_location = package_issue.fixed_location
            if package_issue.affected_location.vendor:
                full_pkg = "{}:{}".format(
                    package_issue.affected_location.vendor,
                    package_issue.affected_location.package,
                )
        # De-alias package names
        full_pkg = pkg_aliases.get(full_pkg, full_pkg)
        version_upgrades = pkg_fix_map.get(full_pkg, set())
        version_upgrades.add(fixed_location)
        pkg_fix_map[full_pkg] = version_upgrades
    for k, v in pkg_fix_map.items():
        if v:
            mversion = max_version(list(v))
            if mversion:
                sug_map[k] = mversion
    return sug_map


def classify_links(id, package, package_type, version, related_urls):
    """Method to classify and identify well-known links"""
    clinks = {}
    for rurl in related_urls:
        if "github.com" in rurl and "/pull" in rurl:
            clinks["GitHub PR"] = rurl
        elif "github.com" in rurl and "/issues" in rurl:
            clinks["GitHub Issue"] = rurl
        elif "poc" in rurl:
            clinks["poc"] = rurl
        elif "apache.org" in rurl and "security" in rurl:
            clinks["Apache Security"] = rurl
            clinks["vendor"] = rurl
        elif "debian.org" in rurl and "security" in rurl:
            clinks["Debian Security"] = rurl
            clinks["vendor"] = rurl
        elif "security.gentoo.org" in rurl:
            clinks["Gentoo Security"] = rurl
            clinks["vendor"] = rurl
        elif "usn.ubuntu.com" in rurl:
            clinks["Ubuntu Security"] = rurl
            clinks["vendor"] = rurl
        elif "rubyonrails-security" in rurl:
            clinks["Ruby Security"] = rurl
            clinks["vendor"] = rurl
        elif "support.apple.com" in rurl:
            clinks["Apple Security"] = rurl
            clinks["vendor"] = rurl
        elif "gitlab.alpinelinux.org" in rurl or "bugs.busybox.net" in rurl:
            clinks["vendor"] = rurl
        elif "redhat.com" in rurl or "oracle.com" in rurl:
            clinks["vendor"] = rurl
        elif (
            "openwall.com" in rurl
            or "oss-security" in rurl
            or "www.mail-archive.com" in rurl
            or "lists.debian.org" in rurl
            or "lists.fedoraproject.org" in rurl
            or "portal.msrc.microsoft.com" in rurl
            or "lists.opensuse.org" in rurl
        ):
            clinks["Mailing List"] = rurl
            clinks["vendor"] = rurl
        elif (
            "exploit-db" in rurl
            or "exploit-database" in rurl
            or "seebug.org" in rurl
            or "seclists.org" in rurl
            or "nu11secur1ty" in rurl
        ):
            clinks["exploit"] = rurl
        elif "github.com/advisories" in rurl:
            clinks["GitHub Advisory"] = rurl
        elif "hackerone" in rurl or "bugcrowd" in rurl or "bug-bounty" in rurl:
            clinks["Bug Bounty"] = rurl
        elif "cwe.mitre.org" in rurl:
            clinks["cwe"] = rurl
    return clinks
