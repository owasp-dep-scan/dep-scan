"""Convert vulnerability-db records into CycloneDX VDR fields.

This module reads the plain CVE-5 dicts and occurrence records that vdb
returns (descriptions, aliases, references, metrics, problem types, affected
locations) and turns them into the corresponding VDR pieces: text, advisories,
references, ratings, CWE lists and fix versions.

It does not merge entries that describe the same vulnerability (see
analysis_lib.merge) and does not decide priority, reachability or insights
(see analysis_lib.prioritize).
"""

import base64
import contextlib
import encodings.utf_8
import re
from typing import Any, Dict, List, Tuple

import cvss
from analysis_lib.config import (
    ADVISORY,
    CWE_SPLITTER,
    JFROG_ADVISORY,
    REF_MAP,
    SEVERITY_REF,
    UPPER_VERSION_FROM_DETAIL_A,
    UPPER_VERSION_FROM_DETAIL_B,
)
from analysis_lib.merge import combine_references
from custom_json_diff.lib.utils import compare_versions
from cvss import CVSSError
from vdb.lib.config import PLACEHOLDER_FIX_VERSION
from vdb.lib.utils import parse_cpe


def format_system_name(system_name):
    system_name = (
        system_name.capitalize()
        .replace("Redhat", "Red Hat")
        .replace("Zerodayinitiative", "Zero Day Initiative")
        .replace("Github", "GitHub")
        .replace("Netapp", "NetApp")
        .replace("Npmjs", "NPM")
        .replace("Alpinelinux", "Alpine Linux")
        .replace("Fedoraproject", "Fedora Project")
        .replace("Djangoproject", "Django Project")
        .replace("Opensuse", "Open Suse")
        .replace("Securityfocus", "Security Focus")
    )
    return system_name


def get_description_detail(data: List[Dict] | str | None) -> Tuple[str, str]:
    """The summary and full text of a record's first description.

    ``data`` is the plain CVE-5 dict list vdb 7 returns (``[{"lang": ...,
    "value": ...}, ...]``); a bare string is accepted for callers holding
    pre-extracted text.
    """
    if not data:
        return "", ""
    if isinstance(data, str):
        detail = data
    elif isinstance(data, list) and data and isinstance(data[0], dict):
        detail = data[0].get("value") or ""
    else:
        detail = ""
    description = ""
    detail = (
        detail.replace("\\r\\n", "\n")
        .replace("\\n", "\n")
        .replace("\\r", "\n")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\\t", "\t")
        .replace("\\`", "`")
    )
    if detail and "\n" in detail:
        description = detail.split("\n")[0]
    elif "." in detail:
        description = detail.split(".")[0]
    detail = bytes.decode(encodings.utf_8.encode(detail)[0], errors="replace")
    description = description.lstrip("# ")
    return description, detail


_ALIASES_SECTION_RE = re.compile(r"## Aliases\s*\n\s*([^\n\r]+)")


def description_full_text(data: List[Dict] | str | None) -> str:
    """The complete description text vdb stored for a record.

    vdb stores descriptions longer than 4096 characters as the placeholder
    "Refer to the supporting media" and moves the real text into a base64
    ``supportingMedia`` item, so the value alone can miss the Aliases block.
    """
    if not data:
        return ""
    if isinstance(data, str):
        return data
    parts = []
    for desc in data or []:
        if not isinstance(desc, dict):
            continue
        if desc.get("value"):
            parts.append(desc["value"])
        for media in desc.get("supportingMedia") or []:
            value = media.get("value") if isinstance(media, dict) else None
            if not value:
                continue
            if media.get("base64"):
                try:
                    value = base64.b64decode(value).decode("utf-8", errors="replace")
                except (ValueError, TypeError):
                    continue
            parts.append(str(value))
    return "\n".join(parts)


def parse_alias_ids(detail: str) -> List[str]:
    """Ids from the Aliases block vdb bakes into OSV and errata descriptions.

    vdb appends ``## Aliases`` followed by one comma-separated line of ids to
    the descriptions it stores (see vulnerability-db osv.py). The line is
    osv.dev's alias group as published, which never contains the record's
    own id. The Related block that may follow lists ids of *other*
    vulnerabilities, so only the Aliases line is read here.
    """
    if not detail:
        return []
    # vdb stores the description with escaped newlines
    detail = detail.replace("\\r\\n", "\n").replace("\\n", "\n")
    match = _ALIASES_SECTION_RE.search(detail)
    if not match:
        return []
    return [
        alias.strip()
        for alias in match.group(1).split(",")
        if re.match(r"^(CVE|GHSA)-", alias.strip())
    ]


def cvss_to_vdr_rating(vuln_occ_dict):
    """
    Generates a rating object for inclusion in the vdr file.

    :param vuln_occ_dict: Vulnerability data

    :return: A list containing a dictionary with CVSS score information.
    """
    cvss_score = vuln_occ_dict.get("cvss_score", 2.0)
    with contextlib.suppress(ValueError, TypeError):
        cvss_score = float(cvss_score)
    if (pkg_severity := vuln_occ_dict.get("severity", "").lower()) not in SEVERITY_REF:
        pkg_severity = "unknown"
    # CycloneDX ratings mix float scores and string severity/vector/method.
    ratings: List[Dict[str, Any]] = [
        {
            "score": cvss_score,
            "severity": pkg_severity.lower(),
        }
    ]
    method = "31"
    if vuln_occ_dict.get("cvss_v3") and (
        vector_string := vuln_occ_dict["cvss_v3"].get("vector_string")
    ):
        ratings[0]["vector"] = vector_string
        with contextlib.suppress(CVSSError):
            method = cvss.CVSS3(vector_string).as_json().get("version", "")
            method = method.replace(".", "").replace("0", "")
    ratings[0]["method"] = f"CVSSv{method}"

    return ratings


def split_cwe(cwe):
    """
    Split the given CWE string into a list of CWE IDs.

    :param cwe: The problem issue taken from a vulnerability object

    :return: A list of CWE IDs
    :rtype: list
    """
    cwe_ids = []

    if isinstance(cwe, str):
        cwe_ids = re.findall(CWE_SPLITTER, cwe)
    elif isinstance(cwe, list):
        cwes = "|".join(cwe)
        cwe_ids = re.findall(CWE_SPLITTER, cwes)

    with contextlib.suppress(ValueError, TypeError):
        cwe_ids = [int(cwe_id) for cwe_id in cwe_ids]
    return cwe_ids


def classify_links(related_urls):
    """
    Method to classify and identify well-known links

    :param related_urls: List of URLs
    :return: Dictionary of classified links and URLs
    """
    clinks = {}
    if not related_urls:
        return clinks
    for rurl in related_urls:
        if "github.com" in rurl and "/pull" in rurl:
            clinks["GitHub PR"] = rurl
        elif "github.com" in rurl and "/issues" in rurl:
            clinks["GitHub Issue"] = rurl
        elif "bitbucket.org" in rurl and "/issues" in rurl:
            clinks["Bitbucket Issue"] = rurl
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
        elif "access.redhat.com" in rurl:
            clinks["Red Hat Security"] = rurl
            clinks["vendor"] = rurl
        elif "oracle.com" in rurl and "security" in rurl:
            clinks["Oracle Security"] = rurl
            clinks["vendor"] = rurl
        elif "gitlab.alpinelinux.org" in rurl or "bugs.busybox.net" in rurl:
            clinks["vendor"] = rurl
        elif (
            "redhat.com" in rurl
            or "oracle.com" in rurl
            or "curl.haxx.se" in rurl
            or "nodejs.org" in rurl
            or "/security." in rurl
            or "/securityadvisories." in rurl
            or "sec-consult.com" in rurl
            or "jenkins.io/security" in rurl
            or "support.f5.com" in rurl
            or "suricata-ids.org/" in rurl
            or "foxitsoftware.com/support/" in rurl
            or "success.trendmicro.com/" in rurl
            or "docs.jamf.com/" in rurl
            or "www.postgresql.org/about" in rurl
        ):
            clinks["vendor"] = rurl
        elif "wordpress" in rurl or "wpvulndb" in rurl:
            clinks["wordpress"] = rurl
        elif "chrome.google.com/webstore" in rurl:
            clinks["Chrome Extension"] = rurl
        elif (
            "openwall.com" in rurl
            or "oss-security" in rurl
            or "www.mail-archive.com" in rurl
            or "lists." in rurl
            or "portal.msrc.microsoft.com" in rurl
            or "mail." in rurl
            or "securityfocus." in rurl
            or "securitytracker." in rurl
            or "/discussion/" in rurl
            or "/archives/" in rurl
            or "groups." in rurl
        ):
            clinks["Mailing List"] = rurl
        elif (
            "exploit-db" in rurl
            or "exploit-database" in rurl
            or "seebug.org" in rurl
            or "seclists.org" in rurl
            or "nu11secur1ty" in rurl
            or "packetstormsecurity.com" in rurl
            or "coresecurity.com" in rurl
            or "project-zero" in rurl
            or "0dd.zone" in rurl
            or "snyk.io/research/" in rurl
            or "chromium.googlesource.com/infra" in rurl
            or "synacktiv.com" in rurl
            or "bishopfox.com" in rurl
            or "zerodayinitiative.com" in rurl
            or "www.samba.org/samba/security/" in rurl
            or "www.synology.com/support/security/" in rurl
            or "us-cert.gov/advisories" in rurl
        ):
            clinks["exploit"] = rurl
        elif "oss-fuzz" in rurl:
            clinks["OSS-Fuzz"] = rurl
        elif "github.com/advisories" in rurl:
            clinks["GitHub Advisory"] = rurl
        elif (
            "hackerone" in rurl
            or "bugcrowd" in rurl
            or "bug-bounty" in rurl
            or "huntr.dev" in rurl
            or "bounties" in rurl
        ):
            clinks["Bug Bounty"] = rurl
        elif "cwe.mitre.org" in rurl:
            clinks["cwe"] = rurl
        elif "/community" in rurl or "/forum" in rurl or "/discuss" in rurl:
            clinks["Forum"] = rurl
        elif "bugzilla." in rurl or "bugs." in rurl or "chat." in rurl:
            clinks["Issue"] = rurl
        else:
            clinks["other"] = rurl
    return clinks


def get_cwe_list(data: List[Dict] | None) -> List:
    """CWE numbers from a record's ``problemTypes`` block (plain CVE-5 dict)."""
    cwes = []
    if not data:
        return cwes
    for block in data:
        for rec in (block.get("descriptions") if isinstance(block, dict) else None) or []:
            if rec.get("type") == "CWE" and rec.get("cweId"):
                cwes.append(int(rec["cweId"].split("-")[1]))
    return cwes


def _cna(record) -> Dict:
    """The ``containers.cna`` block of a CVE-5 record dict, or an empty dict.

    Any level may be missing or null in a hydrated record, and a missing
    block must read as "no data", not raise.
    """
    if not isinstance(record, dict):
        return {}
    containers = record.get("containers")
    if not isinstance(containers, dict):
        return {}
    cna = containers.get("cna")
    return cna if isinstance(cna, dict) else {}


def cve_to_vdr(cve: Dict, vid: str):
    """Extract the VDR fields from a hydrated vdb record's CVE-5 dict.

    ``cve`` is the plain ``source_data`` dict vdb 7 returns (the JSON form of
    the CVE-5 record: ``containers.cna``, ``cveMetadata`` at the top level).
    """
    root = cve if isinstance(cve, dict) else {}
    cna = _cna(root)
    metadata = root.get("cveMetadata") or {}
    description, detail = get_description_detail(cna.get("descriptions"))
    alias_ids = parse_alias_ids(description_full_text(cna.get("descriptions")))
    advisories, references, bug_bounties, pocs, exploits, vendors, source = refs_to_vdr(
        cna.get("references"), vid.lower(), alias_ids
    )
    vector, method, severity, score = parse_metrics(cna.get("metrics"))
    if not source:
        assigner_short_name = metadata.get("assignerShortName")
        assigner_name = str(assigner_short_name) if assigner_short_name else ""

        source = {"name": assigner_name.capitalize()}
        if source.get("name") == "Github_m":
            source = {
                "name": "GitHub Advisory Database",
                "url": f"https://github.com/advisories/{vid}",
            }
            advisories.append(
                {
                    "title": f"GitHub Advisory {vid}",
                    "url": f"https://github.com/advisories/{vid}",
                }
            )
    cwes = get_cwe_list(cna.get("problemTypes"))
    vendor = ""
    affected_root = cna.get("affected") or []
    if affected_root:
        vendor = affected_root[0].get("vendor", "") or ""
    ratings = {}
    if vector:
        ratings = {
            "method": method,
            "severity": severity.lower(),
            "vector": vector,
        }
        # A metric without a baseScore leaves the score unset rather than
        # empty: the CycloneDX rating schema accepts a number or no field,
        # never an empty string.
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            ratings["score"] = score
    return (
        source,
        references,
        advisories,
        cwes,
        description,
        detail,
        ratings,
        bug_bounties,
        pocs,
        exploits,
        vendors,
        vendor,
    )


def parse_metrics(metrics):
    """Vector, method, severity and score from a record's ``metrics`` list.

    The CVSS sub-objects are plain dicts in the CVE-5 JSON form; ``baseScore``
    is a number there and reaches the VDR rating unchanged.
    """
    vector = ""
    method = ""
    severity = "unknown"
    score: Any = ""
    if not metrics:
        return vector, method, severity, score
    for metric in metrics:
        if not isinstance(metric, dict):
            continue
        cvss_v4 = metric.get("cvssV4_0")
        if cvss_v4:
            return (
                cvss_v4.get("vectorString") or "",
                "CVSSv4",
                cvss_v4.get("baseSeverity") or "unknown",
                cvss_v4.get("baseScore") or "",
            )

        if method == "CVSSv31":
            continue

        cvss_v3 = metric.get("cvssV3_1") or metric.get("cvssV3_0")
        if not cvss_v3:
            continue

        vector = cvss_v3.get("vectorString") or ""
        version = cvss_v3.get("version") or ""
        method = "CVSSv31" if version == "3.1" else "CVSSv3"
        severity = cvss_v3.get("baseSeverity") or "unknown"
        score = cvss_v3.get("baseScore") or ""
    return vector, method, severity, score


def process_package_issue(options, vuln_occ_dict):
    package_issue = vuln_occ_dict.get("package_issue") or {}
    matched_by = vuln_occ_dict.get("matched_by") or ""
    full_pkg = vuln_occ_dict.get("affected") or package_issue.get("affected_location")
    full_pkg = (full_pkg.get("package") if isinstance(full_pkg, dict) else "") or ""
    project_type_pkg = (
        f"{options.project_type}:{package_issue.get('affected_location', {}).get('package')}"
    )
    if package_issue.get("affected_location", {}).get("vendor"):
        full_pkg = (
            f"{package_issue['affected_location'].get('vendor')}:"
            f"{package_issue['affected_location'].get('package')}"
        )
    elif package_issue.get("affected_location", {}).get("cpe_uri"):
        vendor, _, _, _ = parse_cpe(package_issue.get("affected_location", {}).get("cpe_uri"))
        if vendor:
            full_pkg = f"{vendor}:{package_issue['affected_location'].get('package')}"
    if matched_by:
        version = matched_by.split("|")[-1]
        full_pkg = full_pkg + ":" + version
    # De-alias package names
    if options.pkg_aliases.get(full_pkg):
        full_pkg = options.pkg_aliases.get(full_pkg)
    else:
        full_pkg = options.pkg_aliases.get(full_pkg.lower(), full_pkg)
    version_used = package_issue.get("affected_location", {}).get("version") or ""
    purl = options.purl_aliases.get(full_pkg, full_pkg)
    return full_pkg, package_issue, project_type_pkg, purl, version_used


def get_unaffected(vuln):
    # Do we have a pre-computed fix_version from vdb already? vdb 7 computes
    # it at hydration time, so this is the usual path.
    if vuln.get("fix_version"):
        return vuln.get("fix_version")
    source_data = vuln.get("source_data")
    cna = _cna(source_data)
    for p in cna.get("affected") or []:
        for ver in p.get("versions") or []:
            if ver.get("status") == "unaffected" and ver.get("version"):
                return ver.get("version") or ""
    vers = vuln.get("matching_vers", "")
    if "|" in vers:
        vers = vers.split("|")[-1]
        if "!=" in vers or "<=" not in vers:
            return vers.replace("<", "").replace("!=", "")
    elif "/<" in vers and "/<=" not in vers:
        return vers.split("/<")[-1]
    elif vers.endswith(f"<{PLACEHOLDER_FIX_VERSION}"):
        return PLACEHOLDER_FIX_VERSION
    return ""


def get_version_from_detail(detail, affected_version):
    version = ""
    if match := UPPER_VERSION_FROM_DETAIL_A.search(detail):
        version = match["version"].rstrip(".")
    if match := UPPER_VERSION_FROM_DETAIL_B.search(detail):
        version = match["version"].rstrip(".")
    if affected_version and version and compare_versions(affected_version, version, "<="):
        return version
    return ""


def get_ref_summary(url, patterns):
    """
    Returns the summary string associated with a given URL.

    :param url: The URL to match against the patterns in the REF_MAP.
    :type url: str

    :param patterns: Regex patterns to match against the URL
    :type patterns: dict

    :return: The summary string corresponding to the matched pattern in REF_MAP.
    :rtype: str

    :raises: TypeError if url is not a string
    """
    if not isinstance(url, str):
        raise TypeError("url must be a string")
    for pattern, value in patterns.items():
        if match := pattern.search(url):
            return value, match
    return "Other", None


def get_ref_summary_helper(url, patterns):
    lower_url = url.lower().rstrip("/")
    if (
        any(
            (
                "github.com" in lower_url,
                "bitbucket.org" in lower_url,
                "chromium" in lower_url,
            )
        )
        and "advisory" not in lower_url
        and "advisories" not in lower_url
        and "nvd.nist.gov/vuln/detail/CVE" not in lower_url
    ):
        value, match = get_ref_summary(url, patterns["repo_hosts"])
        if match:
            if value == "Generic":
                return (
                    (
                        f"{match['host']}-{match['type']}-{match['user']}-{match['repo']}-"
                        f"{match['id']}"
                    ).replace("[p/", "["),
                    match,
                    f"{format_system_name(match['host'])} {match['type'].capitalize()} "
                    f"[{match['user']}/{match['repo']}]".replace("[p/", "["),
                )
            if value == "GitHub Blob":
                return (
                    f"github-blob-{match['user']}/{match['repo']}-{match['file']}@{match['ref']}",
                    match,
                    f"GitHub Blob [{match['user']}/{match['repo']}]",
                )
            if value == "GitHub Gist":
                return (
                    f"github-gist-{match['user']}-{match['id']}",
                    match,
                    f"GitHub Gist [{match['user']}]",
                )
        return value, match, ""
    value, match = get_ref_summary(url, patterns["other"])
    if value == "Advisory":
        org = match["org"] if match else ""
        return value, match, f"{format_system_name(org)} Advisory"
    elif value == "Exploit":
        if "seclists" in lower_url:
            _, match = get_ref_summary(url, {patterns["exploits"]["seclists"]: "seclists"})
            value = value.replace("/", "-")
        else:
            _, match = get_ref_summary(url, {patterns["exploits"]["generic"]: "generic"})
        return (
            (value, match, f"{format_system_name(match['org'])} Exploit")
            if match
            else (value, None, "Exploit")
        )
    return value, match, value


def refs_to_vdr(
    references: List[Dict] | None, vid, alias_ids: List[str] | None = None
) -> Tuple[List, List, List, List, List, List, Dict]:
    """
    Parses the reference list provided by VDB and converts to VDR objects

    :param references: List of reference dicts (``{"url": ..., "tags": ...}``)
    :param vid: str of vulnerability id
    :param alias_ids: ids from the record's Aliases block, when the source
        provides one (vdb bakes it into OSV and errata descriptions)

    :return: Tuple of advisories, references for VDR
    :rtype: tuple[list, list]
    """
    if not references:
        return [], [], [], [], [], [], {}
    # Dedupe while keeping the stored order so the same BOM always renders
    # the same VDR (a set would iterate in per-process hash order). See #540.
    ref = []
    seen_urls = set()
    for reference in references:
        url = reference.get("url") if isinstance(reference, dict) else None
        if url and str(url) not in seen_urls:
            seen_urls.add(str(url))
            ref.append(str(url))
    # osv.dev merges the aliases of a whole advisory group, so a group
    # holding a CVE other than this record's id means the group also names
    # a *different* vulnerability (an incomplete-fix sibling) and its
    # advisory, and the record's references can link them. CycloneDX
    # defines references as pointers to equivalent vulnerabilities, so in
    # that case the group's ids other than the record's own are dropped
    # from references; their URLs stay in the advisories list. osv.dev
    # never lists a record's own id in its aliases, so the record's own
    # GHSA (linked by vdb >= 6.7.4 as github.com/advisories/<GHSA>) is
    # kept. See #540.
    foreign_ids = set()
    vid_upper = str(vid).upper()
    group = {alias.upper() for alias in alias_ids or []}
    if any(a.startswith("CVE-") and a != vid_upper for a in group):
        foreign_ids = group - {vid_upper}
    advisories = []
    refs = []
    bug_bounty = []
    poc = []
    exploit = []
    vendor = []
    source = {}
    for i in ref:
        category, rmatch, system_name = get_ref_summary_helper(i, REF_MAP)
        if not rmatch:
            continue
        if category == "CVE Record":
            record = {"id": rmatch[0], "source": {"url": i}}
            if "nvd.nist.gov" in i:
                record["source"]["name"] = "NVD"
            refs.append(record)
            if rmatch[0].lower() == vid and not source:
                source = record["source"]
            advisories.append({"title": rmatch[0], "url": i})
        elif "Advisory" in category:
            adv_id = rmatch["id"]
            if (tmp := adv_id.replace("-", "")) and tmp.isalpha() and len(tmp) < 20:
                continue
            if "vuldb" in i.lower():
                adv_id = f"vuldb-{adv_id}"
            if system_name in {"Jfrog Advisory", "Gentoo Advisory"}:
                adv_id, system_name = adv_ref_parsing(adv_id, i, system_name)
            if adv_id.lower() == vid and not source:
                source = {"name": system_name, "url": i}
            advisories.append({"title": f"{system_name} {adv_id}", "url": i})
            if system_name == "NPM Advisory":
                adv_id = f"NPM-{adv_id}"
            refs.append({"id": adv_id, "source": {"name": system_name, "url": i}})
            vendor.append(i)
        elif category in ("POC", "BugBounty", "Exploit"):
            if category == "POC":
                poc.append(i)
            elif category == "BugBounty":
                bug_bounty.append(i)
            else:
                adv_id = f"{system_name.lower().replace(' ', '-')}-{rmatch['id']}"
                refs.append({"id": adv_id, "source": {"name": system_name, "url": i}})
                if system_name in {"Synology", "Samba", "CISA", "Zero Day Initiative"}:
                    advisories.append(
                        {"title": f"{system_name} Advisory {rmatch['id']}", "url": i}
                    )
                    if system_name in {"Synology Exploits", "Samba Exploits"}:
                        vendor.append(i)
                exploit.append(i)
        elif category == "Bugzilla":
            refs.append(
                {
                    "id": f"{rmatch['org']}-bugzilla-{rmatch['id']}",
                    "source": {
                        "name": f"{format_system_name(rmatch['org'])} Bugzilla",
                        "url": i,
                    },
                }
            )
            vendor.append(i)
        elif category == "Vendor":
            if "announce" in i:
                vendor.append(i)
            if rmatch := ADVISORY.search(i):
                system_name = f"{format_system_name(rmatch['org'])} Mailing List"
                refs.append(
                    {
                        "id": f"{rmatch['org']}-msg-{rmatch['id']}",
                        "source": {"name": system_name, "url": i},
                    }
                )
        elif category == "Mailing List":
            if "openwall" in i:
                if not (rmatch := REF_MAP["openwall"].search(i)):
                    continue
                adv_id = f"openwall-{rmatch['list_type']}-msg-{rmatch['id'].replace('/', '-')}"
            else:
                rmatch = ADVISORY.search(i)
                if not rmatch:
                    continue
                adv_id = f"{rmatch['org']}-msg-{rmatch['id']}"
            if rmatch:
                system_name = f"{format_system_name(rmatch['org'])} {category}"
                refs.append({"id": adv_id, "source": {"name": system_name, "url": i}})
                vendor.append(i)
        elif category == "Generic":
            refs.append(
                {
                    "id": f"{rmatch['user']}-{rmatch['repo']}-{rmatch['type']}-{rmatch['id']}",
                    "source": {
                        "name": f"{format_system_name(rmatch['host'])} {rmatch['type'].capitalize()}",
                        "url": i,
                    },
                }
            )
    # One entry per id: a record can link the same advisory on several hosts
    # (github.com/advisories/<GHSA> and the repository's advisory page).
    kept_refs = []
    seen_ref_ids = set()
    for aref in refs:
        ref_id = str(aref.get("id", "")).upper()
        if ref_id in foreign_ids or ref_id in seen_ref_ids:
            continue
        seen_ref_ids.add(ref_id)
        kept_refs.append(aref)
    return (
        combine_references(advisories, []),
        combine_references(kept_refs, []),
        bug_bounty,
        poc,
        exploit,
        vendor,
        source,
    )


def adv_ref_parsing(adv_id, i, system_name):
    if system_name == "Gentoo Advisory":
        adv_id = f"glsa-{adv_id}"
    if system_name == "Jfrog Advisory":
        system_name = "JFrog Advisory"
        if id_match := JFROG_ADVISORY.search(i):
            adv_id = id_match["id"]
    return adv_id, system_name
