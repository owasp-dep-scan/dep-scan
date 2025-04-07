from vdb.lib import VulnerabilityOccurrence

from analysis_lib import Counts, VdrOptions, VDRResult, XBOMAnalyzer
from analysis_lib.utils import (
    retrieve_bom_dependency_tree,
    retrieve_oci_properties,
    process_vuln_occ,
    analyze_cve_vuln,
    make_version_suggestions,
    dedupe_vdrs,
    get_pkg_list,
    remove_extra_metadata,
)
from analysis_lib.output import generate_console_output, output_results
from analysis_lib.search import find_vulns


class VDRAnalyzer(XBOMAnalyzer):
    """
    CycloneDX VDR Analyzer
    """

    def process(self) -> VDRResult:
        options: VdrOptions = self.vdr_options
        if not options.bom_file and not options.pkg_list:
            if options.logger:
                options.logger.debug("The BOM file and package list were empty.")
            return VDRResult(success=False, pkg_vulnerabilities=None)
        pkg_list = options.pkg_list or []
        if options.bom_file:
            pkg_list = get_pkg_list(options.bom_file)
        if not pkg_list:
            if options.logger:
                options.logger.debug("The package list was empty.")
            return VDRResult(success=False, pkg_vulnerabilities=None)
        vdb_results, pkg_aliases, purl_aliases = find_vulns(
            options.project_type, pkg_list
        )
        options.pkg_aliases = pkg_aliases
        options.purl_aliases = purl_aliases
        if not vdb_results:
            return VDRResult(success=False, pkg_vulnerabilities=None)
        pkg_vulnerabilities = []
        pkg_group_rows = {}
        direct_purls = options.direct_purls or {}
        reached_purls = options.reached_purls or {}
        required_pkgs = options.scoped_pkgs.get("required", [])
        optional_pkgs = options.scoped_pkgs.get("optional", [])
        # Retrieve any dependency tree from the SBOM
        bom_dependency_tree, bom_data = retrieve_bom_dependency_tree(options.bom_file)
        oci_props = retrieve_oci_properties(bom_data)
        oci_product_types = oci_props.get("oci:image:componentTypes", "")
        counts = Counts()
        include_pkg_group_rows = set()
        if options.init_results:
            vdb_results = vdb_results + options.init_results
        for vuln_occ_dict in vdb_results:
            if not vuln_occ_dict:
                continue
            if isinstance(vuln_occ_dict, VulnerabilityOccurrence):
                counts, add_to_pkg_group_rows, vuln = process_vuln_occ(
                    bom_dependency_tree,
                    direct_purls,
                    oci_product_types,
                    optional_pkgs,
                    options,
                    reached_purls,
                    required_pkgs,
                    vuln_occ_dict.to_dict(),
                    counts,
                )
            else:
                counts, vuln, add_to_pkg_group_rows = analyze_cve_vuln(
                    vuln_occ_dict,
                    reached_purls,
                    direct_purls,
                    optional_pkgs,
                    required_pkgs,
                    bom_dependency_tree,
                    counts,
                )
            pkg_vulnerabilities.append(vuln)
            if add_to_pkg_group_rows:
                include_pkg_group_rows.add(vuln.get("bom-ref"))
            # If the user doesn't want any table output return quickly
        if options.suggest_mode:
            pkg_vulnerabilities = make_version_suggestions(
                pkg_vulnerabilities, options.project_type
            )
        pkg_vulnerabilities = dedupe_vdrs(pkg_vulnerabilities)
        # Should we print the vulnerability table
        if not options.no_vuln_table:
            pkg_group_rows, table = generate_console_output(
                pkg_vulnerabilities,
                bom_dependency_tree,
                include_pkg_group_rows,
                options,
            )
            output_results(
                counts,
                direct_purls,
                options,
                pkg_group_rows,
                pkg_vulnerabilities,
                reached_purls,
                table,
            )
        return VDRResult(
            success=True,
            pkg_vulnerabilities=remove_extra_metadata(pkg_vulnerabilities),
            pkg_group_rows=pkg_group_rows,
        )
