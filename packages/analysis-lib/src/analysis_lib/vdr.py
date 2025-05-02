from vdb.lib import VulnerabilityOccurrence

from analysis_lib import Counts, VdrAnalysisKV, VDRResult, XBOMAnalyzer
from analysis_lib.output import generate_console_output, output_priority_suggestions
from analysis_lib.search import find_vulns
from analysis_lib.utils import (
    analyze_cve_vuln,
    dedupe_vdrs,
    get_all_lifecycle_pkgs,
    get_lifecycle_pkgs,
    make_version_suggestions,
    process_vuln_occ,
    remove_extra_metadata,
    retrieve_bom_dependency_tree,
    retrieve_oci_properties,
)


def predict_optionals(prebuild_purls, build_purls, postbuild_purls, optional_pkgs):
    for prepurl in prebuild_purls.keys():
        if prepurl in optional_pkgs:
            continue
        if prepurl not in build_purls and prepurl not in postbuild_purls:
            optional_pkgs.append(prepurl)


class VDRAnalyzer(XBOMAnalyzer):
    """
    CycloneDX VDR Analyzer
    """

    def process(self) -> VDRResult:
        options: VdrAnalysisKV = self.vdr_options
        # Are we dealing with empty everything
        if not options.bom_file and not options.pkg_list and not options.bom_dir:
            if options.logger:
                options.logger.debug("The BOM file and package list were empty.")
            return VDRResult(success=False, pkg_vulnerabilities=None)
        pkg_list = options.pkg_list or []
        (
            prebuild_purls,
            build_purls,
            postbuild_purls,
            executable_purls,
            setuid_executable_purls,
            setgid_executable_purls,
            purl_identities,
        ) = {}, {}, {}, {}, {}, {}, {}
        if options.bom_dir:
            (
                prebuild_purls,
                build_purls,
                postbuild_purls,
                executable_purls,
                setuid_executable_purls,
                setgid_executable_purls,
                purl_identities,
            ) = get_all_lifecycle_pkgs(options.bom_dir)
        elif options.bom_file:
            (
                prebuild_purls,
                build_purls,
                postbuild_purls,
                executable_purls,
                setuid_executable_purls,
                setgid_executable_purls,
                purl_identities,
            ) = get_lifecycle_pkgs(options.bom_file)
        options.prebuild_purls = prebuild_purls
        options.build_purls = build_purls
        options.postbuild_purls = postbuild_purls
        if not pkg_list:
            if options.logger:
                options.logger.debug("The package list was empty.")
            return VDRResult(success=False, pkg_vulnerabilities=None)
        vdb_results, pkg_aliases, purl_aliases = find_vulns(
            options.project_type, pkg_list, options.fuzzy_search, options.search_order
        )
        options.pkg_aliases = pkg_aliases
        options.purl_aliases = purl_aliases
        if not vdb_results:
            if options.logger:
                if options.search_order and options.search_order != "pcu":
                    if not options.fuzzy_search:
                        options.logger.info(
                            "No vulnerabilities found. Try using a different search order and enabling fuzzy search. Example: pass the arguments `--fuzzy-search --search-order pcu`"
                        )
                    else:
                        options.logger.info(
                            "No vulnerabilities found. Try using a different search order. Example: pass the arguments `--search-order cpu`"
                        )
            return VDRResult(success=False, pkg_vulnerabilities=None)
        pkg_vulnerabilities = []
        pkg_group_rows = {}
        direct_purls = options.direct_purls or {}
        reached_purls = options.reached_purls or {}
        reached_services = options.reached_services or {}
        endpoint_reached_purls = options.endpoint_reached_purls or {}
        required_pkgs = options.scoped_pkgs.get("required", [])
        optional_pkgs = options.scoped_pkgs.get("optional", [])
        # Can we identify more optional packages?
        if prebuild_purls and build_purls:
            predict_optionals(
                prebuild_purls, build_purls, postbuild_purls, optional_pkgs
            )
        # Retrieve any dependency tree from the SBOM
        # This logic could be improved to retrieve multiple matching dependency trees
        bom_dependency_tree = retrieve_bom_dependency_tree(
            options.bom_file, options.bom_dir
        )
        # OCI properties will give us information about the container layer
        # Can we do anything clever with this information?
        oci_props = retrieve_oci_properties(options.bom_file, options.bom_dir)
        oci_product_types = oci_props.get("oci:image:componentTypes", "")
        counts = Counts()
        include_pkg_group_rows = set()
        likely_false_positive = False
        if options.init_results:
            vdb_results = vdb_results + options.init_results
        added_results = {}
        for vuln_occ_dict in vdb_results:
            if not vuln_occ_dict:
                continue
            if isinstance(vuln_occ_dict, VulnerabilityOccurrence):
                # To reduce duplicates, this function is not enhanced to support the new analysis algorithms.
                # This results in quality loss when working with VDB 5-style remote audit results.
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
                # All our focus has gone into this particular method.
                counts, vuln, add_to_pkg_group_rows, likely_false_positive = (
                    analyze_cve_vuln(
                        vuln_occ_dict,
                        reached_purls,
                        direct_purls,
                        reached_services,
                        endpoint_reached_purls,
                        optional_pkgs,
                        required_pkgs,
                        prebuild_purls,
                        build_purls,
                        postbuild_purls,
                        purl_identities,
                        bom_dependency_tree,
                        counts,
                    )
                )
                # When multiple BOMs are scanned, we might end up with duplicate vulns
                # This section attempts to filter the results further.
                # This is similar to normalize.py -> dedup method, which no longer works
                vid = vuln.get("id")
                fixed_location = vuln.get("fixed_location") or ""
                if vid:
                    key = f"{vid}|{fixed_location}"
                    if added_results.get(key):
                        likely_false_positive = True
                    else:
                        added_results[key] = True
            # Surface false positive results only in fuzzy search mode
            if not likely_false_positive or options.fuzzy_search:
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
            output_priority_suggestions(
                counts,
                direct_purls,
                options,
                pkg_group_rows,
                pkg_vulnerabilities,
                reached_purls,
                reached_services,
                endpoint_reached_purls,
                executable_purls,
                setuid_executable_purls,
                setgid_executable_purls,
                purl_identities,
                oci_props,
                table,
            )
        return VDRResult(
            success=True,
            pkg_vulnerabilities=remove_extra_metadata(pkg_vulnerabilities),
            prioritized_pkg_vuln_trees=pkg_group_rows,
            reached_purls=reached_purls,
            reached_services=reached_services,
            endpoint_reached_purls=endpoint_reached_purls,
            purl_identities=purl_identities,
        )
