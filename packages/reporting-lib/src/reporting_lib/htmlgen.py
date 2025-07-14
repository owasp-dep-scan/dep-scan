import json
import html
import re

from reporting_lib.template import (
    PRIORITIZED_VULNERABILITIES,
    VDR,
    PROACTIVE_MEASURES,
    SERVICE_ENDPOINTS,
    REACHABLE_FLOWS,
    SECURE_DESIGN_TIPS,
    HTML_REPORT,
    MALWARE_ALERT,
)

NEWLINE = "\n"


class ReportGenerator:
    VULNERABILITIES_COUNT = "Vulnerabilities count"
    SUMMARY = "Summary"
    DATA = "Data"
    TABLE_HEADERS = "Table headers"
    RECOMMENDATION = "Recommendation"

    VULNERABILITY_DISCLOSURE_REPORT = "Vulnerability Disclosure Report"

    DEPENDENCY_SCAN_RESULTS_BOM = "Dependency Scan Results (BOM)"
    DEPENDENCY_SCAN_RESULTS_BOM_SUMMARY = DEPENDENCY_SCAN_RESULTS_BOM + " " + SUMMARY
    DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS = [
        "Dependency Tree",
        "Insights",
        "Fix Version",
        "Severity",
        "Score",
    ]
    DEPENDENCY_SCAN_RESULTS_BOM_DATA = DEPENDENCY_SCAN_RESULTS_BOM + " " + DATA
    DEPENDENCY_SCAN_RESULTS_BOM_RECOMMENDATION = (
        DEPENDENCY_SCAN_RESULTS_BOM + " " + RECOMMENDATION
    )

    PRIORITIZED_VULNERABILITIES = "Prioritized Vulnerabilities"
    PRIORITIZED_VULNERABILITIES_ALTERNATIVE = "Next Steps"
    TOP_PRIORITY_BOM = "Top Priority (BOM)"
    TOP_PRIORITY_BOM_SUMMARY = TOP_PRIORITY_BOM + " " + SUMMARY
    TOP_PRIORITY_BOM_DATA_COLUMNS = [
        "Package",
        "Prioritized CVEs",
        "Fix Version",
        "Next Steps",
    ]
    TOP_PRIORITY_BOM_DATA = TOP_PRIORITY_BOM + " " + DATA
    PRIORITIZED_COUNT = "Prioritized count"

    PROACTIVE_MEASURES = "Proactive Measures"
    TOP_REACHABLE_PACKAGES = "Top Reachable Packages"
    TOP_REACHABLE_PACKAGES_ALTERNATIVE_01 = "💥 Top Endpoint-Reachable Packages"
    TOP_REACHABLE_PACKAGES_ALTERNATIVE_02 = "🕸  Top Endpoint-Reachable Packages"
    TOP_REACHABLE_PACKAGES_SUMMARY = TOP_REACHABLE_PACKAGES + " " + SUMMARY
    TOP_REACHABLE_PACKAGES_DATA_COLUMNS = ["Package", "Reachable Flows"]
    TOP_REACHABLE_PACKAGES_DATA = TOP_REACHABLE_PACKAGES + " " + DATA

    SERVICE_ENDPOINTS = "Service Endpoints"
    ENDPOINTS = "Endpoints"
    ENDPOINTS_SUMMARY = ENDPOINTS + " " + SUMMARY
    ENDPOINTS_DATA_COLUMNS = ["URL Pattern", "HTTP Methods", "Code Hotspots"]
    ENDPOINTS_DATA = ENDPOINTS + " " + DATA
    IDENTIFIED_ENDPOINTS = "Identified Endpoints"

    REACHABLE_FLOWS = "Reachable Flows"
    REACHABLE_PACKAGES = "Reachable Packages"
    REACHABLE_FLOWS_SUMMARY = REACHABLE_FLOWS + " " + SUMMARY
    REACHABLE_FLOWS_DATA = REACHABLE_FLOWS + " " + DATA
    REACHABLE_FLOWS_DATA_COLUMNS = ["Summary", "Reachable Flows", "Reachable Packages"]
    REACHABLE_FLOWS_REACHABLE_PACKAGES = REACHABLE_FLOWS + " " + REACHABLE_PACKAGES

    SECURE_DESIGN_TIPS = "Secure Design Tips"
    MALWARE_ALERT = "Malware Alert"

    def __init__(
        self,
        report_output_path,
        input_vdr_json_path=None,
        input_rich_html_path=None,
        input_txt_path=None,
        raw_content=False,
    ):
        input_counter = 0

        if input_vdr_json_path is not None:
            input_counter += 1

        if input_rich_html_path is not None:
            input_counter += 1

        if input_txt_path is not None:
            input_counter += 1

        if input_counter != 1:
            raise ValueError(
                "At least and at most one between 'input_vdr_json_path', 'input_rich_html_path', 'input_txt_path' should be not None"
            )
        self.report_output_path = report_output_path
        self.input_vdr_json_path = input_vdr_json_path
        self.input_rich_html_path = input_rich_html_path
        self.input_txt_path = input_txt_path
        self.raw_content = raw_content

    def extract_depscan_reports_from_vdr_json(self):
        depscan_reports = set()
        with open(self.input_vdr_json_path, "r", encoding="utf-8") as file:
            data = json.load(file)
            if "annotations" not in data:
                return []
            for annotation in data["annotations"]:
                if "annotator" not in annotation or "text" not in annotation:
                    continue
                annotator = annotation["annotator"]
                if "component" not in annotator:
                    continue
                component = annotator["component"]
                if "name" not in component:
                    continue
                if component["name"] != "owasp-depscan":
                    continue
                depscan_reports.add(annotation["text"])

            return list(depscan_reports)

    def extract_depscan_report_from_rich_html(self):
        with open(self.input_rich_html_path, "r", encoding="utf-8") as file:
            data = file.read()

            styles = data.split("<style>", 1)[1].split("</style>", 1)[0]
            if "body {" in styles:
                styles = styles.split("body {", 1)[0]

            depscan_report = data.split("<body>", 1)[1].split("</body>", 1)[0]
            if depscan_report.strip().endswith("</code></pre>"):
                depscan_report = depscan_report.rsplit("</code></pre>", 1)[0]

            return depscan_report, styles

    def extract_depscan_report_from_txt(self):
        with open(self.input_txt_path, "r", encoding="utf-8") as file:
            data = file.read()
            return data

    def string_matches_span_pattern(self, text, pattern_content):
        pattern_content = pattern_content.replace("(", r"\(")
        pattern_content = pattern_content.replace(")", r"\)")

        pattern = rf'<span class="r\d\d?">[ \t]*{pattern_content}[ \t]*<\/span>'
        match = re.fullmatch(pattern, text)
        if match:
            return True
        else:  # try with additional empty spans around the one with the string, it may happen
            pattern = rf'<span class="r\d\d?">[ \t]*<\/span>{pattern}<span class="r\d\d?">[ \t]*<\/span>'
            match = re.fullmatch(pattern, text)
            if match:
                return True
            else:
                return False

    def string_matches_regex(self, text, pattern):
        match = re.fullmatch(pattern, text)
        if match:
            return True
        else:
            return False

    def array_matches_span_pattern(self, text_array, pattern_content_array):
        if len(text_array) != len(pattern_content_array):
            return False

        for idx in range(0, len(text_array)):
            if not self.string_matches_span_pattern(
                text_array[idx], pattern_content_array[idx]
            ):
                return False

        return True

    def parse_depscan_report(self, depscan_report):
        current_location = None
        current_table_row = None
        current_columns_count = None
        summary_column = ""
        reachable_flow_column = ""
        reachable_packages_column = ""

        sections_tree = {
            self.VULNERABILITY_DISCLOSURE_REPORT: {
                self.DEPENDENCY_SCAN_RESULTS_BOM: {
                    self.VULNERABILITIES_COUNT: "-1",
                    self.SUMMARY: "",
                    self.TABLE_HEADERS: [],
                    self.DATA: [],
                },
                self.RECOMMENDATION: "",
            },
            self.PRIORITIZED_VULNERABILITIES: {
                self.TOP_PRIORITY_BOM: {
                    self.PRIORITIZED_COUNT: "-1",
                    self.SUMMARY: "",
                    self.TABLE_HEADERS: [],
                    self.DATA: [],
                }
            },
            self.PROACTIVE_MEASURES: {
                self.TOP_REACHABLE_PACKAGES: {
                    self.SUMMARY: "",
                    self.TABLE_HEADERS: [],
                    self.DATA: [],
                }
            },
            self.SERVICE_ENDPOINTS: {
                self.ENDPOINTS: {
                    self.IDENTIFIED_ENDPOINTS: "-1",
                    self.SUMMARY: "",
                    self.TABLE_HEADERS: [],
                    self.DATA: [],
                }
            },
            self.REACHABLE_FLOWS: {self.SUMMARY: "", self.DATA: []},
            self.SECURE_DESIGN_TIPS: {self.SUMMARY: ""},
            self.MALWARE_ALERT: {self.SUMMARY: ""},
        }

        for line in depscan_report.splitlines():
            line = line.strip()

            # ---- Location identification: Vulnerability Disclosure Report ----

            if (
                line == self.VULNERABILITY_DISCLOSURE_REPORT
                or self.string_matches_span_pattern(
                    line, self.VULNERABILITY_DISCLOSURE_REPORT
                )
            ):
                current_location = self.DEPENDENCY_SCAN_RESULTS_BOM_SUMMARY
                continue

            if (
                line == self.DEPENDENCY_SCAN_RESULTS_BOM
                or self.string_matches_span_pattern(
                    line, self.DEPENDENCY_SCAN_RESULTS_BOM
                )
            ):
                current_location = self.DEPENDENCY_SCAN_RESULTS_BOM
                continue

            if (
                current_location == self.DEPENDENCY_SCAN_RESULTS_BOM
                and line.startswith("╔")
                and line.endswith("╗")
            ):
                current_location = self.DEPENDENCY_SCAN_RESULTS_BOM_DATA
                current_columns_count = len(line[1:-1].split("╤"))
                continue

            if (
                current_location == self.DEPENDENCY_SCAN_RESULTS_BOM_DATA
                and line.startswith("╚")
                and line.endswith("╝")
            ):
                current_location = self.DEPENDENCY_SCAN_RESULTS_BOM
                if len(current_table_row) == 0:  # should never happen:
                    continue

                cells = ["" for index in range(0, len(current_table_row[0]))]

                for row_piece in current_table_row:
                    for index, row_piece_column in enumerate(row_piece):
                        cells[index] += row_piece_column + "\n"

                sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
                    self.DEPENDENCY_SCAN_RESULTS_BOM
                ][self.DATA].append(cells)
                current_table_row = []

                continue

            if (
                current_location == self.DEPENDENCY_SCAN_RESULTS_BOM
                and line.startswith("╭")
                and line.endswith("╮")
                and "─ Recommendation ─" in line
            ):
                current_location = self.DEPENDENCY_SCAN_RESULTS_BOM_RECOMMENDATION
                continue

            if (
                current_location == self.DEPENDENCY_SCAN_RESULTS_BOM_RECOMMENDATION
                and line.startswith("╰")
                and line.endswith("╯")
            ):
                current_location = None
                continue

            # ---- Data population: Vulnerability Disclosure Report ----

            if current_location == self.DEPENDENCY_SCAN_RESULTS_BOM_SUMMARY:
                if (
                    sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
                        self.DEPENDENCY_SCAN_RESULTS_BOM
                    ][self.SUMMARY]
                    != ""
                ):
                    sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
                        self.DEPENDENCY_SCAN_RESULTS_BOM
                    ][self.SUMMARY] += "\n"
                sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
                    self.DEPENDENCY_SCAN_RESULTS_BOM
                ][self.SUMMARY] += line
                continue

            if current_location == self.DEPENDENCY_SCAN_RESULTS_BOM_DATA:
                if line.startswith("║") and line.endswith("║"):  # in table row
                    columns = line[1:-1].rsplit("│", maxsplit=current_columns_count - 1)

                    stripped_columns = [column.strip() for column in columns]
                    if (
                        stripped_columns
                        == self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS
                        or self.array_matches_span_pattern(
                            stripped_columns,
                            self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS,
                        )
                    ):
                        sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
                            self.DEPENDENCY_SCAN_RESULTS_BOM
                        ][self.TABLE_HEADERS] = stripped_columns
                        current_table_row = []
                        continue
                    else:
                        current_table_row.append(columns)

                elif line.startswith("╟") and line.endswith("╢"):  # row separator
                    if len(current_table_row) == 0:  # should never happen:
                        continue

                    cells = ["" for index in range(0, len(current_table_row[0]))]

                    for row_piece in current_table_row:
                        for index, row_piece_column in enumerate(row_piece):
                            cells[index] += row_piece_column + "\n"

                    sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
                        self.DEPENDENCY_SCAN_RESULTS_BOM
                    ][self.DATA].append(cells)
                    current_table_row = []

                continue

            if current_location == self.DEPENDENCY_SCAN_RESULTS_BOM and (
                line.startswith("Vulnerabilities count:")
                or self.string_matches_span_pattern(line, r"Vulnerabilities count: \d+")
            ):
                sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
                    self.DEPENDENCY_SCAN_RESULTS_BOM
                ][self.VULNERABILITIES_COUNT] = (
                    line.split("Vulnerabilities count:", 1)[1].split("<", 1)[0].strip()
                )
                continue

            if (
                current_location == self.DEPENDENCY_SCAN_RESULTS_BOM_RECOMMENDATION
                and line.startswith("│")
                and line.endswith("│")
            ):
                if (
                    sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
                        self.RECOMMENDATION
                    ]
                    != ""
                ):
                    sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
                        self.RECOMMENDATION
                    ] += "\n"
                sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
                    self.RECOMMENDATION
                ] += line[1:-1]
                continue

            # ---- Location identification: Proactive Measures ----

            if line == self.PROACTIVE_MEASURES or self.string_matches_span_pattern(
                line, self.PROACTIVE_MEASURES
            ):
                current_location = self.TOP_REACHABLE_PACKAGES_SUMMARY
                continue

            if (
                line
                in [
                    self.TOP_REACHABLE_PACKAGES,
                    self.TOP_REACHABLE_PACKAGES_ALTERNATIVE_01,
                    self.TOP_REACHABLE_PACKAGES_ALTERNATIVE_02,
                ]
                or self.string_matches_span_pattern(line, self.TOP_REACHABLE_PACKAGES)
                or self.string_matches_span_pattern(
                    line, self.TOP_REACHABLE_PACKAGES_ALTERNATIVE_01
                )
                or self.string_matches_span_pattern(
                    line, self.TOP_REACHABLE_PACKAGES_ALTERNATIVE_02
                )
            ):
                current_location = self.TOP_REACHABLE_PACKAGES
                continue

            if (
                current_location == self.TOP_REACHABLE_PACKAGES
                and line.startswith("╔")
                and line.endswith("╗")
            ):
                current_location = self.TOP_REACHABLE_PACKAGES_DATA
                current_columns_count = len(line[1:-1].split("╤"))
                continue

            if (
                current_location == self.TOP_REACHABLE_PACKAGES_DATA
                and line.startswith("╚")
                and line.endswith("╝")
            ):
                current_location = self.TOP_REACHABLE_PACKAGES
                if len(current_table_row) == 0:  # should never happen:
                    continue

                cells = ["" for index in range(0, len(current_table_row[0]))]

                for row_piece in current_table_row:
                    for index, row_piece_column in enumerate(row_piece):
                        cells[index] += row_piece_column + "\n"
                for index, cell in enumerate(cells): # dirty fix to eliminate the useless \n added at the end of each cell
                    cells[index] = cell[:-1]

                sections_tree[self.PROACTIVE_MEASURES][self.TOP_REACHABLE_PACKAGES][
                    self.DATA
                ].append(cells)
                current_table_row = []
                continue

            # ---- Data population: Proactive Measures ----

            if current_location == self.TOP_REACHABLE_PACKAGES_SUMMARY:
                if (
                    sections_tree[self.PROACTIVE_MEASURES][self.TOP_REACHABLE_PACKAGES][
                        self.SUMMARY
                    ]
                    != ""
                ):
                    sections_tree[self.PROACTIVE_MEASURES][self.TOP_REACHABLE_PACKAGES][
                        self.SUMMARY
                    ] += "\n"
                sections_tree[self.PROACTIVE_MEASURES][self.TOP_REACHABLE_PACKAGES][
                    self.SUMMARY
                ] += line
                continue

            if current_location == self.TOP_REACHABLE_PACKAGES_DATA:
                if line.startswith("║") and line.endswith("║"):  # in table row
                    columns = line[1:-1].rsplit("│", maxsplit=current_columns_count - 1)

                    stripped_columns = [column.strip() for column in columns]
                    if (
                        stripped_columns == self.TOP_REACHABLE_PACKAGES_DATA_COLUMNS
                        or self.array_matches_span_pattern(
                            stripped_columns, self.TOP_REACHABLE_PACKAGES_DATA_COLUMNS
                        )
                    ):
                        sections_tree[self.PROACTIVE_MEASURES][
                            self.TOP_REACHABLE_PACKAGES
                        ][self.TABLE_HEADERS] = stripped_columns
                        current_table_row = []
                        continue
                    else:
                        current_table_row.append(columns)

                elif line.startswith("╟") and line.endswith("╢"):  # row separator
                    if len(current_table_row) == 0:  # should never happen:
                        continue

                    cells = ["" for index in range(0, len(current_table_row[0]))]

                    for row_piece in current_table_row:
                        for index, row_piece_column in enumerate(row_piece):
                            cells[index] += row_piece_column + "\n"
                    for index, cell in enumerate(cells): # dirty fix to eliminate the useless \n added at the end of each cell
                        cells[index] = cell[:-1]

                    sections_tree[self.PROACTIVE_MEASURES][self.TOP_REACHABLE_PACKAGES][
                        self.DATA
                    ].append(cells)
                    current_table_row = []

                continue

            # ---- Location identification: Reachable Flows ----

            if line == self.REACHABLE_FLOWS or self.string_matches_span_pattern(
                line, self.REACHABLE_FLOWS
            ):
                current_location = self.REACHABLE_FLOWS_SUMMARY
                continue

            if (
                current_location == self.REACHABLE_FLOWS_SUMMARY
                and line == ""
                and sections_tree[self.REACHABLE_FLOWS][self.SUMMARY] != ""
            ):
                current_location = self.REACHABLE_FLOWS_DATA
                continue

            if (
                current_location == self.REACHABLE_FLOWS_REACHABLE_PACKAGES
                and line == ""
            ):
                cells = [
                    summary_column,
                    reachable_flow_column,
                    reachable_packages_column,
                ]
                sections_tree[self.REACHABLE_FLOWS][self.DATA].append(cells)
                summary_column = ""
                reachable_flow_column = ""
                reachable_packages_column = ""
                current_location = self.REACHABLE_FLOWS_DATA
                continue

            if current_location == self.REACHABLE_FLOWS_DATA and (
                line == "Reachable Packages:"
                or self.string_matches_span_pattern(line, r"Reachable Packages:")
            ):
                current_location = self.REACHABLE_FLOWS_REACHABLE_PACKAGES
                continue

            # ---- Data population: Reachable Flows ----

            if current_location == self.REACHABLE_FLOWS_SUMMARY:
                if sections_tree[self.REACHABLE_FLOWS][self.SUMMARY] != "":
                    sections_tree[self.REACHABLE_FLOWS][self.SUMMARY] += "\n"
                sections_tree[self.REACHABLE_FLOWS][self.SUMMARY] += line
                continue

            if current_location == self.REACHABLE_FLOWS_DATA:
                if line.startswith("#"):
                    summary_column = line.split(" ", 1)[1]
                    reachable_flow_column = ""
                    reachable_packages_column = ""
                    continue

                if self.string_matches_regex(
                    line,
                    r'<span class="r\d+">#\d+<\/span><span class="r\d+">.*<\/span>',
                ):
                    summary_column = "</span>".join(line.split("</span>")[1:])
                    reachable_flow_column = ""
                    reachable_packages_column = ""
                    continue

                if line.startswith("║") and line.endswith("║"):  # in table row
                    if reachable_flow_column != "":
                        reachable_flow_column += "\n"
                    reachable_flow_column += line[1:-1]
                    continue

            if current_location == self.REACHABLE_FLOWS_REACHABLE_PACKAGES:
                if reachable_packages_column != "":
                    reachable_packages_column += "\n"
                reachable_packages_column += line
                continue

            # ---- Location identification: Secure Design Tips ----

            if line == self.SECURE_DESIGN_TIPS or self.string_matches_span_pattern(
                line, self.SECURE_DESIGN_TIPS
            ):
                current_location = self.SECURE_DESIGN_TIPS
                continue

            # ---- Data population: Secure Design Tips ----

            if current_location == self.SECURE_DESIGN_TIPS:
                if sections_tree[self.SECURE_DESIGN_TIPS][self.SUMMARY] != "":
                    sections_tree[self.SECURE_DESIGN_TIPS][self.SUMMARY] += "\n"
                sections_tree[self.SECURE_DESIGN_TIPS][self.SUMMARY] += line
                continue

            # ---- Location identification: Malware Alert ----

            if line == self.MALWARE_ALERT or self.string_matches_span_pattern(
                line, self.MALWARE_ALERT
            ):
                current_location = self.MALWARE_ALERT
                continue

            if (
                current_location == self.MALWARE_ALERT
                and line == ""
                and sections_tree[self.MALWARE_ALERT][self.SUMMARY] != ""
            ):
                current_location = None
                continue

            # ---- Data population: Malware Alert ----

            if current_location == self.MALWARE_ALERT:
                if sections_tree[self.MALWARE_ALERT][self.SUMMARY] != "":
                    sections_tree[self.MALWARE_ALERT][self.SUMMARY] += "\n"
                sections_tree[self.MALWARE_ALERT][self.SUMMARY] += line
                continue

            # ---- Location identification: Service Endpoints ----

            if line == self.SERVICE_ENDPOINTS or self.string_matches_span_pattern(
                line, self.SERVICE_ENDPOINTS
            ):
                current_location = self.ENDPOINTS_SUMMARY
                continue

            if line == self.ENDPOINTS or self.string_matches_span_pattern(
                line, self.ENDPOINTS
            ):
                current_location = self.ENDPOINTS
                continue

            if (
                current_location == self.ENDPOINTS
                and line.startswith("╔")
                and line.endswith("╗")
            ):
                current_location = self.ENDPOINTS_DATA
                current_columns_count = len(line[1:-1].split("╤"))
                continue

            if (
                current_location == self.ENDPOINTS_DATA
                and line.startswith("╚")
                and line.endswith("╝")
            ):
                current_location = self.ENDPOINTS
                if len(current_table_row) == 0:  # should never happen:
                    continue

                cells = ["" for index in range(0, len(current_table_row[0]))]

                for row_piece in current_table_row:
                    for index, row_piece_column in enumerate(row_piece):
                        cells[index] += row_piece_column + "\n"

                sections_tree[self.SERVICE_ENDPOINTS][self.ENDPOINTS][self.DATA].append(
                    cells
                )
                current_table_row = []

                continue

            # ---- Data population: Service Endpoints ----

            if current_location == self.ENDPOINTS_SUMMARY:
                if (
                    sections_tree[self.SERVICE_ENDPOINTS][self.ENDPOINTS][self.SUMMARY]
                    != ""
                ):
                    sections_tree[self.SERVICE_ENDPOINTS][self.ENDPOINTS][
                        self.SUMMARY
                    ] += "\n"
                sections_tree[self.SERVICE_ENDPOINTS][self.ENDPOINTS][self.SUMMARY] += (
                    line
                )
                continue

            if current_location == self.ENDPOINTS_DATA:
                if line.startswith("║") and line.endswith("║"):  # in table row
                    columns = line[1:-1].rsplit("│", maxsplit=current_columns_count - 1)

                    stripped_columns = [column.strip() for column in columns]
                    if (
                        stripped_columns == self.ENDPOINTS_DATA_COLUMNS
                        or self.array_matches_span_pattern(
                            stripped_columns, self.ENDPOINTS_DATA_COLUMNS
                        )
                    ):
                        sections_tree[self.SERVICE_ENDPOINTS][self.ENDPOINTS][
                            self.TABLE_HEADERS
                        ] = stripped_columns
                        current_table_row = []
                        continue
                    else:
                        current_table_row.append(columns)

                elif line.startswith("╟") and line.endswith("╢"):  # row separator
                    if len(current_table_row) == 0:  # should never happen:
                        continue

                    cells = ["" for index in range(0, len(current_table_row[0]))]

                    for row_piece in current_table_row:
                        for index, row_piece_column in enumerate(row_piece):
                            cells[index] += row_piece_column + "\n"

                    sections_tree[self.SERVICE_ENDPOINTS][self.ENDPOINTS][
                        self.DATA
                    ].append(cells)
                    current_table_row = []

                continue

            if current_location == self.ENDPOINTS and (
                line.startswith("Identified Endpoints:")
                or self.string_matches_span_pattern(line, r"Identified Endpoints: \d+")
            ):
                sections_tree[self.SERVICE_ENDPOINTS][self.ENDPOINTS][
                    self.IDENTIFIED_ENDPOINTS
                ] = line.split("Identified Endpoints:", 1)[1].split("<", 1)[0].strip()
                current_location = None
                continue

            # ---- Location identification: Prioritized Vulnerabilities ----

            if (
                line == self.PRIORITIZED_VULNERABILITIES
                or self.string_matches_span_pattern(
                    line, self.PRIORITIZED_VULNERABILITIES
                )
            ):
                current_location = self.TOP_PRIORITY_BOM_SUMMARY
                continue

            if (
                line == self.PRIORITIZED_VULNERABILITIES_ALTERNATIVE
                or self.string_matches_span_pattern(
                    line, self.PRIORITIZED_VULNERABILITIES_ALTERNATIVE
                )
            ):
                current_location = self.TOP_PRIORITY_BOM_SUMMARY
                continue

            if line == self.TOP_PRIORITY_BOM or self.string_matches_span_pattern(
                line, self.TOP_PRIORITY_BOM
            ):
                current_location = self.TOP_PRIORITY_BOM
                continue

            if (
                current_location == self.TOP_PRIORITY_BOM
                and line.startswith("╔")
                and line.endswith("╗")
            ):
                current_location = self.TOP_PRIORITY_BOM_DATA
                current_columns_count = len(line[1:-1].split("╤"))
                continue

            if (
                current_location == self.TOP_PRIORITY_BOM_DATA
                and line.startswith("╚")
                and line.endswith("╝")
            ):
                current_location = self.TOP_PRIORITY_BOM
                if len(current_table_row) == 0:  # should never happen:
                    continue

                cells = ["" for index in range(0, len(current_table_row[0]))]

                for row_piece in current_table_row:
                    for index, row_piece_column in enumerate(row_piece):
                        cells[index] += row_piece_column + "\n"
                for index, cell in enumerate(cells): # dirty fix to eliminate the useless \n added at the end of each cell
                    cells[index] = cell[:-1]

                sections_tree[self.PRIORITIZED_VULNERABILITIES][self.TOP_PRIORITY_BOM][
                    self.DATA
                ].append(cells)
                current_table_row = []
                continue

            # ---- Data population: Prioritized Vulnerabilities ----

            if current_location == self.TOP_PRIORITY_BOM_SUMMARY:
                if (
                    sections_tree[self.PRIORITIZED_VULNERABILITIES][
                        self.TOP_PRIORITY_BOM
                    ][self.SUMMARY]
                    != ""
                ):
                    sections_tree[self.PRIORITIZED_VULNERABILITIES][
                        self.TOP_PRIORITY_BOM
                    ][self.SUMMARY] += "\n"
                sections_tree[self.PRIORITIZED_VULNERABILITIES][self.TOP_PRIORITY_BOM][
                    self.SUMMARY
                ] += line
                continue

            if current_location == self.TOP_PRIORITY_BOM_DATA:
                if line.startswith("║") and line.endswith("║"):  # in table row
                    columns = line[1:-1].rsplit("│", maxsplit=current_columns_count - 1)

                    stripped_columns = [column.strip() for column in columns]
                    if (
                        stripped_columns == self.TOP_PRIORITY_BOM_DATA_COLUMNS
                        or self.array_matches_span_pattern(
                            stripped_columns, self.TOP_PRIORITY_BOM_DATA_COLUMNS
                        )
                    ):
                        sections_tree[self.PRIORITIZED_VULNERABILITIES][
                            self.TOP_PRIORITY_BOM
                        ][self.TABLE_HEADERS] = stripped_columns
                        current_table_row = []
                        continue
                    else:
                        current_table_row.append(columns)

                elif line.startswith("╟") and line.endswith("╢"):  # row separator
                    if len(current_table_row) == 0:  # should never happen:
                        continue

                    cells = ["" for index in range(0, len(current_table_row[0]))]

                    for row_piece in current_table_row:
                        for index, row_piece_column in enumerate(row_piece):
                            cells[index] += row_piece_column + "\n"
                    for index, cell in enumerate(cells): # dirty fix to eliminate the useless \n added at the end of each cell
                        cells[index] = cell[:-1]

                    sections_tree[self.PRIORITIZED_VULNERABILITIES][
                        self.TOP_PRIORITY_BOM
                    ][self.DATA].append(cells)
                    current_table_row = []

                continue

            if (
                current_location == self.TOP_PRIORITY_BOM
                and line.startswith("Prioritized count:")
                or self.string_matches_span_pattern(line, r"Prioritized count: \d+")
            ):
                sections_tree[self.PRIORITIZED_VULNERABILITIES][self.TOP_PRIORITY_BOM][
                    self.PRIORITIZED_COUNT
                ] = line.split("Prioritized count:", 1)[1]
                current_location = None
                continue

        return sections_tree

    def format_as_html_ul(self, input_string):
        formatted_content = ["<ul>"]

        for content_element in input_string.strip().splitlines():
            content_element = content_element.strip()
            if content_element.startswith("•"):
                content_element = content_element[1:]
            elif " • " in content_element:
                content_element = content_element.replace(" • ", "")
            formatted_content.append(f"<li>{content_element}</li>")

        formatted_content.append("</ul>")

        return "\n".join(formatted_content)

    def generate_section_prioritized_vulnerabilities(
        self, sections_tree, report_content, table_inits, tree_is_from_html
    ):
        prioritized_vulnerabilities = PRIORITIZED_VULNERABILITIES
        current_content = sections_tree[self.PRIORITIZED_VULNERABILITIES][
            self.TOP_PRIORITY_BOM
        ][self.PRIORITIZED_COUNT]
        if tree_is_from_html is False:
            current_content = html.escape(current_content)

        try:
            prioritized_count = int(current_content)
        except ValueError:
            prioritized_count = -1
            pass
        if prioritized_count == -1:
            all_cves = set()
            for row_data in sections_tree[self.PRIORITIZED_VULNERABILITIES][self.TOP_PRIORITY_BOM][self.DATA]:
                current_data = row_data[
                                self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Prioritized CVEs")
                            ] if len(row_data) >= self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Prioritized CVEs")+1 else "-"
                if current_data == "-":
                    continue
                for data_element in current_data.strip().splitlines():
                    all_cves.add(data_element)
            current_content = f"{len(all_cves)}"

        prioritized_vulnerabilities = prioritized_vulnerabilities.replace(
            "<PRIORITIZED_COUNT_PLACEHOLDER>", current_content, 1
        )

        current_content = sections_tree[self.PRIORITIZED_VULNERABILITIES][
            self.TOP_PRIORITY_BOM
        ][self.SUMMARY]
        if tree_is_from_html is False:
            current_content = html.escape(current_content)
        prioritized_vulnerabilities = prioritized_vulnerabilities.replace(
            "<SUMMARY_PLACEHOLDER>", current_content, 1
        )

        html_table = []
        for row_data in sections_tree[self.PRIORITIZED_VULNERABILITIES][
            self.TOP_PRIORITY_BOM
        ][self.DATA]:
            if self.raw_content:
                html_row = ["<tr>"]

                current_content = row_data[
                    self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Package")
                ] if len(row_data) >= self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Package")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                current_content = row_data[
                    self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Prioritized CVEs")
                ] if len(row_data) >= self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Prioritized CVEs")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                current_content = row_data[
                    self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Fix Version")
                ] if len(row_data) >= self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Fix Version")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                current_content = row_data[
                    self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Next Steps")
                ] if len(row_data) >= self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Next Steps")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                html_row.append("</tr>")

                html_table.append("\n".join(html_row))
            else:
                html_row = ["<tr>"]

                current_content = row_data[
                    self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Package")
                ] if len(row_data) >= self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Package")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td>{current_content}</td>")

                current_content = row_data[
                    self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Prioritized CVEs")
                ] if len(row_data) >= self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Prioritized CVEs")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                cves = []
                for content_element in current_content.strip().splitlines():
                    cves.append(
                        f'<span class="badge bg-secondary">{content_element}</span>'
                    )
                html_row.append(f"<td>{'<br>'.join(cves)}</td>")

                current_content = row_data[
                    self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Fix Version")
                ] if len(row_data) >= self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Fix Version")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td>{current_content}</td>")

                current_content = row_data[
                    self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Next Steps")
                ] if len(row_data) >= self.TOP_PRIORITY_BOM_DATA_COLUMNS.index("Next Steps")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td>{current_content.replace(NEWLINE, '<br>')}</td>")

                html_row.append("</tr>")

                html_table.append("\n".join(html_row))

        prioritized_vulnerabilities = prioritized_vulnerabilities.replace(
            "<TABLE_PLACEHOLDER>", "\n".join(html_table), 1
        )

        report_content.append(prioritized_vulnerabilities)
        table_inits.append('initTable("#prioritized-vulnerabilities-table");')

    def generate_section_vulnerability_disclosure_report(
        self, sections_tree, report_content, table_inits, tree_is_from_html
    ):
        vulnerability_disclosure_report = VDR

        current_content = sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
            self.DEPENDENCY_SCAN_RESULTS_BOM
        ][self.VULNERABILITIES_COUNT]
        if tree_is_from_html is False:
            current_content = html.escape(current_content)

        try:
            vulnerabilities_count = int(current_content)
        except ValueError:
            vulnerabilities_count = -1
            pass
        if vulnerabilities_count == -1:
            all_cves = set()
            for row_data in sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][self.DEPENDENCY_SCAN_RESULTS_BOM][self.DATA]:
                current_data = row_data[
                    self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index(
                        "Dependency Tree"
                    )] if len(row_data) >= self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Dependency Tree")+1 else "-"
                if current_data == "-":
                    continue
                for data_element in current_data.strip().splitlines():
                    if "⬅" in data_element:
                        all_cves.add(data_element)
            current_content = f"{len(all_cves)}"

        vulnerability_disclosure_report = vulnerability_disclosure_report.replace(
            "<VULNERABILITIES_COUNT_PLACEHOLDER>", current_content, 1
        )

        current_content = sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
            self.DEPENDENCY_SCAN_RESULTS_BOM
        ][self.SUMMARY]
        if tree_is_from_html is False:
            current_content = html.escape(current_content)

        if current_content == "":
            current_content = "The table below lists all vulnerabilities identified in this project. Review and triage the information to identify any critical vulnerabilities."
        vulnerability_disclosure_report = vulnerability_disclosure_report.replace(
            "<SUMMARY_PLACEHOLDER>", current_content, 1
        )

        if (
            sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][self.RECOMMENDATION]
            != ""
        ):
            current_content = sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
                self.RECOMMENDATION
            ]
            if tree_is_from_html is False:
                current_content = html.escape(current_content)
            current_content = current_content.replace("\n", "<br>")
            current_content = f"""
        <br><br>
            <div class="alert alert-info" role="alert">
            <h4>Recommendation</h4>
            <br>
            <span>{current_content}</span>
            </div>"""
            vulnerability_disclosure_report = vulnerability_disclosure_report.replace(
                "<RECOMMENDATION_PLACEHOLDER>", current_content, 1
            )

        html_table = []
        for row_data in sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
            self.DEPENDENCY_SCAN_RESULTS_BOM
        ][self.DATA]:
            if self.raw_content:
                html_row = ["<tr>"]

                current_content = row_data[
                    self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index(
                        "Dependency Tree"
                    )
                ] if len(row_data) >= self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Dependency Tree")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                current_content = row_data[
                    self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Insights")
                ] if len(row_data) >= self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Insights")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                current_content = row_data[
                    self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Fix Version")
                ] if len(row_data) >= self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Fix Version")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                current_content = row_data[
                    self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Severity")
                ] if len(row_data) >= self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Severity")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                current_content = row_data[
                    self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Score")
                ] if len(row_data) >= self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Score")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                html_row.append("</tr>")

                html_table.append("\n".join(html_row))
            else:
                html_row = ["<tr>"]

                current_content = row_data[
                    self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index(
                        "Dependency Tree"
                    )
                ] if len(row_data) >= self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Dependency Tree")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                current_content = row_data[
                    self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Insights")
                ] if len(row_data) >= self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Insights")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                current_content = row_data[
                    self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Fix Version")
                ] if len(row_data) >= self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Fix Version")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                current_content = row_data[
                    self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Severity")
                ] if len(row_data) >= self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Severity")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                current_content = row_data[
                    self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Score")
                ] if len(row_data) >= self.DEPENDENCY_SCAN_RESULTS_BOM_DATA_COLUMNS.index("Score")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                html_row.append("</tr>")

                html_table.append("\n".join(html_row))

        vulnerability_disclosure_report = vulnerability_disclosure_report.replace(
            "<TABLE_PLACEHOLDER>", "\n".join(html_table), 1
        )

        report_content.append(vulnerability_disclosure_report)
        table_inits.append('initTable("#vulnerability-disclosure-report-table");')

    def generate_section_proactive_measures(
        self, sections_tree, report_content, table_inits, tree_is_from_html
    ):
        proactive_measures = PROACTIVE_MEASURES

        current_content = sections_tree[self.PROACTIVE_MEASURES][
            self.TOP_REACHABLE_PACKAGES
        ][self.SUMMARY]
        if tree_is_from_html is False:
            current_content = html.escape(current_content)
        proactive_measures = proactive_measures.replace(
            "<SUMMARY_PLACEHOLDER>", current_content, 1
        )

        html_table = []
        for row_data in sections_tree[self.PROACTIVE_MEASURES][
            self.TOP_REACHABLE_PACKAGES
        ][self.DATA]:
            if self.raw_content:
                html_row = ["<tr>"]

                current_content = row_data[
                    self.TOP_REACHABLE_PACKAGES_DATA_COLUMNS.index("Package")
                ] if len(row_data) >= self.TOP_REACHABLE_PACKAGES_DATA_COLUMNS.index("Package")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                current_content = row_data[
                    self.TOP_REACHABLE_PACKAGES_DATA_COLUMNS.index("Reachable Flows")
                ] if len(row_data) >= self.TOP_REACHABLE_PACKAGES_DATA_COLUMNS.index("Reachable Flows")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                html_row.append("</tr>")

                html_table.append("\n".join(html_row))

            else:
                html_row = ["<tr>"]

                current_content = row_data[
                    self.TOP_REACHABLE_PACKAGES_DATA_COLUMNS.index("Package")
                ] if len(row_data) >= self.TOP_REACHABLE_PACKAGES_DATA_COLUMNS.index("Package")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td>{current_content}</td>")
                reachable_flows_index = self.TOP_REACHABLE_PACKAGES_DATA_COLUMNS.index(
                    "Reachable Flows"
                )
                current_content = row_data[
                    self.TOP_REACHABLE_PACKAGES_DATA_COLUMNS.index("Reachable Flows")
                ] if len(row_data) >= self.TOP_REACHABLE_PACKAGES_DATA_COLUMNS.index("Reachable Flows")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                if current_content:
                    html_row.append(f"<td>{current_content}</td>")

                html_row.append("</tr>")

                html_table.append("\n".join(html_row))

        proactive_measures = proactive_measures.replace(
            "<TABLE_PLACEHOLDER>", "\n".join(html_table), 1
        )

        report_content.append(proactive_measures)
        table_inits.append('initTable("#proactive-measures-table");')

    def generate_section_service_endpoints(
        self, sections_tree, report_content, table_inits, tree_is_from_html
    ):
        service_endpoints = SERVICE_ENDPOINTS

        current_content = sections_tree[self.SERVICE_ENDPOINTS][self.ENDPOINTS][
            self.IDENTIFIED_ENDPOINTS
        ]
        if tree_is_from_html is False:
            current_content = html.escape(current_content)

        try:
            identified_endpoints = int(current_content)
        except ValueError:
            identified_endpoints = -1
            pass
        if identified_endpoints == -1:
            current_content = f"{len(sections_tree[self.SERVICE_ENDPOINTS][self.ENDPOINTS][self.DATA])}"


        service_endpoints = service_endpoints.replace(
            "<IDENTIFIED_ENDPOINTS_PLACEHOLDER>", current_content, 1
        )

        current_content = sections_tree[self.SERVICE_ENDPOINTS][self.ENDPOINTS][
            self.SUMMARY
        ]
        if tree_is_from_html is False:
            current_content = html.escape(current_content)
        service_endpoints = service_endpoints.replace(
            "<SUMMARY_PLACEHOLDER>", current_content, 1
        )

        html_table = []
        for row_data in sections_tree[self.SERVICE_ENDPOINTS][self.ENDPOINTS][
            self.DATA
        ]:
            if self.raw_content:
                html_row = ["<tr>"]

                current_content = row_data[
                    self.ENDPOINTS_DATA_COLUMNS.index("URL Pattern")
                ] if len(row_data) >= self.ENDPOINTS_DATA_COLUMNS.index("URL Pattern")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                current_content = row_data[
                    self.ENDPOINTS_DATA_COLUMNS.index("HTTP Methods")
                ] if len(row_data) >= self.ENDPOINTS_DATA_COLUMNS.index("HTTP Methods")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                current_content = row_data[
                    self.ENDPOINTS_DATA_COLUMNS.index("Code Hotspots")
                ] if len(row_data) >= self.ENDPOINTS_DATA_COLUMNS.index("Code Hotspots")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td><pre>{current_content}</pre></td>")

                html_row.append("</tr>")

                html_table.append("\n".join(html_row))
            else:
                html_row = ["<tr>"]

                current_content = row_data[
                    self.ENDPOINTS_DATA_COLUMNS.index("URL Pattern")
                ] if len(row_data) >= self.ENDPOINTS_DATA_COLUMNS.index("URL Pattern")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td>{current_content}</td>")

                current_content = row_data[
                    self.ENDPOINTS_DATA_COLUMNS.index("HTTP Methods")
                ] if len(row_data) >= self.ENDPOINTS_DATA_COLUMNS.index("HTTP Methods")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                current_content = current_content.replace("\n", "<br>")
                html_row.append(f"<td>{current_content}</td>")

                current_content = row_data[
                    self.ENDPOINTS_DATA_COLUMNS.index("Code Hotspots")
                ] if len(row_data) >= self.ENDPOINTS_DATA_COLUMNS.index("Code Hotspots")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                current_content = current_content.replace("\n", "<br>")
                html_row.append(f"<td>{current_content}</td>")

                html_row.append("</tr>")

                html_table.append("\n".join(html_row))

        service_endpoints = service_endpoints.replace(
            "<TABLE_PLACEHOLDER>", "\n".join(html_table), 1
        )

        report_content.append(service_endpoints)
        table_inits.append('initTable("#service-endpoints-table");')

    def generate_section_reachable_flows(
        self, sections_tree, report_content, table_inits, tree_is_from_html
    ):
        reachable_flows = REACHABLE_FLOWS

        current_content = sections_tree[self.REACHABLE_FLOWS][self.SUMMARY]
        if tree_is_from_html is False:
            current_content = html.escape(current_content)
        reachable_flows = reachable_flows.replace(
            "<SUMMARY_PLACEHOLDER>", current_content, 1
        )

        html_table = []
        for row_data in sections_tree[self.REACHABLE_FLOWS][self.DATA]:
            if self.raw_content:
                html_row = ["<tr>"]

                current_content = row_data[
                    self.REACHABLE_FLOWS_DATA_COLUMNS.index("Summary")
                ] if len(row_data) >= self.REACHABLE_FLOWS_DATA_COLUMNS.index("Summary")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(
                    f'<td><pre class="breakable">{current_content}</pre></td>'
                )

                current_content = row_data[
                    self.REACHABLE_FLOWS_DATA_COLUMNS.index("Reachable Flows")
                ] if len(row_data) >= self.REACHABLE_FLOWS_DATA_COLUMNS.index("Reachable Flows")+1 else "-"
                current_content = "\n".join(
                    line.rstrip() for line in current_content.splitlines()
                )
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(
                    f'<td><pre class="breakable">{current_content}</pre></td>'
                )

                current_content = row_data[
                    self.REACHABLE_FLOWS_DATA_COLUMNS.index("Reachable Packages")
                ] if len(row_data) >= self.REACHABLE_FLOWS_DATA_COLUMNS.index("Reachable Packages")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(
                    f'<td><pre class="breakable">{current_content}</pre></td>'
                )

                html_row.append("</tr>")

                html_table.append("\n".join(html_row))

            else:
                html_row = ["<tr>"]

                current_content = row_data[
                    self.REACHABLE_FLOWS_DATA_COLUMNS.index("Summary")
                ] if len(row_data) >= self.REACHABLE_FLOWS_DATA_COLUMNS.index("Summary")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(f"<td>{current_content}</td>")

                current_content = row_data[
                    self.REACHABLE_FLOWS_DATA_COLUMNS.index("Reachable Flows")
                ] if len(row_data) >= self.REACHABLE_FLOWS_DATA_COLUMNS.index("Reachable Flows")+1 else "-"
                current_content = "\n".join(
                    line.rstrip() for line in current_content.splitlines()
                )
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                html_row.append(
                    f'<td><pre class="breakable">{current_content}</pre></td>'
                )

                current_content = row_data[
                    self.REACHABLE_FLOWS_DATA_COLUMNS.index("Reachable Packages")
                ] if len(row_data) >= self.REACHABLE_FLOWS_DATA_COLUMNS.index("Reachable Packages")+1 else "-"
                if tree_is_from_html is False:
                    current_content = html.escape(current_content)
                formatted_content = self.format_as_html_ul(current_content)
                html_row.append(f"<td>{formatted_content}</td>")

                html_row.append("</tr>")

                html_table.append("\n".join(html_row))

        reachable_flows = reachable_flows.replace(
            "<TABLE_PLACEHOLDER>", "\n".join(html_table), 1
        )

        report_content.append(reachable_flows)
        table_inits.append('initTable("#reachable-flows-table");')

    def generate_section_secure_design_tips(
        self, sections_tree, report_content, table_inits, tree_is_from_html
    ):
        secure_design_tips = SECURE_DESIGN_TIPS

        current_content = sections_tree[self.SECURE_DESIGN_TIPS][self.SUMMARY]
        if tree_is_from_html is False:
            current_content = html.escape(current_content)

        if self.raw_content:
            secure_design_tips = secure_design_tips.replace(
                "<SUMMARY_PLACEHOLDER>", f"<pre>{current_content}</pre>", 1
            )
        else:
            formatted_content = self.format_as_html_ul(current_content)

            secure_design_tips = secure_design_tips.replace(
                "<SUMMARY_PLACEHOLDER>", formatted_content, 1
            )

        report_content.append(secure_design_tips)

    def generate_section_malware_alert(
        self, sections_tree, report_content, table_inits, tree_is_from_html
    ):
        malware_alert = MALWARE_ALERT

        current_content = sections_tree[self.MALWARE_ALERT][self.SUMMARY]
        if tree_is_from_html is False:
            current_content = html.escape(current_content)

        if self.raw_content:
            malware_alert = malware_alert.replace(
                "<SUMMARY_PLACEHOLDER>", f"<pre>{current_content}</pre>", 1
            )
        else:
            malware_alert = malware_alert.replace(
                "<SUMMARY_PLACEHOLDER>",
                current_content.strip().replace("\n", "<br>"),
                1,
            )

        report_content.append(malware_alert)

    def generate_html(self, sections_tree, tree_is_from_html, styles=""):
        main_report = HTML_REPORT

        main_report = main_report.replace("<ADDITIONAL_STYLES_PLACEHOLDER>", styles)

        report_content = []
        table_inits = []

        # if a summary is populated it means that the corresponding section was in the original data, so we put it also in the html report

        if sections_tree[self.MALWARE_ALERT][self.SUMMARY] != "":
            self.generate_section_malware_alert(
                sections_tree, report_content, table_inits, tree_is_from_html
            )

        if (
            sections_tree[self.PRIORITIZED_VULNERABILITIES][self.TOP_PRIORITY_BOM][
                self.SUMMARY
            ]
            != ""
        ):
            self.generate_section_prioritized_vulnerabilities(
                sections_tree, report_content, table_inits, tree_is_from_html
            )

        if (
            sections_tree[self.PROACTIVE_MEASURES][self.TOP_REACHABLE_PACKAGES][
                self.SUMMARY
            ]
            != ""
        ):
            self.generate_section_proactive_measures(
                sections_tree, report_content, table_inits, tree_is_from_html
            )

        if (
            sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][
                self.DEPENDENCY_SCAN_RESULTS_BOM
            ][self.SUMMARY]
            != ""
        ) or len(sections_tree[self.VULNERABILITY_DISCLOSURE_REPORT][self.DEPENDENCY_SCAN_RESULTS_BOM][self.DATA]) > 0:
            self.generate_section_vulnerability_disclosure_report(
                sections_tree, report_content, table_inits, tree_is_from_html
            )

        if sections_tree[self.SERVICE_ENDPOINTS][self.ENDPOINTS][self.SUMMARY] != "":
            self.generate_section_service_endpoints(
                sections_tree, report_content, table_inits, tree_is_from_html
            )

        if sections_tree[self.REACHABLE_FLOWS][self.SUMMARY] != "":
            self.generate_section_reachable_flows(
                sections_tree, report_content, table_inits, tree_is_from_html
            )

        if sections_tree[self.SECURE_DESIGN_TIPS][self.SUMMARY] != "":
            self.generate_section_secure_design_tips(
                sections_tree, report_content, table_inits, tree_is_from_html
            )

        main_report = main_report.replace(
            "<CONTENT_PLACEHOLDER>", "\n<p>&nbsp;</p>".join(report_content), 1
        )
        main_report = main_report.replace(
            "<INIT_TABLE_PLACEHOLDER>", "\n".join(table_inits), 1
        )

        with open(self.report_output_path, "w", encoding="utf-8") as f:
            f.write(main_report)

    def parse_and_generate_report(self):
        if self.input_vdr_json_path is not None:
            depscan_reports = self.extract_depscan_reports_from_vdr_json()
            for depscan_report in depscan_reports:
                sections_tree = self.parse_depscan_report(depscan_report)
                self.generate_html(sections_tree=sections_tree, tree_is_from_html=False)
                break  # we assume the VDR JSON file contains at most one Depscan report
            return

        if self.input_rich_html_path is not None:
            depscan_report, styles = self.extract_depscan_report_from_rich_html()
            sections_tree = self.parse_depscan_report(depscan_report)
            self.generate_html(
                sections_tree=sections_tree, tree_is_from_html=True, styles=styles
            )
            return

        if self.input_txt_path is not None:
            depscan_report = self.extract_depscan_report_from_txt()
            sections_tree = self.parse_depscan_report(depscan_report)
            self.generate_html(sections_tree=sections_tree, tree_is_from_html=False)
            return
