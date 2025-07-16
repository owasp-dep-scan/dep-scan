MALWARE_ALERT = """
<div class="alert alert-danger" role="alert">
    <h4><PIECE_ID_PLACEHOLDER>Malware Alert</h4> <br>
<span><SUMMARY_PLACEHOLDER></span>
</div>
"""

RECOMMENDATION = """
<div class="alert alert-info" role="alert">
    <h4><PIECE_ID_PLACEHOLDER>Recommendation</h4> <br>
<span><SUMMARY_PLACEHOLDER></span>
</div>
"""

INFO = """
<div class="alert alert-info" role="alert">
    <h4><PIECE_ID_PLACEHOLDER>Info</h4> <br>
<span><SUMMARY_PLACEHOLDER></span>
</div>
"""

PRIORITIZED_VULNERABILITIES = """
<h3 class="light-text"><code class="code-title"><PIECE_ID_PLACEHOLDER>Prioritized Vulnerabilities</code></h3>
<div class="box-container">
    <br>
   <h4>Top Priority (BOM)</h4>
   <span class="badge border border-dark text-dark fs-6">Prioritized count: <PRIORITIZED_COUNT_PLACEHOLDER></span><br><br>
   <span><SUMMARY_PLACEHOLDER></span>
    <div>
        <table id="<TABLE_ID_PLACEHOLDER>" class="table table-striped table-bordered"><thead>
            <tr>
                <th>Package</th>
                <th>Prioritized CVEs</th>
                <th>Fix Version</th>
                <th>Next Steps</th>
            </tr>
            <tr>
                <th><input type="text" placeholder="Search Package" class="form-control search-in-table-comp"></th>
                <th><input type="text" placeholder="Search Prioritized CVEs" class="form-control search-in-table-comp"></th>
                <th><input type="text" placeholder="Search Fix Version" class="form-control search-in-table-comp"></th>
                <th><input type="text" placeholder="Search Next Steps" class="form-control search-in-table-comp"></th>
            </tr>
        </thead>
            <tbody>
                <TABLE_PLACEHOLDER>
            </tbody>
        </table>
    </div>
</div>
"""

PROACTIVE_MEASURES = """
<h3 class="light-text"><code class="code-title"><PIECE_ID_PLACEHOLDER>Proactive Measures</code></h3>
<div class="box-container">
    <br>
   <h4>Top Reachable Packages</h4><br>
   <span><SUMMARY_PLACEHOLDER></span>
    <div id="table-container-inner">
        <table id="<TABLE_ID_PLACEHOLDER>" class="table table-striped table-bordered"><thead>
            <tr>
                <th>Package</th>
                <th>Reachable Flows</th>
            </tr>
            <tr>
                <th><input type="text" placeholder="Search Package" class="form-control search-in-table-comp"></th>
                <th><input type="text" placeholder="Search Reachable Flows" class="form-control search-in-table-comp"></th>
            </tr>
        </thead>
            <tbody>
                <TABLE_PLACEHOLDER>
            </tbody>
        </table>
    </div>
</div>
"""

REACHABLE_FLOWS = """
<h3 class="light-text"><code class="code-title"><PIECE_ID_PLACEHOLDER>Reachable Flows</code></h3>
<div class="box-container">
   <br>
   <span><SUMMARY_PLACEHOLDER></span>
    <div>
        <table id="<TABLE_ID_PLACEHOLDER>" class="table table-striped table-bordered"><thead>
            <tr>
                <th width=15%>Summary</th>
                <th>Flows</th>
                <th width=15%>Reachable Packages</th>
            </tr>
            <tr>
                <th><input type="text" placeholder="Search Summary" class="form-control search-in-table-comp"></th>
                <th><input type="text" placeholder="Search Flows" class="form-control search-in-table-comp"></th>
                <th><input type="text" placeholder="Search Reachable Packages" class="form-control search-in-table-comp"></th>
            </tr>
        </thead>
            <tbody>
                <TABLE_PLACEHOLDER>
            </tbody>
        </table>
    </div>
</div>
"""

NON_REACHABLE_FLOWS = """
<h3 class="light-text"><code class="code-title"><PIECE_ID_PLACEHOLDER>Non-Reachable Flows</code></h3>
<div class="box-container">
   <br>
   <span><SUMMARY_PLACEHOLDER></span>
    <div>
        <table id="<TABLE_ID_PLACEHOLDER>" class="table table-striped table-bordered"><thead>
            <tr>
                <th width=15%>Summary</th>
                <th>Flows</th>
                <th width=15%>Reachable Packages</th>
            </tr>
            <tr>
                <th><input type="text" placeholder="Search Summary" class="form-control search-in-table-comp"></th>
                <th><input type="text" placeholder="Search Flows" class="form-control search-in-table-comp"></th>
                <th><input type="text" placeholder="Search Reachable Packages" class="form-control search-in-table-comp"></th>
            </tr>
        </thead>
            <tbody>
                <TABLE_PLACEHOLDER>
            </tbody>
        </table>
    </div>
</div>
"""

SECURE_DESIGN_TIPS = """
<h3  class="light-text"><code class="code-title"><PIECE_ID_PLACEHOLDER>Secure Design Tips</code></h3>
<div class="box-container">
   <br>
   <SUMMARY_PLACEHOLDER>
</div>
"""

SERVICE_ENDPOINTS = """
<h3  class="light-text"><code class="code-title"><PIECE_ID_PLACEHOLDER>Service Endpoints</code></h3>
<div class="box-container">
   <br>
   <h4>Endpoints</h4>
   <span class="badge border border-dark text-dark fs-6">Identified Endpoints: <IDENTIFIED_ENDPOINTS_PLACEHOLDER></span>
   <br><br>
   <span><SUMMARY_PLACEHOLDER></span>
    <div>
        <table id="<TABLE_ID_PLACEHOLDER>" class="table table-striped table-bordered"><thead>
            <tr>
                <th>URL Pattern</th>
                <th>HTTP Methods</th>
                <th>Code Hotspots</th>
            </tr>
            <tr>
                <th><input type="text" placeholder="Search URL Pattern" class="form-control search-in-table-comp"></th>
                <th><input type="text" placeholder="Search HTTP Methods" class="form-control search-in-table-comp"></th>
                <th><input type="text" placeholder="Search Code Hotspots" class="form-control search-in-table-comp"></th>
            </tr>
        </thead>
            <tbody>
                <TABLE_PLACEHOLDER>
            </tbody>
        </table>
    </div>
</div>
"""

VDR = """
<h3  class="light-text"><code class="code-title"><PIECE_ID_PLACEHOLDER>Vulnerability Disclosure Report</code></h3>
<div class="box-container">
    <br>
   <h4>Dependency Scan Results (BOM)</h4>
   <br>
   <span class="badge border border-dark text-dark fs-6">Vulnerabilities count: <VULNERABILITIES_COUNT_PLACEHOLDER></span>
   <br><br>
   <span><SUMMARY_PLACEHOLDER></span>
    <div>
        <table id="<TABLE_ID_PLACEHOLDER>" class="table table-striped table-bordered"><thead>
            <tr>
                <th>Dependency Tree</th>
                <th>Insights</th>
                <th>Fix Version</th>
                <th>Severity</th>
                <th>Score</th>
            </tr>
            <tr>
                <th><input type="text" placeholder="Search Dependency Tree" class="form-control search-in-table-comp"></th>
                <th><input type="text" placeholder="Search Insights" class="form-control search-in-table-comp"></th>
                <th><input type="text" placeholder="Search Fix Version" class="form-control search-in-table-comp"></th>
                <th><input type="text" placeholder="Search Severity" class="form-control search-in-table-comp"></th>
                <th><input type="text" placeholder="Search Score" class="form-control search-in-table-comp"></th>
            </tr>
        </thead>
            <tbody>
                <TABLE_PLACEHOLDER>
            </tbody>
    </table>
    </div>
    <RECOMMENDATION_PLACEHOLDER>
    <ACTION_REQUIRED_PLACEHOLDER>
</div>
"""

HTML_REPORT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Depscan Report</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css">
    <script src="https://code.jquery.com/jquery-3.7.1.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.print.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>

    <script src="https://fastly.jsdelivr.net/npm/echarts@5.5.1/dist/echarts.min.js"></script>

    <style>
        body {
            margin: 20px;
            height: 100vh;
            background: linear-gradient(to right, #16448f, #6e3cab);
            font-family: sans-serif;
            font-size: 90%;
        }

        .box-container {
            background-color: #ffffff;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            position: relative;
        }

        #table-container {
            background-color: #fffffF;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        #table-container-placeholder {
            background-color: #fffffF;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        .dataTables_filter {
            display: none;
        }
        th input {
            width: 100%;
            box-sizing: border-box;
        }

        .dataTables_length {
            padding-bottom: 10px !important;
        }
        .light-text {
            color: #baccde;
        }

        .dt-buttons {
            float: right;
        }
        .active>.page-link, .page-link.active {
            background-color: #1C538E !important;
            color: white !important;
        }

        .page-link {
            color: #1C538E;
        }

        #components-table_paginate {
            float: right;
            margin-top: -33px;
        }

        .bg-dark-red {
            background-color: #a10a0a;
            color: white;
        }

        .bg-orange {
            background-color: #ff9335;
            color: white;
        }

        .bg-yellow {
            background-color: #fccd58;
            color: white;
        }

        .bg-light-blue {
            background-color: #9fc5e8;
            color: black;
        }

        #footer {
            position: fixed;
            bottom: 0;
            left: 0;
            width: 100%;
            background-color: #032c57;
            color: #baccde;
            text-align: center;
            z-index: 100000;
        }

        #footer a {
            color: #baccde;
        }

        .top-aligned-td {
            padding-top: 7px;
            vertical-align: top;
        }

        .dotted-hr {
            border-top: dotted 1px;
        }

        .fix-version {
            color: green !important;
            font-weight: bold;
        }

        .vulnerable-software {
            color: #ff4d01 !important;
            font-weight: bold;
        }

        .vulnerable-element {
            color: #a10a0a !important;
        }

        .dataTables_length {
            display: inline;
        }

        .dataTables_info {
            display: inline;
            margin-left: 5px;
        }

        .dataTables_info::before {
          content: "- ";
        }

        .dataTables_paginate {
            margin-top: -31px !important;
        }

        .tree {
          --spacing: 1.5rem;
          --radius: 10px;
        }

        .tree li {
          display: block;
          position: relative;
          padding-left: calc(2 * var(--spacing) - var(--radius) - 2px);
        }

        .tree ul {
          margin-left: calc(var(--radius) - var(--spacing));
          padding-left: 0;
        }

        .tree ul li {
          border-left: 2px solid #ababab;
        }

        .second-root-line {
            border-left: 2px solid #ababab;
            padding-left: 13px;
            margin-left: -14px;
            padding-top: 20px;
        }

        .tree ul li:last-child {
          border-color: transparent;
        }

        .tree ul li::before {
          content: '';
          display: block;
          position: absolute;
          top: calc(var(--spacing) / -2);
          left: -2px;
          width: calc(var(--spacing) + 2px);
          height: calc(var(--spacing) + 1px);
          border: solid #ababab;
          border-width: 0 0 2px 2px;
        }

        .tree summary {
          display: block;
          cursor: pointer;
        }

        .tree summary::marker,
        .tree summary::-webkit-details-marker {
          display: none;
        }

        .tree summary:focus {
          outline: none;
        }

        .tree summary:focus-visible {
          outline: 1px dotted #000;
        }

        .tree li::after,
        .tree summary::before {
          content: '';
          display: block;
          position: absolute;
          top: calc(var(--spacing) / 1.7 - var(--radius));
          left: calc(var(--spacing) - var(--radius) + 1px);
          width: calc(1.5 * var(--radius));
          height: calc(1.5 * var(--radius));
          border-radius: 50%;
          background: #ababab;
        }

        .no-pointer-events {
          pointer-events: none;
        }

        .code-title {
            color: #b5e853;
        }

        .opaque {
            opacity: 0.5 !important;
        }

        .bg-critical {
            background-color: #a10a0a;
            color: white;
        }

        .bg-high {
            background-color: red;
            color: white;
        }

        .bg-medium {
            background-color: #ff9335;
            color: white;
        }

        .bg-low {
            background-color: #fccd58;
            color: white;
        }

        .reachable-code {
            color: black;
            border: 1px solid grey;
            padding: 2px;
        }

        .breakable {
            white-space: pre-wrap;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }

        table {
            width: 100% !important;
        }

        <ADDITIONAL_STYLES_PLACEHOLDER>
    </style>
</head>


<body>
    <h1 class="light-text"><pre>
  _|  _  ._   _  _  _. ._
 (_| (/_ |_) _> (_ (_| | |
         |
</pre></h1>

    <CONTENT_PLACEHOLDER>

    <br><br>
    <script>

        function initTable(tableId) {
            let table = $(tableId).DataTable({
                "order": [],
                pageLength: 25,
                dom: 'Bfrtlip',
                lengthMenu: [
                    [10, 25, 50, -1],
                    [10, 25, 50, 'All']
                ],
                buttons: [
                  { extend: 'copy', className: 'btn btn-light border-dark text-dark mb-3 btn-sm',
                    exportOptions: {
                      stripNewlines: false,
                    }
                  },
                  { extend: 'csv', className: 'btn btn-light border-dark text-dark mb-3 btn-sm',
                    exportOptions: {
                      stripNewlines: false,
                    }
                  },
                  { extend: 'excel', className: 'btn btn-light border-dark text-dark mb-3 btn-sm',
                    exportOptions: {
                      stripNewlines: false,
                    }
                  },
                  { extend: 'print', className: 'btn btn-light border-dark text-dark mb-3 btn-sm',
                    customize: function (win) {
                        $(win.document.body).css('font-size', '8pt');
                        $(win.document.body).find('table').addClass('compact').css('font-size', 'inherit');

                        // Add landscape mode
                        var css = '@page { size: landscape; }',
                            head = win.document.head || win.document.getElementsByTagName('head')[0],
                            style = win.document.createElement('style');

                        style.type = 'text/css';
                        style.media = 'print';

                        if (style.styleSheet) {
                            style.styleSheet.cssText = css;
                        } else {
                            style.appendChild(win.document.createTextNode(css));
                        }
                        head.appendChild(style);
                    },
                    exportOptions: {
                        format: {
                          body: function(data, row, column, node) {
                            return typeof data === 'string'
                              ? data.replace(/\\n/g, '<br>')
                              : data;
                          }
                        }
                    }
                  }
                ],
                orderCellsTop: true,
                "autoWidth": true
              });

            $(tableId + ' thead input').on('keyup change', function () {
                let columnIndex = $(this).parent().index();
                table.column(columnIndex).search(this.value).draw();
            });
        }

        <INIT_TABLE_PLACEHOLDER>

    </script>
</body>
</html>
"""
