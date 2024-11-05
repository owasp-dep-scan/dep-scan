# Introduction

## Usage

```
git clone https://github.com/owasp-dep-scan/dep-scan.git
cd dep-scan
python -m pip install .
cd contrib/pkg-state-research
pip install -r requirements.txt

python collect.py -o report.csv
```

The full list of options is below:

```shell
usage: collect.py [-h] [--keywords KEYWORDS] [--insecure] [--unstable] [-o OUTPUT_FILE] [--pages PAGES] [--per-page PER_PAGE]

Collect popular packages from registries for analysis.

options:
  -h, --help            show this help message and exit
  --keywords KEYWORDS   Comma separated list of keywords to search.
  --insecure            Top insecure packages only.
  --unstable            Top unstable packages only.
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Output CSV file.
  --pages PAGES         Page count.
  --per-page PER_PAGE   Page count.
```
