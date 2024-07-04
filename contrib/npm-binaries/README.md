# Introduction

This folder contains a script to collect npm packages with binary risks. libraries.io API is used for the initial search for packages based on popularity or rank. Depscan pkg_query is then used as a library to identify binary risk with the results stored in a CSV file.

## Usage

```
git clone https://github.com/owasp-dep-scan/dep-scan.git
cd dep-scan
python -m pip install .
cd contrib/npm-binaries
pip install -r requirements.txt

# Signup and get an api key for libraries.io
export LIBRARIES_API_KEY=key

# Search for packages by keywords
python collect.py --keywords binary,prebuilt -o report.csv

# top popular packages
python collect.py --popular -o report.csv
```

The full list of options is below:

```shell
python collect.py --help
usage: collect.py [-h] [--keywords KEYWORDS] [-s {rank,stars,dependents_count,dependent_repos_count,contributions_count}] [-t {npm}] [-o OUTPUT_FILE] [--popular]

Collect npm packages for given search strings.

options:
  -h, --help            show this help message and exit
  --keywords KEYWORDS   Comma separated list of keywords to search.
  -s {rank,stars,dependents_count,dependent_repos_count,contributions_count}, --sort {rank,stars,dependents_count,dependent_repos_count,contributions_count}
                        Sort options.
  -t {npm}, --type {npm}
                        Package type.
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Output CSV file.
  --popular             Top popular packages.
```
