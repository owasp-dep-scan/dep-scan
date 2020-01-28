# Introduction

```bash
  ___            _____ _                    _
 / _ \          |_   _| |                  | |
/ /_\ \_ __  _ __ | | | |__  _ __ ___  __ _| |_
|  _  | '_ \| '_ \| | | '_ \| '__/ _ \/ _` | __|
| | | | |_) | |_) | | | | | | | |  __/ (_| | |_
\_| |_/ .__/| .__/\_/ |_| |_|_|  \___|\__,_|\__|
      | |   | |
      |_|   |_|
```

dep-scan is a fully open-source security audit tool for project dependencies based on known vulnerabilities and advisories. The output is fully compatible with [grafeas](https://github.com/grafeas/grafeas). The tool is ideal for CI environments with built-in build breaker logic.

## Features

- Package vulnerability scanning is performed locally. No server is used!
- Configurable `cache` and `sync` functionality to manage vulnerabilities locally
- Supports direct input from [sast-scan](https://github.com/AppThreat/sast-scan/)

## Usage

dep-scan is ideal for use with CI and also as a tool for local development.

### Customisation through environment variables

Following environment variables can be used to customise the behaviour.

- VULNDB_HOME - Directory to use for caching database. For docker based execution, this directory should get mounted as a volume from the host
- NVD_START_YEAR - Default: 2018. Supports upto 2002
- GITHUB_PAGE_COUNT - Default: 2. Supports upto 20

### Scanning projects locally

`appthreat/dep-scan` or `quay.io/appthreat/dep-scan` container image can be used to perform the scan.

To scan with default settings

```bash
docker run --rm -v $PWD:/app appthreat/dep-scan scan --src /app --out_dir /app/reports
```

To scan with custom environment variables based configuration

```bash
docker run --rm \
    -e VULNDB_HOME=/db \
    -e NVD_START_YEAR=2010 \
    -e GITHUB_PAGE_COUNT=5 \
    -e GITHUB_TOKEN=<token> \
    -v /tmp:/db \
    -v $PWD:/app appthreat/dep-scan scan --src /app --out_dir /app/reports
```

In the above example, `/tmp` is mounted as `/db` into the container. This directory is then specified as `VULNDB_HOME` for caching the vulnerability information. This way the database can be cached and reused to improve performance.

## GitHub security advisory

To download security advisories from GitHub, a personal access token with the following scope is necessary.

- read:packages

```bash
export GITHUB_TOKEN="<PAT token>"
```

This environment variable is not required when dep-scan is executed via GitHub action.

## Alternatives
