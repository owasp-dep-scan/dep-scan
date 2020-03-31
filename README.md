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

dep-scan is a fully open-source security audit tool for project dependencies based on known vulnerabilities, advisories and license limitations. The output is compatible with [grafeas](https://github.com/grafeas/grafeas). The tool is ideal for CI environments with built-in build breaker logic.

[![Docker Repository on Quay](https://quay.io/repository/appthreat/dep-scan/status "Docker Repository on Quay")](https://quay.io/repository/appthreat/dep-scan)

## Features

- Package vulnerability scanning is performed locally and is quite fast. No server is used!
- Configurable `cache` and `sync` functionality to manage local cache data
- Pre-installed and integrated with [sast-scan](https://github.com/AppThreat/sast-scan/)
- (Alpha) Reports packages with license limitations (such as [copyleft](https://www.gnu.org/licenses/copyleft.en.html))

Known issue:

- Possibility of false positives due to the version matching logic currently ignoring [package exclude information in CVE](https://github.com/AppThreat/vulndb/issues/1)

## Usage

dep-scan is ideal for use during continuous integration (CI) and also as a tool for local development.

### Use with sast-scan

dep-scan is integrated with [sast-scan](https://github.com/AppThreat/sast-scan/), a free and open-source SAST tool. To enable this feature simply pass `depscan` to the `--type` argument. [See here](https://github.com/AppThreat/sast-scan/blob/master/.github/workflows/pythonapp.yml#L38) for an example.

```yaml
---
--type python,depscan,credscan
```

This approach should work for all CI environments supported by sast-scan.

### Scanning projects locally (Python version)

```bash
npm install -g @appthreat/cdxgen
pip install appthreat-depscan
```

This would install two commands called `cdxgen` and `scan`.

You can invoke the scan command directly with the various options.

```bash
cd <project to scan>
scan --src $PWD --report_file $PWD/reports/depscan.json
```

### Scanning projects locally (Docker container)

`appthreat/dep-scan` or `quay.io/appthreat/dep-scan` container image can be used to perform the scan.

To scan with default settings

```bash
docker run --rm -v $PWD:/app appthreat/dep-scan scan --src /app --report_file /app/reports/depscan.json
```

To scan with custom environment variables based configuration

```bash
docker run --rm \
    -e VULNDB_HOME=/db \
    -e NVD_START_YEAR=2010 \
    -e GITHUB_PAGE_COUNT=5 \
    -e GITHUB_TOKEN=<token> \
    -v /tmp:/db \
    -v $PWD:/app appthreat/dep-scan scan --src /app --report_file /app/reports/depscan.json
```

In the above example, `/tmp` is mounted as `/db` into the container. This directory is then specified as `VULNDB_HOME` for caching the vulnerability information. This way the database can be cached and reused to improve performance.

## Supported languages and package format

dep-scan uses [cdxgen](https://github.com/AppThreat/cdxgen) command internally to create Software Bill-of-Materials (SBoM) file for the project. This is then used for performing the scans.

The following projects and package-dependency format is supported by cdxgen.

| Language  | Package format                              |
| --------- | ------------------------------------------- |
| node.js   | package-lock.json                           |
| java (\*) | maven (pom.xml), gradle (build.gradle)      |
| python    | requirements.txt, Pipfile.lock, poetry.lock |
| go        | go.sum, Gopkg.lock                          |
| rust      | Cargo.lock                                  |
| .Net core | .csproj                                     |

**NOTE**

The docker image for dep-scan currently doesn't bundle suitable java and maven commands required for bom generation. To workaround this limitation, you can -

1. Use python-based execution from a VM containing the correct versions for java, maven and gradle.
2. Generate the bom file by invoking `cdxgen` command locally and subsequently passing this to `dep-scan` via the `--bom` argument.

## Integration with CI environments

### Integration with Azure DevOps

Refer to [this example yaml](https://github.com/AppThreat/WebGoat/blob/develop/azure-pipelines.yml#L33) configuration for integrating dep-scan with Azure Pipelines. The build step would perform the scan and display the report inline as shown below:

![Azure DevOps integration](docs/dep-scan-azure.png)

### Integration with GitHub Actions

This tool can be used with GitHub Actions using this [action](https://github.com/marketplace/actions/dep-scan).

This repo self-tests itself with both sast-scan and dep-scan! Check the GitHub [workflow file](https://github.com/AppThreat/dep-scan/blob/master/.github/workflows/pythonapp.yml) of this repo.

```yaml
- name: Self dep-scan
  uses: AppThreat/dep-scan-action@master
  env:
    VULNDB_HOME: ${{ github.workspace }}/db
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Customisation through environment variables

The following environment variables can be used to customise the behaviour.

- VULNDB_HOME - Directory to use for caching database. For docker based execution, this directory should get mounted as a volume from the host
- NVD_START_YEAR - Default: 2018. Supports upto 2002
- GITHUB_PAGE_COUNT - Default: 2. Supports upto 20

## GitHub Security Advisory

To download security advisories from GitHub, a personal access token with the following scope is necessary.

- read:packages

```bash
export GITHUB_TOKEN="<PAT token>"
```

## License scan (alpha)

dep-scan can automatically scan the dependencies for any license limitations and report them directly on the console log. The licenses data is sourced from choosealicense.com and is quite limited. If the license of a given package cannot be reliably matched against this list it will get silently ignored to reduce any noise. This behaviour could change in the future once the detection logic gets improved.

![License scan](docs/license-scan.png)

## Alternatives

[Dependency Check](https://github.com/jeremylong/DependencyCheck) is considered to be the industry standard for open-source dependency scanning. After personally using this great product for a number of years I decided to write my own from scratch partly as a dedication to this project. By using a streaming database based on msgpack and using json schema, dep-scan is more performant than dependency check in CI environments. Plus with support for GitHub advisory source and grafeas report export and submission, dep-scan is on track to become a next-generation dependency audit tool

There are a number of other tools that piggy back on Sonatype [ossindex](https://ossindex.sonatype.org/) API server. For some reason, I always felt uncomfortable letting a commercial company track the usage of various projects across the world. dep-scan is therefore 100% private and guarantees never to perform any tracking!
