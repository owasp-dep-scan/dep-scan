# Perform Semantic Reachability Analysis for a Java project

## Learning Objective

In this lesson, we will learn about performing a comprehensive semantic analysis for a Java project, namely dependency-track, with OWASP depscan.

## Pre-requisites

Ensure the following tools are installed:

- Java >= 21
- Maven
- Python > 3.10
- Node.js > 20
- Docker Desktop, podman, or nerdctl


## Getting started

Install cdxgen and depscan.

```shell
sudo npm install -g @cyclonedx/cdxgen
python -m pip install owasp-depscan[all]
```

Clone and compile dependency track

```shell
git clone https://github.com/DependencyTrack/dependency-track
cd dependency-track
mvn clean compile -P clean-exclude-wars -P enhance -P embedded-jetty -DskipTests
```

Pull the appropriate container image tag

```shell
docker pull dependencytrack/bundled:latest
```

## Invoke depscan

```shell
# Let depscan know the name of the container image
export DEPSCAN_SOURCE_IMAGE=dependencytrack/bundled:latest

# Perform semantic analysis with local cdxgen engine and detailed explanation
depscan --src path/to/dependency-track --reports-dir path/to/dependency-track/reports -t java --bom-engine CdxgenGenerator --reachability-analyzer SemanticReachability --explain
```

Additional learning. Leaving out the `--bom-engine` argument would make depscan use the `CdxgenImageBasedGenerator`, which uses a container image-based BOM generation for better compatibility. On Windows, or in environments without Docker, `CdxgenGenerator` would be used by default.

```shell
depscan --src path/to/dependency-track --reports-dir path/to/dependency-track/reports -t java --reachability-analyzer SemanticReachability --explain
```

Unsetting the environment variable `DEPSCAN_SOURCE_IMAGE` would make depscan analyze only the source code without considering the container layer.
