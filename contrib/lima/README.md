# Introduction

[Lima](https://lima-vm.io/) launches Linux virtual machines with automatic file sharing and port forwarding (similar to WSL2).

## Getting Started

Use the below command to install lima and create a cdxgen vm.

```shell
brew install lima
```

```shell
git clone https://github.com/owasp-dep-scan/dep-scan.git
cd dep-scan

# The below command might take several minutes

limactl start --name=depscan contrib/lima/depscan-ubuntu.yaml --tty=false
```

To open a shell to the cdxgen VM:

```shell
limactl shell depscan
```
