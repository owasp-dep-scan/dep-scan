{
  description = "OWASP dep-scan Nix Flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    pyproject-nix = {
      url = "github:nix-community/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, pyproject-nix }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });

      project = pyproject-nix.lib.project.loadPyproject {
        projectRoot = ./.;
      };

    in
    {
      formatter = forAllSystems ({ pkgs }: pkgs.nixpkgs-fmt);

      packages = forAllSystems ({ pkgs }:
        let
          python = pkgs.python3;
          attrs = project.renderers.buildPythonPackage { inherit python; };
        in
        {
          default = python.pkgs.buildPythonPackage (attrs // {
            pname = "depscan";
            propagatedBuildInputs = attrs.propagatedBuildInputs ++ [ pkgs.cdxgen ];
          });
        }
      );

      devShells = forAllSystems ({ pkgs }:
        let
          python = pkgs.python3;
          arg = project.renderers.withPackages { inherit python; extras = [ "dev" ]; };
          pythonEnv = python.withPackages arg;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.cdxgen
              pythonEnv
            ];
          };
        });
    };
}
