{ pkgs, lib, inputs, config, ... }:
let pkgs-unstable = import inputs.nixpkgs-unstable { system = pkgs.stdenv.system; };
in
{
  # Language-specific topions
  options = {
    profile = lib.mkOption {
      type = lib.types.enum [ "ruby" "php" "c" "cplusplus" "go" "swift" "scala" "rust" "dotnet" "basic" ];
      default = "basic";
      description = "Development profile to use";
    };
  };
  config = {
      languages = {
        python = {
          enable = true;
          venv.enable = true;
          venv.quiet = true;
          version = "3.13";
          uv.enable = true;
          uv.sync.allExtras = true;
          uv.sync.enable = true;
        };
        javascript = {
          enable = true;
          package = pkgs-unstable.nodejs_24;
        };
        java = {
          enable = true;
          jdk.package = pkgs.jdk23_headless;
        };
        ruby = {
          enable = lib.mkIf (config.profile == "ruby") true;
          version = "3.4.3";
        };
        dotnet = {
          enable = lib.mkIf (config.profile == "dotnet") true;
        };
        swift = {
          enable = lib.mkIf (config.profile == "swift") true;
        };
        c = {
          enable = lib.mkIf (config.profile == "c") true;
        };
        cplusplus = {
          enable = lib.mkIf (config.profile == "cplusplus") true;
        };
        go = {
          enable = lib.mkIf (config.profile == "go") true;
        };
        rust = {
          enable = lib.mkIf (config.profile == "rust") true;
        };
        scala = {
          enable = lib.mkIf (config.profile == "scala") true;
          sbt.enable = lib.mkIf (config.profile == "scala") true;
          mill.enable = lib.mkIf (config.profile == "scala") true;
        };
        php = {
          enable = lib.mkIf (config.profile == "php") true;
          extensions = [
            "openssl"
            "zip"
          ];
          packages = {
            composer = pkgs.phpPackages.composer;
          };
        };
      };

      # Common packages
      packages = [
        pkgs-unstable.nodejs_24
        pkgs.python313Full
        config.languages.python.package.pkgs.astral
        pkgs.uv
        pkgs-unstable.pnpm_10
      ];

      # Useful features
      devcontainer.enable = true;
      difftastic.enable = true;
      # Setup the latest cdxgen using pnpm
      enterShell = ''
        set -e
        pnpm setup
        source $HOME/.bashrc
        export PNPM_GLOBAL_DIR="$HOME/.local/share/pnpm/global"
        mkdir -p $PNPM_GLOBAL_DIR
        export PATH="$PNPM_GLOBAL_DIR/bin:$PATH"
        pnpm config set global-dir "$PNPM_GLOBAL_DIR" --location=global
        pnpm add -g --allow-build=sqlite3 https://github.com/CycloneDX/cdxgen.git
        uv sync --all-extras --all-packages --dev -p 3.13 --active
      '';

      # Tasks
      tasks."vdb:clean" = {
        exec = ''
        uv run vdb --clean
        '';
      };
      tasks."vdb:download-image" = {
        exec = ''
        uv run vdb --download-image
        '';
      };
      tasks."vdb:download-full-image" = {
        exec = ''
        uv run vdb --download-full-image
        '';
      };
  };
}
