{ pkgs, inputs, config, ... }:
let pkgs-unstable = import inputs.nixpkgs-unstable { system = pkgs.stdenv.system; };
in
{
  # https://devenv.sh/languages/
  languages = {
    python = {
      enable = true;
      version = "3.12";
    };
    javascript = {
      enable = true;
      package = pkgs.nodejs_23;
    };
    java = {
      enable = true;
      jdk.package = pkgs.jdk21;
    };
  };

  packages = [
    config.languages.python.package.pkgs.astral
    pkgs.uv
    pkgs-unstable.pnpm_10
  ];
  devcontainer.enable = true;
  # Setup the latest cdxgen using pnpm
  enterShell = ''
    pnpm setup
    source $HOME/.bashrc
    export PNPM_GLOBAL_DIR="$HOME/.local/share/pnpm/global"
    export PATH="$PNPM_GLOBAL_DIR/bin:$PATH"
    pnpm config set global-dir "$PNPM_GLOBAL_DIR" --location=global
    pnpm add -g --allow-build sqlite3 @cyclonedx/cdxgen
    cdxgen --version
    python3 --version
    uv sync --all-extras --all-packages --dev
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
}
