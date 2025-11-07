{
  description = "Ubuntu and Nix SBOM Generator - Creates SPDX SBOMs for combined Ubuntu/Nix systems";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    flake-parts.url = "github:hercules-ci/flake-parts";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
    git-hooks.url = "github:cachix/git-hooks.nix";
    git-hooks.inputs.nixpkgs.follows = "nixpkgs";
    sbomnix = {
      url = "github:tiiuae/sbomnix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];

      imports = [
        inputs.treefmt-nix.flakeModule
        inputs.git-hooks.flakeModule
      ];

      perSystem =
        {
          config,
          pkgs,
          system,
          ...
        }:
        let
          sbomnix = inputs.sbomnix.packages.${system}.default;

          # Build the Ubuntu SBOM generator
          ubuntu-sbom = pkgs.buildGoModule {
            pname = "ubuntu-sbom-generator";
            version = "1.0.0";
            src = ./.;
            vendorHash = null;

            buildPhase = ''
              go build -o ubuntu-sbom main.go
            '';

            installPhase = ''
              mkdir -p $out/bin
              cp ubuntu-sbom $out/bin/
            '';

            meta = with pkgs.lib; {
              description = "SPDX SBOM generator for Ubuntu/Debian packages";
              license = licenses.asl20;
            };
          };

          # Build the merger tool
          sbom-merger = pkgs.buildGoModule {
            pname = "sbom-merger";
            version = "1.0.0";
            src = ./.;
            vendorHash = null;

            buildPhase = ''
              go build -o sbom-merge merge.go
            '';

            installPhase = ''
              mkdir -p $out/bin
              cp sbom-merge $out/bin/
            '';

            meta = with pkgs.lib; {
              description = "Merges Ubuntu and Nix SPDX SBOMs";
              license = licenses.asl20;
            };
          };

          # Wrapper script for Ubuntu-only SBOM
          ubuntu-only-wrapper = pkgs.writeShellScriptBin "sbom-ubuntu" ''
            ${ubuntu-sbom}/bin/ubuntu-sbom "$@"
          '';

          # Wrapper script for Nix-only SBOM
          nix-only-wrapper = pkgs.writeShellScriptBin "sbom-nix" ''
            if [ $# -eq 0 ]; then
              echo "Error: Derivation path required"
              echo "Usage: sbom-nix <derivation-path> [--output <file>]"
              exit 1
            fi

            DERIVATION="$1"
            shift

            OUTPUT="nix-sbom.spdx.json"

            # Parse remaining arguments for --output flag
            while [[ $# -gt 0 ]]; do
              case $1 in
                --output)
                  OUTPUT="$2"
                  shift 2
                  ;;
                *)
                  echo "Unknown option: $1"
                  exit 1
                  ;;
              esac
            done

            ${sbomnix}/bin/sbomnix "$DERIVATION" --spdx="$OUTPUT"
          '';

          # Wrapper script for merged SBOM
          merged-wrapper = pkgs.writeShellScriptBin "sbom-generator" ''
            OUTPUT="merged-sbom.spdx.json"
            NIX_TARGET=""
            INCLUDE_FILES=""
            PROGRESS="--progress"

            # Parse arguments
            while [[ $# -gt 0 ]]; do
              case $1 in
                --output)
                  OUTPUT="$2"
                  shift 2
                  ;;
                --nix-target)
                  NIX_TARGET="$2"
                  shift 2
                  ;;
                --include-files)
                  INCLUDE_FILES="--include-files"
                  shift
                  ;;
                --no-progress)
                  PROGRESS=""
                  shift
                  ;;
                --progress)
                  PROGRESS="--progress"
                  shift
                  ;;
                *)
                  echo "Unknown option: $1"
                  echo "Usage: sbom-generator --nix-target <derivation> [--output <file>] [--include-files] [--progress]"
                  exit 1
                  ;;
              esac
            done

            if [ -z "$NIX_TARGET" ]; then
              echo "Error: --nix-target is required"
              echo "Usage: sbom-generator --nix-target <derivation> [--output <file>] [--include-files] [--progress]"
              exit 1
            fi

            # Create temporary directory for intermediate files
            TMPDIR=$(mktemp -d)
            trap "rm -rf $TMPDIR" EXIT

            UBUNTU_SBOM="$TMPDIR/ubuntu-sbom.spdx.json"
            NIX_SBOM="$TMPDIR/nix-sbom.spdx.json"

            echo "Generating Ubuntu SBOM..."
            ${ubuntu-sbom}/bin/ubuntu-sbom --output "$UBUNTU_SBOM" $INCLUDE_FILES $PROGRESS

            echo "Generating Nix SBOM..."
            ${sbomnix}/bin/sbomnix "$NIX_TARGET" --spdx="$NIX_SBOM"

            echo "Merging SBOMs..."
            ${sbom-merger}/bin/sbom-merge --ubuntu "$UBUNTU_SBOM" --nix "$NIX_SBOM" --output "$OUTPUT"
          '';

          # Static binary for current system
          ubuntu-sbom-static-current = pkgs.buildGoModule {
            pname = "ubuntu-sbom-generator";
            version = "1.0.0";
            src = ./.;
            vendorHash = null;

            # Build static binary with no CGO
            buildPhase = ''
              CGO_ENABLED=0 go build -a -ldflags '-s -w -extldflags "-static"' -o ubuntu-sbom main.go
            '';

            installPhase = ''
              mkdir -p $out/bin
              cp ubuntu-sbom $out/bin/
            '';

            meta = with pkgs.lib; {
              description = "SPDX SBOM generator for Ubuntu/Debian packages (static binary)";
              license = licenses.asl20;
            };
          };

          # Static binary builder for a specific architecture
          buildStaticBinary =
            targetSystem:
            let
              targetPkgs = import inputs.nixpkgs {
                system = targetSystem;
                crossSystem = null;
              };
            in
            targetPkgs.buildGoModule {
              pname = "ubuntu-sbom-generator";
              version = "1.0.0";
              src = ./.;
              vendorHash = null;

              # Build static binary with no CGO
              buildPhase = ''
                CGO_ENABLED=0 go build -a -ldflags '-s -w -extldflags "-static"' -o ubuntu-sbom main.go
              '';

              installPhase = ''
                mkdir -p $out/bin
                cp ubuntu-sbom $out/bin/
              '';

              meta = with targetPkgs.lib; {
                description = "SPDX SBOM generator for Ubuntu/Debian packages (static binary)";
                license = licenses.asl20;
                platforms = [ targetSystem ];
              };
            };

        in
        {
          # Treefmt configuration
          treefmt = {
            projectRootFile = "flake.nix";
            programs = {
              # Nix formatter
              nixfmt = {
                enable = true;
                package = pkgs.nixfmt-rfc-style;
              };
              # Shell script formatter
              shellcheck.enable = true;
              shfmt.enable = true;
              # Go formatter
              gofmt.enable = true;
              # Remove dead Nix code
              deadnix.enable = true;
            };
          };

          # Pre-commit hooks configuration
          pre-commit = {
            check.enable = true;
            settings = {
              hooks = {
                treefmt = {
                  enable = true;
                  package = config.treefmt.build.wrapper;
                };
              };
            };
          };

          # Packages
          packages = {
            ubuntu-sbom-generator = ubuntu-sbom;
            sbom-merger = sbom-merger;
            default = merged-wrapper;

            # Static binaries for release
            ubuntu-sbom-static-amd64 = buildStaticBinary "x86_64-linux";
            ubuntu-sbom-static-arm64 = buildStaticBinary "aarch64-linux";
            ubuntu-sbom-static = ubuntu-sbom-static-current;
          };

          # Apps
          apps = {
            # Main app: merged SBOM generator
            sbom-generator = {
              type = "app";
              program = "${merged-wrapper}/bin/sbom-generator";
            };

            # Ubuntu-only SBOM
            sbom-ubuntu = {
              type = "app";
              program = "${ubuntu-only-wrapper}/bin/sbom-ubuntu";
            };

            # Nix-only SBOM
            sbom-nix = {
              type = "app";
              program = "${nix-only-wrapper}/bin/sbom-nix";
            };

            # Default app
            default = {
              type = "app";
              program = "${merged-wrapper}/bin/sbom-generator";
            };
          };

          # Development shell
          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [
              go
              gopls
              gotools
              sbomnix
              python3Packages.spdx-tools
              # Formatting tools
              nixfmt-rfc-style
              shellcheck
              shfmt
              config.treefmt.build.wrapper
            ];
            shellHook = ''
              ${config.pre-commit.installationScript}
            '';
          };
        };
    };
}
