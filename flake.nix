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

          # Build the full-featured sbom binary
          sbom = pkgs.buildGoModule {
            pname = "sbom";
            version = "1.0.0";
            src = ./.;
            vendorHash = null;

            buildPhase = ''
              go build -o sbom ./cmd/sbom
            '';

            installPhase = ''
              mkdir -p $out/bin
              cp sbom $out/bin/
            '';

            meta = with pkgs.lib; {
              description = "SPDX SBOM generator with Ubuntu and Nix support";
              license = licenses.asl20;
            };
          };

          # Wrapper script for Ubuntu-only SBOM
          ubuntu-only-wrapper = pkgs.writeShellScriptBin "sbom-ubuntu" ''
            ${sbom}/bin/sbom ubuntu "$@"
          '';

          # Wrapper script for Nix-only SBOM
          nix-only-wrapper = pkgs.writeShellScriptBin "sbom-nix" ''
            export PATH="${sbomnix}/bin:$PATH"
            ${sbom}/bin/sbom nix "$@"
          '';

          # Wrapper script for merged SBOM
          merged-wrapper = pkgs.writeShellScriptBin "sbom-generator" ''
            export PATH="${sbomnix}/bin:$PATH"
            ${sbom}/bin/sbom combined "$@"
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
            sbom = sbom;
            default = sbom;

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

            # Combined SBOM (alias for sbom-generator)
            sbom-combined = {
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

            # SPDX validation tool
            validate-spdx = {
              type = "app";
              program = "${pkgs.writeShellScript "validate-spdx" ''
                if [ $# -eq 0 ]; then
                  echo "Usage: nix run .#validate-spdx -- <sbom-file.json>"
                  echo ""
                  echo "Validates an SPDX SBOM file against the SPDX 2.3 specification."
                  echo ""
                  echo "Example:"
                  echo "  nix run .#validate-spdx -- my-sbom.spdx.json"
                  exit 1
                fi

                SBOM_FILE="$1"

                if [ ! -f "$SBOM_FILE" ]; then
                  echo "ERROR: File not found: $SBOM_FILE"
                  exit 1
                fi

                echo "Validating SPDX document: $SBOM_FILE"
                echo "---"
                ${pkgs.python3Packages.spdx-tools}/bin/pyspdxtools -i "$SBOM_FILE"

                if [ $? -eq 0 ]; then
                  echo "---"
                  echo "✓ SPDX validation passed!"
                else
                  echo "---"
                  echo "✗ SPDX validation failed!"
                  exit 1
                fi
              ''}";
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

          # Checks
          checks = {
            # Verify sbomnix is accessible in wrapper scripts
            sbomnix-available = pkgs.runCommand "check-sbomnix-available" { } ''
              # Test that sbomnix is in PATH when running through wrapper
              export PATH="${sbomnix}/bin:$PATH"

              # Check sbomnix is executable
              if ! command -v sbomnix &> /dev/null; then
                echo "ERROR: sbomnix not found in PATH"
                exit 1
              fi

              # Check sbomnix can show help (verifies it's not just present but functional)
              if ! sbomnix --help &> /dev/null; then
                echo "ERROR: sbomnix --help failed"
                exit 1
              fi

              echo "SUCCESS: sbomnix is available and functional"
              touch $out
            '';

            # Verify sbom binary can be built
            sbom-builds = pkgs.runCommand "check-sbom-builds" { buildInputs = [ sbom ]; } ''
              # Check the binary exists
              if [ ! -f ${sbom}/bin/sbom ]; then
                echo "ERROR: sbom binary not found"
                exit 1
              fi

              # Check it's executable
              if ! ${sbom}/bin/sbom help &> /dev/null; then
                echo "ERROR: sbom help command failed"
                exit 1
              fi

              echo "SUCCESS: sbom binary builds and runs"
              touch $out
            '';
          };
        };
    };
}
