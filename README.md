# Ubuntu-Nix SBOM Generator

A comprehensive SBOM (Software Bill of Materials) generator for systems running both Ubuntu and Nix packages. Generates SPDX 2.3 compliant JSON documents.

## Features

- **Ubuntu SBOM Generation**: Scans dpkg-installed packages on Ubuntu/Debian systems
- **Nix SBOM Generation**: Uses [sbomnix](https://github.com/tiiuae/sbomnix) to analyze Nix derivations
- **Merged SBOM**: Combines both Ubuntu and Nix packages into a single unified SBOM
- **SPDX 2.3 Compliant**: Generates valid SPDX JSON documents
- **License Detection**: Extracts license information from package metadata
- **Package URLs (purl)**: Includes purl references for both deb and nix packages

## Prerequisites

- Nix with flakes enabled
- Ubuntu/Debian system (for Ubuntu SBOM generation)
- Access to dpkg and package metadata

## Installation

Clone the repository and enter the development shell:

```bash
git clone <repository-url>
cd ubuntu-nix-sbom
nix develop
```

## Usage

### Merged SBOM (Ubuntu + Nix)

Generate a combined SBOM for both Ubuntu and Nix packages:

```bash
nix run .#sbom-generator -- --nix-target /nix/store/xxx-system --output merged-sbom.json
```

Or use the sbom binary directly:

```bash
sbom combined --nix-target /nix/store/xxx-system --output merged-sbom.json
```

Options:
- `--nix-target <path>`: Required. Path to the Nix derivation to analyze
- `--output <file>`: Output file path (default: merged-sbom.spdx.json)
- `--include-files`: Include file checksums for Ubuntu packages (slower)
- `--progress`: Show progress indicators (default: true)
- `--no-progress`: Disable progress indicators

Example with all options:

```bash
nix run .#sbom-generator -- \
  --nix-target /nix/var/nix/profiles/system \
  --output my-system-sbom.json \
  --include-files \
  --progress
```

### Ubuntu-Only SBOM

Generate SBOM for Ubuntu packages only:

```bash
nix run .#sbom-ubuntu -- --output ubuntu-sbom.json
```

Options:
- `--output <file>`: Output file path (default: ubuntu-sbom.spdx.json)
- `--include-files`: Include file checksums (slower but more detailed)
- `--progress`: Show progress indicators (default: true)

### Nix-Only SBOM

Generate SBOM for Nix packages only:

```bash
nix run .#sbom-nix -- /nix/store/xxx-derivation --output nix-sbom.json
```

The first argument (derivation path) is required. Options:
- `--output <file>`: Output file path (default: nix-sbom.spdx.json)

## CLI Reference

The project provides two binaries:

### ubuntu-sbom (Static Binary)

Standalone binary for Ubuntu/Debian systems without Nix:

```bash
ubuntu-sbom --output ubuntu-sbom.json [--include-files] [--progress]
```

### sbom (Full-Featured Binary)

Complete tooling with subcommands:

**Ubuntu-only SBOM:**
```bash
sbom ubuntu --output ubuntu-sbom.json [--include-files] [--progress]
```

**Nix-only SBOM:**
```bash
sbom nix <derivation-path> --output nix-sbom.json
```

**Combined SBOM:**
```bash
sbom combined --nix-target <derivation> --output merged.json [--include-files] [--progress]
```

## How It Works

### Ubuntu SBOM Generation

1. Queries dpkg for all installed packages
2. Extracts metadata (version, architecture, maintainer, homepage)
3. Reads license information from `/usr/share/doc/<package>/copyright`
4. Optionally calculates SHA256 checksums of package files
5. Generates SPDX 2.3 JSON with purl references (`pkg:deb/ubuntu/...`)

### Nix SBOM Generation

1. Uses sbomnix to analyze the specified derivation
2. Extracts all dependencies and their metadata
3. Generates SPDX 2.3 JSON with purl references (`pkg:nix/...`)

### Merging Process

1. Loads both Ubuntu and Nix SPDX documents
2. Creates a new document with a single "SPDXRef-System" root package
3. Renames package SPDXIDs to avoid conflicts:
   - Ubuntu packages: `SPDXRef-Ubuntu-Package-*`
   - Nix packages: `SPDXRef-Nix-Package-*`
4. Preserves all package metadata and relationships
5. Combines creator information from both sources
6. Adds merger tool to the creator list

## SPDX Document Structure

### Merged SBOM

```
SPDXRef-DOCUMENT (describes) → SPDXRef-System
                                    ├── (contains) SPDXRef-Ubuntu-Package-1-bash
                                    ├── (contains) SPDXRef-Ubuntu-Package-2-curl
                                    ├── (contains) SPDXRef-Nix-Package-1-nixpkgs-...
                                    └── (contains) SPDXRef-Nix-Package-2-...
```

### Package Identification

Duplicate packages (same software in both Ubuntu and Nix) are kept separate and identified by:
- Different SPDXIDs (Ubuntu vs Nix prefix)
- Different purl external references:
  - Ubuntu: `pkg:deb/ubuntu/bash@5.1-6ubuntu1?arch=amd64`
  - Nix: `pkg:nix/nixpkgs/bash@5.1-...`

## Example Output

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "Ubuntu-Nix-System-SBOM-2025-11-05",
  "documentNamespace": "https://sbom.ubuntu-nix.system/...",
  "creationInfo": {
    "created": "2025-11-05T12:00:00Z",
    "creators": [
      "Tool: ubuntu-sbom-generator-1.0",
      "Tool: sbomnix-...",
      "Tool: ubuntu-nix-sbom-merger-1.0"
    ],
    "licenseListVersion": "3.20"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-System",
      "name": "Ubuntu-Nix-System",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION",
      "description": "Combined Ubuntu and Nix package system"
    },
    ...
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-System",
      "relationshipType": "DESCRIBES"
    },
    ...
  ]
}
```

## CI/CD

The project includes GitHub Actions workflows for automated testing and releases:

### PR Checks

On every pull request to `main`:
- **Nix Flake Check**: Runs `nix flake check --all-systems` to validate the flake
- **Formatting**: Checks code formatting with `nix fmt --fail-on-change`
- **SPDX Validation**:
  - Builds the Ubuntu SBOM generator
  - Generates a test SBOM
  - Validates the output against SPDX 2.3 specification using `spdx-tools`
  - Tests conversion to other SPDX formats (tag-value, XML, YAML)
  - Uploads test SBOM as artifact

### Automated Releases

On every merge to `main`:
- Builds the ARM64 static binary on an ARM Linux runner
- Tests the binary and validates SPDX output
- Automatically increments the patch version (semver)
- Creates a GitHub release with:
  - Changelog from commits since last release
  - ARM64 static binary as downloadable asset
  - SHA256 checksum file
  - Installation and verification instructions
  - Binary size

The release workflow uses semantic versioning (e.g., v1.2.3) and automatically tags releases.

## Building Static Binaries for Release

The flake includes static binary builds that can be distributed to Ubuntu users without requiring Nix:

### Build arm64 static binary:

```bash
nix build .#ubuntu-sbom-static-arm64 -o result-arm64
```

The binary will be available at `result-arm64/bin/ubuntu-sbom` (2.4MB, statically linked, no dependencies).

### Build for current system:

```bash
nix build .#ubuntu-sbom-static -o result-static
```

### Creating a GitHub Release

To release static binaries:

```bash
# Build the binary
nix build .#ubuntu-sbom-static-arm64 -o result-arm64

# Create a GitHub release and upload the binary
gh release create v1.0.0 \
  result-arm64/bin/ubuntu-sbom#ubuntu-sbom-arm64 \
  --title "v1.0.0" \
  --notes "Ubuntu SBOM Generator v1.0.0"
```

Users can then download and run directly on Ubuntu ARM64 systems:

```bash
# Download from GitHub release (use -L to follow redirects)
curl -LO https://github.com/YOUR_ORG/ubuntu-nix-sbom/releases/download/v1.0.0/ubuntu-sbom-arm64
chmod +x ubuntu-sbom-arm64

# Run without Nix
./ubuntu-sbom-arm64 --output my-sbom.json
```

## Validating SPDX Output

The project uses the official [spdx-tools](https://github.com/spdx/tools-python) to validate SPDX 2.3 compliance.

### Install SPDX validation tools:

```bash
pip install spdx-tools
```

### Validate an SBOM:

```bash
# Generate an SBOM
nix run .#sbom-ubuntu -- --output my-sbom.spdx.json

# Validate it against SPDX 2.3 specification
pyspdxtools -i my-sbom.spdx.json --validate
```

### Convert to other SPDX formats:

```bash
# Convert to SPDX tag-value format
pyspdxtools -i my-sbom.spdx.json -o my-sbom.spdx --output-format tag-value

# Convert to SPDX XML format
pyspdxtools -i my-sbom.spdx.json -o my-sbom.spdx.xml --output-format xml

# Convert to SPDX YAML format
pyspdxtools -i my-sbom.spdx.json -o my-sbom.spdx.yaml --output-format yaml
```

### Validation in CI/CD

Both the PR check and release workflows automatically validate SPDX output:
- PR workflow: Validates test SBOMs and uploads them as artifacts
- Release workflow: Validates SPDX output before creating releases

## Development

Enter the development shell:

```bash
nix develop
```

This provides:
- Go toolchain
- gopls (Go language server)
- sbomnix
- Formatting tools (nixfmt, shellcheck, shfmt, gofmt)
- Pre-commit hooks (automatically installed)

Build the Go binaries manually:

```bash
go build -o ubuntu-sbom main.go
go build -o sbom-merge merge.go
```

### Code Formatting

The project uses `treefmt` to format code automatically. Formatters are configured for:
- **Nix** files: `nixfmt-rfc-style`
- **Shell** scripts: `shellcheck` and `shfmt`
- **Go** code: `gofmt`
- **Dead code removal**: `deadnix`

Format all files:

```bash
nix fmt
```

Check formatting without modifying files:

```bash
nix flake check
```

### Pre-commit Hooks

Pre-commit hooks are automatically installed when entering the dev shell. They will:
- Run `treefmt` on all staged files before each commit
- Ensure code is properly formatted

To manually run the pre-commit checks:

```bash
nix flake check
```

The hooks will automatically format your code when you commit changes.

## License

Apache-2.0

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

The Apache-2.0 license is compatible with [sbomnix](https://github.com/tiiuae/sbomnix) (also Apache-2.0), which this project integrates with for Nix SBOM generation.

## Contributing

Contributions welcome! Please open issues or pull requests.

## References

- [SPDX Specification 2.3](https://spdx.github.io/spdx-spec/v2.3/)
- [sbomnix](https://github.com/tiiuae/sbomnix)
- [Package URL (purl) Specification](https://github.com/package-url/purl-spec)
