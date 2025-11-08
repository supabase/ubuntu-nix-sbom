package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/ubuntu-nix-sbom/internal/ubuntu"
)

func main() {
	var (
		outputFile   = flag.String("output", "ubuntu-sbom.spdx.json", "Output file path")
		includeFiles = flag.Bool("include-files", false, "Include file checksums for each package")
		progress     = flag.Bool("progress", true, "Show progress indicators")
	)
	flag.Parse()

	generator := ubuntu.NewGenerator(*includeFiles, *progress)

	doc, err := generator.Generate()
	if err != nil {
		log.Fatalf("Failed to generate SBOM: %v", err)
	}

	if err := generator.Save(doc, *outputFile); err != nil {
		log.Fatalf("Failed to save SBOM: %v", err)
	}

	fmt.Printf("Ubuntu SBOM generated successfully: %s\n", *outputFile)
}
