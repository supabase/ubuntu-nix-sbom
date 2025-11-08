package merge

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ubuntu-nix-sbom/internal/spdx"
)

type Merger struct{}

func NewMerger() *Merger {
	return &Merger{}
}

func (m *Merger) Merge(ubuntuPath, nixPath string) (*spdx.Document, error) {
	// Load Ubuntu SBOM
	ubuntuDoc, err := m.loadDocument(ubuntuPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load Ubuntu SBOM: %w", err)
	}

	// Load Nix SBOM
	nixDoc, err := m.loadDocument(nixPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load Nix SBOM: %w", err)
	}

	// Create merged document
	mergedDoc := &spdx.Document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              fmt.Sprintf("Ubuntu-Nix-System-SBOM-%s", time.Now().Format("2006-01-02")),
		DocumentNamespace: fmt.Sprintf("https://sbom.ubuntu-nix.system/%s", generateUUID()),
		CreationInfo: spdx.CreationInfo{
			Created:            time.Now().UTC().Format(time.RFC3339),
			Creators:           m.mergeCreators(ubuntuDoc, nixDoc),
			LicenseListVersion: "3.20",
		},
		Packages:      []spdx.Package{},
		Relationships: []spdx.Relationship{},
	}

	// Create the single root System package
	systemPkg := spdx.Package{
		SPDXID:           "SPDXRef-System",
		Name:             "Ubuntu-Nix-System",
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		LicenseConcluded: "NOASSERTION",
		LicenseDeclared:  "NOASSERTION",
		CopyrightText:    "NOASSERTION",
		Description:      "Combined Ubuntu and Nix package system",
	}
	mergedDoc.Packages = append(mergedDoc.Packages, systemPkg)

	// Add document describes relationship
	mergedDoc.Relationships = append(mergedDoc.Relationships, spdx.Relationship{
		SPDXElementID:      "SPDXRef-DOCUMENT",
		RelatedSPDXElement: "SPDXRef-System",
		RelationshipType:   "DESCRIBES",
	})

	// Process Ubuntu packages (skip the root package)
	ubuntuCount := 0
	for _, pkg := range ubuntuDoc.Packages {
		if pkg.SPDXID == "SPDXRef-Ubuntu-System" || pkg.SPDXID == "SPDXRef-System" {
			continue // Skip root packages
		}

		// Ensure SPDXID has Ubuntu prefix
		if !strings.HasPrefix(pkg.SPDXID, "SPDXRef-Ubuntu-") {
			pkg.SPDXID = m.renumberSPDXID(pkg.SPDXID, "Ubuntu")
		}

		mergedDoc.Packages = append(mergedDoc.Packages, pkg)

		// Add relationship to system root
		mergedDoc.Relationships = append(mergedDoc.Relationships, spdx.Relationship{
			SPDXElementID:      "SPDXRef-System",
			RelatedSPDXElement: pkg.SPDXID,
			RelationshipType:   "CONTAINS",
		})
		ubuntuCount++
	}

	// Process Nix packages (skip any root packages)
	nixCount := 0
	for _, pkg := range nixDoc.Packages {
		// Skip root/system packages
		if strings.Contains(strings.ToLower(pkg.Name), "system") &&
			(pkg.SPDXID == "SPDXRef-DOCUMENT" || strings.HasSuffix(pkg.SPDXID, "-System")) {
			continue
		}

		// Ensure SPDXID has Nix prefix to avoid conflicts
		if !strings.HasPrefix(pkg.SPDXID, "SPDXRef-Nix-") {
			pkg.SPDXID = m.renumberSPDXID(pkg.SPDXID, "Nix")
		}

		mergedDoc.Packages = append(mergedDoc.Packages, pkg)

		// Add relationship to system root
		mergedDoc.Relationships = append(mergedDoc.Relationships, spdx.Relationship{
			SPDXElementID:      "SPDXRef-System",
			RelatedSPDXElement: pkg.SPDXID,
			RelationshipType:   "CONTAINS",
		})
		nixCount++
	}

	fmt.Printf("Merged %d Ubuntu packages and %d Nix packages\n", ubuntuCount, nixCount)

	return mergedDoc, nil
}

func (m *Merger) loadDocument(path string) (*spdx.Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var doc spdx.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	return &doc, nil
}

func (m *Merger) mergeCreators(ubuntuDoc, nixDoc *spdx.Document) []string {
	creatorMap := make(map[string]bool)
	var creators []string

	// Add creators from both documents
	for _, creator := range ubuntuDoc.CreationInfo.Creators {
		if !creatorMap[creator] {
			creators = append(creators, creator)
			creatorMap[creator] = true
		}
	}

	for _, creator := range nixDoc.CreationInfo.Creators {
		if !creatorMap[creator] {
			creators = append(creators, creator)
			creatorMap[creator] = true
		}
	}

	// Add merger tool
	mergerTool := "Tool: ubuntu-nix-sbom-merger-1.0"
	if !creatorMap[mergerTool] {
		creators = append(creators, mergerTool)
	}

	return creators
}

func (m *Merger) renumberSPDXID(originalID, prefix string) string {
	// Extract the base name from the SPDXID
	re := regexp.MustCompile(`SPDXRef-(.+)`)
	matches := re.FindStringSubmatch(originalID)

	if len(matches) > 1 {
		baseName := matches[1]
		return fmt.Sprintf("SPDXRef-%s-%s", prefix, baseName)
	}

	// Fallback: just add prefix
	return fmt.Sprintf("SPDXRef-%s-%s", prefix, strings.TrimPrefix(originalID, "SPDXRef-"))
}

func (m *Merger) Save(doc *spdx.Document, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(doc)
}

func generateUUID() string {
	// Simple UUID v4 generation
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(time.Now().UnixNano() & 0xff)
	}

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
