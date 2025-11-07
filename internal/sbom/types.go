package sbom

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"time"
)

type SPDXDocument struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      CreationInfo   `json:"creationInfo"`
	Packages          []Package      `json:"packages"`
	Relationships     []Relationship `json:"relationships"`
}

type CreationInfo struct {
	Created            string   `json:"created"`
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion"`
}

type Package struct {
	SPDXID           string        `json:"SPDXID"`
	Name             string        `json:"name"`
	DownloadLocation string        `json:"downloadLocation"`
	FilesAnalyzed    bool          `json:"filesAnalyzed"`
	VerificationCode *Verification `json:"verificationCode,omitempty"`
	Checksums        []Checksum    `json:"checksums,omitempty"`
	HomePage         string        `json:"homePage,omitempty"`
	LicenseConcluded string        `json:"licenseConcluded"`
	LicenseDeclared  string        `json:"licenseDeclared"`
	CopyrightText    string        `json:"copyrightText"`
	Description      string        `json:"description,omitempty"`
	PackageVersion   string        `json:"versionInfo,omitempty"`
	Supplier         string        `json:"supplier,omitempty"`
	ExternalRefs     []ExternalRef `json:"externalRefs,omitempty"`
}

type Verification struct {
	Value string `json:"packageVerificationCodeValue"`
}

type Checksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}

type Relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

type ExternalRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type DpkgPackage struct {
	Name         string
	Version      string
	Architecture string
	Status       string
	Maintainer   string
	Homepage     string
	Description  string
	License      string
	Copyright    string
}

func GenerateUUID() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(time.Now().UnixNano() & 0xff)
	}

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func HashFile(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return ""
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}
