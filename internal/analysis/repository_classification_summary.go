package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// RepositoryClassificationSummary counts exact signals in a classification receipt.
type RepositoryClassificationSummary struct {
	identity             string
	receiptIdentity      string
	manifestIdentity     string
	classifierVersion    string
	fileCount            int
	nulFreeFileCount     int
	containsNULFileCount int
	vendorPathFileCount  int
	goTestPathFileCount  int
}

// NewRepositoryClassificationSummary summarizes a structurally valid manifest receipt.
func NewRepositoryClassificationSummary(manifest evidence.RepositoryManifest, receipt RepositoryClassificationReceipt) (RepositoryClassificationSummary, error) {
	canonicalManifest, err := evidence.NewRepositoryManifest(manifest.Files())
	if err != nil || canonicalManifest.Identity() != manifest.Identity() {
		return RepositoryClassificationSummary{}, fmt.Errorf("repository manifest is not canonical")
	}
	if receipt.ManifestIdentity() != canonicalManifest.Identity() {
		return RepositoryClassificationSummary{}, fmt.Errorf("classification receipt does not bind the repository manifest")
	}
	if receipt.ClassifierVersion() != fileClassificationVersion {
		return RepositoryClassificationSummary{}, fmt.Errorf("unsupported classifier version %q", receipt.ClassifierVersion())
	}
	if receipt.files == nil {
		return RepositoryClassificationSummary{}, fmt.Errorf("classification receipt files are not canonical")
	}
	manifestFiles := canonicalManifest.Files()
	classifiedFiles := receipt.Files()
	if len(classifiedFiles) != len(manifestFiles) || receipt.FileCount() != canonicalManifest.FileCount() {
		return RepositoryClassificationSummary{}, fmt.Errorf("classification receipt has %d files, want %d", len(classifiedFiles), len(manifestFiles))
	}
	for i, manifestFile := range manifestFiles {
		classifiedFile := classifiedFiles[i]
		if classifiedFile.Path() != manifestFile.Path() || classifiedFile.RepositoryFileIdentity() != manifestFile.Identity() || classifiedFile.ManifestIdentity() != canonicalManifest.Identity() {
			return RepositoryClassificationSummary{}, fmt.Errorf("classification receipt file %d does not match manifest path %q", i, manifestFile.Path())
		}
		expected, err := newFileClassificationReceipt(canonicalManifest.Identity(), manifestFile, classifiedFile.ContentSignal())
		if err != nil || classifiedFile != expected {
			return RepositoryClassificationSummary{}, fmt.Errorf("classification receipt file %q is not canonical", manifestFile.Path())
		}
	}
	expectedReceipt, err := newRepositoryClassificationReceipt(canonicalManifest.Identity(), classifiedFiles)
	if err != nil || receipt.Identity() != expectedReceipt.Identity() || receipt.ManifestIdentity() != expectedReceipt.ManifestIdentity() || receipt.ClassifierVersion() != expectedReceipt.ClassifierVersion() {
		return RepositoryClassificationSummary{}, fmt.Errorf("repository classification receipt is not canonical")
	}
	nulFreeFileCount := 0
	containsNULFileCount := 0
	vendorPathFileCount := 0
	goTestPathFileCount := 0
	for _, file := range classifiedFiles {
		switch file.ContentSignal() {
		case FileContentNULFree:
			nulFreeFileCount++
		case FileContentContainsNUL:
			containsNULFileCount++
		default:
			return RepositoryClassificationSummary{}, fmt.Errorf("unsupported file content signal %q", file.ContentSignal())
		}
		if file.IsVendorPath() {
			vendorPathFileCount++
		}
		if file.IsGoTestPath() {
			goTestPathFileCount++
		}
	}
	if nulFreeFileCount+containsNULFileCount != len(classifiedFiles) {
		return RepositoryClassificationSummary{}, fmt.Errorf("file content signals do not partition classified files")
	}
	preimage := struct {
		Contract             string `json:"contract"`
		SchemaVersion        int    `json:"schema_version"`
		ReceiptIdentity      string `json:"receipt_identity"`
		ManifestIdentity     string `json:"manifest_identity"`
		Classifier           string `json:"classifier"`
		ClassifierVersion    string `json:"classifier_version"`
		FileCount            int    `json:"file_count"`
		NULFreeFileCount     int    `json:"nul_free_file_count"`
		ContainsNULFileCount int    `json:"contains_nul_file_count"`
		VendorPathFileCount  int    `json:"vendor_path_file_count"`
		GoTestPathFileCount  int    `json:"go_test_path_file_count"`
	}{
		Contract:             "open-trestle/repository-classification-summary",
		SchemaVersion:        1,
		ReceiptIdentity:      receipt.Identity(),
		ManifestIdentity:     canonicalManifest.Identity(),
		Classifier:           fileClassificationName,
		ClassifierVersion:    fileClassificationVersion,
		FileCount:            len(classifiedFiles),
		NULFreeFileCount:     nulFreeFileCount,
		ContainsNULFileCount: containsNULFileCount,
		VendorPathFileCount:  vendorPathFileCount,
		GoTestPathFileCount:  goTestPathFileCount,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RepositoryClassificationSummary{}, fmt.Errorf("encode repository classification summary identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return RepositoryClassificationSummary{
		identity:             hex.EncodeToString(digest[:]),
		receiptIdentity:      receipt.Identity(),
		manifestIdentity:     canonicalManifest.Identity(),
		classifierVersion:    fileClassificationVersion,
		fileCount:            len(classifiedFiles),
		nulFreeFileCount:     nulFreeFileCount,
		containsNULFileCount: containsNULFileCount,
		vendorPathFileCount:  vendorPathFileCount,
		goTestPathFileCount:  goTestPathFileCount,
	}, nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (s RepositoryClassificationSummary) Identity() string {
	return s.identity
}

// ReceiptIdentity returns the exact source classification receipt identity.
func (s RepositoryClassificationSummary) ReceiptIdentity() string {
	return s.receiptIdentity
}

// ManifestIdentity returns the exact source manifest identity.
func (s RepositoryClassificationSummary) ManifestIdentity() string {
	return s.manifestIdentity
}

// ClassifierVersion returns the identity-bound classifier version.
func (s RepositoryClassificationSummary) ClassifierVersion() string {
	return s.classifierVersion
}

// FileCount returns the number of classified files.
func (s RepositoryClassificationSummary) FileCount() int {
	return s.fileCount
}

// NULFreeFileCount returns the number of files without a NUL byte.
func (s RepositoryClassificationSummary) NULFreeFileCount() int {
	return s.nulFreeFileCount
}

// ContainsNULFileCount returns the number of files with a NUL byte.
func (s RepositoryClassificationSummary) ContainsNULFileCount() int {
	return s.containsNULFileCount
}

// VendorPathFileCount returns the number of files with a lowercase vendor segment.
func (s RepositoryClassificationSummary) VendorPathFileCount() int {
	return s.vendorPathFileCount
}

// GoTestPathFileCount returns the number of files whose basename ends in _test.go.
func (s RepositoryClassificationSummary) GoTestPathFileCount() int {
	return s.goTestPathFileCount
}
