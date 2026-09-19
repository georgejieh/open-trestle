package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestNewRepositoryClassificationSummaryCountsExactSignals(t *testing.T) {
	manifest, receipt := mustRepositoryClassification(t,
		classificationFileSpec{path: "a.go", content: []byte("a")},
		classificationFileSpec{path: "vendor/b_test.go", content: []byte{'b', 0}},
		classificationFileSpec{path: "c_test.go", content: []byte("c")},
		classificationFileSpec{path: "vendor/d.bin", content: []byte("d")},
	)
	summary, err := NewRepositoryClassificationSummary(manifest, receipt)
	if err != nil {
		t.Fatalf("NewRepositoryClassificationSummary() error = %v", err)
	}
	if len(summary.Identity()) != 64 || summary.ReceiptIdentity() != receipt.Identity() || summary.ManifestIdentity() != manifest.Identity() || summary.ClassifierVersion() != fileClassificationVersion {
		t.Fatalf("summary binding = (%q, %q, %q, %q)", summary.Identity(), summary.ReceiptIdentity(), summary.ManifestIdentity(), summary.ClassifierVersion())
	}
	if summary.FileCount() != 4 || summary.NULFreeFileCount() != 3 || summary.ContainsNULFileCount() != 1 || summary.VendorPathFileCount() != 2 || summary.GoTestPathFileCount() != 2 {
		t.Fatalf("summary counts = (%d, %d, %d, %d, %d)", summary.FileCount(), summary.NULFreeFileCount(), summary.ContainsNULFileCount(), summary.VendorPathFileCount(), summary.GoTestPathFileCount())
	}
	if summary.NULFreeFileCount()+summary.ContainsNULFileCount() != summary.FileCount() {
		t.Fatal("NUL signal counts do not partition classified files")
	}
}

func TestRepositoryClassificationSummaryIdentityUsesCanonicalPreimage(t *testing.T) {
	manifest, receipt := mustRepositoryClassification(t,
		classificationFileSpec{path: "main.go", content: []byte("package main\n")},
	)
	summary, err := NewRepositoryClassificationSummary(manifest, receipt)
	if err != nil {
		t.Fatalf("NewRepositoryClassificationSummary() error = %v", err)
	}
	preimage := fmt.Sprintf(`{"contract":"open-trestle/repository-classification-summary","schema_version":1,"receipt_identity":"%s","manifest_identity":"%s","classifier":"exact-path-and-nul-signals","classifier_version":"1","file_count":1,"nul_free_file_count":1,"contains_nul_file_count":0,"vendor_path_file_count":0,"go_test_path_file_count":0}`, receipt.Identity(), manifest.Identity())
	digest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(digest[:]); summary.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", summary.Identity(), preimage)
	}
}

func TestNewRepositoryClassificationSummaryAcceptsEmptyReceipt(t *testing.T) {
	manifest, receipt := mustRepositoryClassification(t)
	first, err := NewRepositoryClassificationSummary(manifest, receipt)
	if err != nil {
		t.Fatalf("NewRepositoryClassificationSummary(first) error = %v", err)
	}
	second, err := NewRepositoryClassificationSummary(manifest, receipt)
	if err != nil {
		t.Fatalf("NewRepositoryClassificationSummary(second) error = %v", err)
	}
	if first != second || len(first.Identity()) != 64 || first.FileCount() != 0 || first.NULFreeFileCount() != 0 || first.ContainsNULFileCount() != 0 || first.VendorPathFileCount() != 0 || first.GoTestPathFileCount() != 0 {
		t.Fatalf("empty summaries = (%#v, %#v)", first, second)
	}
}

func TestNewRepositoryClassificationSummaryRejectsInvalidRootBinding(t *testing.T) {
	manifest, receipt := mustRepositoryClassification(t, classificationFileSpec{path: "main.go", content: []byte("main")})
	otherManifest, _ := mustRepositoryClassification(t, classificationFileSpec{path: "other.go", content: []byte("other")})
	wrongManifestReceipt := cloneRepositoryClassificationReceipt(receipt)
	wrongManifestReceipt.manifestIdentity = strings.Repeat("a", 64)
	forgedIdentityReceipt := cloneRepositoryClassificationReceipt(receipt)
	forgedIdentityReceipt.identity = strings.Repeat("b", 64)
	wrongVersionReceipt := cloneRepositoryClassificationReceipt(receipt)
	wrongVersionReceipt.classifierVersion = "2"
	testCases := []struct {
		name     string
		manifest evidence.RepositoryManifest
		receipt  RepositoryClassificationReceipt
	}{
		{name: "zero manifest", receipt: receipt},
		{name: "zero receipt", manifest: manifest},
		{name: "different manifest", manifest: otherManifest, receipt: receipt},
		{name: "wrong manifest identity", manifest: manifest, receipt: wrongManifestReceipt},
		{name: "forged receipt identity", manifest: manifest, receipt: forgedIdentityReceipt},
		{name: "wrong classifier version", manifest: manifest, receipt: wrongVersionReceipt},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			summary, err := NewRepositoryClassificationSummary(testCase.manifest, testCase.receipt)
			if err == nil || summary.Identity() != "" {
				t.Fatalf("NewRepositoryClassificationSummary() = (%#v, %v), want zero error result", summary, err)
			}
		})
	}
}

func TestNewRepositoryClassificationSummaryRejectsCoverageForgeries(t *testing.T) {
	manifest, receipt := mustRepositoryClassification(t,
		classificationFileSpec{path: "a.go", content: []byte("a")},
		classificationFileSpec{path: "b.go", content: []byte("b")},
	)
	missing := cloneRepositoryClassificationReceipt(receipt)
	missing.files = missing.files[:1]
	missing = mustRebuildRepositoryClassificationReceipt(t, missing)
	extra := cloneRepositoryClassificationReceipt(receipt)
	extra.files = append(extra.files, extra.files[1])
	extra = mustRebuildRepositoryClassificationReceipt(t, extra)
	reordered := cloneRepositoryClassificationReceipt(receipt)
	reordered.files[0], reordered.files[1] = reordered.files[1], reordered.files[0]
	reordered = mustRebuildRepositoryClassificationReceipt(t, reordered)
	duplicate := cloneRepositoryClassificationReceipt(receipt)
	duplicate.files[1] = duplicate.files[0]
	duplicate = mustRebuildRepositoryClassificationReceipt(t, duplicate)
	for name, forged := range map[string]RepositoryClassificationReceipt{
		"missing child":   missing,
		"extra child":     extra,
		"reordered child": reordered,
		"duplicate child": duplicate,
	} {
		t.Run(name, func(t *testing.T) {
			summary, err := NewRepositoryClassificationSummary(manifest, forged)
			if err == nil || summary.Identity() != "" {
				t.Fatalf("NewRepositoryClassificationSummary() = (%#v, %v), want zero error result", summary, err)
			}
		})
	}
}

func TestNewRepositoryClassificationSummaryRejectsChildForgeries(t *testing.T) {
	manifest, receipt := mustRepositoryClassification(t, classificationFileSpec{path: "main.go", content: []byte("main")})
	forgeries := map[string]FileClassificationReceipt{}
	forged := receipt.files[0]
	forged.identity = strings.Repeat("0", 64)
	forgeries["identity"] = forged
	forged = receipt.files[0]
	forged.manifestIdentity = strings.Repeat("1", 64)
	forgeries["manifest identity"] = forged
	forged = receipt.files[0]
	forged.repositoryFileIdentity = strings.Repeat("2", 64)
	forgeries["file identity"] = forged
	forged = receipt.files[0]
	forged.path = "other.go"
	forgeries["path"] = forged
	forged = receipt.files[0]
	forged.extension = ".txt"
	forgeries["extension"] = forged
	forged = receipt.files[0]
	forged.vendorPath = true
	forgeries["vendor path"] = forged
	forged = receipt.files[0]
	forged.goTestPath = true
	forgeries["go test path"] = forged
	forged = receipt.files[0]
	forged.classifierVersion = "2"
	forgeries["classifier version"] = forged
	forged = receipt.files[0]
	forged.contentSignal = FileContentSignal("unknown")
	forgeries["content signal"] = forged
	for name, forgedChild := range forgeries {
		t.Run(name, func(t *testing.T) {
			forgedReceipt := cloneRepositoryClassificationReceipt(receipt)
			forgedReceipt.files[0] = forgedChild
			forgedReceipt = mustRebuildRepositoryClassificationReceipt(t, forgedReceipt)
			summary, err := NewRepositoryClassificationSummary(manifest, forgedReceipt)
			if err == nil || summary.Identity() != "" {
				t.Fatalf("NewRepositoryClassificationSummary() = (%#v, %v), want zero error result", summary, err)
			}
		})
	}
}

func TestNewRepositoryClassificationSummaryRejectsStaleAggregateIdentity(t *testing.T) {
	manifest, receipt := mustRepositoryClassification(t, classificationFileSpec{path: "main.go", content: []byte("main")})
	file, _ := manifest.File("main.go")
	changedChild, err := newFileClassificationReceipt(manifest.Identity(), file, FileContentContainsNUL)
	if err != nil {
		t.Fatalf("newFileClassificationReceipt() error = %v", err)
	}
	forged := cloneRepositoryClassificationReceipt(receipt)
	forged.files[0] = changedChild
	summary, err := NewRepositoryClassificationSummary(manifest, forged)
	if err == nil || summary.Identity() != "" {
		t.Fatalf("NewRepositoryClassificationSummary() = (%#v, %v), want zero error result", summary, err)
	}
}

func TestRepositoryClassificationSummaryCountsStructurallyValidSignals(t *testing.T) {
	manifest, receipt := mustRepositoryClassification(t, classificationFileSpec{path: "main.go", content: []byte("main")})
	file, _ := manifest.File("main.go")
	changedChild, err := newFileClassificationReceipt(manifest.Identity(), file, FileContentContainsNUL)
	if err != nil {
		t.Fatalf("newFileClassificationReceipt() error = %v", err)
	}
	structuralReceipt := cloneRepositoryClassificationReceipt(receipt)
	structuralReceipt.files[0] = changedChild
	structuralReceipt = mustRebuildRepositoryClassificationReceipt(t, structuralReceipt)
	summary, err := NewRepositoryClassificationSummary(manifest, structuralReceipt)
	if err != nil {
		t.Fatalf("NewRepositoryClassificationSummary() error = %v", err)
	}
	if summary.NULFreeFileCount() != 0 || summary.ContainsNULFileCount() != 1 {
		t.Fatalf("signal counts = (%d, %d), want (0, 1)", summary.NULFreeFileCount(), summary.ContainsNULFileCount())
	}
}

func TestRepositoryClassificationSummaryChangesWithAcceptedSignals(t *testing.T) {
	firstManifest, firstReceipt := mustRepositoryClassification(t, classificationFileSpec{path: "asset.bin", content: []byte("asset")})
	first, err := NewRepositoryClassificationSummary(firstManifest, firstReceipt)
	if err != nil {
		t.Fatalf("NewRepositoryClassificationSummary(first) error = %v", err)
	}
	changedManifest, changedReceipt := mustRepositoryClassification(t, classificationFileSpec{path: "asset.bin", content: []byte{'a', 0}})
	changed, err := NewRepositoryClassificationSummary(changedManifest, changedReceipt)
	if err != nil {
		t.Fatalf("NewRepositoryClassificationSummary(changed) error = %v", err)
	}
	if changed.Identity() == first.Identity() || changed.ReceiptIdentity() == first.ReceiptIdentity() || changed.NULFreeFileCount() != 0 || changed.ContainsNULFileCount() != 1 {
		t.Fatalf("changed summary = %#v, first %#v", changed, first)
	}
}

func TestRepositoryClassificationSummaryIsImmutable(t *testing.T) {
	manifest, receipt := mustRepositoryClassification(t, classificationFileSpec{path: "main.go", content: []byte("main")})
	summary, err := NewRepositoryClassificationSummary(manifest, receipt)
	if err != nil {
		t.Fatalf("NewRepositoryClassificationSummary() error = %v", err)
	}
	identity := summary.Identity()
	receipt.files[0] = FileClassificationReceipt{}
	if summary.Identity() != identity || summary.FileCount() != 1 || summary.NULFreeFileCount() != 1 {
		t.Fatal("input mutation changed RepositoryClassificationSummary")
	}
}

func TestRepositoryClassificationSummaryAtFileLimit(t *testing.T) {
	const fileLimit = 65_536
	files := make([]evidence.RepositoryFile, fileLimit)
	contents := make(map[string][]byte, fileLimit)
	for i := range files {
		filePath := fmt.Sprintf("files/%05d", i)
		file, err := evidence.NewRepositoryFile(filePath, nil)
		if err != nil {
			t.Fatalf("NewRepositoryFile(%d) error = %v", i, err)
		}
		files[i] = file
		contents[filePath] = nil
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	if err != nil {
		t.Fatalf("NewRepositoryManifest() error = %v", err)
	}
	receipt, err := ClassifyRepositoryManifest(manifest, contents)
	if err != nil {
		t.Fatalf("ClassifyRepositoryManifest() error = %v", err)
	}
	summary, err := NewRepositoryClassificationSummary(manifest, receipt)
	if err != nil {
		t.Fatalf("NewRepositoryClassificationSummary() error = %v", err)
	}
	if summary.FileCount() != fileLimit || summary.NULFreeFileCount() != fileLimit || summary.ContainsNULFileCount() != 0 || summary.VendorPathFileCount() != 0 || summary.GoTestPathFileCount() != 0 {
		t.Fatalf("boundary counts = (%d, %d, %d, %d, %d)", summary.FileCount(), summary.NULFreeFileCount(), summary.ContainsNULFileCount(), summary.VendorPathFileCount(), summary.GoTestPathFileCount())
	}
	missing := cloneRepositoryClassificationReceipt(receipt)
	missing.files = missing.files[:fileLimit-1]
	missing = mustRebuildRepositoryClassificationReceipt(t, missing)
	if result, err := NewRepositoryClassificationSummary(manifest, missing); err == nil || result.Identity() != "" {
		t.Fatalf("missing boundary child = (%#v, %v), want zero error result", result, err)
	}
	extra := cloneRepositoryClassificationReceipt(receipt)
	extra.files = append(extra.files, extra.files[fileLimit-1])
	extra = mustRebuildRepositoryClassificationReceipt(t, extra)
	if result, err := NewRepositoryClassificationSummary(manifest, extra); err == nil || result.Identity() != "" {
		t.Fatalf("extra boundary child = (%#v, %v), want zero error result", result, err)
	}
}

func mustRepositoryClassification(t *testing.T, specs ...classificationFileSpec) (evidence.RepositoryManifest, RepositoryClassificationReceipt) {
	t.Helper()
	manifest := mustClassificationManifest(t, specs...)
	contents := make(map[string][]byte, len(specs))
	for _, spec := range specs {
		contents[spec.path] = spec.content
	}
	receipt, err := ClassifyRepositoryManifest(manifest, contents)
	if err != nil {
		t.Fatalf("ClassifyRepositoryManifest() error = %v", err)
	}
	return manifest, receipt
}

func cloneRepositoryClassificationReceipt(receipt RepositoryClassificationReceipt) RepositoryClassificationReceipt {
	receipt.files = append([]FileClassificationReceipt{}, receipt.files...)
	return receipt
}

func mustRebuildRepositoryClassificationReceipt(t *testing.T, receipt RepositoryClassificationReceipt) RepositoryClassificationReceipt {
	t.Helper()
	rebuilt, err := newRepositoryClassificationReceipt(receipt.manifestIdentity, receipt.files)
	if err != nil {
		t.Fatalf("newRepositoryClassificationReceipt() error = %v", err)
	}
	return rebuilt
}
