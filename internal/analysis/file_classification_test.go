package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestClassifyRepositoryFileRecordsExactSignals(t *testing.T) {
	content := []byte("package worker\n")
	manifest := mustClassificationManifest(t, classificationFileSpec{path: "src/main.go", content: content})
	receipt, err := ClassifyRepositoryFile(manifest, "src/main.go", content)
	if err != nil {
		t.Fatalf("ClassifyRepositoryFile() error = %v", err)
	}
	file, _ := manifest.File("src/main.go")
	if len(receipt.Identity()) != 64 || receipt.ManifestIdentity() != manifest.Identity() || receipt.RepositoryFileIdentity() != file.Identity() || receipt.Path() != "src/main.go" {
		t.Fatalf("receipt binding = (%q, %q, %q, %q)", receipt.Identity(), receipt.ManifestIdentity(), receipt.RepositoryFileIdentity(), receipt.Path())
	}
	if receipt.Extension() != ".go" || receipt.ContentSignal() != FileContentNULFree || receipt.IsVendorPath() || receipt.IsGoTestPath() || receipt.ClassifierVersion() != fileClassificationVersion {
		t.Fatalf("receipt signals = (%q, %q, %t, %t, %q)", receipt.Extension(), receipt.ContentSignal(), receipt.IsVendorPath(), receipt.IsGoTestPath(), receipt.ClassifierVersion())
	}
}

func TestFileClassificationReceiptIdentityUsesCanonicalPreimage(t *testing.T) {
	content := []byte("package worker\n")
	path := "vendor/pkg/x_test.go"
	manifest := mustClassificationManifest(t, classificationFileSpec{path: path, content: content})
	receipt, err := ClassifyRepositoryFile(manifest, path, content)
	if err != nil {
		t.Fatalf("ClassifyRepositoryFile() error = %v", err)
	}
	file, _ := manifest.File(path)
	preimage := fmt.Sprintf(`{"contract":"open-trestle/file-classification-receipt","schema_version":1,"classifier":"exact-path-and-nul-signals","classifier_version":"1","manifest_identity":"%s","repository_file_identity":"%s","path":"vendor/pkg/x_test.go","extension":".go","content_signal":"nul_free","vendor_path":true,"go_test_path":true}`, manifest.Identity(), file.Identity())
	digest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(digest[:]); receipt.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", receipt.Identity(), preimage)
	}
}

func TestClassifyRepositoryFileDetectsExactGoTestSuffix(t *testing.T) {
	testCases := []struct {
		path string
		want bool
	}{
		{path: "x_test.go", want: true},
		{path: "nested/_test.go", want: true},
		{path: "x_test.GO"},
		{path: "test.go"},
		{path: "x_test.go.txt"},
		{path: "x_Test.go"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.path, func(t *testing.T) {
			content := []byte("x")
			manifest := mustClassificationManifest(t, classificationFileSpec{path: testCase.path, content: content})
			receipt, err := ClassifyRepositoryFile(manifest, testCase.path, content)
			if err != nil || receipt.IsGoTestPath() != testCase.want {
				t.Fatalf("ClassifyRepositoryFile() = (%#v, %v), want go test %t", receipt, err, testCase.want)
			}
		})
	}
}

func TestClassifyRepositoryFileDetectsExactVendorSegment(t *testing.T) {
	testCases := []struct {
		path string
		want bool
	}{
		{path: "vendor/x.go", want: true},
		{path: "a/vendor/x.go", want: true},
		{path: "vendor", want: true},
		{path: "a/vendor", want: true},
		{path: "Vendor/x.go"},
		{path: ".vendor/x.go"},
		{path: "vendorized/x.go"},
		{path: "pkg/vendor.go"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.path, func(t *testing.T) {
			content := []byte("x")
			manifest := mustClassificationManifest(t, classificationFileSpec{path: testCase.path, content: content})
			receipt, err := ClassifyRepositoryFile(manifest, testCase.path, content)
			if err != nil || receipt.IsVendorPath() != testCase.want {
				t.Fatalf("ClassifyRepositoryFile() = (%#v, %v), want vendor %t", receipt, err, testCase.want)
			}
		})
	}
}

func TestClassifyRepositoryFileDetectsNULBytes(t *testing.T) {
	testCases := []struct {
		name    string
		content []byte
		want    FileContentSignal
	}{
		{name: "empty", want: FileContentNULFree},
		{name: "invalid UTF-8", content: []byte{0xff, 0xfe}, want: FileContentNULFree},
		{name: "first", content: []byte{0, 'a'}, want: FileContentContainsNUL},
		{name: "middle", content: []byte{'a', 0, 'b'}, want: FileContentContainsNUL},
		{name: "last", content: []byte{'a', 0}, want: FileContentContainsNUL},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			manifest := mustClassificationManifest(t, classificationFileSpec{path: "asset.bin", content: testCase.content})
			receipt, err := ClassifyRepositoryFile(manifest, "asset.bin", testCase.content)
			if err != nil || receipt.ContentSignal() != testCase.want {
				t.Fatalf("ClassifyRepositoryFile() = (%#v, %v), want %q", receipt, err, testCase.want)
			}
		})
	}
}

func TestClassifyRepositoryFilePreservesPathExtension(t *testing.T) {
	testCases := []struct {
		path string
		want string
	}{
		{path: "main.go", want: ".go"},
		{path: "main.GO", want: ".GO"},
		{path: "archive.tar.gz", want: ".gz"},
		{path: ".gitignore", want: ".gitignore"},
		{path: "trailing.", want: "."},
		{path: "LICENSE"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.path, func(t *testing.T) {
			content := []byte("x")
			manifest := mustClassificationManifest(t, classificationFileSpec{path: testCase.path, content: content})
			receipt, err := ClassifyRepositoryFile(manifest, testCase.path, content)
			if err != nil || receipt.Extension() != testCase.want {
				t.Fatalf("ClassifyRepositoryFile() = (%#v, %v), want extension %q", receipt, err, testCase.want)
			}
		})
	}
}

func TestFileClassificationReceiptBindsManifestAndContent(t *testing.T) {
	content := []byte("same")
	firstManifest := mustClassificationManifest(t, classificationFileSpec{path: "main.go", content: content})
	secondManifest := mustClassificationManifest(t,
		classificationFileSpec{path: "main.go", content: content},
		classificationFileSpec{path: "other.txt", content: []byte("other")},
	)
	first, err := ClassifyRepositoryFile(firstManifest, "main.go", content)
	if err != nil {
		t.Fatalf("ClassifyRepositoryFile(first) error = %v", err)
	}
	second, err := ClassifyRepositoryFile(secondManifest, "main.go", content)
	if err != nil || second.Identity() == first.Identity() || second.RepositoryFileIdentity() != first.RepositoryFileIdentity() {
		t.Fatalf("second = (%#v, %v), first %#v", second, err, first)
	}
	changedContent := []byte{'s', 'a', 0, 'e'}
	changedManifest := mustClassificationManifest(t, classificationFileSpec{path: "main.go", content: changedContent})
	changed, err := ClassifyRepositoryFile(changedManifest, "main.go", changedContent)
	if err != nil || changed.Identity() == first.Identity() || changed.RepositoryFileIdentity() == first.RepositoryFileIdentity() || changed.ContentSignal() != FileContentContainsNUL {
		t.Fatalf("changed = (%#v, %v), first %#v", changed, err, first)
	}
}

func TestClassifyRepositoryFileRejectsInvalidBinding(t *testing.T) {
	content := []byte("content")
	manifest := mustClassificationManifest(t, classificationFileSpec{path: "main.go", content: content})
	testCases := []struct {
		name     string
		manifest evidence.RepositoryManifest
		path     string
		content  []byte
	}{
		{name: "zero manifest", path: "main.go", content: content},
		{name: "missing path", manifest: manifest, path: "other.go", content: content},
		{name: "empty path", manifest: manifest, content: content},
		{name: "unclean path", manifest: manifest, path: "./main.go", content: content},
		{name: "wrong bytes", manifest: manifest, path: "main.go", content: []byte("Content")},
		{name: "extra bytes", manifest: manifest, path: "main.go", content: []byte("content\n")},
		{name: "missing bytes", manifest: manifest, path: "main.go", content: []byte("conten")},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			receipt, err := ClassifyRepositoryFile(testCase.manifest, testCase.path, testCase.content)
			if err == nil || receipt.Identity() != "" {
				t.Fatalf("ClassifyRepositoryFile() = (%#v, %v), want zero error result", receipt, err)
			}
		})
	}
}

func TestFileClassificationReceiptDoesNotRetainContent(t *testing.T) {
	content := []byte("content")
	manifest := mustClassificationManifest(t, classificationFileSpec{path: "main.go", content: content})
	receipt, err := ClassifyRepositoryFile(manifest, "main.go", content)
	if err != nil {
		t.Fatalf("ClassifyRepositoryFile() error = %v", err)
	}
	identity := receipt.Identity()
	for i := range content {
		content[i] = 0
	}
	if receipt.Identity() != identity || receipt.ContentSignal() != FileContentNULFree {
		t.Fatal("caller mutation changed FileClassificationReceipt")
	}
	repeated, err := ClassifyRepositoryFile(manifest, "main.go", []byte("content"))
	if err != nil || repeated != receipt {
		t.Fatalf("repeated = (%#v, %v), want %#v", repeated, err, receipt)
	}
}

type classificationFileSpec struct {
	path    string
	content []byte
}

func mustClassificationManifest(t *testing.T, specs ...classificationFileSpec) evidence.RepositoryManifest {
	t.Helper()
	files := make([]evidence.RepositoryFile, len(specs))
	for i, spec := range specs {
		file, err := evidence.NewRepositoryFile(spec.path, spec.content)
		if err != nil {
			t.Fatalf("NewRepositoryFile() error = %v", err)
		}
		files[i] = file
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	if err != nil {
		t.Fatalf("NewRepositoryManifest() error = %v", err)
	}
	return manifest
}
