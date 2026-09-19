package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestClassifyRepositoryManifestBindsEveryFile(t *testing.T) {
	contents := map[string][]byte{
		"vendor/pkg/x_test.go": []byte("package pkg\n"),
	}
	manifest := mustClassificationManifest(t, classificationFileSpec{path: "vendor/pkg/x_test.go", content: contents["vendor/pkg/x_test.go"]})
	receipt, err := ClassifyRepositoryManifest(manifest, contents)
	if err != nil {
		t.Fatalf("ClassifyRepositoryManifest() error = %v", err)
	}
	child, err := ClassifyRepositoryFile(manifest, "vendor/pkg/x_test.go", contents["vendor/pkg/x_test.go"])
	if err != nil {
		t.Fatalf("ClassifyRepositoryFile() error = %v", err)
	}
	files := receipt.Files()
	lookedUp, ok := receipt.File("vendor/pkg/x_test.go")
	if len(receipt.Identity()) != 64 || receipt.ManifestIdentity() != manifest.Identity() || receipt.ClassifierVersion() != fileClassificationVersion || receipt.FileCount() != 1 {
		t.Fatalf("receipt binding = (%q, %q, %q, %d)", receipt.Identity(), receipt.ManifestIdentity(), receipt.ClassifierVersion(), receipt.FileCount())
	}
	if len(files) != 1 || files[0] != child || !ok || lookedUp != child {
		t.Fatalf("receipt files = (%#v, %#v, %t), want child %#v", files, lookedUp, ok, child)
	}
	if _, ok := receipt.File("missing.go"); ok {
		t.Fatal("File(missing.go) found absent file")
	}
}

func TestRepositoryClassificationReceiptUsesCanonicalOrder(t *testing.T) {
	manifest := mustClassificationManifest(t,
		classificationFileSpec{path: "z/vendor/x_test.go", content: []byte{'x', 0}},
		classificationFileSpec{path: "a/main.go", content: []byte("package a\n")},
	)
	firstContents := make(map[string][]byte)
	firstContents["z/vendor/x_test.go"] = []byte{'x', 0}
	firstContents["a/main.go"] = []byte("package a\n")
	secondContents := make(map[string][]byte)
	secondContents["a/main.go"] = []byte("package a\n")
	secondContents["z/vendor/x_test.go"] = []byte{'x', 0}
	first, err := ClassifyRepositoryManifest(manifest, firstContents)
	if err != nil {
		t.Fatalf("ClassifyRepositoryManifest(first) error = %v", err)
	}
	second, err := ClassifyRepositoryManifest(manifest, secondContents)
	if err != nil {
		t.Fatalf("ClassifyRepositoryManifest(second) error = %v", err)
	}
	if !reflect.DeepEqual(first, second) || first.Files()[0].Path() != "a/main.go" || first.Files()[1].Path() != "z/vendor/x_test.go" {
		t.Fatalf("receipts = (%#v, %#v), want equal canonical order", first, second)
	}
	if first.Files()[0].ContentSignal() != FileContentNULFree || first.Files()[1].ContentSignal() != FileContentContainsNUL || !first.Files()[1].IsVendorPath() || !first.Files()[1].IsGoTestPath() {
		t.Fatalf("child signals = %#v", first.Files())
	}
}

func TestRepositoryClassificationReceiptIdentityUsesCanonicalPreimage(t *testing.T) {
	contents := map[string][]byte{"a.go": []byte("a"), "b.go": []byte("b")}
	manifest := mustClassificationManifest(t,
		classificationFileSpec{path: "b.go", content: contents["b.go"]},
		classificationFileSpec{path: "a.go", content: contents["a.go"]},
	)
	receipt, err := ClassifyRepositoryManifest(manifest, contents)
	if err != nil {
		t.Fatalf("ClassifyRepositoryManifest() error = %v", err)
	}
	files := receipt.Files()
	preimage := fmt.Sprintf(`{"contract":"open-trestle/repository-classification-receipt","schema_version":1,"classifier":"exact-path-and-nul-signals","classifier_version":"1","manifest_identity":"%s","files":[{"path":"a.go","classification_identity":"%s"},{"path":"b.go","classification_identity":"%s"}]}`, manifest.Identity(), files[0].Identity(), files[1].Identity())
	digest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(digest[:]); receipt.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", receipt.Identity(), preimage)
	}
}

func TestClassifyRepositoryManifestAcceptsEmptyManifest(t *testing.T) {
	manifest := mustClassificationManifest(t)
	withNil, err := ClassifyRepositoryManifest(manifest, nil)
	if err != nil {
		t.Fatalf("ClassifyRepositoryManifest(nil) error = %v", err)
	}
	withEmpty, err := ClassifyRepositoryManifest(manifest, map[string][]byte{})
	if err != nil {
		t.Fatalf("ClassifyRepositoryManifest(empty) error = %v", err)
	}
	if !reflect.DeepEqual(withNil, withEmpty) || len(withNil.Identity()) != 64 || withNil.FileCount() != 0 || withNil.Files() == nil || len(withNil.Files()) != 0 {
		t.Fatalf("empty receipts = (%#v, %#v), want equal non-nil empty files", withNil, withEmpty)
	}
}

func TestClassifyRepositoryManifestRejectsInexactContentsBeforeClassification(t *testing.T) {
	manifest := mustClassificationManifest(t,
		classificationFileSpec{path: "a.go", content: []byte("a")},
		classificationFileSpec{path: "b.go", content: []byte("b")},
	)
	testCases := []struct {
		name     string
		contents map[string][]byte
	}{
		{name: "missing", contents: map[string][]byte{"a.go": []byte("a")}},
		{name: "extra", contents: map[string][]byte{"a.go": []byte("a"), "b.go": []byte("b"), "c.go": []byte("c")}},
		{name: "missing and extra", contents: map[string][]byte{"a.go": []byte("a"), "./b.go": []byte("b")}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			calls := 0
			receipt, err := buildRepositoryClassification(manifest, testCase.contents, func(string, evidence.RepositoryFile, []byte) (FileClassificationReceipt, error) {
				calls++
				return FileClassificationReceipt{}, nil
			})
			if err == nil || receipt.Identity() != "" || calls != 0 {
				t.Fatalf("buildRepositoryClassification() = (%#v, %v), calls %d; want zero error result and no calls", receipt, err, calls)
			}
		})
	}
}

func TestClassifyRepositoryManifestRejectsInvalidBinding(t *testing.T) {
	manifest := mustClassificationManifest(t, classificationFileSpec{path: "main.go", content: []byte("content")})
	testCases := []struct {
		name     string
		manifest evidence.RepositoryManifest
		contents map[string][]byte
	}{
		{name: "zero manifest", contents: map[string][]byte{}},
		{name: "wrong bytes", manifest: manifest, contents: map[string][]byte{"main.go": []byte("Content")}},
		{name: "extra bytes", manifest: manifest, contents: map[string][]byte{"main.go": []byte("content\n")}},
		{name: "missing bytes", manifest: manifest, contents: map[string][]byte{"main.go": []byte("conten")}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			receipt, err := ClassifyRepositoryManifest(testCase.manifest, testCase.contents)
			if err == nil || receipt.Identity() != "" {
				t.Fatalf("ClassifyRepositoryManifest() = (%#v, %v), want zero error result", receipt, err)
			}
		})
	}
}

func TestBuildRepositoryClassificationRejectsForgedContentBinding(t *testing.T) {
	manifest := mustClassificationManifest(t, classificationFileSpec{path: "main.go", content: []byte("content")})
	receipt, err := buildRepositoryClassification(manifest, map[string][]byte{"main.go": []byte("Content")}, func(manifestIdentity string, file evidence.RepositoryFile, _ []byte) (FileClassificationReceipt, error) {
		return newFileClassificationReceipt(manifestIdentity, file, FileContentNULFree)
	})
	if err == nil || receipt.Identity() != "" {
		t.Fatalf("buildRepositoryClassification() = (%#v, %v), want zero error result", receipt, err)
	}
}

func TestBuildRepositoryClassificationCallsEachFileOnce(t *testing.T) {
	manifest := mustClassificationManifest(t,
		classificationFileSpec{path: "c.go", content: []byte("c")},
		classificationFileSpec{path: "a.go", content: []byte("a")},
		classificationFileSpec{path: "b.go", content: []byte("b")},
	)
	contents := map[string][]byte{"a.go": []byte("a"), "b.go": []byte("b"), "c.go": []byte("c")}
	var paths []string
	receipt, err := buildRepositoryClassification(manifest, contents, func(manifestIdentity string, file evidence.RepositoryFile, content []byte) (FileClassificationReceipt, error) {
		paths = append(paths, file.Path())
		return classifyValidatedRepositoryFile(manifestIdentity, file, content)
	})
	if err != nil {
		t.Fatalf("buildRepositoryClassification() error = %v", err)
	}
	if want := []string{"a.go", "b.go", "c.go"}; !reflect.DeepEqual(paths, want) || receipt.FileCount() != len(want) {
		t.Fatalf("paths = %v, count %d; want %v", paths, receipt.FileCount(), want)
	}
}

func TestBuildRepositoryClassificationStopsAtChildFailure(t *testing.T) {
	manifest := mustClassificationManifest(t,
		classificationFileSpec{path: "a.go", content: []byte("a")},
		classificationFileSpec{path: "b.go", content: []byte("b")},
		classificationFileSpec{path: "c.go", content: []byte("c")},
	)
	contents := map[string][]byte{"a.go": []byte("a"), "b.go": []byte("b"), "c.go": []byte("c")}
	calls := 0
	receipt, err := buildRepositoryClassification(manifest, contents, func(manifestIdentity string, file evidence.RepositoryFile, content []byte) (FileClassificationReceipt, error) {
		calls++
		if file.Path() == "b.go" {
			return FileClassificationReceipt{}, fmt.Errorf("classification failed")
		}
		return classifyValidatedRepositoryFile(manifestIdentity, file, content)
	})
	if err == nil || receipt.Identity() != "" || calls != 2 {
		t.Fatalf("buildRepositoryClassification() = (%#v, %v), calls %d; want zero error result after two calls", receipt, err, calls)
	}
}

func TestBuildRepositoryClassificationRejectsForgedChild(t *testing.T) {
	content := []byte("package main\n")
	manifest := mustClassificationManifest(t, classificationFileSpec{path: "main.go", content: content})
	file, _ := manifest.File("main.go")
	good, err := classifyValidatedRepositoryFile(manifest.Identity(), file, content)
	if err != nil {
		t.Fatalf("classifyValidatedRepositoryFile() error = %v", err)
	}
	wrongSignal, err := newFileClassificationReceipt(manifest.Identity(), file, FileContentContainsNUL)
	if err != nil {
		t.Fatalf("newFileClassificationReceipt() error = %v", err)
	}
	forgeries := map[string]FileClassificationReceipt{"self-consistent wrong signal": wrongSignal}
	forged := good
	forged.identity = strings.Repeat("0", 64)
	forgeries["identity"] = forged
	forged = good
	forged.manifestIdentity = strings.Repeat("1", 64)
	forgeries["manifest identity"] = forged
	forged = good
	forged.repositoryFileIdentity = strings.Repeat("2", 64)
	forgeries["file identity"] = forged
	forged = good
	forged.path = "other.go"
	forgeries["path"] = forged
	forged = good
	forged.extension = ".txt"
	forgeries["extension"] = forged
	forged = good
	forged.contentSignal = FileContentContainsNUL
	forgeries["signal-derived identity"] = forged
	forged = good
	forged.vendorPath = true
	forgeries["vendor path"] = forged
	forged = good
	forged.goTestPath = true
	forgeries["go test path"] = forged
	forged = good
	forged.classifierVersion = "2"
	forgeries["classifier version"] = forged
	for name, forgedChild := range forgeries {
		t.Run(name, func(t *testing.T) {
			receipt, err := buildRepositoryClassification(manifest, map[string][]byte{"main.go": content}, func(string, evidence.RepositoryFile, []byte) (FileClassificationReceipt, error) {
				return forgedChild, nil
			})
			if err == nil || receipt.Identity() != "" {
				t.Fatalf("buildRepositoryClassification() = (%#v, %v), want zero error result", receipt, err)
			}
		})
	}
}

func TestRepositoryClassificationReceiptIsImmutable(t *testing.T) {
	buffer := []byte("content")
	contents := map[string][]byte{"main.go": buffer}
	manifest := mustClassificationManifest(t, classificationFileSpec{path: "main.go", content: []byte("content")})
	receipt, err := ClassifyRepositoryManifest(manifest, contents)
	if err != nil {
		t.Fatalf("ClassifyRepositoryManifest() error = %v", err)
	}
	identity := receipt.Identity()
	files := receipt.Files()
	files[0] = FileClassificationReceipt{}
	contents["main.go"] = []byte("replacement")
	for i := range buffer {
		buffer[i] = 0
	}
	if receipt.Identity() != identity || receipt.Files()[0].Identity() == "" {
		t.Fatal("caller mutation changed RepositoryClassificationReceipt")
	}
}

func TestRepositoryClassificationReceiptDistinguishesPathsAndContent(t *testing.T) {
	contents := map[string][]byte{"a.go": []byte("same"), "b.go": []byte("same")}
	manifest := mustClassificationManifest(t,
		classificationFileSpec{path: "a.go", content: contents["a.go"]},
		classificationFileSpec{path: "b.go", content: contents["b.go"]},
	)
	first, err := ClassifyRepositoryManifest(manifest, contents)
	if err != nil {
		t.Fatalf("ClassifyRepositoryManifest(first) error = %v", err)
	}
	if first.Files()[0].Identity() == first.Files()[1].Identity() {
		t.Fatal("same bytes at different paths produced equal child identities")
	}
	changedContents := map[string][]byte{"a.go": []byte("Same"), "b.go": []byte("same")}
	changedManifest := mustClassificationManifest(t,
		classificationFileSpec{path: "a.go", content: changedContents["a.go"]},
		classificationFileSpec{path: "b.go", content: changedContents["b.go"]},
	)
	changed, err := ClassifyRepositoryManifest(changedManifest, changedContents)
	if err != nil || changed.Identity() == first.Identity() || changed.Files()[0].Identity() == first.Files()[0].Identity() || changed.Files()[1].RepositoryFileIdentity() != first.Files()[1].RepositoryFileIdentity() {
		t.Fatalf("changed = (%#v, %v), first %#v", changed, err, first)
	}
}

func TestBuildRepositoryClassificationAtFileLimitIsLinear(t *testing.T) {
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
	calls := 0
	receipt, err := buildRepositoryClassification(manifest, contents, func(manifestIdentity string, file evidence.RepositoryFile, _ []byte) (FileClassificationReceipt, error) {
		calls++
		return newFileClassificationReceipt(manifestIdentity, file, FileContentNULFree)
	})
	if err != nil || calls != fileLimit || receipt.FileCount() != fileLimit {
		t.Fatalf("buildRepositoryClassification() = (%d files, %v), calls %d; want %d", receipt.FileCount(), err, calls, fileLimit)
	}
	if receipt.Files()[0].Path() != "files/00000" || receipt.Files()[fileLimit-1].Path() != "files/65535" {
		t.Fatalf("boundary paths = (%q, %q)", receipt.Files()[0].Path(), receipt.Files()[fileLimit-1].Path())
	}
}
