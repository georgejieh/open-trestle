package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestNewRepositoryFileRecordsExactContentMetadata(t *testing.T) {
	content := []byte("package worker\n")
	file, err := NewRepositoryFile("src/main.go", content)
	if err != nil {
		t.Fatalf("NewRepositoryFile() error = %v", err)
	}
	digest := sha256.Sum256(content)
	wantDigest := hex.EncodeToString(digest[:])
	if len(file.Identity()) != 64 || file.Path() != "src/main.go" || file.Digest() != wantDigest || file.SizeBytes() != len(content) {
		t.Fatalf("RepositoryFile = (%q, %q, %q, %d)", file.Identity(), file.Path(), file.Digest(), file.SizeBytes())
	}
	repeated, err := NewRepositoryFile("src/main.go", append([]byte(nil), content...))
	if err != nil || repeated != file {
		t.Fatalf("repeated = (%#v, %v), want %#v", repeated, err, file)
	}
}

func TestRepositoryFileIdentityUsesCanonicalPreimage(t *testing.T) {
	content := []byte("hello\n")
	file, err := NewRepositoryFile("README.md", content)
	if err != nil {
		t.Fatalf("NewRepositoryFile() error = %v", err)
	}
	digest := sha256.Sum256(content)
	contentDigest := hex.EncodeToString(digest[:])
	preimage := fmt.Sprintf(`{"contract":"open-trestle/repository-file","schema_version":1,"path":"README.md","digest":"%s","size_bytes":6}`, contentDigest)
	identityDigest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(identityDigest[:]); file.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", file.Identity(), preimage)
	}
}

func TestNewRepositoryFileAcceptsEmptyAndBinaryContent(t *testing.T) {
	testCases := []struct {
		name    string
		content []byte
	}{
		{name: "empty"},
		{name: "NUL", content: []byte{0, 1, 2, 3}},
		{name: "invalid UTF-8", content: []byte{0xff, 0xfe, 0xfd}},
		{name: "mixed binary", content: []byte{'a', 0, '\n', 0xff}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			file, err := NewRepositoryFile("asset.bin", testCase.content)
			if err != nil {
				t.Fatalf("NewRepositoryFile() error = %v", err)
			}
			digest := sha256.Sum256(testCase.content)
			if file.Digest() != hex.EncodeToString(digest[:]) || file.SizeBytes() != len(testCase.content) || file.Identity() == "" {
				t.Fatalf("RepositoryFile = %#v", file)
			}
			repeated, err := NewRepositoryFile("asset.bin", append([]byte(nil), testCase.content...))
			if err != nil || repeated != file {
				t.Fatalf("repeated = (%#v, %v), want %#v", repeated, err, file)
			}
		})
	}
}

func TestRepositoryFilePreservesEveryContentByte(t *testing.T) {
	contents := [][]byte{
		[]byte("line\n"),
		[]byte("line\r\n"),
		[]byte("line"),
		[]byte("line\n\n"),
		[]byte("Line\n"),
	}
	seenDigests := make(map[string]struct{}, len(contents))
	seenIdentities := make(map[string]struct{}, len(contents))
	for _, content := range contents {
		file, err := NewRepositoryFile("file.txt", content)
		if err != nil {
			t.Fatalf("NewRepositoryFile() error = %v", err)
		}
		if _, exists := seenDigests[file.Digest()]; exists {
			t.Fatalf("duplicate digest for %q", content)
		}
		if _, exists := seenIdentities[file.Identity()]; exists {
			t.Fatalf("duplicate identity for %q", content)
		}
		seenDigests[file.Digest()] = struct{}{}
		seenIdentities[file.Identity()] = struct{}{}
	}
}

func TestRepositoryFileIdentityBindsPath(t *testing.T) {
	content := []byte("same bytes")
	first, err := NewRepositoryFile("a/file.txt", content)
	if err != nil {
		t.Fatalf("NewRepositoryFile(first) error = %v", err)
	}
	second, err := NewRepositoryFile("b/file.txt", content)
	if err != nil {
		t.Fatalf("NewRepositoryFile(second) error = %v", err)
	}
	if first.Digest() != second.Digest() || first.SizeBytes() != second.SizeBytes() || first.Identity() == second.Identity() {
		t.Fatalf("path variants = (%#v, %#v)", first, second)
	}
}

func TestNewRepositoryFileValidatesPath(t *testing.T) {
	invalidUTF8 := string([]byte{'b', 'a', 'd', 0xff})
	invalidPaths := []string{
		"",
		"/absolute",
		"../outside",
		"a/../b",
		"./file",
		"a//b",
		"a/",
		`a\b`,
		"a\x00b",
		"a\nb",
		"a\u202eb",
		invalidUTF8,
		strings.Repeat("a", maxRepositoryFilePathBytes+1),
	}
	for _, path := range invalidPaths {
		file, err := NewRepositoryFile(path, nil)
		if err == nil || file != (RepositoryFile{}) {
			t.Fatalf("NewRepositoryFile(%q) = (%#v, %v), want zero error result", path, file, err)
		}
	}
	atLimit := strings.Repeat("a", maxRepositoryFilePathBytes)
	if _, err := NewRepositoryFile(atLimit, nil); err != nil {
		t.Fatalf("NewRepositoryFile(path at limit) error = %v", err)
	}
	unicodePath := "資料/例.bin"
	file, err := NewRepositoryFile(unicodePath, nil)
	if err != nil || file.Path() != unicodePath {
		t.Fatalf("NewRepositoryFile(Unicode path) = (%#v, %v)", file, err)
	}
}

func TestRepositoryFileDoesNotRetainContent(t *testing.T) {
	content := []byte("immutable\n")
	file, err := NewRepositoryFile("file.txt", content)
	if err != nil {
		t.Fatalf("NewRepositoryFile() error = %v", err)
	}
	identity := file.Identity()
	digest := file.Digest()
	size := file.SizeBytes()
	for i := range content {
		content[i] = 'x'
	}
	if file.Identity() != identity || file.Digest() != digest || file.SizeBytes() != size {
		t.Fatal("caller mutation changed RepositoryFile")
	}

	typeOfFile := reflect.TypeOf(file)
	for i := 0; i < typeOfFile.NumField(); i++ {
		kind := typeOfFile.Field(i).Type.Kind()
		if kind == reflect.Slice || kind == reflect.Map || kind == reflect.Pointer {
			t.Fatalf("RepositoryFile field %q retains mutable state", typeOfFile.Field(i).Name)
		}
	}
}
