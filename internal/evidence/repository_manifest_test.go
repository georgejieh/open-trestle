package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestNewRepositoryManifestCreatesCanonicalAggregate(t *testing.T) {
	file := mustRepositoryFile(t, "src/main.go", []byte("package worker\n"))
	manifest, err := NewRepositoryManifest([]RepositoryFile{file})
	if err != nil {
		t.Fatalf("NewRepositoryManifest() error = %v", err)
	}
	if len(manifest.Identity()) != 64 || manifest.FileCount() != 1 || manifest.TotalSizeBytes() != int64(file.SizeBytes()) {
		t.Fatalf("manifest metadata = (%q, %d, %d)", manifest.Identity(), manifest.FileCount(), manifest.TotalSizeBytes())
	}
	if files := manifest.Files(); len(files) != 1 || files[0] != file {
		t.Fatalf("Files() = %#v", files)
	}
	if got, ok := manifest.File("src/main.go"); !ok || got != file {
		t.Fatalf("File() = (%#v, %t)", got, ok)
	}
}

func TestRepositoryManifestIdentityUsesCanonicalPreimage(t *testing.T) {
	file := mustRepositoryFile(t, "README.md", []byte("hello\n"))
	manifest, err := NewRepositoryManifest([]RepositoryFile{file})
	if err != nil {
		t.Fatalf("NewRepositoryManifest() error = %v", err)
	}
	preimage := fmt.Sprintf(`{"contract":"open-trestle/repository-manifest","schema_version":1,"files":[{"path":"README.md","repository_file_identity":"%s"}]}`, file.Identity())
	digest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(digest[:]); manifest.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", manifest.Identity(), preimage)
	}
}

func TestNewRepositoryManifestCanonicalizesFileOrder(t *testing.T) {
	alpha := mustRepositoryFile(t, "alpha.txt", []byte("a"))
	zeta := mustRepositoryFile(t, "zeta.txt", []byte("z"))
	first, err := NewRepositoryManifest([]RepositoryFile{zeta, alpha})
	if err != nil {
		t.Fatalf("NewRepositoryManifest(first) error = %v", err)
	}
	second, err := NewRepositoryManifest([]RepositoryFile{alpha, zeta})
	if err != nil || second.Identity() != first.Identity() {
		t.Fatalf("second = (%q, %v), want %q", second.Identity(), err, first.Identity())
	}
	files := first.Files()
	if len(files) != 2 || files[0] != alpha || files[1] != zeta {
		t.Fatalf("Files() = %#v", files)
	}
}

func TestNewRepositoryManifestAcceptsEmptyRepository(t *testing.T) {
	first, err := NewRepositoryManifest(nil)
	if err != nil {
		t.Fatalf("NewRepositoryManifest(nil) error = %v", err)
	}
	second, err := NewRepositoryManifest([]RepositoryFile{})
	if err != nil || second.Identity() != first.Identity() || first.Identity() == "" {
		t.Fatalf("empty manifests = (%q, %q, %v)", first.Identity(), second.Identity(), err)
	}
	if first.FileCount() != 0 || first.TotalSizeBytes() != 0 || first.Files() == nil || len(first.Files()) != 0 {
		t.Fatalf("empty manifest = (%d, %d, %#v)", first.FileCount(), first.TotalSizeBytes(), first.Files())
	}
}

func TestRepositoryManifestIdentityBindsMembership(t *testing.T) {
	first := mustRepositoryFile(t, "a.txt", []byte("a"))
	second := mustRepositoryFile(t, "b.txt", []byte("b"))
	replacement := mustRepositoryFile(t, "b.txt", []byte("B"))
	renamed := mustRepositoryFile(t, "c.txt", []byte("b"))
	variants := [][]RepositoryFile{
		{first},
		{first, second},
		{first, replacement},
		{first, renamed},
		{second},
	}
	identities := make(map[string]struct{}, len(variants))
	for _, files := range variants {
		manifest, err := NewRepositoryManifest(files)
		if err != nil {
			t.Fatalf("NewRepositoryManifest() error = %v", err)
		}
		if _, exists := identities[manifest.Identity()]; exists {
			t.Fatalf("duplicate identity %q for %#v", manifest.Identity(), files)
		}
		identities[manifest.Identity()] = struct{}{}
	}
}

func TestNewRepositoryManifestAllowsSameContentAtDifferentPaths(t *testing.T) {
	content := []byte("same")
	first := mustRepositoryFile(t, "a.txt", content)
	second := mustRepositoryFile(t, "b.txt", content)
	manifest, err := NewRepositoryManifest([]RepositoryFile{second, first})
	if err != nil || manifest.FileCount() != 2 || first.Digest() != second.Digest() {
		t.Fatalf("NewRepositoryManifest() = (%#v, %v)", manifest, err)
	}
	replacement := mustRepositoryFile(t, "a.txt", []byte("different"))
	for _, files := range [][]RepositoryFile{{first, first}, {second, second}, {first, replacement}} {
		manifest, err := NewRepositoryManifest(files)
		if err == nil || manifest.Identity() != "" {
			t.Fatalf("duplicate result = (%#v, %v), want zero error result", manifest, err)
		}
	}
}

func TestNewRepositoryManifestRejectsForgedFiles(t *testing.T) {
	valid := mustRepositoryFile(t, "file.txt", []byte("content"))
	forgedIdentity := valid
	forgedIdentity.identity = strings.Repeat("0", 64)
	forgedPath := valid
	forgedPath.path = "other.txt"
	forgedDigest := valid
	forgedDigest.digest = strings.Repeat("a", 64)
	invalidDigest := valid
	invalidDigest.digest = "bad"
	forgedSize := valid
	forgedSize.sizeBytes++
	negativeSize := valid
	negativeSize.sizeBytes = -1
	for _, file := range []RepositoryFile{{}, forgedIdentity, forgedPath, forgedDigest, invalidDigest, forgedSize, negativeSize} {
		manifest, err := NewRepositoryManifest([]RepositoryFile{file})
		if err == nil || manifest.Identity() != "" {
			t.Fatalf("NewRepositoryManifest(%#v) = (%#v, %v), want zero error result", file, manifest, err)
		}
	}
}

func TestNewRepositoryManifestEnforcesFileLimit(t *testing.T) {
	atLimit := make([]RepositoryFile, maxRepositoryManifestFiles)
	for i := range atLimit {
		atLimit[i] = mustRepositoryFile(t, fmt.Sprintf("pkg/%05d", i), nil)
	}
	manifest, err := NewRepositoryManifest(atLimit)
	if err != nil || manifest.FileCount() != maxRepositoryManifestFiles {
		t.Fatalf("NewRepositoryManifest(at limit) = (%d files, %v)", manifest.FileCount(), err)
	}
	tooMany := make([]RepositoryFile, maxRepositoryManifestFiles+1)
	manifest, err = NewRepositoryManifest(tooMany)
	if err == nil || !strings.Contains(err.Error(), "exceeds") || manifest.Identity() != "" {
		t.Fatalf("NewRepositoryManifest(over limit) = (%#v, %v), want bounded zero error result", manifest, err)
	}
}

func TestNewRepositoryManifestRejectsTotalSizeOverflow(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("int64 overflow cannot be represented within the file-count bound")
	}
	maxInt := int(^uint(0) >> 1)
	large := mustRepositoryFileMetadata(t, "large.bin", impactDigestForEvidence(1), maxInt)
	extra := mustRepositoryFileMetadata(t, "small.bin", impactDigestForEvidence(2), 1)
	manifest, err := NewRepositoryManifest([]RepositoryFile{large, extra})
	if err == nil || manifest.Identity() != "" {
		t.Fatalf("NewRepositoryManifest(overflow) = (%#v, %v), want zero error result", manifest, err)
	}
}

func TestRepositoryManifestAccessorsAreImmutableAndExact(t *testing.T) {
	alpha := mustRepositoryFile(t, "alpha.txt", []byte("a"))
	zeta := mustRepositoryFile(t, "zeta.txt", []byte("z"))
	input := []RepositoryFile{zeta, alpha}
	manifest, err := NewRepositoryManifest(input)
	if err != nil {
		t.Fatalf("NewRepositoryManifest() error = %v", err)
	}
	identity := manifest.Identity()
	input[0] = RepositoryFile{}
	files := manifest.Files()
	files[0] = RepositoryFile{}
	if manifest.Identity() != identity || manifest.Files()[0] != alpha || manifest.FileCount() != 2 || manifest.TotalSizeBytes() != 2 {
		t.Fatal("caller mutation changed RepositoryManifest")
	}
	for _, path := range []string{"", "missing.txt", "./alpha.txt", "../alpha.txt"} {
		if file, ok := manifest.File(path); ok || file != (RepositoryFile{}) {
			t.Fatalf("File(%q) = (%#v, %t)", path, file, ok)
		}
	}

	typeOfManifest := reflect.TypeOf(manifest)
	for i := 0; i < typeOfManifest.NumField(); i++ {
		kind := typeOfManifest.Field(i).Type.Kind()
		if kind == reflect.Map || kind == reflect.Pointer {
			t.Fatalf("RepositoryManifest field %q retains mutable state", typeOfManifest.Field(i).Name)
		}
	}
}

func mustRepositoryFile(t *testing.T, path string, content []byte) RepositoryFile {
	t.Helper()
	file, err := NewRepositoryFile(path, content)
	if err != nil {
		t.Fatalf("NewRepositoryFile() error = %v", err)
	}
	return file
}

func mustRepositoryFileMetadata(t *testing.T, path, digest string, sizeBytes int) RepositoryFile {
	t.Helper()
	identity, err := repositoryFileIdentity(path, digest, sizeBytes)
	if err != nil {
		t.Fatalf("repositoryFileIdentity() error = %v", err)
	}
	return RepositoryFile{identity: identity, path: path, digest: digest, sizeBytes: sizeBytes}
}

func impactDigestForEvidence(value int) string {
	return fmt.Sprintf("%064x", value)
}
