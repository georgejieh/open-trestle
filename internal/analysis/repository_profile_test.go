package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestNewRepositoryProfileCreatesManifestInventory(t *testing.T) {
	manifest := mustProfileManifest(t, profileFileSpec{path: "main.go", content: []byte("abc")})
	profile, err := NewRepositoryProfile(manifest)
	if err != nil {
		t.Fatalf("NewRepositoryProfile() error = %v", err)
	}
	if len(profile.Identity()) != 64 || profile.ManifestIdentity() != manifest.Identity() || profile.FileCount() != 1 || profile.TotalSizeBytes() != 3 {
		t.Fatalf("profile = (%q, %q, %d, %d)", profile.Identity(), profile.ManifestIdentity(), profile.FileCount(), profile.TotalSizeBytes())
	}
	facts := profile.ExtensionFacts()
	if len(facts) != 1 || facts[0].Extension() != ".go" || facts[0].FileCount() != 1 || facts[0].TotalSizeBytes() != 3 {
		t.Fatalf("ExtensionFacts() = %#v", facts)
	}
	if fact, ok := profile.Extension(".go"); !ok || fact != facts[0] {
		t.Fatalf("Extension(.go) = (%#v, %t)", fact, ok)
	}
}

func TestRepositoryProfileIdentityUsesCanonicalPreimage(t *testing.T) {
	manifest := mustProfileManifest(t, profileFileSpec{path: "main.go", content: []byte("abc")})
	profile, err := NewRepositoryProfile(manifest)
	if err != nil {
		t.Fatalf("NewRepositoryProfile() error = %v", err)
	}
	preimage := fmt.Sprintf(`{"contract":"open-trestle/repository-profile","schema_version":1,"manifest_identity":"%s","file_count":1,"total_size_bytes":3,"extensions":[{"extension":".go","file_count":1,"total_size_bytes":3}]}`, manifest.Identity())
	digest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(digest[:]); profile.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", profile.Identity(), preimage)
	}
}

func TestNewRepositoryProfilePreservesExactExtensions(t *testing.T) {
	manifest := mustProfileManifest(t,
		profileFileSpec{path: "LICENSE", content: []byte("license")},
		profileFileSpec{path: "archive.tar.gz", content: []byte("archive")},
		profileFileSpec{path: "main.GO", content: []byte("upper")},
		profileFileSpec{path: "main.go", content: []byte("lower")},
	)
	profile, err := NewRepositoryProfile(manifest)
	if err != nil {
		t.Fatalf("NewRepositoryProfile() error = %v", err)
	}
	facts := profile.ExtensionFacts()
	want := []string{"", ".GO", ".go", ".gz"}
	if len(facts) != len(want) {
		t.Fatalf("len(ExtensionFacts()) = %d, want %d", len(facts), len(want))
	}
	for i, extension := range want {
		if facts[i].Extension() != extension || facts[i].FileCount() != 1 {
			t.Fatalf("facts[%d] = %#v, want extension %q", i, facts[i], extension)
		}
	}
}

func TestNewRepositoryProfileAggregatesExactExtensionTotals(t *testing.T) {
	manifest := mustProfileManifest(t,
		profileFileSpec{path: "a.go", content: []byte("a")},
		profileFileSpec{path: "nested/b.go", content: []byte("bbb")},
		profileFileSpec{path: "c.txt", content: []byte("cc")},
	)
	profile, err := NewRepositoryProfile(manifest)
	if err != nil {
		t.Fatalf("NewRepositoryProfile() error = %v", err)
	}
	goFact, ok := profile.Extension(".go")
	if !ok || goFact.FileCount() != 2 || goFact.TotalSizeBytes() != 4 {
		t.Fatalf("Extension(.go) = (%#v, %t)", goFact, ok)
	}
	if profile.FileCount() != 3 || profile.TotalSizeBytes() != 6 {
		t.Fatalf("profile totals = (%d, %d)", profile.FileCount(), profile.TotalSizeBytes())
	}
	totalCount := 0
	var totalSize int64
	for _, fact := range profile.ExtensionFacts() {
		totalCount += fact.FileCount()
		totalSize += fact.TotalSizeBytes()
	}
	if totalCount != profile.FileCount() || totalSize != profile.TotalSizeBytes() {
		t.Fatalf("extension totals = (%d, %d), profile = (%d, %d)", totalCount, totalSize, profile.FileCount(), profile.TotalSizeBytes())
	}
}

func TestNewRepositoryProfileIgnoresManifestInputOrder(t *testing.T) {
	firstManifest := mustProfileManifest(t,
		profileFileSpec{path: "zeta.go", content: []byte("z")},
		profileFileSpec{path: "alpha.go", content: []byte("a")},
	)
	secondManifest := mustProfileManifest(t,
		profileFileSpec{path: "alpha.go", content: []byte("a")},
		profileFileSpec{path: "zeta.go", content: []byte("z")},
	)
	first, err := NewRepositoryProfile(firstManifest)
	if err != nil {
		t.Fatalf("NewRepositoryProfile(first) error = %v", err)
	}
	second, err := NewRepositoryProfile(secondManifest)
	if err != nil || second.Identity() != first.Identity() || second.ManifestIdentity() != first.ManifestIdentity() {
		t.Fatalf("second = (%q, %q, %v), want (%q, %q)", second.Identity(), second.ManifestIdentity(), err, first.Identity(), first.ManifestIdentity())
	}
}

func TestNewRepositoryProfileAcceptsEmptyManifest(t *testing.T) {
	manifest, err := evidence.NewRepositoryManifest(nil)
	if err != nil {
		t.Fatalf("NewRepositoryManifest() error = %v", err)
	}
	first, err := NewRepositoryProfile(manifest)
	if err != nil {
		t.Fatalf("NewRepositoryProfile() error = %v", err)
	}
	second, err := NewRepositoryProfile(manifest)
	if err != nil || second.Identity() != first.Identity() || first.Identity() == "" {
		t.Fatalf("empty profiles = (%q, %q, %v)", first.Identity(), second.Identity(), err)
	}
	if first.FileCount() != 0 || first.TotalSizeBytes() != 0 || first.ExtensionFacts() == nil || len(first.ExtensionFacts()) != 0 {
		t.Fatalf("empty profile = (%d, %d, %#v)", first.FileCount(), first.TotalSizeBytes(), first.ExtensionFacts())
	}
}

func TestRepositoryProfileIdentityBindsManifestAndExtensions(t *testing.T) {
	variants := []evidence.RepositoryManifest{
		mustProfileManifest(t, profileFileSpec{path: "a.go", content: []byte("a")}),
		mustProfileManifest(t, profileFileSpec{path: "a.go", content: []byte("b")}),
		mustProfileManifest(t, profileFileSpec{path: "a.txt", content: []byte("a")}),
		mustProfileManifest(t, profileFileSpec{path: "a.go", content: []byte("a")}, profileFileSpec{path: "b.go", content: []byte("b")}),
	}
	identities := make(map[string]struct{}, len(variants))
	for _, manifest := range variants {
		profile, err := NewRepositoryProfile(manifest)
		if err != nil {
			t.Fatalf("NewRepositoryProfile() error = %v", err)
		}
		if _, exists := identities[profile.Identity()]; exists {
			t.Fatalf("duplicate profile identity %q", profile.Identity())
		}
		identities[profile.Identity()] = struct{}{}
	}
}

func TestNewRepositoryProfileRejectsZeroManifest(t *testing.T) {
	profile, err := NewRepositoryProfile(evidence.RepositoryManifest{})
	if err == nil || profile.Identity() != "" {
		t.Fatalf("NewRepositoryProfile(zero) = (%#v, %v), want zero error result", profile, err)
	}
}

func TestRepositoryProfileAccessorsAreImmutableAndExact(t *testing.T) {
	manifest := mustProfileManifest(t,
		profileFileSpec{path: "LICENSE", content: []byte("a")},
		profileFileSpec{path: "main.go", content: []byte("bbb")},
	)
	profile, err := NewRepositoryProfile(manifest)
	if err != nil {
		t.Fatalf("NewRepositoryProfile() error = %v", err)
	}
	identity := profile.Identity()
	facts := profile.ExtensionFacts()
	facts[0] = FileExtensionFact{}
	if profile.Identity() != identity || profile.ExtensionFacts()[0].Extension() != "" {
		t.Fatal("caller mutation changed RepositoryProfile")
	}
	if fact, ok := profile.Extension(""); !ok || fact.Extension() != "" || fact.FileCount() != 1 {
		t.Fatalf("Extension(empty) = (%#v, %t)", fact, ok)
	}
	for _, extension := range []string{"missing", ".Go", "go"} {
		if fact, ok := profile.Extension(extension); ok || fact != (FileExtensionFact{}) {
			t.Fatalf("Extension(%q) = (%#v, %t)", extension, fact, ok)
		}
	}

	typeOfProfile := reflect.TypeOf(profile)
	for i := 0; i < typeOfProfile.NumField(); i++ {
		kind := typeOfProfile.Field(i).Type.Kind()
		if kind == reflect.Map || kind == reflect.Pointer {
			t.Fatalf("RepositoryProfile field %q retains mutable state", typeOfProfile.Field(i).Name)
		}
	}
}

type profileFileSpec struct {
	path    string
	content []byte
}

func mustProfileManifest(t *testing.T, specs ...profileFileSpec) evidence.RepositoryManifest {
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
