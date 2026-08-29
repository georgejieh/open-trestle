package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

func TestNewRepositoryManifestDeltaClassifiesCompletePathPartition(t *testing.T) {
	base := mustManifestFromContents(t, map[string][]byte{
		"deleted.go":  []byte("deleted\n"),
		"modified.go": []byte("old\n"),
		"same.go":     []byte("same\n"),
	})
	head := mustManifestFromContents(t, map[string][]byte{
		"added.go":    []byte("added\n"),
		"modified.go": []byte("new\n"),
		"same.go":     []byte("same\n"),
	})
	delta, err := NewRepositoryManifestDelta(base, head)
	if err != nil {
		t.Fatalf("NewRepositoryManifestDelta() error = %v", err)
	}
	entries := delta.Entries()
	if delta.Identity() == "" || delta.BaseManifestIdentity() != base.Identity() || delta.HeadManifestIdentity() != head.Identity() || delta.ChangedFileCount() != 3 || delta.AddedFileCount() != 1 || delta.ModifiedFileCount() != 1 || delta.RemovedFileCount() != 1 || delta.UnchangedFileCount() != 1 {
		t.Fatalf("delta = %#v", delta)
	}
	if delta.RemovedFileCount()+delta.ModifiedFileCount()+delta.UnchangedFileCount() != base.FileCount() || delta.AddedFileCount()+delta.ModifiedFileCount()+delta.UnchangedFileCount() != head.FileCount() {
		t.Fatal("delta counts do not partition both manifests")
	}
	wantPaths := []string{"added.go", "deleted.go", "modified.go"}
	wantKinds := []RepositoryFileDeltaKind{RepositoryFileDeltaAdded, RepositoryFileDeltaRemoved, RepositoryFileDeltaModified}
	for i, entry := range entries {
		if entry.Identity() == "" || entry.Path() != wantPaths[i] || entry.Kind() != wantKinds[i] || entry.Identity() != expectedRepositoryFileDeltaIdentity(entry) {
			t.Fatalf("entry %d = %#v", i, entry)
		}
		lookedUp, ok := delta.Entry(entry.Path())
		if !ok || lookedUp != entry {
			t.Fatalf("Entry(%q) = (%#v, %v)", entry.Path(), lookedUp, ok)
		}
	}
	if _, ok := entries[0].BaseFile(); ok {
		t.Fatal("added entry has a base file")
	}
	if _, ok := entries[0].HeadFile(); !ok {
		t.Fatal("added entry lacks a head file")
	}
	if _, ok := entries[1].BaseFile(); !ok {
		t.Fatal("removed entry lacks a base file")
	}
	if _, ok := entries[1].HeadFile(); ok {
		t.Fatal("removed entry has a head file")
	}
	baseModified, baseOK := entries[2].BaseFile()
	headModified, headOK := entries[2].HeadFile()
	if !baseOK || !headOK || baseModified.Digest() == headModified.Digest() {
		t.Fatalf("modified sides = (%#v, %#v)", baseModified, headModified)
	}
	if _, ok := delta.Entry("same.go"); ok {
		t.Fatal("unchanged path appears in delta")
	}
	if delta.Identity() != expectedRepositoryManifestDeltaIdentity(delta) {
		t.Fatalf("Identity() = %q, want %q", delta.Identity(), expectedRepositoryManifestDeltaIdentity(delta))
	}
}

func TestNewRepositoryManifestDeltaAcceptsEmptyAndEqualManifests(t *testing.T) {
	for _, contents := range []map[string][]byte{{}, {"same": []byte("value")}} {
		manifest := mustManifestFromContents(t, contents)
		delta, err := NewRepositoryManifestDelta(manifest, manifest)
		if err != nil || delta.Identity() == "" || delta.ChangedFileCount() != 0 || delta.UnchangedFileCount() != manifest.FileCount() || delta.Entries() != nil || delta.Identity() != expectedRepositoryManifestDeltaIdentity(delta) {
			t.Fatalf("equal delta = (%#v, %v)", delta, err)
		}
	}
}

func TestNewRepositoryManifestDeltaClassifiesEmptySides(t *testing.T) {
	empty := mustManifestFromContents(t, map[string][]byte{})
	files := mustManifestFromContents(t, map[string][]byte{"a": []byte("a"), "b": []byte("b")})
	added, err := NewRepositoryManifestDelta(empty, files)
	if err != nil || added.AddedFileCount() != 2 || added.ChangedFileCount() != 2 || added.RemovedFileCount() != 0 || added.ModifiedFileCount() != 0 || added.UnchangedFileCount() != 0 {
		t.Fatalf("all-added delta = (%#v, %v)", added, err)
	}
	removed, err := NewRepositoryManifestDelta(files, empty)
	if err != nil || removed.RemovedFileCount() != 2 || removed.ChangedFileCount() != 2 || removed.AddedFileCount() != 0 || removed.ModifiedFileCount() != 0 || removed.UnchangedFileCount() != 0 {
		t.Fatalf("all-removed delta = (%#v, %v)", removed, err)
	}
	for _, entry := range added.Entries() {
		if _, ok := entry.BaseFile(); ok {
			t.Fatal("all-added entry has a base file")
		}
	}
	for _, entry := range removed.Entries() {
		if _, ok := entry.HeadFile(); ok {
			t.Fatal("all-removed entry has a head file")
		}
	}
}

func TestNewRepositoryManifestDeltaPreservesOrientationWithoutRenameInference(t *testing.T) {
	base := mustManifestFromContents(t, map[string][]byte{"old.go": []byte("same\n"), "changed.go": []byte("old\n")})
	head := mustManifestFromContents(t, map[string][]byte{"new.go": []byte("same\n"), "changed.go": []byte("new\n")})
	forward, err := NewRepositoryManifestDelta(base, head)
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := NewRepositoryManifestDelta(head, base)
	if err != nil {
		t.Fatal(err)
	}
	if forward.Identity() == reverse.Identity() || forward.AddedFileCount() != 1 || reverse.AddedFileCount() != 1 || forward.RemovedFileCount() != 1 || reverse.RemovedFileCount() != 1 {
		t.Fatalf("orientation = %#v %#v", forward, reverse)
	}
	forwardChanged, _ := forward.Entry("changed.go")
	reverseChanged, _ := reverse.Entry("changed.go")
	forwardBase, _ := forwardChanged.BaseFile()
	forwardHead, _ := forwardChanged.HeadFile()
	reverseBase, _ := reverseChanged.BaseFile()
	reverseHead, _ := reverseChanged.HeadFile()
	if forwardBase != reverseHead || forwardHead != reverseBase {
		t.Fatal("modified sides did not reverse")
	}
	oldEntry, _ := forward.Entry("old.go")
	newEntry, _ := forward.Entry("new.go")
	if oldEntry.Kind() != RepositoryFileDeltaRemoved || newEntry.Kind() != RepositoryFileDeltaAdded {
		t.Fatal("same bytes at another path were treated as a rename")
	}
}

func TestNewRepositoryManifestDeltaIgnoresCallerFileOrderAndIsCaseSensitive(t *testing.T) {
	upper, _ := NewRepositoryFile("A.go", []byte("upper"))
	lower, _ := NewRepositoryFile("a.go", []byte("lower"))
	base, _ := NewRepositoryManifest([]RepositoryFile{lower, upper})
	head, _ := NewRepositoryManifest([]RepositoryFile{upper, lower})
	first, err := NewRepositoryManifestDelta(base, head)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewRepositoryManifestDelta(head, base)
	if err != nil || first.Identity() != second.Identity() || first.ChangedFileCount() != 0 || first.UnchangedFileCount() != 2 {
		t.Fatalf("order deltas = (%#v, %#v, %v)", first, second, err)
	}
}

func TestNewRepositoryManifestDeltaRejectsNonCanonicalManifests(t *testing.T) {
	canonical := mustManifestFromContents(t, map[string][]byte{"file": []byte("content")})
	for _, test := range []struct {
		name string
		base RepositoryManifest
		head RepositoryManifest
	}{
		{name: "zero base", head: canonical},
		{name: "zero head", base: canonical},
		{name: "forged base identity", base: alterRepositoryManifest(canonical, func(manifest *RepositoryManifest) { manifest.identity = "forged" }), head: canonical},
		{name: "forged head total", base: canonical, head: alterRepositoryManifest(canonical, func(manifest *RepositoryManifest) { manifest.totalSizeBytes++ })},
		{name: "forged file", base: alterRepositoryManifest(canonical, func(manifest *RepositoryManifest) { manifest.files[0].digest = "forged" }), head: canonical},
	} {
		t.Run(test.name, func(t *testing.T) {
			delta, err := NewRepositoryManifestDelta(test.base, test.head)
			if err == nil || delta.Identity() != "" || delta.Entries() != nil {
				t.Fatalf("NewRepositoryManifestDelta() = (%#v, %v)", delta, err)
			}
		})
	}
}

func TestRepositoryManifestDeltaAccessorsAreDefensive(t *testing.T) {
	base := mustManifestFromContents(t, map[string][]byte{"file": []byte("base")})
	head := mustManifestFromContents(t, map[string][]byte{"file": []byte("head")})
	delta, err := NewRepositoryManifestDelta(base, head)
	if err != nil {
		t.Fatal(err)
	}
	entries := delta.Entries()
	entries[0] = RepositoryFileDelta{}
	if delta.Entries()[0].Identity() == "" {
		t.Fatal("returned entries alias stored state")
	}
	baseFile, _ := delta.Entries()[0].BaseFile()
	baseFile.identity = "forged"
	storedBase, _ := delta.Entries()[0].BaseFile()
	if storedBase.Identity() == "forged" {
		t.Fatal("returned base file aliases stored state")
	}
}

func TestRepositoryManifestDeltaZeroValue(t *testing.T) {
	var delta RepositoryManifestDelta
	if delta.Identity() != "" || delta.BaseManifestIdentity() != "" || delta.HeadManifestIdentity() != "" || delta.ChangedFileCount() != 0 || delta.AddedFileCount() != 0 || delta.ModifiedFileCount() != 0 || delta.RemovedFileCount() != 0 || delta.UnchangedFileCount() != 0 || delta.Entries() != nil {
		t.Fatalf("zero delta = %#v", delta)
	}
	if _, ok := delta.Entry("file"); ok {
		t.Fatal("zero delta returned an entry")
	}
	var entry RepositoryFileDelta
	if entry.Identity() != "" || entry.Kind() != "" || entry.Path() != "" {
		t.Fatalf("zero entry = %#v", entry)
	}
	if _, ok := entry.BaseFile(); ok {
		t.Fatal("zero entry has a base file")
	}
	if _, ok := entry.HeadFile(); ok {
		t.Fatal("zero entry has a head file")
	}
}

func TestNewRepositoryManifestDeltaAcceptsManifestFileLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("large linear boundary")
	}
	baseFiles := make([]RepositoryFile, maxRepositoryManifestFiles)
	headFiles := make([]RepositoryFile, maxRepositoryManifestFiles)
	for i := 0; i < maxRepositoryManifestFiles; i++ {
		baseFiles[i], _ = NewRepositoryFile(fmt.Sprintf("base/%05d", i), nil)
		headFiles[i], _ = NewRepositoryFile(fmt.Sprintf("head/%05d", i), nil)
	}
	base, err := NewRepositoryManifest(baseFiles)
	if err != nil {
		t.Fatal(err)
	}
	head, err := NewRepositoryManifest(headFiles)
	if err != nil {
		t.Fatal(err)
	}
	delta, err := NewRepositoryManifestDelta(base, head)
	if err != nil || delta.ChangedFileCount() != maxRepositoryManifestDeltaFiles || delta.RemovedFileCount() != maxRepositoryManifestFiles || delta.AddedFileCount() != maxRepositoryManifestFiles {
		t.Fatalf("boundary delta = (%#v, %v)", delta, err)
	}
}

func mustManifestFromContents(t *testing.T, contents map[string][]byte) RepositoryManifest {
	t.Helper()
	files := make([]RepositoryFile, 0, len(contents))
	for path, content := range contents {
		file, err := NewRepositoryFile(path, content)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	manifest, err := NewRepositoryManifest(files)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func alterRepositoryManifest(manifest RepositoryManifest, alter func(*RepositoryManifest)) RepositoryManifest {
	manifest.files = append([]RepositoryFile(nil), manifest.files...)
	alter(&manifest)
	return manifest
}

func expectedRepositoryFileDeltaIdentity(entry RepositoryFileDelta) string {
	base, _ := entry.BaseFile()
	head, _ := entry.HeadFile()
	preimage := struct {
		Contract                   string                  `json:"contract"`
		SchemaVersion              int                     `json:"schema_version"`
		Kind                       RepositoryFileDeltaKind `json:"kind"`
		Path                       string                  `json:"path"`
		BaseRepositoryFileIdentity string                  `json:"base_repository_file_identity"`
		HeadRepositoryFileIdentity string                  `json:"head_repository_file_identity"`
	}{"open-trestle/repository-file-delta", 1, entry.Kind(), entry.Path(), base.Identity(), head.Identity()}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func expectedRepositoryManifestDeltaIdentity(delta RepositoryManifestDelta) string {
	type entryWire struct {
		Path                        string                  `json:"path"`
		Kind                        RepositoryFileDeltaKind `json:"kind"`
		RepositoryFileDeltaIdentity string                  `json:"repository_file_delta_identity"`
	}
	entries := delta.Entries()
	preimage := struct {
		Contract             string      `json:"contract"`
		SchemaVersion        int         `json:"schema_version"`
		BaseManifestIdentity string      `json:"base_manifest_identity"`
		HeadManifestIdentity string      `json:"head_manifest_identity"`
		Entries              []entryWire `json:"entries"`
	}{"open-trestle/repository-manifest-delta", 1, delta.BaseManifestIdentity(), delta.HeadManifestIdentity(), make([]entryWire, len(entries))}
	for i, entry := range entries {
		preimage.Entries[i] = entryWire{entry.Path(), entry.Kind(), entry.Identity()}
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
