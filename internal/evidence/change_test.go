package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestNewChangeCreatesSingleFileAggregate(t *testing.T) {
	fileChange, lineMap := mustParseUnifiedFileDiff(
		t,
		"main.go",
		[]byte("a\nb\n"),
		[]byte("a\nB\n"),
		unifiedPatch("main.go", "@@ -2 +2 @@\n-b\n+B\n"),
	)
	change, err := NewChange([]FileChange{fileChange}, []LineMap{lineMap})
	if err != nil {
		t.Fatalf("NewChange() error = %v", err)
	}
	if len(change.Identity()) != 64 {
		t.Fatalf("len(Identity()) = %d, want 64", len(change.Identity()))
	}
	if got := change.FileChanges(); len(got) != 1 || got[0].Identity() != fileChange.Identity() {
		t.Fatalf("FileChanges() = %#v", got)
	}
	if got := change.LineMaps(); len(got) != 1 || got[0].Identity() != lineMap.Identity() {
		t.Fatalf("LineMaps() = %#v", got)
	}
	gotFile, ok := change.FileChangeForPath("main.go")
	if !ok || gotFile.Identity() != fileChange.Identity() {
		t.Fatalf("FileChangeForPath() = (%#v, %t)", gotFile, ok)
	}
	gotMap, ok := change.LineMapForPath("main.go")
	if !ok || gotMap.Identity() != lineMap.Identity() {
		t.Fatalf("LineMapForPath() = (%#v, %t)", gotMap, ok)
	}
}

func TestNewChangeCanonicalizesIndependentInputOrder(t *testing.T) {
	alphaFile, alphaMap := mustChangePair(t, "alpha.go")
	zetaFile, zetaMap := mustChangePair(t, "zeta.go")
	testCases := []struct {
		files []FileChange
		maps  []LineMap
	}{
		{files: []FileChange{alphaFile, zetaFile}, maps: []LineMap{alphaMap, zetaMap}},
		{files: []FileChange{zetaFile, alphaFile}, maps: []LineMap{alphaMap, zetaMap}},
		{files: []FileChange{alphaFile, zetaFile}, maps: []LineMap{zetaMap, alphaMap}},
		{files: []FileChange{zetaFile, alphaFile}, maps: []LineMap{zetaMap, alphaMap}},
	}
	var wantIdentity string
	for i, testCase := range testCases {
		change, err := NewChange(testCase.files, testCase.maps)
		if err != nil {
			t.Fatalf("case %d NewChange() error = %v", i, err)
		}
		if i == 0 {
			wantIdentity = change.Identity()
		} else if change.Identity() != wantIdentity {
			t.Fatalf("case %d Identity() = %q, want %q", i, change.Identity(), wantIdentity)
		}
		files := change.FileChanges()
		maps := change.LineMaps()
		if files[0].Path() != "alpha.go" || files[1].Path() != "zeta.go" || maps[0].Path() != "alpha.go" || maps[1].Path() != "zeta.go" {
			t.Fatalf("case %d canonical paths = (%q, %q), (%q, %q)", i, files[0].Path(), files[1].Path(), maps[0].Path(), maps[1].Path())
		}
	}
}

func TestChangeIdentityUsesVersionedCanonicalPreimage(t *testing.T) {
	alphaFile, alphaMap := mustChangePair(t, "alpha.go")
	zetaFile, zetaMap := mustChangePair(t, "zeta.go")
	change := mustChange(t, []FileChange{zetaFile, alphaFile}, []LineMap{zetaMap, alphaMap})
	preimage := fmt.Sprintf(
		`{"contract":"open-trestle/change","schema_version":1,"files":[{"path":"alpha.go","file_change_identity":"%s","line_map_identity":"%s"},{"path":"zeta.go","file_change_identity":"%s","line_map_identity":"%s"}]}`,
		alphaFile.Identity(), alphaMap.Identity(), zetaFile.Identity(), zetaMap.Identity(),
	)
	digest := sha256.Sum256([]byte(preimage))
	want := hex.EncodeToString(digest[:])
	if change.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", change.Identity(), preimage)
	}
}

func TestChangeIdentityBindsMembershipAndChildren(t *testing.T) {
	alphaFile, alphaMap := mustChangePair(t, "alpha.go")
	zetaFile, zetaMap := mustChangePair(t, "zeta.go")
	single := mustChange(t, []FileChange{alphaFile}, []LineMap{alphaMap})
	multiple := mustChange(t, []FileChange{alphaFile, zetaFile}, []LineMap{alphaMap, zetaMap})
	if single.Identity() == multiple.Identity() {
		t.Fatal("adding a file did not change identity")
	}

	owner := mustFileChange(t, "geometry.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "geometry.go", 2, 3)})
	firstHunk := mustHunk(t, owner, 2, 1, 2, 2)
	firstMap := mustLineMap(t, owner, 3, 4, []Hunk{firstHunk})
	geometryChange := mustChange(t, []FileChange{owner}, []LineMap{firstMap})
	otherHunk := mustHunk(t, owner, 2, 2, 2, 2)
	otherMap := mustLineMap(t, owner, 4, 4, []Hunk{otherHunk})
	if geometryChange.Identity() == mustChange(t, []FileChange{owner}, []LineMap{otherMap}).Identity() {
		t.Fatal("changing Hunk geometry did not change identity")
	}
	largerMap := mustLineMap(t, owner, 4, 5, []Hunk{firstHunk})
	if geometryChange.Identity() == mustChange(t, []FileChange{owner}, []LineMap{largerMap}).Identity() {
		t.Fatal("changing line totals did not change identity")
	}

	otherHeadDigest := "bbcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	otherFile := mustFileChange(t, "alpha.go", testBaseDigest, otherHeadDigest, []SourceRange{mustSourceRange(t, "alpha.go", 2, 2)})
	otherFileMap := mustLineMap(t, otherFile, 3, 3, []Hunk{mustHunk(t, otherFile, 2, 1, 2, 1)})
	if single.Identity() == mustChange(t, []FileChange{otherFile}, []LineMap{otherFileMap}).Identity() {
		t.Fatal("changing file content identity did not change Change identity")
	}
}

func TestNewChangeRejectsInvalidPairingAndDuplicates(t *testing.T) {
	alphaFile, alphaMap := mustChangePair(t, "alpha.go")
	zetaFile, zetaMap := mustChangePair(t, "zeta.go")
	otherHeadDigest := "bbcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	duplicatePathFile := mustFileChange(t, "alpha.go", testBaseDigest, otherHeadDigest, []SourceRange{mustSourceRange(t, "alpha.go", 2, 2)})
	duplicatePathMap := mustLineMap(t, duplicatePathFile, 3, 3, []Hunk{mustHunk(t, duplicatePathFile, 2, 1, 2, 1)})
	forgedFile := alphaFile
	forgedFile.headDigest = otherHeadDigest
	forgedMap := alphaMap
	forgedMap.path = "other.go"
	forgedTotalMap := alphaMap
	forgedTotalMap.headLineCount++

	testCases := []struct {
		name  string
		files []FileChange
		maps  []LineMap
	}{
		{name: "nil"},
		{name: "empty", files: []FileChange{}, maps: []LineMap{}},
		{name: "missing map", files: []FileChange{alphaFile}},
		{name: "extra map", maps: []LineMap{alphaMap}},
		{name: "zero file", files: []FileChange{{}}, maps: []LineMap{alphaMap}},
		{name: "zero map", files: []FileChange{alphaFile}, maps: []LineMap{{}}},
		{name: "wrong owner", files: []FileChange{zetaFile}, maps: []LineMap{alphaMap}},
		{name: "cross paired", files: []FileChange{alphaFile, zetaFile}, maps: []LineMap{alphaMap, duplicatePathMap}},
		{name: "duplicate file", files: []FileChange{alphaFile, alphaFile}, maps: []LineMap{alphaMap, alphaMap}},
		{name: "duplicate map", files: []FileChange{alphaFile, zetaFile}, maps: []LineMap{alphaMap, alphaMap}},
		{name: "duplicate path", files: []FileChange{alphaFile, duplicatePathFile}, maps: []LineMap{alphaMap, duplicatePathMap}},
		{name: "forged file", files: []FileChange{forgedFile}, maps: []LineMap{alphaMap}},
		{name: "forged map path", files: []FileChange{alphaFile}, maps: []LineMap{forgedMap}},
		{name: "forged map total", files: []FileChange{alphaFile}, maps: []LineMap{forgedTotalMap}},
		{name: "extra unrelated map", files: []FileChange{alphaFile, zetaFile}, maps: []LineMap{alphaMap, duplicatePathMap}},
		{name: "valid control", files: []FileChange{alphaFile, zetaFile}, maps: []LineMap{alphaMap, zetaMap}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			change, err := NewChange(testCase.files, testCase.maps)
			if testCase.name == "valid control" {
				if err != nil {
					t.Fatalf("NewChange() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("NewChange() error = nil, want validation error")
			}
			if change.Identity() != "" || len(change.FileChanges()) != 0 || len(change.LineMaps()) != 0 {
				t.Fatalf("NewChange() = %#v, want zero value", change)
			}
		})
	}
}

func TestNewChangeEnforcesFileLimit(t *testing.T) {
	files := make([]FileChange, maxChangeFiles+1)
	maps := make([]LineMap, maxChangeFiles+1)
	for i := range files {
		files[i], maps[i] = mustChangePair(t, fmt.Sprintf("files/%04d.go", i))
	}
	change, err := NewChange(files, maps)
	if err == nil {
		t.Fatal("NewChange(over limit) error = nil")
	}
	if change.Identity() != "" || len(change.FileChanges()) != 0 || len(change.LineMaps()) != 0 {
		t.Fatalf("NewChange(over limit) = %#v, want zero value", change)
	}
	mustChange(t, files[:maxChangeFiles], maps[:maxChangeFiles])
}

func TestChangeDoesNotExposeMutableCollections(t *testing.T) {
	alphaFile, alphaMap := mustChangePair(t, "alpha.go")
	zetaFile, zetaMap := mustChangePair(t, "zeta.go")
	files := []FileChange{zetaFile, alphaFile}
	maps := []LineMap{alphaMap, zetaMap}
	change := mustChange(t, files, maps)
	identity := change.Identity()

	files[0].ranges[0] = SourceRange{}
	maps[0].hunks[0] = Hunk{}
	files[0] = FileChange{}
	maps[0] = LineMap{}
	returnedFiles := change.FileChanges()
	returnedMaps := change.LineMaps()
	returnedFiles[0].ranges[0] = SourceRange{}
	returnedMaps[0].hunks[0] = Hunk{}
	lookupFile, _ := change.FileChangeForPath("alpha.go")
	lookupMap, _ := change.LineMapForPath("alpha.go")
	lookupFile.ranges[0] = SourceRange{}
	lookupMap.hunks[0] = Hunk{}

	if change.Identity() != identity || change.FileChanges()[0].Path() != "alpha.go" || change.LineMaps()[0].Path() != "alpha.go" {
		t.Fatal("caller or accessor mutation changed Change")
	}
	if change.FileChanges()[0].ChangedRanges()[0].Path() != "alpha.go" || change.LineMaps()[0].Hunks()[0].Path() != "alpha.go" {
		t.Fatal("nested caller or accessor mutation changed Change")
	}
}

func TestChangeLookupRejectsAbsentOrInvalidPath(t *testing.T) {
	fileChange, lineMap := mustChangePair(t, "main.go")
	change := mustChange(t, []FileChange{fileChange}, []LineMap{lineMap})
	paths := []string{"", "missing.go", "../main.go", string([]byte{'b', 'a', 'd', 0xff})}
	for _, path := range paths {
		if got, ok := change.FileChangeForPath(path); ok || got.Identity() != "" {
			t.Fatalf("FileChangeForPath(%q) = (%#v, %t)", path, got, ok)
		}
		if got, ok := change.LineMapForPath(path); ok || got.Identity() != "" {
			t.Fatalf("LineMapForPath(%q) = (%#v, %t)", path, got, ok)
		}
	}
}

func mustChangePair(t *testing.T, path string) (FileChange, LineMap) {
	t.Helper()
	fileChange := mustFileChange(t, path, testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, path, 2, 2)})
	lineMap := mustLineMap(t, fileChange, 3, 3, []Hunk{mustHunk(t, fileChange, 2, 1, 2, 1)})
	return fileChange, lineMap
}

func mustChange(t *testing.T, fileChanges []FileChange, lineMaps []LineMap) Change {
	t.Helper()
	change, err := NewChange(fileChanges, lineMaps)
	if err != nil {
		t.Fatalf("NewChange() error = %v", err)
	}
	return change
}
