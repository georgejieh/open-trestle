package main

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/localreview"
)

func walkthroughOf(t *testing.T, f *localModelFixture, wantCode int) localreview.Walkthrough {
	t.Helper()
	_, stdout := localModelExecute(t, f, f.args, wantCode)
	var receipt struct {
		Walkthrough *localreview.Walkthrough `json:"walkthrough"`
	}
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Walkthrough == nil {
		t.Fatalf("result has no walkthrough: %s", stdout)
	}
	return *receipt.Walkthrough
}

// The walkthrough of the ordinary fixture leads with what was verified, then
// summarizes the changed file from the diff and the semantic-impact profile,
// and notes that no test file references the changed function.
func TestWalkthroughFromFixture(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true})
	walk := walkthroughOf(t, f, 4)
	verified := walk.Verified
	// Local-only requests are secret-scanned too: one receipt each for the
	// finder and the checker request. The fixture's secret sits outside the
	// selected source, so nothing matched.
	if scan := verified.SecretScan; scan.State != localreview.SecretScanScanned || scan.Requests != 2 || scan.ScannedBytes == 0 || scan.Matches != 0 || scan.RedactedBytes != 0 {
		t.Fatalf("secret scan = %+v", scan)
	}
	if len(verified.StaticChecks) != 1 || verified.StaticChecks[0].Key != "static_debug_output" || verified.StaticChecks[0].CheckedFiles == 0 {
		t.Fatalf("static checks = %+v", verified.StaticChecks)
	}
	if verified.StyleDetection.State != "ran" || verified.StyleDetection.Recommendations != 1 {
		t.Fatalf("style detection = %+v", verified.StyleDetection)
	}
	if impact := verified.SemanticImpact; impact.State != "ran" || impact.Declarations != 1 || impact.References == 0 || impact.TestReferences != 0 {
		t.Fatalf("semantic impact = %+v", impact)
	}
	if verifier := verified.Verifier; verifier == nil || *verifier != (localreview.WalkthroughVerifier{Candidates: 1, Verified: 1, Independence: "distinct_provider"}) {
		t.Fatalf("verifier = %+v", verifier)
	}
	one := uint32(1)
	want := []localreview.WalkthroughFile{{Path: "a.go", Change: "modified", AddedLines: &one, RemovedLines: &one, Declarations: []localreview.WalkthroughDeclaration{{Change: "modified", Kind: "function", Name: "Changed"}}}}
	if !reflect.DeepEqual(walk.Files, want) {
		encoded, _ := json.Marshal(walk.Files)
		t.Fatalf("files = %s", encoded)
	}
	if !reflect.DeepEqual(walk.MissingVerification, []localreview.MissingVerification{{Path: "a.go", Kind: "function", Name: "Changed", Change: "modified"}}) || walk.MissingVerificationIncomplete {
		t.Fatalf("missing verification = %+v incomplete=%t", walk.MissingVerification, walk.MissingVerificationIncomplete)
	}
}

// An unchanged test file that calls the changed function removes its
// missing-verification note: the affected-test candidates cover it.
func TestWalkthroughMissingVerificationUsesAffectedTests(t *testing.T) {
	test := []byte("package p\nimport \"testing\"\nfunc TestChanged(t *testing.T) { _ = Changed(1) }\n")
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, extraBase: map[string][]byte{"a_test.go": test}, extraHead: map[string][]byte{"a_test.go": test}})
	walk := walkthroughOf(t, f, 4)
	if len(walk.MissingVerification) != 0 || walk.Verified.SemanticImpact.TestReferences == 0 {
		t.Fatalf("a tested function was reported as missing verification: %+v (test references %d)", walk.MissingVerification, walk.Verified.SemanticImpact.TestReferences)
	}
}

// A file moved with identical content is one renamed entry; a non-Go file
// reports its added and removed line counts from the diff.
func TestWalkthroughRenamesAndLineCounts(t *testing.T) {
	notes := []byte("first\nsecond\n")
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true,
		extraBase: map[string][]byte{"old-name.txt": notes, "notes.md": []byte("a\nb\nc\n")},
		extraHead: map[string][]byte{"new-name.txt": notes, "notes.md": []byte("a\nB\nc\nd\n")},
	})
	walk := walkthroughOf(t, f, 4)
	files := map[string]localreview.WalkthroughFile{}
	for _, file := range walk.Files {
		files[file.Path] = file
	}
	renamed, ok := files["new-name.txt"]
	if !ok || renamed.Change != "renamed" || renamed.RenamedFrom != "old-name.txt" || *renamed.AddedLines != 0 || *renamed.RemovedLines != 0 {
		t.Fatalf("rename = %+v", renamed)
	}
	if _, listed := files["old-name.txt"]; listed {
		t.Fatal("the rename's source path was also listed as removed")
	}
	if counted := files["notes.md"]; counted.Change != "modified" || counted.AddedLines == nil || *counted.AddedLines != 2 || *counted.RemovedLines != 1 || len(counted.Declarations) != 0 {
		t.Fatalf("notes.md = %+v", counted)
	}
}
