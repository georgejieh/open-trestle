package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
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
	f := newCheckoutModelFixture(t, localModelFixtureOptions{chatCompletions: true})
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
	f := newCheckoutModelFixture(t, localModelFixtureOptions{chatCompletions: true, extraBase: map[string][]byte{"a_test.go": test}, extraHead: map[string][]byte{"a_test.go": test}})
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

// A review set's walkthrough describes the whole set: the secret scan and the
// independent verifier are totals over every completed member, each member's
// own account is in verified_by_member, and the per-file summary and the
// missing-verification note appear once.
func TestReviewSetWalkthroughTotalsEveryMember(t *testing.T) {
	f := newCheckoutModelFixture(t, localModelFixtureOptions{chatCompletions: true, specialist: true})
	_, stdout := runLocalModelSet(t, f, []string{"--specialists", "auto"}, 4)
	var receipt struct {
		Members []struct {
			Member string `json:"member"`
		} `json:"members"`
		Walkthrough *localreview.SetWalkthrough `json:"walkthrough"`
	}
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil || receipt.Walkthrough == nil {
		t.Fatalf("set has no walkthrough: %v", err)
	}
	walk := receipt.Walkthrough
	if len(receipt.Members) < 3 || len(walk.VerifiedByMember) != len(receipt.Members) {
		t.Fatalf("members=%d verified_by_member=%d", len(receipt.Members), len(walk.VerifiedByMember))
	}
	requests, bytes := 0, 0
	for index, member := range walk.VerifiedByMember {
		if member.Member != receipt.Members[index].Member || member.SecretScan.State != localreview.SecretScanScanned || member.SecretScan.Requests != 2 || member.Verifier == nil || member.Verifier.Verified != 1 {
			t.Fatalf("member account %d = %+v", index, member)
		}
		requests, bytes = requests+member.SecretScan.Requests, bytes+member.SecretScan.ScannedBytes
	}
	if scan := walk.Verified.SecretScan; scan.State != localreview.SecretScanScanned || scan.Requests != requests || scan.ScannedBytes != bytes || requests != 2*len(receipt.Members) {
		t.Fatalf("set secret scan = %+v, members sent %d requests (%d bytes)", scan, requests, bytes)
	}
	members := len(receipt.Members)
	if verifier := walk.Verified.Verifier; verifier == nil || int(verifier.Candidates) != members || int(verifier.Verified) != members || verifier.Independence != "distinct_provider" {
		t.Fatalf("set verifier = %+v", verifier)
	}
	if len(walk.Files) != 1 || len(walk.MissingVerification) != 1 {
		t.Fatalf("shared parts: files=%+v missing=%+v", walk.Files, walk.MissingVerification)
	}
	text := runModelReviewOutput(t, f, []string{"--specialists", "auto", "--format", "text"}, 4)
	requireInOrder(t, text, "walkthrough:\n",
		fmt.Sprintf("verified: secret scan: %d model requests from %d reviewers scanned before sending (", requests, members),
		fmt.Sprintf("verified: independent verifier (distinct_provider): %d of %d candidates from %d reviewers confirmed, 0 rejected, 0 inconclusive\n", members, members, members),
		"file: a.go modified +1 -1; changed function Changed\n",
		"missing verification: no test file references the changed function Changed (a.go)\n")
	if strings.Count(text, "file: a.go") != 1 || strings.Count(text, "missing verification:") != 1 {
		t.Fatalf("a shared walkthrough line repeats:\n%s", text)
	}
	markdown := runModelReviewOutput(t, f, []string{"--specialists", "auto", "--format", "markdown"}, 4)
	requireInOrder(t, markdown, "### What was verified\n\n", fmt.Sprintf("- Secret scan: %d model requests from %d reviewers scanned before sending (", requests, members), fmt.Sprintf("candidates from %d reviewers confirmed", members))
}
