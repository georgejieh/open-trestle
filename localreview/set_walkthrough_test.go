package localreview

import (
	"reflect"
	"strings"
	"testing"
)

func memberWalkthrough(requests, bytes, matches int, verifier *WalkthroughVerifier, missing ...MissingVerification) *Walkthrough {
	added, removed := uint32(1), uint32(1)
	return &Walkthrough{
		Verified: WalkthroughVerified{
			SecretScan:     WalkthroughSecretScan{State: SecretScanScanned, Requests: requests, ScannedBytes: bytes, Matches: matches},
			StaticChecks:   []WalkthroughStaticCheck{{Key: "static_debug_output", State: "passed", CheckedFiles: 1}},
			StyleDetection: WalkthroughStyleDetection{State: "ran", Recommendations: 1},
			SemanticImpact: WalkthroughSemanticImpact{State: "ran", Declarations: 1, References: 1},
			Verifier:       verifier,
		},
		Files:               []WalkthroughFile{{Path: "a.go", Change: "modified", AddedLines: &added, RemovedLines: &removed}},
		MissingVerification: append([]MissingVerification{}, missing...),
	}
}

// A review set's walkthrough totals the secret scan and the verifier over its
// completed members, lists each member's own account, keeps the shared
// per-file summary once and deduplicates missing-verification notes.
func TestAggregateWalkthroughsTotalsTheSet(t *testing.T) {
	changed := MissingVerification{Path: "a.go", Kind: "function", Name: "Changed", Change: "modified"}
	other := MissingVerification{Path: "a.go", Kind: "function", Name: "Other", Change: "added"}
	members := []MemberWalkthrough{
		{Member: "general", Walkthrough: memberWalkthrough(2, 300, 0, &WalkthroughVerifier{Candidates: 1, Verified: 1, Independence: "distinct_provider"}, changed)},
		{Member: "bug_hunter", Walkthrough: memberWalkthrough(2, 350, 1, &WalkthroughVerifier{Candidates: 2, Verified: 1, Rejected: 1, Independence: "distinct_provider"}, changed)},
		{Member: "backend", Walkthrough: memberWalkthrough(2, 340, 0, &WalkthroughVerifier{Candidates: 3, Verified: 0, Rejected: 2, Inconclusive: 1, Independence: "distinct_model"}, changed, other)},
		{Member: "style_conformance", Walkthrough: memberWalkthrough(2, 310, 0, &WalkthroughVerifier{Candidates: 1, Verified: 1, Independence: "distinct_provider"})},
	}
	set := AggregateWalkthroughs(members)
	if set == nil {
		t.Fatal("no set walkthrough")
	}
	if scan := set.Verified.SecretScan; scan != (WalkthroughSecretScan{State: SecretScanScanned, Requests: 8, ScannedBytes: 1300, Matches: 1}) {
		t.Fatalf("secret scan total = %+v", scan)
	}
	// The weakest independence among the members is reported.
	if verifier := set.Verified.Verifier; verifier == nil || *verifier != (WalkthroughVerifier{Candidates: 7, Verified: 3, Rejected: 3, Inconclusive: 1, Independence: "distinct_model"}) {
		t.Fatalf("verifier total = %+v", verifier)
	}
	if len(set.VerifiedByMember) != 4 || set.VerifiedByMember[1].Member != "bug_hunter" || set.VerifiedByMember[1].SecretScan.Requests != 2 || set.VerifiedByMember[1].Verifier.Rejected != 1 {
		t.Fatalf("per-member breakdown = %+v", set.VerifiedByMember)
	}
	if !reflect.DeepEqual(set.MissingVerification, []MissingVerification{changed, other}) || len(set.Files) != 1 {
		t.Fatalf("shared parts: files=%d missing=%+v", len(set.Files), set.MissingVerification)
	}
	// The members' own walkthroughs are not changed.
	if members[0].Walkthrough.Verified.SecretScan.Requests != 2 || len(members[0].Walkthrough.MissingVerification) != 1 {
		t.Fatal("aggregation changed a member's walkthrough")
	}
	text := strings.Join(SetWalkthroughText(set), "")
	for _, want := range []string{
		"verified: secret scan: 8 model requests from 4 reviewers scanned before sending (1300 bytes, 1 secret match)\n",
		"verified: independent verifier (distinct_model): 3 of 7 candidates from 4 reviewers confirmed, 3 rejected, 1 inconclusive\n",
		"file: a.go modified +1 -1\n",
		"missing verification: no test file references the changed function Changed (a.go)\n",
		"missing verification: no test file references the new function Other (a.go)\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("set walkthrough text lacks %q:\n%s", want, text)
		}
	}
	if strings.Count(text, "file: a.go") != 1 || strings.Count(text, "function Changed") != 1 {
		t.Fatalf("a shared line repeats:\n%s", text)
	}
	markdown := SetWalkthroughMarkdown(set)
	if !strings.Contains(markdown, "- Secret scan: 8 model requests from 4 reviewers scanned before sending (1300 bytes, 1 secret match).\n") || !strings.Contains(markdown, "3 of 7 candidates from 4 reviewers confirmed") {
		t.Fatalf("set walkthrough Markdown:\n%s", markdown)
	}
	// One member keeps the single-review wording apart from the reviewer count.
	single := AggregateWalkthroughs(members[:1])
	if text := strings.Join(SetWalkthroughText(single), ""); !strings.Contains(text, "secret scan: 2 model requests from 1 reviewer scanned before sending (300 bytes, 0 secret matches)\n") || !strings.Contains(text, "1 of 1 candidate from 1 reviewer confirmed") {
		t.Fatalf("one-member set walkthrough:\n%s", text)
	}
}

// A member whose scan account could not be read makes the set's scan state
// unavailable; the totals then cover the members that scanned, and the text
// names both. A member without a verified set is not counted as verified.
func TestAggregateWalkthroughsNamesUnreadableAccounts(t *testing.T) {
	unread := memberWalkthrough(0, 0, 0, nil)
	unread.Verified.SecretScan = WalkthroughSecretScan{State: SecretScanUnreadable}
	set := AggregateWalkthroughs([]MemberWalkthrough{
		{Member: "general", Walkthrough: memberWalkthrough(2, 300, 0, &WalkthroughVerifier{Candidates: 1, Verified: 1, Independence: "distinct_provider"})},
		{Member: "bug_hunter", Walkthrough: unread},
		{Member: "backend"},
	})
	if set.Verified.SecretScan.State != SecretScanUnreadable || set.Verified.SecretScan.Requests != 2 {
		t.Fatalf("scan = %+v", set.Verified.SecretScan)
	}
	if set.VerifiedByMember[2].SecretScan.State != SecretScanUnreadable || set.VerifiedByMember[2].Verifier != nil {
		t.Fatalf("a member without a walkthrough = %+v", set.VerifiedByMember[2])
	}
	text := strings.Join(SetWalkthroughText(set), "")
	for _, want := range []string{
		"verified: secret scan: the scan account of 2 of 3 reviewers could not be read; 2 model requests from 1 reviewer scanned before sending (300 bytes, 0 secret matches)\n",
		"verified: independent verifier (distinct_provider): 1 of 1 candidate from 1 of 3 reviewers confirmed, 0 rejected, 0 inconclusive\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("set walkthrough text lacks %q:\n%s", want, text)
		}
	}
	if AggregateWalkthroughs([]MemberWalkthrough{{Member: "general"}}) != nil || AggregateWalkthroughs(nil) != nil {
		t.Fatal("a set walkthrough was built without any member walkthrough")
	}
}
