package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/localreview"
)

type paraphraseSetReceipt struct {
	Findings []struct {
		FindingIdentity string `json:"finding_identity"`
		Title           string `json:"title"`
		Contributors    []struct {
			Member string `json:"member"`
		} `json:"contributors"`
		Merged []struct {
			Member          string `json:"member"`
			FindingIdentity string `json:"finding_identity"`
			Title           string `json:"title"`
			Claim           string `json:"claim"`
			Rule            string `json:"rule"`
		} `json:"merged"`
	} `json:"findings"`
	Summary struct {
		DuplicatesMerged int `json:"duplicates_merged"`
	} `json:"summary"`
}

// A specialist's paraphrase of the general review's finding, at the same
// lines inside the same changed function and in one category family, is one
// defect: the set reports it once, lists the other wording in merged[] with
// the rule, and text and Markdown show it as "also reported as".
func TestReviewSetMergesAParaphraseInTheSameDeclaration(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, specialist: true, generationMode: "paraphrase_specialist"})
	_, stdout := runLocalModelSet(t, f, []string{"--specialists", "bug_hunter"}, 4)
	var receipt paraphraseSetReceipt
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
		t.Fatal(err)
	}
	if len(receipt.Findings) != 1 || receipt.Summary.DuplicatesMerged != 1 {
		t.Fatalf("the paraphrase was not merged: findings=%d duplicates=%d", len(receipt.Findings), receipt.Summary.DuplicatesMerged)
	}
	finding := receipt.Findings[0]
	if finding.Title != "Zero-valued caller now panics" || len(finding.Contributors) != 2 || len(finding.Merged) != 1 {
		t.Fatalf("merged finding = %+v", finding)
	}
	merged := finding.Merged[0]
	if merged.Member != "bug_hunter" || merged.Title != "Changed panics on a zero divisor" || !strings.Contains(merged.Claim, "missing division guard") || merged.Rule != localreview.MergeRuleSameDeclaration || merged.FindingIdentity == finding.FindingIdentity {
		t.Fatalf("merged wording = %+v", merged)
	}
	text := runModelReviewOutput(t, f, []string{"--specialists", "bug_hunter", "--format", "text"}, 4)
	requireInOrder(t, text, "confirmed findings (ranked): 1\n", "finding: error Zero-valued caller now panics\n", "also reported as: Changed panics on a zero divisor (bug_hunter)\n")
	markdown := runModelReviewOutput(t, f, []string{"--specialists", "bug_hunter", "--format", "markdown"}, 4)
	requireInOrder(t, markdown, "1. **High or critical: Zero-valued caller now panics**", "   Also reported as: Changed panics on a zero divisor (`bug_hunter`)\n")
}

// A specialist's different defect at the same lines, in the same changed
// function and category family, is a second finding: the set lists both,
// each confirmed by its own member, and neither is shown as the other's
// wording.
func TestReviewSetKeepsADifferentDefectAtTheSameLinesApart(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, specialist: true, generationMode: "distinct_specialist"})
	_, stdout := runLocalModelSet(t, f, []string{"--specialists", "bug_hunter"}, 4)
	var receipt paraphraseSetReceipt
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
		t.Fatal(err)
	}
	if len(receipt.Findings) != 2 || receipt.Summary.DuplicatesMerged != 0 {
		t.Fatalf("distinct defects merged: findings=%d duplicates=%d", len(receipt.Findings), receipt.Summary.DuplicatesMerged)
	}
	members := map[string]string{}
	for _, finding := range receipt.Findings {
		if len(finding.Contributors) != 1 || len(finding.Merged) != 0 {
			t.Fatalf("finding %q: contributors=%+v merged=%+v", finding.Title, finding.Contributors, finding.Merged)
		}
		members[finding.Title] = finding.Contributors[0].Member
	}
	if members["Zero-valued caller now panics"] != "general" || members["Changed truncates the quotient"] != "bug_hunter" {
		t.Fatalf("findings by member = %v", members)
	}
	text := runModelReviewOutput(t, f, []string{"--specialists", "bug_hunter", "--format", "text"}, 4)
	if !strings.Contains(text, "confirmed findings (ranked): 2\n") || strings.Contains(text, "also reported as:") {
		t.Fatalf("text output:\n%s", text)
	}
}

// A direct result records which findings a changed declaration holds; the
// import checks each anchor names a finding and contains its lines.
func TestDirectResultRecordsDeclarationAnchors(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true})
	_, stdout := runJudgement(t, f, nil, 4)
	var receipt struct {
		Anchors []struct {
			FindingIdentity string `json:"finding_identity"`
			StartLine       uint32 `json:"start_line"`
			EndLine         uint32 `json:"end_line"`
		} `json:"declaration_anchors"`
		Diagnostics struct {
			Findings []struct {
				Identity string `json:"identity"`
			} `json:"findings"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(stdout, &receipt); err != nil {
		t.Fatal(err)
	}
	// The fixture's finding is a.go:2, inside the one-line function Changed.
	if len(receipt.Anchors) != 1 || receipt.Anchors[0].FindingIdentity != receipt.Diagnostics.Findings[0].Identity || receipt.Anchors[0].StartLine != 2 || receipt.Anchors[0].EndLine != 2 {
		t.Fatalf("declaration anchors = %+v", receipt.Anchors)
	}
	if _, err := localreview.ParseCompletedResult(stdout); err != nil {
		t.Fatalf("a result with declaration anchors does not import: %v", err)
	}
	identity := receipt.Anchors[0].FindingIdentity
	anchor := []byte(`"declaration_anchors":[{"finding_identity":"` + identity + `","start_line":2,"end_line":2}]`)
	if !bytes.Contains(stdout, anchor) {
		t.Fatalf("the anchor is not where expected: %s", stdout)
	}
	for name, tampered := range map[string][]byte{
		"outside the finding": bytes.Replace(stdout, anchor, []byte(`"declaration_anchors":[{"finding_identity":"`+identity+`","start_line":3,"end_line":9}]`), 1),
		"unknown finding":     bytes.Replace(stdout, anchor, []byte(`"declaration_anchors":[{"finding_identity":"`+strings.Repeat("a", 64)+`","start_line":2,"end_line":2}]`), 1),
		"repeated finding":    bytes.Replace(stdout, anchor, []byte(`"declaration_anchors":[{"finding_identity":"`+identity+`","start_line":2,"end_line":2},{"finding_identity":"`+identity+`","start_line":1,"end_line":2}]`), 1),
		"zero start":          bytes.Replace(stdout, anchor, []byte(`"declaration_anchors":[{"finding_identity":"`+identity+`","start_line":0,"end_line":2}]`), 1),
	} {
		if bytes.Equal(tampered, stdout) {
			t.Fatalf("%s: tampering did not change the result", name)
		}
		if _, err := localreview.ParseCompletedResult(tampered); err == nil {
			t.Fatalf("%s: an inconsistent declaration anchor was accepted", name)
		}
	}
}
