package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/georgejieh/open-trestle/localreview"
)

// A completed review whose confirmed findings are all low severity is
// advisory: it keeps status findings, is inconclusive rather than blocked,
// and maps through the exit-code policies like an all-pre-existing review:
// default 3, findings 0, strict 3 (there were candidates), always-zero 0.
func TestLowSeverityOnlyReviewIsAdvisory(t *testing.T) {
	for policy, want := range map[string]int{"default": 3, "findings": 0, "strict": 3, "always-zero": 0} {
		f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: "low"})
		receipt, _ := runJudgement(t, f, []string{"--exit-code-policy", policy}, want)
		if receipt.Status != "findings" || receipt.CI != "inconclusive" || len(receipt.Rank) != 1 || len(receipt.PreExisting) != 0 {
			t.Fatalf("policy %s: status=%s ci=%s rank=%d pre_existing=%v", policy, receipt.Status, receipt.CI, len(receipt.Rank), receipt.PreExisting)
		}
	}
	// SARIF keeps the finding's level and reports the disposition.
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: "low"})
	var sarif struct {
		Runs []struct {
			Properties struct {
				CI string `json:"trestleCiDisposition"`
			} `json:"properties"`
			Results []struct {
				Level string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(runModelReviewOutput(t, f, []string{"--format", "sarif"}, 3)), &sarif); err != nil || len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 || sarif.Runs[0].Results[0].Level != "note" || sarif.Runs[0].Properties.CI != "inconclusive" {
		t.Fatalf("SARIF of an advisory run: %+v %v", sarif, err)
	}
}

// A medium finding the change introduced still blocks; only the findings
// policy (no high or critical finding) and always-zero exit 0. A high finding
// blocks under every policy but always-zero.
func TestIntroducedMediumOrHighFindingStillBlocks(t *testing.T) {
	for mode, codes := range map[string]map[string]int{
		"medium": {"default": 4, "findings": 0, "strict": 4, "always-zero": 0},
		"":       {"default": 4, "findings": 4, "strict": 4, "always-zero": 0},
	} {
		for policy, want := range codes {
			f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: mode})
			receipt, _ := runJudgement(t, f, []string{"--exit-code-policy", policy}, want)
			if receipt.Status != "findings" || receipt.CI != "blocked" {
				t.Fatalf("mode %q policy %s: status=%s ci=%s", mode, policy, receipt.Status, receipt.CI)
			}
		}
	}
}

// The import re-derives the advisory disposition from the recorded
// severities and refuses any other: a low-severity-only result imports as
// inconclusive and is refused when it claims blocked; a medium result must be
// blocked and is refused when it claims inconclusive.
func TestParseCompletedResultRederivesAdvisoryDisposition(t *testing.T) {
	low := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: "low"})
	_, advisory := runJudgement(t, low, nil, 3)
	imported, err := localreview.ParseCompletedResult(advisory)
	if err != nil {
		t.Fatalf("an advisory low-severity result does not import: %v", err)
	}
	if imported.CIDisposition() != "inconclusive" || imported.ExitCode() != 3 || imported.ExitCodeFor(localreview.ExitPolicyStrict) != 3 || imported.ExitCodeFor(localreview.ExitPolicyFindings) != 0 {
		t.Fatalf("imported advisory result: ci=%s exit=%d", imported.CIDisposition(), imported.ExitCode())
	}
	blocked := bytes.Replace(advisory, []byte(`"ci_disposition":"inconclusive"`), []byte(`"ci_disposition":"blocked"`), 1)
	if bytes.Equal(blocked, advisory) {
		t.Fatal("the disposition was not changed")
	}
	if _, err := localreview.ParseCompletedResult(blocked); err == nil {
		t.Fatal("a low-severity-only result claiming blocked was accepted")
	}
	medium := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: "medium"})
	_, honest := runJudgement(t, medium, nil, 4)
	if _, err := localreview.ParseCompletedResult(honest); err != nil {
		t.Fatalf("the blocked medium result does not import: %v", err)
	}
	relaxed := bytes.Replace(honest, []byte(`"ci_disposition":"blocked"`), []byte(`"ci_disposition":"inconclusive"`), 1)
	if bytes.Equal(relaxed, honest) {
		t.Fatal("the disposition was not changed")
	}
	if _, err := localreview.ParseCompletedResult(relaxed); err == nil {
		t.Fatal("a self-asserted relaxation of a medium finding was accepted")
	}
}

// A review set follows the same rule: merged findings that are all low
// severity are advisory, and a medium finding blocks.
func TestReviewSetLowSeverityOnlyIsAdvisory(t *testing.T) {
	for policy, want := range map[string]int{"default": 3, "findings": 0, "strict": 3, "always-zero": 0} {
		f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: "low"})
		receipt, _ := runLocalModelSet(t, f, []string{"--specialists", "bug_hunter", "--exit-code-policy", policy}, want)
		if receipt.Status != "findings" || receipt.CI != "inconclusive" || !receipt.Complete || len(receipt.Findings) != 1 {
			t.Fatalf("policy %s: set status=%s ci=%s complete=%t findings=%d", policy, receipt.Status, receipt.CI, receipt.Complete, len(receipt.Findings))
		}
		for _, member := range receipt.Members {
			if member.CI != "inconclusive" {
				t.Fatalf("policy %s: member %s ci=%s", policy, member.Member, member.CI)
			}
		}
	}
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: "medium"})
	if receipt, _ := runLocalModelSet(t, f, []string{"--specialists", "bug_hunter"}, 4); receipt.CI != "blocked" {
		t.Fatalf("a set with a medium finding is %s", receipt.CI)
	}
}
