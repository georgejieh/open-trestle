package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/localreview"
)

// oldFunctionFixture is the ordinary fixture whose model, in the pre_existing
// modes, reports a defect on the unchanged caller line caller.go:2, which
// reaches it as a direct reference to the changed function.
func oldFunctionFixture(t *testing.T, mode string) *localModelFixture {
	t.Helper()
	return newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, generationMode: mode, verificationMode: mode})
}

type judgementReceipt struct {
	Status string `json:"status"`
	CI     string `json:"ci_disposition"`
	Rank   []struct {
		Rank            int      `json:"rank"`
		FindingIdentity string   `json:"finding_identity"`
		Merged          []string `json:"merged_finding_identities"`
	} `json:"rank"`
	PreExisting []string `json:"pre_existing"`
	Diagnostics struct {
		Findings []struct {
			Identity string `json:"identity"`
		} `json:"findings"`
	} `json:"diagnostics"`
}

func runJudgement(t *testing.T, f *localModelFixture, extra []string, wantCode int) (judgementReceipt, []byte) {
	t.Helper()
	args := append(append([]string(nil), f.args...), extra...)
	_, stdout := localModelExecute(t, f, args, wantCode)
	var receipt judgementReceipt
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt, []byte(stdout)
}

// A confirmed finding anchored only on an unchanged caller line,
// citing no change evidence, is pre-existing: the result lists it under
// pre_existing and in rank, keeps status findings, and is not blocked.
func TestRunLocalGitModelReviewClassifiesPreExistingFinding(t *testing.T) {
	f := oldFunctionFixture(t, "pre_existing")
	receipt, stdout := runJudgement(t, f, nil, 3)
	if receipt.Status != "findings" || receipt.CI != "inconclusive" || len(receipt.Diagnostics.Findings) != 1 {
		t.Fatalf("status=%s ci=%s findings=%d", receipt.Status, receipt.CI, len(receipt.Diagnostics.Findings))
	}
	identity := receipt.Diagnostics.Findings[0].Identity
	if len(receipt.PreExisting) != 1 || receipt.PreExisting[0] != identity || len(receipt.Rank) != 1 || receipt.Rank[0].Rank != 1 || receipt.Rank[0].FindingIdentity != identity {
		t.Fatalf("pre_existing=%v rank=%+v", receipt.PreExisting, receipt.Rank)
	}
	// The strict reader accepts the recorded judgement and the non-blocking
	// disposition, and refuses a judgement its own findings do not produce.
	if _, err := localreview.ParseCompletedResult(stdout); err != nil {
		t.Fatalf("ParseCompletedResult refused a pre-existing result: %v", err)
	}
	for _, tampered := range [][]byte{
		bytes.Replace(stdout, []byte(`"ci_disposition":"inconclusive"`), []byte(`"ci_disposition":"blocked"`), 1),
		bytes.Replace(stdout, []byte(`,"pre_existing":["`+identity+`"]`), nil, 1),
		bytes.Replace(stdout, []byte(`"rank":1,`), []byte(`"rank":2,`), 1),
	} {
		if bytes.Equal(tampered, stdout) {
			t.Fatal("tampering did not change the result")
		}
		if _, err := localreview.ParseCompletedResult(tampered); err == nil {
			t.Fatal("ParseCompletedResult accepted an inconsistent judgement")
		}
	}
}

// Pre-existing findings never block CI, and every exit-code policy keeps its
// meaning: default stays non-zero (3, inconclusive), findings exits 0 (no
// introduced high or critical finding), strict stays non-zero (there were
// candidates), and always-zero exits 0.
func TestPreExistingFindingsUnderEachExitCodePolicy(t *testing.T) {
	for policy, want := range map[string]int{"default": 3, "findings": 0, "strict": 3, "always-zero": 0} {
		f := oldFunctionFixture(t, "pre_existing")
		receipt, _ := runJudgement(t, f, []string{"--exit-code-policy", policy}, want)
		if receipt.CI != "inconclusive" || len(receipt.PreExisting) != 1 {
			t.Fatalf("policy %s: ci=%s pre_existing=%v", policy, receipt.CI, receipt.PreExisting)
		}
	}
}

// The same location citing the changed hunk is evidence of the change: the
// finding is introduced, blocks, and the findings policy keeps exit 4.
func TestFindingCitingChangeEvidenceIsNotPreExisting(t *testing.T) {
	for policy, want := range map[string]int{"default": 4, "findings": 4} {
		f := oldFunctionFixture(t, "pre_existing_cited_change")
		receipt, _ := runJudgement(t, f, []string{"--exit-code-policy", policy}, want)
		if receipt.Status != "findings" || receipt.CI != "blocked" || len(receipt.PreExisting) != 0 || len(receipt.Rank) != 1 {
			t.Fatalf("policy %s: status=%s ci=%s pre_existing=%v rank=%d", policy, receipt.Status, receipt.CI, receipt.PreExisting, len(receipt.Rank))
		}
	}
	// The ordinary fixture's finding is on the changed line and cites its
	// caller: introduced, ranked first, never pre-existing.
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true})
	receipt, stdout := runJudgement(t, f, nil, 4)
	if receipt.CI != "blocked" || len(receipt.PreExisting) != 0 || len(receipt.Rank) != 1 || strings.Contains(string(stdout), `"pre_existing"`) {
		t.Fatalf("ordinary finding: ci=%s pre_existing=%v rank=%+v", receipt.CI, receipt.PreExisting, receipt.Rank)
	}
}
