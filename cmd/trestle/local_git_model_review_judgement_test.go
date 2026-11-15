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
	// The strict reader cannot re-derive the class without the change, so it
	// refuses a result whose CI disposition the class relaxed. With the
	// readiness disposition the list is advisory and the result imports; a
	// rank its own findings do not produce is refused.
	if _, err := localreview.ParseCompletedResult(stdout); err == nil {
		t.Fatal("ParseCompletedResult accepted a CI disposition relaxed by an unverifiable pre-existing class")
	}
	readiness := bytes.Replace(stdout, []byte(`"ci_disposition":"inconclusive"`), []byte(`"ci_disposition":"blocked"`), 1)
	if _, err := localreview.ParseCompletedResult(readiness); err != nil {
		t.Fatalf("ParseCompletedResult refused an advisory pre_existing list: %v", err)
	}
	for _, tampered := range [][]byte{
		bytes.Replace(readiness, []byte(`"rank":1,`), []byte(`"rank":2,`), 1),
		bytes.Replace(readiness, []byte(`"pre_existing":["`+identity+`"]`), []byte(`"pre_existing":["`+identity+`","`+identity+`"]`), 1),
		bytes.Replace(readiness, []byte(`"pre_existing":["`+identity+`"]`), []byte(`"pre_existing":["`+strings.Repeat("a", 64)+`"]`), 1),
	} {
		if bytes.Equal(tampered, stdout) {
			t.Fatal("tampering did not change the result")
		}
		if _, err := localreview.ParseCompletedResult(tampered); err == nil {
			t.Fatal("ParseCompletedResult accepted an inconsistent judgement")
		}
	}
}

// An imported result is untrusted: the importer cannot re-derive the
// pre-existing class without the change, so a crafted result that marks its
// blocking finding pre-existing and claims a non-blocking CI disposition is
// refused.
func TestParseCompletedResultRefusesSelfAssertedPreExistingRelaxation(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true})
	receipt, stdout := runJudgement(t, f, nil, 4)
	if receipt.CI != "blocked" || len(receipt.Rank) != 1 || len(receipt.PreExisting) != 0 {
		t.Fatalf("fixture: ci=%s rank=%+v pre_existing=%v", receipt.CI, receipt.Rank, receipt.PreExisting)
	}
	if _, err := localreview.ParseCompletedResult(stdout); err != nil {
		t.Fatalf("the honest result does not import: %v", err)
	}
	identity := receipt.Rank[0].FindingIdentity
	rank := []byte(`"rank":[{"rank":1,"finding_identity":"` + identity + `"}]`)
	crafted := bytes.Replace(stdout, rank, append(append([]byte(nil), rank...), []byte(`,"pre_existing":["`+identity+`"]`)...), 1)
	crafted = bytes.Replace(crafted, []byte(`"ci_disposition":"blocked"`), []byte(`"ci_disposition":"inconclusive"`), 1)
	if bytes.Equal(crafted, stdout) || !bytes.Contains(crafted, []byte(`"pre_existing":["`+identity+`"]`)) || !bytes.Contains(crafted, []byte(`"ci_disposition":"inconclusive"`)) {
		t.Fatal("the crafted result was not built")
	}
	if _, err := localreview.ParseCompletedResult(crafted); err == nil {
		t.Fatal("ParseCompletedResult accepted a self-asserted pre-existing relaxation of a blocking finding")
	}
	// With the readiness disposition kept, the recorded class is advisory: the
	// result imports, and no exit policy trusts it.
	advisory := bytes.Replace(crafted, []byte(`"ci_disposition":"inconclusive"`), []byte(`"ci_disposition":"blocked"`), 1)
	imported, err := localreview.ParseCompletedResult(advisory)
	if err != nil {
		t.Fatalf("an advisory pre_existing list with the readiness disposition does not import: %v", err)
	}
	if code := imported.ExitCodeFor(localreview.ExitPolicyFindings); code != 4 {
		t.Fatalf("an imported pre_existing list relaxed the findings policy: exit %d", code)
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
