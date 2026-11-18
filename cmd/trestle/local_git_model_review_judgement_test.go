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
	PreExisting    []string `json:"pre_existing"`
	UnprovenOrigin []string `json:"unproven_origin"`
	Diagnostics    struct {
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

// A confirmed finding anchored only on an unchanged caller line, citing no
// change evidence, is still a dependent of the changed function: the change
// may have broken it. Its origin is unproven, so the result lists it under
// unproven_origin and in rank, and it blocks like an introduced finding.
func TestRunLocalGitModelReviewMarksACallerOfTheChangeOfUnprovenOrigin(t *testing.T) {
	f := oldFunctionFixture(t, "pre_existing")
	receipt, stdout := runJudgement(t, f, nil, 4)
	if receipt.Status != "findings" || receipt.CI != "blocked" || len(receipt.Diagnostics.Findings) != 1 {
		t.Fatalf("status=%s ci=%s findings=%d", receipt.Status, receipt.CI, len(receipt.Diagnostics.Findings))
	}
	identity := receipt.Diagnostics.Findings[0].Identity
	if len(receipt.PreExisting) != 0 || len(receipt.UnprovenOrigin) != 1 || receipt.UnprovenOrigin[0] != identity || len(receipt.Rank) != 1 || receipt.Rank[0].Rank != 1 || receipt.Rank[0].FindingIdentity != identity {
		t.Fatalf("pre_existing=%v unproven_origin=%v rank=%+v", receipt.PreExisting, receipt.UnprovenOrigin, receipt.Rank)
	}
	imported, err := localreview.ParseCompletedResult(stdout)
	if err != nil {
		t.Fatalf("ParseCompletedResult refused an unproven_origin list: %v", err)
	}
	if code := imported.ExitCodeFor(localreview.ExitPolicyFindings); code != 4 {
		t.Fatalf("an imported finding of unproven origin did not block the findings policy: exit %d", code)
	}
	for name, tampered := range map[string][]byte{
		"rank":     bytes.Replace(stdout, []byte(`"rank":1,`), []byte(`"rank":2,`), 1),
		"repeated": bytes.Replace(stdout, []byte(`"unproven_origin":["`+identity+`"]`), []byte(`"unproven_origin":["`+identity+`","`+identity+`"]`), 1),
		"unknown":  bytes.Replace(stdout, []byte(`"unproven_origin":["`+identity+`"]`), []byte(`"unproven_origin":["`+strings.Repeat("a", 64)+`"]`), 1),
		"both":     bytes.Replace(stdout, []byte(`"unproven_origin":["`+identity+`"]`), []byte(`"pre_existing":["`+identity+`"],"unproven_origin":["`+identity+`"]`), 1),
	} {
		if bytes.Equal(tampered, stdout) {
			t.Fatalf("%s: tampering did not change the result", name)
		}
		if _, err := localreview.ParseCompletedResult(tampered); err == nil {
			t.Fatalf("%s: ParseCompletedResult accepted an inconsistent judgement", name)
		}
	}
	// A pre_existing list in place of the unproven one keeps the readiness
	// disposition and is advisory: the result imports, and no exit policy
	// trusts it.
	advisory := bytes.Replace(stdout, []byte(`"unproven_origin":["`+identity+`"]`), []byte(`"pre_existing":["`+identity+`"]`), 1)
	if imported, err := localreview.ParseCompletedResult(advisory); err != nil || imported.ExitCodeFor(localreview.ExitPolicyFindings) != 4 {
		t.Fatalf("an advisory pre_existing list: err=%v", err)
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

// A high finding of unproven origin blocks under every exit-code policy that
// an introduced one blocks: default, findings and strict exit 4, and only
// always-zero exits 0.
func TestUnprovenOriginFindingsUnderEachExitCodePolicy(t *testing.T) {
	for policy, want := range map[string]int{"default": 4, "findings": 4, "strict": 4, "always-zero": 0} {
		f := oldFunctionFixture(t, "pre_existing")
		receipt, _ := runJudgement(t, f, []string{"--exit-code-policy", policy}, want)
		if receipt.CI != "blocked" || len(receipt.PreExisting) != 0 || len(receipt.UnprovenOrigin) != 1 {
			t.Fatalf("policy %s: ci=%s pre_existing=%v unproven_origin=%v", policy, receipt.CI, receipt.PreExisting, receipt.UnprovenOrigin)
		}
	}
}

// The same location citing the changed hunk is evidence of the change: the
// finding is introduced, blocks, and the findings policy keeps exit 4.
func TestFindingCitingChangeEvidenceIsNotPreExisting(t *testing.T) {
	for policy, want := range map[string]int{"default": 4, "findings": 4} {
		f := oldFunctionFixture(t, "pre_existing_cited_change")
		receipt, _ := runJudgement(t, f, []string{"--exit-code-policy", policy}, want)
		if receipt.Status != "findings" || receipt.CI != "blocked" || len(receipt.PreExisting) != 0 || len(receipt.UnprovenOrigin) != 0 || len(receipt.Rank) != 1 {
			t.Fatalf("policy %s: status=%s ci=%s pre_existing=%v unproven_origin=%v rank=%d", policy, receipt.Status, receipt.CI, receipt.PreExisting, receipt.UnprovenOrigin, len(receipt.Rank))
		}
	}
	// The ordinary fixture's finding is on the changed line and cites its
	// caller: introduced, ranked first, never pre-existing.
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true})
	receipt, stdout := runJudgement(t, f, nil, 4)
	if receipt.CI != "blocked" || len(receipt.PreExisting) != 0 || len(receipt.Rank) != 1 || strings.Contains(string(stdout), `"pre_existing"`) || strings.Contains(string(stdout), `"unproven_origin"`) {
		t.Fatalf("ordinary finding: ci=%s pre_existing=%v rank=%+v", receipt.CI, receipt.PreExisting, receipt.Rank)
	}
}

// A review set whose merged findings are all on unchanged lines that the
// change may affect marks them unproven_origin and blocks; the findings
// policy keeps exit 4.
func TestReviewSetUnprovenOriginFindingsBlock(t *testing.T) {
	f := oldFunctionFixture(t, "pre_existing")
	receipt, stdout := runLocalModelSet(t, f, []string{"--specialists", "bug_hunter"}, 4)
	if receipt.Status != "findings" || receipt.CI != "blocked" || !receipt.Complete || len(receipt.Findings) != 1 {
		t.Fatalf("set status=%s ci=%s complete=%t findings=%d", receipt.Status, receipt.CI, receipt.Complete, len(receipt.Findings))
	}
	if !strings.Contains(stdout, `"unproven_origin":true`) || strings.Contains(stdout, `"pre_existing":true`) {
		t.Fatalf("set finding origin class:\n%s", stdout)
	}
	runLocalModelSet(t, f, []string{"--specialists", "bug_hunter", "--exit-code-policy", "findings"}, 4)
}
