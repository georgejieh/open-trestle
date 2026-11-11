package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/agentprofile"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/localreview"
)

// Regressions for defects found in the first live end-to-end runs. The fake
// model servers reuse the captured live response shapes; no real model runs.

func runLocalModelText(t *testing.T, f *localModelFixture, wantCode int, extra ...string) string {
	t.Helper()
	args := replaceLocalGitChangeValue(append([]string(nil), f.args...), "--format", "text")
	args = append(args, extra...)
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != wantCode {
		t.Fatalf("exit=%d want=%d stdout=%q stderr=%q", code, wantCode, stdout.String(), stderr.String())
	}
	for _, forbidden := range []string{localModelSecret, localModelKey, "Bearer "} {
		if strings.Contains(stdout.String()+stderr.String(), forbidden) {
			t.Fatal("text output disclosed private input")
		}
	}
	return stdout.String()
}

// Defect A: a change that only removes a guard used to be refused at the
// context task (failure policy, all_sources_omitted) before any model call.
func TestLocalModelReviewReviewsDeletionOnlyChange(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, deletionOnly: true})
	result, _ := localModelExecute(t, f, f.args, 4)
	gc, _ := f.generation.snapshot()
	vc, _ := f.verification.snapshot()
	if result.Status != "findings" || result.RunStatus != "succeeded" || gc != 1 || vc != 1 || len(result.Diagnostics.Findings) != 1 {
		t.Fatalf("deletion-only review status=%s run=%s calls=%d/%d findings=%d", result.Status, result.RunStatus, gc, vc, len(result.Diagnostics.Findings))
	}
	text := runLocalModelText(t, newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, deletionOnly: true}), 4)
	if !strings.Contains(text, "status: findings\n") || strings.Contains(text, "failure:") || !strings.Contains(text, "source omission: unsupported=1\n") {
		t.Fatalf("deletion-only text=%q", text)
	}
}

// Removing a file over the 1 MiB change-model size bound failed the analysis
// task with an internal error, so the whole review failed; adding one that
// gets no whole-text range was recorded as an empty added file. Each is now a
// resource_limit omission, and the small Go change beside it is reviewed.
func TestLocalModelReviewRecordsALargeFileAsAResourceLimit(t *testing.T) {
	large := map[string][]byte{"large.bin": bytes.Repeat([]byte("large file line\n"), 128<<10)}
	binary := map[string][]byte{"large.bin": bytes.Repeat([]byte{0, 1, 2, 3}, 512<<10)}
	for _, tc := range []struct {
		name    string
		options localModelFixtureOptions
	}{
		{"removed", localModelFixtureOptions{chatCompletions: true, extraBase: large}},
		{"added", localModelFixtureOptions{chatCompletions: true, extraHead: binary}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLocalModelFixture(t, tc.options)
			result, _ := localModelExecute(t, f, f.args, 4)
			if result.Status != "findings" || result.RunStatus != "succeeded" || len(result.Diagnostics.Findings) != 1 || result.Diagnostics.Findings[0].Path != "a.go" {
				t.Fatalf("review beside a large %s file: status=%s run=%s findings=%d", tc.name, result.Status, result.RunStatus, len(result.Diagnostics.Findings))
			}
			text := runLocalModelText(t, newLocalModelFixture(t, tc.options), 4)
			if !strings.Contains(text, "status: findings\n") || !strings.Contains(text, "resource_limit=") {
				t.Fatalf("large %s file text=%q", tc.name, text)
			}
		})
	}
}

// A change that only removes a file used to be refused at the context task
// (all_sources_omitted). It is now reviewed from the file's removed text, and
// the verified finding is on its removed base lines.
func TestLocalModelReviewReviewsAChangeThatOnlyRemovesAFile(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, removedOnly: true})
	result, _ := localModelExecute(t, f, f.args, 4)
	gc, _ := f.generation.snapshot()
	vc, _ := f.verification.snapshot()
	if result.Status != "findings" || result.RunStatus != "succeeded" || gc != 1 || vc != 1 || len(result.Diagnostics.Findings) != 1 {
		t.Fatalf("removed-only review status=%s run=%s calls=%d/%d findings=%d", result.Status, result.RunStatus, gc, vc, len(result.Diagnostics.Findings))
	}
	if finding := result.Diagnostics.Findings[0]; finding.Path != "gone.go" || finding.Side != "base" || finding.Start != 3 || finding.End != 3 || finding.HeadLine != 0 {
		t.Fatalf("removed-file finding=%+v", finding)
	}
	text := runLocalModelText(t, newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, removedOnly: true}), 4)
	if !strings.Contains(text, "status: findings\n") || !strings.Contains(text, "source: gone.go removed base lines 3-3\n") || strings.Contains(text, "gone.go:3-3") {
		t.Fatalf("removed-only text=%q", text)
	}
}

// Defect B: a failed run printed only its status; it now names the failure
// class, the failing task and a plain-language hint.
func TestLocalModelReviewTextNamesFailureClassTaskAndHint(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "malformed"})
	text := runLocalModelText(t, f, 1)
	if !strings.Contains(text, "run: failed\nfailure: internal (task candidates)\nhint: a model response could not be accepted") {
		t.Fatalf("failure line missing: %q", text)
	}
	succeeded := runLocalModelText(t, newLocalModelFixture(t, localModelFixtureOptions{}), 4)
	if strings.Contains(succeeded, "failure:") || strings.Contains(succeeded, "hint:") {
		t.Fatalf("succeeded run printed a failure line: %q", succeeded)
	}
}

// Defect C: a reasoning verifier that stopped at the output limit with empty
// content (the live nemotron reply) failed as a generic internal failure.
func TestLocalModelReviewReportsExhaustedVerifierOutput(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: "exhausted"})
	var stdout, stderr bytes.Buffer
	if code := run(f.args, &stdout, &stderr); code != 1 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	var wire struct {
		Status        string `json:"status"`
		Failure       string `json:"failure"`
		FailureDetail string `json:"failure_detail"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &wire); err != nil || wire.Status != "failed" || wire.Failure != "internal" || wire.FailureDetail != localreview.FailureDetailModelOutputExhausted {
		t.Fatalf("result=%+v err=%v", wire, err)
	}
	// The exhausted verifier reply reported its usage, so the failed attempt
	// keeps it and settles from it: the run's tokens and cost are known.
	const stage = `{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0}`
	const tokens = `"token_usage":{"known":true,"route_attempts":2,"input_tokens":200,"output_tokens":200,"cached_input_tokens":0,"generation":` + stage + `,"verification":` + stage + `}`
	if !strings.Contains(stdout.String(), `"usage_known":true,"actual_cost_micro_usd":0,`+tokens+`,`) || strings.Contains(stdout.String(), "unknown_final_usage") {
		t.Fatalf("failed verifier attempt usage and cost: %s", stdout.String())
	}
	// The same reply without usage leaves the attempt, and so the run's tokens
	// and cost, unknown.
	unreported := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: "exhausted_unreported"})
	stdout.Reset()
	const unknown = `"usage_known":false,"actual_cost_micro_usd":0,"token_usage":{"known":false,"route_attempts":2,"generation":` + stage + `,"verification":{"known":false,"route_attempts":1}}`
	if code := run(unreported.args, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), `"failure_detail":"model_output_exhausted"`) || !strings.Contains(stdout.String(), unknown) || !strings.Contains(stdout.String(), "unknown_final_usage") {
		t.Fatalf("unreported exhausted reply: %s", stdout.String())
	}
	text := runLocalModelText(t, newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: "exhausted"}), 1)
	if !strings.Contains(text, "failure: internal (task verification): model_output_exhausted\nhint: the model used its whole output allowance (reasoning) before answering") || !strings.Contains(text, "--max-output-tokens") {
		t.Fatalf("exhausted output not reported: %q", text)
	}
	if !strings.Contains(text, "\ntokens: input=200 output=200 cached_input=0 over 2 route attempts\n") {
		t.Fatalf("exhausted text lacks the token line: %q", text)
	}
	// Any other failure keeps the field absent, so other results keep their bytes.
	other := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "malformed"})
	stdout.Reset()
	if code := run(other.args, &stdout, &stderr); code != 1 || bytes.Contains(stdout.Bytes(), []byte("failure_detail")) {
		t.Fatalf("unrelated failure carried failure_detail: %s", stdout.String())
	}
}

// Defect F: a provider that refused the request for billing (HTTP 402) or had
// retired the model (HTTP 410) failed every run as a bare internal failure
// with no detail or hint. Each provider refusal now names its class, the
// failing task, a fixed detail and a fixed hint, and the provider's own
// message text never reaches any output.
func TestLocalModelReviewNamesProviderRefusals(t *testing.T) {
	for _, test := range []struct {
		name, generation, verification string
		code                           int
		failure, task, detail, hint    string
	}{
		{"payment required", "refuse_402", "", 4, "policy", "candidates", localreview.FailureDetailProviderPaymentRequired, "the provider refused the request for billing: add credit or a subscription to the provider account, or choose another route"},
		{"model retired at verification", "", "refuse_410", 4, "policy", "verification", localreview.FailureDetailProviderModelRetired, "the provider no longer serves this model: choose a model the provider lists as available and re-run setup"},
		{"model unavailable", "refuse_404", "", 4, "policy", "candidates", localreview.FailureDetailProviderModelUnavailable, "the provider does not serve this model at this endpoint"},
		{"authentication", "refuse_401", "", 4, "policy", "candidates", localreview.FailureDetailProviderAuthenticationFailed, "the provider did not accept the credential"},
		{"authorization", "refuse_403", "", 4, "policy", "candidates", localreview.FailureDetailProviderAuthorizationDenied, "the provider refused this account access"},
		{"rate limited", "refuse_429", "", 1, "transient", "candidates", localreview.FailureDetailProviderRateLimited, "the provider rate-limited the request on its last attempt"},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := localModelFixtureOptions{chatCompletions: true, generationMode: test.generation, verificationMode: test.verification}
			f := newLocalModelFixture(t, options)
			var stdout, stderr bytes.Buffer
			if code := run(f.args, &stdout, &stderr); code != test.code {
				t.Fatalf("exit=%d want=%d stdout=%s stderr=%q", code, test.code, stdout.String(), stderr.String())
			}
			var wire struct {
				RunStatus     string `json:"run_status"`
				Failure       string `json:"failure"`
				FailureDetail string `json:"failure_detail"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &wire); err != nil || wire.RunStatus != "failed" || wire.Failure != test.failure || wire.FailureDetail != test.detail {
				t.Fatalf("result=%+v err=%v", wire, err)
			}
			assertNoProviderRefusalText(t, stdout.String()+stderr.String())
			if test.failure == "policy" {
				// A refusal the provider repeats on every replay is attempted once.
				calls, _ := f.generation.snapshot()
				if test.task == "verification" {
					calls, _ = f.verification.snapshot()
				}
				if calls != 1 {
					t.Fatalf("refused route was called %d times", calls)
				}
			}
			text := runLocalModelText(t, newLocalModelFixture(t, options), test.code)
			if want := "failure: " + test.failure + " (task " + test.task + "): " + test.detail + "\nhint: " + test.hint; !strings.Contains(text, want) {
				t.Fatalf("text=%q want %q", text, want)
			}
			assertNoProviderRefusalText(t, text)
		})
	}
	// A review set member carries the same detail and hint.
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, generationMode: "refuse_402"})
	_, text := runLocalModelSet(t, f, []string{"--specialists", "auto", "--format", "text"}, 4)
	if !strings.Contains(text, "member: general status=refused run=failed verified_findings=0 failure=policy (task candidates): provider_payment_required\nmember hint: general: the provider refused the request for billing") {
		t.Fatalf("set text=%q", text)
	}
	assertNoProviderRefusalText(t, text)
}

func assertNoProviderRefusalText(t *testing.T, output string) {
	t.Helper()
	for _, forbidden := range []string{localModelRefusalText, "usage credits", "ollama.com/plans", "retired on", "glm-5.3-flash", "not found, try pulling"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("provider message text %q reached the output", forbidden)
		}
	}
}

// Defects B and E for review sets: a member's failure names its class and
// task, and change features are reported from the recorded change even when
// the general review failed after it (the live run printed languages=none).
func TestLocalModelReviewSetNamesMemberFailureAndKeepsFeatures(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "malformed_specialist"})
	_, text := runLocalModelSet(t, f, []string{"--specialists", "bug_hunter,backend", "--format", "text"}, 4)
	if !strings.Contains(text, "member: bug_hunter status=failed run=failed verified_findings=0 failure=internal (task candidates)\nmember hint: bug_hunter: a model response could not be accepted") {
		t.Fatalf("member failure line missing: %q", text)
	}
	general := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "malformed"})
	_, generalText := runLocalModelSet(t, general, []string{"--specialists", "auto", "--format", "text"}, 1)
	if !strings.Contains(generalText, "languages=go") || strings.Contains(generalText, "languages=none") || !strings.Contains(generalText, "member: general status=failed run=failed verified_findings=0 failure=internal (task candidates)") {
		t.Fatalf("general failure set text=%q", generalText)
	}
}

func TestSummarizeSpecialistFeaturesWithoutPlan(t *testing.T) {
	features, err := agentprofile.NewChangeFeatures(agentprofile.ChangeFeaturesSpec{Files: []agentprofile.ChangedFileSpec{{Path: "calc.go", DeletedLines: 3}}})
	if err != nil {
		t.Fatal(err)
	}
	summary := summarizeSpecialistFeatures(features)
	if summary.ChangedFiles != 1 || strings.Join(summary.Languages, ",") != "go" || len(summary.FileClasses) == 0 {
		t.Fatalf("summary=%+v", summary)
	}
	unstarted, err := localreview.NewUnstartedResult("refused")
	if err != nil {
		t.Fatal(err)
	}
	if reason := featuresUnavailableReason(unstarted); !strings.HasPrefix(reason, "general review did not complete") {
		t.Fatalf("reason=%q", reason)
	}
	set := modelReviewSetWire{Selection: specialistSelectionWire{Mode: "auto", Status: "features_unavailable", Reason: "general review failed at context", MaxSpecialists: 3}}
	rendered, err := renderModelReviewSetText(set)
	if err != nil || !strings.Contains(string(rendered), "selection: mode=auto status=features_unavailable (general review failed at context) max=3\n") {
		t.Fatalf("rendered=%q err=%v", rendered, err)
	}
}

// Defect D: the live set reported "Avg may divide by zero" (general) and "Avg
// panics on empty slice" (bug_hunter) as two findings. They share path,
// category, an overlapping range and the cited evidence.
func TestMergeVerifiedFindingsMergesLiveDuplicate(t *testing.T) {
	const evidence = "76a14b86b8e4bfef0306da257cc6b99fa1f3d8057b992b0aa74b2d50f4424e45"
	general := localreview.ReportFinding{Identity: "g1", Title: "Avg function may divide by zero", Claim: "The Avg function returns sum / len(xs) without checking if xs is empty, which can cause a runtime panic due to division by zero.", Severity: diagnostics.SeverityWarning, Path: "calc.go", StartLine: 10, EndLine: 18, EvidenceIDs: []string{evidence}, Category: "correctness"}
	bugHunter := localreview.ReportFinding{Identity: "b1", Title: "Avg panics on empty slice", Claim: "Calling Avg with an empty slice triggers a runtime panic because it divides by zero (len(xs) == 0).", Severity: diagnostics.SeverityError, Path: "calc.go", StartLine: 16, EndLine: 16, EvidenceIDs: []string{evidence}, Category: "correctness"}
	merged, duplicates := mergeVerifiedFindings([]string{"general", "bug_hunter"}, [][]localreview.ReportFinding{{general}, {bugHunter}})
	if len(merged) != 1 || duplicates != 1 {
		t.Fatalf("merged=%d duplicates=%d", len(merged), duplicates)
	}
	got := merged[0]
	if got.FindingIdentity != "b1" || got.Severity != "error" || got.StartLine != 16 || got.EndLine != 16 || strings.Join(got.contributorLabels(), ",") != "general,bug_hunter" {
		t.Fatalf("merged finding=%+v", got)
	}
	// Word overlap alone (no shared evidence) also identifies the duplicate.
	general.EvidenceIDs, bugHunter.EvidenceIDs = []string{"e1"}, []string{"e2"}
	if merged, _ := mergeVerifiedFindings([]string{"general", "bug_hunter"}, [][]localreview.ReportFinding{{general}, {bugHunter}}); len(merged) != 1 {
		t.Fatalf("token-overlap duplicate kept apart: %d", len(merged))
	}
}

func TestMergeVerifiedFindingsKeepsNearMissesApart(t *testing.T) {
	finding := func(id, title, claim string, evidence ...string) localreview.ReportFinding {
		return localreview.ReportFinding{Identity: id, Title: title, Claim: claim, Severity: diagnostics.SeverityWarning, Path: "calc.go", StartLine: 10, EndLine: 18, EvidenceIDs: evidence, Category: "correctness"}
	}
	divide := finding("g1", "Avg may divide by zero", "Avg divides by len(xs) without checking for an empty slice.", "e1")
	overflow := finding("b1", "Sum overflows for large inputs", "Accumulating int values can overflow and wrap silently on long slices.", "e2")
	if merged, duplicates := mergeVerifiedFindings([]string{"general", "bug_hunter"}, [][]localreview.ReportFinding{{divide}, {overflow}}); len(merged) != 2 || duplicates != 0 {
		t.Fatalf("unrelated claim with different evidence merged: %d/%d", len(merged), duplicates)
	}
	// One member's two distinct issues in the same hunk share the hunk's
	// evidence ID; that alone does not merge them.
	overflow.EvidenceIDs = []string{"e1"}
	if merged, _ := mergeVerifiedFindings([]string{"general"}, [][]localreview.ReportFinding{{divide, overflow}}); len(merged) != 2 {
		t.Fatal("one member's distinct findings merged on shared hunk evidence")
	}
	// Across members, a different category never merges.
	overflow.Category = "performance"
	if merged, _ := mergeVerifiedFindings([]string{"general", "bug_hunter"}, [][]localreview.ReportFinding{{divide}, {overflow}}); len(merged) != 2 {
		t.Fatal("different categories merged")
	}
}
