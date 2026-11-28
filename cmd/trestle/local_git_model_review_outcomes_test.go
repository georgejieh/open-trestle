package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/agentprofile"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/routehint"
	"github.com/georgejieh/open-trestle/localreview"
)

// Outcomes of a direct model review against fake model servers: unusual
// changes, named failures, provider refusals and merged review sets.

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

// A change that only removes a guard is reviewed, not refused at the context
// task.
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

// A removed or added file over the change-model size bound is a resource_limit
// omission, and the small Go change beside it is still reviewed.
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

// A change that only removes a file is reviewed from the file's removed text,
// and the verified finding is on its removed base lines.
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

// A failed run names the failure class, the failing task and a hint.
func TestLocalModelReviewTextNamesFailureClassTaskAndHint(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "malformed"})
	text := runLocalModelText(t, f, 1)
	if !strings.Contains(text, "run: failed\nfailure: internal (task candidates): model_output_invalid\nhint: the model's answer was not a valid review document") {
		t.Fatalf("failure line missing: %q", text)
	}
	succeeded := runLocalModelText(t, newLocalModelFixture(t, localModelFixtureOptions{}), 4)
	if strings.Contains(succeeded, "failure:") || strings.Contains(succeeded, "hint:") {
		t.Fatalf("succeeded run printed a failure line: %q", succeeded)
	}
}

// A verifier that stopped at the output limit with empty content reports an
// exhausted output allowance.
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
	// The exhausted verifier reply reported its usage, so each failed attempt,
	// the first and its one retry, keeps it and settles from it: the run's
	// tokens and cost are known.
	const stage = `{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0}`
	const retried = `{"known":true,"route_attempts":2,"input_tokens":200,"output_tokens":200,"cached_input_tokens":0}`
	const tokens = `"token_usage":{"known":true,"route_attempts":3,"input_tokens":300,"output_tokens":300,"cached_input_tokens":0,"generation":` + stage + `,"verification":` + retried + `}`
	if !strings.Contains(stdout.String(), `"usage_known":true,"actual_cost_micro_usd":0,`+tokens+`,`) || strings.Contains(stdout.String(), "unknown_final_usage") {
		t.Fatalf("failed verifier attempt usage and cost: %s", stdout.String())
	}
	// The same reply without usage leaves the attempt, and so the run's tokens
	// and cost, unknown.
	unreported := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: "exhausted_unreported"})
	stdout.Reset()
	const unknown = `"usage_known":false,"actual_cost_micro_usd":0,"token_usage":{"known":false,"route_attempts":3,"generation":` + stage + `,"verification":{"known":false,"route_attempts":2}}`
	if code := run(unreported.args, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), `"failure_detail":"model_output_exhausted"`) || !strings.Contains(stdout.String(), unknown) || !strings.Contains(stdout.String(), "unknown_final_usage") {
		t.Fatalf("unreported exhausted reply: %s", stdout.String())
	}
	text := runLocalModelText(t, newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: "exhausted"}), 1)
	if !strings.Contains(text, "failure: internal (task verification): model_output_exhausted\nhint: the model used its whole output allowance, usually on reasoning, before finishing its answer") || !strings.Contains(text, "--max-output-tokens") {
		t.Fatalf("exhausted output not reported: %q", text)
	}
	if !strings.Contains(text, "\ntokens: input=300 output=300 cached_input=0 over 3 route attempts\n") || !strings.Contains(text, "\n"+localreview.ModelAnswerRetriedText) {
		t.Fatalf("exhausted text lacks the token line: %q", text)
	}
	// An answer that stopped normally is never reported as an exhausted allowance.
	other := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "malformed"})
	stdout.Reset()
	if code := run(other.args, &stdout, &stderr); code != 1 || bytes.Contains(stdout.Bytes(), []byte("model_output_exhausted")) {
		t.Fatalf("unrelated failure carried the exhausted detail: %s", stdout.String())
	}
}

// A verifier that stopped at the output limit part way through its answer
// reports an exhausted output allowance with the usage the reply reported.
func TestLocalModelReviewReportsAPartialAnswerAtTheOutputLimit(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: "exhausted_partial"})
	var stdout, stderr bytes.Buffer
	if code := run(f.args, &stdout, &stderr); code != 1 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	const stage = `{"known":true,"route_attempts":2,"input_tokens":200,"output_tokens":200,"cached_input_tokens":0}`
	if !strings.Contains(stdout.String(), `"failure":"internal","failure_detail":"model_output_exhausted"`) || !strings.Contains(stdout.String(), `"verification":`+stage) {
		t.Fatalf("partial answer at the limit: %s", stdout.String())
	}
	text := runLocalModelText(t, newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: "exhausted_partial"}), 1)
	if !strings.Contains(text, "failure: internal (task verification): model_output_exhausted\nhint: the model used its whole output allowance, usually on reasoning, before finishing its answer") {
		t.Fatalf("partial answer text: %q", text)
	}
}

// A reply that stopped normally but whose answer is not a valid review
// document (chat-template tokens around the JSON, a raw control character, a
// cut-short document, or a verdict for an unnamed candidate) names the model's
// answer with a fixed hint, and the answer's text never reaches any output.
func TestLocalModelReviewNamesAnAnswerThatIsNotAReviewDocument(t *testing.T) {
	for _, test := range []struct {
		name          string
		options       localModelFixtureOptions
		task, problem string
	}{
		{"chat-template tokens", localModelFixtureOptions{chatCompletions: true, generationMode: "template_tokens"}, "candidates", "not_json"},
		{"control character at verification", localModelFixtureOptions{chatCompletions: true, verificationMode: "control_character"}, "verification", "not_json"},
		{"document cut short", localModelFixtureOptions{generationMode: "malformed"}, "candidates", "not_json"},
		{"verdict for another candidate", localModelFixtureOptions{verificationMode: "wrong_candidate"}, "verification", "unknown_candidate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newLocalModelFixture(t, test.options)
			var stdout, stderr bytes.Buffer
			if code := run(f.args, &stdout, &stderr); code != 1 {
				t.Fatalf("exit=%d stdout=%s stderr=%q", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), `"failure":"internal","failure_detail":"model_output_invalid","model_output_problem":"`+test.problem+`"`) || strings.Contains(stdout.String()+stderr.String(), "<|") || strings.Contains(stdout.String(), "\\u0001") {
				t.Fatalf("result=%s", stdout.String())
			}
			text := runLocalModelText(t, newLocalModelFixture(t, test.options), 1)
			if want := "failure: internal (task " + test.task + "): model_output_invalid\nhint: " + routehint.ModelOutputInvalidHint(test.problem); !strings.Contains(text, want) || strings.Contains(text, "<|") {
				t.Fatalf("text=%q want %q", text, want)
			}
		})
	}
	// A review set member carries the same detail, class and hint.
	hint := routehint.ModelOutputInvalidHint("not_json")
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, generationMode: "template_tokens"})
	_, text := runLocalModelSet(t, f, []string{"--specialists", "auto", "--format", "text"}, 1)
	if !strings.Contains(text, "not finished: general (failed: internal (task candidates): model_output_invalid)\nhint: general: "+hint) || strings.Contains(text, "<|") {
		t.Fatalf("set text=%q", text)
	}
	_, verbose := runLocalModelSet(t, f, []string{"--specialists", "auto", "--format", "text", "--verbose"}, 1)
	if !strings.Contains(verbose, "member: general status=failed run=failed verified_findings=0 failure=internal (task candidates): model_output_invalid\nmember hint: general: "+hint) || strings.Contains(verbose, "<|") {
		t.Fatalf("verbose set text=%q", verbose)
	}
}

// Each provider refusal names its class, the failing task, a fixed detail and
// a fixed hint, and the provider's own message text never reaches any output.
func TestLocalModelReviewNamesProviderRefusals(t *testing.T) {
	for _, test := range []struct {
		name, generation, verification string
		code                           int
		failure, task, detail, hint    string
	}{
		{"payment required", "refuse_402", "", 4, "policy", "candidates", "provider_payment_required", "the provider refused the request for billing: add credit or a subscription to the provider account, or choose another route"},
		{"model retired at verification", "", "refuse_410", 4, "policy", "verification", "provider_model_retired", "the provider no longer serves this model: choose a model the provider lists as available and re-run setup"},
		{"model unavailable", "refuse_404", "", 4, "policy", "candidates", "provider_model_unavailable", "the provider does not serve this model at this endpoint"},
		{"authentication", "refuse_401", "", 4, "policy", "candidates", "provider_authentication_failed", "the provider did not accept the credential"},
		{"authorization", "refuse_403", "", 4, "policy", "candidates", "provider_authorization_denied", "the provider refused this account access"},
		{"rate limited", "refuse_429", "", 1, "transient", "candidates", "provider_rate_limited", "the provider rate-limited the request on its last attempt"},
		// A reply the adapter refuses, or a status it does not classify, is named
		// as a refused reply.
		{"reply with an unknown field", "reply_unknown_field", "", 1, "internal", "candidates", localreview.FailureDetailProviderResponseInvalid, "the provider answered, but its reply did not match what Open Trestle accepts, for example malformed or truncated output, an unrecognized field or an unexpected HTTP status: run the review again; if it repeats, choose another model or route and report it"},
		{"truncated reply at verification", "", "reply_truncated", 1, "internal", "verification", localreview.FailureDetailProviderResponseInvalid, "the provider answered, but its reply did not match"},
		{"unclassified status", "refuse_409", "", 1, "internal", "candidates", localreview.FailureDetailProviderResponseInvalid, "the provider answered, but its reply did not match"},
		// A request the provider rejects as invalid, such as an unknown model ID,
		// is named as a rejected request, not a refused reply.
		{"request rejected", "refuse_400", "", 4, "policy", "candidates", "provider_request_rejected", "the provider rejected the request as invalid, for example an unknown model ID or a parameter the model or endpoint does not accept: check the model ID, the endpoint and its transport, and that the model and endpoint accept structured output and the requested output allowance; then re-run setup"},
		{"request unprocessable at verification", "", "refuse_422", 4, "policy", "verification", "provider_request_rejected", "the provider rejected the request as invalid"},
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
	if !strings.Contains(text, "not finished: general (refused: policy (task candidates): provider_payment_required)\nhint: general: the provider refused the request for billing") {
		t.Fatalf("set text=%q", text)
	}
	assertNoProviderRefusalText(t, text)
	_, verbose := runLocalModelSet(t, f, []string{"--specialists", "auto", "--format", "text", "--verbose"}, 4)
	if !strings.Contains(verbose, "member: general status=refused run=failed verified_findings=0 failure=policy (task candidates): provider_payment_required\nmember hint: general: the provider refused the request for billing") {
		t.Fatalf("verbose set text=%q", verbose)
	}
	assertNoProviderRefusalText(t, verbose)
	unaccepted := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, generationMode: "reply_unknown_field"})
	_, text = runLocalModelSet(t, unaccepted, []string{"--specialists", "auto", "--format", "text"}, 1)
	if !strings.Contains(text, "not finished: general (failed: internal (task candidates): provider_response_invalid)\nhint: general: the provider answered, but its reply did not match") {
		t.Fatalf("set text=%q", text)
	}
	assertNoProviderRefusalText(t, text)
}

// A request the provider rate-limits once is retried on the same route after
// its Retry-After, inside the task's one attempt, and the review completes;
// three rate limits in a row fail it as transient after two retries.
func TestLocalModelReviewRetriesARateLimitedRequest(t *testing.T) {
	for _, test := range []struct {
		name                     string
		generation, verification string
	}{
		{"generation", "refuse_429_once", ""},
		{"verification", "", "refuse_429_once"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, generationMode: test.generation, verificationMode: test.verification})
			result, stdout := localModelExecute(t, f, f.args, 4)
			gc, _ := f.generation.snapshot()
			vc, _ := f.verification.snapshot()
			if result.Status != "findings" || result.RunStatus != "succeeded" || len(result.Diagnostics.Findings) != 1 {
				t.Fatalf("status=%s run=%s findings=%d", result.Status, result.RunStatus, len(result.Diagnostics.Findings))
			}
			// The rate-limited side was sent its request twice: refused, then retried.
			want := map[string][2]int{"generation": {2, 1}, "verification": {1, 2}}[test.name]
			if gc != want[0] || vc != want[1] {
				t.Fatalf("requests generation=%d verification=%d, want %v", gc, vc, want)
			}
			assertNoProviderRefusalText(t, stdout)
			// The refused request consumed nothing, so its known zero usage
			// keeps the retried stage's usage, and so the run's usage and
			// cost, known.
			retried := `"` + test.name + `":{"known":true,"route_attempts":2,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0}`
			if !strings.Contains(stdout, `"usage_known":true,"actual_cost_micro_usd":0,"token_usage":{"known":true,"route_attempts":3,`) || !strings.Contains(stdout, retried) {
				t.Fatalf("retried usage is not known: %s", stdout)
			}
		})
	}
	// A 503 that names a Retry-After is the same refusal before processing:
	// retried on the same route, with known zero usage.
	unavailable := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, generationMode: "refuse_503_once"})
	result, unavailableOut := localModelExecute(t, unavailable, unavailable.args, 4)
	if calls, _ := unavailable.generation.snapshot(); calls != 2 || result.RunStatus != "succeeded" || !strings.Contains(unavailableOut, `"generation":{"known":true,"route_attempts":2,`) {
		t.Fatalf("503 with Retry-After: calls=%d run=%s", calls, result.RunStatus)
	}
	assertNoProviderRefusalText(t, unavailableOut)
	// Both model tasks using both retries still read back as one result.
	both := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, generationMode: "refuse_429_twice", verificationMode: "refuse_429_twice"})
	if result, _ := localModelExecute(t, both, both.args, 4); result.RunStatus != "succeeded" || len(result.Diagnostics.Findings) != 1 {
		t.Fatalf("two retries on each task: run=%s findings=%d", result.RunStatus, len(result.Diagnostics.Findings))
	}
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, generationMode: "refuse_429"})
	var stdout, stderr bytes.Buffer
	if code := run(f.args, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), `"failure_detail":"provider_rate_limited"`) {
		t.Fatalf("exit=%d stdout=%s", code, stdout.String())
	}
	if calls, _ := f.generation.snapshot(); calls != 1+2 {
		t.Fatalf("rate-limited route was sent %d requests, want 3", calls)
	}
}

// An answer that is not usable, a cut-short finder document or an exhausted
// verifier allowance, is sent once more on the same route; the second answer
// completes the review, both requests count in its tokens, and the result
// says so without the rejected answer.
func TestLocalModelReviewRetriesAnAnswerThatIsNotUsable(t *testing.T) {
	for _, test := range []struct {
		name    string
		options localModelFixtureOptions
		stage   string
		calls   [2]int
	}{
		{"finder", localModelFixtureOptions{generationMode: "malformed_first"}, "generation", [2]int{2, 1}},
		{"checker", localModelFixtureOptions{chatCompletions: true, verificationMode: "exhausted_first"}, "verification", [2]int{1, 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newLocalModelFixture(t, test.options)
			result, stdout := localModelExecute(t, f, f.args, 4)
			gc, _ := f.generation.snapshot()
			vc, _ := f.verification.snapshot()
			if result.RunStatus != "succeeded" || len(result.Diagnostics.Findings) != 1 || gc != test.calls[0] || vc != test.calls[1] {
				t.Fatalf("run=%s findings=%d calls=%d/%d", result.RunStatus, len(result.Diagnostics.Findings), gc, vc)
			}
			retried := `"` + test.stage + `":{"known":true,"route_attempts":2,"input_tokens":200,"output_tokens":200,"cached_input_tokens":0}`
			if !strings.Contains(stdout, `"token_usage":{"known":true,"route_attempts":3,`) || !strings.Contains(stdout, retried) || !strings.Contains(stdout, `"`+localreview.LimitationModelAnswerRetried+`"`) || strings.Contains(stdout, "model_output") {
				t.Fatalf("result=%s", stdout)
			}
			text := runLocalModelText(t, newLocalModelFixture(t, test.options), 4)
			if !strings.Contains(text, "\n"+localreview.ModelAnswerRetriedText) || strings.Contains(text, "failure:") {
				t.Fatalf("text=%q", text)
			}
		})
	}
	// A review set says so once.
	f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "malformed_first"})
	_, text := runLocalModelSet(t, f, []string{"--specialists", "auto", "--format", "text"}, 4)
	if strings.Count(text, localreview.ModelAnswerRetriedText) != 1 {
		t.Fatalf("set text=%q", text)
	}
}

func assertNoProviderRefusalText(t *testing.T, output string) {
	t.Helper()
	for _, forbidden := range []string{localModelRefusalText, localModelReplyField, "usage credits", "ollama.com/plans", "retired on", "glm-5.3-flash", "not found, try pulling"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("provider message text %q reached the output", forbidden)
		}
	}
}

// In a review set a member's failure names its class and task, and change
// features are reported from the recorded change even when the general review
// failed after it.
func TestLocalModelReviewSetNamesMemberFailureAndKeepsFeatures(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "malformed_specialist"})
	_, text := runLocalModelSet(t, f, []string{"--specialists", "bug_hunter,backend", "--format", "text"}, 4)
	if !strings.Contains(text, "not finished: bug_hunter (failed: internal (task candidates): model_output_invalid)\nhint: bug_hunter: the model's answer was not a valid review document") {
		t.Fatalf("member failure line missing: %q", text)
	}
	// The member after the failed one was not run, and says why.
	if !strings.Contains(text, "not run: backend (stopped after bug_hunter did not finish (failed))\n") || !strings.Contains(text, "reviewers: general, bug_hunter (2 of 3 ran)\n") {
		t.Fatalf("not-run member line missing: %q", text)
	}
	if !strings.Contains(text, "incomplete: one or more reviewers did not finish; the findings come only from those that did, so this is not a clean result\n") || strings.Contains(text, "member: ") {
		t.Fatalf("an incomplete set does not say so, or shows member internals: %q", text)
	}
	general := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "malformed"})
	_, generalText := runLocalModelSet(t, general, []string{"--specialists", "auto", "--format", "text", "--verbose"}, 1)
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
	rendered, err := renderModelReviewSetText(set, localreview.RenderOptions{Verbose: true})
	if err != nil || !strings.Contains(string(rendered), "selection: mode=auto status=features_unavailable (general review failed at context) max=3\n") {
		t.Fatalf("rendered=%q err=%v", rendered, err)
	}
}

// Findings that share path, category, an overlapping range and evidence but
// word their statements differently stay as two ranked findings, the more
// severe first. Only near-identical statements merge, so a distinct defect is
// never hidden behind another's statement.
func TestMergeVerifiedFindingsKeepsParaphrasesApartAndRanked(t *testing.T) {
	const evidence = "76a14b86b8e4bfef0306da257cc6b99fa1f3d8057b992b0aa74b2d50f4424e45"
	general := localreview.ReportFinding{Identity: "g1", Title: "Avg function may divide by zero", Claim: "The Avg function returns sum / len(xs) without checking if xs is empty, which can cause a runtime panic due to division by zero.", Severity: diagnostics.SeverityWarning, Path: "calc.go", StartLine: 10, EndLine: 18, EvidenceIDs: []string{evidence}, Category: "correctness"}
	bugHunter := localreview.ReportFinding{Identity: "b1", Title: "Avg panics on empty slice", Claim: "Calling Avg with an empty slice triggers a runtime panic because it divides by zero (len(xs) == 0).", Severity: diagnostics.SeverityError, Path: "calc.go", StartLine: 16, EndLine: 16, EvidenceIDs: []string{evidence}, Category: "correctness"}
	merged, duplicates := mergeVerifiedFindings([]string{"general", "bug_hunter"}, [][]localreview.ReportFinding{{general}, {bugHunter}})
	if len(merged) != 2 || duplicates != 0 {
		t.Fatalf("merged=%d duplicates=%d", len(merged), duplicates)
	}
	if merged[0].FindingIdentity != "b1" || merged[0].Rank != 1 || merged[1].FindingIdentity != "g1" || merged[1].Rank != 2 {
		t.Fatalf("paraphrases are not in rank order: %+v", merged)
	}
	// The same defect worded the same way by both members merges.
	bugHunter.Title, bugHunter.Claim = general.Title, general.Claim
	merged, duplicates = mergeVerifiedFindings([]string{"general", "bug_hunter"}, [][]localreview.ReportFinding{{general}, {bugHunter}})
	if len(merged) != 1 || duplicates != 1 || merged[0].FindingIdentity != "b1" || merged[0].Severity != "error" || strings.Join(merged[0].contributorLabels(), ",") != "general,bug_hunter" {
		t.Fatalf("near-identical duplicate kept apart: %+v", merged)
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
