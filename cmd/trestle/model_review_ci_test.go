package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/localreview"
)

type modelSARIF struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID string `json:"id"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Invocations []struct {
			ExecutionSuccessful bool `json:"executionSuccessful"`
			Notifications       []struct {
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
						EndLine   int `json:"endLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			Fingerprints        map[string]string `json:"fingerprints"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
			Properties          map[string]any    `json:"properties"`
			Fixes               json.RawMessage   `json:"fixes"`
		} `json:"results"`
		Properties map[string]any `json:"properties"`
	} `json:"runs"`
}

func modelReviewWithFlags(args []string, extra ...string) []string {
	return append(append([]string(nil), args...), extra...)
}

func modelReviewSARIFRun(t *testing.T, f *localModelFixture, wantCode int, extra ...string) (modelSARIF, []byte) {
	t.Helper()
	args := replaceLocalGitChangeValue(f.args, "--format", "sarif")
	var stdout, stderr bytes.Buffer
	if code := run(modelReviewWithFlags(args, extra...), &stdout, &stderr); code != wantCode {
		t.Fatalf("exit=%d want=%d stderr=%q", code, wantCode, stderr.String())
	}
	raw := stdout.Bytes()
	if len(raw) == 0 || raw[len(raw)-1] != '\n' || bytes.Count(raw, []byte("\n")) != 1 {
		t.Fatalf("SARIF is not one newline-terminated document: %q", raw)
	}
	for _, forbidden := range []string{f.objects, f.inventoryPath, f.policyPath, localModelSecret, localModelKey, "return 10 / x"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("SARIF disclosed source, configuration path or credential")
		}
	}
	var log modelSARIF
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || log.Schema != sarifSchemaURI || len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "Open Trestle" || len(log.Runs[0].Invocations) != 1 || log.Runs[0].Results == nil {
		t.Fatalf("not a SARIF 2.1.0 log with one run and invocation: %s", raw)
	}
	if clearance, ok := log.Runs[0].Properties["trestleComprehensiveClearance"].(bool); !ok || clearance {
		t.Fatal("SARIF run must carry comprehensive_clearance=false")
	}
	return log, raw
}

func TestModelReviewSARIFCarriesVerifiedFindingGuidanceAndFingerprints(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	log, raw := modelReviewSARIFRun(t, f, 4)
	run := log.Runs[0]
	if len(run.Results) != 1 || len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != "open-trestle/correctness" {
		t.Fatalf("unexpected results or rules: %s", raw)
	}
	result := run.Results[0]
	location := result.Locations[0].PhysicalLocation
	if result.RuleID != "open-trestle/correctness" || result.Level != "error" || location.ArtifactLocation.URI != "a.go" || location.Region.StartLine != 2 || location.Region.EndLine != 2 {
		t.Fatalf("rule, level or location wrong: %+v", result)
	}
	if want := "Zero-valued caller now panics: Consume passes zero to Changed after removal of the division guard."; result.Message.Text != want {
		t.Fatalf("message=%q want=%q", result.Message.Text, want)
	}
	if len(result.Fixes) != 0 {
		t.Fatal("fixes[] must not be emitted without artifactChanges (invalid SARIF)")
	}
	if strings.Contains(result.Message.Text, "zero guard") {
		t.Fatal("unverified fix text leaked into the verified message")
	}
	properties := result.Properties
	if properties["trestleCategory"] != "correctness" || properties["trestleSeverity"] != "error" || properties["trestleVerificationIndependence"] != "distinct_provider" ||
		properties["trestleFixGuidance"] != "Restore the zero guard before dividing." || properties["trestleFixAuthority"] != "unverified_model_guidance" {
		t.Fatalf("result properties wrong: %v", properties)
	}
	for _, key := range []string{"openTrestleFindingFingerprint/v1", "openTrestleContentHash/v1"} {
		if len(result.PartialFingerprints[key]) != 64 {
			t.Fatalf("partialFingerprints[%s]=%q", key, result.PartialFingerprints[key])
		}
	}
	if len(result.Fingerprints["openTrestleVerifiedFindingId/v1"]) != 64 {
		t.Fatal("missing verified finding identity fingerprint")
	}
	invocation := run.Invocations[0]
	if !invocation.ExecutionSuccessful {
		t.Fatal("a completed review must report executionSuccessful=true")
	}
	properties = run.Properties
	if properties["trestleModelReviewStatus"] != "findings" || properties["trestleCiDisposition"] != "blocked" || properties["trestleRunStatus"] != "succeeded" || properties["trestleVerifiedCount"] != float64(1) || properties["trestleCandidateCount"] != float64(1) {
		t.Fatalf("run properties wrong: %v", properties)
	}
	limitations, _ := properties["trestleLimitations"].([]any)
	if len(limitations) == 0 {
		t.Fatal("run limitations were dropped")
	}
}

func TestModelReviewSARIFMapsSeverityToLevel(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{verificationMode: "medium"})
	log, _ := modelReviewSARIFRun(t, f, 4)
	if got := log.Runs[0].Results[0]; got.Level != "warning" || got.Properties["trestleSeverity"] != "warning" {
		t.Fatalf("medium finding level=%q properties=%v", got.Level, got.Properties)
	}
}

func TestModelReviewSARIFForUnsuccessfulAndInconclusiveRuns(t *testing.T) {
	for _, tc := range []struct {
		name       string
		options    localModelFixtureOptions
		missing    bool
		code       int
		status     string
		successful bool
		level      string
		contains   string
	}{
		{"refused by policy", localModelFixtureOptions{verifierPending: true}, false, 4, "refused", false, "error", "refused by policy"},
		{"local egress refusal", localModelFixtureOptions{remote: true}, false, 4, "refused", false, "error", "no findings were evaluated"},
		{"failed readback", localModelFixtureOptions{generationMode: "malformed"}, false, 1, "failed", false, "error", "not a clean result"},
		{"unreadable change", localModelFixtureOptions{}, true, 3, "incomplete", false, "error", "shallow checkout"},
		{"no candidates", localModelFixtureOptions{generationMode: "empty"}, false, 3, "no_candidates", true, "note", "not a clearance"},
		{"verifier abstains", localModelFixtureOptions{verificationMode: "inconclusive"}, false, 3, "incomplete", true, "warning", "coverage gaps"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// go.mod declares the Go style, so the only notification is the run's
			// status; style notes are covered by the style SARIF test.
			goModule := map[string][]byte{"go.mod": []byte("module example.test/p\n")}
			tc.options.extraBase, tc.options.extraHead = goModule, goModule
			f := newLocalModelFixture(t, tc.options)
			if tc.missing {
				f.args = replaceLocalGitChangeValue(f.args, "--head-revision-digest", strings.Repeat("e", 40))
			}
			log, _ := modelReviewSARIFRun(t, f, tc.code)
			run := log.Runs[0]
			if len(run.Results) != 0 || run.Properties["trestleModelReviewStatus"] != tc.status {
				t.Fatalf("results=%d status=%v", len(run.Results), run.Properties["trestleModelReviewStatus"])
			}
			invocation := run.Invocations[0]
			if invocation.ExecutionSuccessful != tc.successful || len(invocation.Notifications) != 1 || invocation.Notifications[0].Level != tc.level || !strings.Contains(invocation.Notifications[0].Message.Text, tc.contains) {
				t.Fatalf("invocation=%+v", invocation)
			}
			if run.Properties["trestleCiDisposition"] == "pass" {
				t.Fatal("SARIF reported a passing disposition")
			}
		})
	}
}

func modelReviewTestReport() localreview.Report {
	return localreview.Report{
		Status: "findings", CIDisposition: "blocked", RunStatus: "succeeded", Independence: "distinct_provider",
		Limitations: []string{"z_last", "a_first"}, HasVerifiedSet: true, Candidates: 3, Verified: 3,
		HasSourceCoverage: true, SourceAnalyzed: 4, SourceSelected: 3, SourceOmitted: 1,
		Omissions: []localreview.ReportOmission{{Reason: "z", Count: 1}, {Reason: "a", Count: 2}},
		Findings: []localreview.ReportFinding{
			{Identity: "id3", Fingerprint: "f3", Title: "T3", Claim: "C3", Severity: diagnostics.SeverityInformation, Path: "b.go", StartLine: 9, EndLine: 9, Category: "style"},
			{Identity: "id1", Fingerprint: "f1", Title: "T1", Claim: "C1", Severity: diagnostics.SeverityError, Path: "a.go", StartLine: 4, EndLine: 5, Category: "security", Fix: "Do X."},
			{Identity: "id2", Fingerprint: "f2", Title: "T2", Claim: "C2", Severity: diagnostics.SeverityWarning, Path: "a.go", StartLine: 1, EndLine: 1},
		},
	}
}

func TestModelReviewSARIFIsDeterministicAndSorted(t *testing.T) {
	first, err := buildModelReviewSARIF(modelReviewTestReport())
	if err != nil {
		t.Fatal(err)
	}
	shuffled := modelReviewTestReport()
	shuffled.Findings[0], shuffled.Findings[2] = shuffled.Findings[2], shuffled.Findings[0]
	shuffled.Limitations[0], shuffled.Limitations[1] = shuffled.Limitations[1], shuffled.Limitations[0]
	second, err := buildModelReviewSARIF(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if !bytes.Equal(a, b) {
		t.Fatalf("SARIF bytes depend on input order:\n%s\n%s", a, b)
	}
	var log modelSARIF
	if err := json.Unmarshal(a, &log); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, result := range log.Runs[0].Results {
		order = append(order, result.RuleID+"@"+result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if want := "open-trestle/uncategorized@a.go,open-trestle/security@a.go,open-trestle/style@b.go"; strings.Join(order, ",") != want {
		t.Fatalf("results order=%v", order)
	}
	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != 3 || rules[0].ID != "open-trestle/security" || rules[1].ID != "open-trestle/style" || rules[2].ID != "open-trestle/uncategorized" {
		t.Fatalf("rules not sorted: %+v", rules)
	}
	if log.Runs[0].Results[0].Properties["trestleFixGuidance"] != nil || log.Runs[0].Results[1].Properties["trestleFixGuidance"] != "Do X." {
		t.Fatalf("fix guidance misattributed: %+v", log.Runs[0].Results)
	}
	if a2, _ := json.Marshal(first); !bytes.Equal(a, a2) {
		t.Fatal("repeat encoding differs")
	}
}

func TestModelReviewSARIFContentHashIgnoresSnapshotAndLines(t *testing.T) {
	left := localreview.ReportFinding{Path: "a.go", Category: "security", Title: "T", Claim: "C", StartLine: 1, EndLine: 1, Fingerprint: "snapshot-1"}
	right := left
	right.StartLine, right.EndLine, right.Fingerprint = 40, 41, "snapshot-2"
	if modelReviewContentHash(left) != modelReviewContentHash(right) {
		t.Fatal("content hash changed with line numbers or snapshot")
	}
	right.Claim = "other"
	if modelReviewContentHash(left) == modelReviewContentHash(right) {
		t.Fatal("content hash ignored the claim")
	}
}

func TestModelReviewSARIFFromCompletedResultIsByteStable(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	_, raw := localModelExecute(t, f, f.args, 4)
	result, err := localreview.ParseCompletedResult([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	first, err := encodeModelReviewSARIF(result)
	if err != nil {
		t.Fatal(err)
	}
	second, err := encodeModelReviewSARIF(result)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("encoding is not deterministic: %v", err)
	}
}

func TestModelReviewExitCodePolicyTable(t *testing.T) {
	type row struct {
		name                              string
		options                           localModelFixtureOptions
		missing                           bool
		def, findings, strict, alwaysZero int
	}
	rows := []row{
		{"high finding", localModelFixtureOptions{}, false, 4, 4, 4, 0},
		{"medium finding", localModelFixtureOptions{verificationMode: "medium"}, false, 4, 0, 4, 0},
		{"no candidates", localModelFixtureOptions{generationMode: "empty"}, false, 3, 0, 0, 0},
		{"verifier abstains", localModelFixtureOptions{verificationMode: "inconclusive"}, false, 3, 0, 3, 0},
		{"refused", localModelFixtureOptions{verifierPending: true}, false, 4, 4, 4, 0},
		{"failed", localModelFixtureOptions{generationMode: "malformed"}, false, 1, 1, 1, 0},
		{"source not readable", localModelFixtureOptions{}, true, 3, 3, 3, 0},
	}
	for _, tc := range rows {
		for policy, want := range map[string]int{"": tc.def, "default": tc.def, "findings": tc.findings, "strict": tc.strict, "always-zero": tc.alwaysZero} {
			t.Run(tc.name+"/"+policy, func(t *testing.T) {
				f := newLocalModelFixture(t, tc.options)
				if tc.missing {
					f.args = replaceLocalGitChangeValue(f.args, "--head-revision-digest", strings.Repeat("e", 40))
				}
				args := f.args
				if policy != "" {
					args = modelReviewWithFlags(args, "--exit-code-policy", policy)
				}
				var stdout, stderr bytes.Buffer
				if code := run(args, &stdout, &stderr); code != want {
					t.Fatalf("policy %q exit=%d want=%d stderr=%q", policy, code, want, stderr.String())
				}
				var receipt struct {
					Contract               string `json:"contract"`
					ComprehensiveClearance bool   `json:"comprehensive_clearance"`
				}
				if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.ComprehensiveClearance {
					t.Fatal("a passing exit must not alter the result or claim clearance")
				}
			})
		}
	}
}

func TestModelReviewExitCodePolicyRejectsUnknownValue(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	for _, args := range [][]string{
		modelReviewWithFlags(f.args, "--exit-code-policy", "pass"),
		modelReviewWithFlags(f.args, "--exit-code-policy", ""),
		modelReviewWithFlags(f.args, "--exit-code-policy", "findings", "--exit-code-policy", "strict"),
		replaceLocalGitChangeValue(f.args, "--format", "yaml"),
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "[--exit-code-policy") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	}
	if gc, _ := f.generation.snapshot(); gc != 0 {
		t.Fatal("invalid intent reached a provider")
	}
}

// checkoutModelReviewArgs swaps the fixture's explicit object-store source for a
// --checkout source over directory.
func checkoutModelReviewArgs(f *localModelFixture, directory, base, head string) []string {
	args := []string{}
	for index := 0; index < len(f.args); index += 2 {
		switch f.args[index] {
		case "--objects-root", "--revision-algorithm", "--base-revision-digest", "--head-revision-digest":
			continue
		}
		args = append(args, f.args[index:index+2]...)
	}
	return append(args, "--checkout", directory, "--base", base, "--head", head)
}

func TestShallowCheckoutMissingBaseExplainsHowToFetch(t *testing.T) {
	origin, base, head := newCheckoutFixture(t, "sha1")
	shallow := filepath.Join(t.TempDir(), "shallow")
	checkoutGit(t, origin, "config", "uploadpack.allowAnySHA1InWant", "true")
	checkoutGit(t, filepath.Dir(shallow), "clone", "--quiet", "--depth=1", "--no-local", "file://"+origin, shallow)
	if checkoutGit(t, shallow, "rev-parse", "--is-shallow-repository") != "true" {
		t.Skip("Git did not produce a shallow clone")
	}
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	var stdout, stderr bytes.Buffer
	if code := run(checkoutModelReviewArgs(f, shallow, base, head), &stdout, &stderr); code != 3 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	message := stderr.String()
	for _, want := range []string{"base revision " + base, "shallow checkout", "git fetch --no-tags --depth=N origin " + base, "fetch-depth: 0", "No fetch was attempted"} {
		if !strings.Contains(message, want) {
			t.Fatalf("hint lacks %q:\n%s", want, message)
		}
	}
	var receipt struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.Status != "incomplete" {
		t.Fatalf("result=%s err=%v", stdout.String(), err)
	}
	if gc, _ := f.generation.snapshot(); gc != 0 {
		t.Fatal("an unreadable source reached a model")
	}
	if checkoutGit(t, shallow, "rev-parse", "--is-shallow-repository") != "true" {
		t.Fatal("the review must not deepen the checkout")
	}
}

func TestShallowCheckoutWithBothCommitsPresentStillReviews(t *testing.T) {
	// A depth-N fetch that reaches the base is enough: only the two named
	// commits and their trees are read, never the history behind them.
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	directory := t.TempDir()
	checkoutGit(t, directory, "init")
	if err := os.CopyFS(filepath.Join(directory, ".git", "objects"), os.DirFS(f.objects)); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, directory, "update-ref", "refs/heads/base", f.base)
	checkoutGit(t, directory, "update-ref", "refs/heads/review", f.head)
	checkoutGit(t, directory, "gc", "--prune=now")
	if err := os.WriteFile(filepath.Join(directory, ".git", "shallow"), []byte(f.base+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if checkoutGit(t, directory, "rev-parse", "--is-shallow-repository") != "true" {
		t.Skip("Git did not honor the shallow file")
	}
	var stdout, stderr bytes.Buffer
	if code := run(checkoutModelReviewArgs(f, directory, f.base, f.head), &stdout, &stderr); code != 4 || withoutIndexNotice(stderr.String()) != "" {
		t.Fatalf("exit=%d stdout=%s stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestCheckoutIsPartialCloneDetectsPromisorRemote(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git is not installed")
	}
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	directory := t.TempDir()
	checkoutGit(t, directory, "init")
	if err := os.CopyFS(filepath.Join(directory, ".git", "objects"), os.DirFS(f.objects)); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, directory, "update-ref", "refs/heads/base", f.base)
	checkoutGit(t, directory, "update-ref", "refs/heads/review", f.head)
	checkoutGit(t, directory, "gc", "--prune=now")
	checkoutGit(t, directory, "config", "remote.origin.url", "file:///nonexistent")
	checkoutGit(t, directory, "config", "remote.origin.promisor", "true")
	if !checkoutIsPartialClone(t.Context(), directory) {
		t.Fatal("promisor remote not detected")
	}
	plain := t.TempDir()
	checkoutGit(t, plain, "init")
	if checkoutIsPartialClone(t.Context(), plain) {
		t.Fatal("ordinary checkout reported as partial clone")
	}
}

func TestPartialCloneMissingBlobHintsAtFilter(t *testing.T) {
	for _, promisor := range []bool{true, false} {
		f := newLocalModelFixture(t, localModelFixtureOptions{})
		directory := t.TempDir()
		checkoutGit(t, directory, "init")
		if err := os.CopyFS(filepath.Join(directory, ".git", "objects"), os.DirFS(f.objects)); err != nil {
			t.Fatal(err)
		}
		checkoutGit(t, directory, "update-ref", "refs/heads/base", f.base)
		checkoutGit(t, directory, "update-ref", "refs/heads/review", f.head)
		blob := checkoutGit(t, directory, "rev-parse", f.head+":a.go")
		if err := os.Remove(filepath.Join(directory, ".git", "objects", blob[:2], blob[2:])); err != nil {
			t.Fatal(err)
		}
		if promisor {
			checkoutGit(t, directory, "config", "remote.origin.url", "file:///nonexistent")
			checkoutGit(t, directory, "config", "remote.origin.promisor", "true")
		}
		var stdout, stderr bytes.Buffer
		if code := run(checkoutModelReviewArgs(f, directory, f.base, f.head), &stdout, &stderr); code != 3 {
			t.Fatalf("promisor=%v exit=%d stdout=%s stderr=%q", promisor, code, stdout.String(), stderr.String())
		}
		if got := strings.Contains(stderr.String(), "partial clone"); got != promisor {
			t.Fatalf("promisor=%v hint=%v stderr=%q", promisor, got, stderr.String())
		}
		if gc, _ := f.generation.snapshot(); gc != 0 {
			t.Fatal("an unreadable source reached a model")
		}
	}
}

func TestExampleGitHubWorkflowIsWellFormed(t *testing.T) {
	path := filepath.Join("..", "..", "examples", "github-actions", "open-trestle-review.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"pull_request:", "fetch-depth: 0", "contents: read", "pull-requests: write", "security-events: write",
		"--format sarif", "--exit-code-policy", "github.event.pull_request.base.sha", "github.event.pull_request.head.sha",
		"github/codeql-action/upload-sarif@", "reviewdog", "GITHUB_STEP_SUMMARY", "OLLAMA_API_KEY", "PLACEHOLDER",
		"tools/vulnerability_gate.py --staging .container", "install --destdir", "--repository-checks",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("example workflow lacks %q", want)
		}
	}
	if strings.Contains(text, "\t") {
		t.Error("YAML must not contain tabs")
	}
	if strings.Contains(text, "pull_request_target") {
		t.Error("the example must not use pull_request_target with untrusted code")
	}
	// A real YAML parse runs when python3 with PyYAML is present; there is no Go
	// YAML dependency in this module, so absence skips only this check.
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed; structural checks only")
	}
	command := exec.Command(python, "-I", "-c", "import sys\ntry:\n import yaml\nexcept ImportError:\n sys.exit(3)\ndoc=yaml.safe_load(open(sys.argv[1]))\nassert isinstance(doc.get('jobs'),dict) and len(doc['jobs']['review']['steps'])>3\n", path)
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if asExit(err, &exit) && exit.ExitCode() == 3 {
			t.Skip("PyYAML not installed; structural checks only")
		}
		t.Fatalf("workflow does not parse as YAML: %v", err)
	}
}

func asExit(err error, target **exec.ExitError) bool {
	exit, ok := err.(*exec.ExitError)
	if ok {
		*target = exit
	}
	return ok
}
