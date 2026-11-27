package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/checksandbox"
	"github.com/georgejieh/open-trestle/internal/repochecks"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/localreview"
)

func checksTestDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "setup")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestChecksConsentRoundTrip(t *testing.T) {
	dir := checksTestDir(t)
	repository := checksRepository(context.Background(), latestChangeCheckout(t))
	if len(repository) != 64 {
		t.Fatalf("repository identity %q", repository)
	}
	if _, decided := readChecksConsent(dir, repository); decided {
		t.Fatal("a new setup has an answer")
	}
	for _, allowed := range []bool{true, false} {
		if err := writeChecksConsent(context.Background(), dir, repository, allowed); err != nil {
			t.Fatal(err)
		}
		if got, decided := readChecksConsent(dir, repository); !decided || got != allowed {
			t.Fatalf("read %v %v, want %v", got, decided, allowed)
		}
	}
	if err := writeChecksConsent(context.Background(), dir, "", true); err == nil {
		t.Fatal("an answer was saved for a repository without a commit")
	}
}

// An answer belongs to the repository it was given for: another repository
// in the same folder, or using the same setup folder, is asked again.
func TestChecksConsentFollowsTheRepository(t *testing.T) {
	dir := checksTestDir(t)
	first := latestChangeCheckout(t)
	if err := writeChecksConsent(context.Background(), dir, checksRepository(context.Background(), first), true); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	checkoutGit(t, other, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(other, "README"), []byte("other\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, other, "add", ".")
	checkoutGit(t, other, "commit", "-q", "-m", "other")
	if _, decided := readChecksConsent(dir, checksRepository(context.Background(), other)); decided {
		t.Fatal("the answer for one repository held for another")
	}
	if _, decided := readChecksConsent(dir, checksRepository(context.Background(), t.TempDir())); decided {
		t.Fatal("the answer held for a folder that is not a repository")
	}
}

func TestChecksConsentRefusesAnUnexpectedFile(t *testing.T) {
	dir := checksTestDir(t)
	repository := strings.Repeat("a", 64)
	for _, content := range []string{
		`{"contract":"open-trestle/repository-checks-consent","schema_version":2,"repository":"` + repository + `","allowed":true,"recorded_at":"2026-11-18T00:00:00Z"}`,
		`{"contract":"open-trestle/repository-checks-consent","schema_version":1,"repository":"` + repository + `","allowed":true,"recorded_at":"2026-11-18T00:00:00Z","extra":1}`,
		`{"contract":"other","schema_version":1,"repository":"` + repository + `","allowed":true,"recorded_at":"2026-11-18T00:00:00Z"}`,
		`{"contract":"open-trestle/repository-checks-consent","schema_version":1,"allowed":true,"recorded_at":"2026-11-18T00:00:00Z"}`,
	} {
		if err := replaceProtectedFile(context.Background(), filepath.Join(dir, "checks.json"), []byte(content)); err != nil {
			t.Fatal(err)
		}
		if _, decided := readChecksConsent(dir, repository); decided {
			t.Fatalf("accepted %s", content)
		}
	}
}

func TestReviewChecksDecision(t *testing.T) {
	var out bytes.Buffer
	checkout := latestChangeCheckout(t)
	w := latestReviewPrinter(context.Background(), &out, checkout)
	dir := checksTestDir(t)
	nobody := strings.NewReader("")
	if reviewChecksAllowed(context.Background(), w, dir, latestReviewOptions{}, nobody) {
		t.Fatal("checks ran without an answer and without a terminal")
	}
	if !initHas(out.String(), "Repository checks did not run: they are off until you allow them") {
		t.Fatalf("no explanation: %q", out.String())
	}
	if !reviewChecksAllowed(context.Background(), w, dir, latestReviewOptions{checks: true}, nobody) {
		t.Fatal("--checks did not allow the checks")
	}
	if err := writeChecksConsent(context.Background(), dir, checksRepository(context.Background(), checkout), true); err != nil {
		t.Fatal(err)
	}
	if !reviewChecksAllowed(context.Background(), w, dir, latestReviewOptions{}, nobody) {
		t.Fatal("the stored answer did not allow the checks")
	}
	if reviewChecksAllowed(context.Background(), w, dir, latestReviewOptions{noChecks: true}, nobody) {
		t.Fatal("--no-checks did not skip the checks")
	}
}

func TestReviewRefusesChecksAndNoChecksTogether(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if _, code, done := parseLatestReviewFlags([]string{"--checks", "--no-checks"}, &stdout, &stderr); !done || code != 2 {
		t.Fatalf("code %d done %v: %s", code, done, stderr.String())
	}
}

func TestModelReviewAcceptsRepositoryChecksOnce(t *testing.T) {
	args := append(newLocalModelFixture(t, localModelFixtureOptions{}).args[2:], "--repository-checks")
	options, _, _, _, err := parseLocalModelReview(args)
	if err != nil || !options.repositoryChecks {
		t.Fatalf("options %+v, err %v", options.repositoryChecks, err)
	}
	if _, _, _, _, err := parseLocalModelReview(append(args, "--repository-checks")); err == nil {
		t.Fatal("the flag was accepted twice")
	}
	if _, _, _, _, err := parseLocalModelReview(append(args, "--investigation-policy", "/policy.json")); err == nil {
		t.Fatal("repository checks were accepted for an investigation session")
	}
}

// --model-checks needs the repository checks, on both commands.
func TestModelChecksNeedRepositoryChecks(t *testing.T) {
	args := newLocalModelFixture(t, localModelFixtureOptions{}).args[2:]
	options, _, _, _, err := parseLocalModelReview(append(append([]string{}, args...), "--repository-checks", "--model-checks"))
	if err != nil || !options.modelChecks || !options.repositoryChecks {
		t.Fatalf("options %+v, err %v", options.modelChecks, err)
	}
	if _, _, _, _, err := parseLocalModelReview(append(append([]string{}, args...), "--model-checks")); !errors.Is(err, errModelChecksNeedChecks) {
		t.Fatalf("--model-checks alone: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := runLocalGitModelReview(context.Background(), append(append([]string{}, args...), "--model-checks"), &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "--model-checks needs the repository checks: pass --repository-checks too") {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
	stderr.Reset()
	if _, code, done := parseLatestReviewFlags([]string{"--model-checks", "--no-checks"}, &stdout, &stderr); !done || code != 2 || !strings.Contains(stderr.String(), "--model-checks needs the repository checks") {
		t.Fatalf("code %d done %v: %s", code, done, stderr.String())
	}
	if options, _, done := parseLatestReviewFlags([]string{"--model-checks", "--checks"}, &stdout, &stderr); done || !options.modelChecks {
		t.Fatalf("--model-checks --checks refused: %s", stderr.String())
	}
	if command := latestReviewCommand([]string{"--format", "text"}, "a", "b", latestReviewOptions{modelChecks: true}); slices.Contains(command, "--model-checks") {
		t.Fatal("the saved command took --model-checks before consent was decided")
	}
}

// Without consent, trestle review --model-checks sends nothing.
func TestReviewModelChecksWithoutConsentSendsNothing(t *testing.T) {
	checkout := checksChangeCheckout(t)
	latestChangeSetup(t, checkout)
	transport := latestFixtureTransport(t)
	code, _, stderr := runReviewCommand(t, checkout, "--model-checks")
	if code != 2 || len(transport.payloads) != 0 || !initHas(stderr, "--model-checks needs the repository checks, which are off for this review. Nothing was sent.") {
		t.Fatalf("exit=%d requests=%d\nstderr:\n%s", code, len(transport.payloads), stderr)
	}
}

func TestTerminalTextNeutralisesControls(t *testing.T) {
	if got := terminalText("npm test\x1b]52;c;aGk=\x07 ‮ok", 100); got != "npm test?]52;c;aGk=? ?ok" {
		t.Fatalf("got %q", got)
	}
	if got := terminalText("abcdef", 3); got != "abc..." {
		t.Fatalf("got %q", got)
	}
}

func TestReasonsAndTestIDsShowTheHomeFolderAsTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home folder")
	}
	if got := withoutHomeFolder("the sandbox could not be given read access to " + filepath.Join(home, "sdk", "go")); strings.Contains(got, home) {
		t.Fatalf("got %q", got)
	}
	// A TAP test named by its file carries the tree's path.
	id := "file:///" + filepath.ToSlash(filepath.Join(home, "AppData", "tree", "a.test.mjs"))
	if got := namedTests([]string{id, " \n"}); len(got) != 1 || strings.Contains(got[0], filepath.ToSlash(home)) || !strings.Contains(got[0], "~") {
		t.Fatalf("got %q", got)
	}
}

func TestDependentsWithoutAnIndexAreUnknown(t *testing.T) {
	var index *reviewIndexContext
	if paths, scope := index.dependents(context.Background()); scope != review.CheckRunsChangedOnly || paths != nil {
		t.Fatalf("got %v %v without an index", paths, scope)
	}
}

// The whole path from runner output to the bound outcomes: ten tests that
// stop running on head are listed apart from the regressions and keep the
// run, and a run out of bounds costs only itself.
func TestCheckRunsFromRunnerOutputKeepEveryRun(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		if _, err := exec.LookPath("python"); err != nil {
			t.Skip("python is not installed")
		}
	}
	files := map[string]string{"pkg/mod.py": "", "tests/__init__.py": "", "tests/test_a.py": "", "tests/test_b.py": ""}
	trees := [2]string{t.TempDir(), t.TempDir()}
	for _, tree := range trees {
		for name, content := range files {
			path := filepath.Join(tree, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	runner := func(_ context.Context, spec checksandbox.Spec) (checksandbox.Result, error) {
		lines := []string{"test_b (tests.test_b.B.test_b) ... ok"}
		if spec.Tree == trees[0] {
			for index := range 10 {
				lines = append(lines, "test_"+string(rune('a'+index))+" (tests.test_a.A.test_"+string(rune('a'+index))+") ... ok")
			}
		}
		return checksandbox.Result{Stderr: []byte(strings.Join(lines, "\n"))}, nil
	}
	report, err := repochecks.Run(context.Background(), repochecks.Input{BaseTree: trees[0], HeadTree: trees[1], Scope: repochecks.Scope{Changed: []string{"pkg/mod.py"}}, Limits: checksandbox.DefaultLimits(), Runner: runner})
	if err != nil || len(report.Results) != 1 || !report.Results[0].Ran {
		t.Fatalf("report %+v, %v", report, err)
	}
	report.Results = append(report.Results, repochecks.Result{Name: "broken", Ran: true, Tests: 1, Regressions: []string{"x.A", "x.B"}})
	value, err := review.NewCheckRuns(strings.Repeat("1", 40), strings.Repeat("2", 40), review.CheckRunsChangedOnly, checkRunsOf(report))
	if err != nil {
		t.Fatal(err)
	}
	runs := value.Runs()
	if len(runs) != 2 || runs[0].State != review.CheckRunRan || len(runs[0].StoppedRunning) != 10 || len(runs[0].Regressions) != 0 || runs[0].Tests != 2 || runs[1].State != review.CheckRunCouldNotRun {
		t.Fatalf("runs %+v", runs)
	}
	if !slices.Contains(runs[0].StoppedRunning, "tests.test_a.A.test_a") {
		t.Fatalf("stopped %v", runs[0].StoppedRunning)
	}
}

// A check regression blocks a review set under every exit policy but
// always-zero, and every format of the set shows it.
func TestCheckRegressionsBlockAReviewSet(t *testing.T) {
	runs, err := review.NewCheckRuns(strings.Repeat("a", 40), strings.Repeat("b", 40), review.CheckRunsChangedOnly, []review.CheckRun{
		{Name: "go test ./calc", State: review.CheckRunRan, Tests: 3, Regressions: []string{"calc.TestDivide"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	set := modelReviewSetWire{Contract: modelReviewSetContract, Version: modelReviewSetVersion, Status: "no_candidates", CI: "inconclusive", Complete: true, runStatus: "succeeded",
		Members:  []setMemberWire{{Member: generalMemberLabel, Launched: true, Status: "no_candidates", CI: "inconclusive", RunStatus: "succeeded", reportAvailable: true, Limitations: []string{}}},
		Findings: []setFindingWire{}, Limitations: []string{}, Summary: setSummaryWire{BySeverity: map[string]int{}, ByCategory: map[string]int{}}}
	for policy, want := range map[localreview.ExitPolicy]int{localreview.ExitPolicyDefault: 3, localreview.ExitPolicyFindings: 0, localreview.ExitPolicyStrict: 0, localreview.ExitPolicyAlwaysZero: 0} {
		if code := set.exitCode(policy); code != want {
			t.Fatalf("without regressions, exit for %s = %d, want %d", policy, code, want)
		}
	}
	set.CheckRegressions, set.CI = localreview.NewCheckRegressions(&runs), "blocked"
	for policy, want := range map[localreview.ExitPolicy]int{localreview.ExitPolicyDefault: 4, localreview.ExitPolicyFindings: 4, localreview.ExitPolicyStrict: 4, localreview.ExitPolicyAlwaysZero: 0} {
		if code := set.exitCode(policy); code != want {
			t.Fatalf("exit for %s = %d, want %d", policy, code, want)
		}
	}
	text, err := renderModelReviewSetText(set, localreview.RenderOptions{})
	if err != nil || !bytes.Contains(text, []byte("check regression: go test ./calc: calc.TestDivide\n")) || bytes.Contains(text, []byte("did not finish")) {
		t.Fatalf("text: %v\n%s", err, text)
	}
	markdown, err := renderModelReviewSetMarkdown(set, localreview.RenderOptions{})
	if err != nil || !bytes.Contains(markdown, []byte("### Check regressions")) || !bytes.Contains(markdown, []byte("- `go test ./calc`: `calc.TestDivide`\n")) {
		t.Fatalf("Markdown: %v\n%s", err, markdown)
	}
	sarif, err := encodeModelReviewSetSARIF(set)
	if err != nil || !bytes.Contains(sarif, []byte(`{"level":"error","message":{"text":"Check regression (source: repository check, not a model finding): go test ./calc: calc.TestDivide passed on base and failed on head."}}`)) || !bytes.Contains(sarif, []byte(`"trestleCheckRegressions":{"source":"repository_check","count":1,`)) {
		t.Fatalf("SARIF: %v\n%s", err, sarif)
	}
	set.Complete, set.Status, set.runStatus = false, "failed", "failed"
	set.Members[0].Status, set.Members[0].RunStatus = "failed", "failed"
	if text, err := renderModelReviewSetText(set, localreview.RenderOptions{}); err != nil || !bytes.Contains(text, []byte("check regressions: the model review did not finish")) {
		t.Fatalf("unfinished text: %v\n%s", err, text)
	}
	if sarif, err := encodeModelReviewSetSARIF(set); err != nil || !bytes.Contains(sarif, []byte("Check regression (source: repository check")) {
		t.Fatalf("unfinished SARIF lost the regression: %v\n%s", err, sarif)
	}
}
