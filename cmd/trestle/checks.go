package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/georgejieh/open-trestle/internal/checksandbox"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/repochecks"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
)

// Consent to run a repository's own tests and linters is stored per setup
// in checks.json, a protected 0600 file, with the identity of the
// repository it was given for. Without it, or for another repository, a
// review asks; with it the stored answer holds until `trestle checks
// on|off` changes it.

const checksConsentContract = "open-trestle/repository-checks-consent"

const checksQuestion = "Run this repository's tests inside a sandbox on this machine? It has no network and no access to your home folder or keys."

type checksConsent struct {
	Contract   string `json:"contract"`
	Version    int    `json:"schema_version"`
	Repository string `json:"repository"`
	Allowed    bool   `json:"allowed"`
	RecordedAt string `json:"recorded_at"`
}

// checksRepository identifies the repository of checkout by its root
// commits, which another repository cloned into the same folder does not
// share: the SHA-256 of their sorted IDs. It is "" when there is no commit
// or Git cannot read them.
func checksRepository(ctx context.Context, checkout string) string {
	roots, truncated, err := initGit(ctx, checkout, "rev-list", "--max-parents=0", "HEAD")
	if err != nil || truncated || strings.TrimSpace(roots) == "" {
		return ""
	}
	ids := strings.Fields(roots)
	slices.Sort(ids)
	digest := sha256.Sum256([]byte(strings.Join(ids, "\n")))
	return hex.EncodeToString(digest[:])
}

// readChecksConsent returns the answer stored for repository, and false
// when there is none, it was given for another repository, or it cannot be
// trusted.
func readChecksConsent(dir, repository string) (allowed, decided bool) {
	content, err := readSetupBootstrapFile(filepath.Join(dir, "checks.json"))
	if err != nil || repository == "" {
		return false, false
	}
	var consent checksConsent
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&consent) != nil || decoder.Decode(&struct{}{}) != io.EOF || consent.Contract != checksConsentContract || consent.Version != 1 || consent.Repository != repository {
		return false, false
	}
	if _, err := time.Parse(time.RFC3339, consent.RecordedAt); err != nil {
		return false, false
	}
	return consent.Allowed, true
}

func writeChecksConsent(ctx context.Context, dir, repository string, allowed bool) error {
	if repository == "" {
		return errors.New("the repository has no commit to recognise it by")
	}
	encoded, err := json.Marshal(checksConsent{Contract: checksConsentContract, Version: 1, Repository: repository, Allowed: allowed, RecordedAt: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	return replaceProtectedFile(context.WithoutCancel(ctx), filepath.Join(dir, "checks.json"), append(encoded, '\n'))
}

func writeChecksUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle checks on|off|status [--directory PATH]")
	fmt.Fprintln(w, "       allow or stop running this repository's own tests in a sandbox before each review; see docs/repository-checks.md")
}

// runChecks is `trestle checks on|off|status`.
func runChecks(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		writeChecksUsage(stdout)
		return 0
	}
	directory := ""
	if len(args) == 3 && args[1] == "--directory" {
		directory, args = args[2], args[:1]
	}
	if len(args) != 1 || args[0] != "on" && args[0] != "off" && args[0] != "status" {
		writeChecksUsage(stderr)
		return 2
	}
	checkout, err := findRepositoryCheckout(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "trestle checks: this folder is not inside a Git checkout (or git is not installed). Change into your repository and try again.")
		return 2
	}
	dir := discoverSetupDirectory(ctx, checkout)
	if directory != "" {
		if dir, err = initValidateDirectory(directory); err != nil {
			fmt.Fprintln(stderr, "trestle checks: --directory: "+err.Error())
			return 2
		}
	}
	if !setupExists(dir) {
		fmt.Fprintf(stderr, "trestle checks: this repository has no Open Trestle setup yet (looked in %s). Run trestle init here first.\n", initDisplayPath(dir))
		return 3
	}
	repository := checksRepository(ctx, checkout)
	switch args[0] {
	case "on", "off":
		if err := writeChecksConsent(ctx, dir, repository, args[0] == "on"); err != nil {
			fmt.Fprintf(stderr, "trestle checks: the answer could not be saved in %s (%v).\n", initDisplayPath(dir), err)
			return 4
		}
	}
	if args[0] == "off" {
		if err := checksandbox.RemoveToolchainGrants(); err != nil {
			fmt.Fprintf(stderr, "trestle checks: some toolchain folders still grant the sandbox read access (%v); run trestle checks off again to retry.\n", withoutHomeFolder(err.Error()))
		}
	}
	allowed, decided := readChecksConsent(dir, repository)
	sandbox := checksandbox.Available()
	if p := newOutPrinter(ctx, stdout); p.terminal {
		checksStatusTerminal(p, allowed, decided, sandbox)
		return 0
	}
	switch {
	case !decided:
		fmt.Fprintln(stdout, "Repository checks: not decided yet. The next review asks before it runs any.")
	case allowed:
		fmt.Fprintln(stdout, "Repository checks: on. Each review runs this repository's tests for the changed area in a sandbox first.")
	default:
		fmt.Fprintln(stdout, "Repository checks: off. Reviews do not run this repository's code.")
	}
	if sandbox != nil {
		fmt.Fprintf(stdout, "Sandbox: not available on this machine, so checks would be reported as could not run (%v).\n", sandbox)
	} else {
		fmt.Fprintln(stdout, "Sandbox: available here. Turn checks on or off with trestle checks on or trestle checks off.")
	}
	return 0
}

// checksStatusTerminal is the checks answer and the sandbox for a person.
func checksStatusTerminal(p outPrinter, allowed, decided bool, sandbox error) {
	answer := outRow{mark: p.optional, label: "Checks", value: "off: reviews do not run this repository's code"}
	switch {
	case !decided:
		answer.mark, answer.value = p.wait, "not decided yet: the next review asks before it runs any"
	case allowed:
		answer.mark, answer.value = p.ok, "on: each review first runs this repository's tests for the changed area in a sandbox"
	}
	box := outRow{mark: p.ok, label: "Sandbox", value: "available here"}
	if sandbox != nil {
		box.mark, box.value = p.bad, fmt.Sprintf("not available on this machine, so checks would be reported as could not run (%v)", sandbox)
	}
	p.heading("Repository checks")
	p.rows(answer, box)
	p.next("trestle checks on", "trestle checks off")
}

// reviewChecksAllowed decides whether one `trestle review` runs the
// repository's checks: a flag decides; otherwise the stored answer; otherwise
// a terminal question with Allow, Deny and Always allow. Without a terminal
// and without an answer, nothing runs.
func reviewChecksAllowed(ctx context.Context, w *initWizard, dir string, options latestReviewOptions, in io.Reader) bool {
	if options.noChecks {
		return false
	}
	if options.checks {
		return true
	}
	repository := checksRepository(ctx, w.checkout)
	if allowed, decided := readChecksConsent(dir, repository); decided {
		return allowed
	}
	if !interactiveInput(in) || !initTerminal(w.out) {
		w.say("  Repository checks did not run: they are off until you allow them. Run trestle checks on, or pass --checks.")
		return false
	}
	prompter := newInitPrompter(ctx, in, w.out, w.style, func(line string) { w.say("%s", line) })
	defer prompter.close()
	w.say("  %s", checksQuestion)
	choice, err := prompter.choose("Run the checks for this review?", []string{"Allow this time", "Deny (run trestle checks off to stop this question)", "Always allow for this repository"}, 1)
	if err != nil {
		return false
	}
	if choice == 2 {
		if err := writeChecksConsent(ctx, dir, repository, true); err != nil {
			w.say("  %s The answer could not be saved (%v); this review runs the checks once.", w.wait, err)
		}
	}
	return choice != 1
}

// interactiveInput reports whether in is a terminal a person can answer at.
func interactiveInput(in io.Reader) bool {
	file, ok := in.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// askChecksConsent asks the init question once per setup, only when a review
// is about to run; with --no-input, --checks answers yes and its absence no.
// When it is not asked or no answer can be read, nothing is saved and a later
// review asks; quitting at it stops setup.
func (w *initWizard) askChecksConsent() error {
	repository := checksRepository(w.ctx, w.checkout)
	if _, decided := readChecksConsent(w.a.directory, repository); decided {
		return nil
	}
	allowed, err := w.confirm(checksQuestion, false, w.bools["checks"])
	if errors.Is(err, errInitCanceled) {
		return err
	}
	if err != nil {
		return nil
	}
	w.saveChecksAnswer(repository, allowed)
	return nil
}

// saveChecksAnswer saves the repository checks answer in the setup folder
// and says how to change it.
func (w *initWizard) saveChecksAnswer(repository string, allowed bool) {
	if err := writeChecksConsent(w.ctx, w.a.directory, repository, allowed); err != nil {
		w.say("  %s Your answer could not be saved; a review will ask again.", w.wait)
		return
	}
	if allowed {
		w.say("  %s Repository checks are on. Turn them off with trestle checks off.", w.ok)
	} else {
		w.say("  Repository checks are off. Turn them on with trestle checks on.")
	}
}

// runRepositoryChecks runs the repository's checks for the change between
// base and head, read from the verified object store, and returns them for
// the model requests. The repository index, when the review has one, adds
// the files that depend on the change; without it, or when it covers only
// some of them, the result says so. A failure to prepare the trees becomes
// one check that could not run; it never stops the review. A change that no
// check applies to is an outcome too, so the walkthrough says so.
func runRepositoryChecks(ctx context.Context, objectsPath string, base, head evidence.RevisionIdentity, index *reviewIndexContext, stderr io.Writer) *review.CheckRuns {
	fmt.Fprintln(stderr, "Running this repository's checks for the change in a sandbox (tests twice on each side, linters once)...")
	progress := reviewProgressOf(ctx)
	progress.begin("Repository checks", true)
	checksandbox.SweepStale()
	dependents, scope := index.dependents(ctx)
	switch scope {
	case review.CheckRunsChangedOnly:
		fmt.Fprintln(stderr, "The repository index is unavailable, so the checks cover the changed files only.")
	case review.CheckRunsChangedAndPartialDependents:
		fmt.Fprintln(stderr, "The repository index does not cover the whole change, so the checks cover only some of its dependents.")
	}
	report, err := repositoryChecksReport(ctx, objectsPath, base, head, dependents)
	progress.end()
	if err != nil {
		report = repochecks.Report{Results: []repochecks.Result{{Name: "repository checks", Reason: err.Error()}}}
	}
	fmt.Fprintln(stderr, terminalText(withoutHomeFolder(report.Summary()), 2000))
	for _, leftover := range report.Leftovers {
		fmt.Fprintf(stderr, "A check's scratch folder could not be removed: %s. A later review removes it, or delete it yourself.\n", terminalText(withoutHomeFolder(leftover), 500))
	}
	value, err := review.NewCheckRuns(base.Digest(), head.Digest(), scope, checkRunsOf(report))
	if err != nil {
		fmt.Fprintln(stderr, "The check results could not be bound to the review; the review continues without them.")
		return nil
	}
	return &value
}

// checkRunsOf converts a report for the model requests. Test IDs and
// reasons may hold the paths of the trees, which can sit below the home
// folder, so it is shown as ~ in them.
func checkRunsOf(report repochecks.Report) []review.CheckRun {
	runs := make([]review.CheckRun, 0, len(report.Results))
	for _, result := range report.Results {
		state := review.CheckRunRan
		if !result.Ran {
			state = review.CheckRunCouldNotRun
		}
		runs = append(runs, review.CheckRun{
			Name: result.Name, State: state, Reason: withoutHomeFolder(result.Reason), Tests: result.Tests, FlakyDropped: result.Flaky,
			Fixed: result.Fixed, StillFailing: result.StillFailing,
			Regressions: namedTests(result.Regressions), NewFailures: namedTests(result.NewFailures), StoppedRunning: namedTests(result.StoppedRunning),
		})
	}
	return runs
}

// withoutHomeFolder shows the home folder as ~ in text, so a toolchain or
// tree path does not carry the account name into model requests. It covers
// the folder written with either separator, as a file URL writes it.
func withoutHomeFolder(text string) string {
	home, err := os.UserHomeDir()
	if err != nil || len(home) < 2 {
		return text
	}
	text = strings.ReplaceAll(text, home, "~")
	if slashed := filepath.ToSlash(home); slashed != home {
		text = strings.ReplaceAll(text, slashed, "~")
	}
	return text
}

// terminalText makes repository-derived text safe to print: control and
// format characters, which could drive the terminal, become "?", and the
// text is cut at limit characters.
func terminalText(text string, limit int) string {
	var out strings.Builder
	for index, character := range []rune(text) {
		if index == limit {
			out.WriteString("...")
			break
		}
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			character = '?'
		}
		out.WriteRune(character)
	}
	return out.String()
}

// namedTests drops test IDs that hold no visible text, which the bound
// outcomes cannot carry, and shows the home folder as ~ in the others.
func namedTests(ids []string) []string {
	var named []string
	for _, id := range ids {
		if strings.TrimFunc(id, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) != "" {
			named = append(named, withoutHomeFolder(id))
		}
	}
	return named
}

func repositoryChecksReport(ctx context.Context, objectsPath string, base, head evidence.RevisionIdentity, dependents []string) (repochecks.Report, error) {
	objects, err := os.OpenRoot(objectsPath)
	if err != nil {
		return repochecks.Report{}, errors.New("the checkout's Git objects cannot be opened")
	}
	defer objects.Close()
	repository, _ := evidence.NewRepositoryIdentity("local", []string{"checkout"}, "repository")
	store, err := scm.NewLocalGitObjectStoreWithOptions(scm.LocalGitObjectStoreOptions{ObjectsRoot: objects, Repository: repository, Profile: scm.LocalGitObjectStoreProfileLooseAndPackIndexV1, ObjectAlgorithm: base.Algorithm()})
	if err != nil {
		return repochecks.Report{}, errors.New("the checkout's Git objects cannot be read")
	}
	defer store.Close(context.WithoutCancel(ctx))
	changed, err := repochecks.ChangedPaths(ctx, store, base, head)
	if err != nil {
		return repochecks.Report{}, errors.New("the changed files cannot be listed")
	}
	scratch, err := os.MkdirTemp("", checksandbox.TreesFolderPrefix)
	if err != nil {
		return repochecks.Report{}, errors.New("a scratch folder cannot be created")
	}
	defer os.RemoveAll(scratch)
	limits := checksandbox.DefaultLimits()
	trees := [2]string{filepath.Join(scratch, "base"), filepath.Join(scratch, "head")}
	for index, commit := range []evidence.RevisionIdentity{base, head} {
		if err := os.Mkdir(trees[index], 0o700); err != nil {
			return repochecks.Report{}, errors.New("a scratch folder cannot be created")
		}
		if err := repochecks.Materialize(ctx, store, commit, trees[index], limits.DiskBytes); err != nil {
			return repochecks.Report{}, err
		}
	}
	return repochecks.Run(ctx, repochecks.Input{BaseTree: trees[0], HeadTree: trees[1], Scope: repochecks.Scope{Changed: changed, Dependents: dependents}, Limits: limits, Budget: repochecks.DefaultBudget})
}
