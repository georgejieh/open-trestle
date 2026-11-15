package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/georgejieh/open-trestle/localreview"
)

// `trestle review` with no fixture path reviews the latest change in the
// repository `trestle init` set up: HEAD against its merge base with the
// default branch. It finds the setup folder the way `trestle init` does,
// takes the saved review command's route inventory, runtime policy, scope
// labels, egress and timeout, and replaces only the two commits, which are
// picked again on every run. The review itself is the unchanged
// `trestle local-git model-review` path, so its egress, secret-scanning and
// spending-limit behaviour and messages are exactly that command's.
//
// Which commits:
//   - head: HEAD, the commit checked out now (--head REF picks another);
//   - base: the newest commit HEAD shares with the default branch, as this
//     repository has it or as origin has it, whichever is newer (git merge-base
//     HEAD BRANCH origin/BRANCH). The default branch is the one origin/HEAD
//     names, else main, else master. --base REF picks the base exactly.
//
// Uncommitted changes are never included and nothing is written into the
// repository.

// defaultSetupDirectory is the setup folder `trestle init` proposes for a
// checkout: ~/.local/state/open-trestle/<folder name>-<8 hex characters of
// the checkout path's SHA-256>.
func defaultSetupDirectory(checkout string) string {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return ""
	}
	sum := sha256.Sum256([]byte(checkout))
	return filepath.Join(home, ".local", "state", "open-trestle", initLabel(filepath.Base(checkout), "repository")+"-"+hex.EncodeToString(sum[:])[:8])
}

// findRepositoryCheckout is the top folder of the Git checkout that holds the
// current directory.
func findRepositoryCheckout(ctx context.Context) (string, error) {
	top, _, err := initGit(ctx, ".", "rev-parse", "--show-toplevel")
	if err != nil || !filepath.IsAbs(top) {
		return "", errors.New("not inside a Git checkout")
	}
	return filepath.Clean(top), nil
}

// repositorySetup is a saved setup and the review command it was made with.
type repositorySetup struct {
	checkout  string // the repository's top folder
	directory string // the setup folder
	setup     initSetup
	// template is the saved review command's arguments after
	// "trestle local-git model-review"; its --base and --head are replaced.
	template         []string
	templateCheckout string
}

// setupExists reports whether a setup folder holds a finished setup.
func setupExists(dir string) bool {
	if dir == "" {
		return false
	}
	_, err := os.Lstat(filepath.Join(dir, "bootstrap.json"))
	return err == nil
}

// loadRepositorySetup reads a setup folder and its saved review command. The
// command must use this folder's protected route inventory and runtime
// policy, and the egress its kind of setup allows.
func loadRepositorySetup(ctx context.Context, checkout, dir string) (repositorySetup, error) {
	setup, err := loadInitSetup(ctx, dir)
	if err != nil {
		return repositorySetup{}, err
	}
	content, err := readSetupBootstrapFile(filepath.Join(dir, "bootstrap.json"))
	if err != nil {
		return repositorySetup{}, errors.New("bootstrap.json is missing or not a protected 0600 file")
	}
	var saved struct {
		ReviewCommand          []string `json:"review_command"`
		EphemeralReviewCommand []string `json:"ephemeral_review_command"`
	}
	if json.Unmarshal(content, &saved) != nil {
		return repositorySetup{}, errors.New("bootstrap.json is not valid JSON")
	}
	command, egress := saved.EphemeralReviewCommand, localreview.EgressLocalOnly
	if setup.remote {
		command, egress = saved.ReviewCommand, localreview.EgressPolicyApproved
	}
	if len(command) < 4 || strings.Join(command[:3], " ") != "trestle local-git model-review" {
		return repositorySetup{}, errors.New("bootstrap.json has no usable review command")
	}
	options, _, _, _, err := parseLocalModelReview(command[3:])
	if err != nil || options.inventory != filepath.Join(dir, "routes.json") || options.policy != filepath.Join(dir, "policy.json") || options.egress != egress || !filepath.IsAbs(options.checkout) {
		return repositorySetup{}, errors.New("the saved review command does not use this folder's protected configuration")
	}
	return repositorySetup{checkout: checkout, directory: dir, setup: setup, template: append([]string{}, command[3:]...), templateCheckout: filepath.Clean(options.checkout)}, nil
}

// currentRepositorySetup is the setup of the repository in the current
// directory at the folder `trestle init` proposes, if there is one.
func currentRepositorySetup(ctx context.Context) (initSetup, bool) {
	checkout, err := findRepositoryCheckout(ctx)
	if err != nil {
		return initSetup{}, false
	}
	dir := defaultSetupDirectory(checkout)
	if !setupExists(dir) {
		return initSetup{}, false
	}
	setup, err := loadInitSetup(ctx, dir)
	return setup, err == nil
}

// sameCheckout reports whether two paths name the same folder.
func sameCheckout(a, b string) bool {
	if a == b {
		return true
	}
	left, leftErr := os.Stat(a)
	right, rightErr := os.Stat(b)
	return leftErr == nil && rightErr == nil && os.SameFile(left, right)
}

// latestReviewOptions are the flags `trestle review` passes through.
type latestReviewOptions struct {
	directory, base, head string
	format, timeout       string
	profile, specialists  string
	maxSpecialists        string
	exitPolicy            string
}

// latestReviewCommand is the saved review command with fresh commits and the
// operator's pass-through flags; every other argument stays as saved.
func latestReviewCommand(template []string, base, head string, options latestReviewOptions) []string {
	replace := map[string]string{"--base": base, "--head": head}
	if options.format != "" {
		replace["--format"] = options.format
	}
	if options.timeout != "" {
		replace["--timeout"] = options.timeout
	}
	args := []string{}
	for i := 0; i+1 < len(template); i += 2 {
		flag, value := template[i], template[i+1]
		if replacement, ok := replace[flag]; ok {
			value = replacement
			delete(replace, flag)
		}
		args = append(args, flag, value)
	}
	for _, flag := range []string{"--format", "--timeout"} {
		if value, ok := replace[flag]; ok {
			args = append(args, flag, value)
		}
	}
	for _, extra := range [][2]string{{"--profile", options.profile}, {"--specialists", options.specialists}, {"--max-specialists", options.maxSpecialists}, {"--exit-code-policy", options.exitPolicy}} {
		if extra[1] != "" {
			args = append(args, extra[0], extra[1])
		}
	}
	return append([]string{"trestle", "local-git", "model-review"}, args...)
}

func writeLatestReviewUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle review [--format text|json|sarif] [--timeout DURATION] [--profile ID | --specialists auto|none|ID[,ID...] [--max-specialists N]] [--exit-code-policy default|findings|strict|always-zero] [--base REF] [--head REF] [--directory PATH]")
	fmt.Fprintln(w, "       review the latest change (HEAD against its merge base with the default branch) with the setup trestle init made; see docs/getting-started.md")
	fmt.Fprintln(w, "       trestle review <path>   (review a local fixture file)")
}

// parseLatestReviewFlags reads `trestle review` flags; each is allowed once.
func parseLatestReviewFlags(args []string, stdout, stderr io.Writer) (latestReviewOptions, int, bool) {
	var options latestReviewOptions
	flags := flag.NewFlagSet("trestle review", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	for name, target := range map[string]*string{"directory": &options.directory, "base": &options.base, "head": &options.head, "format": &options.format, "timeout": &options.timeout, "profile": &options.profile, "specialists": &options.specialists, "max-specialists": &options.maxSpecialists, "exit-code-policy": &options.exitPolicy} {
		flags.StringVar(target, name, "", name)
	}
	seen := map[string]bool{}
	for _, argument := range args {
		if name := strings.TrimLeft(strings.SplitN(argument, "=", 2)[0], "-"); strings.HasPrefix(argument, "-") && name != "" {
			if seen[name] {
				fmt.Fprintf(stderr, "trestle review: --%s was given twice.\n", name)
				return options, 2, true
			}
			seen[name] = true
		}
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeLatestReviewUsage(stdout)
			return options, 0, true
		}
		fmt.Fprintln(stderr, "trestle review: "+err.Error())
		writeLatestReviewUsage(stderr)
		return options, 2, true
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "trestle review: unexpected argument %q; give either one fixture path or flags.\n", flags.Arg(0))
		writeLatestReviewUsage(stderr)
		return options, 2, true
	}
	if options.format != "" && options.format != "text" && options.format != "json" && options.format != "sarif" {
		fmt.Fprintln(stderr, "trestle review: --format must be text, json or sarif.")
		return options, 2, true
	}
	return options, 0, false
}

// latestReviewPrinter writes the lines around a review to w with the
// wizard's width, marks and colors.
func latestReviewPrinter(ctx context.Context, w io.Writer, checkout string) *initWizard {
	printer := &initWizard{ctx: ctx, out: w, errOut: w, checkout: checkout, style: newInitStyle(w, false)}
	printer.ok, printer.wait, printer.bad, printer.optional = printer.style.marks()
	return printer
}

// latestChange picks the two commits of the latest change, or explains why
// there is nothing to review. code is the exit code for a problem.
func latestChange(ctx context.Context, w *initWizard, options latestReviewOptions) (base, label, head string, source localCheckoutSource, code int, problem string) {
	head = "HEAD"
	if options.head != "" {
		value, err := initNormalizeSelection(ctx, w.checkout, options.head)
		if err != nil {
			return "", "", "", source, 2, "--head: " + err.Error()
		}
		head = value
	}
	if options.base != "" {
		value, err := initNormalizeSelection(ctx, w.checkout, options.base)
		if err != nil {
			return "", "", "", source, 2, "--base: " + err.Error()
		}
		base = value
	} else {
		base, label = initDefaultMergeBase(ctx, w.checkout)
		if base == "" {
			return "", "", "", source, 3, "no main or master branch was found here (locally or on origin), so there is no default branch to compare against. Pass --base REF, for example --base main."
		}
	}
	source, problem = w.resolvePair(base, head)
	if problem == "" {
		return base, label, head, source, 0, ""
	}
	if options.base == "" && options.head == "" && strings.Contains(problem, "same commit") {
		if label == "" {
			label = "tip of the default branch"
		}
		return "", "", "", source, 3, fmt.Sprintf("nothing to review: HEAD (%s) is already the %s, so there is no committed change on it. Commit your change and run trestle review again, or pass --base REF.", initShort(strings.TrimSpace(gitRevParse(ctx, w.checkout, "HEAD"))), label)
	}
	code = 2
	if options.base == "" && options.head == "" {
		code = 3
	}
	return "", "", "", source, code, problem
}

func gitRevParse(ctx context.Context, checkout, ref string) string {
	value, _, err := initGit(ctx, checkout, "rev-parse", "--verify", "--quiet", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return ref
	}
	return value
}

// missingReviewKeys names the setup's key variables that have no key in the
// environment, the credential store or this session.
func missingReviewKeys(setup initSetup) []string {
	if !setup.remote || setup.provider.key == ollamaSigninProvider {
		return nil
	}
	missing := []string{}
	for _, name := range setup.credentials {
		if !providerKeyStatus(name).available() {
			missing = append(missing, name)
		}
	}
	return missing
}

// runLatestReview is `trestle review` without a fixture path.
func runLatestReview(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	options, code, done := parseLatestReviewFlags(args, stdout, stderr)
	if done {
		return code
	}
	checkout, err := findRepositoryCheckout(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "trestle review: this folder is not inside a Git checkout (or git is not installed). Change into your repository and run trestle review again. To review a fixture file, run trestle review <path>.")
		return 2
	}
	dir := defaultSetupDirectory(checkout)
	if options.directory != "" {
		if dir, err = initValidateDirectory(options.directory); err != nil {
			fmt.Fprintln(stderr, "trestle review: --directory: "+err.Error())
			return 2
		}
	}
	if !setupExists(dir) {
		fmt.Fprintf(stderr, "trestle review: this repository has no Open Trestle setup yet (looked in %s). Run trestle init here first: it asks a few questions and can run the first review.\n", initDisplayPath(dir))
		return 3
	}
	repo, err := loadRepositorySetup(ctx, checkout, dir)
	if err != nil {
		fmt.Fprintf(stderr, "trestle review: the setup in %s cannot be used (%s). Nothing was sent. Run trestle init to check it.\n", initDisplayPath(dir), err)
		return 4
	}
	if !sameCheckout(repo.templateCheckout, checkout) {
		fmt.Fprintf(stderr, "trestle review: the setup in %s is for %s, not this repository. Run trestle review there, or trestle init here.\n", initDisplayPath(dir), initDisplayPath(repo.templateCheckout))
		return 2
	}
	code, _ = reviewLatestChange(ctx, latestReviewPrinter(ctx, stderr, checkout), repo, options, stdout, stderr)
	return code
}

// reviewLatestChange picks the latest change, says what will be reviewed and
// where it is sent, then runs the review. Its lines go to the printer
// (standard error for `trestle review`), so the result on stdout stays one
// document in every format. ran reports whether a review was started.
func reviewLatestChange(ctx context.Context, w *initWizard, repo repositorySetup, options latestReviewOptions, stdout, stderr io.Writer) (code int, ran bool) {
	w.say("%s", w.style.paint(initToneHeading, "Open Trestle · review the latest change"))
	base, label, head, source, code, problem := latestChange(ctx, w, options)
	if problem != "" {
		w.say("  %s %s", w.wait, strings.ToUpper(problem[:1])+problem[1:])
		return code, false
	}
	w.printSelection(base, label, head, source, initSummarizeChange(ctx, w.checkout, source.base, source.head))
	if missing := missingReviewKeys(repo.setup); len(missing) != 0 {
		for _, name := range missing {
			w.say("  %s No API key for %s: it is not set in this shell and no key is saved for it. Nothing was sent. Save it once (the input is hidden), or export it without showing it:", w.bad, name)
			w.sayVerbatim("    trestle keys set " + name)
			w.sayVerbatim("    read -rs " + name + " && export " + name)
		}
		return 3, false
	}
	w.say("  A review sends the selected source to %s.", repo.setup.destination())
	command := latestReviewCommand(repo.template, source.base, source.head, options)
	if _, _, _, _, err := parseLocalModelReview(command[3:]); err != nil {
		var unknown errUnknownModelReviewProfile
		if errors.As(err, &unknown) {
			w.say("  %s %s", w.bad, unknown.Error())
		} else {
			w.say("  %s These flags cannot be combined with this setup's review (for example --profile with --specialists, or a --timeout over 15m). Nothing was sent.", w.bad)
		}
		return 2, false
	}
	w.say("  Running the review. This can take several minutes; press Ctrl-C to stop.")
	var outcome modelReviewOutcome
	code = runLocalGitModelReviewObserved(ctx, command[3:], stdout, stderr, func(result modelReviewOutcome) { outcome = result })
	if outcome.status != "" {
		recordLastReview(ctx, repo.directory, lastReview{Status: outcome.status, Findings: outcome.findings, Base: source.base, Head: source.head})
		w.say("%s", latestOutcomeLine(w, outcome))
	}
	return code, true
}

// latestOutcomeLine says what a finished review means, in the words the
// first review in `trestle init` uses.
func latestOutcomeLine(w *initWizard, outcome modelReviewOutcome) string {
	switch outcome.status {
	case "findings":
		return fmt.Sprintf("  %s Review finished: %d confirmed finding%s. Each was proposed by the finder and confirmed by the checker; the review is not a complete audit (comprehensive clearance: false).", w.ok, outcome.findings, initPlural(outcome.findings))
	case "no_candidates":
		return fmt.Sprintf("  %s Review finished: no problems were found and confirmed for this change. That is not proof the change is correct; it is not a complete audit.", w.ok)
	case "incomplete":
		return fmt.Sprintf("  %s The review could not cover everything; see coverage and omissions in the result.", w.wait)
	case "canceled":
		return fmt.Sprintf("  %s The review was stopped before it finished.", w.wait)
	case "refused":
		return fmt.Sprintf("  %s The review was refused; the result says why.", w.bad)
	}
	return fmt.Sprintf("  %s The review did not finish (%s); the result says why.", w.bad, outcome.status)
}
