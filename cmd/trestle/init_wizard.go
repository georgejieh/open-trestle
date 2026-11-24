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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/secretscan"
	"github.com/georgejieh/open-trestle/modelcatalog"
	"github.com/georgejieh/open-trestle/spending"
)

// `trestle init` is a guided front end over the existing bootstrap. It collects
// answers, then calls `setup bootstrap init` and `check` in-process with an
// ordinary argument array, renders their results in plain language, and runs
// the printed review command only after explicit consent. It adds no new
// configuration format, default model, privacy claim or bypass: every fact the
// bootstrap needs is still an explicit operator answer.

const (
	initExitDone    = 0
	initExitFailed  = 1
	initExitUsage   = 2
	initExitPending = 3
	initExitRefused = 4
)

// Tests replace the model-list reader; production uses the bounded catalog fetch.
// The resolver is nil unless the source names a credential variable.
var initListModels = func(ctx context.Context, source modelcatalog.Source, allowRemote bool, resolver modelcatalog.CredentialResolver) ([]modelcatalog.Model, error) {
	return modelcatalog.List(ctx, source, allowRemote, resolver)
}

type initProviderInfo struct {
	key, label, short  string
	credentialProposal string
	catalog            *modelcatalog.Source
	example            string
	docs               string
}

var initProviders = []initProviderInfo{
	{key: "openrouter", label: "OpenRouter (remote, needs an API key)", short: "OpenRouter", credentialProposal: "OPEN_TRESTLE_PROVIDER_OPENROUTER", example: "vendor/model-name, exactly as listed at https://openrouter.ai/models", docs: "docs/remote-model-review.md#openrouter"},
	{key: "ollama-cloud", label: "Ollama Cloud (remote, needs an API key)", short: "Ollama Cloud", credentialProposal: "OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD", catalog: &modelcatalog.Source{ID: "ollama-cloud", Kind: "ollama_tags", URL: "https://ollama.com/api/tags"}, example: "name:tag", docs: "docs/remote-model-review.md#ollama-cloud"},
	{key: "opencode-go", label: "OpenCode Go (remote, needs an API key)", short: "OpenCode Go", credentialProposal: "OPEN_TRESTLE_PROVIDER_OPENCODE_GO", catalog: &modelcatalog.Source{ID: "opencode-go", Kind: "openai_models", URL: "https://opencode.ai/inference/go/v1/models"}, example: "model-name", docs: "docs/remote-model-review.md#opencode-go"},
	{key: "local", label: "A model server on this machine (Ollama, llama.cpp, vLLM, LM Studio)", short: "your local model server", docs: "docs/local-first-bootstrap.md"},
	{key: ollamaSigninProvider, label: "Ollama on this machine, signed in to Ollama Cloud (remote)", short: "Ollama Cloud through your signed-in local Ollama", example: "name:tag-cloud", docs: "docs/remote-model-review.md#ollama-signed-in-to-ollama-cloud"},
}

// Listener addresses from docs/named-local-runtimes.md; they are offered as
// choices, never assumed.
var initLocalServers = []struct{ name, endpoint string }{
	{"Ollama", "http://127.0.0.1:11434/v1"},
	{"LM Studio", "http://127.0.0.1:1234/v1"},
	{"llama.cpp", "http://127.0.0.1:8080/v1"},
	{"vLLM", "http://127.0.0.1:8000/v1"},
}

var initStringFlags = []string{"directory", "base", "head", "provider", "endpoint", "verification-endpoint", "transport", "generation-model", "verification-model", "credential-env", "owner", "tenant", "repository", "repository-authority", "repository-namespace", "repository-name", "context-tokens", "output-tokens", "max-output-tokens", "input-micro-usd-per-million-tokens", "output-micro-usd-per-million-tokens", "max-cost-micro-usd", "spending-limit", "spending-alert", "specialists", "generation-provider-slug", "verification-provider-slug", "generation-model-evidence", "verification-model-evidence", "broker-evidence", "account-evidence", "evidence-retrieved-at", "reviewed-at", "valid-from", "valid-until"}
var initBoolFlags = []string{"no-input", "run-review", "checks", "allow-local-probe", "declare-local-capabilities", "declare-remote-route", "without-zdr", "declare-opencode-go-account", "declare-ollama-cloud-signin"}

// initStop ends the wizard with a plain-language reason and exit code.
type initStop struct {
	code    int
	message string
}

func (s *initStop) Error() string { return s.message }

func initStopf(code int, format string, args ...any) error {
	return &initStop{code: code, message: fmt.Sprintf(format, args...)}
}

type initAnswers struct {
	base, head                               string
	source                                   localCheckoutSource
	directory                                string
	provider                                 initProviderInfo
	generationEndpoint, verificationEndpoint string
	transport                                string
	generationModel, verificationModel       string
	credentialEnv                            string
	contextTokens, outputTokens              string
	reviewOutput                             uint64 // the review output allowance an OpenRouter setup chose, or 0
	inputPrice, outputPrice, maxCost         string
	// spendingLimit is the chosen monthly limit for the key in micro-USD, 0
	// for none, alerting at spendingAlert percent and at the limit.
	// spendingExisting is a limit the key already has, which is kept.
	spendingLimit              uint64
	spendingAlert              int
	spendingExisting           *spending.Limit
	owner, tenant, repository  string
	authority, namespace, name string
	extra                      []string // provider-specific bootstrap arguments
	declarations               []string
}

type initWizard struct {
	ctx                     context.Context
	out                     io.Writer
	errOut                  io.Writer
	prompt                  *initPrompter
	flags                   map[string]string
	bools                   map[string]bool
	missing                 []string
	clock                   setupClock
	ok, wait, bad, optional string
	checkout                string
	repoName                string
	a                       initAnswers
	models                  map[string][]modelcatalog.Model
	saved                   bool // the bootstrap wrote or found a complete setup
	fetched                 map[string]initFetchedEvidence
	lastFetch               time.Time                       // the latest evidence fetch, if any
	modelEndpoint           string                          // the local server whose model is being chosen
	listed                  map[string][]modelcatalog.Model // model lists read from local servers
	ollamaBinary            bool                            // the ollama command was found on PATH
	pendingHeader           string                          // a --no-input step header not yet printed
	openRouter              *openRouterObservation
	zdr                     bool // every OpenRouter request requires zero data retention
	style                   initStyle
	// terminal is standard input's terminal when its echo can be turned off
	// for typing an API key; nil otherwise, and then no key is asked for.
	terminal echoTerminal
	// enteredKeys names typed keys to save once the setup is saved.
	enteredKeys []string
	pending     []initDeclaration // confirmed together at the summary
}

func runInit(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runInitWithClock(ctx, args, stdin, stdout, stderr, systemSetupClock{})
}

func runInitWithClock(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, clock setupClock) int {
	w := &initWizard{ctx: ctx, out: stdout, errOut: stderr, flags: map[string]string{}, bools: map[string]bool{}, clock: clock, models: map[string][]modelcatalog.Model{}, fetched: map[string]initFetchedEvidence{}}
	if code, done := w.parseFlags(args); done {
		return code
	}
	w.style = newInitStyle(stdout, w.bools["no-input"])
	w.ok, w.wait, w.bad, w.optional = w.style.marks()
	if !w.bools["no-input"] {
		w.prompt = newInitPrompter(ctx, stdin, stdout, w.style, func(line string) { w.say("%s", line) })
		defer w.prompt.close()
		if terminal, ok := openEchoTerminal(stdin); ok {
			w.terminal = terminal
		}
	}
	code, err := w.run()
	if err != nil {
		return w.stop(err)
	}
	return code
}

func (w *initWizard) stop(err error) int {
	var stop *initStop
	switch {
	case errors.As(err, &stop):
		fmt.Fprintln(w.out)
		w.complain(stop.message)
		return stop.code
	case errors.Is(err, errInitInputEnded):
		w.complain("stopped because input ended (Ctrl-D, Ctrl-C or a closed pipe). " + w.writtenNote())
		return initExitUsage
	case errors.Is(err, errInitTooManyTries):
		w.complain("stopped after three answers that could not be used. " + w.writtenNote() + " `trestle init --help` lists the answer flags.")
		return initExitUsage
	default:
		w.complain("internal error: " + err.Error())
		return initExitFailed
	}
}

// complain writes a stopping reason to standard error, wrapped to the same
// width as everything else.
func (w *initWizard) complain(message string) {
	for index, line := range strings.Split("trestle init: "+message, "\n") {
		if index > 0 && strings.HasPrefix(line, "  ") && initCommandLine(line) {
			fmt.Fprintln(w.errOut, line)
			continue
		}
		for _, part := range initFit(line, initWidth) {
			fmt.Fprintln(w.errOut, part)
		}
	}
}

// initCommandLine reports a line that shows a command to copy: it keeps its
// full length so the command still works when pasted.
func initCommandLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	for _, prefix := range []string{"trestle ", "--", "python3 ", "sudo ", "./", "sha256sum ", "REVISION=", "CREATED=", "git clone ", "read -rs ", "export ", "/usr/local/bin/trestle", "DIR/bin/trestle", "ollama ", "chmod "} {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

func (w *initWizard) writtenNote() string {
	if w.saved {
		return "Your setup in " + initDisplayPath(w.a.directory) + " is saved; run `trestle init` again to check it or run a review."
	}
	return "Nothing was written. Run `trestle init` again to start over."
}

// initFlagValues names the value of each string flag in the help; any other
// string flag takes VALUE.
var initFlagValues = map[string]string{
	"directory": "PATH", "base": "REF", "head": "REF",
	"provider": "openrouter|openrouter-zdr|ollama-cloud|opencode-go|local|ollama-signin",
	"endpoint": "URL", "verification-endpoint": "URL",
	"transport":        "openai_chat_completions|openai_responses",
	"generation-model": "ID", "verification-model": "ID",
	"credential-env": "OPEN_TRESTLE_PROVIDER_NAME",
	"owner":          "LABEL", "tenant": "LABEL", "repository": "LABEL",
	"repository-authority": "LABEL", "repository-namespace": "LABEL", "repository-name": "LABEL",
	"context-tokens": "N", "output-tokens": "N", "max-output-tokens": "N",
	"input-micro-usd-per-million-tokens": "N", "output-micro-usd-per-million-tokens": "N", "max-cost-micro-usd": "N",
	"spending-limit": "USD", "spending-alert": "PERCENT", "specialists": "auto|none",
	"generation-provider-slug": "SLUG[,SLUG]", "verification-provider-slug": "SLUG[,SLUG]",
	"evidence-retrieved-at": "UTC_TIME", "reviewed-at": "UTC_TIME", "valid-from": "UTC_TIME", "valid-until": "UTC_TIME",
}

// writeInitUsage lists every flag the wizard accepts, from the same tables the
// flag parser reads.
func writeInitUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle init [flags]")
	fmt.Fprintln(w, "       guided first setup and first review for the Git repository in the current directory")
	fmt.Fprintln(w, "flags (each at most once; docs/getting-started.md#non-interactive-use explains them):")
	items := []string{}
	for _, name := range initStringFlags {
		value, ok := initFlagValues[name]
		if !ok {
			value = "VALUE"
			if strings.HasSuffix(name, "-evidence") {
				value = "HTTPS_URL,SHA256"
			}
		}
		items = append(items, "--"+name+" "+value)
	}
	for _, name := range initBoolFlags {
		items = append(items, "--"+name)
	}
	const indent, width = "  ", 100
	line := indent
	for _, item := range items {
		if line != indent && len(line)+2+len(item) > width {
			fmt.Fprintln(w, line)
			line = indent
		}
		if line != indent {
			line += "  "
		}
		line += item
	}
	fmt.Fprintln(w, line)
}

func (w *initWizard) parseFlags(args []string) (int, bool) {
	flags := flag.NewFlagSet("trestle init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	strs := map[string]*string{}
	for _, name := range initStringFlags {
		strs[name] = flags.String(name, "", name)
	}
	bools := map[string]*bool{}
	for _, name := range initBoolFlags {
		bools[name] = flags.Bool(name, false, name)
	}
	seen := map[string]bool{}
	for _, argument := range args {
		if name := strings.TrimLeft(strings.SplitN(argument, "=", 2)[0], "-"); strings.HasPrefix(argument, "-") && name != "" {
			if seen[name] {
				fmt.Fprintf(w.errOut, "trestle init: --%s was given twice; give each answer once.\n", name)
				return initExitUsage, true
			}
			seen[name] = true
		}
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeInitUsage(w.out)
			return initExitDone, true
		}
		fmt.Fprintln(w.errOut, "trestle init: "+err.Error())
		writeInitUsage(w.errOut)
		return initExitUsage, true
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(w.errOut, "trestle init: unexpected argument %q; answers are given as --flag VALUE.\n", flags.Arg(0))
		writeInitUsage(w.errOut)
		return initExitUsage, true
	}
	flags.Visit(func(f *flag.Flag) {
		if value, ok := strs[f.Name]; ok {
			w.flags[f.Name] = *value
		} else {
			w.bools[f.Name] = *bools[f.Name]
		}
	})
	if value, given := w.flags["specialists"]; given && !validSetupSpecialists(value) || given && value == "" {
		fmt.Fprintln(w.errOut, "trestle init: --specialists must be auto (the default: the general review, then specialist reviews picked from the change) or none (the general review only).")
		return initExitUsage, true
	}
	return 0, false
}

// specialists is the specialist choice the setup saves: auto unless
// --specialists none was given. It is never asked: the default runs them,
// and the flag turns them off.
func (w *initWizard) specialists() string {
	if value := w.flags["specialists"]; value == specialistModeNone {
		return specialistModeNone
	}
	return specialistModeAuto
}

// say prints text, each line wrapped to initWidth columns.
func (w *initWizard) say(format string, args ...any) {
	w.flushHeader()
	for _, line := range strings.Split(fmt.Sprintf(format, args...), "\n") {
		for _, part := range initFit(line, initWidth) {
			fmt.Fprintln(w.out, part)
		}
	}
}

// sayVerbatim prints a command to copy exactly as given, never wrapped.
func (w *initWizard) sayVerbatim(text string) {
	w.flushHeader()
	fmt.Fprintln(w.out, text)
}

// hint prints a dim explanation under a mark or question.
func (w *initWizard) hint(text string) {
	w.flushHeader()
	for _, part := range initFit(text, initWidth) {
		fmt.Fprintln(w.out, w.style.paint(initToneDim, part))
	}
}

func (w *initWizard) flushHeader() {
	if w.pendingHeader != "" {
		fmt.Fprint(w.out, w.pendingHeader)
		w.pendingHeader = ""
	}
}

// header starts a step. Interactively a question always follows, so it is
// printed at once. With --no-input a step may have nothing to show, so its
// header waits for the step's first line and is dropped when none comes.
func (w *initWizard) header(step int, title string) {
	text := strings.Join(w.style.stepHeader(step, title), "\n") + "\n"
	if w.prompt != nil {
		fmt.Fprint(w.out, text)
		return
	}
	w.pendingHeader = text
}

type initQuestion struct {
	flag, question, proposed string
	// acceptProposal lets --no-input use a derived proposal (labels, refs,
	// directory). Facts the operator must declare never set it.
	acceptProposal bool
	validate       func(string) (string, error)
	// validateFlag replaces validate for a flag value given in another unit
	// (micro-USD flags versus dollar answers).
	validateFlag func(string) (string, error)
}

func (w *initWizard) answer(q initQuestion) (string, error) {
	if raw, ok := w.flags[q.flag]; ok {
		validate := q.validate
		if q.validateFlag != nil {
			validate = q.validateFlag
		}
		value, err := validate(raw)
		if err != nil {
			return "", initStopf(initExitUsage, "--%s: %v", q.flag, err)
		}
		return value, nil
	}
	if w.prompt == nil {
		if q.acceptProposal && q.proposed != "" {
			return q.proposed, nil
		}
		w.missing = append(w.missing, "--"+q.flag)
		return "", nil
	}
	return w.prompt.ask(q.question, q.proposed, q.validate)
}

func (w *initWizard) confirm(question string, defaultYes, noInput bool) (bool, error) {
	if w.prompt == nil {
		return noInput, nil
	}
	return w.prompt.confirm(question, defaultYes)
}

// initDeclaration is one operator declaration. Its facts are read when it is
// shown, so they follow any setting changed at the summary.
type initDeclaration struct {
	flag, title, doc string
	facts            func() []string
}

// declare adds a declaration to the summary, where one answer confirms every
// declaration, or each is confirmed by its own existing bootstrap flag. There
// is no blanket bypass.
func (w *initWizard) declare(flagName, title, doc string, facts func() []string) {
	if w.prompt == nil && len(w.missing) != 0 {
		if !w.bools[flagName] {
			w.missing = append(w.missing, "--"+flagName)
		}
		return
	}
	w.pending = append(w.pending, initDeclaration{flag: flagName, title: title, doc: doc, facts: facts})
}

// showDeclarations prints the pending declarations and the spending limit
// under the summary panel.
func (w *initWizard) showDeclarations() {
	w.say("\n  Open Trestle records what you state below; it cannot check it for you.")
	for _, d := range w.pending {
		w.say("\n  Declaration: %s", d.title)
		w.say("  By confirming, you state that:")
		for _, fact := range d.facts() {
			w.say("    • %s", fact)
		}
		w.say("  Details: %s", d.doc)
		if w.bools[d.flag] {
			w.say("  Confirmed with --%s.", d.flag)
		}
	}
	if row, ok := w.spendingRow(); ok {
		w.say("\n  Spending limit: %s", row)
	}
}

func (w *initWizard) run() (int, error) {
	top, _, err := initGit(w.ctx, ".", "rev-parse", "--show-toplevel")
	if err != nil || !filepath.IsAbs(top) {
		return 0, initStopf(initExitUsage, "this folder is not inside a Git checkout (or git is not installed). Change into your repository folder and run `trestle init` again.")
	}
	w.checkout = filepath.Clean(top)
	w.repoName = initLabel(filepath.Base(w.checkout), "repository")
	for _, line := range w.style.banner(w.prompt == nil) {
		w.say("%s", line)
	}

	w.a.directory = w.defaultDirectory()
	if raw, ok := w.flags["directory"]; ok {
		directory, err := initValidateDirectory(raw)
		if err != nil {
			return 0, initStopf(initExitUsage, "--directory: %v", err)
		}
		w.a.directory = directory
	}
	if existing, err := w.existingSetup(); err != nil || existing {
		if err != nil {
			return 0, err
		}
		return w.resume()
	}
	steps := []func() error{w.stepSelection, w.stepProvider, w.stepModels, w.stepCredentials, w.autoNames, w.stepDeclarations, w.stepSummary}
	for _, step := range steps {
		if err := step(); err != nil {
			return 0, err
		}
		if w.prompt == nil && slices.Contains(w.missing, "--provider") {
			break
		}
	}
	if len(w.missing) != 0 {
		var list strings.Builder
		for _, name := range w.missing {
			list.WriteString("\n  " + name)
		}
		hint := ""
		if slices.Contains(w.missing, "--provider") {
			hint = "\nThe provider decides which other answers are needed; add --provider first."
		}
		return 0, initStopf(initExitUsage, "--no-input needs these answers as flags (nothing was written):%s%s\nSee docs/getting-started.md#non-interactive-use.", list.String(), hint)
	}
	return w.stepWrite()
}

func (w *initWizard) defaultDirectory() string { return discoverSetupDirectory(w.ctx, w.checkout) }

func initValidateDirectory(value string) (string, error) {
	if strings.HasPrefix(value, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			value = filepath.Join(home, value[2:])
		}
	}
	absolute, err := filepath.Abs(value)
	if err != nil || len(absolute) > 4096 {
		return "", errors.New("that is not a usable folder path")
	}
	return absolute, nil
}

func (w *initWizard) stepSelection() error {
	w.header(1, "What will be reviewed")
	normalize := func(value string) (string, error) { return initNormalizeSelection(w.ctx, w.checkout, value) }
	_, baseGiven := w.flags["base"]
	_, headGiven := w.flags["head"]
	head := "HEAD"
	if headGiven {
		value, err := normalize(w.flags["head"])
		if err != nil {
			return initStopf(initExitUsage, "--head: %v", err)
		}
		head = value
	}
	base, proposedLabel := initDefaultMergeBase(w.ctx, w.checkout, head)
	proposedBase := base
	if baseGiven {
		value, err := normalize(w.flags["base"])
		if err != nil {
			return initStopf(initExitUsage, "--base: %v", err)
		}
		base = value
	}
	askBoth := false
	for range initMaxTries {
		if base == "" || askBoth {
			if base == "" && !askBoth {
				w.say("  No main or master branch was found. Which branch, tag or commit is the starting point?")
			}
			var err error
			if !askBoth {
				if base, err = w.answer(initQuestion{flag: "base", question: "Base: the starting point to compare against", validate: normalize}); err != nil || base == "" {
					return err
				}
			} else {
				if base, err = w.prompt.ask("Base: the starting point to compare against", base, normalize); err != nil {
					return err
				}
				if head, err = w.prompt.ask("Head: the commit with your changes", head, normalize); err != nil {
					return err
				}
			}
		}
		source, problem := w.resolvePair(base, head)
		if problem != "" {
			if w.prompt == nil || baseGiven && headGiven {
				return initStopf(initExitUsage, "%s", problem)
			}
			w.say("  %s %s", w.bad, problem)
			askBoth = true
			continue
		}
		label := ""
		if base == proposedBase {
			label = proposedLabel
		}
		w.printSelection(base, label, head, source, initSummarizeChange(w.ctx, w.checkout, source.base, source.head))
		w.a.base, w.a.head, w.a.source = base, head, source
		return w.sourcePreflight()
	}
	return errInitTooManyTries
}

func (w *initWizard) resolvePair(base, head string) (localCheckoutSource, string) {
	source, err := resolveLocalCheckout(w.ctx, w.checkout, base, head)
	if err == nil {
		return source, ""
	}
	baseCommit, _, baseErr := initGit(w.ctx, w.checkout, "rev-parse", "--verify", "--quiet", "--end-of-options", base+"^{commit}")
	headCommit, _, headErr := initGit(w.ctx, w.checkout, "rev-parse", "--verify", "--quiet", "--end-of-options", head+"^{commit}")
	switch {
	case baseErr != nil:
		return source, fmt.Sprintf("the base %s does not name a commit in this repository.", base)
	case headErr != nil:
		return source, fmt.Sprintf("the head %s does not name a commit in this repository.", head)
	case baseCommit == headCommit:
		return source, fmt.Sprintf("base %s and head %s are the same commit (%s), so there is nothing to compare. Check out the branch with your changes, or pick a different base.", base, head, initShort(baseCommit))
	}
	return source, "Git could not read these commits for review. Use a full ref such as refs/heads/main, HEAD, or a full commit ID."
}

// printSelection shows the two commits the review compares. The commit count and
// shortstat come from the same resolved base and head commits.
func (w *initWizard) printSelection(base, baseLabel, head string, source localCheckoutSource, summary initChangeSummary) {
	where := ""
	if summary.currentLabel != "" {
		where = "  (on branch " + summary.currentLabel + ")"
	}
	w.say("  Repository: %s%s", initDisplayPath(w.checkout), where)
	if baseLabel != "" {
		w.say("  Base:       %s  (%s)", initShort(source.base), baseLabel)
	} else {
		w.say("  Base:       %s  (%s)", base, initShort(source.base))
	}
	w.say("  Head:       %s  (%s)", head, initShort(source.head))
	changes := "unknown"
	if summary.commits >= 0 {
		changes = fmt.Sprintf("%d commit%s", summary.commits, initPlural(summary.commits))
		if summary.shortstat != "" {
			changes += " · " + summary.shortstat
		}
	}
	w.say("  Changes:    %s", changes)
	w.say("  Open Trestle compares exactly these two commits; it does not fetch.")
	if summary.uncommitted {
		w.say("  Note: you have uncommitted changes, and they are not included: only committed work is reviewed. To include them, commit them first.")
	}
}

// sourcePreflight reads the two selected commits with the reader every review
// uses (local or remote), before any further question. It needs no private
// objects folder and no loose objects; it changes nothing.
func (w *initWizard) sourcePreflight() error {
	err := setupCheckDirectReviewSource(w.ctx, w.a.source)
	if err == nil {
		return nil
	}
	return initStopf(initExitRefused, "Open Trestle cannot read the selected commits from this repository's Git storage.\n"+
		"  Detail: %v\n"+
		"  Reviews read loose objects and ordinary pack files. They do not follow alternates (clones\n"+
		"  made with --shared or --reference), a multi-pack-index or partial-clone (promisor) packs.\n"+
		"  Make a separate full copy, then run trestle init inside it (your work must be committed):\n"+
		"    git clone --no-local --no-hardlinks %s %s\n"+
		"  Your repository was not changed. Nothing was written.", err, initShellQuote(w.checkout), initShellQuote(w.checkout+"-review"))
}

// initScannerBlock reports why this binary cannot review at all, or "" when
// it can (a missing helper is reported later by the setup check, with its
// fix).
func initScannerBlock() string {
	switch err := setupBootstrapScannerPrerequisite(); {
	case errors.Is(err, secretscan.ErrHelperNotPinned):
		return "development"
	case errors.Is(err, secretscan.ErrScannerUnsupportedPlatform):
		return "platform"
	}
	return ""
}

func (w *initWizard) explainScannerBlock(block string) {
	if block == "platform" {
		w.say("  Note: the secret scanner does not run on this system, so this build cannot send source to a model.")
		return
	}
	w.say("  Note: your source is secret-scanned before it reaches a model, and this development build has no secret scanner of its own, so it refuses.")
	w.sayBuildWithScanner("init")
}

// sayBuildWithScanner shows how to get a trestle with its secret scanner: the
// packaged install on Linux, or a development build with its helper, each
// with the trestle command to run next.
func (w *initWizard) sayBuildWithScanner(next string) {
	if runtime.GOOS == "linux" {
		w.say("  To build and install the packaged trestle from a clean checkout (docs/operations.md):")
		w.sayPackagingSteps()
		w.say("  Then run this in the repository:")
		w.sayVerbatim("    /usr/local/bin/trestle " + next)
		w.say("  Or build trestle with its scanner in a folder (docs/remote-model-review.md):")
	} else {
		w.say("  Build trestle with its scanner in a folder (docs/remote-model-review.md):")
	}
	w.sayVerbatim("    python3 tools/package_secret_scanner.py --development DIR")
	w.say("  Then run this in the repository:")
	w.sayVerbatim("    DIR/bin/trestle " + next)
}

// initPackagingSteps is the packaged-build sequence of docs/operations.md, each
// command exactly as the guide writes it: scanner staging, the passive
// vulnerability gate (the candidate builder refuses a staging tree without its
// release/vulnerability-scan.json), the candidate build and checks, and the
// production install. A test keeps it identical to the guide.
var initPackagingSteps = [][]string{
	{"python3 tools/package_secret_scanner.py --output .container"},
	{"python3 tools/package_secret_scanner.py --verify .container"},
	{"python3 tools/vulnerability_gate.py --staging .container"},
	{`REVISION="$(git rev-parse HEAD)"`},
	{`CREATED="$(date -u -d "$(git show -s --format=%cI "$REVISION")" +%Y-%m-%dT%H:%M:%SZ)"`},
	{`python3 tools/linux_distribution.py \`, `  --staging .container \`, `  --version 0.1.0-dev \`, `  --revision "$REVISION" \`, `  --created "$CREATED" \`, "  --output open-trestle-linux-amd64.pyz"},
	{"sha256sum -c open-trestle-linux-amd64.pyz.sha256"},
	{"./open-trestle-linux-amd64.pyz verify-archive"},
	{"sudo ./open-trestle-linux-amd64.pyz install"},
}

func (w *initWizard) sayPackagingSteps() {
	for _, step := range initPackagingSteps {
		for _, line := range step {
			w.sayVerbatim("    " + line)
		}
	}
}

func (w *initWizard) stepProvider() error {
	w.header(2, "Where the models run")
	block := initScannerBlock()
	if block != "" {
		w.explainScannerBlock(block)
	}
	keys := []string{}
	labels := []string{}
	for _, p := range initProviders {
		keys, labels = append(keys, p.key), append(labels, p.label)
	}
	if raw, ok := w.flags["provider"]; ok {
		// openrouter-zdr is OpenRouter with zero data retention required.
		if raw == "openrouter-zdr" {
			raw = "openrouter"
		}
		index := slices.Index(keys, raw)
		if index < 0 {
			return initStopf(initExitUsage, "--provider must be one of %s (or openrouter-zdr).", strings.Join(keys, ", "))
		}
		w.a.provider = initProviders[index]
	} else if w.prompt == nil {
		w.missing = append(w.missing, "--provider")
		return nil
	} else {
		chosen := false
		for range initMaxTries {
			index, err := w.prompt.choose("Choose", labels)
			if err != nil {
				return err
			}
			w.a.provider = initProviders[index]
			if block == "" {
				chosen = true
				break
			}
			w.say("  %s This build cannot send source to %s; that needs a trestle with its secret scanner.", w.wait, w.a.provider.short)
			anyway, err := w.prompt.confirm("Set it up anyway, and review later with a trestle that has it?", false)
			if err != nil {
				return err
			}
			if anyway {
				chosen = true
				break
			}
		}
		if !chosen {
			return errInitTooManyTries
		}
	}
	w.say("  Using: %s", w.a.provider.label)
	return nil
}

func (w *initWizard) stepModels() error {
	w.header(3, "The two models")
	if w.a.provider.key == "openrouter" {
		return w.openRouterModels()
	}
	if w.a.provider.key == "local" {
		if err := w.localModels(); err != nil {
			return err
		}
	} else if w.a.provider.key == ollamaSigninProvider {
		if err := w.ollamaSigninModels(); err != nil {
			return err
		}
	} else if err := w.remoteModels(); err != nil {
		return err
	}
	if err := w.capacities(); err != nil {
		return err
	}
	if w.a.provider.key != "local" {
		return w.prices()
	}
	return nil
}

func (w *initWizard) remoteModels() error {
	var models []modelcatalog.Model
	_, generationGiven := w.flags["generation-model"]
	_, verificationGiven := w.flags["verification-model"]
	if catalog := w.a.provider.catalog; catalog != nil && w.prompt != nil && !(generationGiven && verificationGiven) {
		host, _ := url.Parse(catalog.URL)
		w.say("  Fetching the public model list from %s (no code or key is sent)...", host.Host)
		listed, err := initListModels(w.ctx, *catalog, true, nil)
		if err != nil || len(listed) == 0 {
			w.say("  %s Could not read the model list. Type each model ID exactly instead (format: %s).", w.wait, w.a.provider.example)
		} else {
			models = listed
		}
	}
	return w.pickPair(models, models)
}

func (w *initWizard) pickPair(generation, verification []modelcatalog.Model) error {
	var err error
	if w.a.generationModel, err = w.pickModel("generation-model", "Finder model: looks for problems in your change", generation, "", ""); err != nil {
		return err
	}
	w.a.verificationModel, err = w.pickChecker(verification)
	return err
}

// pickChecker picks the checker model. It must differ from the finder, and a
// model from another family is recommended but not required: different model
// families tend to miss different problems.
func (w *initWizard) pickChecker(models []modelcatalog.Model) (string, error) {
	if w.prompt != nil {
		w.say("\n  The checker must be a different model. A model from a different family is recommended, because different families tend to miss different problems.")
	}
	_, given := w.flags["verification-model"]
	for {
		checker, err := w.pickModel("verification-model", "Checker model: double-checks each finding", models, w.a.generationModel, "")
		if err != nil {
			return "", err
		}
		family := initSameFamily(w.a.generationModel, checker)
		if family == "" {
			return checker, nil
		}
		w.say("  %s The finder and the checker are both %s models. A checker from a different family is recommended.", w.wait, family)
		if w.prompt == nil || given {
			return checker, nil
		}
		keep, err := w.confirm("Keep this checker?", true, true)
		if err != nil || keep {
			return checker, err
		}
	}
}

var initModelSize = regexp.MustCompile(`(?i)(?:^|[^a-z0-9.])(\d+(?:\.\d+)?)b(?:$|[^a-z0-9])`)

// initSmallModel reports whether metadata or the selector says the model has at
// most 7 billion parameters. Unknown sizes are not reported as small.
func initSmallModel(model modelcatalog.Model) bool {
	sizes := []string{}
	var fields struct {
		Details struct {
			ParameterSize string `json:"parameter_size"`
		} `json:"details"`
	}
	if json.Unmarshal(model.Metadata, &fields) == nil && fields.Details.ParameterSize != "" {
		sizes = append(sizes, " "+fields.Details.ParameterSize+" ")
	}
	sizes = append(sizes, model.Selector)
	for _, text := range sizes {
		if match := initModelSize.FindStringSubmatch(text); match != nil {
			if size, err := strconv.ParseFloat(match[1], 64); err == nil {
				return size <= 7
			}
		}
	}
	return false
}

func initModelNote(model modelcatalog.Model) string {
	notes := []string{}
	if n := initMetadataNumber(model.Metadata, "context_length", "context_window", "max_context_length", "max_model_len"); n > 0 {
		notes = append(notes, fmt.Sprintf("context %d", n))
	}
	if initMetadataNumber(model.Metadata, "zero_data_retention_endpoints") > 0 {
		notes = append(notes, "zero data retention")
	}
	if initSmallModel(model) {
		notes = append(notes, "small: weak reviews")
	}
	if len(notes) == 0 {
		return ""
	}
	return "  (" + strings.Join(notes, ", ") + ")"
}

func initValidSelector(value string) error {
	if value == "" || len(value) > 1024 || strings.ContainsFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return errors.New("A model ID has no spaces; copy it exactly from the provider's list.")
	}
	if lower := strings.ToLower(value); strings.HasPrefix(lower, "sk-") || strings.HasPrefix(lower, "sk_") || strings.HasPrefix(value, "OPEN_TRESTLE_PROVIDER_") {
		return errors.New("That looks like an API key or its variable name, not a model ID. Never type a key here; the key variable is asked for in step 5.")
	}
	return nil
}

// pickModel picks one model: from its flag, as a typed ID when there is no
// list, or from the list (chooseModel). keep, when set, is the current model,
// which Enter keeps.
func (w *initWizard) pickModel(flagName, question string, models []modelcatalog.Model, exclude, keep string) (string, error) {
	validate := func(value string) (string, error) {
		if err := initValidSelector(value); err != nil {
			return "", err
		}
		if value == exclude {
			return "", errors.New("That is the same model as the finder. Pick a different model for the checker.")
		}
		if w.a.provider.key == "local" {
			// A model the local Ollama relays to Ollama Cloud is refused here, not warned about.
			if err := ollamaLocalModelError(w.ctx, w.modelEndpoint, value); err != nil {
				return "", fmt.Errorf("%v. Choose a model that runs on this machine, or run trestle init again and choose \"Ollama on this machine, signed in to Ollama Cloud\".", err)
			}
		}
		if w.a.provider.key == ollamaSigninProvider && !slices.ContainsFunc(models, func(m modelcatalog.Model) bool { return m.Selector == value }) {
			return "", fmt.Errorf("%s is not one of the Ollama Cloud models your local Ollama lists. Pick a number from the list, or add the model with `ollama pull %s` and run trestle init again.", value, value)
		}
		return value, nil
	}
	var choice string
	var err error
	if _, given := w.flags[flagName]; given || w.prompt == nil || len(models) == 0 {
		choice, err = w.answer(initQuestion{flag: flagName, question: question, validate: validate})
	} else {
		choice, err = w.chooseModel(question, models, keep, validate)
	}
	if err != nil || choice == "" || choice == keep {
		return choice, err
	}
	index := slices.IndexFunc(models, func(m modelcatalog.Model) bool { return m.Selector == choice })
	model := modelcatalog.Model{Selector: choice}
	if index >= 0 {
		model = models[index]
	} else if len(models) > 0 && w.prompt != nil {
		w.say("    Note: %s is not in the list above; it will be used exactly as typed.", choice)
	}
	if initSmallModel(model) {
		w.say("    %s Warning: %s looks like a small model (7B parameters or fewer). Small models miss real problems and report false ones; expect weak reviews.", w.wait, choice)
	}
	w.models[flagName] = []modelcatalog.Model{model}
	return choice, nil
}

const initModelListLimit = 40

// chooseModel shows the list and asks one question: a number picks from the
// list shown, a listed ID picks that model, and other text narrows the list
// to the IDs that contain it. Text that matches nothing, typed twice in a
// row, is used exactly as typed.
func (w *initWizard) chooseModel(question string, models []modelcatalog.Model, keep string, validate func(string) (string, error)) (string, error) {
	shown, filter, unmatched, show := models, "", "", true
	for tries := 0; tries < initMaxTries; {
		listed := shown[:min(len(shown), initModelListLimit)]
		if show {
			if filter == "" {
				w.say("\n  %s", question)
			} else {
				w.say("\n  Models whose ID contains %q:", filter)
			}
			for i, model := range listed {
				w.say("    %2d) %s%s", i+1, model.Selector, initModelNote(model))
			}
			if more := len(shown) - len(listed); more > 0 && filter != "" {
				w.say("    ... %d more match; type more of the name, or an exact ID.", more)
			} else if more > 0 {
				w.say("    ... %d more; type part of a name to narrow the list.", more)
			}
			show = false
		}
		answer, err := w.prompt.ask("Number, model ID, or part of a name", keep, func(value string) (string, error) { return value, nil })
		if err != nil || answer == keep {
			return answer, err
		}
		if n, err := strconv.Atoi(answer); err == nil {
			if n < 1 || n > len(listed) {
				w.say("    Please type a number from 1 to %d, a model ID, or part of a name.", len(listed))
				tries++
				continue
			}
			answer = listed[n-1].Selector
		} else if answer != unmatched && !slices.ContainsFunc(models, func(m modelcatalog.Model) bool { return m.Selector == answer }) {
			if matches := initMatchModels(models, answer); len(matches) != 0 {
				shown, filter, unmatched, show = matches, answer, "", true
				continue
			}
			if _, err := validate(answer); err != nil {
				w.say("    %s", err.Error())
			} else {
				w.say("    No listed model contains %q. Type a shorter part of the name, or type %s again to use it exactly as typed.", answer, answer)
				unmatched = answer
			}
			tries++
			continue
		}
		value, err := validate(answer)
		if err == nil {
			return value, nil
		}
		w.say("    %s", err.Error())
		tries++
	}
	return "", errInitTooManyTries
}

// initMatchModels returns the models whose ID contains text: an exact ID
// first, then the same name under another vendor prefix, then names that
// start with the text; otherwise the catalog order is kept.
func initMatchModels(models []modelcatalog.Model, text string) []modelcatalog.Model {
	needle := strings.ToLower(text)
	matches := []modelcatalog.Model{}
	for _, model := range models {
		if strings.Contains(strings.ToLower(model.Selector), needle) {
			matches = append(matches, model)
		}
	}
	rank := func(model modelcatalog.Model) int {
		selector := strings.ToLower(model.Selector)
		_, name, _ := strings.Cut(selector, "/")
		switch {
		case selector == needle:
			return 0
		case name == needle:
			return 1
		case strings.HasPrefix(selector, needle) || strings.HasPrefix(name, needle):
			return 2
		}
		return 3
	}
	slices.SortStableFunc(matches, func(x, y modelcatalog.Model) int { return rank(x) - rank(y) })
	return matches
}

func initMetadataNumber(metadata json.RawMessage, keys ...string) uint64 {
	var fields map[string]json.RawMessage
	if json.Unmarshal(metadata, &fields) != nil {
		return 0
	}
	for _, key := range keys {
		var n uint64
		if raw, ok := fields[key]; ok && json.Unmarshal(raw, &n) == nil && n > 0 {
			return n
		}
	}
	if raw, ok := fields["top_provider"]; ok {
		return initMetadataNumber(raw, keys...)
	}
	return 0
}

func (w *initWizard) localEndpoint(flagName, question, proposed string) (string, error) {
	validate := func(value string) (string, error) {
		value = strings.TrimRight(value, "/")
		parsed, err := url.Parse(value)
		if err == nil && (parsed.Hostname() == "localhost" || strings.HasSuffix(parsed.Hostname(), ".localhost")) {
			return "", errors.New("Use the numeric address 127.0.0.1 instead of localhost (names are not trusted for local servers).")
		}
		locality, err := provider.ClassifyServiceEndpoint(value)
		if err != nil || locality != provider.ServiceEndpointLoopback {
			return "", errors.New("Type the server's API address on this machine, such as http://127.0.0.1:11434/v1 (127.0.0.1 or [::1] only).")
		}
		return value, nil
	}
	if _, given := w.flags[flagName]; given || w.prompt == nil || proposed != "" {
		return w.answer(initQuestion{flag: flagName, question: question, proposed: proposed, acceptProposal: proposed != "", validate: validate})
	}
	servers := []initLocalServer{}
	for _, server := range initLocalServers {
		servers = append(servers, initLocalServer{name: server.name, endpoint: server.endpoint})
	}
	if found := w.detectLocalServers(); len(found) == 1 {
		w.say("  %s Found %s at %s.", w.ok, found[0].name, found[0].endpoint)
		return found[0].endpoint, nil
	} else if len(found) > 1 {
		servers = found
	}
	options := []string{}
	for _, server := range servers {
		options = append(options, fmt.Sprintf("%-10s %s", server.name, server.endpoint))
	}
	options = append(options, "Another address on this machine")
	w.say("  %s", question)
	index, err := w.prompt.choose("Which server are you running?", options)
	if err != nil {
		return "", err
	}
	if index < len(servers) {
		return servers[index].endpoint, nil
	}
	return w.prompt.ask("Server API address", "", validate)
}

// initLocalServer is a known local model server and the models it lists.
type initLocalServer struct {
	name, endpoint string
	models         []modelcatalog.Model
}

// initDetectLocalServers reads each known local server's model list once (a
// bounded GET to a loopback address; no model request) and returns those that
// list a model. Tests replace it so they never reach a real local server.
var initDetectLocalServers = func(ctx context.Context) []initLocalServer {
	found := []initLocalServer{}
	for _, server := range initLocalServers {
		models, err := initListModels(ctx, modelcatalog.Source{ID: "local-server", Kind: "openai_models", URL: server.endpoint + "/models"}, false, nil)
		if err == nil && len(models) > 0 {
			found = append(found, initLocalServer{name: server.name, endpoint: server.endpoint, models: models})
		}
	}
	return found
}

// detectLocalServers returns the answering servers not already chosen and
// remembers their model lists, so they are not read twice.
func (w *initWizard) detectLocalServers() []initLocalServer {
	found := []initLocalServer{}
	for _, server := range initDetectLocalServers(w.ctx) {
		if server.endpoint == w.a.generationEndpoint {
			continue
		}
		if w.listed == nil {
			w.listed = map[string][]modelcatalog.Model{}
		}
		w.listed[server.endpoint] = server.models
		found = append(found, server)
	}
	return found
}

// probeLocal reads the server's model list: one bounded GET to a loopback
// address through the existing catalog fetch. No model request is made.
func (w *initWizard) probeLocal(endpoint string) ([]modelcatalog.Model, error) {
	if w.prompt == nil {
		return nil, nil
	}
	if models, ok := w.listed[endpoint]; ok {
		w.say("  %s Found %d model%s.", w.ok, len(models), initPlural(len(models)))
		return models, nil
	}
	for {
		w.say("  Reading the model list from %s/models ...", endpoint)
		models, err := initListModels(w.ctx, modelcatalog.Source{ID: "local-server", Kind: "openai_models", URL: endpoint + "/models"}, false, nil)
		if err == nil && len(models) > 0 {
			w.say("  %s Found %d model%s.", w.ok, len(models), initPlural(len(models)))
			if w.listed == nil {
				w.listed = map[string][]modelcatalog.Model{}
			}
			w.listed[endpoint] = models
			return models, nil
		}
		reason := "it answered, but listed no models"
		if err != nil {
			reason = "no usable answer (is the server running and listening on that port?)"
		}
		w.say("  %s Could not read the model list: %s.", w.wait, reason)
		again, err := w.prompt.confirm("Try again?", true)
		if err != nil {
			return nil, err
		}
		if !again {
			w.say("  You can still type the exact model ID yourself.")
			return nil, nil
		}
	}
}

func (w *initWizard) localModels() error {
	if w.prompt != nil {
		w.say("  Note: local models are only as good as their size allows. Models with 7B parameters or fewer give weak reviews; larger models need more memory.")
	}
	var err error
	if w.a.generationEndpoint, err = w.localEndpoint("endpoint", "Where is the finder model's server?", ""); err != nil {
		return err
	}
	generation, err := w.probeLocal(w.a.generationEndpoint)
	if err != nil {
		return err
	}
	w.modelEndpoint = w.a.generationEndpoint
	if w.a.generationModel, err = w.pickModel("generation-model", "Finder model: looks for problems in your change", generation, "", ""); err != nil {
		return err
	}
	_, flagged := w.flags["verification-endpoint"]
	sameServer := !flagged
	if w.prompt != nil && !flagged && len(generation) == 1 {
		w.say("\n  This server offers one model. llama.cpp and vLLM usually run the second model as a separate server on another port, such as http://127.0.0.1:8081/v1.")
		sameServer = false
	}
	verification := generation
	if sameServer {
		w.a.verificationEndpoint = w.a.generationEndpoint
	} else {
		if w.a.verificationEndpoint, err = w.localEndpoint("verification-endpoint", "Where is the checker model's server?", ""); err != nil {
			return err
		}
		if verification, err = w.probeLocal(w.a.verificationEndpoint); err != nil {
			return err
		}
	}
	w.modelEndpoint = w.a.verificationEndpoint
	if w.a.verificationModel, err = w.pickChecker(verification); err != nil {
		return err
	}
	w.a.transport = "openai_chat_completions"
	if raw, ok := w.flags["transport"]; ok {
		if raw != "openai_chat_completions" && raw != "openai_responses" {
			return initStopf(initExitUsage, "--transport must be openai_chat_completions or openai_responses.")
		}
		w.a.transport = raw
	}
	return nil
}

// initLocalContextTokens is the context the named local runtime examples declare
// and start their servers with (docs/named-local-runtimes.md#context-length).
const initLocalContextTokens = 32768

// initContextProposal returns the proposed context for listed, the smaller
// context both models' metadata states, or 0 when unstated. A local server is
// proposed the examples' context and never more than its listed value: a
// listed model length does not show the server was started with it, and a
// declaration above the server's setting would let an over-long prompt be
// truncated.
func initContextProposal(provider string, listed uint64) uint64 {
	if provider != "local" {
		return listed
	}
	if listed == 0 {
		return initLocalContextTokens
	}
	return min(listed, initLocalContextTokens)
}

func (w *initWizard) capacities() error {
	// Propose the smaller listed value only when both models' metadata states it.
	contextProposal, outputProposal := uint64(1<<63), uint64(1<<63)
	for _, role := range []string{"generation-model", "verification-model"} {
		var c, o uint64
		for _, model := range w.models[role] {
			c = initMetadataNumber(model.Metadata, "context_length", "context_window", "max_context_length", "max_model_len")
			o = initMetadataNumber(model.Metadata, "max_completion_tokens", "max_output_tokens")
		}
		contextProposal, outputProposal = min(contextProposal, c), min(outputProposal, o)
	}
	if contextProposal == 1<<63 {
		contextProposal = 0
	}
	if outputProposal == 1<<63 {
		outputProposal = 0
	}
	listed := contextProposal
	contextProposal = initContextProposal(w.a.provider.key, listed)
	if w.a.provider.key == "local" && outputProposal == 0 {
		// A review writes at most 4096 tokens, which every local model with the
		// proposed context can.
		outputProposal = remoteReviewMaxOutputTokens
	}
	_, contextGiven := w.flags["context-tokens"]
	_, outputGiven := w.flags["output-tokens"]
	if outputProposal > contextProposal {
		outputProposal = contextProposal
	}
	if !contextGiven && !outputGiven && contextProposal >= 8192 && outputProposal >= remoteReviewMaxOutputTokens {
		w.a.contextTokens, w.a.outputTokens = strconv.FormatUint(contextProposal, 10), strconv.FormatUint(outputProposal, 10)
		source := "from the model list"
		if w.a.provider.key == "local" {
			source = "start both servers with this context length (llama.cpp --ctx-size, Ollama OLLAMA_CONTEXT_LENGTH, vLLM --max-model-len, LM Studio --context-length; docs/named-local-runtimes.md#context-length)"
		}
		w.say("\n  Limits: context %s and output %s tokens; %s.", w.a.contextTokens, w.a.outputTokens, source)
		return nil
	}
	if w.prompt != nil {
		w.say("\n  Model capacity. Check each model's page (or your server's settings) and give the smaller of the two values. A review reads up to the context and writes up to 4096 tokens, so models must support at least 8192 and 4096.")
		if w.a.provider.key == "local" {
			w.say("  Start both servers with the same context length you give here (llama.cpp --ctx-size, Ollama OLLAMA_CONTEXT_LENGTH, vLLM --max-model-len, LM Studio --context-length). Reviews reserve input by bytes, so 32768 is proposed; see docs/named-local-runtimes.md#context-length.")
		} else if contextProposal > 0 {
			w.say("  The value in brackets comes from the model list you just read.")
		}
	}
	proposal := func(n uint64) string {
		if n == 0 {
			return ""
		}
		return strconv.FormatUint(n, 10)
	}
	var err error
	w.a.contextTokens, err = w.answer(initQuestion{flag: "context-tokens", question: "Context window in tokens (how much each model can read)", proposed: proposal(contextProposal), validate: initTokens(8192, 1<<31, "The context must be at least 8192 tokens.")})
	if err != nil || w.a.contextTokens == "" {
		if _, given := w.flags["output-tokens"]; err == nil && !given && w.prompt == nil {
			w.missing = append(w.missing, "--output-tokens")
		}
		return err
	}
	limit, _ := strconv.ParseUint(w.a.contextTokens, 10, 64)
	if outputProposal > limit {
		outputProposal = limit
	}
	w.a.outputTokens, err = w.answer(initQuestion{flag: "output-tokens", question: "Output limit in tokens (how much each model can write)", proposed: proposal(outputProposal), validate: initTokens(4096, limit, fmt.Sprintf("The output limit must be from 4096 to %d tokens (the context).", limit))})
	return err
}

func initTokens(minimum, maximum uint64, message string) func(string) (string, error) {
	return func(value string) (string, error) {
		n, err := strconv.ParseUint(strings.ReplaceAll(value, ",", ""), 10, 64)
		if err != nil || n < minimum || n > maximum {
			return "", errors.New(message + " Type a whole number.")
		}
		return strconv.FormatUint(n, 10), nil
	}
}

func (w *initWizard) prices() error {
	flagged := false
	for _, name := range []string{"input-micro-usd-per-million-tokens", "output-micro-usd-per-million-tokens", "max-cost-micro-usd"} {
		_, given := w.flags[name]
		flagged = flagged || given
	}
	perToken := true
	if !flagged && w.prompt != nil {
		w.say("")
		if w.a.provider.key != "openrouter" {
			var err error
			if perToken, err = w.prompt.confirm("Does your "+w.a.provider.short+" plan charge per token?", false); err != nil {
				return err
			}
			if !perToken {
				w.say("  Recording zero per-token prices and a zero cost limit. Plan quotas still apply and are not checked by Open Trestle.")
				w.a.inputPrice, w.a.outputPrice, w.a.maxCost = "0", "0", "0"
				return nil
			}
		}
		w.say("  Give prices in US dollars per million tokens. Use the higher of the two models.")
	}
	var err error
	if w.a.inputPrice, err = w.answer(initQuestion{flag: "input-micro-usd-per-million-tokens", question: "Input price, USD per million tokens", validate: initUSD, validateFlag: initMicro}); err != nil {
		return err
	}
	if w.a.outputPrice, err = w.answer(initQuestion{flag: "output-micro-usd-per-million-tokens", question: "Output price, USD per million tokens", validate: initUSD, validateFlag: initMicro}); err != nil || w.a.outputPrice == "" || w.a.inputPrice == "" {
		return err
	}
	return w.costLimit()
}

// costLimit sets the per-request cost bound, max_cost_micro_usd: every model
// request reserves its worst case against it, and a review sends two (the
// finder's and the checker's), so a review costs at most twice the bound. It
// is not asked: setup writes the cost of one request that fills the whole
// context and writes the full output allowance, rounded up to a cent, and
// the summary shows it. --max-cost-micro-usd sets another bound, for CI and
// advanced use. Spending over time is limited per key instead (spendingLimit).
func (w *initWizard) costLimit() error {
	input, _ := strconv.ParseUint(w.a.inputPrice, 10, 64)
	output, _ := strconv.ParseUint(w.a.outputPrice, 10, 64)
	contextTokens, _ := strconv.ParseUint(w.a.contextTokens, 10, 64)
	reviewOutput := w.reviewOutputTokens()
	reservation := (reviewOutput*output + 999_999) / 1_000_000
	full := reservation + (contextTokens*input+999_999)/1_000_000
	if raw, given := w.flags["max-cost-micro-usd"]; given {
		micro, err := initMicro(raw)
		if err != nil {
			return initStopf(initExitUsage, "--max-cost-micro-usd: %v", err)
		}
		n, _ := strconv.ParseUint(micro, 10, 64)
		if n < reservation || input+output > 0 && n == 0 {
			return initStopf(initExitUsage, "--max-cost-micro-usd: the bound must be at least %s to cover the %d-token answer.", initFormatUSD(max(reservation, 1)), reviewOutput)
		}
		w.a.maxCost = micro
		return nil
	}
	cents := (full + 9_999) / 10_000 * 10_000
	w.a.maxCost = strconv.FormatUint(max(cents, reservation), 10)
	return nil
}

func initMicro(value string) (string, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n > 1<<40 {
		return "", errors.New("give a whole number of micro-US-dollars (1 USD = 1000000)")
	}
	return strconv.FormatUint(n, 10), nil
}

// initUSD parses dollars (at most six decimals) into integer micro-USD. A value
// given through a *-micro-usd flag is already micro-USD and reaches here only
// interactively, so flags are checked separately in initValidMicro.
func initUSD(value string) (string, error) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "$")
	whole, fraction, _ := strings.Cut(value, ".")
	if whole == "" {
		whole = "0"
	}
	if len(fraction) > 6 || strings.Trim(whole, "0123456789") != "" || strings.Trim(fraction, "0123456789") != "" || len(whole) > 9 {
		return "", errors.New("Type an amount in US dollars, such as 3 or 0.15.")
	}
	fraction += strings.Repeat("0", 6-len(fraction))
	n, err := strconv.ParseUint(whole+fraction, 10, 64)
	if err != nil {
		return "", errors.New("Type an amount in US dollars, such as 3 or 0.15.")
	}
	return strconv.FormatUint(n, 10), nil
}

func initFormatUSD(micro uint64) string {
	// Whole cents at least ($0.10, $3.30), with more digits only when the
	// amount has them ($0.048692).
	text := strings.TrimRight(fmt.Sprintf("$%d.%06d", micro/1_000_000, micro%1_000_000), "0")
	if _, decimals, _ := strings.Cut(text, "."); len(decimals) < 2 {
		text += strings.Repeat("0", 2-len(decimals))
	}
	return text
}

func initCredentialName(value string) (string, error) {
	if remoteCredentialEnvironmentError("credential-env", value) == nil {
		return value, nil
	}
	if strings.ContainsFunc(value, unicode.IsLower) || strings.ContainsAny(value, "-./+=") || len(value) > 40 {
		return "", errors.New("That looks like a key, not a variable name. Never type the key itself here; type a name such as OPEN_TRESTLE_PROVIDER_OPENROUTER.")
	}
	return "", errors.New("The name must start with OPEN_TRESTLE_PROVIDER_ and use only capital letters, digits and _.")
}

// stepCredentials names the key variable. The provider's usual name is used
// unless --credential-env names another. When that variable has no key yet
// and standard input is a terminal, the key is asked for with hidden input
// (askProviderKey); it is never shown. A local server needs no key when both
// model lists were read without one; otherwise the operator says whether it
// does.
func (w *initWizard) stepCredentials() error {
	if w.a.provider.key == ollamaSigninProvider {
		w.say("  No API key: your local Ollama sends requests to Ollama Cloud with the account it is signed in to (`ollama signin`). Open Trestle stores and sends no key.")
		return nil
	}
	if w.a.provider.key == "local" {
		if _, given := w.flags["credential-env"]; !given {
			_, generationListed := w.listed[w.a.generationEndpoint]
			_, verificationListed := w.listed[w.a.verificationEndpoint]
			needs := false
			if !generationListed || !verificationListed {
				var err error
				if needs, err = w.confirm("Does your local server require an API key?", false, false); err != nil {
					return err
				}
			}
			if !needs {
				w.say("  No key: requests to your local server are sent without one.")
				return nil
			}
		}
	}
	proposal := w.a.provider.credentialProposal
	if proposal == "" {
		proposal = "OPEN_TRESTLE_PROVIDER_LOCAL"
	}
	w.a.credentialEnv = proposal
	if raw, ok := w.flags["credential-env"]; ok {
		name, err := initCredentialName(raw)
		if err != nil {
			return initStopf(initExitUsage, "--credential-env: %v", err)
		}
		w.a.credentialEnv = name
	}
	if err := w.askProviderKey(w.a.credentialEnv, w.a.provider.key, w.a.provider.short, false); err != nil {
		return err
	}
	return w.spendingLimit()
}

// stepDeclarations collects the declarations the summary confirms, after any
// evidence they need.
func (w *initWizard) stepDeclarations() error {
	w.header(4, "Your settings and consent")
	a := &w.a
	if a.provider.key == "openrouter" {
		w.openRouterConsent()
		return nil
	}
	capacity := func() string {
		return fmt.Sprintf("accept %s tokens of input and write up to %s tokens of output", a.contextTokens, a.outputTokens)
	}
	if a.provider.key == "local" {
		w.declare("declare-local-capabilities", "your local models", "docs/local-first-bootstrap.md#choose-the-repository-and-model-pair", func() []string {
			return []string{
				"both models run entirely on this machine; the server is not relaying them to a cloud service",
				"they " + capacity(),
				"they return structured JSON output",
				"the server does not log your content and costs nothing per request",
				"both models are loaded and available now",
			}
		})
		return nil
	}
	w.declare("declare-remote-route", "the two model routes", "docs/remote-model-review.md#common-declarations", func() []string {
		input, _ := strconv.ParseUint(a.inputPrice, 10, 64)
		output, _ := strconv.ParseUint(a.outputPrice, 10, 64)
		facts := []string{}
		if a.provider.key != ollamaSigninProvider {
			facts = append(facts, "each review sends the selected source, after secret scanning, to "+a.provider.short+" for "+a.generationModel+" and "+a.verificationModel)
		}
		return append(facts,
			"both models "+capacity(),
			"they return structured JSON output",
			"you use them with content logging turned off",
			fmt.Sprintf("they cost no more than %s (input) and %s (output) per million tokens", initFormatUSD(input), initFormatUSD(output)),
			"both models are available to your account now",
		)
	})
	switch a.provider.key {
	case "opencode-go":
		return w.openCodeGoDeclarations()
	case ollamaSigninProvider:
		w.declare("declare-ollama-cloud-signin", "sending your source to Ollama Cloud through your signed-in Ollama", "docs/remote-model-review.md#ollama-signed-in-to-ollama-cloud", func() []string {
			return []string{
				"Ollama at " + a.generationEndpoint + " is signed in (`ollama signin`) to an Ollama account you control",
				"each review sends the selected source, after secret scanning, from that Ollama to Ollama Cloud (https://ollama.com) under that account, so it leaves this machine",
				"both models are Ollama Cloud models; they do not run on this machine",
				"their use counts against that account's Ollama Cloud plan; Open Trestle records no retention or zero-data promise for Ollama Cloud (read https://docs.ollama.com/cloud)",
			}
		})
		return nil
	default:
		w.say("\n  Ollama Cloud: Open Trestle records no retention or zero-data promise for this provider. Read Ollama's current privacy terms and your plan before you send private source (https://docs.ollama.com/cloud).")
		return nil
	}
}

// initEvidence describes one evidence answer the wizard asks for.
type initEvidence struct {
	flag, description string
	proposedURL       string // a public page the profile documentation cites, or ""
	reuse             string // an earlier "URL,SHA256" answer that also covers this item
	reuseLabel        string
	account           bool // the operator's own account review: never fetched
}

func (w *initWizard) evidenceItem(item initEvidence) (string, error) {
	check := func(value string) error {
		_, err := remoteParseEvidence(item.flag, value, "2000-01-01T00:00:00Z")
		return err
	}
	if raw, ok := w.flags[item.flag]; ok {
		if err := check(raw); err != nil {
			return "", initStopf(initExitUsage, "%v", err)
		}
		return raw, nil
	}
	if w.prompt == nil {
		w.missing = append(w.missing, "--"+item.flag)
		return "", nil
	}
	w.say("\n  Evidence: %s", item.description)
	if item.reuse != "" {
		location, digest, _ := strings.Cut(item.reuse, ",")
		w.say("    The %s uses the same provider, so its evidence applies here too:", item.reuseLabel)
		w.say("      %s", location)
		w.say("      SHA-256 %s", digest)
		same, err := w.prompt.confirm("Use the same evidence?", true)
		if err != nil || same {
			return item.reuse, err
		}
	}
	if item.proposedURL != "" {
		w.say("    Proposed: the page the profile documentation cites for this. Press Enter to use it, or type the address of the page you actually reviewed.")
	}
	if item.account {
		w.say("    This is your own account page, so it is never fetched: save a copy of it (for example print it to PDF) and give the address you read plus that file's path.")
	}
	location, err := w.prompt.ask("Web address you read (https://...)", item.proposedURL, func(value string) (string, error) {
		if check(value+","+strings.Repeat("ab", 32)) != nil {
			return "", errors.New("Use an https:// address with no ?query, #fragment or user name in it.")
		}
		return value, nil
	})
	if err != nil {
		return "", err
	}
	if !item.account {
		recorded, digest, err := w.offerFetch(location)
		if err != nil || digest != "" {
			return recorded + "," + digest, err
		}
	}
	digest, err := w.prompt.ask("SHA-256 of the copy you saved, or that file's path (computed here)", "", initEvidenceDigest)
	if err != nil {
		return "", err
	}
	return location + "," + digest, nil
}

// offerFetch offers one bounded, credential-free GET of a public page and shows
// the SHA-256 computed here for confirmation. An empty digest means the operator
// gives a digest or saved copy instead.
func (w *initWizard) offerFetch(location string) (string, string, error) {
	if cached, ok := w.fetched[location]; ok {
		w.say("    Already fetched during this setup: SHA-256 %s", cached.digest)
		return cached.url, cached.digest, nil
	}
	if initPublicEvidenceURL(location) != nil {
		return "", "", nil
	}
	fetch, err := w.prompt.confirm("Fetch this public page now and compute its SHA-256 here?", true)
	if err != nil || !fetch {
		return "", "", err
	}
	host, _ := url.Parse(location)
	w.say("    Fetching from %s (no key, cookie or code is sent; at most 8 MiB, 20 seconds) ...", host.Host)
	got, err := initFetchEvidence(w.ctx, location)
	if err != nil {
		w.say("    %s Could not fetch it: %v.", w.wait, err)
		w.say("    Give the SHA-256 of a copy you saved, or that file's path, instead.")
		return "", "", nil
	}
	w.lastFetch = w.clock.Now().UTC().Truncate(time.Second)
	if got.url != location {
		w.say("    The address redirected to %s; that address is recorded.", got.url)
	}
	w.say("    %s Read %d bytes. SHA-256 of exactly that content:", w.ok, got.size)
	w.say("      %s", got.digest)
	w.say("    The digest records which version you reviewed. Read the page there if you have not.")
	use, err := w.prompt.confirm("Record this address and SHA-256?", true)
	if err != nil || !use {
		return "", "", err
	}
	w.fetched[location] = got
	return got.url, got.digest, nil
}

// initEvidenceDigest accepts a SHA-256 or hashes a saved local copy. It reads
// only the named regular file and never fetches anything.
func initEvidenceDigest(value string) (string, error) {
	lower := strings.ToLower(value)
	if len(lower) == 64 && strings.Trim(lower, "0123456789abcdef") == "" {
		if lower == strings.Repeat("0", 64) {
			return "", errors.New("That digest is all zeros; use the SHA-256 of the saved copy.")
		}
		return lower, nil
	}
	path, err := initValidateDirectory(value)
	if err != nil {
		return "", errors.New("Type a 64-character SHA-256 (from sha256sum) or the path to the saved file.")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("Could not open that file. Type its path or its 64-character SHA-256.")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
		return "", errors.New("That is not a regular file of at most 256 MiB.")
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", errors.New("Could not read that file.")
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func (w *initWizard) reviewWindow() ([]string, string, error) {
	now := w.clock.Now().UTC().Truncate(time.Second)
	canonical := func(value string) (string, error) {
		if strings.EqualFold(value, "now") {
			return now.Format(time.RFC3339), nil
		}
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
			return "", errors.New("Use UTC like 2026-11-07T10:00:00Z, or type now.")
		}
		if parsed.After(now) {
			return "", errors.New("That time is in the future; use when you actually reviewed the evidence.")
		}
		if !w.lastFetch.IsZero() && parsed.Before(w.lastFetch) {
			return "", fmt.Errorf("Evidence was fetched at %s; your review cannot be earlier. Type now or a later time.", w.lastFetch.Format(time.RFC3339))
		}
		return value, nil
	}
	if w.prompt != nil {
		w.say("\n  Review window. Remote reviews are refused outside the window you declare, so you review the provider's terms and your account again when it ends.")
	}
	reviewed, err := w.answer(initQuestion{flag: "reviewed-at", question: "When did you review the evidence and your account (UTC, or now)", proposed: "now", validate: canonical})
	if err != nil {
		return nil, "", err
	}
	retrieved, validFrom := reviewed, reviewed
	if w.prompt == nil {
		if retrieved, err = w.answer(initQuestion{flag: "evidence-retrieved-at", validate: canonical}); err != nil {
			return nil, "", err
		}
		if validFrom, err = w.answer(initQuestion{flag: "valid-from", validate: func(v string) (string, error) {
			parsed, err := time.Parse(time.RFC3339, v)
			if err != nil || parsed.Format(time.RFC3339) != v || parsed.Location() != time.UTC {
				return "", errors.New("use a canonical UTC time such as 2026-11-07T10:00:00Z")
			}
			return v, nil
		}}); err != nil {
			return nil, "", err
		}
	} else {
		for _, name := range []string{"evidence-retrieved-at", "valid-from"} {
			if raw, ok := w.flags[name]; ok {
				if name == "valid-from" {
					validFrom = raw
				} else {
					retrieved = raw
				}
			}
		}
	}
	reviewedTime, parseErr := time.Parse(time.RFC3339, reviewed)
	if parseErr != nil && w.prompt != nil {
		return nil, "", parseErr
	}
	var until string
	if raw, ok := w.flags["valid-until"]; ok {
		until = raw
	} else if w.prompt == nil {
		w.missing = append(w.missing, "--valid-until")
	} else {
		days, err := w.prompt.ask("How many days should this review stay valid (1-365)", "30", func(value string) (string, error) {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 365 {
				return "", errors.New("Type a whole number of days from 1 to 365.")
			}
			return value, nil
		})
		if err != nil {
			return nil, "", err
		}
		n, _ := strconv.Atoi(days)
		until = reviewedTime.Add(time.Duration(n) * 24 * time.Hour).Format(time.RFC3339)
	}
	window := []string{"--evidence-retrieved-at", retrieved, "--reviewed-at", reviewed, "--valid-from", validFrom, "--valid-until", until}
	fact := fmt.Sprintf("you retrieved and reviewed this evidence at %s, and the review is valid from %s until %s", reviewed, validFrom, until)
	return window, fact, nil
}

func (w *initWizard) witnessIntro(provider string) {
	if w.prompt == nil {
		return
	}
	w.say("\n  %s needs a record of what you reviewed. For each item, give the web address you read and a SHA-256 of that exact content. For a public page, Open Trestle can fetch it once and compute the SHA-256 here (you confirm it). Otherwise give the SHA-256 of a copy you saved, or that file's path. Your account page is never fetched.", provider)
}

func (w *initWizard) openCodeGoDeclarations() error {
	w.witnessIntro("OpenCode Go")
	extra := []string{}
	items := []initEvidence{
		{flag: "broker-evidence", description: "OpenCode Go's documentation of its service privacy scope"},
		{flag: "account-evidence", description: "your review of the actual Go workspace that owns this key (a public page is not an account review)", account: true},
		{flag: "generation-model-evidence", description: "the finder model's documented zero-day retention and no-training terms"},
		{flag: "verification-model-evidence", description: "the checker model's documented zero-day retention and no-training terms"},
	}
	for _, item := range items {
		value, err := w.evidenceItem(item)
		if err != nil {
			return err
		}
		extra = append(extra, "--"+item.flag, value)
	}
	window, windowFact, err := w.reviewWindow()
	if err != nil {
		return err
	}
	extra = append(extra, window...)
	w.a.extra = extra
	w.declare("declare-opencode-go-account", "your OpenCode Go workspace privacy", "docs/remote-model-review.md#opencode-go and docs/opencode-go-profile.md", func() []string {
		return []string{
			"the key belongs to a Go workspace with exactly one member",
			"privacy training and extra usage are turned off in that workspace",
			"both models' documentation states zero-day retention and no training",
			windowFact,
		}
	})
	return nil
}

func initLabel(value, fallback string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	label := strings.Trim(b.String(), "-_.")
	if len(label) > 48 {
		label = strings.Trim(label[:48], "-_.")
	}
	if label == "" {
		return fallback
	}
	return label
}

func initValidLabel(value string) (string, error) {
	if initLabel(value, "") != value {
		return "", errors.New("Use lowercase letters, digits, - _ and . only, starting and ending with a letter or digit.")
	}
	return value, nil
}

func (w *initWizard) setLabels(values map[string]string) error {
	a := &w.a
	a.owner, a.tenant, a.repository = values["owner"], values["tenant"], values["repository"]
	a.authority, a.namespace, a.name = values["repository-authority"], values["repository-namespace"], values["repository-name"]
	if _, err := evidence.NewRepositoryIdentity(a.authority, strings.Split(a.namespace, "/"), a.name); err != nil {
		return initStopf(initExitUsage, "the repository host label, namespace or name is not valid: %v", err)
	}
	return nil
}

const initDisplayPathLimit = 44

// initDisplayPath shortens a path for reading only: the home folder becomes ~,
// and a path still longer than about 60 characters keeps its start and end
// around "...". Commands, flags and saved files always keep full paths.
func initDisplayPath(path string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "/" && strings.HasPrefix(path, home+string(filepath.Separator)) {
		path = "~" + path[len(home):]
	}
	runes := []rune(path)
	if len(runes) <= initDisplayPathLimit {
		return path
	}
	head, tail := runes[:22], runes[len(runes)-(initDisplayPathLimit-25):]
	for i := len(head) - 1; i > 1; i-- {
		if head[i] == filepath.Separator {
			head = head[:i+1]
			break
		}
	}
	for i := 0; i < len(tail)-1; i++ {
		if tail[i] == filepath.Separator {
			tail = tail[i+1:]
			break
		}
	}
	return string(head) + "..." + string(filepath.Separator) + string(tail)
}

func initShort(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

func initPlural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func initRoleName(role string) string {
	if role == "generation" {
		return "finder"
	}
	return "checker"
}
