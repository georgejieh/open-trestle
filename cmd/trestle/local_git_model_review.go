package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/agentprofile"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/internal/secretscan"
	"github.com/georgejieh/open-trestle/localreview"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type localModelReviewOptions struct {
	objects, inventory, policy, tenant, repository, format string
	checkout, baseSelection, headSelection                 string
	investigation, retainedMemory                          string
	egress                                                 localreview.Egress
	objectStoreProfile                                     scm.LocalGitObjectStoreProfile
	timeout                                                time.Duration
	specialist                                             review.ContextSpecialist
	exitPolicy                                             localreview.ExitPolicy
	// specialists is the multi-specialist request; its zero value (mode none)
	// keeps the single-run path and output unchanged.
	specialists specialistRequest
	// all lists every confirmed finding in text and Markdown output (--all);
	// by default only high, critical and medium findings are listed.
	all bool
	// verbose adds the internal tokens to text output (--verbose).
	verbose bool
	// repositoryChecks runs the repository's own checks in the sandbox
	// before the model calls (--repository-checks); it is the caller's
	// consent.
	repositoryChecks bool
	// modelChecks asks the checker for tests of its verified findings and runs
	// them after the review (--model-checks); it needs repositoryChecks.
	modelChecks bool
}

// renderOptions are the text and Markdown options the flags select.
func (o localModelReviewOptions) renderOptions() localreview.RenderOptions {
	return localreview.RenderOptions{All: o.all, Verbose: o.verbose}
}

// errUnknownModelReviewProfile is a usage error for a --profile (or --specialists)
// value that is not a packaged model-calling specialist profile.
type errUnknownModelReviewProfile struct{ value, flag string }

func (e errUnknownModelReviewProfile) Error() string {
	flag := e.flag
	if flag == "" {
		flag = "--profile"
	}
	return fmt.Sprintf("unknown %s %q; valid profile ids: %s", flag, e.value, strings.Join(review.ContextSpecialistProfileIDs(), ", "))
}

// Tests replace the sanitizers with fakes; production leaves both nil, and
// each review member then scans through a scan helper session of its own.
var localReviewGenerationSanitizer review.GenerationRequestSanitizer
var localReviewVerificationSanitizer review.VerificationRequestSanitizer

// localReviewScanner prepares this program's scan helper for one invocation
// and returns the opener of each member's session. Tests replace it.
var localReviewScanner = func(ctx context.Context, stderr io.Writer) (secretscan.ReviewSessionOpener, error) {
	config, err := secretscan.InstalledConfig(os.Getenv)
	if err != nil {
		return nil, err
	}
	return prepareReviewScanner(ctx, stderr, config)
}

// prepareReviewScanner fills the helper's cache on first use, with a notice,
// and returns the opener of a session with config.
func prepareReviewScanner(ctx context.Context, stderr io.Writer, config secretscan.SessionConfig) (secretscan.ReviewSessionOpener, error) {
	announce := func() {
		fmt.Fprintln(stderr, "Preparing the secret scanner for first use; this can take a minute.")
		reviewProgressOf(ctx).begin("Preparing the secret scanner", true)
	}
	err := secretscan.PrepareCache(ctx, config, announce)
	reviewProgressOf(ctx).end()
	if err != nil {
		return nil, err
	}
	return config.Opener(), nil
}

// reportScanner says why a review sent nothing because its scanner failed.
func reportScanner(stderr io.Writer, err error) {
	fmt.Fprintf(stderr, "trestle: the secret scanner is not available, so nothing was sent to a model: %v\n", err)
}

// Tests replace the policy-approved model transport with an offline fake. Production
// leaves both empty, so the adapter uses its default bounded HTTPS client.
var localReviewModelHTTPClient *http.Client
var localReviewModelHTTPClientIdentity string

type localReviewClock struct{}

func (localReviewClock) Now() time.Time { return time.Now().UTC() }
func parseLocalModelReview(args []string) (localModelReviewOptions, evidence.RepositoryIdentity, evidence.RevisionIdentity, evidence.RevisionIdentity, error) {
	var o localModelReviewOptions
	fail := func() (localModelReviewOptions, evidence.RepositoryIdentity, evidence.RevisionIdentity, evidence.RevisionIdentity, error) {
		return o, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("invalid explicit model review intent")
	}
	// --all, --verbose, --repository-checks and --model-checks are the flags
	// without a value.
	// They are recognized only where a flag is expected, so a flag's value is
	// never taken for one.
	all, verbose, checks, modelChecks := false, false, false, false
	pairs := make([]string, 0, len(args))
	for index := 0; index < len(args); {
		if args[index] == "--all" || args[index] == "--verbose" || args[index] == "--repository-checks" || args[index] == "--model-checks" {
			seen := map[string]*bool{"--all": &all, "--verbose": &verbose, "--repository-checks": &checks, "--model-checks": &modelChecks}[args[index]]
			if *seen {
				return fail()
			}
			*seen, index = true, index+1
			continue
		}
		if index+1 >= len(args) {
			return fail()
		}
		pairs, index = append(pairs, args[index], args[index+1]), index+2
	}
	args = pairs
	sourceFlags := []string{"--objects-root", "--repository-authority", "--repository-namespace", "--repository-name", "--revision-algorithm", "--base-revision-digest", "--head-revision-digest"}
	allowed := map[string]bool{"--tenant": true, "--repository": true, "--route-inventory": true, "--runtime-policy": true, "--investigation-policy": true, "--retained-memory-input": true, "--egress": true, "--timeout": true, "--format": true, "--object-store": true, "--profile": true, "--exit-code-policy": true, "--specialists": true, "--max-specialists": true}
	for _, flag := range sourceFlags {
		allowed[flag] = true
	}
	allowed["--checkout"], allowed["--base"], allowed["--head"] = true, true, true
	if len(args) < 24 || len(args) > 40 || len(args)%2 != 0 {
		return fail()
	}
	values := map[string]string{}
	for i := 0; i < len(args); i += 2 {
		flag, value := args[i], args[i+1]
		if !allowed[flag] || value == "" || len(value) > 4096 || values[flag] != "" {
			return fail()
		}
		values[flag] = value
	}
	checkout := values["--checkout"] != ""
	if checkout {
		for _, flag := range []string{"--objects-root", "--revision-algorithm", "--base-revision-digest", "--head-revision-digest", "--object-store"} {
			if values[flag] != "" {
				return fail()
			}
		}
		if !checkoutSelection.MatchString(values["--base"]) || !checkoutSelection.MatchString(values["--head"]) {
			return fail()
		}
	} else if values["--base"] != "" || values["--head"] != "" {
		return fail()
	}
	for flag := range allowed {
		if checkout && (flag == "--objects-root" || flag == "--revision-algorithm" || flag == "--base-revision-digest" || flag == "--head-revision-digest") || !checkout && (flag == "--checkout" || flag == "--base" || flag == "--head") {
			continue
		}
		if flag != "--format" && flag != "--investigation-policy" && flag != "--retained-memory-input" && flag != "--object-store" && flag != "--profile" && flag != "--exit-code-policy" && flag != "--specialists" && flag != "--max-specialists" && values[flag] == "" {
			return fail()
		}
	}
	var source localGitChangeOptions
	var repository evidence.RepositoryIdentity
	var base, head evidence.RevisionIdentity
	var err error
	if checkout {
		repository, err = evidence.NewRepositoryIdentity(values["--repository-authority"], strings.Split(values["--repository-namespace"], "/"), values["--repository-name"])
	} else {
		sourceArgs := []string{}
		for _, flag := range sourceFlags {
			sourceArgs = append(sourceArgs, flag, values[flag])
		}
		source, repository, base, head, err = parseLocalGitChangeOptions(sourceArgs)
		if base.Identity() == head.Identity() {
			return fail()
		}
	}
	if err != nil {
		return fail()
	}
	if _, err := audit.NewReviewScope(values["--tenant"], values["--repository"], "intent-validation"); err != nil {
		return fail()
	}
	timeout, err := time.ParseDuration(values["--timeout"])
	if err != nil || timeout < time.Second || timeout > 15*time.Minute {
		return fail()
	}
	egress := localreview.Egress(values["--egress"])
	if egress != localreview.EgressLocalOnly && egress != localreview.EgressPolicyApproved {
		return fail()
	}
	if values["--retained-memory-input"] != "" && (values["--investigation-policy"] != "" || egress != localreview.EgressLocalOnly) {
		return fail()
	}
	// Investigation requests are not secret-scanned, so they stay on this
	// machine.
	if values["--investigation-policy"] != "" && egress != localreview.EgressLocalOnly {
		return fail()
	}
	format := values["--format"]
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "text" && format != "sarif" && format != "markdown" {
		return fail()
	}
	exitPolicy := localreview.ExitPolicyDefault
	if value := values["--exit-code-policy"]; value != "" {
		var ok bool
		if exitPolicy, ok = localreview.ParseExitPolicy(value); !ok {
			return fail()
		}
	}
	objectStoreProfile := scm.LocalGitObjectStoreProfile(values["--object-store"])
	if objectStoreProfile != "" && objectStoreProfile != scm.LocalGitObjectStoreProfileLooseOnly && objectStoreProfile != scm.LocalGitObjectStoreProfileLooseAndPackIndexV1 {
		return fail()
	}
	var specialist review.ContextSpecialist
	if profileID := values["--profile"]; profileID != "" {
		// A specialist applies to the direct generation request only; the
		// investigation pipeline has its own context contract.
		if values["--investigation-policy"] != "" {
			return fail()
		}
		specialist, err = review.NewContextSpecialist(profileID)
		if err != nil {
			return o, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, evidence.RevisionIdentity{}, errUnknownModelReviewProfile{value: profileID}
		}
	}
	var specialists specialistRequest
	if values["--specialists"] != "" || values["--max-specialists"] != "" {
		// --profile is the single-specialist form; the set applies to the direct
		// generation path only, like --profile.
		if values["--profile"] != "" || values["--investigation-policy"] != "" {
			return fail()
		}
		specialists, err = parseSpecialistRequest(values["--specialists"], values["--max-specialists"])
		if err != nil {
			var unknownProfile errUnknownModelReviewProfile
			if errors.As(err, &unknownProfile) {
				return o, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, evidence.RevisionIdentity{}, err
			}
			return fail()
		}
	}
	o = localModelReviewOptions{objects: source.objectsRoot, inventory: values["--route-inventory"], policy: values["--runtime-policy"], tenant: values["--tenant"], repository: values["--repository"], format: format, investigation: values["--investigation-policy"], retainedMemory: values["--retained-memory-input"], egress: egress, objectStoreProfile: objectStoreProfile, timeout: timeout, specialist: specialist, exitPolicy: exitPolicy, specialists: specialists}
	o.checkout, o.baseSelection, o.headSelection = values["--checkout"], values["--base"], values["--head"]
	o.all, o.verbose, o.repositoryChecks, o.modelChecks = all, verbose, checks, modelChecks
	if modelChecks && !checks {
		return o, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, evidence.RevisionIdentity{}, errModelChecksNeedChecks
	}
	// An investigation session takes no repository check outcomes.
	if checks && o.investigation != "" {
		return fail()
	}
	if checkout {
		o.objectStoreProfile = scm.LocalGitObjectStoreProfileLooseAndPackIndexV1
	}
	return o, repository, base, head, nil
}

// errModelChecksNeedChecks is the usage error of --model-checks without the
// repository checks.
var errModelChecksNeedChecks = errors.New("--model-checks needs the repository checks: pass --repository-checks too, so the checker writes tests only where the repository's own tests ran")

func runLocalGitModelReview(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runLocalGitModelReviewObserved(ctx, args, stdout, stderr, nil)
}

// modelReviewOutcome is what a finished review tells an in-process caller,
// such as `trestle review`: the result status and the number of confirmed
// findings. It carries no source, prompt or model reply.
type modelReviewOutcome struct {
	status   string
	findings int
	// advisory is set for a review with findings none of which blocks CI:
	// each is low severity or pre-existing (ci_disposition inconclusive).
	advisory bool
	// regressions counts the tests the repository's own checks proved
	// broken.
	regressions int
	// view is the result as a person reads it on a terminal.
	view *reviewView
	// unfinished names each reviewer of a set that ran but did not finish,
	// with its failure.
	unfinished []string
}

// advisoryOutcomeNote follows the finished-review line of an advisory review.
const advisoryOutcomeNote = " None of them blocks CI: each is low severity or on lines the change did not touch."

// observeModelResult reports a single run's result to observe, when set.
func observeModelResult(observe func(modelReviewOutcome), result localreview.Result) {
	if observe == nil {
		return
	}
	if report, err := result.Report(); err == nil {
		outcome := modelReviewOutcome{status: report.Status, findings: len(report.Findings), advisory: report.Status == "findings" && report.CIDisposition == "inconclusive", view: singleReviewView(report)}
		if report.CheckRegressions != nil {
			outcome.regressions = report.CheckRegressions.Count
		}
		observe(outcome)
	}
}

// runLocalGitModelReviewObserved is `trestle local-git model-review`; observe,
// when set, receives the outcome just before the result is written.
func runLocalGitModelReviewObserved(ctx context.Context, args []string, stdout, stderr io.Writer, observe func(modelReviewOutcome)) int {
	options, repository, base, head, err := parseLocalModelReview(args)
	if err != nil {
		var unknownProfile errUnknownModelReviewProfile
		if errors.As(err, &unknownProfile) {
			fmt.Fprintln(stderr, unknownProfile.Error())
		}
		if errors.Is(err, errModelChecksNeedChecks) {
			fmt.Fprintln(stderr, err.Error())
		}
		writeLocalGitModelReviewUsage(stderr)
		return 2
	}
	// Check regressions are reported whatever the model review did, so every
	// result takes the ones that ran.
	var checks *review.CheckRuns
	unstarted := func(status string) int {
		result, err := localreview.NewUnstartedSpecialistResult(status, options.objectStoreProfile, options.specialist)
		if err != nil {
			return 1
		}
		result = localreview.WithCheckRegressions(result, checks)
		observeModelResult(observe, result)
		return writeLocalModelResultWithOptions(options.format, options.exitPolicy, options.renderOptions(), result, stdout, stderr)
	}
	if ctx == nil {
		if options.specialists.active() {
			return runLocalModelReviewSet(nil, nil, options, localModelReviewInputs{}, "failed", stdout, stderr, observe)
		}
		return unstarted("failed")
	}
	if ctx.Err() != nil {
		if options.specialists.active() {
			return runLocalModelReviewSet(ctx, ctx, options, localModelReviewInputs{}, "canceled", stdout, stderr, observe)
		}
		return unstarted("canceled")
	}
	// A caller that supplies progress owns it; otherwise it lasts for this run,
	// and standard output stops it before the first byte of the result.
	if reviewProgressOf(ctx) == nil {
		if progress := startReviewProgress(stderr); progress != nil {
			defer progress.stop()
			ctx = withReviewProgress(ctx, progress)
			stdout, stderr = stopWriter{progress, stdout}, progressWriter{progress, stderr}
		}
	}
	execution, cancel := context.WithTimeout(ctx, options.timeout)
	defer cancel()
	inputs, status := prepareLocalModelReview(execution, &options, repository, base, head, stderr)
	defer inputs.index.close()
	checks = inputs.checks
	if status == "" {
		inputs.spending = newReviewSpending(inputs, options, stderr)
	}
	if options.specialists.active() {
		return runLocalModelReviewSet(ctx, execution, options, inputs, status, stdout, stderr, observe)
	}
	if status != "" {
		return unstarted(status)
	}
	member, ok := runLocalModelReviewMember(ctx, execution, options, inputs, options.specialist, false)
	if !ok {
		return 1
	}
	result := localreview.WithCheckRegressions(member.result, checks)
	if options.modelChecks {
		pending, dropped := pendingModelChecks(member.result, member.authored)
		result = localreview.WithModelWrittenChecks(result, runModelWrittenChecks(ctx, options.objects, inputs.base, inputs.head, pending, dropped+member.authoredDropped, stderr))
	}
	reviewProgressOf(ctx).finish()
	if member.partialCheckout {
		fmt.Fprintln(stderr, partialCheckoutHint)
	}
	inputs.spending.finish()
	observeModelResult(observe, result)
	return writeLocalModelResultWithOptions(options.format, options.exitPolicy, options.renderOptions(), result, stdout, stderr)
}

// localModelReviewInputs is the protected configuration and pinned revisions
// that every member of one invocation shares.
type localModelReviewInputs struct {
	inventory           runtimeconfig.RouteInventory
	policy              runtimeconfig.RuntimePolicy
	investigationPolicy review.InvestigationPolicy
	retainedInput       *runtimeconfig.RetainedMemoryInput
	repository          evidence.RepositoryIdentity
	base, head          evidence.RevisionIdentity
	// spending checks and records the spend of each member run; nil when no
	// route uses an API key.
	spending *reviewSpending
	// index is the repository index the review reads context from; nil for
	// an investigation or when the objects have no usable index.
	index *reviewIndexContext
	// checks are the repository's check runs, or nil when none ran.
	checks *review.CheckRuns
	// scanner opens each member's scan helper session; nil only when tests
	// replace the sanitizers.
	scanner secretscan.ReviewSessionOpener
}

// prepareLocalModelReview loads protected configuration and resolves the source
// before any session exists. A non-empty status is the unstarted result status.
func prepareLocalModelReview(execution context.Context, options *localModelReviewOptions, repository evidence.RepositoryIdentity, base, head evidence.RevisionIdentity, stderr io.Writer) (localModelReviewInputs, string) {
	inputs := localModelReviewInputs{repository: repository}
	inventory, policy, err := runtimeconfig.LoadProtectedConfiguration(execution, options.inventory, options.policy)
	if err != nil {
		if execution.Err() != nil {
			return inputs, "canceled"
		}
		return inputs, "refused"
	}
	if execution.Err() != nil {
		return inputs, "canceled"
	}
	inputs.inventory, inputs.policy = inventory, policy
	if options.investigation != "" {
		inputs.investigationPolicy, err = runtimeconfig.LoadProtectedInvestigationPolicy(execution, options.investigation)
		if err != nil || inputs.investigationPolicy.ValidateRuntimeBudget(policy.Budget()) != nil {
			if execution.Err() != nil {
				return inputs, "canceled"
			}
			return inputs, "refused"
		}
		if execution.Err() != nil {
			return inputs, "canceled"
		}
	}
	if options.checkout != "" {
		source, err := resolveLocalCheckout(execution, options.checkout, options.baseSelection, options.headSelection)
		if err != nil {
			if execution.Err() != nil {
				return inputs, "canceled"
			}
			var unavailable errCheckoutCommitUnavailable
			if errors.As(err, &unavailable) {
				fmt.Fprintln(stderr, unavailable.hint())
			}
			return inputs, "incomplete"
		}
		options.objects = source.objects
		base, err = evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithm(source.algorithm), source.base)
		if err != nil {
			return inputs, "incomplete"
		}
		head, err = evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithm(source.algorithm), source.head)
		if err != nil {
			return inputs, "incomplete"
		}
	}
	inputs.base, inputs.head = base, head
	if options.investigation == "" {
		inputs.index = prepareReviewIndex(execution, openReviewIndexSession(execution, *options, base), base, head, stderr)
	}
	if options.repositoryChecks && options.objects != "" {
		inputs.checks = runRepositoryChecks(execution, options.objects, base, head, inputs.index, options.modelChecks, stderr)
		if execution.Err() != nil {
			return inputs, "canceled"
		}
	}
	if options.retainedMemory != "" {
		scope, scopeErr := memory.NewScope(options.tenant, options.repository, "local-reviewer", memory.RefVisibilityExact, head.Identity(), []string{"."})
		if scopeErr != nil {
			if execution.Err() != nil {
				return inputs, "canceled"
			}
			return inputs, "refused"
		}
		input, loadErr := runtimeconfig.LoadProtectedRetainedMemoryInput(execution, options.retainedMemory, scope, repository, policy, localReviewClock{}.Now())
		if execution.Err() != nil {
			return inputs, "canceled"
		}
		if loadErr != nil {
			return inputs, "refused"
		}
		inputs.retainedInput = &input
	}
	if localReviewGenerationSanitizer == nil || localReviewVerificationSanitizer == nil {
		opener, err := localReviewScanner(execution, stderr)
		if err != nil {
			if execution.Err() != nil {
				return inputs, "canceled"
			}
			reportScanner(stderr, err)
			return inputs, "refused"
		}
		inputs.scanner = func(ctx context.Context) (secretscan.ReviewSession, error) {
			session, err := opener(ctx)
			if err != nil && ctx.Err() == nil {
				reportScanner(stderr, err)
			}
			return session, err
		}
	}
	return inputs, ""
}

// localModelReviewMember is one terminal review run of an invocation.
type localModelReviewMember struct {
	specialist      review.ContextSpecialist
	result          localreview.Result
	features        agentprofile.ChangeFeatures
	hasFeatures     bool
	partialCheckout bool
	// styleConfigUnread counts base style configuration files the features
	// could not carry.
	styleConfigUnread int
	// authored are the checks its checker wrote, and authoredDropped those it
	// dropped.
	authored        []review.AuthoredCheck
	authoredDropped int
}

// runLocalModelReviewMember runs one review session to a terminal result under
// execution. It owns and closes its own objects root, scan helper session and
// review session; the scan session opens first and closes last, and a scan
// session that fails at its close fails the member. ok is false
// only when not even an unstarted result could be constructed. When
// wantFeatures is set, the change features are read back from the run's own
// recorded change and analysis artifacts before the session closes.
func runLocalModelReviewMember(ctx, execution context.Context, options localModelReviewOptions, inputs localModelReviewInputs, specialist review.ContextSpecialist, wantFeatures bool) (localModelReviewMember, bool) {
	member := localModelReviewMember{specialist: specialist}
	unstarted := func(status string) (localModelReviewMember, bool) {
		result, err := localreview.NewUnstartedSpecialistResult(status, options.objectStoreProfile, specialist)
		if err != nil {
			return member, false
		}
		member.result = result
		return member, true
	}
	// A key at or over its spending limit refuses the run here, before the
	// objects root is opened, any credential is read or any request is sent.
	if inputs.spending.refuse() {
		result, err := localreview.NewSpendingLimitRefusalResult(options.objectStoreProfile, specialist)
		if err != nil {
			return member, false
		}
		member.result = result
		return member, true
	}
	base, head := inputs.base, inputs.head
	objects, err := os.OpenRoot(options.objects)
	if err != nil {
		return unstarted("incomplete")
	}
	credentials, err := runtimecatalog.NewEnvironmentOpenAICredentialResolver(localReviewCredentialLookup)
	if err != nil {
		_ = objects.Close()
		return unstarted("failed")
	}
	var scan secretscan.ReviewSession
	if inputs.scanner != nil {
		if scan, err = inputs.scanner(execution); err != nil {
			_ = objects.Close()
			if execution.Err() != nil {
				return unstarted("canceled")
			}
			return unstarted("refused")
		}
	}
	closeScan := func() error {
		if scan == nil {
			return nil
		}
		return scan.Close()
	}
	sessionOptions := localreview.SessionOptions{TenantID: options.tenant, RepositoryID: options.repository, Repository: inputs.repository, ObjectsRoot: objects, ObjectStoreProfile: options.objectStoreProfile, Inventory: inputs.inventory, Policy: inputs.policy, Egress: options.egress, Credentials: credentials, Clock: localReviewClock{}, Timeout: options.timeout, RetainedMemoryInput: inputs.retainedInput, CheckRuns: inputs.checks, Scanner: scan, GenerationSanitizer: localReviewGenerationSanitizer, VerificationSanitizer: localReviewVerificationSanitizer, AnswerRetry: inputs.spending.allowAnswerRetry}
	if options.egress == localreview.EgressPolicyApproved {
		sessionOptions.ModelHTTPClient, sessionOptions.ModelHTTPClientIdentity = localReviewModelHTTPClient, localReviewModelHTTPClientIdentity
	}
	if inputs.index != nil {
		sessionOptions.IndexContext = inputs.index
	}
	if options.objectStoreProfile == scm.LocalGitObjectStoreProfileLooseAndPackIndexV1 {
		sessionOptions.ObjectAlgorithm = base.Algorithm()
	}
	name := ""
	if options.specialists.active() {
		name = memberLabel(specialist)
	}
	progress := reviewProgressOf(ctx)
	progress.startMember(name)
	sessionOptions.Progress = progress.memberEvents()
	var session *localreview.Session
	if options.investigation != "" {
		session, err = localreview.NewInvestigationSession(sessionOptions, inputs.investigationPolicy)
	} else if !specialist.IsZero() {
		session, err = localreview.NewSpecialistSession(sessionOptions, specialist)
	} else {
		session, err = localreview.NewSession(sessionOptions)
	}
	if err != nil {
		if closeErr := errors.Join(objects.Close(), closeScan()); closeErr != nil {
			return unstarted("failed")
		}
		if execution.Err() != nil {
			return unstarted("canceled")
		}
		if errors.Is(err, localreview.ErrUnsupportedSource) {
			return unstarted("incomplete")
		}
		return unstarted("refused")
	}
	closeSession := func() error {
		cleanup, stop := context.WithTimeout(context.Background(), localModelCleanupTimeout(options.timeout))
		defer stop()
		return errors.Join(session.Close(cleanup), closeScan())
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		_ = closeSession()
		return unstarted("failed")
	}
	hostID := hex.EncodeToString(nonce)
	scope, err := audit.NewReviewScope(options.tenant, options.repository, "local-"+hostID)
	if err != nil {
		_ = closeSession()
		return unstarted("failed")
	}
	prepared, err := session.Prepare(execution, scope, hostID, base, head)
	if err != nil {
		if closeSession() != nil {
			return unstarted("failed")
		}
		if execution.Err() != nil {
			return unstarted("canceled")
		}
		return unstarted("refused")
	}
	result, runErr := session.Run(execution, prepared)
	member.authored, member.authoredDropped = session.AuthoredChecks()
	if wantFeatures && runErr == nil && execution.Err() == nil {
		// Read-only replay of this run's own recorded artifacts; no model call.
		if features, unread, err := session.ChangeFeatures(execution, prepared); err == nil {
			member.features, member.hasFeatures, member.styleConfigUnread = features, true, len(unread)
		}
	}
	// Render normal journal/artifact readback only after safe closure. On failure,
	// emit only an unknown-state error, not a false claim that no work started.
	// Drain failure retains ownership; there is no reaper.
	closeErr := closeSession()
	if options.checkout != "" && result.CIDisposition() == "inconclusive" && runErr == nil && result.IncompleteSourceRead() && checkoutIsPartialClone(ctx, options.checkout) {
		member.partialCheckout = true
	}
	if runErr != nil || closeErr != nil {
		member.result = session.FailureResult()
	} else {
		member.result = result
	}
	// The ledger entry uses the result's settled cost when its usage is known,
	// and otherwise the requests the session saw sent, at their reservation.
	inputs.spending.record(scope.ReviewRunID(), member.result, session.SpendObservation())
	return member, true
}
func localModelCleanupTimeout(configured time.Duration) time.Duration {
	if configured < 3*time.Second {
		return 3 * time.Second
	}
	return configured
}
func writeLocalModelResult(format string, result localreview.Result, stdout, stderr io.Writer) int {
	return writeLocalModelResultWithPolicy(format, localreview.ExitPolicyDefault, result, stdout, stderr)
}
func writeLocalModelResultWithPolicy(format string, policy localreview.ExitPolicy, result localreview.Result, stdout, stderr io.Writer) int {
	return writeLocalModelResultWithOptions(format, policy, localreview.RenderOptions{}, result, stdout, stderr)
}

// writeLocalModelResultWithOptions writes one result in format (json, text,
// sarif or markdown); options apply to text and Markdown.
func writeLocalModelResultWithOptions(format string, policy localreview.ExitPolicy, options localreview.RenderOptions, result localreview.Result, stdout, stderr io.Writer) int {
	var err error
	if format == "text" {
		err = localreview.RenderResultWithOptions(stdout, result, options)
	} else if format == "markdown" {
		err = localreview.RenderResultMarkdown(stdout, result, options)
	} else {
		var encoded []byte
		if format == "sarif" {
			encoded, err = encodeModelReviewSARIF(result)
		} else {
			encoded, err = localreview.EncodeResult(result)
		}
		if err == nil {
			var n int
			n, err = stdout.Write(encoded)
			if err == nil && n != len(encoded) {
				err = io.ErrShortWrite
			}
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "write result: failed")
		return 1
	}
	return result.ExitCodeFor(policy)
}
func writeLocalGitModelReviewUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle local-git model-review --objects-root PATH --repository-authority AUTHORITY --repository-namespace SEGMENT[/SEGMENT...] --repository-name NAME --revision-algorithm sha1|sha256 --base-revision-digest HEX --head-revision-digest HEX --tenant ID --repository ID --route-inventory PATH --runtime-policy PATH --egress local-only|policy-approved --timeout DURATION [--object-store loose-only|loose-and-pack-index-v1] [--format json|text|sarif|markdown] [--all] [--verbose] [--repository-checks [--model-checks]] [--exit-code-policy default|findings|strict|always-zero] [--investigation-policy PATH | --retained-memory-input PATH] [--profile PROFILE_ID | --specialists auto|none|ID[,ID...] [--max-specialists N]]")
	fmt.Fprintln(stderr, "       checkout source alternative: --checkout PATH --base FULL_REF_OR_COMMIT --head FULL_REF_OR_COMMIT (replaces --objects-root and revision flags)")
	fmt.Fprintln(stderr, "       --repository-checks runs the repository's own tests for the change in a sandbox first and gives the outcomes to the models; a test regression is reported and blocks even without them; see docs/repository-checks.md")
	fmt.Fprintln(stderr, "       --model-checks also asks the checker to write a test for each of up to 3 verified findings and keeps those that pass on base and fail on head; they never change the status")
}
