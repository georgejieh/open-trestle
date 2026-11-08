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

var localReviewGenerationSanitizer review.GenerationRequestSanitizer
var localReviewVerificationSanitizer review.VerificationRequestSanitizer

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
	format := values["--format"]
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "text" && format != "sarif" {
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
	if checkout {
		o.objectStoreProfile = scm.LocalGitObjectStoreProfileLooseAndPackIndexV1
	}
	return o, repository, base, head, nil
}
func runLocalGitModelReview(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	options, repository, base, head, err := parseLocalModelReview(args)
	if err != nil {
		var unknownProfile errUnknownModelReviewProfile
		if errors.As(err, &unknownProfile) {
			fmt.Fprintln(stderr, unknownProfile.Error())
		}
		writeLocalGitModelReviewUsage(stderr)
		return 2
	}
	unstarted := func(status string) int {
		result, err := localreview.NewUnstartedSpecialistResult(status, options.objectStoreProfile, options.specialist)
		if err != nil {
			return 1
		}
		return writeLocalModelResultWithPolicy(options.format, options.exitPolicy, result, stdout, stderr)
	}
	if ctx == nil {
		if options.specialists.active() {
			return runLocalModelReviewSet(nil, nil, options, localModelReviewInputs{}, "failed", stdout, stderr)
		}
		return unstarted("failed")
	}
	if ctx.Err() != nil {
		if options.specialists.active() {
			return runLocalModelReviewSet(ctx, ctx, options, localModelReviewInputs{}, "canceled", stdout, stderr)
		}
		return unstarted("canceled")
	}
	execution, cancel := context.WithTimeout(ctx, options.timeout)
	defer cancel()
	inputs, status := prepareLocalModelReview(execution, &options, repository, base, head, stderr)
	if options.specialists.active() {
		return runLocalModelReviewSet(ctx, execution, options, inputs, status, stdout, stderr)
	}
	if status != "" {
		return unstarted(status)
	}
	member, ok := runLocalModelReviewMember(ctx, execution, options, inputs, options.specialist, false)
	if !ok {
		return 1
	}
	if member.partialCheckout {
		fmt.Fprintln(stderr, partialCheckoutHint)
	}
	return writeLocalModelResultWithPolicy(options.format, options.exitPolicy, member.result, stdout, stderr)
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
	return inputs, ""
}

// localModelReviewMember is one terminal review run of an invocation.
type localModelReviewMember struct {
	specialist      review.ContextSpecialist
	result          localreview.Result
	features        agentprofile.ChangeFeatures
	hasFeatures     bool
	partialCheckout bool
}

// runLocalModelReviewMember runs one review session to a terminal result under
// execution. It owns and closes its own objects root and session. ok is false
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
	base, head := inputs.base, inputs.head
	objects, err := os.OpenRoot(options.objects)
	if err != nil {
		return unstarted("incomplete")
	}
	credentials, err := runtimecatalog.NewEnvironmentOpenAICredentialResolver(os.Getenv)
	if err != nil {
		_ = objects.Close()
		return unstarted("failed")
	}
	sessionOptions := localreview.SessionOptions{TenantID: options.tenant, RepositoryID: options.repository, Repository: inputs.repository, ObjectsRoot: objects, ObjectStoreProfile: options.objectStoreProfile, Inventory: inputs.inventory, Policy: inputs.policy, Egress: options.egress, Credentials: credentials, Clock: localReviewClock{}, Timeout: options.timeout, RetainedMemoryInput: inputs.retainedInput, GenerationSanitizer: localReviewGenerationSanitizer, VerificationSanitizer: localReviewVerificationSanitizer}
	if options.egress == localreview.EgressPolicyApproved {
		sessionOptions.ModelHTTPClient, sessionOptions.ModelHTTPClientIdentity = localReviewModelHTTPClient, localReviewModelHTTPClientIdentity
	}
	if options.objectStoreProfile == scm.LocalGitObjectStoreProfileLooseAndPackIndexV1 {
		sessionOptions.ObjectAlgorithm = base.Algorithm()
	}
	var session *localreview.Session
	if options.investigation != "" {
		session, err = localreview.NewInvestigationSession(sessionOptions, inputs.investigationPolicy)
	} else if !specialist.IsZero() {
		session, err = localreview.NewSpecialistSession(sessionOptions, specialist)
	} else {
		session, err = localreview.NewSession(sessionOptions)
	}
	if err != nil {
		if closeErr := objects.Close(); closeErr != nil {
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
		return session.Close(cleanup)
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
	if wantFeatures && runErr == nil && execution.Err() == nil {
		// Read-only replay of this run's own recorded artifacts; no model call.
		if features, err := session.ChangeFeatures(execution, prepared); err == nil {
			member.features, member.hasFeatures = features, true
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
		return member, true
	}
	member.result = result
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
	var err error
	if format == "text" {
		err = localreview.RenderResult(stdout, result)
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
	fmt.Fprintln(stderr, "usage: trestle local-git model-review --objects-root PATH --repository-authority AUTHORITY --repository-namespace SEGMENT[/SEGMENT...] --repository-name NAME --revision-algorithm sha1|sha256 --base-revision-digest HEX --head-revision-digest HEX --tenant ID --repository ID --route-inventory PATH --runtime-policy PATH --egress local-only|policy-approved --timeout DURATION [--object-store loose-only|loose-and-pack-index-v1] [--format json|text|sarif] [--exit-code-policy default|findings|strict|always-zero] [--investigation-policy PATH | --retained-memory-input PATH] [--profile PROFILE_ID | --specialists auto|none|ID[,ID...] [--max-specialists N]]")
	fmt.Fprintln(stderr, "       checkout source alternative: --checkout PATH --base FULL_REF_OR_COMMIT --head FULL_REF_OR_COMMIT (replaces --objects-root and revision flags)")
}
