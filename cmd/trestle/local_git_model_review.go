package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/localreview"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"io"
	"os"
	"time"
)

type localModelReviewOptions struct {
	objects, inventory, policy, tenant, repository, format string
	investigation, retainedMemory                          string
	egress                                                 localreview.Egress
	objectStoreProfile                                     scm.LocalGitObjectStoreProfile
	timeout                                                time.Duration
}
type localReviewClock struct{}

func (localReviewClock) Now() time.Time { return time.Now().UTC() }
func parseLocalModelReview(args []string) (localModelReviewOptions, evidence.RepositoryIdentity, evidence.RevisionIdentity, evidence.RevisionIdentity, error) {
	var o localModelReviewOptions
	fail := func() (localModelReviewOptions, evidence.RepositoryIdentity, evidence.RevisionIdentity, evidence.RevisionIdentity, error) {
		return o, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("invalid explicit model review intent")
	}
	sourceFlags := []string{"--objects-root", "--repository-authority", "--repository-namespace", "--repository-name", "--revision-algorithm", "--base-revision-digest", "--head-revision-digest"}
	allowed := map[string]bool{"--tenant": true, "--repository": true, "--route-inventory": true, "--runtime-policy": true, "--investigation-policy": true, "--retained-memory-input": true, "--egress": true, "--timeout": true, "--format": true, "--object-store": true}
	for _, flag := range sourceFlags {
		allowed[flag] = true
	}
	if len(args) < 26 || len(args) > 32 || len(args)%2 != 0 {
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
	for flag := range allowed {
		if flag != "--format" && flag != "--investigation-policy" && flag != "--retained-memory-input" && flag != "--object-store" && values[flag] == "" {
			return fail()
		}
	}
	sourceArgs := []string{}
	for _, flag := range sourceFlags {
		sourceArgs = append(sourceArgs, flag, values[flag])
	}
	source, repository, base, head, err := parseLocalGitChangeOptions(sourceArgs)
	if err != nil || base.Identity() == head.Identity() {
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
	if format != "json" && format != "text" {
		return fail()
	}
	objectStoreProfile := scm.LocalGitObjectStoreProfile(values["--object-store"])
	if objectStoreProfile != "" && objectStoreProfile != scm.LocalGitObjectStoreProfileLooseOnly && objectStoreProfile != scm.LocalGitObjectStoreProfileLooseAndPackIndexV1 {
		return fail()
	}
	o = localModelReviewOptions{objects: source.objectsRoot, inventory: values["--route-inventory"], policy: values["--runtime-policy"], tenant: values["--tenant"], repository: values["--repository"], format: format, investigation: values["--investigation-policy"], retainedMemory: values["--retained-memory-input"], egress: egress, objectStoreProfile: objectStoreProfile, timeout: timeout}
	return o, repository, base, head, nil
}
func runLocalGitModelReview(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	options, repository, base, head, err := parseLocalModelReview(args)
	if err != nil {
		writeLocalGitModelReviewUsage(stderr)
		return 2
	}
	unstarted := func(status string) int {
		result, err := localreview.NewUnstartedResultWithObjectStoreProfile(status, options.objectStoreProfile)
		if err != nil {
			return 1
		}
		return writeLocalModelResult(options.format, result, stdout, stderr)
	}
	if ctx == nil {
		return unstarted("failed")
	}
	if ctx.Err() != nil {
		return unstarted("canceled")
	}
	execution, cancel := context.WithTimeout(ctx, options.timeout)
	defer cancel()
	inventory, policy, err := runtimeconfig.LoadProtectedConfiguration(execution, options.inventory, options.policy)
	if err != nil {
		if execution.Err() != nil {
			return unstarted("canceled")
		}
		return unstarted("refused")
	}
	if execution.Err() != nil {
		return unstarted("canceled")
	}
	var investigationPolicy review.InvestigationPolicy
	if options.investigation != "" {
		investigationPolicy, err = runtimeconfig.LoadProtectedInvestigationPolicy(execution, options.investigation)
		if err != nil || investigationPolicy.ValidateRuntimeBudget(policy.Budget()) != nil {
			if execution.Err() != nil {
				return unstarted("canceled")
			}
			return unstarted("refused")
		}
		if execution.Err() != nil {
			return unstarted("canceled")
		}
	}
	var retainedInput *runtimeconfig.RetainedMemoryInput
	if options.retainedMemory != "" {
		scope, scopeErr := memory.NewScope(options.tenant, options.repository, "local-reviewer", memory.RefVisibilityExact, head.Identity(), []string{"."})
		if scopeErr != nil {
			if execution.Err() != nil {
				return unstarted("canceled")
			}
			return unstarted("refused")
		}
		input, loadErr := runtimeconfig.LoadProtectedRetainedMemoryInput(execution, options.retainedMemory, scope, repository, policy, localReviewClock{}.Now())
		if execution.Err() != nil {
			return unstarted("canceled")
		}
		if loadErr != nil {
			return unstarted("refused")
		}
		retainedInput = &input
	}
	objects, err := os.OpenRoot(options.objects)
	if err != nil {
		return unstarted("incomplete")
	}
	credentials, err := runtimecatalog.NewEnvironmentOpenAICredentialResolver(os.Getenv)
	if err != nil {
		_ = objects.Close()
		return unstarted("failed")
	}
	sessionOptions := localreview.SessionOptions{TenantID: options.tenant, RepositoryID: options.repository, Repository: repository, ObjectsRoot: objects, ObjectStoreProfile: options.objectStoreProfile, Inventory: inventory, Policy: policy, Egress: options.egress, Credentials: credentials, Clock: localReviewClock{}, Timeout: options.timeout, RetainedMemoryInput: retainedInput}
	if options.objectStoreProfile == scm.LocalGitObjectStoreProfileLooseAndPackIndexV1 {
		sessionOptions.ObjectAlgorithm = base.Algorithm()
	}
	var session *localreview.Session
	if options.investigation != "" {
		session, err = localreview.NewInvestigationSession(sessionOptions, investigationPolicy)
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
	// Render normal journal/artifact readback only after safe closure. On failure,
	// emit only an unknown-state error, not a false claim that no work started.
	// Drain failure retains ownership; there is no reaper.
	closeErr := closeSession()
	if runErr != nil || closeErr != nil {
		return writeLocalModelResult(options.format, session.FailureResult(), stdout, stderr)
	}
	return writeLocalModelResult(options.format, result, stdout, stderr)
}
func localModelCleanupTimeout(configured time.Duration) time.Duration {
	if configured < 3*time.Second {
		return 3 * time.Second
	}
	return configured
}
func writeLocalModelResult(format string, result localreview.Result, stdout, stderr io.Writer) int {
	var err error
	if format == "text" {
		err = localreview.RenderResult(stdout, result)
	} else {
		var encoded []byte
		encoded, err = localreview.EncodeResult(result)
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
	return result.ExitCode()
}
func writeLocalGitModelReviewUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle local-git model-review --objects-root PATH --repository-authority AUTHORITY --repository-namespace SEGMENT[/SEGMENT...] --repository-name NAME --revision-algorithm sha1|sha256 --base-revision-digest HEX --head-revision-digest HEX --tenant ID --repository ID --route-inventory PATH --runtime-policy PATH --egress local-only|policy-approved --timeout DURATION [--object-store loose-only|loose-and-pack-index-v1] [--format json|text] [--investigation-policy PATH | --retained-memory-input PATH]")
}
