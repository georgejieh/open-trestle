package runtimecatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"time"
)

var ErrInvalidPreparedReview = errors.New("invalid prepared local review")

type PreparedReviewRequestOptions struct {
	Scope                                                                              audit.ReviewScope
	HostRequestIdentity                                                                string
	Repository                                                                         evidence.RepositoryIdentity
	BaseRevision, HeadRevision                                                         evidence.RevisionIdentity
	SourceAdapter                                                                      evidence.SourceAdapterIdentity
	SourceRootIdentity, InventoryIdentity, RuntimePolicyIdentity, ReviewPolicyIdentity string
	Classification                                                                     artifact.Classification
	Protection                                                                         artifact.Protection
	CreatedAt                                                                          time.Time
	Retention                                                                          time.Duration
	Catalog                                                                            PipelineCatalog
}
type PreparedReviewRequest struct {
	options  PreparedReviewRequestOptions
	identity string
}
type PreparedReviewRun struct {
	request PreparedReviewRequest
	plan    controlplane.ReviewRunPlan
	inputs  []artifact.Artifact
}

func NewPreparedReviewRequest(o PreparedReviewRequestOptions) (PreparedReviewRequest, error) {
	if o.Scope.Validate() != nil || o.Catalog.Validate() != nil || o.Catalog.Mode() != controlplane.ReviewRunLocal || len(o.Catalog.Bindings()) != 8 || o.Classification.String() == "" || o.Protection != artifact.ProtectionProcessPrivate || o.CreatedAt.UnixMilli() <= 0 || o.Retention < time.Minute || o.Retention > 24*time.Hour {
		return PreparedReviewRequest{}, ErrInvalidPreparedReview
	}
	for _, id := range []string{o.HostRequestIdentity, o.SourceRootIdentity, o.InventoryIdentity, o.RuntimePolicyIdentity, o.ReviewPolicyIdentity} {
		if controlplane.ValidateHandlerIdentity(id) != nil {
			return PreparedReviewRequest{}, ErrInvalidPreparedReview
		}
	}
	for _, rev := range []evidence.RevisionIdentity{o.BaseRevision, o.HeadRevision} {
		if rev.Kind() != evidence.RevisionKindGitCommit || (rev.Algorithm() != evidence.RevisionAlgorithmSHA1 && rev.Algorithm() != evidence.RevisionAlgorithmSHA256) {
			return PreparedReviewRequest{}, ErrInvalidPreparedReview
		}
		if _, err := sourcehandler.NewInput(o.Repository, rev, o.SourceAdapter); err != nil {
			return PreparedReviewRequest{}, ErrInvalidPreparedReview
		}
	}
	if o.BaseRevision.Identity() == o.HeadRevision.Identity() || o.BaseRevision.Algorithm() != o.HeadRevision.Algorithm() || o.SourceAdapter.Kind() != evidence.SourceAdapterKindGit {
		return PreparedReviewRequest{}, ErrInvalidPreparedReview
	}
	if expires := o.CreatedAt.Add(o.Retention).UnixMilli(); expires <= o.CreatedAt.UnixMilli() || expires > 253402300799999 {
		return PreparedReviewRequest{}, ErrInvalidPreparedReview
	}
	o.CreatedAt = time.UnixMilli(o.CreatedAt.UnixMilli()).UTC()
	o.Retention = o.Retention.Truncate(time.Millisecond)
	identity := preparedDigest([]any{"open-trestle/prepared-review-request", 1, o.Scope.Identity(), o.HostRequestIdentity, o.Repository.Identity(), o.BaseRevision.Identity(), o.HeadRevision.Identity(), o.SourceAdapter.Identity(), o.SourceRootIdentity, o.InventoryIdentity, o.RuntimePolicyIdentity, o.ReviewPolicyIdentity, o.Classification.String(), o.Protection.String(), o.CreatedAt.UnixMilli(), o.CreatedAt.Add(o.Retention).UnixMilli(), o.Catalog.Identity()})
	return PreparedReviewRequest{o, identity}, nil
}
func PrepareReviewRun(ctx context.Context, request PreparedReviewRequest) (PreparedReviewRun, error) {
	if ctx == nil || ctx.Err() != nil {
		return PreparedReviewRun{}, ErrInvalidPreparedReview
	}
	canonical, err := NewPreparedReviewRequest(request.options)
	if err != nil || canonical.identity != request.identity {
		return PreparedReviewRun{}, ErrInvalidPreparedReview
	}
	return buildPreparedReview(ctx, canonical)
}
func buildPreparedReview(ctx context.Context, request PreparedReviewRequest) (PreparedReviewRun, error) {
	o := request.options
	inputs := make([]artifact.Artifact, 0, 2)
	for _, revision := range []evidence.RevisionIdentity{o.BaseRevision, o.HeadRevision} {
		if ctx.Err() != nil {
			return PreparedReviewRun{}, ctx.Err()
		}
		input, err := sourcehandler.NewInput(o.Repository, revision, o.SourceAdapter)
		if err != nil {
			return PreparedReviewRun{}, ErrInvalidPreparedReview
		}
		value, err := sourcehandler.NewInputArtifact(o.Scope, input, o.Classification, o.Protection, []string{request.identity}, o.CreatedAt, o.CreatedAt.Add(o.Retention))
		if err != nil {
			return PreparedReviewRun{}, ErrInvalidPreparedReview
		}
		inputs = append(inputs, value)
	}
	specs := []struct {
		key          string
		kind         controlplane.TaskKind
		dependencies []string
	}{
		{"source-base", controlplane.TaskAcquireSource, nil}, {"source-head", controlplane.TaskAcquireSource, nil},
		{"change", controlplane.TaskBuildChange, []string{"source-base", "source-head"}},
		{"analysis", controlplane.TaskInspectDeterministic, []string{"change"}},
		{"memory", controlplane.TaskRetrieveContext, []string{"change"}},
		{"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}},
		{"candidates", controlplane.TaskGenerateCandidates, []string{"context"}},
		{"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}},
		{"readiness", controlplane.TaskEvaluatePublication, []string{"analysis", "change", "verification"}},
	}
	bindings := map[controlplane.TaskKind]string{}
	for _, binding := range o.Catalog.Bindings() {
		bindings[binding.Kind] = binding.HandlerIdentity
	}
	identities := map[string]string{}
	tasks := make([]controlplane.TaskDefinition, 0, len(specs))
	for i, spec := range specs {
		dependencies := []string{}
		for _, key := range spec.dependencies {
			dependencies = append(dependencies, identities[key])
		}
		input := preparedDigest([]any{"open-trestle/prepared-review-task-input", 1, request.identity, spec.kind.String(), dependencies})
		if i < 2 {
			input = inputs[i].Identity()
		}
		attempt, err := controlplane.DefaultTaskAttemptPolicy(spec.kind)
		if err != nil {
			return PreparedReviewRun{}, ErrInvalidPreparedReview
		}
		task, err := controlplane.NewTaskDefinition(spec.key, spec.kind, input, bindings[spec.kind], spec.dependencies, attempt.MaximumAttempts(), attempt.RetryDelayMilliseconds(), attempt.LeaseDurationMilliseconds(), true)
		if err != nil {
			return PreparedReviewRun{}, ErrInvalidPreparedReview
		}
		tasks = append(tasks, task)
		identities[spec.key] = task.Identity()
	}
	plan, err := controlplane.NewReviewRunPlan(o.Scope, request.identity, o.ReviewPolicyIdentity, controlplane.ReviewRunLocal, tasks)
	if err != nil {
		return PreparedReviewRun{}, ErrInvalidPreparedReview
	}
	return PreparedReviewRun{request, plan, inputs}, nil
}
func (p PreparedReviewRun) Plan() controlplane.ReviewRunPlan { return p.plan }
func (p PreparedReviewRun) Inputs() []artifact.Artifact {
	return append([]artifact.Artifact(nil), p.inputs...)
}
func (p PreparedReviewRun) RequestIdentity() string { return p.request.identity }
func (p PreparedReviewRun) Validate() error {
	expected, err := PrepareReviewRun(context.Background(), p.request)
	if err != nil || p.plan.Validate() != nil || expected.plan.Identity() != p.plan.Identity() || len(p.inputs) != 2 {
		return ErrInvalidPreparedReview
	}
	for i, input := range p.inputs {
		if input.Validate() != nil || input.Identity() != expected.inputs[i].Identity() {
			return ErrInvalidPreparedReview
		}
	}
	return nil
}
func preparedDigest(value any) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
