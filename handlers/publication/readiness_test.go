package publication

import (
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
	"strings"
	"testing"
	"time"
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }
func TestNewReadinessHandlerBindsBothPolicies(t *testing.T) {
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	policy, _ := review.NewPublicationPolicy(review.SeverityMedium, 10, gateway.RouteIndependenceDistinctProvider, true)
	diagnosticStore := diagnostics.NewMemoryStore()
	handler, err := NewReadinessHandler(store, diagnosticStore, fixedClock{time.UnixMilli(100)}, strings.Repeat("a", 64), policy)
	if err != nil || handler.Validate() != nil || handler.Kind() != controlplane.TaskEvaluatePublication || handler.HandlerIdentity() != "031872918541d21a5869460d6288f88b17fdb8d999b4dd8f44f2eabc4169030e" {
		t.Fatalf("handler=(%#v,%v)", handler, err)
	}
	other, _ := review.NewPublicationPolicy(review.SeverityHigh, 10, gateway.RouteIndependenceDistinctProvider, true)
	changed, _ := NewReadinessHandler(store, diagnosticStore, fixedClock{time.UnixMilli(100)}, strings.Repeat("a", 64), other)
	if changed.HandlerIdentity() == handler.HandlerIdentity() {
		t.Fatal("publication policy did not bind handler identity")
	}
	if invalid, err := NewReadinessHandler(store, nil, fixedClock{time.UnixMilli(100)}, strings.Repeat("a", 64), policy); !errors.Is(err, ErrInvalidReadinessHandler) || invalid != nil {
		t.Fatalf("nil diagnostic store handler=(%#v,%v)", invalid, err)
	}
	completion := handler.Execute(nil, controlplane.TaskExecutionRequest{})
	if completion.Status() != controlplane.TaskCompletionFailed || completion.Failure() != controlplane.RunFailureInvalidInput {
		t.Fatalf("completion=%#v", completion)
	}
}

func TestPublicationInputRoundTripsExactTarget(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant", "repository", "run")
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	head, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	input, err := NewInput("github-review", repository, "42", head)
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewInputArtifact(scope, input, artifact.ClassificationRestricted, artifact.ProtectionProcessPrivate, []string{strings.Repeat("b", 64)}, time.UnixMilli(10), time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseInput(value.Payload())
	target, targetErr := parsed.Target()
	if err != nil || targetErr != nil || target.ChangeID() != "42" || target.HeadRevision().Identity() != head.Identity() {
		t.Fatalf("target=(%#v,%v,%v)", target, err, targetErr)
	}
}

type fakePublicationEndpoint struct{}

func (fakePublicationEndpoint) PublisherID() string           { return "github-review" }
func (fakePublicationEndpoint) ResolverID() string            { return "github-review" }
func (fakePublicationEndpoint) ConfigurationIdentity() string { return strings.Repeat("a", 64) }
func (fakePublicationEndpoint) IdempotencyGuarantee() review.PublisherIdempotencyGuarantee {
	return review.PublisherExactOperationKey
}
func (fakePublicationEndpoint) Publish(context.Context, review.PublicationDispatchRequest) review.PublicationResult {
	value, _ := review.NewFailedPublicationResult(review.PublicationFailureProvider, 0)
	return value
}
func (fakePublicationEndpoint) ResolveHead(context.Context, review.PublicationHeadRequest) review.PublicationHeadObservation {
	value, _ := review.NewFailedPublicationHeadObservation(review.PublicationHeadFailureProvider)
	return value
}

type fakeEffectAuthorizer struct{}

func (fakeEffectAuthorizer) Identity() string { return strings.Repeat("9", 64) }
func (fakeEffectAuthorizer) Authorize(context.Context, audit.ReviewScope, review.PublicationPlan, time.Time) (review.PublicationAuthorization, error) {
	return review.PublicationAuthorization{}, errors.New("denied")
}
func TestPublicationHandlerBindsEffectAndAdapterCatalogs(t *testing.T) {
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	policy, _ := review.NewPublicationPolicy(review.SeverityLow, 10, gateway.RouteIndependenceDistinctProvider, true)
	publishers, _ := review.NewPublisherCatalog([]review.Publisher{fakePublicationEndpoint{}})
	resolvers, _ := review.NewHeadResolverCatalog([]review.HeadResolver{fakePublicationEndpoint{}})
	ledger := audit.NewMemoryLedger()
	handler, err := NewHandler(store, fixedClock{time.UnixMilli(100)}, ledger, strings.Repeat("a", 64), policy, fakeEffectAuthorizer{}, publishers, resolvers)
	if err != nil || handler.Validate() != nil || handler.Kind() != controlplane.TaskPublishResult {
		t.Fatalf("handler=(%#v,%v)", handler, err)
	}
	completion := handler.Execute(nil, controlplane.TaskExecutionRequest{})
	if completion.Failure() != controlplane.RunFailureInvalidInput {
		t.Fatalf("completion=%#v", completion)
	}
}

func TestDiagnosticWriteFailureDoesNotReportSuccess(t *testing.T) {
	active := context.Background()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		name string
		ctx  context.Context
		err  error
		want controlplane.RunFailure
	}{
		{"diagnostic capacity", active, diagnostics.ErrStoreCapacity, controlplane.RunFailureResourceLimit},
		{"artifact capacity", active, artifact.ErrStoreCapacity, controlplane.RunFailureResourceLimit},
		{"conflict", active, diagnostics.ErrSetConflict, controlplane.RunFailureInternal},
		{"store context done", active, diagnostics.ErrStoreContextDone, controlplane.RunFailureCanceled},
		{"request canceled", canceled, errors.New("write failed"), controlplane.RunFailureCanceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := diagnosticWriteFailure(test.ctx, test.err); got != test.want {
				t.Fatalf("failure=%s want=%s", got, test.want)
			}
		})
	}
}

func TestDiagnosticDeterministicCheckPreservesExactAnalysisState(t *testing.T) {
	source, err := analysishandler.NewDeterministicCheck(strings.Repeat("a", 64), analysishandler.CheckFailed, 2, 3, 1, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := diagnosticDeterministicCheck(source, strings.Repeat("b", 64), strings.Repeat("a", 64))
	if err != nil || mapped.Validate() != nil || mapped.SourceCheckIdentity() != source.Identity() || mapped.AnalysisResultIdentity() != strings.Repeat("b", 64) || mapped.ChangeIdentity() != source.ChangeIdentity() || mapped.State() != diagnostics.CheckFailed || mapped.ApplicableFiles() != 2 || mapped.CheckedRanges() != 2 || mapped.MatchCount() != 1 {
		t.Fatalf("mapped=(%#v,%v)", mapped, err)
	}
	if crossed, err := diagnosticDeterministicCheck(source, strings.Repeat("b", 64), strings.Repeat("c", 64)); err == nil || crossed.Identity() != "" {
		t.Fatalf("crossed=(%#v,%v)", crossed, err)
	}
}
