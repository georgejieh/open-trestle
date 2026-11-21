package publication

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }
func TestNewReadinessHandlerBindsBothPolicies(t *testing.T) {
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	policy, _ := review.NewPublicationPolicy(review.SeverityMedium, 10, gateway.RouteIndependenceDistinctProvider, true)
	diagnosticStore := diagnostics.NewMemoryStore()
	handler, err := NewReadinessHandler(store, diagnosticStore, fixedClock{time.UnixMilli(100)}, strings.Repeat("a", 64), policy)
	if err != nil || handler.Validate() != nil || handler.Kind() != controlplane.TaskEvaluatePublication || handler.HandlerIdentity() != "cbf2367986287ed602a4623f406c91f71321ea66c9173d346c268f0c44283e6d" {
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

func TestFinalOnlyReadinessDoesNotClaimDiagnosticSlot(t *testing.T) {
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	policy, _ := review.NewPublicationPolicy(review.SeverityMedium, 10, gateway.RouteIndependenceDistinctProvider, true)
	legacy, err := NewReadinessHandler(store, diagnostics.NewMemoryStore(), fixedClock{time.UnixMilli(100)}, strings.Repeat("a", 64), policy)
	if err != nil {
		t.Fatal(err)
	}
	final, err := NewFinalOnlyReadinessHandler(store, fixedClock{time.UnixMilli(100)}, strings.Repeat("a", 64), policy)
	if err != nil || final.Validate() != nil || final.HandlerIdentity() != legacy.HandlerIdentity() || !final.finalOnly || final.diagnosticStore != nil {
		t.Fatalf("final=%#v err=%v", final, err)
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

func TestDiagnosticWriteFailureClassifiesSetEncodingLimit(t *testing.T) {
	if got := diagnosticWriteFailure(context.Background(), diagnostics.ErrSetResourceLimit); got != controlplane.RunFailureResourceLimit {
		t.Fatalf("diagnostic set limit mapped to %s", got)
	}
}
