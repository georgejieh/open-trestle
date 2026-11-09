package model_test

import (
	"context"
	"sync"
	"testing"

	model "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

type shortfallRecorder struct {
	mu        sync.Mutex
	shortfall []gateway.RouteContextShortfall
}

func (r *shortfallRecorder) refused(err error) {
	if shortfall, ok := gateway.RouteContextShortfallOf(err); ok {
		r.mu.Lock()
		r.shortfall = append(r.shortfall, shortfall)
		r.mu.Unlock()
	}
}

// An investigation reports a turn that outgrows the pinned route's declared
// context with its counts, both for the first turn and for a later turn the
// route owner plans.
func TestInvestigationReportsRouteContextShortfalls(t *testing.T) {
	control, _, modelA, _, _, _ := upperFixture(t, "")
	baseline, err := model.NewInvestigation(context.Background(), control)
	upperCheck(t, err)
	first, err := baseline.Step(context.Background())
	upperCheck(t, err)
	need := func(request provider.Request) uint64 {
		return uint64(len(request.Payload())) + uint64(review.ModelRequestSystemChannelBytes(request)) + 256 + 4096
	}
	initialNeed, nextNeed := need(modelA.calls[0].Request()), need(first.NextRequest())
	for _, tc := range []struct {
		name     string
		capacity uint64
		later    bool
		required uint64
	}{
		{"first turn", initialNeed - 1, false, initialNeed},
		{"later owner turn", (initialNeed + nextNeed) / 2, true, nextNeed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options, _, _, _, _, _ := upperFixture(t, "", tc.capacity)
			recorder := &shortfallRecorder{}
			options.PlanningRefusals = recorder.refused
			controller, err := model.NewInvestigation(context.Background(), options)
			if err == nil {
				_, err = controller.Step(context.Background())
			}
			if tc.later {
				upperCheck(t, err)
				_, err = controller.Step(context.Background())
			}
			if err == nil || len(recorder.shortfall) != 1 {
				t.Fatalf("refusal %v reported %d shortfalls", err, len(recorder.shortfall))
			}
			if shortfall := recorder.shortfall[0]; shortfall.DeclaredContextTokens != uint32(tc.capacity) || shortfall.RequiredTokens != tc.required || shortfall.RequiredTokens != uint64(shortfall.EstimatedInputTokens)+uint64(shortfall.MaxOutputTokens) {
				t.Fatalf("shortfall = %+v, want required %d against %d", shortfall, tc.required, tc.capacity)
			}
		})
	}
}

// The constructor pre-plans the first turn to establish an independent
// verifier, so it must plan the exact request the first turn sends: it refuses
// a route one token too small for that request, before any model effect, and
// accepts the exact fit.
func TestInvestigationPrePlanRefusesExactlyWhenTheFirstTurnWould(t *testing.T) {
	control, _, modelA, _, _, _ := upperFixture(t, "")
	baseline, err := model.NewInvestigation(context.Background(), control)
	upperCheck(t, err)
	_, err = baseline.Step(context.Background())
	upperCheck(t, err)
	needOf := func(request provider.Request) uint64 {
		return uint64(len(request.Payload())) + uint64(review.ModelRequestSystemChannelBytes(request)) + 256 + 4096
	}
	need := needOf(modelA.calls[0].Request())
	for _, tc := range []struct {
		capacity uint64
		refused  bool
	}{{need - 1, true}, {need, false}} {
		options, _, a, b, _, _ := upperFixture(t, "", tc.capacity)
		recorder := &shortfallRecorder{}
		options.PlanningRefusals = recorder.refused
		controller, err := model.NewInvestigation(context.Background(), options)
		if tc.refused {
			if err == nil || a.count() != 0 || b.count() != 0 || len(recorder.shortfall) != 1 || recorder.shortfall[0].RequiredTokens != need {
				t.Fatalf("capacity %d: constructor err=%v dispatches=%d/%d shortfalls=%+v, want a refusal needing %d", tc.capacity, err, a.count(), b.count(), recorder.shortfall, need)
			}
			continue
		}
		upperCheck(t, err)
		step, err := controller.Step(context.Background())
		upperCheck(t, err)
		if a.count() != 1 || len(recorder.shortfall) != 0 || step.Turn().RequestIdentity() != a.calls[0].Request().Identity() || needOf(a.calls[0].Request()) != tc.capacity {
			t.Fatalf("capacity %d: exact fit did not dispatch the planned first turn", tc.capacity)
		}
	}
}
