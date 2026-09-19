package gateway

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
)

type investigationOwnerClock struct{ at time.Time }

func (c *investigationOwnerClock) Now() time.Time { return c.at }

type investigationFailLedger struct {
	audit.Ledger
	fail audit.EventKind
}

func (l *investigationFailLedger) Append(ctx context.Context, head string, event audit.Event) error {
	if event.Kind() == l.fail {
		return errors.New("fixture persistence failure")
	}
	return l.Ledger.Append(ctx, head, event)
}

type investigationOwnerDispatcher struct {
	mu            sync.Mutex
	adapter       string
	ledger        audit.Ledger
	scope         audit.ReviewScope
	mode          string
	calls         []RouteDispatchRequest
	deadlines     []time.Time
	contextValues []any
	entered       chan struct{}
	release       chan struct{}
	t             *testing.T
}

func (d *investigationOwnerDispatcher) AdapterID() string             { return d.adapter }
func (d *investigationOwnerDispatcher) ConfigurationIdentity() string { return strings.Repeat("a", 64) }
func (d *investigationOwnerDispatcher) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}
func (d *investigationOwnerDispatcher) DispatchRoute(ctx context.Context, request RouteDispatchRequest) RouteDispatchResult {
	events, err := d.ledger.Read(ctx, d.scope, 0, 100)
	claimed := false
	for _, e := range events {
		if e.Kind() == audit.EventRouteAttemptClaimed && e.SubjectIdentity() == request.Authorization().Identity() && slices.Contains(e.CausalParentIdentities(), request.Authorization().SelectionReceiptIdentity()) {
			claimed = true
		}
	}
	if err != nil || !claimed || request.Validate() != nil {
		d.t.Error("external dispatch preceded actual exact route authority claim")
	}
	deadline, _ := ctx.Deadline()
	d.mu.Lock()
	d.calls = append(d.calls, request)
	d.deadlines = append(d.deadlines, deadline)
	d.contextValues = append(d.contextValues, ctx.Value(investigationOwnerContextKey{}))
	d.mu.Unlock()
	if d.mode == "blocked" {
		close(d.entered)
		select {
		case <-d.release:
		case <-ctx.Done():
		}
	}
	usage, _ := provider.NewRouteTokenUsage(9000, 10000, 0)
	if d.mode == "unknown usage" {
		usage = provider.NewUnknownRouteTokenUsage()
	}
	if d.mode == "overrun" {
		usage, _ = provider.NewRouteTokenUsage(110000, 10000, 0)
	}
	if d.mode == "invalid result" {
		return RouteDispatchResult{}
	}
	if d.mode == "unknown transport" {
		failed, err := NewFailedRouteDispatchResult(RouteFailureTimeout, RouteReplayOutcomeUnknown, provider.NewUnknownRouteTokenUsage(), 0)
		if err != nil {
			d.t.Error(err)
		}
		return failed
	}
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(`{"schema_version":1,"candidates":[]}`))
	if err != nil {
		d.t.Error(err)
	}
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	if err != nil {
		d.t.Error(err)
	}
	result, err := NewSuccessfulRouteDispatchResult(response)
	if err != nil {
		d.t.Error(err)
	}
	return result
}
func investigationOwnerOptionsFixture(t *testing.T, mode string, cap uint64, turns uint8) (InvestigationRouteOwnerOptions, *investigationOwnerDispatcher, *investigationOwnerClock, audit.Ledger) {
	t.Helper()
	_, requirements, constraints := newRoutingFixture(t, []byte("fixture"))
	pricing, _ := provider.NewRoutePricing(1000000, 1000000)
	route := newFallbackRoute(t, 140000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, pricing)
	ranking, _ := NewRouteRankingPolicy(nil)
	plan, err := NewInvestigationRoutePlan(21, []ObservedRouteCandidate{route}, ranking, 4, []provider.RoutePerformanceObservation{routePerformance(t, route, 4, 100)})
	if err != nil {
		t.Fatal(err)
	}
	var ledger audit.Ledger = audit.NewMemoryLedger()
	if mode == "outcome persistence" {
		ledger = &investigationFailLedger{ledger, audit.EventRouteDispatchCompleted}
	}
	if mode == "cost persistence" {
		ledger = &investigationFailLedger{ledger, audit.EventRouteCostReconciled}
	}
	d := &investigationOwnerDispatcher{adapter: observedRouteReference(route).AdapterID(), ledger: ledger, scope: newRoutingScope(t), mode: mode, entered: make(chan struct{}), release: make(chan struct{}), t: t}
	catalog, err := NewRouteDispatcherCatalog([]RouteDispatcher{d})
	if err != nil {
		t.Fatal(err)
	}
	budget, err := provider.NewModelCostBudget(1, 16000, cap)
	if err != nil {
		t.Fatal(err)
	}
	clock := &investigationOwnerClock{time.UnixMilli(1000)}
	options := InvestigationRouteOwnerOptions{Scope: d.scope, SessionIdentity: strings.Repeat("b", 64), PolicyIdentity: strings.Repeat("c", 64), Deadline: time.UnixMilli(10000), MaxTurns: turns, Budget: budget, Requirements: requirements, Constraints: constraints, Generation: plan, Verification: plan, Catalog: catalog, Ledger: ledger, Clock: clock}
	return options, d, clock, ledger
}
func investigationOwnerFixture(t *testing.T, mode string, cap uint64, turns uint8) (*InvestigationRouteOwner, *investigationOwnerDispatcher, *investigationOwnerClock, audit.Ledger) {
	t.Helper()
	options, d, clock, ledger := investigationOwnerOptionsFixture(t, mode, cap, turns)
	owner, err := NewInvestigationRouteOwner(options)
	if err != nil {
		t.Fatal(err)
	}
	return owner, d, clock, ledger
}
func ownerRequest(t *testing.T, label string) provider.Request {
	t.Helper()
	request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(`{"request":"`+label+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	return request
}
func TestInvestigationRouteOwnerSettlesActualUsageAndIncludesVerifier(t *testing.T) {
	ctx := context.Background()
	owner, d, _, ledger := investigationOwnerFixture(t, "", 40000, 4)
	firstRequest, secondRequest := ownerRequest(t, "generation"), ownerRequest(t, "verification")
	first, err := owner.Dispatch(ctx, InvestigationGenerationTurn, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	if first.Reconciliation().Status() != RouteCostWithinBudget || first.Reconciliation().ActualCost().TotalCostMicroUSD() != 19000 || first.Authorization().ReservedCostMicroUSD() >= 19000 {
		t.Fatal("fixture did not reach successful underestimated reservation")
	}
	second, err := owner.Dispatch(ctx, InvestigationVerificationTurn, secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if second.Authorization().RemainingCostBeforeMicroUSD() != 21000 || second.Reconciliation().RemainingCostMicroUSD() != 2000 || owner.State().RemainingCostMicroUSD() != 2000 {
		t.Fatal("verifier received a reset original budget")
	}
	if _, err := owner.Dispatch(ctx, InvestigationGenerationTurn, ownerRequest(t, "third")); err == nil || d.count() != 2 {
		t.Fatal("cumulative budget exhaustion reached external dispatch")
	}
	events, err := ledger.Read(ctx, d.scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, turn := range []InvestigationTurnRecord{first, second} {
		a, o, r, dispatch, selection := turn.Authorization(), turn.Outcome(), turn.Reconciliation(), turn.Dispatch(), turn.Selection()
		if a.Validate() != nil || o.Validate() != nil || r.Validate() != nil || selection.Validate() != nil || dispatch.Validate() != nil || a.Kind() != RouteAttemptInitial || a.PreviousOutcomeIdentity() != "" {
			t.Fatal("successful turn relabeled as transport retry")
		}
		for _, id := range []string{a.Identity(), o.Identity(), r.Identity()} {
			if seen[id] {
				t.Fatal("turn authority identity reused")
			}
			seen[id] = true
		}
		if a.RequestIdentity() != turn.RequestIdentity() || selection.RequestIdentity() != a.RequestIdentity() || a.SelectionReceiptIdentity() != selection.Identity() || dispatch.AuthorizationIdentity() != a.Identity() || o.AuthorizationIdentity() != a.Identity() || o.ResponseIdentity() != dispatch.Response().Identity() || r.AttemptAuthorizationIdentity() != a.Identity() || r.AttemptOutcomeIdentity() != o.Identity() {
			t.Fatal("cross-wired actual route record")
		}
		want := map[audit.EventKind]struct {
			subject string
			parents []string
		}{
			audit.EventRouteSelected:          {selection.Identity(), []string{selection.RoutingInputIdentity(), selection.SelectedRecordIdentity(), selection.RankingPolicyIdentity()}},
			audit.EventRouteAttemptClaimed:    {a.Identity(), []string{selection.Identity()}},
			audit.EventRouteDispatchCompleted: {o.Identity(), []string{a.Identity(), dispatch.Identity(), dispatch.Response().Identity()}},
			audit.EventRouteCostReconciled:    {r.Identity(), []string{a.Identity(), o.Identity()}},
		}
		for kind, expected := range want {
			count := 0
			for _, event := range events {
				if event.Kind() == kind && event.SubjectIdentity() == expected.subject {
					count++
					parents := append([]string(nil), expected.parents...)
					slices.Sort(parents)
					if event.Scope().Identity() != d.scope.Identity() || !slices.Equal(event.CausalParentIdentities(), parents) {
						t.Fatal("actual ledger causal parents mismatch")
					}
				}
			}
			if count != 1 {
				t.Fatal("missing or duplicated route audit evidence")
			}
		}
	}
	for i := 1; i < len(events); i++ {
		if events[i].PreviousIdentity() != events[i-1].Identity() {
			t.Fatal("ledger chain broken")
		}
	}
	if first.RequestIdentity() != firstRequest.Identity() || second.RequestIdentity() != secondRequest.Identity() || second.PreviousTurnIdentity() != first.Identity() {
		t.Fatal("owner lost turn lineage")
	}
	before := owner.State()
	if _, err := owner.Dispatch(ctx, InvestigationGenerationTurn, firstRequest); err == nil || d.count() != 2 || owner.State().RemainingCostMicroUSD() != before.RemainingCostMicroUSD() {
		t.Fatal("replay resettled prior usage or dispatched again")
	}
	kind := reflect.TypeOf(owner)
	for _, method := range []string{"Settle", "Reset", "Restore", "ImportReceipt", "Credit", "SetRemainingBudget"} {
		if _, ok := kind.MethodByName(method); ok {
			t.Fatal("owner exposes caller-invented accounting authority")
		}
	}
}
func TestInvestigationRouteOwnerFreezesUnknownEffectAndPersistenceFailure(t *testing.T) {
	for _, mode := range []string{"unknown usage", "unknown transport", "outcome persistence", "cost persistence"} {
		t.Run(mode, func(t *testing.T) {
			owner, d, _, _ := investigationOwnerFixture(t, mode, 100000, 5)
			_, _ = owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "first"))
			if d.count() != 1 || !owner.State().Frozen() {
				t.Fatal("unknown or unrecorded actual effect did not freeze account")
			}
			if _, err := owner.Dispatch(context.Background(), InvestigationVerificationTurn, ownerRequest(t, "next")); err == nil || d.count() != 1 {
				t.Fatal("unknown authority was reauthorized")
			}
		})
	}
}
func TestInvestigationRouteOwnerDeniesConcurrentCanceledAndExpiredDispatch(t *testing.T) {
	owner, d, clock, _ := investigationOwnerFixture(t, "blocked", 100000, 5)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	first := ownerRequest(t, "first")
	go func() { _, err := owner.Dispatch(ctx, InvestigationGenerationTurn, first); done <- err }()
	select {
	case <-d.entered:
	case <-time.After(time.Second):
		t.Fatal("first real dispatch not reached")
	}
	if state := owner.State(); !state.InFlight() || state.UsageKnown() {
		t.Fatal("in-flight effect was projected as settled known usage")
	}
	if _, err := owner.Dispatch(ctx, InvestigationVerificationTurn, ownerRequest(t, "parallel")); err == nil || d.count() != 1 {
		t.Fatal("second in-flight effect admitted")
	}
	close(d.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("owner did not settle released provider")
	}
	cancel()
	if _, err := owner.Dispatch(ctx, InvestigationGenerationTurn, ownerRequest(t, "canceled")); err == nil || d.count() != 1 {
		t.Fatal("canceled operation dispatched")
	}
	clock.at = time.UnixMilli(10000)
	if _, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "expired")); err == nil || d.count() != 1 {
		t.Fatal("expired session deadline was refreshed")
	}
}

func investigationOwnerEvents(t *testing.T, ledger audit.Ledger, scope audit.ReviewScope) []audit.Event {
	t.Helper()
	events, err := ledger.Read(context.Background(), scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	return events
}
func TestInvestigationRouteOwnerTurnLimitDeniesWithAmpleRemainingMoney(t *testing.T) {
	owner, d, _, ledger := investigationOwnerFixture(t, "", 100000, 1)
	first, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "first"))
	if err != nil || d.count() != 1 {
		t.Fatal("first actual model effect did not complete")
	}
	next := ownerRequest(t, "second")
	remaining := owner.State().RemainingCostMicroUSD()
	if remaining != 81000 || uint64(len(next.Payload()))+256+16000 >= remaining || first.Authorization().ReservedCostMicroUSD() >= remaining {
		t.Fatal("turn-limit fixture is money-constrained")
	}
	before := investigationOwnerEvents(t, ledger, d.scope)
	if _, err := owner.Dispatch(context.Background(), InvestigationVerificationTurn, next); err == nil {
		t.Fatal("MaxTurns ignored despite available money")
	}
	after := investigationOwnerEvents(t, ledger, d.scope)
	if d.count() != 1 || owner.State().RemainingCostMicroUSD() != remaining || !slices.EqualFunc(before, after, func(a, b audit.Event) bool { return a.Identity() == b.Identity() }) {
		t.Fatal("turn denial selected, claimed, dispatched or spent again")
	}
}
func TestInvestigationRouteOwnerInvalidConstructorHasNoEffects(t *testing.T) {
	for _, mode := range []string{"zero", "scope", "session identity", "policy identity", "deadline zero", "deadline expired", "deadline equality", "turns zero", "turns ceiling", "budget", "generation plan", "verification plan", "catalog", "ledger nil", "ledger typed nil", "clock nil", "clock typed nil"} {
		t.Run(mode, func(t *testing.T) {
			options, d, clock, ledger := investigationOwnerOptionsFixture(t, "", 100000, 5)
			switch mode {
			case "zero":
				options = InvestigationRouteOwnerOptions{}
			case "scope":
				options.Scope = audit.ReviewScope{}
			case "session identity":
				options.SessionIdentity = "invalid"
			case "policy identity":
				options.PolicyIdentity = "invalid"
			case "deadline zero":
				options.Deadline = time.Time{}
			case "deadline expired":
				options.Deadline = clock.at.Add(-time.Millisecond)
			case "deadline equality":
				options.Deadline = clock.at
			case "turns zero":
				options.MaxTurns = 0
			case "turns ceiling":
				options.MaxTurns = 9
			case "budget":
				options.Budget = provider.ModelCostBudget{}
			case "generation plan":
				options.Generation = InvestigationRoutePlan{}
			case "verification plan":
				options.Verification = InvestigationRoutePlan{}
			case "catalog":
				options.Catalog = RouteDispatcherCatalog{}
			case "ledger nil":
				options.Ledger = nil
			case "ledger typed nil":
				var missing *audit.MemoryLedger
				options.Ledger = missing
			case "clock nil":
				options.Clock = nil
			case "clock typed nil":
				var missing *investigationOwnerClock
				options.Clock = missing
			}
			owner, err := NewInvestigationRouteOwner(options)
			if err == nil || owner != nil {
				t.Fatal("invalid constructor produced an owner")
			}
			if d.count() != 0 || len(investigationOwnerEvents(t, ledger, d.scope)) != 0 {
				t.Fatal("invalid constructor created route authority or external effect")
			}
		})
	}
}
func TestInvestigationRoutePlanRefusesInvalidRevisionsAndValuesWithoutEffects(t *testing.T) {
	pricing, err := provider.NewRoutePricing(1000000, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	route := newFallbackRoute(t, 140000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, pricing)
	ranking, err := NewRouteRankingPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	observation := routePerformance(t, route, 4, 100)
	for _, mode := range []string{"registry zero", "registry mismatch", "performance zero", "performance mismatch", "no routes", "invalid route", "invalid ranking", "no observations"} {
		t.Run(mode, func(t *testing.T) {
			registry, performance := uint64(21), uint64(4)
			routes := []ObservedRouteCandidate{route}
			observations := []provider.RoutePerformanceObservation{observation}
			policy := ranking
			switch mode {
			case "registry zero":
				registry = 0
			case "registry mismatch":
				registry = 22
			case "performance zero":
				performance = 0
			case "performance mismatch":
				performance = 5
			case "no routes":
				routes = nil
			case "invalid route":
				routes = []ObservedRouteCandidate{{}}
			case "invalid ranking":
				policy = RouteRankingPolicy{}
			case "no observations":
				observations = nil
			}
			if _, err := NewInvestigationRoutePlan(registry, routes, policy, performance, observations); err == nil {
				t.Fatal("invalid plan became usable immutable routing input")
			}
		})
	}
}
func TestInvestigationRouteOwnerInvalidDispatchHasNoEffects(t *testing.T) {
	for _, mode := range []string{"zero role", "unknown role", "zero request", "nil context", "pre-canceled"} {
		t.Run(mode, func(t *testing.T) {
			owner, d, _, ledger := investigationOwnerFixture(t, "", 100000, 5)
			role := InvestigationGenerationTurn
			request := ownerRequest(t, "invalid-call")
			ctx := context.Background()
			switch mode {
			case "zero role":
				role = InvestigationTurnRole(0)
			case "unknown role":
				role = InvestigationTurnRole(255)
			case "zero request":
				request = provider.Request{}
			case "nil context":
				ctx = nil
			case "pre-canceled":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			before := owner.State().RemainingCostMicroUSD()
			if _, err := owner.Dispatch(ctx, role, request); err == nil {
				t.Fatal("invalid dispatch admitted")
			}
			if d.count() != 0 || len(investigationOwnerEvents(t, ledger, d.scope)) != 0 || owner.State().RemainingCostMicroUSD() != before {
				t.Fatal("invalid call created route authority, external effect or spend")
			}
		})
	}
}
func TestInvestigationRouteOwnerReconstructionCannotReacquireExistingExactClaim(t *testing.T) {
	options, d, _, ledger := investigationOwnerOptionsFixture(t, "", 100000, 5)
	owner, err := NewInvestigationRouteOwner(options)
	if err != nil {
		t.Fatal(err)
	}
	request := ownerRequest(t, "exact-existing-request")
	first, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, request)
	if err != nil || d.count() != 1 || first.RequestIdentity() != request.Identity() {
		t.Fatal("actual first dispatch did not establish existing authority")
	}
	before := investigationOwnerEvents(t, ledger, d.scope)
	claims := 0
	for _, event := range before {
		if event.Kind() == audit.EventRouteAttemptClaimed && event.SubjectIdentity() == first.Authorization().Identity() {
			claims++
		}
	}
	if claims != 1 {
		t.Fatal("actual first dispatch did not create one exact claim")
	}
	balance := owner.State().RemainingCostMicroUSD()
	reconstructed, err := NewInvestigationRouteOwner(options)
	if err == nil {
		if reconstructed == nil {
			t.Fatal("constructor returned nil without error")
		}
		if _, err := reconstructed.Dispatch(context.Background(), InvestigationGenerationTurn, request); err == nil {
			t.Fatal("new owner reacquired an existing exact request effect")
		}
	} else if reconstructed != nil {
		t.Fatal("refused reconstruction returned usable owner")
	}
	after := investigationOwnerEvents(t, ledger, d.scope)
	if d.count() != 1 || owner.State().RemainingCostMicroUSD() != balance || !slices.EqualFunc(before, after, func(a, b audit.Event) bool { return a.Identity() == b.Identity() }) {
		t.Fatal("reconstructed exact claim repeated route work or altered prior accounting")
	}
}

type investigationOwnerContextKey struct{}

func TestInvestigationRouteOwnerImposesOneDeadlineAndKeepsCallerContext(t *testing.T) {
	options, d, _, _ := investigationOwnerOptionsFixture(t, "", 100000, 5)
	owner, err := NewInvestigationRouteOwner(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), investigationOwnerContextKey{}, "caller")
	for _, label := range []string{"first", "second"} {
		if _, err := owner.Dispatch(ctx, InvestigationGenerationTurn, ownerRequest(t, label)); err != nil {
			t.Fatal(err)
		}
	}
	d.mu.Lock()
	deadlines := append([]time.Time(nil), d.deadlines...)
	values := append([]any(nil), d.contextValues...)
	d.mu.Unlock()
	if len(deadlines) != 2 || deadlines[0].IsZero() || !deadlines[0].Equal(deadlines[1]) || deadlines[0].Before(time.Now()) || deadlines[0].After(time.Now().Add(10*time.Second)) {
		t.Fatal("protocol clock was treated as wall time or total owner timeout reset")
	}
	if len(values) != 2 || values[0] != "caller" || values[1] != "caller" {
		t.Fatal("model effect lost caller context")
	}
}
func TestInvestigationRouteOwnerRemainingDeadlineCancelsActualProvider(t *testing.T) {
	options, d, clock, _ := investigationOwnerOptionsFixture(t, "blocked", 100000, 5)
	options.Deadline = clock.at.Add(250 * time.Millisecond)
	owner, err := NewInvestigationRouteOwner(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := ownerRequest(t, "bounded-wait")
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, err := owner.Dispatch(ctx, InvestigationGenerationTurn, request)
		done <- err
	}()
	t.Cleanup(func() {
		cancel()
		close(d.release)
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("bounded fixture did not drain")
		}
	})
	select {
	case <-d.entered:
	case <-time.After(time.Second):
		t.Fatal("actual provider wait not reached")
	}
	select {
	case err := <-done:
		if err == nil || !owner.State().Frozen() {
			t.Fatal("expired real effect returned usable successful record")
		}
	case <-time.After(time.Second):
		t.Fatal("remaining owner deadline never canceled provider")
	}
	if d.count() != 1 {
		t.Fatal("deadline repeated external dispatch")
	}
}
func TestInvestigationRouteOwnerOverrunAndInvalidResultFreeze(t *testing.T) {
	for _, mode := range []string{"overrun", "invalid result"} {
		t.Run(mode, func(t *testing.T) {
			owner, d, _, _ := investigationOwnerFixture(t, mode, 100000, 5)
			record, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "first"))
			if err == nil || record.Identity() != "" || !owner.State().Frozen() || d.count() != 1 {
				t.Fatal("invalid or over-budget effect returned successful authority")
			}
			if mode == "overrun" && (!owner.State().UsageKnown() || owner.State().KnownCostMicroUSD() != 120000 || owner.State().RemainingCostMicroUSD() != 0) {
				t.Fatal("known overrun lost exact actual cost")
			}
			if mode == "invalid result" && owner.State().UsageKnown() {
				t.Fatal("invalid result became known zero usage")
			}
			if _, err := owner.Dispatch(context.Background(), InvestigationVerificationTurn, ownerRequest(t, "next")); err == nil || d.count() != 1 {
				t.Fatal("frozen owner dispatched after unsafe outcome")
			}
		})
	}
}
func TestInvestigationTurnRecordValidatesCompleteImmutableBinding(t *testing.T) {
	if (InvestigationTurnRecord{}).Validate() == nil {
		t.Fatal("zero turn record validated")
	}
	owner, d, _, _ := investigationOwnerFixture(t, "", 100000, 5)
	record, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "record"))
	if err != nil || record.Validate() != nil || record.Identity() == "" || d.count() != 1 {
		t.Fatal("actual complete record did not validate")
	}
	kind := reflect.TypeOf(record)
	for i := 0; i < kind.NumField(); i++ {
		if kind.Field(i).PkgPath == "" {
			t.Fatal("turn record exposes mutable authority fields")
		}
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%q"} {
		if strings.Contains(fmt.Sprintf(verb, record), record.RequestIdentity()) {
			t.Fatal("record formatting exposed request lineage")
		}
	}
}

func TestInvestigationRouteOwnerHonorsShorterParentDeadline(t *testing.T) {
	owner, d, _, _ := investigationOwnerFixture(t, "", 100000, 5)
	deadline := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if _, err := owner.Dispatch(ctx, InvestigationGenerationTurn, ownerRequest(t, "parent-deadline")); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	deadlines := append([]time.Time(nil), d.deadlines...)
	d.mu.Unlock()
	if len(deadlines) != 1 || !deadlines[0].Equal(deadline) {
		t.Fatal("owner replaced earlier caller deadline")
	}
}
func TestInvestigationTurnRecordRejectsRehashedCrossWiredComponents(t *testing.T) {
	owner, _, _, _ := investigationOwnerFixture(t, "", 100000, 5)
	first, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "first-record"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := owner.Dispatch(context.Background(), InvestigationVerificationTurn, ownerRequest(t, "second-record"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"scope", "request", "selection", "ranking", "authorization", "dispatch", "outcome", "reconciliation", "timing", "estimate version", "ordinal"} {
		t.Run(mode, func(t *testing.T) {
			changed := second
			switch mode {
			case "scope":
				changed.scopeIdentity = strings.Repeat("f", 64)
			case "request":
				changed.request = first.request
			case "selection":
				changed.selection = first.selection
			case "ranking":
				changed.ranking = first.ranking
			case "authorization":
				changed.authorization = first.authorization
			case "dispatch":
				changed.dispatch = first.dispatch
			case "outcome":
				changed.outcome = first.outcome
			case "reconciliation":
				changed.reconciliation = first.reconciliation
			case "timing":
				changed.finishedMillis = changed.deadlineMillis
			case "estimate version":
				changed.estimateVersion = 2
			case "ordinal":
				changed.ordinal = 1
			}
			changed.identity = changed.deriveIdentity()
			if changed.Validate() == nil {
				t.Fatal("rehashed component substitution validated")
			}
		})
	}
}

func TestInvestigationRoutePlanCopiesCallerSlices(t *testing.T) {
	pricing, err := provider.NewRoutePricing(1000000, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	route := newFallbackRoute(t, 140000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, pricing)
	ranking, err := NewRouteRankingPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	routes := []ObservedRouteCandidate{route}
	observations := []provider.RoutePerformanceObservation{routePerformance(t, route, 4, 100)}
	plan, err := NewInvestigationRoutePlan(21, routes, ranking, 4, observations)
	if err != nil {
		t.Fatal(err)
	}
	identity := plan.Identity()
	routes[0] = ObservedRouteCandidate{}
	observations[0] = provider.RoutePerformanceObservation{}
	if plan.Validate() != nil || plan.Identity() != identity {
		t.Fatal("route plan retained mutable caller slice authority")
	}
}
