package gateway

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func strictLocalFixture(t *testing.T) (audit.ReviewScope, provider.Request, ReviewRoutingInput, RouteRankingPolicy, RouteSelectionReceipt, RouteAttemptAuthorization) {
	return strictLocalFixtureWithZones(t, provider.ProviderZoneLocal)
}

func strictLocalFixtureWithZones(t *testing.T, allowed ...provider.ProviderZone) (audit.ReviewScope, provider.Request, ReviewRoutingInput, RouteRankingPolicy, RouteSelectionReceipt, RouteAttemptAuthorization) {
	t.Helper()
	scope := newRoutingScope(t)
	request, requirements, _ := newRoutingFixture(t, []byte("fallback payload"))
	zones, err := policy.NewAllowedProviderZones(allowed...)
	if err != nil {
		t.Fatal(err)
	}
	constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewReviewRoutingInput(scope, request, requirements, constraints)
	if err != nil {
		t.Fatal(err)
	}
	pricing, err := provider.NewRoutePricing(1_000_000, 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	route := newFallbackRoute(t, 140_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, pricing)
	budget, err := provider.NewModelCostBudget(1, 16_000, 20_000)
	if err != nil {
		t.Fatal(err)
	}
	eligibility, err := FilterEligibleRoutes(input, budget, 21, []ObservedRouteCandidate{route})
	if err != nil {
		t.Fatal(err)
	}
	pin := route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
	rankingPolicy, err := NewPinnedRouteRankingPolicy(pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	ranking, err := RankEligibleRoutes(eligibility, rankingPolicy, 4, []provider.RoutePerformanceObservation{routePerformance(t, route, 4, 100)})
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRouteSelectionReceipt(eligibility, ranking)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := NewInitialRouteAttemptAuthorization(request, selection, ranking)
	if err != nil {
		t.Fatal(err)
	}
	return scope, request, input, rankingPolicy, selection, authorization
}

func TestClaimStrictInitialLocalRouteAttemptPrerequisites(t *testing.T) {
	for _, storage := range []string{"memory", "file"} {
		t.Run(storage, func(t *testing.T) {
			newLedger := func() audit.Ledger {
				t.Helper()
				if storage == "memory" {
					return audit.NewMemoryLedger()
				}
				file, err := audit.NewFileLedger(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := file.Close(); err != nil {
						t.Error(err)
					}
				})
				return file
			}
			scope, request, input, ranking, selection, auth := strictLocalFixture(t)
			_ = request
			parents := []string{input.Identity(), selection.SelectedRecordIdentity(), ranking.Identity()}
			for _, tc := range []struct {
				name             string
				selectionParents []string
				duplicate        bool
				absent           bool
				want             error
			}{
				{name: "wrong routing input", selectionParents: []string{differentDigest(input.Identity()), parents[1], parents[2]}, want: ErrRouteAuditRecordMismatch},
				{name: "wrong ranking policy", selectionParents: []string{parents[0], parents[1], differentDigest(parents[2])}, want: ErrRouteAuditRecordMismatch},
				{name: "wrong selected record", selectionParents: []string{parents[0], differentDigest(parents[1]), parents[2]}, want: ErrRouteAuditRecordMismatch},
				{name: "duplicate selection", selectionParents: parents, duplicate: true, want: ErrRouteAuditRecordMismatch},
				{name: "absent selection", absent: true, want: ErrRouteAuditPrerequisiteMissing},
			} {
				t.Run(tc.name, func(t *testing.T) {
					ledger := newLedger()
					ctx := context.Background()
					before := 0
					if !tc.absent {
						first, err := audit.NewEvent(scope, 1, "", audit.EventRouteSelected, selection.Identity(), tc.selectionParents, time.UnixMilli(1))
						if err != nil {
							t.Fatal(err)
						}
						if err := ledger.Append(ctx, "", first); err != nil {
							t.Fatal(err)
						}
						before++
						if tc.duplicate {
							second, err := audit.NewEvent(scope, 2, first.Identity(), audit.EventRouteSelected, selection.Identity(), tc.selectionParents, time.UnixMilli(2))
							if err != nil {
								t.Fatal(err)
							}
							if err := ledger.Append(ctx, first.Identity(), second); err != nil {
								t.Fatal(err)
							}
							before++
						}
					}
					event, acquired, err := ClaimStrictInitialLocalRouteAttempt(ctx, ledger, scope, request, input, ranking, selection, auth, time.UnixMilli(3))
					if !errors.Is(err, tc.want) || acquired || event.Identity() != "" {
						t.Fatalf("claim = (%#v,%t,%v), want %v", event, acquired, err, tc.want)
					}
					events, err := ledger.Read(ctx, scope, 0, 10)
					if err != nil || len(events) != before {
						t.Fatalf("events=%d err=%v want=%d", len(events), err, before)
					}
				})
			}
			ledger := newLedger()
			ctx := context.Background()
			if _, err := RecordRouteSelection(ctx, ledger, scope, selection, time.UnixMilli(1)); err != nil {
				t.Fatal(err)
			}
			first, acquired, err := ClaimStrictInitialLocalRouteAttempt(ctx, ledger, scope, request, input, ranking, selection, auth, time.UnixMilli(2))
			if err != nil || !acquired || first.Kind() != audit.EventRouteAttemptClaimed || first.SubjectIdentity() != auth.Identity() || !routeAuditParentsMatch(first, append([]string{selection.Identity()}, parents...)) {
				t.Fatalf("first claim = (%#v,%t,%v)", first, acquired, err)
			}
			second, acquired, err := ClaimStrictInitialLocalRouteAttempt(ctx, ledger, scope, request, input, ranking, selection, auth, time.UnixMilli(3))
			if err != nil || acquired || second.Identity() != first.Identity() {
				t.Fatalf("replay = (%#v,%t,%v)", second, acquired, err)
			}
			// Existing legacy claim with the same subject but incompatible parent contract cannot be reused.
			legacy := newLedger()
			if _, err := RecordRouteSelection(ctx, legacy, scope, selection, time.UnixMilli(1)); err != nil {
				t.Fatal(err)
			}
			if _, acquired, err := ClaimRouteAttempt(ctx, legacy, scope, auth, time.UnixMilli(2)); err != nil || !acquired {
				t.Fatalf("legacy fixture = (%t,%v)", acquired, err)
			}
			if event, acquired, err := ClaimStrictInitialLocalRouteAttempt(ctx, legacy, scope, request, input, ranking, selection, auth, time.UnixMilli(3)); !errors.Is(err, ErrRouteAuditRecordMismatch) || acquired || event.Identity() != "" {
				t.Fatalf("incompatible claim = (%#v,%t,%v)", event, acquired, err)
			}
			for _, tc := range []struct {
				name      string
				wrong     bool
				duplicate bool
			}{
				{name: "same subject wrong claim parent", wrong: true},
				{name: "duplicate same subject claims", duplicate: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					ledger := newLedger()
					if _, err := RecordRouteSelection(ctx, ledger, scope, selection, time.UnixMilli(1)); err != nil {
						t.Fatal(err)
					}
					claimParents := append([]string{selection.Identity()}, parents...)
					if tc.wrong {
						claimParents[2] = differentDigest(claimParents[2])
					}
					head, _, err := ledger.Head(ctx, scope)
					if err != nil {
						t.Fatal(err)
					}
					previous := head.Identity()
					before := 2
					if tc.duplicate {
						before++
					}
					for sequence := uint64(2); sequence < uint64(before+1); sequence++ {
						claim, err := audit.NewEvent(scope, sequence, previous, audit.EventRouteAttemptClaimed, auth.Identity(), claimParents, time.UnixMilli(int64(sequence)))
						if err != nil {
							t.Fatal(err)
						}
						if err := ledger.Append(ctx, previous, claim); err != nil {
							t.Fatal(err)
						}
						previous = claim.Identity()
					}
					event, acquired, err := ClaimStrictInitialLocalRouteAttempt(ctx, ledger, scope, request, input, ranking, selection, auth, time.UnixMilli(4))
					if !errors.Is(err, ErrRouteAuditRecordMismatch) || acquired || event.Identity() != "" {
						t.Fatalf("incompatible claim = (%#v,%t,%v)", event, acquired, err)
					}
					events, err := ledger.Read(ctx, scope, 0, 10)
					if err != nil || len(events) != before {
						t.Fatalf("events=(%d,%v), want %d without append", len(events), err, before)
					}
				})
			}
		})
	}
}

func differentDigest(identity string) string {
	if identity[0] == 'f' {
		return "e" + identity[1:]
	}
	return "f" + identity[1:]
}

// appendBeforeClaimLedger forces a competing append at the precise CAS boundary.
type appendBeforeClaimLedger struct {
	audit.Ledger
	inserted  bool
	selection RouteSelectionReceipt
}

func (l *appendBeforeClaimLedger) Append(ctx context.Context, previous string, event audit.Event) error {
	if event.Kind() == audit.EventRouteAttemptClaimed && !l.inserted {
		l.inserted = true
		competing, err := audit.NewEvent(event.Scope(), event.Sequence(), previous, audit.EventRouteSelected, l.selection.Identity(), []string{l.selection.RoutingInputIdentity(), l.selection.SelectedRecordIdentity(), differentDigest(l.selection.RankingPolicyIdentity())}, time.UnixMilli(10))
		if err != nil {
			return err
		}
		if err := l.Ledger.Append(ctx, previous, competing); err != nil {
			return err
		}
	}
	return l.Ledger.Append(ctx, previous, event)
}

func TestStrictInitialLocalClaimRescansAfterCASConflict(t *testing.T) {
	for _, storage := range []string{"memory", "file"} {
		t.Run(storage, func(t *testing.T) {
			var backing audit.Ledger = audit.NewMemoryLedger()
			if storage == "file" {
				file, err := audit.NewFileLedger(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := file.Close(); err != nil {
						t.Error(err)
					}
				})
				backing = file
			}
			scope, request, input, ranking, selection, auth := strictLocalFixture(t)
			ctx := context.Background()
			if _, err := RecordRouteSelection(ctx, backing, scope, selection, time.UnixMilli(1)); err != nil {
				t.Fatal(err)
			}
			ledger := &appendBeforeClaimLedger{Ledger: backing, selection: selection}
			event, acquired, err := ClaimStrictInitialLocalRouteAttempt(ctx, ledger, scope, request, input, ranking, selection, auth, time.UnixMilli(2))
			if !errors.Is(err, ErrRouteAuditRecordMismatch) || acquired || event.Identity() != "" || !ledger.inserted {
				t.Fatalf("claim after interleaved append=(%#v,%t,%v), inserted=%t", event, acquired, err, ledger.inserted)
			}
			events, err := backing.Read(ctx, scope, 0, 10)
			if err != nil || len(events) != 2 || events[1].Kind() != audit.EventRouteSelected {
				t.Fatalf("events=(%d,%v)", len(events), err)
			}
		})
	}
}

func TestStrictInitialLocalClaimRejectsTypedMismatches(t *testing.T) {
	scope, request, input, ranking, selection, auth := strictLocalFixture(t)
	other, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte("other payload"))
	if err != nil {
		t.Fatal(err)
	}
	unpinned, err := NewRouteRankingPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherScope, err := audit.NewReviewScope("other-tenant", "repository", "review-run")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		scope     audit.ReviewScope
		request   provider.Request
		input     ReviewRoutingInput
		ranking   RouteRankingPolicy
		selection RouteSelectionReceipt
		auth      RouteAttemptAuthorization
		want      error
	}{
		{name: "request", scope: scope, request: other, input: input, ranking: ranking, selection: selection, auth: auth, want: ErrRouteAuditRecordMismatch},
		{name: "ranking", scope: scope, request: request, input: input, ranking: unpinned, selection: selection, auth: auth, want: ErrRouteAuditRecordMismatch},
		{name: "scope", scope: otherScope, request: request, input: input, ranking: ranking, selection: selection, auth: auth, want: ErrRouteAuditScopeMismatch},
		{name: "empty authorization", scope: scope, request: request, input: input, ranking: ranking, selection: selection, auth: RouteAttemptAuthorization{}, want: ErrInvalidRouteAttemptKind},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ledger := audit.NewMemoryLedger()
			if _, err := RecordRouteSelection(context.Background(), ledger, scope, selection, time.UnixMilli(1)); err != nil {
				t.Fatal(err)
			}
			event, acquired, err := ClaimStrictInitialLocalRouteAttempt(context.Background(), ledger, tc.scope, tc.request, tc.input, tc.ranking, tc.selection, tc.auth, time.UnixMilli(2))
			if !errors.Is(err, tc.want) || acquired || event.Identity() != "" {
				t.Fatalf("claim=(%#v,%t,%v) want %v", event, acquired, err, tc.want)
			}
			events, err := ledger.Read(context.Background(), scope, 0, 10)
			if err != nil || len(events) != 1 {
				t.Fatalf("events=(%d,%v)", len(events), err)
			}
		})
	}
}

func TestStrictInitialLocalClaimConcurrentOneAcquisition(t *testing.T) {
	for _, storage := range []string{"memory", "file"} {
		t.Run(storage, func(t *testing.T) {
			var ledger audit.Ledger = audit.NewMemoryLedger()
			if storage == "file" {
				file, err := audit.NewFileLedger(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := file.Close(); err != nil {
						t.Error(err)
					}
				})
				ledger = file
			}
			scope, request, input, ranking, selection, auth := strictLocalFixture(t)
			ctx := context.Background()
			if _, err := RecordRouteSelection(ctx, ledger, scope, selection, time.UnixMilli(1)); err != nil {
				t.Fatal(err)
			}
			type result struct {
				event    audit.Event
				acquired bool
				err      error
			}
			results := make(chan result, 8)
			var group sync.WaitGroup
			for range 8 {
				group.Add(1)
				go func() {
					defer group.Done()
					event, acquired, err := ClaimStrictInitialLocalRouteAttempt(ctx, ledger, scope, request, input, ranking, selection, auth, time.UnixMilli(2))
					results <- result{event, acquired, err}
				}()
			}
			group.Wait()
			close(results)
			acquiredCount := 0
			identity := ""
			for result := range results {
				if result.err != nil {
					t.Fatal(result.err)
				}
				if result.acquired {
					acquiredCount++
				}
				if identity == "" {
					identity = result.event.Identity()
				} else if identity != result.event.Identity() {
					t.Fatal("claim event identities differ")
				}
			}
			if acquiredCount != 1 {
				t.Fatalf("acquired count=%d", acquiredCount)
			}
			events, err := ledger.Read(ctx, scope, 0, 10)
			if err != nil || len(events) != 2 {
				t.Fatalf("events=(%d,%v)", len(events), err)
			}
		})
	}
}

func TestStrictInitialLocalClaimRejectsLocalPlusRemotePolicy(t *testing.T) {
	for _, remote := range []provider.ProviderZone{provider.ProviderZonePrivateRemote, provider.ProviderZoneBrokeredRemote, provider.ProviderZoneSubscriptionOAuth} {
		t.Run(remote.String(), func(t *testing.T) {
			scope, request, input, ranking, selection, auth := strictLocalFixtureWithZones(t, provider.ProviderZoneLocal, remote)
			ledger := audit.NewMemoryLedger()
			ctx := context.Background()
			if _, err := RecordRouteSelection(ctx, ledger, scope, selection, time.UnixMilli(1)); err != nil {
				t.Fatal(err)
			}
			event, acquired, err := ClaimStrictInitialLocalRouteAttempt(ctx, ledger, scope, request, input, ranking, selection, auth, time.UnixMilli(2))
			if !errors.Is(err, ErrRouteAuditRecordMismatch) || acquired || event.Identity() != "" {
				t.Fatalf("mixed-zone claim = (%#v,%t,%v), want mismatch and no acquisition", event, acquired, err)
			}
			events, err := ledger.Read(ctx, scope, 0, 10)
			if err != nil || len(events) != 1 {
				t.Fatalf("events=(%d,%v), want only selection", len(events), err)
			}
		})
	}
}

// appendCompetingClaimLedger inserts a same-subject claim just before the candidate CAS append.
type appendCompetingClaimLedger struct {
	audit.Ledger
	inserted bool
	parents  []string
}

func (l *appendCompetingClaimLedger) Append(ctx context.Context, previous string, event audit.Event) error {
	if event.Kind() == audit.EventRouteAttemptClaimed && !l.inserted {
		l.inserted = true
		competing, err := audit.NewEvent(event.Scope(), event.Sequence(), previous, audit.EventRouteAttemptClaimed, event.SubjectIdentity(), l.parents, time.UnixMilli(10))
		if err != nil {
			return err
		}
		if err := l.Ledger.Append(ctx, previous, competing); err != nil {
			return err
		}
	}
	return l.Ledger.Append(ctx, previous, event)
}

func TestStrictInitialLocalClaimRescansCompetingSameSubjectCAS(t *testing.T) {
	for _, storage := range []string{"memory", "file"} {
		for _, wrong := range []bool{false, true} {
			name := storage + "/valid"
			if wrong {
				name = storage + "/wrong parent"
			}
			t.Run(name, func(t *testing.T) {
				var backing audit.Ledger = audit.NewMemoryLedger()
				if storage == "file" {
					file, err := audit.NewFileLedger(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := file.Close(); err != nil {
							t.Error(err)
						}
					})
					backing = file
				}
				scope, request, input, ranking, selection, auth := strictLocalFixture(t)
				ctx := context.Background()
				if _, err := RecordRouteSelection(ctx, backing, scope, selection, time.UnixMilli(1)); err != nil {
					t.Fatal(err)
				}
				parents := []string{selection.Identity(), input.Identity(), selection.SelectedRecordIdentity(), ranking.Identity()}
				if wrong {
					parents[2] = differentDigest(parents[2])
				}
				ledger := &appendCompetingClaimLedger{Ledger: backing, parents: parents}
				event, acquired, err := ClaimStrictInitialLocalRouteAttempt(ctx, ledger, scope, request, input, ranking, selection, auth, time.UnixMilli(2))
				if !ledger.inserted || acquired {
					t.Fatalf("competing append inserted=%t acquired=%t err=%v", ledger.inserted, acquired, err)
				}
				if wrong {
					if !errors.Is(err, ErrRouteAuditRecordMismatch) || event.Identity() != "" {
						t.Fatalf("wrong parent rescan=(%#v,%v)", event, err)
					}
				} else if err != nil || event.Kind() != audit.EventRouteAttemptClaimed || !routeAuditParentsMatch(event, parents) {
					t.Fatalf("valid competitor replay=(%#v,%v)", event, err)
				}
				events, err := backing.Read(ctx, scope, 0, 10)
				if err != nil || len(events) != 2 || events[1].Kind() != audit.EventRouteAttemptClaimed {
					t.Fatalf("events=(%d,%v), want selection and sole competing claim", len(events), err)
				}
			})
		}
	}
}
