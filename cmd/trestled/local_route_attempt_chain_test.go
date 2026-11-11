package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

type routeAttemptSpec struct {
	kind    audit.EventKind
	subject string
	parents []string
}

func routeAttemptDigest(name string, n int) string {
	sum := sha256.Sum256([]byte(fmt.Sprint(name, n)))
	return hex.EncodeToString(sum[:])
}

// routeAttemptSpecs is one model request as the handler records it: its
// selection, refused rate-limited attempts and a final attempt that returned a
// response. Selections and attempts of a second request start at offset.
func routeAttemptSpecs(refused, offset int, final bool) []routeAttemptSpec {
	selection := routeAttemptDigest("selection", offset)
	specs := []routeAttemptSpec{{audit.EventRouteSelected, selection, []string{routeAttemptDigest("input", offset), routeAttemptDigest("record", offset), routeAttemptDigest("ranking", offset)}}}
	parents := []string{selection}
	for i := offset; i <= offset+refused; i++ {
		authorization, outcome := routeAttemptDigest("authorization", i), routeAttemptDigest("outcome", i)
		specs = append(specs, routeAttemptSpec{audit.EventRouteAttemptClaimed, authorization, parents})
		if i == offset+refused && !final {
			break
		}
		dispatch := []string{authorization, routeAttemptDigest("dispatch", i)}
		if i == offset+refused {
			dispatch = append(dispatch, routeAttemptDigest("response", i))
		}
		specs = append(specs, routeAttemptSpec{audit.EventRouteDispatchCompleted, outcome, dispatch}, routeAttemptSpec{audit.EventRouteCostReconciled, routeAttemptDigest("reconciliation", i), []string{authorization, outcome}})
		parents = []string{selection, outcome, routeAttemptDigest("decision", i)}
	}
	return specs
}

func routeAttemptStream(t *testing.T, specs []routeAttemptSpec) []audit.Event {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-route-attempts")
	if err != nil {
		t.Fatal(err)
	}
	events, previous := make([]audit.Event, len(specs)), ""
	for i, spec := range specs {
		event, err := audit.NewEvent(scope, uint64(i+1), previous, spec.kind, spec.subject, spec.parents, time.UnixMilli(1_800_000_000_000+int64(i)))
		if err != nil {
			t.Fatal(err)
		}
		events[i], previous = event, event.Identity()
	}
	return events
}

// The handler's same-route retry shape is read back attempt by attempt:
// at most two refused attempts, each naming its refused outcome and decision.
func TestRecordedRouteAttemptsReadTheSameRouteRetryShape(t *testing.T) {
	for refused := 0; refused <= 2; refused++ {
		events := routeAttemptStream(t, routeAttemptSpecs(refused, 0, true))
		attempts, ok := recordedRouteAttempts(events, 1, events[0].SubjectIdentity())
		if !ok || len(attempts) != refused+1 || attempts[0].claim != 1 || attempts[0].previousOutcome != "" || attempts[0].decision != "" {
			t.Fatalf("refused %d: %v %+v", refused, ok, attempts)
		}
		for depth, attempt := range attempts[1:] {
			if attempt.claim != 1+3*(depth+1) || attempt.previousOutcome != routeAttemptDigest("outcome", depth) || attempt.decision != routeAttemptDigest("decision", depth) {
				t.Fatalf("refused %d depth %d: %+v", refused, depth+1, attempt)
			}
		}
	}
	for name, edit := range map[string]func([]routeAttemptSpec) []routeAttemptSpec{
		"three refused attempts": func([]routeAttemptSpec) []routeAttemptSpec { return routeAttemptSpecs(3, 0, true) },
		"refused attempt with a response": func(specs []routeAttemptSpec) []routeAttemptSpec {
			specs[2].parents = append(specs[2].parents, routeAttemptDigest("response", 0))
			return specs
		},
		"retry without a decision": func(specs []routeAttemptSpec) []routeAttemptSpec {
			specs[4].parents = specs[4].parents[:2]
			return specs
		},
		"retry after another outcome": func(specs []routeAttemptSpec) []routeAttemptSpec {
			specs[4].parents[1] = routeAttemptDigest("outcome", 9)
			return specs
		},
		"retry from another selection": func(specs []routeAttemptSpec) []routeAttemptSpec {
			specs[4].parents[0] = routeAttemptDigest("selection", 9)
			return specs
		},
		"retry repeating the authorization": func(specs []routeAttemptSpec) []routeAttemptSpec {
			specs[4].subject = specs[1].subject
			return specs
		},
		"first claim with a lineage": func(specs []routeAttemptSpec) []routeAttemptSpec {
			specs[1].parents = append(specs[1].parents, routeAttemptDigest("decision", 9))
			return specs
		},
		"dispatch of another attempt": func(specs []routeAttemptSpec) []routeAttemptSpec {
			specs[2].parents[0] = routeAttemptDigest("authorization", 9)
			return specs
		},
		"reconciliation of another outcome": func(specs []routeAttemptSpec) []routeAttemptSpec {
			specs[3].parents[1] = routeAttemptDigest("outcome", 9)
			return specs
		},
	} {
		events := routeAttemptStream(t, edit(routeAttemptSpecs(1, 0, true)))
		if attempts, ok := recordedRouteAttempts(events, 1, events[0].SubjectIdentity()); ok {
			t.Fatalf("%s admitted: %+v", name, attempts)
		}
	}
}

// A lease-expired model tail is the generation request's attempts, ending in
// its final reconciliation, and for verification the verification selection
// and its attempts ending in the claim the lease ended at. A tail that stops
// between a refused attempt and its retry is not that shape.
func TestTerminalExpiryAuditShapeAcceptsOnlyTheRetryShape(t *testing.T) {
	verification := func(generation, refused int, final bool) []routeAttemptSpec {
		return append(routeAttemptSpecs(generation, 0, true), routeAttemptSpecs(refused, 10, final)...)
	}
	for _, test := range []struct {
		name         string
		specs        []routeAttemptSpec
		verification bool
		ok           bool
	}{
		{"candidate", routeAttemptSpecs(0, 0, true), false, true},
		{"retried candidate", routeAttemptSpecs(2, 0, true), false, true},
		{"candidate with verification", verification(0, 0, false), false, false},
		{"candidate ended at a claim", routeAttemptSpecs(1, 0, false), false, false},
		{"candidate missing a reconciliation", slices.Delete(routeAttemptSpecs(1, 0, true), 3, 4), false, false},
		{"candidate refused at its end", routeAttemptSpecs(0, 0, true)[:3], false, false},
		{"verification claim", verification(0, 0, false), true, true},
		{"retried verification claim", verification(2, 2, false), true, true},
		{"verification without a claim", routeAttemptSpecs(0, 0, true)[:4:4], true, false},
		{"verification ended at a refusal", verification(1, 1, false)[:11], true, false},
		{"verification after its dispatch", verification(0, 0, true), true, false},
		{"three refused verification attempts", verification(0, 3, false), true, false},
	} {
		if got := terminalExpiryAuditShape(routeAttemptStream(t, test.specs), test.verification); got != test.ok {
			t.Fatalf("%s: shape %t, want %t", test.name, got, test.ok)
		}
	}
}

// A rejected generation's audit is its attempts followed by the rejection.
func TestGenerationRejectionAuditShapeAcceptsOnlyTheRetryShape(t *testing.T) {
	rejected := func(specs []routeAttemptSpec) []routeAttemptSpec {
		return append(specs, routeAttemptSpec{audit.EventGenerationRejected, routeAttemptDigest("rejection", 0), []string{routeAttemptDigest("input", 0), routeAttemptDigest("packet", 0), routeAttemptDigest("attempt", 0)}})
	}
	for _, test := range []struct {
		name  string
		specs []routeAttemptSpec
		ok    bool
	}{
		{"rejection", rejected(routeAttemptSpecs(0, 0, true)), true},
		{"retried rejection", rejected(routeAttemptSpecs(2, 0, true)), true},
		{"no rejection", routeAttemptSpecs(2, 0, true), false},
		{"rejection without a final dispatch", rejected(routeAttemptSpecs(1, 0, false)), false},
		{"rejection after three refusals", rejected(routeAttemptSpecs(3, 0, true)), false},
	} {
		if got := generationRejectionAuditShape(routeAttemptStream(t, test.specs)); got != test.ok {
			t.Fatalf("%s: shape %t, want %t", test.name, got, test.ok)
		}
	}
}
