package main

import (
	"slices"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/gateway"
)

// auditEventSpec is the kind, subject and causal parents a proof expects of
// one audit event.
type auditEventSpec struct {
	kind    audit.EventKind
	subject string
	parents []string
}

// recordedAuditEventSpec is the spec an event already checked by shape and
// lineage meets as recorded, for a refused attempt that left no artifact.
func recordedAuditEventSpec(event audit.Event) auditEventSpec {
	return auditEventSpec{event.Kind(), event.SubjectIdentity(), event.CausalParentIdentities()}
}

// recordedRouteAttempt is one route attempt claim of a model request in a
// closed audit stream: the claim's event index and, for a same-route retry,
// the refused outcome and the retry decision the claim names.
type recordedRouteAttempt struct {
	claim                     int
	previousOutcome, decision string
}

// recordedRouteAttempts reads the route attempts of one model request whose
// first claim is events[start] and whose route selection has the subject
// selection. It accepts only the shape the handler records after rate limits:
// the first attempt claimed after the selection alone, then at most
// gateway.MaxRateLimitRetries refused attempts, each a claim, a failed
// dispatch that returned no response and its cost reconciliation, followed by
// a retry claim caused by the selection, that refused outcome and one retry
// decision. The last element is the final attempt; the events after its claim
// are the caller's to check.
func recordedRouteAttempts(events []audit.Event, start int, selection string) ([]recordedRouteAttempt, bool) {
	if start < 0 || start >= len(events) || events[start].Kind() != audit.EventRouteAttemptClaimed || !slices.Equal(events[start].CausalParentIdentities(), []string{selection}) {
		return nil, false
	}
	attempts := []recordedRouteAttempt{{claim: start}}
	for i := start; i+3 < len(events) && events[i+3].Kind() == audit.EventRouteAttemptClaimed; i += 3 {
		if len(attempts) > gateway.MaxRateLimitRetries {
			return nil, false
		}
		authorization, completed, retry := events[i].SubjectIdentity(), events[i+1], events[i+3]
		outcome, parents := completed.SubjectIdentity(), retry.CausalParentIdentities()
		if completed.Kind() != audit.EventRouteDispatchCompleted || len(completed.CausalParentIdentities()) != 2 || !slices.Contains(completed.CausalParentIdentities(), authorization) || !reconciledRouteAttempt(events[i+2], authorization, outcome) {
			return nil, false
		}
		decision := slices.DeleteFunc(slices.Clone(parents), func(parent string) bool { return parent == selection || parent == outcome })
		if len(parents) != 3 || len(decision) != 1 || !slices.Contains(parents, selection) || !slices.Contains(parents, outcome) || retry.SubjectIdentity() == authorization {
			return nil, false
		}
		attempts = append(attempts, recordedRouteAttempt{claim: i + 3, previousOutcome: outcome, decision: decision[0]})
	}
	return attempts, true
}

// respondedRouteAttempt reports whether the claim events[claim] is followed by
// a dispatch that returned a response and that dispatch's cost reconciliation.
func respondedRouteAttempt(events []audit.Event, claim int) bool {
	if claim < 0 || claim+2 >= len(events) {
		return false
	}
	authorization, completed := events[claim].SubjectIdentity(), events[claim+1]
	return completed.Kind() == audit.EventRouteDispatchCompleted && len(completed.CausalParentIdentities()) == 3 && slices.Contains(completed.CausalParentIdentities(), authorization) && reconciledRouteAttempt(events[claim+2], authorization, completed.SubjectIdentity())
}

func reconciledRouteAttempt(event audit.Event, authorization, outcome string) bool {
	parents := []string{authorization, outcome}
	slices.Sort(parents)
	return event.Kind() == audit.EventRouteCostReconciled && slices.Equal(event.CausalParentIdentities(), parents)
}

// routeAttemptsGrantedFrom reports whether the first claim names initial and
// each retry claim names the authorization the gateway grants for that
// lineage from initial, so every recorded attempt kept initial's request,
// route, terms and reservation.
func routeAttemptsGrantedFrom(events []audit.Event, attempts []recordedRouteAttempt, initial gateway.RouteAttemptAuthorization) bool {
	if len(attempts) == 0 || events[attempts[0].claim].SubjectIdentity() != initial.Identity() {
		return false
	}
	for depth, attempt := range attempts[1:] {
		granted, ok := gateway.SameReservationRetryIdentity(initial, depth+1, attempt.previousOutcome, attempt.decision)
		if !ok || events[attempt.claim].SubjectIdentity() != granted {
			return false
		}
	}
	return true
}

// finalRouteAttemptIs reports whether authorization is the one the final
// recorded attempt claimed, with the same retry lineage.
func finalRouteAttemptIs(events []audit.Event, attempts []recordedRouteAttempt, authorization gateway.RouteAttemptAuthorization) bool {
	if len(attempts) == 0 {
		return false
	}
	final := attempts[len(attempts)-1]
	return events[final.claim].SubjectIdentity() == authorization.Identity() && authorization.PreviousOutcomeIdentity() == final.previousOutcome && authorization.ContinuationDecisionIdentity() == final.decision
}

// modelRequestAudit reads the selection at events[start] and its model
// request's route attempts. It returns the attempts, or false for anything
// but that shape.
func modelRequestAudit(events []audit.Event, start int) ([]recordedRouteAttempt, bool) {
	if start < 0 || start >= len(events) || events[start].Kind() != audit.EventRouteSelected {
		return nil, false
	}
	return recordedRouteAttempts(events, start+1, events[start].SubjectIdentity())
}

// terminalExpiryAuditShape reports whether a lease-expired model tail's
// closed audit stream is exactly the generation request's selection and route
// attempts, ending in the final attempt's response and reconciliation, and for
// a verification expiry then the verification request's selection and route
// attempts, ending in the claim the lease ended at.
func terminalExpiryAuditShape(events []audit.Event, verification bool) bool {
	generation, ok := modelRequestAudit(events, 0)
	if !ok || !respondedRouteAttempt(events, generation[len(generation)-1].claim) {
		return false
	}
	next := generation[len(generation)-1].claim + 3
	if !verification {
		return next == len(events)
	}
	attempts, ok := modelRequestAudit(events, next)
	return ok && attempts[len(attempts)-1].claim == len(events)-1
}

// generationRejectionAuditShape reports whether a rejected generation's closed
// audit stream is exactly its selection, its route attempts ending in the
// final attempt's response and reconciliation, and the rejection.
func generationRejectionAuditShape(events []audit.Event) bool {
	attempts, ok := modelRequestAudit(events, 0)
	if !ok || !respondedRouteAttempt(events, attempts[len(attempts)-1].claim) {
		return false
	}
	return attempts[len(attempts)-1].claim+4 == len(events) && events[len(events)-1].Kind() == audit.EventGenerationRejected
}
