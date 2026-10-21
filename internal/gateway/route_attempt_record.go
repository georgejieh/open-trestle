package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrInvalidCompletedRouteAttemptRecord identifies incomplete or cross-wired accounting.
var ErrInvalidCompletedRouteAttemptRecord = errors.New("invalid completed route attempt record")

// CompletedRouteAttemptRecord preserves settled accounting without claiming admitted output.
// It contains identities and accounting only, never provider request or response content.
type CompletedRouteAttemptRecord struct {
	identity       string
	authorization  RouteAttemptAuthorization
	outcome        RouteAttemptOutcome
	reconciliation RouteCostReconciliation
}

func NewCompletedRouteAttemptRecord(authorization RouteAttemptAuthorization, outcome RouteAttemptOutcome, reconciliation RouteCostReconciliation) (CompletedRouteAttemptRecord, error) {
	value := CompletedRouteAttemptRecord{authorization: authorization, outcome: outcome, reconciliation: reconciliation}
	value.identity = value.deriveIdentity()
	if value.Validate() != nil {
		return CompletedRouteAttemptRecord{}, ErrInvalidCompletedRouteAttemptRecord
	}
	return value, nil
}
func (r CompletedRouteAttemptRecord) Identity() string { return r.identity }
func (r CompletedRouteAttemptRecord) Authorization() RouteAttemptAuthorization {
	return r.authorization
}
func (r CompletedRouteAttemptRecord) Outcome() RouteAttemptOutcome { return r.outcome }
func (r CompletedRouteAttemptRecord) Reconciliation() RouteCostReconciliation {
	return r.reconciliation
}
func (r CompletedRouteAttemptRecord) Validate() error {
	if r.authorization.Validate() != nil || r.outcome.Validate() != nil || r.reconciliation.Validate() != nil || r.outcome.AuthorizationIdentity() != r.authorization.Identity() {
		return ErrInvalidCompletedRouteAttemptRecord
	}
	expected, err := ReconcileAuthorizedRouteAttemptCost(r.authorization, r.outcome)
	if err != nil || expected.Identity() != r.reconciliation.Identity() || r.identity != r.deriveIdentity() {
		return ErrInvalidCompletedRouteAttemptRecord
	}
	return nil
}

// DispatchResultIdentity derives the audited result identity from validated accounting.
// It does not recreate or validate response content.
func (r CompletedRouteAttemptRecord) DispatchResultIdentity() (string, error) {
	if r.Validate() != nil {
		return "", ErrInvalidCompletedRouteAttemptRecord
	}
	status := RouteDispatchFailed
	if r.outcome.Status() == RouteAttemptSucceeded {
		status = RouteDispatchSucceeded
	}
	return deriveRouteDispatchIdentity(r.authorization.Identity(), status, r.outcome.ResponseIdentity(), r.outcome.Failure(), r.outcome.ReplaySafety(), r.outcome.Usage(), r.outcome.RetryAfterMilliseconds()), nil
}

func (r CompletedRouteAttemptRecord) deriveIdentity() string {
	encoded, err := json.Marshal([]any{"open-trestle/completed-route-attempt", 1, r.authorization.Identity(), r.outcome.Identity(), r.reconciliation.Identity()})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func (r CompletedRouteAttemptRecord) String() string { return "completed route attempt record" }
func (r CompletedRouteAttemptRecord) GoString() string {
	return "gateway.CompletedRouteAttemptRecord{<redacted>}"
}
func (r CompletedRouteAttemptRecord) Format(s fmt.State, verb rune) {
	value := "completed route attempt record"
	if verb == 'q' {
		value = `"completed route attempt record"`
	} else if verb == 'v' && s.Flag('#') {
		value = "gateway.CompletedRouteAttemptRecord{<redacted>}"
	}
	_, _ = s.Write([]byte(value))
}

type completedRouteAttemptWire struct {
	Contract       string                  `json:"contract"`
	SchemaVersion  int                     `json:"schema_version"`
	Identity       string                  `json:"identity"`
	Authorization  routeAuthorizationWire  `json:"authorization"`
	Outcome        routeOutcomeWire        `json:"outcome"`
	Reconciliation routeReconciliationWire `json:"reconciliation"`
}

func EncodeCompletedRouteAttemptRecord(record CompletedRouteAttemptRecord) ([]byte, error) {
	if record.Validate() != nil {
		return nil, ErrInvalidCompletedRouteAttemptRecord
	}
	encoded, err := json.Marshal(completedRouteAttemptWire{"open-trestle/completed-route-attempt", 1, record.Identity(), routeAuthorizationWireValue(record.Authorization()), routeOutcomeWireValue(record.Outcome()), routeReconciliationWireValue(record.Reconciliation())})
	if err != nil || len(encoded) > maximumRouteRecordEncodingBytes {
		return nil, ErrInvalidCompletedRouteAttemptRecord
	}
	return encoded, nil
}
func ParseCompletedRouteAttemptRecord(encoded []byte) (CompletedRouteAttemptRecord, error) {
	fail := func() (CompletedRouteAttemptRecord, error) {
		return CompletedRouteAttemptRecord{}, ErrInvalidCompletedRouteAttemptRecord
	}
	if len(encoded) == 0 || len(encoded) > maximumRouteRecordEncodingBytes {
		return fail()
	}
	var wire completedRouteAttemptWire
	if decodeCanonicalRouteRecord(encoded, &wire) != nil || wire.Contract != "open-trestle/completed-route-attempt" || wire.SchemaVersion != 1 {
		return fail()
	}
	authorization, err := parseRouteAuthorizationWire(wire.Authorization)
	if err != nil {
		return fail()
	}
	outcome, err := parseRouteOutcomeWire(authorization, wire.Outcome)
	if err != nil {
		return fail()
	}
	cost, err := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	if err != nil || !reconciliationWireMatches(wire.Reconciliation, cost) {
		return fail()
	}
	record, err := NewCompletedRouteAttemptRecord(authorization, outcome, cost)
	if err != nil || record.Identity() != wire.Identity {
		return fail()
	}
	canonical, err := EncodeCompletedRouteAttemptRecord(record)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return fail()
	}
	return record, nil
}
