package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrInvalidRouteIndependenceLevel identifies an unknown independence requirement.
	ErrInvalidRouteIndependenceLevel = errors.New("invalid route independence level")
	// ErrInvalidRouteIndependencePolicyIdentity identifies policy content inconsistent with its identity.
	ErrInvalidRouteIndependencePolicyIdentity = errors.New("invalid route independence policy identity")
	// ErrRouteIndependenceRequiresSuccess identifies a non-successful generation or verification attempt.
	ErrRouteIndependenceRequiresSuccess = errors.New("route independence requires successful attempts")
	// ErrRouteIndependenceScopeMismatch identifies attempts from different review scopes.
	ErrRouteIndependenceScopeMismatch = errors.New("route independence scope mismatch")
	// ErrRouteIndependenceRequestMismatch identifies reuse of the candidate-generation request for verification.
	ErrRouteIndependenceRequestMismatch = errors.New("route independence request mismatch")
	// ErrRouteAttemptsNotIndependent identifies routes that fail the configured independence level.
	ErrRouteAttemptsNotIndependent = errors.New("route attempts are not independent")
	// ErrInvalidRouteIndependenceReceipt identifies inconsistent receipt fields.
	ErrInvalidRouteIndependenceReceipt = errors.New("invalid route independence receipt")
	// ErrInvalidRouteIndependenceReceiptIdentity identifies receipt content inconsistent with its identity.
	ErrInvalidRouteIndependenceReceiptIdentity = errors.New("invalid route independence receipt identity")
)

// RouteIndependenceLevel identifies the minimum separation between generation and verification.
type RouteIndependenceLevel uint8

const (
	RouteIndependenceDistinctRoute RouteIndependenceLevel = iota + 1
	RouteIndependenceDistinctModel
	RouteIndependenceDistinctProvider
)

func (l RouteIndependenceLevel) String() string {
	switch l {
	case RouteIndependenceDistinctRoute:
		return "distinct_route"
	case RouteIndependenceDistinctModel:
		return "distinct_model"
	case RouteIndependenceDistinctProvider:
		return "distinct_provider"
	default:
		return ""
	}
}

// ParseRouteIndependenceLevel parses one exact stable independence token.
func ParseRouteIndependenceLevel(value string) (RouteIndependenceLevel, error) {
	for level := RouteIndependenceDistinctRoute; level <= RouteIndependenceDistinctProvider; level++ {
		if level.String() == value {
			return level, nil
		}
	}
	return 0, ErrInvalidRouteIndependenceLevel
}

func (l RouteIndependenceLevel) Validate() error {
	if l.String() == "" {
		return ErrInvalidRouteIndependenceLevel
	}
	return nil
}

// RouteIndependencePolicy is a content-addressed verifier separation requirement.
type RouteIndependencePolicy struct {
	identity string
	level    RouteIndependenceLevel
}

// NewRouteIndependencePolicy creates a closed independence policy.
func NewRouteIndependencePolicy(level RouteIndependenceLevel) (RouteIndependencePolicy, error) {
	if err := level.Validate(); err != nil {
		return RouteIndependencePolicy{}, err
	}
	policy := RouteIndependencePolicy{level: level}
	policy.identity = deriveRouteIndependencePolicyIdentity(policy)
	return policy, nil
}

func (p RouteIndependencePolicy) Identity() string              { return p.identity }
func (p RouteIndependencePolicy) Level() RouteIndependenceLevel { return p.level }
func (p RouteIndependencePolicy) String() string                { return "route independence policy" }
func (p RouteIndependencePolicy) GoString() string {
	return "gateway.RouteIndependencePolicy{<redacted>}"
}
func (p RouteIndependencePolicy) Format(state fmt.State, verb rune) {
	formatted := "route independence policy"
	if verb == 'q' {
		formatted = `"route independence policy"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteIndependencePolicy{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

func (p RouteIndependencePolicy) Validate() error {
	if err := p.level.Validate(); err != nil {
		return err
	}
	if p.identity != deriveRouteIndependencePolicyIdentity(p) {
		return ErrInvalidRouteIndependencePolicyIdentity
	}
	return nil
}

func deriveRouteIndependencePolicyIdentity(policy RouteIndependencePolicy) string {
	preimage := struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Level    string `json:"level"`
	}{
		Contract: "open-trestle/route-independence-policy", Version: 1,
		Level: policy.level.String(),
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// RouteIndependenceReceipt binds two successful attempts and their measured separation.
type RouteIndependenceReceipt struct {
	identity                    string
	policy                      RouteIndependencePolicy
	reviewScopeIdentity         string
	firstAuthorizationIdentity  string
	firstOutcomeIdentity        string
	firstRequestIdentity        string
	firstRecordIdentity         string
	firstRoute                  provider.RouteReference
	secondAuthorizationIdentity string
	secondOutcomeIdentity       string
	secondRequestIdentity       string
	secondRecordIdentity        string
	secondRoute                 provider.RouteReference
}

// VerifyIndependentRouteCandidate rejects an insufficient verifier candidate before selection.
func VerifyIndependentRouteCandidate(
	policy RouteIndependencePolicy,
	generation RouteAttemptAuthorization,
	candidate ObservedRouteCandidate,
) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	if err := candidate.Validate(); err != nil {
		return err
	}
	record := candidate.ResolvedRecord().RouteRegistryRecord()
	receipt := RouteIndependenceReceipt{
		policy:              policy,
		firstRecordIdentity: generation.RouteRecordIdentity(), firstRoute: generation.RouteReference(),
		secondRecordIdentity: record.Identity(), secondRoute: record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference(),
	}
	if !routeAttemptsSatisfyIndependence(receipt) {
		return ErrRouteAttemptsNotIndependent
	}
	return nil
}

// VerifyIndependentRouteAuthorizations rejects an insufficient verifier route before dispatch.
func VerifyIndependentRouteAuthorizations(
	policy RouteIndependencePolicy,
	firstAuthorization, secondAuthorization RouteAttemptAuthorization,
) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	if err := firstAuthorization.Validate(); err != nil {
		return err
	}
	if err := secondAuthorization.Validate(); err != nil {
		return err
	}
	if firstAuthorization.ReviewScopeIdentity() != secondAuthorization.ReviewScopeIdentity() {
		return ErrRouteIndependenceScopeMismatch
	}
	if firstAuthorization.RequestIdentity() == secondAuthorization.RequestIdentity() {
		return ErrRouteIndependenceRequestMismatch
	}
	receipt := RouteIndependenceReceipt{
		policy: policy, reviewScopeIdentity: firstAuthorization.ReviewScopeIdentity(),
		firstRecordIdentity: firstAuthorization.RouteRecordIdentity(), firstRoute: firstAuthorization.RouteReference(),
		secondRecordIdentity: secondAuthorization.RouteRecordIdentity(), secondRoute: secondAuthorization.RouteReference(),
	}
	if !routeAttemptsSatisfyIndependence(receipt) {
		return ErrRouteAttemptsNotIndependent
	}
	return nil
}

// VerifyIndependentRouteAttempts checks exact successful attempts against the configured separation.
func VerifyIndependentRouteAttempts(policy RouteIndependencePolicy, firstAuthorization RouteAttemptAuthorization, firstOutcome RouteAttemptOutcome, secondAuthorization RouteAttemptAuthorization, secondOutcome RouteAttemptOutcome) (RouteIndependenceReceipt, error) {
	if err := policy.Validate(); err != nil {
		return RouteIndependenceReceipt{}, err
	}
	if err := validateAttemptAndOutcome(firstAuthorization, firstOutcome); err != nil {
		return RouteIndependenceReceipt{}, err
	}
	if err := validateAttemptAndOutcome(secondAuthorization, secondOutcome); err != nil {
		return RouteIndependenceReceipt{}, err
	}
	if firstOutcome.Status() != RouteAttemptSucceeded || secondOutcome.Status() != RouteAttemptSucceeded {
		return RouteIndependenceReceipt{}, ErrRouteIndependenceRequiresSuccess
	}
	if err := VerifyIndependentRouteAuthorizations(policy, firstAuthorization, secondAuthorization); err != nil {
		return RouteIndependenceReceipt{}, err
	}
	receipt := RouteIndependenceReceipt{
		policy: policy, reviewScopeIdentity: firstAuthorization.ReviewScopeIdentity(),
		firstAuthorizationIdentity: firstAuthorization.Identity(), firstOutcomeIdentity: firstOutcome.Identity(),
		firstRequestIdentity: firstAuthorization.RequestIdentity(), firstRecordIdentity: firstAuthorization.RouteRecordIdentity(), firstRoute: firstAuthorization.RouteReference(),
		secondAuthorizationIdentity: secondAuthorization.Identity(), secondOutcomeIdentity: secondOutcome.Identity(),
		secondRequestIdentity: secondAuthorization.RequestIdentity(), secondRecordIdentity: secondAuthorization.RouteRecordIdentity(), secondRoute: secondAuthorization.RouteReference(),
	}
	if !routeAttemptsSatisfyIndependence(receipt) {
		return RouteIndependenceReceipt{}, ErrRouteAttemptsNotIndependent
	}
	receipt.identity = deriveRouteIndependenceReceiptIdentity(receipt)
	if err := receipt.Validate(); err != nil {
		return RouteIndependenceReceipt{}, err
	}
	return receipt, nil
}

func (r RouteIndependenceReceipt) Identity() string              { return r.identity }
func (r RouteIndependenceReceipt) PolicyIdentity() string        { return r.policy.Identity() }
func (r RouteIndependenceReceipt) Level() RouteIndependenceLevel { return r.policy.Level() }
func (r RouteIndependenceReceipt) ReviewScopeIdentity() string   { return r.reviewScopeIdentity }
func (r RouteIndependenceReceipt) FirstAuthorizationIdentity() string {
	return r.firstAuthorizationIdentity
}
func (r RouteIndependenceReceipt) FirstOutcomeIdentity() string { return r.firstOutcomeIdentity }
func (r RouteIndependenceReceipt) SecondAuthorizationIdentity() string {
	return r.secondAuthorizationIdentity
}
func (r RouteIndependenceReceipt) SecondOutcomeIdentity() string { return r.secondOutcomeIdentity }
func (r RouteIndependenceReceipt) String() string                { return "route independence receipt" }
func (r RouteIndependenceReceipt) GoString() string {
	return "gateway.RouteIndependenceReceipt{<redacted>}"
}
func (r RouteIndependenceReceipt) Format(state fmt.State, verb rune) {
	formatted := "route independence receipt"
	if verb == 'q' {
		formatted = `"route independence receipt"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteIndependenceReceipt{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies attempt identities, route semantics, policy, and content identity.
func (r RouteIndependenceReceipt) Validate() error {
	if err := r.policy.Validate(); err != nil {
		return err
	}
	for _, identity := range []string{
		r.reviewScopeIdentity, r.firstAuthorizationIdentity, r.firstOutcomeIdentity,
		r.firstRequestIdentity, r.firstRecordIdentity, r.secondAuthorizationIdentity,
		r.secondOutcomeIdentity, r.secondRequestIdentity, r.secondRecordIdentity,
	} {
		if !validRequestIdentity(identity) {
			return ErrInvalidRouteIndependenceReceipt
		}
	}
	if err := r.firstRoute.Validate(); err != nil {
		return err
	}
	if err := r.secondRoute.Validate(); err != nil {
		return err
	}
	if r.firstRequestIdentity == r.secondRequestIdentity || !routeAttemptsSatisfyIndependence(r) {
		return ErrInvalidRouteIndependenceReceipt
	}
	if r.identity != deriveRouteIndependenceReceiptIdentity(r) {
		return ErrInvalidRouteIndependenceReceiptIdentity
	}
	return nil
}

func routeAttemptsSatisfyIndependence(receipt RouteIndependenceReceipt) bool {
	if receipt.firstRecordIdentity == receipt.secondRecordIdentity {
		return false
	}
	switch receipt.policy.Level() {
	case RouteIndependenceDistinctRoute:
		return receipt.firstRoute != receipt.secondRoute
	case RouteIndependenceDistinctModel:
		return receipt.firstRoute.ProviderID() != receipt.secondRoute.ProviderID() || receipt.firstRoute.ModelID() != receipt.secondRoute.ModelID() || receipt.firstRoute.ModelVersion() != receipt.secondRoute.ModelVersion()
	case RouteIndependenceDistinctProvider:
		return receipt.firstRoute.ProviderID() != receipt.secondRoute.ProviderID()
	default:
		return false
	}
}

func deriveRouteIndependenceReceiptIdentity(receipt RouteIndependenceReceipt) string {
	preimage := struct {
		Contract            string `json:"contract"`
		Version             int    `json:"version"`
		Policy              string `json:"policy"`
		Scope               string `json:"scope"`
		FirstAuthorization  string `json:"first_authorization"`
		FirstOutcome        string `json:"first_outcome"`
		FirstRequest        string `json:"first_request"`
		FirstRecord         string `json:"first_record"`
		FirstProvider       string `json:"first_provider"`
		FirstModel          string `json:"first_model"`
		FirstModelVersion   string `json:"first_model_version"`
		SecondAuthorization string `json:"second_authorization"`
		SecondOutcome       string `json:"second_outcome"`
		SecondRequest       string `json:"second_request"`
		SecondRecord        string `json:"second_record"`
		SecondProvider      string `json:"second_provider"`
		SecondModel         string `json:"second_model"`
		SecondModelVersion  string `json:"second_model_version"`
	}{
		Contract: "open-trestle/route-independence-receipt", Version: 1,
		Policy: receipt.policy.Identity(), Scope: receipt.reviewScopeIdentity,
		FirstAuthorization: receipt.firstAuthorizationIdentity, FirstOutcome: receipt.firstOutcomeIdentity,
		FirstRequest: receipt.firstRequestIdentity, FirstRecord: receipt.firstRecordIdentity,
		FirstProvider: receipt.firstRoute.ProviderID(), FirstModel: receipt.firstRoute.ModelID(), FirstModelVersion: receipt.firstRoute.ModelVersion(),
		SecondAuthorization: receipt.secondAuthorizationIdentity, SecondOutcome: receipt.secondOutcomeIdentity,
		SecondRequest: receipt.secondRequestIdentity, SecondRecord: receipt.secondRecordIdentity,
		SecondProvider: receipt.secondRoute.ProviderID(), SecondModel: receipt.secondRoute.ModelID(), SecondModelVersion: receipt.secondRoute.ModelVersion(),
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
