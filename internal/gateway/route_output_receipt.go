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
	// ErrInvalidRouteOutputKind identifies an unknown normalized review artifact.
	ErrInvalidRouteOutputKind = errors.New("invalid route output kind")
	// ErrRouteOutputRequestMismatch identifies output associated with another provider request.
	ErrRouteOutputRequestMismatch = errors.New("route output request mismatch")
	// ErrRouteOutputRequiresSuccess identifies output claimed from a failed attempt.
	ErrRouteOutputRequiresSuccess = errors.New("route output requires successful attempt")
	// ErrInvalidRouteOutputReceipt identifies malformed or inconsistent output bindings.
	ErrInvalidRouteOutputReceipt = errors.New("invalid route output receipt")
	// ErrInvalidRouteOutputReceiptIdentity identifies receipt content inconsistent with its identity.
	ErrInvalidRouteOutputReceiptIdentity = errors.New("invalid route output receipt identity")
)

// RouteOutputKind identifies the normalized artifact admitted from a successful response.
type RouteOutputKind uint8

const (
	RouteOutputCandidateBatch RouteOutputKind = iota + 1
	RouteOutputVerificationBatch
)

func (k RouteOutputKind) String() string {
	switch k {
	case RouteOutputCandidateBatch:
		return "candidate_batch"
	case RouteOutputVerificationBatch:
		return "verification_batch"
	default:
		return ""
	}
}

// ParseRouteOutputKind parses one exact stable output token.
func ParseRouteOutputKind(value string) (RouteOutputKind, error) {
	for kind := RouteOutputCandidateBatch; kind <= RouteOutputVerificationBatch; kind++ {
		if kind.String() == value {
			return kind, nil
		}
	}
	return 0, ErrInvalidRouteOutputKind
}

func (k RouteOutputKind) Validate() error {
	if k.String() == "" {
		return ErrInvalidRouteOutputKind
	}
	return nil
}

// RouteOutputReceipt binds one normalized artifact to its exact successful route attempt.
type RouteOutputReceipt struct {
	identity              string
	kind                  RouteOutputKind
	reviewScopeIdentity   string
	contextIdentity       string
	artifactIdentity      string
	requestIdentity       string
	responseIdentity      string
	authorizationIdentity string
	outcomeIdentity       string
}

// NewSuccessfulRouteOutputReceipt creates a content-safe output lineage record.
func NewSuccessfulRouteOutputReceipt(kind RouteOutputKind, contextIdentity, artifactIdentity string, request provider.Request, authorization RouteAttemptAuthorization, outcome RouteAttemptOutcome) (RouteOutputReceipt, error) {
	if err := kind.Validate(); err != nil {
		return RouteOutputReceipt{}, err
	}
	if !validRequestIdentity(contextIdentity) || !validRequestIdentity(artifactIdentity) {
		return RouteOutputReceipt{}, ErrInvalidRouteOutputReceipt
	}
	if err := request.Validate(); err != nil {
		return RouteOutputReceipt{}, err
	}
	if err := validateAttemptAndOutcome(authorization, outcome); err != nil {
		return RouteOutputReceipt{}, err
	}
	if outcome.Status() != RouteAttemptSucceeded {
		return RouteOutputReceipt{}, ErrRouteOutputRequiresSuccess
	}
	if request.Identity() != authorization.RequestIdentity() {
		return RouteOutputReceipt{}, ErrRouteOutputRequestMismatch
	}
	receipt := RouteOutputReceipt{
		kind: kind, reviewScopeIdentity: authorization.ReviewScopeIdentity(),
		contextIdentity: contextIdentity, artifactIdentity: artifactIdentity,
		requestIdentity: request.Identity(), responseIdentity: outcome.ResponseIdentity(),
		authorizationIdentity: authorization.Identity(), outcomeIdentity: outcome.Identity(),
	}
	receipt.identity = deriveRouteOutputReceiptIdentity(receipt)
	if err := receipt.Validate(); err != nil {
		return RouteOutputReceipt{}, err
	}
	return receipt, nil
}

func (r RouteOutputReceipt) Identity() string              { return r.identity }
func (r RouteOutputReceipt) Kind() RouteOutputKind         { return r.kind }
func (r RouteOutputReceipt) ReviewScopeIdentity() string   { return r.reviewScopeIdentity }
func (r RouteOutputReceipt) ContextIdentity() string       { return r.contextIdentity }
func (r RouteOutputReceipt) ArtifactIdentity() string      { return r.artifactIdentity }
func (r RouteOutputReceipt) RequestIdentity() string       { return r.requestIdentity }
func (r RouteOutputReceipt) ResponseIdentity() string      { return r.responseIdentity }
func (r RouteOutputReceipt) AuthorizationIdentity() string { return r.authorizationIdentity }
func (r RouteOutputReceipt) OutcomeIdentity() string       { return r.outcomeIdentity }
func (r RouteOutputReceipt) String() string                { return "route output receipt" }
func (r RouteOutputReceipt) GoString() string              { return "gateway.RouteOutputReceipt{<redacted>}" }
func (r RouteOutputReceipt) Format(state fmt.State, verb rune) {
	formatted := "route output receipt"
	if verb == 'q' {
		formatted = `"route output receipt"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteOutputReceipt{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies all content identities, kind, attempt lineage, and receipt identity.
func (r RouteOutputReceipt) Validate() error {
	if err := r.kind.Validate(); err != nil {
		return err
	}
	for _, identity := range []string{
		r.reviewScopeIdentity, r.contextIdentity, r.artifactIdentity, r.requestIdentity,
		r.responseIdentity, r.authorizationIdentity, r.outcomeIdentity,
	} {
		if !validRequestIdentity(identity) {
			return ErrInvalidRouteOutputReceipt
		}
	}
	if r.identity != deriveRouteOutputReceiptIdentity(r) {
		return ErrInvalidRouteOutputReceiptIdentity
	}
	return nil
}

func deriveRouteOutputReceiptIdentity(receipt RouteOutputReceipt) string {
	preimage := struct {
		Contract      string `json:"contract"`
		Version       int    `json:"version"`
		Kind          string `json:"kind"`
		Scope         string `json:"scope"`
		Context       string `json:"context"`
		Artifact      string `json:"artifact"`
		Request       string `json:"request"`
		Response      string `json:"response"`
		Authorization string `json:"authorization"`
		Outcome       string `json:"outcome"`
	}{
		Contract: "open-trestle/route-output-receipt", Version: 1,
		Kind: receipt.kind.String(), Scope: receipt.reviewScopeIdentity,
		Context: receipt.contextIdentity, Artifact: receipt.artifactIdentity,
		Request: receipt.requestIdentity, Response: receipt.responseIdentity,
		Authorization: receipt.authorizationIdentity, Outcome: receipt.outcomeIdentity,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
