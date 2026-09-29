package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

var (
	errInvalidSanitizedDispatchProof  = errors.New("invalid sanitized egress dispatch proof")
	errUnsupportedSanitizedDispatcher = errors.New("dispatcher does not accept sanitized egress proof")
)

type sanitizedDispatchKind string

const (
	sanitizedDispatchGeneration   sanitizedDispatchKind = "generation"
	sanitizedDispatchVerification sanitizedDispatchKind = "verification"
)

// SanitizedDispatchProof is an opaque witness created only by trusted model handlers.
type SanitizedDispatchProof struct {
	identity            string
	kind                sanitizedDispatchKind
	reviewScopeIdentity string
	requestIdentity     string
	receiptIdentity     string
}

func newGenerationDispatchProof(raw, requestArtifact, receiptArtifact artifact.Artifact, expected review.ScannerBinaryDigests) (SanitizedDispatchProof, error) {
	if review.ValidateSanitizedEgressArtifacts(raw, requestArtifact, receiptArtifact, expected) != nil {
		return SanitizedDispatchProof{}, errInvalidSanitizedDispatchProof
	}
	return sanitizedProofFromArtifacts(sanitizedDispatchGeneration, requestArtifact, receiptArtifact)
}

func newVerificationDispatchProof(
	raw provider.Request,
	generationContextIdentity, candidateBatchIdentity string,
	generation, generationInput, generationContext artifact.Artifact,
	requestArtifact, receiptArtifact artifact.Artifact,
	expected review.ScannerBinaryDigests,
) (SanitizedDispatchProof, error) {
	if review.ValidateSanitizedVerificationEgressArtifacts(
		raw, generationContextIdentity, candidateBatchIdentity,
		generation, generationInput, generationContext,
		requestArtifact, receiptArtifact, expected,
	) != nil {
		return SanitizedDispatchProof{}, errInvalidSanitizedDispatchProof
	}
	return sanitizedProofFromArtifacts(sanitizedDispatchVerification, requestArtifact, receiptArtifact)
}

func sanitizedProofFromArtifacts(kind sanitizedDispatchKind, requestArtifact, receiptArtifact artifact.Artifact) (SanitizedDispatchProof, error) {
	sanitized, requestErr := review.ParseSanitizedModelRequest(requestArtifact.Payload())
	receipt, receiptErr := review.ParseSanitizedEgressReceipt(receiptArtifact.Payload())
	request, providerErr := sanitized.ProviderRequest()
	if requestErr != nil || receiptErr != nil || providerErr != nil ||
		receipt.SanitizedRequestIdentity() != request.Identity() ||
		receipt.ReviewScopeIdentity() != sanitized.ReviewScopeIdentity() {
		return SanitizedDispatchProof{}, errInvalidSanitizedDispatchProof
	}
	switch kind {
	case sanitizedDispatchGeneration:
		if review.ValidateCandidateEgressRequest(request, receipt.ReviewScopeIdentity()) != nil {
			return SanitizedDispatchProof{}, errInvalidSanitizedDispatchProof
		}
	case sanitizedDispatchVerification:
		if review.ValidateVerificationEgressRequest(request, receipt.ReviewScopeIdentity()) != nil {
			return SanitizedDispatchProof{}, errInvalidSanitizedDispatchProof
		}
	default:
		return SanitizedDispatchProof{}, errInvalidSanitizedDispatchProof
	}
	proof := SanitizedDispatchProof{
		kind: kind, reviewScopeIdentity: receipt.ReviewScopeIdentity(),
		requestIdentity: request.Identity(), receiptIdentity: receipt.Identity(),
	}
	proof.identity = deriveSanitizedDispatchProofIdentity(proof)
	if proof.validate() != nil {
		return SanitizedDispatchProof{}, errInvalidSanitizedDispatchProof
	}
	return proof, nil
}

// ReceiptIdentity returns the validated receipt identity or an empty string.
func (p SanitizedDispatchProof) ReceiptIdentity() string {
	if p.validate() != nil {
		return ""
	}
	return p.receiptIdentity
}

// ValidateRequest verifies that the proof belongs to the exact authorized request and scope.
func (p SanitizedDispatchProof) ValidateRequest(reviewScopeIdentity, requestIdentity string) error {
	if p.validate() != nil || p.reviewScopeIdentity != reviewScopeIdentity || p.requestIdentity != requestIdentity {
		return errInvalidSanitizedDispatchProof
	}
	return nil
}

func (p SanitizedDispatchProof) validate() error {
	if p.kind != sanitizedDispatchGeneration && p.kind != sanitizedDispatchVerification ||
		!validSanitizedDispatchIdentity(p.identity) || !validSanitizedDispatchIdentity(p.reviewScopeIdentity) ||
		!validSanitizedDispatchIdentity(p.requestIdentity) || !validSanitizedDispatchIdentity(p.receiptIdentity) ||
		p.identity != deriveSanitizedDispatchProofIdentity(p) {
		return errInvalidSanitizedDispatchProof
	}
	return nil
}

func deriveSanitizedDispatchProofIdentity(p SanitizedDispatchProof) string {
	encoded, err := json.Marshal(struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Kind     string `json:"kind"`
		Scope    string `json:"scope"`
		Request  string `json:"request"`
		Receipt  string `json:"receipt"`
	}{"open-trestle/sanitized-egress-dispatch-proof", 1, string(p.kind), p.reviewScopeIdentity, p.requestIdentity, p.receiptIdentity})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func validSanitizedDispatchIdentity(identity string) bool {
	if len(identity) != sha256.Size*2 || identity != strings.ToLower(identity) {
		return false
	}
	decoded, err := hex.DecodeString(identity)
	if err != nil {
		return false
	}
	for _, value := range decoded {
		if value != 0 {
			return true
		}
	}
	return false
}

// SanitizedRouteDispatcher accepts proof-bearing dispatch from the trusted model handlers.
type SanitizedRouteDispatcher interface {
	gateway.RouteDispatcher
	DispatchSanitizedRoute(context.Context, gateway.RouteDispatchRequest, SanitizedDispatchProof) gateway.RouteDispatchResult
}

type sanitizedProofDispatcher struct {
	dispatcher SanitizedRouteDispatcher
	proof      SanitizedDispatchProof
}

func (d sanitizedProofDispatcher) AdapterID() string { return d.dispatcher.AdapterID() }
func (d sanitizedProofDispatcher) ConfigurationIdentity() string {
	return d.dispatcher.ConfigurationIdentity()
}
func (d sanitizedProofDispatcher) DispatchRoute(ctx context.Context, request gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	if d.proof.ValidateRequest(request.Authorization().ReviewScopeIdentity(), request.Request().Identity()) != nil {
		result, _ := gateway.NewFailedRouteDispatchResult(gateway.RouteFailurePolicyDenied, gateway.RouteReplayNotDispatched, provider.NewUnknownRouteTokenUsage(), 0)
		return result
	}
	return d.dispatcher.DispatchSanitizedRoute(ctx, request, d.proof)
}

func dispatchAuthorizedSanitizedRouteFromCatalog(ctx context.Context, catalog gateway.RouteDispatcherCatalog, authorization gateway.RouteAttemptAuthorization, request provider.Request, proof SanitizedDispatchProof) (gateway.RouteDispatchResult, error) {
	if proof.ValidateRequest(authorization.ReviewScopeIdentity(), request.Identity()) != nil {
		return gateway.RouteDispatchResult{}, errInvalidSanitizedDispatchProof
	}
	if err := catalog.Validate(); err != nil {
		return gateway.RouteDispatchResult{}, err
	}
	raw, exists := catalog.Resolve(authorization.RouteReference().AdapterID())
	if !exists {
		return gateway.RouteDispatchResult{}, gateway.ErrRouteDispatcherNotRegistered
	}
	dispatcher, ok := raw.(SanitizedRouteDispatcher)
	if !ok {
		return gateway.RouteDispatchResult{}, errUnsupportedSanitizedDispatcher
	}
	return gateway.DispatchAuthorizedRoute(ctx, sanitizedProofDispatcher{dispatcher: dispatcher, proof: proof}, authorization, request)
}
