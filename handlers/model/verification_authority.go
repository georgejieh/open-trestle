package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// VerificationAuthority binds a distinct verifier route to one generation execution and request.
type VerificationAuthority struct {
	identity, requestIdentity, generationExecutionIdentity string
	generationAuthorization                                gateway.RouteAttemptAuthorization
	authorization                                          gateway.RouteAttemptAuthorization
	independencePolicy                                     gateway.RouteIndependencePolicy
}

// NewVerificationAuthority validates route separation before verifier dispatch.
func NewVerificationAuthority(
	request provider.Request,
	generation gateway.RouteExecutionRecord,
	authorization gateway.RouteAttemptAuthorization,
	policy gateway.RouteIndependencePolicy,
) (VerificationAuthority, error) {
	if request.Validate() != nil || generation.Validate() != nil || authorization.Validate() != nil ||
		policy.Validate() != nil || authorization.RequestIdentity() != request.Identity() ||
		authorization.ReviewScopeIdentity() != generation.Authorization().ReviewScopeIdentity() ||
		gateway.VerifyIndependentRouteAuthorizations(policy, generation.Authorization(), authorization) != nil {
		return VerificationAuthority{}, ErrInvalidVerificationAuthority
	}
	authority := VerificationAuthority{
		requestIdentity: request.Identity(), generationExecutionIdentity: generation.Identity(),
		generationAuthorization: generation.Authorization(), authorization: authorization,
		independencePolicy: policy,
	}
	authority.identity = deriveVerificationAuthorityIdentity(authority)
	if err := authority.Validate(); err != nil {
		return VerificationAuthority{}, err
	}
	return authority, nil
}

func (a VerificationAuthority) Identity() string        { return a.identity }
func (a VerificationAuthority) RequestIdentity() string { return a.requestIdentity }
func (a VerificationAuthority) GenerationExecutionIdentity() string {
	return a.generationExecutionIdentity
}
func (a VerificationAuthority) Authorization() gateway.RouteAttemptAuthorization {
	return a.authorization
}
func (a VerificationAuthority) IndependencePolicy() gateway.RouteIndependencePolicy {
	return a.independencePolicy
}
func (a VerificationAuthority) String() string   { return "verification authority" }
func (a VerificationAuthority) GoString() string { return "model.VerificationAuthority{<redacted>}" }
func (a VerificationAuthority) Format(state fmt.State, verb rune) {
	writeModelRedacted(state, verb, "verification authority", "model.VerificationAuthority{<redacted>}")
}

// Validate verifies immutable request, generation, policy, and route-separation fields.
func (a VerificationAuthority) Validate() error {
	if !validDigest(a.requestIdentity) || !validDigest(a.generationExecutionIdentity) ||
		a.generationAuthorization.Validate() != nil || a.authorization.Validate() != nil ||
		a.independencePolicy.Validate() != nil || a.authorization.RequestIdentity() != a.requestIdentity ||
		gateway.VerifyIndependentRouteAuthorizations(
			a.independencePolicy, a.generationAuthorization, a.authorization,
		) != nil || a.identity != deriveVerificationAuthorityIdentity(a) {
		return ErrInvalidVerificationAuthority
	}
	return nil
}

// MatchesGeneration revalidates the complete request and generation route.
func (a VerificationAuthority) MatchesGeneration(request provider.Request, generation gateway.RouteExecutionRecord) bool {
	return a.Validate() == nil && request.Validate() == nil && generation.Validate() == nil &&
		a.requestIdentity == request.Identity() && a.generationExecutionIdentity == generation.Identity() &&
		a.generationAuthorization.Identity() == generation.Authorization().Identity() &&
		a.authorization.RequestIdentity() == request.Identity() &&
		gateway.VerifyIndependentRouteAuthorizations(
			a.independencePolicy, generation.Authorization(), a.authorization,
		) == nil
}

func deriveVerificationAuthorityIdentity(authority VerificationAuthority) string {
	encoded, err := json.Marshal(struct {
		Contract                string `json:"contract"`
		SchemaVersion           int    `json:"schema_version"`
		Request                 string `json:"request"`
		GenerationExecution     string `json:"generation_execution"`
		GenerationAuthorization string `json:"generation_authorization"`
		Authorization           string `json:"authorization"`
		IndependencePolicy      string `json:"independence_policy"`
	}{
		"open-trestle/verification-authority", 1, authority.requestIdentity,
		authority.generationExecutionIdentity, authority.generationAuthorization.Identity(),
		authority.authorization.Identity(), authority.independencePolicy.Identity(),
	})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// VerificationAuthorizer selects one policy-approved route and durably records its selection.
type VerificationAuthorizer interface {
	Identity() string
	Authorize(context.Context, audit.ReviewScope, provider.Request, gateway.RouteExecutionRecord) (VerificationAuthority, error)
}
