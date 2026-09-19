package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrInvalidRequestIdentity identifies a malformed review request identity.
	ErrInvalidRequestIdentity = errors.New("invalid request identity")
	// ErrInvalidReviewRoutingInputIdentity identifies policy or requirements inconsistent with the input identity.
	ErrInvalidReviewRoutingInputIdentity = errors.New("invalid review routing input identity")
)

// ReviewRoutingInput binds immutable provider-neutral inputs for later route planning.
type ReviewRoutingInput struct {
	identity            string
	reviewScopeIdentity string
	requestIdentity     string
	modelRequirements   provider.ModelRequirements
	dataConstraints     policy.ProviderDataConstraints
}

// NewReviewRoutingInput creates a routing input without retaining request payload bytes.
func NewReviewRoutingInput(scope audit.ReviewScope, request provider.Request, requirements provider.ModelRequirements, constraints policy.ProviderDataConstraints) (ReviewRoutingInput, error) {
	if err := scope.Validate(); err != nil {
		return ReviewRoutingInput{}, fmt.Errorf("validate routing review scope: %w", err)
	}
	if err := request.Validate(); err != nil {
		return ReviewRoutingInput{}, fmt.Errorf("validate routing request: %w", err)
	}
	input := ReviewRoutingInput{
		reviewScopeIdentity: strings.Clone(scope.Identity()),
		requestIdentity:     strings.Clone(request.Identity()),
		modelRequirements:   requirements,
		dataConstraints:     constraints,
	}
	if err := input.validateFields(); err != nil {
		return ReviewRoutingInput{}, err
	}
	input.identity = deriveReviewRoutingInputIdentity(input)
	return input, nil
}

// Identity returns the content-derived request, requirements, and policy input identity.
func (i ReviewRoutingInput) Identity() string { return i.identity }

// ReviewScopeIdentity returns the tenant-owned review scope identity.
func (i ReviewRoutingInput) ReviewScopeIdentity() string { return i.reviewScopeIdentity }

// RequestIdentity returns the canonical request identity.
func (i ReviewRoutingInput) RequestIdentity() string { return i.requestIdentity }

// ModelRequirements returns the immutable model requirements.
func (i ReviewRoutingInput) ModelRequirements() provider.ModelRequirements {
	return i.modelRequirements
}

// ProviderDataConstraints returns the immutable provider data constraints.
func (i ReviewRoutingInput) ProviderDataConstraints() policy.ProviderDataConstraints {
	return i.dataConstraints
}

// Validate verifies that every routing input remains valid.
func (i ReviewRoutingInput) Validate() error {
	if err := i.validateFields(); err != nil {
		return err
	}
	if i.identity != deriveReviewRoutingInputIdentity(i) {
		return ErrInvalidReviewRoutingInputIdentity
	}
	return nil
}

func (i ReviewRoutingInput) validateFields() error {
	if !validRequestIdentity(i.requestIdentity) {
		return fmt.Errorf("validate routing request identity: %w", ErrInvalidRequestIdentity)
	}
	if !validRequestIdentity(i.reviewScopeIdentity) {
		return audit.ErrInvalidAuditScopeIdentity
	}
	if err := i.modelRequirements.Validate(); err != nil {
		return fmt.Errorf("validate routing model requirements: %w", err)
	}
	if err := i.dataConstraints.Validate(); err != nil {
		return fmt.Errorf("validate routing data constraints: %w", err)
	}
	return nil
}

func deriveReviewRoutingInputIdentity(input ReviewRoutingInput) string {
	features := input.modelRequirements.RequiredFeatures()
	featureTokens := make([]string, len(features))
	for index, feature := range features {
		featureTokens[index] = feature.String()
	}
	zoneTokens := make([]string, 0, 4)
	zones := input.dataConstraints.AllowedProviderZones()
	for zone := provider.ProviderZoneLocal; zone <= provider.ProviderZoneSubscriptionOAuth; zone++ {
		if zones.Allows(zone) {
			zoneTokens = append(zoneTokens, zone.String())
		}
	}
	preimage := struct {
		Contract              string   `json:"contract"`
		Version               int      `json:"version"`
		ReviewScopeIdentity   string   `json:"review_scope_identity"`
		RequestIdentity       string   `json:"request_identity"`
		MinimumContextTokens  uint32   `json:"minimum_context_tokens"`
		MinimumOutputTokens   uint32   `json:"minimum_output_tokens"`
		RequiredFeatures      []string `json:"required_features"`
		DataClassification    string   `json:"data_classification"`
		AllowedProviderZones  []string `json:"allowed_provider_zones"`
		ContentLoggingAllowed bool     `json:"content_logging_allowed"`
	}{
		Contract: "open-trestle/review-routing-input", Version: 1,
		ReviewScopeIdentity: input.reviewScopeIdentity, RequestIdentity: input.requestIdentity,
		MinimumContextTokens:  input.modelRequirements.MinContextTokens(),
		MinimumOutputTokens:   input.modelRequirements.MinOutputTokens(),
		RequiredFeatures:      featureTokens,
		DataClassification:    string(input.dataConstraints.Classification()),
		AllowedProviderZones:  zoneTokens,
		ContentLoggingAllowed: input.dataConstraints.ContentLoggingAllowed(),
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func validRequestIdentity(identity string) bool {
	if len(identity) != sha256.Size*2 {
		return false
	}
	for index := 0; index < len(identity); index++ {
		character := identity[index]
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}
