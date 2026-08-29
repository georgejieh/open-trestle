package gateway

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrInvalidRequestIdentity identifies a malformed review request identity.
	ErrInvalidRequestIdentity = errors.New("invalid request identity")
)

// ReviewRoutingInput binds immutable provider-neutral inputs for later route planning.
type ReviewRoutingInput struct {
	requestIdentity   string
	modelRequirements provider.ModelRequirements
	dataConstraints   policy.ProviderDataConstraints
}

// NewReviewRoutingInput creates a routing input without retaining request payload bytes.
func NewReviewRoutingInput(request provider.Request, requirements provider.ModelRequirements, constraints policy.ProviderDataConstraints) (ReviewRoutingInput, error) {
	if err := request.Validate(); err != nil {
		return ReviewRoutingInput{}, fmt.Errorf("validate routing request: %w", err)
	}
	input := ReviewRoutingInput{
		requestIdentity:   strings.Clone(request.Identity()),
		modelRequirements: requirements,
		dataConstraints:   constraints,
	}
	if err := input.Validate(); err != nil {
		return ReviewRoutingInput{}, err
	}
	return input, nil
}

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
	if !validRequestIdentity(i.requestIdentity) {
		return fmt.Errorf("validate routing request identity: %w", ErrInvalidRequestIdentity)
	}
	if err := i.modelRequirements.Validate(); err != nil {
		return fmt.Errorf("validate routing model requirements: %w", err)
	}
	if err := i.dataConstraints.Validate(); err != nil {
		return fmt.Errorf("validate routing data constraints: %w", err)
	}
	return nil
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
