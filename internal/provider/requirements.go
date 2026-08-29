package provider

import (
	"errors"
	"fmt"
)

// Leaves two bits of uint32 headroom for checked downstream token arithmetic.
const maxModelRequirementTokens = 1 << 30

var (
	// ErrInvalidModelFeature identifies an unknown model capability requirement.
	ErrInvalidModelFeature = errors.New("invalid model feature")
	// ErrDuplicateModelFeature identifies a repeated model capability requirement.
	ErrDuplicateModelFeature = errors.New("duplicate model feature")
	// ErrModelRequirementTooLarge identifies a token capacity beyond the supported bound.
	ErrModelRequirementTooLarge = errors.New("model requirement too large")
)

// ModelFeature identifies a stable provider-neutral model capability.
type ModelFeature uint8

const (
	ModelFeatureStructuredOutput ModelFeature = iota + 1
	ModelFeatureNativeTools
	ModelFeatureVision
)

// String returns the stable feature token or an empty string for unknown values.
func (f ModelFeature) String() string {
	switch f {
	case ModelFeatureStructuredOutput:
		return "structured_output"
	case ModelFeatureNativeTools:
		return "native_tools"
	case ModelFeatureVision:
		return "vision"
	default:
		return ""
	}
}

// ParseModelFeature parses one exact stable model feature token.
func ParseModelFeature(value string) (ModelFeature, error) {
	switch value {
	case "structured_output":
		return ModelFeatureStructuredOutput, nil
	case "native_tools":
		return ModelFeatureNativeTools, nil
	case "vision":
		return ModelFeatureVision, nil
	default:
		return 0, fmt.Errorf("parse model feature: %w", ErrInvalidModelFeature)
	}
}

// ModelRequirements declares minimum provider-neutral model capabilities.
type ModelRequirements struct {
	requiredFeatures uint8
	minContextTokens uint32
	minOutputTokens  uint32
}

// NewModelRequirements creates an immutable canonical requirement set.
func NewModelRequirements(minContextTokens, minOutputTokens uint64, requiredFeatures []ModelFeature) (ModelRequirements, error) {
	if minContextTokens > maxModelRequirementTokens || minOutputTokens > maxModelRequirementTokens {
		return ModelRequirements{}, fmt.Errorf("validate model token requirements: %w", ErrModelRequirementTooLarge)
	}
	var featureBits uint8
	for _, feature := range requiredFeatures {
		bit, ok := modelFeatureBit(feature)
		if !ok {
			return ModelRequirements{}, fmt.Errorf("validate model feature: %w", ErrInvalidModelFeature)
		}
		if featureBits&bit != 0 {
			return ModelRequirements{}, fmt.Errorf("validate model feature: %w", ErrDuplicateModelFeature)
		}
		featureBits |= bit
	}
	return ModelRequirements{
		requiredFeatures: featureBits,
		minContextTokens: uint32(minContextTokens),
		minOutputTokens:  uint32(minOutputTokens),
	}, nil
}

// RequiredFeatures returns the required features in canonical order.
func (r ModelRequirements) RequiredFeatures() []ModelFeature {
	if r.requiredFeatures == 0 {
		return nil
	}
	features := make([]ModelFeature, 0, 3)
	for feature := ModelFeatureStructuredOutput; feature <= ModelFeatureVision; feature++ {
		if r.Requires(feature) {
			features = append(features, feature)
		}
	}
	return features
}

// Requires reports whether one known feature is required.
func (r ModelRequirements) Requires(feature ModelFeature) bool {
	bit, ok := modelFeatureBit(feature)
	return ok && r.requiredFeatures&bit != 0
}

// MinContextTokens returns the minimum required context capacity.
func (r ModelRequirements) MinContextTokens() uint32 { return r.minContextTokens }

// MinOutputTokens returns the minimum required output capacity.
func (r ModelRequirements) MinOutputTokens() uint32 { return r.minOutputTokens }

// Validate verifies that the requirements remain canonical and bounded.
func (r ModelRequirements) Validate() error {
	if r.requiredFeatures&^validModelFeatureBits() != 0 {
		return fmt.Errorf("validate model feature: %w", ErrInvalidModelFeature)
	}
	if r.minContextTokens > maxModelRequirementTokens || r.minOutputTokens > maxModelRequirementTokens {
		return fmt.Errorf("validate model token requirements: %w", ErrModelRequirementTooLarge)
	}
	return nil
}

func modelFeatureBit(feature ModelFeature) (uint8, bool) {
	if feature < ModelFeatureStructuredOutput || feature > ModelFeatureVision {
		return 0, false
	}
	return 1 << (feature - 1), true
}

func validModelFeatureBits() uint8 {
	return (1 << uint8(ModelFeatureVision)) - 1
}
