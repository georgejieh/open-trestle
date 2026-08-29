package provider

import (
	"errors"
	"fmt"
)

const maxModelCapabilityTokens = maxModelRequirementTokens

var (
	// ErrInvalidModelCapacity identifies an unusable model token capacity.
	ErrInvalidModelCapacity = errors.New("invalid model capacity")
	// ErrModelCapabilityTooLarge identifies a model capacity beyond the supported bound.
	ErrModelCapabilityTooLarge = errors.New("model capability too large")
)

// ModelCapabilities declares provider-neutral model capacity without registry authority.
type ModelCapabilities struct {
	supportedFeatures uint8
	maxContextTokens  uint32
	maxOutputTokens   uint32
}

// NewModelCapabilities creates an immutable canonical capability declaration.
func NewModelCapabilities(maxContextTokens, maxOutputTokens uint64, supportedFeatures []ModelFeature) (ModelCapabilities, error) {
	if maxContextTokens > maxModelCapabilityTokens || maxOutputTokens > maxModelCapabilityTokens {
		return ModelCapabilities{}, fmt.Errorf("validate model capability limits: %w", ErrModelCapabilityTooLarge)
	}
	if maxContextTokens == 0 || maxOutputTokens == 0 || maxOutputTokens > maxContextTokens {
		return ModelCapabilities{}, fmt.Errorf("validate model capability limits: %w", ErrInvalidModelCapacity)
	}
	var featureBits uint8
	for _, feature := range supportedFeatures {
		bit, ok := modelFeatureBit(feature)
		if !ok {
			return ModelCapabilities{}, fmt.Errorf("validate model capability feature: %w", ErrInvalidModelFeature)
		}
		if featureBits&bit != 0 {
			return ModelCapabilities{}, fmt.Errorf("validate model capability feature: %w", ErrDuplicateModelFeature)
		}
		featureBits |= bit
	}
	return ModelCapabilities{
		supportedFeatures: featureBits,
		maxContextTokens:  uint32(maxContextTokens),
		maxOutputTokens:   uint32(maxOutputTokens),
	}, nil
}

// SupportedFeatures returns declared features in canonical order.
func (c ModelCapabilities) SupportedFeatures() []ModelFeature {
	if c.supportedFeatures == 0 {
		return nil
	}
	features := make([]ModelFeature, 0, 3)
	for feature := ModelFeatureStructuredOutput; feature <= ModelFeatureVision; feature++ {
		if c.Supports(feature) {
			features = append(features, feature)
		}
	}
	return features
}

// Supports reports whether one known feature is declared.
func (c ModelCapabilities) Supports(feature ModelFeature) bool {
	bit, ok := modelFeatureBit(feature)
	return ok && c.supportedFeatures&bit != 0
}

// MaxContextTokens returns the declared total context capacity.
func (c ModelCapabilities) MaxContextTokens() uint32 { return c.maxContextTokens }

// MaxOutputTokens returns the declared output capacity.
func (c ModelCapabilities) MaxOutputTokens() uint32 { return c.maxOutputTokens }

// Validate verifies that the capability declaration remains canonical and bounded.
func (c ModelCapabilities) Validate() error {
	if c.supportedFeatures&^validModelFeatureBits() != 0 {
		return fmt.Errorf("validate model capability feature: %w", ErrInvalidModelFeature)
	}
	if c.maxContextTokens > maxModelCapabilityTokens || c.maxOutputTokens > maxModelCapabilityTokens {
		return fmt.Errorf("validate model capability limits: %w", ErrModelCapabilityTooLarge)
	}
	if c.maxContextTokens == 0 || c.maxOutputTokens == 0 || c.maxOutputTokens > c.maxContextTokens {
		return fmt.Errorf("validate model capability limits: %w", ErrInvalidModelCapacity)
	}
	return nil
}
