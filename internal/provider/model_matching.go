package provider

type modelRequirementCheckError string

func (e modelRequirementCheckError) Error() string { return string(e) }

const (
	// ErrInvalidModelRequirements identifies malformed requirement input.
	ErrInvalidModelRequirements modelRequirementCheckError = "invalid model requirements"
	// ErrInvalidModelCapabilities identifies malformed capability input.
	ErrInvalidModelCapabilities modelRequirementCheckError = "invalid model capabilities"
	// ErrMissingModelFeature identifies an unavailable required feature.
	ErrMissingModelFeature modelRequirementCheckError = "missing required model feature"
	// ErrInsufficientModelContext identifies context capacity below the requirement.
	ErrInsufficientModelContext modelRequirementCheckError = "insufficient model context"
	// ErrInsufficientModelOutput identifies output capacity below the requirement.
	ErrInsufficientModelOutput modelRequirementCheckError = "insufficient model output"
)

// CheckModelRequirements compares declared capabilities with provider-neutral requirements.
func CheckModelRequirements(capabilities ModelCapabilities, requirements ModelRequirements) error {
	if requirements.Validate() != nil {
		return ErrInvalidModelRequirements
	}
	if capabilities.Validate() != nil {
		return ErrInvalidModelCapabilities
	}
	for feature := ModelFeatureStructuredOutput; feature <= ModelFeatureVision; feature++ {
		if requirements.Requires(feature) && !capabilities.Supports(feature) {
			return ErrMissingModelFeature
		}
	}
	if capabilities.MaxContextTokens() < requirements.MinContextTokens() {
		return ErrInsufficientModelContext
	}
	if capabilities.MaxOutputTokens() < requirements.MinOutputTokens() {
		return ErrInsufficientModelOutput
	}
	return nil
}
