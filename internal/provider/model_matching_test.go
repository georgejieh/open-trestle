package provider

import (
	"errors"
	"testing"
)

func mustModelRequirements(t *testing.T, context, output uint64, features ...ModelFeature) ModelRequirements {
	t.Helper()
	requirements, err := NewModelRequirements(context, output, features)
	if err != nil {
		t.Fatal(err)
	}
	return requirements
}

func mustModelCapabilities(t *testing.T, context, output uint64, features ...ModelFeature) ModelCapabilities {
	t.Helper()
	capabilities, err := NewModelCapabilities(context, output, features)
	if err != nil {
		t.Fatal(err)
	}
	return capabilities
}

func TestCheckModelRequirementsAcceptsFeatureAndCapacitySuperset(t *testing.T) {
	requirements := mustModelRequirements(t, 100, 20, ModelFeatureStructuredOutput)
	for _, capabilities := range []ModelCapabilities{
		mustModelCapabilities(t, 100, 20, ModelFeatureStructuredOutput),
		mustModelCapabilities(t, 200, 40, ModelFeatureVision, ModelFeatureStructuredOutput),
	} {
		if err := CheckModelRequirements(capabilities, requirements); err != nil {
			t.Fatalf("CheckModelRequirements() = %v", err)
		}
	}
}

func TestCheckModelRequirementsAcceptsUnconstrainedRequirements(t *testing.T) {
	capabilities := mustModelCapabilities(t, 1, 1)
	if err := CheckModelRequirements(capabilities, ModelRequirements{}); err != nil {
		t.Fatalf("CheckModelRequirements() = %v", err)
	}
}

func TestCheckModelRequirementsRejectsEachMissingFeature(t *testing.T) {
	capabilities := mustModelCapabilities(t, 100, 20)
	for feature := ModelFeatureStructuredOutput; feature <= ModelFeatureVision; feature++ {
		requirements := mustModelRequirements(t, 0, 0, feature)
		if err := CheckModelRequirements(capabilities, requirements); err != ErrMissingModelFeature {
			t.Fatalf("feature %v = %v", feature, err)
		}
	}
}

func TestCheckModelRequirementsRejectsInsufficientCapacity(t *testing.T) {
	capabilities := mustModelCapabilities(t, 100, 20)
	for _, test := range []struct {
		name         string
		requirements ModelRequirements
		want         error
	}{
		{name: "context", requirements: mustModelRequirements(t, 101, 20), want: ErrInsufficientModelContext},
		{name: "output", requirements: mustModelRequirements(t, 100, 21), want: ErrInsufficientModelOutput},
		{name: "context first", requirements: mustModelRequirements(t, 101, 21), want: ErrInsufficientModelContext},
		{name: "feature first", requirements: mustModelRequirements(t, 101, 21, ModelFeatureVision), want: ErrMissingModelFeature},
	} {
		if err := CheckModelRequirements(capabilities, test.requirements); err != test.want {
			t.Fatalf("%s = %v, want %v", test.name, err, test.want)
		}
	}
}

func TestCheckModelRequirementsValidatesOperandsInOrder(t *testing.T) {
	invalidRequirements := ModelRequirements{requiredFeatures: 1 << 7}
	invalidCapabilities := ModelCapabilities{supportedFeatures: 1 << 7}
	validRequirements := ModelRequirements{}
	validCapabilities := mustModelCapabilities(t, 1, 1)
	for _, test := range []struct {
		name         string
		capabilities ModelCapabilities
		requirements ModelRequirements
		want         error
	}{
		{name: "requirements", capabilities: validCapabilities, requirements: invalidRequirements, want: ErrInvalidModelRequirements},
		{name: "capabilities", capabilities: invalidCapabilities, requirements: validRequirements, want: ErrInvalidModelCapabilities},
		{name: "requirements first", capabilities: invalidCapabilities, requirements: invalidRequirements, want: ErrInvalidModelRequirements},
		{name: "zero capabilities", requirements: validRequirements, want: ErrInvalidModelCapabilities},
	} {
		if err := CheckModelRequirements(test.capabilities, test.requirements); err != test.want {
			t.Fatalf("%s = %v, want %v", test.name, err, test.want)
		}
	}
}

func TestCheckModelRequirementsDoesNotMutateInputs(t *testing.T) {
	requirements := mustModelRequirements(t, 100, 20, ModelFeatureStructuredOutput)
	capabilities := mustModelCapabilities(t, 200, 40, ModelFeatureStructuredOutput, ModelFeatureVision)
	originalRequirements := requirements
	originalCapabilities := capabilities
	_ = CheckModelRequirements(capabilities, requirements)
	if requirements != originalRequirements || capabilities != originalCapabilities {
		t.Fatal("CheckModelRequirements changed an input")
	}
}

func TestModelRequirementCheckErrorsAreDistinctSentinels(t *testing.T) {
	errorsToCheck := []error{
		ErrInvalidModelRequirements,
		ErrInvalidModelCapabilities,
		ErrMissingModelFeature,
		ErrInsufficientModelContext,
		ErrInsufficientModelOutput,
	}
	for index, current := range errorsToCheck {
		if !errors.Is(current, current) {
			t.Fatalf("errors.Is(%v, itself) = false", current)
		}
		for previous := 0; previous < index; previous++ {
			if errors.Is(current, errorsToCheck[previous]) || errors.Is(errorsToCheck[previous], current) {
				t.Fatalf("errors %v and %v overlap", current, errorsToCheck[previous])
			}
		}
	}
}
