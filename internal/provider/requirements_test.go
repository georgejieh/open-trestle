package provider

import (
	"errors"
	"reflect"
	"testing"
)

func TestModelFeatureRoundTrips(t *testing.T) {
	features := []struct {
		feature ModelFeature
		name    string
	}{
		{ModelFeatureStructuredOutput, "structured_output"},
		{ModelFeatureNativeTools, "native_tools"},
		{ModelFeatureVision, "vision"},
	}
	for _, test := range features {
		parsed, err := ParseModelFeature(test.name)
		if err != nil || parsed != test.feature || parsed.String() != test.name {
			t.Fatalf("feature %q round trip = (%v, %v, %q)", test.name, parsed, err, parsed.String())
		}
	}
	for _, value := range []string{"", "vision ", "VISION", "structured-output", "tools"} {
		if feature, err := ParseModelFeature(value); !errors.Is(err, ErrInvalidModelFeature) || feature != 0 {
			t.Fatalf("ParseModelFeature(%q) = (%v, %v)", value, feature, err)
		}
	}
	if ModelFeature(99).String() != "" {
		t.Fatal("unknown feature has a token")
	}
}

func TestNewModelRequirementsCanonicalizesFeatureOrder(t *testing.T) {
	requirements, err := NewModelRequirements(128_000, 16_000, []ModelFeature{
		ModelFeatureVision,
		ModelFeatureStructuredOutput,
		ModelFeatureNativeTools,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []ModelFeature{ModelFeatureStructuredOutput, ModelFeatureNativeTools, ModelFeatureVision}
	if requirements.MinContextTokens() != 128_000 || requirements.MinOutputTokens() != 16_000 || !reflect.DeepEqual(requirements.RequiredFeatures(), want) {
		t.Fatalf("requirements fields do not round trip")
	}
	for _, feature := range want {
		if !requirements.Requires(feature) {
			t.Fatalf("Requires(%v) = false", feature)
		}
	}
	if requirements.Requires(ModelFeature(99)) {
		t.Fatal("unknown feature is required")
	}
}

func TestModelRequirementsIgnoreInputOrder(t *testing.T) {
	first, _ := NewModelRequirements(100, 20, []ModelFeature{ModelFeatureVision, ModelFeatureStructuredOutput})
	second, _ := NewModelRequirements(100, 20, []ModelFeature{ModelFeatureStructuredOutput, ModelFeatureVision})
	if first != second {
		t.Fatalf("equal requirement sets differ: %#v %#v", first, second)
	}
}

func TestModelRequirementsFeatureAccessorIsDefensive(t *testing.T) {
	requirements, _ := NewModelRequirements(0, 0, []ModelFeature{ModelFeatureStructuredOutput})
	features := requirements.RequiredFeatures()
	features[0] = ModelFeatureVision
	if !requirements.Requires(ModelFeatureStructuredOutput) || requirements.Requires(ModelFeatureVision) {
		t.Fatal("feature accessor changed requirements")
	}
}

func TestModelRequirementsAllowUnconstrainedValue(t *testing.T) {
	requirements, err := NewModelRequirements(0, 0, nil)
	if err != nil || requirements != (ModelRequirements{}) || requirements.RequiredFeatures() != nil || requirements.Validate() != nil {
		t.Fatalf("unconstrained requirements = (%#v, %v)", requirements, err)
	}
}

func TestModelRequirementTokenBoundaries(t *testing.T) {
	requirements, err := NewModelRequirements(maxModelRequirementTokens, maxModelRequirementTokens, nil)
	if err != nil || requirements.MinContextTokens() != maxModelRequirementTokens || requirements.MinOutputTokens() != maxModelRequirementTokens {
		t.Fatalf("maximum requirements = (%#v, %v)", requirements, err)
	}
	for _, test := range []struct {
		name    string
		context uint64
		output  uint64
	}{
		{name: "context", context: maxModelRequirementTokens + 1},
		{name: "output", output: maxModelRequirementTokens + 1},
	} {
		if requirements, err := NewModelRequirements(test.context, test.output, nil); !errors.Is(err, ErrModelRequirementTooLarge) || requirements != (ModelRequirements{}) {
			t.Fatalf("%s overflow = (%#v, %v)", test.name, requirements, err)
		}
	}
}

func TestNewModelRequirementsRejectsInvalidFeatures(t *testing.T) {
	for _, test := range []struct {
		name     string
		features []ModelFeature
		want     error
	}{
		{name: "zero", features: []ModelFeature{0}, want: ErrInvalidModelFeature},
		{name: "unknown", features: []ModelFeature{99}, want: ErrInvalidModelFeature},
		{name: "duplicate", features: []ModelFeature{ModelFeatureVision, ModelFeatureVision}, want: ErrDuplicateModelFeature},
	} {
		requirements, err := NewModelRequirements(0, 0, test.features)
		if !errors.Is(err, test.want) || requirements != (ModelRequirements{}) {
			t.Fatalf("%s = (%#v, %v), want %v", test.name, requirements, err, test.want)
		}
	}
}

func TestModelRequirementsForgedValuesFailValidation(t *testing.T) {
	for _, test := range []struct {
		name         string
		requirements ModelRequirements
		want         error
	}{
		{name: "feature bits", requirements: ModelRequirements{requiredFeatures: 1 << 7}, want: ErrInvalidModelFeature},
		{name: "context", requirements: ModelRequirements{minContextTokens: maxModelRequirementTokens + 1}, want: ErrModelRequirementTooLarge},
		{name: "output", requirements: ModelRequirements{minOutputTokens: maxModelRequirementTokens + 1}, want: ErrModelRequirementTooLarge},
	} {
		if err := test.requirements.Validate(); !errors.Is(err, test.want) {
			t.Fatalf("%s Validate() = %v, want %v", test.name, err, test.want)
		}
	}
}

func TestModelRequirementsSurfaceContainsNoRouteOrPolicyState(t *testing.T) {
	typeOfRequirements := reflect.TypeOf(ModelRequirements{})
	want := []string{"requiredFeatures", "minContextTokens", "minOutputTokens"}
	if typeOfRequirements.NumField() != len(want) {
		t.Fatalf("ModelRequirements has %d fields, want %d", typeOfRequirements.NumField(), len(want))
	}
	for index, name := range want {
		if field := typeOfRequirements.Field(index); field.Name != name {
			t.Fatalf("field %d = %q, want %q", index, field.Name, name)
		}
	}
}
