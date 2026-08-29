package provider

import (
	"errors"
	"reflect"
	"testing"
)

func TestNewModelCapabilitiesBindsDeclaredCapacity(t *testing.T) {
	capabilities, err := NewModelCapabilities(128_000, 16_000, []ModelFeature{
		ModelFeatureVision,
		ModelFeatureStructuredOutput,
		ModelFeatureNativeTools,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []ModelFeature{ModelFeatureStructuredOutput, ModelFeatureNativeTools, ModelFeatureVision}
	if capabilities.MaxContextTokens() != 128_000 || capabilities.MaxOutputTokens() != 16_000 || !reflect.DeepEqual(capabilities.SupportedFeatures(), want) || capabilities.Validate() != nil {
		t.Fatal("model capabilities do not round trip")
	}
	for _, feature := range want {
		if !capabilities.Supports(feature) {
			t.Fatalf("Supports(%v) = false", feature)
		}
	}
	if capabilities.Supports(ModelFeature(99)) {
		t.Fatal("unknown feature is supported")
	}
}

func TestModelCapabilitiesAllowTextOnlyModel(t *testing.T) {
	capabilities, err := NewModelCapabilities(8_192, 2_048, nil)
	if err != nil || capabilities.SupportedFeatures() != nil {
		t.Fatalf("text-only capabilities = (%#v, %v)", capabilities, err)
	}
}

func TestModelCapabilitiesIgnoreFeatureOrder(t *testing.T) {
	first, _ := NewModelCapabilities(100, 20, []ModelFeature{ModelFeatureVision, ModelFeatureStructuredOutput})
	second, _ := NewModelCapabilities(100, 20, []ModelFeature{ModelFeatureStructuredOutput, ModelFeatureVision})
	if first != second {
		t.Fatalf("equal capability sets differ: %#v %#v", first, second)
	}
}

func TestModelCapabilitiesFeatureAccessorIsDefensive(t *testing.T) {
	capabilities, _ := NewModelCapabilities(100, 20, []ModelFeature{ModelFeatureStructuredOutput})
	features := capabilities.SupportedFeatures()
	features[0] = ModelFeatureVision
	if !capabilities.Supports(ModelFeatureStructuredOutput) || capabilities.Supports(ModelFeatureVision) {
		t.Fatal("feature accessor changed capabilities")
	}
}

func TestModelCapabilityCapacityBoundaries(t *testing.T) {
	capabilities, err := NewModelCapabilities(maxModelCapabilityTokens, maxModelCapabilityTokens, nil)
	if err != nil || capabilities.MaxContextTokens() != maxModelCapabilityTokens || capabilities.MaxOutputTokens() != maxModelCapabilityTokens {
		t.Fatalf("maximum capabilities = (%#v, %v)", capabilities, err)
	}
	for _, test := range []struct {
		name    string
		context uint64
		output  uint64
		want    error
	}{
		{name: "zero context", output: 1, want: ErrInvalidModelCapacity},
		{name: "zero output", context: 1, want: ErrInvalidModelCapacity},
		{name: "output beyond context", context: 10, output: 11, want: ErrInvalidModelCapacity},
		{name: "context too large", context: maxModelCapabilityTokens + 1, output: 1, want: ErrModelCapabilityTooLarge},
		{name: "output too large", context: maxModelCapabilityTokens, output: maxModelCapabilityTokens + 1, want: ErrModelCapabilityTooLarge},
	} {
		capabilities, err := NewModelCapabilities(test.context, test.output, nil)
		if !errors.Is(err, test.want) || capabilities != (ModelCapabilities{}) {
			t.Fatalf("%s = (%#v, %v), want %v", test.name, capabilities, err, test.want)
		}
	}
}

func TestNewModelCapabilitiesRejectsInvalidFeatures(t *testing.T) {
	for _, test := range []struct {
		name     string
		features []ModelFeature
		want     error
	}{
		{name: "zero", features: []ModelFeature{0}, want: ErrInvalidModelFeature},
		{name: "unknown", features: []ModelFeature{99}, want: ErrInvalidModelFeature},
		{name: "duplicate", features: []ModelFeature{ModelFeatureVision, ModelFeatureVision}, want: ErrDuplicateModelFeature},
	} {
		capabilities, err := NewModelCapabilities(100, 20, test.features)
		if !errors.Is(err, test.want) || capabilities != (ModelCapabilities{}) {
			t.Fatalf("%s = (%#v, %v), want %v", test.name, capabilities, err, test.want)
		}
	}
}

func TestModelCapabilitiesForgedValuesFailValidation(t *testing.T) {
	for _, test := range []struct {
		name         string
		capabilities ModelCapabilities
		want         error
	}{
		{name: "zero", want: ErrInvalidModelCapacity},
		{name: "feature bits", capabilities: ModelCapabilities{supportedFeatures: 1 << 7, maxContextTokens: 10, maxOutputTokens: 1}, want: ErrInvalidModelFeature},
		{name: "context", capabilities: ModelCapabilities{maxContextTokens: maxModelCapabilityTokens + 1, maxOutputTokens: 1}, want: ErrModelCapabilityTooLarge},
		{name: "output", capabilities: ModelCapabilities{maxContextTokens: maxModelCapabilityTokens, maxOutputTokens: maxModelCapabilityTokens + 1}, want: ErrModelCapabilityTooLarge},
		{name: "relation", capabilities: ModelCapabilities{maxContextTokens: 10, maxOutputTokens: 11}, want: ErrInvalidModelCapacity},
	} {
		if err := test.capabilities.Validate(); !errors.Is(err, test.want) {
			t.Fatalf("%s Validate() = %v, want %v", test.name, err, test.want)
		}
	}
}

func TestModelCapabilitiesSurfaceContainsNoRegistryOrRouteState(t *testing.T) {
	typeOfCapabilities := reflect.TypeOf(ModelCapabilities{})
	want := []string{"supportedFeatures", "maxContextTokens", "maxOutputTokens"}
	if typeOfCapabilities.NumField() != len(want) {
		t.Fatalf("ModelCapabilities has %d fields, want %d", typeOfCapabilities.NumField(), len(want))
	}
	for index, name := range want {
		if field := typeOfCapabilities.Field(index); field.Name != name {
			t.Fatalf("field %d = %q, want %q", index, field.Name, name)
		}
	}
}
