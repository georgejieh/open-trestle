package policy

import (
	"errors"
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestNewProviderDataConstraintsBindsPrivacyInputs(t *testing.T) {
	zones, _ := NewAllowedProviderZones(provider.ProviderZoneLocal, provider.ProviderZonePrivateRemote)
	constraints, err := NewProviderDataConstraints(DataClassificationConfidential, zones, false)
	if err != nil {
		t.Fatal(err)
	}
	if constraints.Classification() != DataClassificationConfidential || constraints.ContentLoggingAllowed() || constraints.AllowedProviderZones() != zones {
		t.Fatalf("constraints fields do not round trip")
	}
	if constraints.Validate() != nil {
		t.Fatalf("Validate() = %v", constraints.Validate())
	}
}

func TestProviderDataConstraintsAllowExplicitContentLogging(t *testing.T) {
	zones, _ := NewAllowedProviderZones(provider.ProviderZoneLocal)
	constraints, err := NewProviderDataConstraints(DataClassificationRestricted, zones, true)
	if err != nil || !constraints.ContentLoggingAllowed() {
		t.Fatalf("logging constraints = (%#v, %v)", constraints, err)
	}
}

func TestProviderDataConstraintsAllowDenyAllZones(t *testing.T) {
	constraints, err := NewProviderDataConstraints(DataClassificationInternal, AllowedProviderZones{}, false)
	if err != nil || constraints.AllowedProviderZones() != (AllowedProviderZones{}) {
		t.Fatalf("deny-all constraints = (%#v, %v)", constraints, err)
	}
}

func TestProviderDataConstraintsZeroValueFailsValidation(t *testing.T) {
	var constraints ProviderDataConstraints
	if err := constraints.Validate(); !errors.Is(err, ErrInvalidDataClassification) {
		t.Fatalf("Validate() = %v", err)
	}
	if constraints.AllowedProviderZones() != (AllowedProviderZones{}) || constraints.ContentLoggingAllowed() {
		t.Fatal("zero constraints grant provider handling")
	}
}

func TestNewProviderDataConstraintsRejectsInvalidInputs(t *testing.T) {
	for _, test := range []struct {
		name           string
		classification DataClassification
		zones          AllowedProviderZones
		want           error
	}{
		{name: "classification", classification: "unknown", want: ErrInvalidDataClassification},
		{name: "zone bits", classification: DataClassificationPublic, zones: AllowedProviderZones{zones: 1 << 7}, want: provider.ErrInvalidProviderZone},
	} {
		constraints, err := NewProviderDataConstraints(test.classification, test.zones, true)
		if !errors.Is(err, test.want) || constraints != (ProviderDataConstraints{}) {
			t.Fatalf("%s = (%#v, %v), want %v", test.name, constraints, err, test.want)
		}
	}
}

func TestInvalidProviderDataConstraintsDoNotAllowContentLogging(t *testing.T) {
	local, _ := NewAllowedProviderZones(provider.ProviderZoneLocal)
	for _, constraints := range []ProviderDataConstraints{
		{classification: "unknown", allowedZones: local, contentLoggingAllowed: true},
		{classification: DataClassificationPublic, allowedZones: AllowedProviderZones{zones: 1 << 7}, contentLoggingAllowed: true},
	} {
		if constraints.ContentLoggingAllowed() {
			t.Fatal("invalid constraints grant content logging")
		}
	}
}

func TestProviderDataConstraintsCopiesRemainEqual(t *testing.T) {
	zones, _ := NewAllowedProviderZones(provider.ProviderZoneLocal)
	constraints, _ := NewProviderDataConstraints(DataClassificationPublic, zones, false)
	copied := constraints
	if copied != constraints {
		t.Fatal("copied constraints changed")
	}
}

func TestProviderDataConstraintsSurfaceContainsOnlyPrivacyInputs(t *testing.T) {
	typeOfConstraints := reflect.TypeOf(ProviderDataConstraints{})
	want := []string{"classification", "allowedZones", "contentLoggingAllowed"}
	if typeOfConstraints.NumField() != len(want) {
		t.Fatalf("ProviderDataConstraints has %d fields, want %d", typeOfConstraints.NumField(), len(want))
	}
	for index, name := range want {
		if field := typeOfConstraints.Field(index); field.Name != name {
			t.Fatalf("field %d = %q, want %q", index, field.Name, name)
		}
	}
}
