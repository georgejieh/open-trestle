package policy

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestDataClassificationExactValuesValidate(t *testing.T) {
	classifications := []struct {
		classification DataClassification
		name           string
	}{
		{DataClassificationPublic, "public"},
		{DataClassificationInternal, "internal"},
		{DataClassificationConfidential, "confidential"},
		{DataClassificationRestricted, "restricted"},
	}
	for _, test := range classifications {
		if string(test.classification) != test.name || test.classification.Validate() != nil {
			t.Fatalf("classification = (%q, %v), want %q", test.classification, test.classification.Validate(), test.name)
		}
	}
}

func TestDataClassificationRejectsUnknownOrNormalizedTokens(t *testing.T) {
	for _, classification := range []DataClassification{"", "PUBLIC", " public", "public ", "private", "secret", "restricted\n"} {
		if err := classification.Validate(); !errors.Is(err, ErrInvalidDataClassification) {
			t.Fatalf("classification %q validation = %v", classification, err)
		}
	}
}

func TestDataClassificationCompareUsesSensitivityOrder(t *testing.T) {
	ordered := []DataClassification{
		DataClassificationPublic,
		DataClassificationInternal,
		DataClassificationConfidential,
		DataClassificationRestricted,
	}
	for leftIndex, left := range ordered {
		for rightIndex, right := range ordered {
			comparison, err := left.Compare(right)
			if err != nil {
				t.Fatalf("Compare(%q, %q) error = %v", left, right, err)
			}
			want := 0
			if leftIndex < rightIndex {
				want = -1
			} else if leftIndex > rightIndex {
				want = 1
			}
			if comparison != want {
				t.Fatalf("Compare(%q, %q) = %d, want %d", left, right, comparison, want)
			}
		}
	}
}

func TestDataClassificationCompareRejectsInvalidOperands(t *testing.T) {
	for _, test := range []struct {
		left  DataClassification
		right DataClassification
	}{
		{left: "unknown", right: DataClassificationPublic},
		{left: DataClassificationPublic, right: "unknown"},
		{left: "unknown", right: "other"},
	} {
		comparison, err := test.left.Compare(test.right)
		if comparison != 0 || !errors.Is(err, ErrInvalidDataClassification) {
			t.Fatalf("Compare(%q, %q) = (%d, %v)", test.left, test.right, comparison, err)
		}
	}
}

func TestDataClassificationErrorsDoNotEchoInput(t *testing.T) {
	classification := DataClassification("credential-shaped-secret")
	err := classification.Validate()
	if err == nil || strings.Contains(err.Error(), string(classification)) {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestDataClassificationHasNoRouteOrProviderState(t *testing.T) {
	typeOfClassification := reflect.TypeOf(DataClassification(""))
	if typeOfClassification.Kind() != reflect.String {
		t.Fatalf("DataClassification kind = %s, want string", typeOfClassification.Kind())
	}
	if typeOfClassification.NumMethod() != 2 {
		t.Fatalf("DataClassification methods = %d, want Validate and Compare only", typeOfClassification.NumMethod())
	}
}
