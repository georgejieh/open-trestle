package gateway

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func newRoutingScope(t *testing.T) audit.ReviewScope {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant", "repository", "review-run")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func newRoutingFixture(t *testing.T, payload []byte) (provider.Request, provider.ModelRequirements, policy.ProviderDataConstraints) {
	t.Helper()
	request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", payload)
	if err != nil {
		t.Fatal(err)
	}
	requirements, err := provider.NewModelRequirements(128_000, 16_000, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	if err != nil {
		t.Fatal(err)
	}
	zones, err := policy.NewAllowedProviderZones(provider.ProviderZoneLocal)
	if err != nil {
		t.Fatal(err)
	}
	constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	if err != nil {
		t.Fatal(err)
	}
	return request, requirements, constraints
}

func TestNewReviewRoutingInputBindsImmutableInputs(t *testing.T) {
	request, requirements, constraints := newRoutingFixture(t, []byte("review payload"))
	input, err := NewReviewRoutingInput(newRoutingScope(t), request, requirements, constraints)
	if err != nil {
		t.Fatal(err)
	}
	if input.Identity() == "" || input.ReviewScopeIdentity() != newRoutingScope(t).Identity() || input.RequestIdentity() != request.Identity() || input.ModelRequirements() != requirements || input.ProviderDataConstraints() != constraints || input.Validate() != nil {
		t.Fatalf("routing input fields do not round trip")
	}
}

func TestReviewRoutingInputDoesNotRetainRequestPayload(t *testing.T) {
	request, requirements, constraints := newRoutingFixture(t, []byte("SENTINEL_PAYLOAD"))
	input, err := NewReviewRoutingInput(newRoutingScope(t), request, requirements, constraints)
	if err != nil {
		t.Fatal(err)
	}
	returned := request.Payload()
	returned[0] = 'X'
	if strings.Contains(fmt.Sprintf("%#v", input), "SENTINEL_PAYLOAD") || input.RequestIdentity() != request.Identity() {
		t.Fatal("routing input retained or changed request payload")
	}
}

func TestNewReviewRoutingInputRejectsInvalidInputs(t *testing.T) {
	request, requirements, constraints := newRoutingFixture(t, []byte("payload"))
	if input, err := NewReviewRoutingInput(audit.ReviewScope{}, request, requirements, constraints); !errors.Is(err, audit.ErrInvalidAuditScopeIdentifier) || input != (ReviewRoutingInput{}) {
		t.Fatalf("invalid scope = (%#v, %v)", input, err)
	}
	for _, test := range []struct {
		name         string
		request      provider.Request
		requirements provider.ModelRequirements
		constraints  policy.ProviderDataConstraints
		want         error
	}{
		{name: "request", requirements: requirements, constraints: constraints, want: provider.ErrInvalidCapability},
		{name: "constraints", request: request, requirements: requirements, want: policy.ErrInvalidDataClassification},
	} {
		input, err := NewReviewRoutingInput(newRoutingScope(t), test.request, test.requirements, test.constraints)
		if !errors.Is(err, test.want) || input != (ReviewRoutingInput{}) {
			t.Fatalf("%s = (%#v, %v), want %v", test.name, input, err, test.want)
		}
	}
}

func TestReviewRoutingInputForgedIdentityFailsValidation(t *testing.T) {
	for _, identity := range []string{
		"",
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		strings.Repeat("A", 64),
		strings.Repeat("g", 64),
	} {
		input := ReviewRoutingInput{reviewScopeIdentity: newRoutingScope(t).Identity(), requestIdentity: identity}
		if err := input.Validate(); !errors.Is(err, ErrInvalidRequestIdentity) {
			t.Fatalf("identity %q Validate() = %v", identity, err)
		}
	}
}

func TestReviewRoutingInputValidationDelegatesToDataConstraints(t *testing.T) {
	request, _, _ := newRoutingFixture(t, []byte("payload"))
	input := ReviewRoutingInput{reviewScopeIdentity: newRoutingScope(t).Identity(), requestIdentity: request.Identity()}
	if err := input.Validate(); !errors.Is(err, policy.ErrInvalidDataClassification) {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestReviewRoutingInputCopiesRemainEqual(t *testing.T) {
	request, requirements, constraints := newRoutingFixture(t, []byte("payload"))
	input, _ := NewReviewRoutingInput(newRoutingScope(t), request, requirements, constraints)
	copied := input
	if copied != input {
		t.Fatal("copied routing input changed")
	}
}

func TestReviewRoutingInputSurfaceContainsNoRequestOrRouteState(t *testing.T) {
	typeOfInput := reflect.TypeOf(ReviewRoutingInput{})
	want := []string{"identity", "reviewScopeIdentity", "requestIdentity", "modelRequirements", "dataConstraints"}
	if typeOfInput.NumField() != len(want) {
		t.Fatalf("ReviewRoutingInput has %d fields, want %d", typeOfInput.NumField(), len(want))
	}
	for index, name := range want {
		if field := typeOfInput.Field(index); field.Name != name {
			t.Fatalf("field %d = %q, want %q", index, field.Name, name)
		}
	}
}

func TestReviewRoutingInputIdentityBindsPolicyAndRequirements(t *testing.T) {
	request, requirements, constraints := newRoutingFixture(t, []byte("payload"))
	baseline, _ := NewReviewRoutingInput(newRoutingScope(t), request, requirements, constraints)
	otherRequirements, _ := provider.NewModelRequirements(128_001, 16_000, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	withRequirements, _ := NewReviewRoutingInput(newRoutingScope(t), request, otherRequirements, constraints)
	zones, _ := policy.NewAllowedProviderZones(provider.ProviderZoneLocal, provider.ProviderZonePrivateRemote)
	otherConstraints, _ := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	withConstraints, _ := NewReviewRoutingInput(newRoutingScope(t), request, requirements, otherConstraints)
	otherScope, _ := audit.NewReviewScope("other-tenant", "repository", "review-run")
	withScope, _ := NewReviewRoutingInput(otherScope, request, requirements, constraints)
	if baseline.Identity() == withRequirements.Identity() || baseline.Identity() == withConstraints.Identity() || baseline.Identity() == withScope.Identity() {
		t.Fatal("routing input identity ignored scope, requirements, or policy constraints")
	}
	forged := baseline
	forged.identity = strings.Repeat("f", 64)
	if !errors.Is(forged.Validate(), ErrInvalidReviewRoutingInputIdentity) {
		t.Fatal("forged routing input identity accepted")
	}
}
