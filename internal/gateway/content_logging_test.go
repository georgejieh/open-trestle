package gateway

import (
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func newContentLoggingInput(t *testing.T, isContentLoggingAllowed bool) ReviewRoutingInput {
	t.Helper()
	request, requirements, _ := newRoutingFixture(t, []byte("payload"))
	zones, err := policy.NewAllowedProviderZones(provider.ProviderZoneLocal)
	if err != nil {
		t.Fatal(err)
	}
	constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationRestricted, zones, isContentLoggingAllowed)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewReviewRoutingInput(newRoutingScope(t), request, requirements, constraints)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func TestCheckRouteContentLoggingRequiresDisabledModeWhenForbidden(t *testing.T) {
	input := newContentLoggingInput(t, false)
	for _, test := range []struct {
		mode provider.ContentLoggingMode
		want error
	}{
		{mode: provider.ContentLoggingDisabled},
		{mode: provider.ContentLoggingEnabled, want: ErrRouteContentLoggingNotAllowed},
		{mode: provider.ContentLoggingUnknown, want: ErrRouteContentLoggingNotAllowed},
	} {
		if err := CheckRouteContentLogging(input, test.mode); err != test.want {
			t.Fatalf("CheckRouteContentLogging(%q) = %v, want %v", test.mode, err, test.want)
		}
	}
}

func TestCheckRouteContentLoggingAllowsEveryDeclaredModeWhenPermitted(t *testing.T) {
	input := newContentLoggingInput(t, true)
	for mode := provider.ContentLoggingDisabled; mode <= provider.ContentLoggingUnknown; mode++ {
		if err := CheckRouteContentLogging(input, mode); err != nil {
			t.Fatalf("CheckRouteContentLogging(%q) = %v", mode, err)
		}
	}
}

func TestCheckRouteContentLoggingValidatesInputsInOrder(t *testing.T) {
	validInput := newContentLoggingInput(t, false)
	for _, test := range []struct {
		name  string
		input ReviewRoutingInput
		mode  provider.ContentLoggingMode
		want  error
	}{
		{name: "input", mode: provider.ContentLoggingDisabled, want: ErrInvalidRequestIdentity},
		{name: "mode", input: validInput, want: provider.ErrInvalidContentLoggingMode},
		{name: "input first", want: ErrInvalidRequestIdentity},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := CheckRouteContentLogging(test.input, test.mode); !errors.Is(err, test.want) {
				t.Fatalf("CheckRouteContentLogging() = %v, want %v", err, test.want)
			}
		})
	}
}
