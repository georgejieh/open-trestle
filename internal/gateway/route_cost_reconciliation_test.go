package gateway

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func knownActualCost(t *testing.T, totalTokens uint64) provider.RouteActualCost {
	t.Helper()
	pricing, _ := provider.NewRoutePricing(1_000_000, 0)
	usage, _ := provider.NewRouteTokenUsage(totalTokens, 0, 0)
	cost, err := provider.CalculateActualRouteCost(pricing, usage)
	if err != nil {
		t.Fatal(err)
	}
	return cost
}

func TestRouteCostReconciliationStatusRoundTrips(t *testing.T) {
	values := []struct {
		status RouteCostReconciliationStatus
		token  string
	}{
		{RouteCostWithinReservation, "within_reservation"},
		{RouteCostWithinBudget, "within_budget"},
		{RouteCostBudgetExceeded, "budget_exceeded"},
		{RouteCostUsageUnknown, "usage_unknown"},
	}
	for _, test := range values {
		parsed, err := ParseRouteCostReconciliationStatus(test.token)
		if err != nil || parsed != test.status || parsed.String() != test.token || parsed.Validate() != nil {
			t.Fatalf("status %q = (%v, %v)", test.token, parsed, err)
		}
	}
	if parsed, err := ParseRouteCostReconciliationStatus(""); !errors.Is(err, ErrInvalidRouteCostReconciliationStatus) || parsed != 0 {
		t.Fatalf("empty status = (%v, %v)", parsed, err)
	}
}

func TestReconcileRouteAttemptCostReleasesUnusedReservation(t *testing.T) {
	attempt := strings.Repeat("a", 64)
	reconciliation, err := reconcileRouteAttemptCost(attempt, strings.Repeat("f", 64), 100, 900, knownActualCost(t, 40))
	if err != nil {
		t.Fatal(err)
	}
	if reconciliation.Identity() == "" || reconciliation.AttemptAuthorizationIdentity() != attempt || reconciliation.Status() != RouteCostWithinReservation || reconciliation.ReservedCostMicroUSD() != 100 || reconciliation.ActualCost().TotalCostMicroUSD() != 40 || reconciliation.RemainingCostMicroUSD() != 960 || reconciliation.BudgetOverrunMicroUSD() != 0 || reconciliation.Validate() != nil {
		t.Fatalf("reconciliation did not round trip: %#v", reconciliation)
	}
}

func TestReconcileRouteAttemptCostConsumesHeadroomAndRecordsOverrun(t *testing.T) {
	attempt := strings.Repeat("b", 64)
	withinBudget, err := reconcileRouteAttemptCost(attempt, strings.Repeat("f", 64), 100, 900, knownActualCost(t, 150))
	if err != nil || withinBudget.Status() != RouteCostWithinBudget || withinBudget.RemainingCostMicroUSD() != 850 || withinBudget.BudgetOverrunMicroUSD() != 0 {
		t.Fatalf("within-budget reconciliation = (%#v, %v)", withinBudget, err)
	}
	over, err := reconcileRouteAttemptCost(attempt, strings.Repeat("f", 64), 100, 20, knownActualCost(t, 150))
	if err != nil || over.Status() != RouteCostBudgetExceeded || over.RemainingCostMicroUSD() != 0 || over.BudgetOverrunMicroUSD() != 30 {
		t.Fatalf("over-budget reconciliation = (%#v, %v)", over, err)
	}
}

func TestReconcileRouteAttemptCostKeepsUnknownUsageReserved(t *testing.T) {
	pricing, _ := provider.NewRoutePricing(1, 1)
	actual, _ := provider.CalculateActualRouteCost(pricing, provider.NewUnknownRouteTokenUsage())
	reconciliation, err := reconcileRouteAttemptCost(strings.Repeat("c", 64), strings.Repeat("f", 64), 100, 900, actual)
	if err != nil || reconciliation.Status() != RouteCostUsageUnknown || reconciliation.RemainingCostMicroUSD() != 900 || reconciliation.BudgetOverrunMicroUSD() != 0 {
		t.Fatalf("unknown reconciliation = (%#v, %v)", reconciliation, err)
	}
}

func TestReconcileRouteAttemptCostRejectsInvalidInputs(t *testing.T) {
	valid := knownActualCost(t, 1)
	for _, test := range []struct {
		name      string
		attempt   string
		reserved  uint64
		remaining uint64
		actual    provider.RouteActualCost
		want      error
	}{
		{name: "attempt", reserved: 1, actual: valid, want: ErrInvalidRequestIdentity},
		{name: "overflow", attempt: strings.Repeat("d", 64), reserved: ^uint64(0), remaining: 1, actual: valid, want: ErrInvalidRouteCostReconciliationBudget},
		{name: "actual", attempt: strings.Repeat("d", 64), reserved: 1, want: provider.ErrInvalidRouteActualCost},
	} {
		t.Run(test.name, func(t *testing.T) {
			reconciliation, err := reconcileRouteAttemptCost(test.attempt, strings.Repeat("f", 64), test.reserved, test.remaining, test.actual)
			if !errors.Is(err, test.want) || reconciliation.Identity() != "" {
				t.Fatalf("reconcileRouteAttemptCost() = (%#v, %v), want %v", reconciliation, err, test.want)
			}
		})
	}
}

func TestRouteCostReconciliationIsContentAddressedAndRedacted(t *testing.T) {
	attempt := strings.Repeat("e", 64)
	reconciliation, _ := reconcileRouteAttemptCost(attempt, strings.Repeat("f", 64), 100, 900, knownActualCost(t, 40))
	other, _ := reconcileRouteAttemptCost(attempt, strings.Repeat("f", 64), 100, 900, knownActualCost(t, 41))
	if reconciliation.Identity() == other.Identity() {
		t.Fatal("actual cost did not affect reconciliation identity")
	}
	forged := reconciliation
	forged.identity = strings.Repeat("0", 64)
	if forged.Validate() != ErrInvalidRouteCostReconciliationIdentity {
		t.Fatal("forged reconciliation identity accepted")
	}
	if reflect.TypeOf(reconciliation).NumField() != 9 {
		t.Fatalf("reconciliation has %d fields", reflect.TypeOf(reconciliation).NumField())
	}
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%d", "%x"} {
		formatted := fmt.Sprintf(format, reconciliation)
		if strings.Contains(formatted, attempt) {
			t.Fatalf("format %q exposed attempt identity: %q", format, formatted)
		}
	}
}
