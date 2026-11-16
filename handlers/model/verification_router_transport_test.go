package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

// The standard transport keeps the exact version 2 identity preimage; the local
// structured-output transport, which reserves a different estimate, uses
// version 3 with the transport bound.
func TestPolicyVerificationAuthorizerIdentityBindsTheTransport(t *testing.T) {
	route, observation := verifierObservedRoute(t)
	snapshot, err := NewVerificationRouteSnapshot(1, 1, []gateway.ObservedRouteCandidate{route}, []provider.RoutePerformanceObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	inventory := &modelRouteInventory{identity: strings.Repeat("a", 64), snapshot: snapshot}
	requirements, _ := provider.NewModelRequirements(1, 1, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	zones, _ := policy.NewAllowedProviderZones(provider.ProviderZoneLocal)
	constraints, _ := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	budget, _ := provider.NewModelCostBudget(7, 100, 0)
	ranking, _ := gateway.NewRouteRankingPolicy(nil)
	independence, _ := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
	ledger, clock := audit.NewMemoryLedger(), fixedClock{at: time.UnixMilli(210)}
	preimage := func(version int, transport string) string {
		t.Helper()
		encoded, err := json.Marshal(struct {
			Contract             string   `json:"contract"`
			SchemaVersion        int      `json:"schema_version"`
			Inventory            string   `json:"inventory"`
			MinContext           uint32   `json:"min_context"`
			MinOutput            uint32   `json:"min_output"`
			Features             []string `json:"features"`
			Classification       string   `json:"classification"`
			Zones                []string `json:"zones"`
			Logging              bool     `json:"logging"`
			EstimatedInput       uint32   `json:"estimated_input"`
			InputEstimateVersion int      `json:"input_estimate_version"`
			InputTransport       string   `json:"input_transport,omitempty"`
			MaxOutput            uint32   `json:"max_output"`
			MaxCost              uint64   `json:"max_cost"`
			Ranking              string   `json:"ranking"`
			Independence         string   `json:"independence"`
		}{"open-trestle/policy-verification-authorizer", version, inventory.identity, 1, 1, []string{"structured_output"}, "confidential", []string{"local"}, false, 7, 1, transport, 100, 0, ranking.Identity(), independence.Identity()})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		return hex.EncodeToString(digest[:])
	}
	for transport, want := range map[review.ModelRequestTransport]string{
		review.ModelRequestTransportStandard:              preimage(2, ""),
		review.ModelRequestTransportLocalStructuredOutput: preimage(3, "local_structured_output"),
	} {
		authorizer, err := NewPolicyVerificationAuthorizerForTransport(transport, inventory, requirements, constraints, budget, ranking, independence, ledger, clock)
		if err != nil || authorizer.Identity() != want || authorizer.Validate() != nil {
			t.Fatalf("%s authorizer identity = %q (%v), want %q", transport, authorizer.Identity(), err, want)
		}
	}
	legacy, err := NewPolicyVerificationAuthorizer(inventory, requirements, constraints, budget, ranking, independence, ledger, clock)
	if err != nil || legacy.Identity() != preimage(2, "") {
		t.Fatal("standard authorizer identity changed")
	}
	if _, err := NewPolicyVerificationAuthorizerForTransport(review.ModelRequestTransportLocalStructuredOutput+1, inventory, requirements, constraints, budget, ranking, independence, ledger, clock); err == nil {
		t.Fatal("unknown transport accepted")
	}
}
