package setup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
	"time"
)

const currentCatalogBoundaryIntegrationIdentity = "8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9"

func currentCatalogBoundaryDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func currentCatalogBoundaryTime() time.Time {
	return time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
}

func currentCatalogBoundaryNewPlan(t *testing.T, profile Profile) Plan {
	t.Helper()
	plan, err := NewCurrentPlan(profile, "pf1-tenant", "pf1-repository", "pf1-owner", currentCatalogBoundaryTime())
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestCurrentCatalogBoundaryExactCatalogAndHistoricalParity(t *testing.T) {
	if got := CurrentIntegrationPermissionCheckerIdentity(); got != currentCatalogBoundaryIntegrationIdentity || got != currentCatalogBoundaryDigest([]byte("open-trestle/setup-checker/v2\x00integration_permissions_validated")) {
		t.Fatal("current integration identity drift")
	}
	for _, profile := range []Profile{ProfileLocalSingleNode} {
		t.Run(string(profile), func(t *testing.T) {
			historical, err := BuiltInCheckerCatalog(profile)
			if err != nil {
				t.Fatal(err)
			}
			original := historical.Authorities()
			current, err := CurrentCheckerCatalog(profile)
			if err != nil || current.Validate() != nil {
				t.Fatalf("current catalog invalid: %v", err)
			}
			expected := historical.Authorities()
			changed := 0
			for i := range expected {
				if expected[i].CheckerIdentity != currentCatalogBoundaryDigest([]byte("open-trestle/setup-checker/v1\x00"+string(expected[i].Key))) {
					t.Fatal("historical recipe changed")
				}
				if expected[i].Key == CheckIntegrationPermissionsValidated {
					expected[i].CheckerIdentity = currentCatalogBoundaryIntegrationIdentity
					changed++
				}
			}
			if !reflect.DeepEqual(current.Authorities(), expected) {
				t.Fatal("current catalog changed more than integration")
			}
			if !reflect.DeepEqual(historical.Authorities(), original) {
				t.Fatal("current catalog mutated historical catalog")
			}
			wire, err := json.Marshal(struct {
				Contract    string             `json:"contract"`
				Version     int                `json:"version"`
				Authorities []CheckerAuthority `json:"authorities"`
			}{"open-trestle/setup-checker-catalog", 1, expected})
			if err != nil {
				t.Fatal(err)
			}
			if current.Identity() != currentCatalogBoundaryDigest(append([]byte("open-trestle/setup-checker-catalog/v1\x00"), wire...)) {
				t.Fatal("catalog identity recipe changed")
			}
			currentPlan := currentCatalogBoundaryNewPlan(t, profile)
			oldPlan, err := NewPlan(profile, "pf1-tenant", "pf1-repository", "pf1-owner", currentCatalogBoundaryTime())
			if err != nil {
				t.Fatal(err)
			}
			if currentPlan.CheckerCatalogIdentity() != current.Identity() || oldPlan.CheckerCatalogIdentity() != historical.Identity() {
				t.Fatal("plan selected wrong catalog")
			}
			if changed == 0 {
				a, err := EncodePlan(oldPlan)
				if err != nil {
					t.Fatal(err)
				}
				b, err := EncodePlan(currentPlan)
				if err != nil || !bytes.Equal(a, b) {
					t.Fatal("local/air-gapped bytes changed")
				}
			} else if changed != 1 || current.Identity() == historical.Identity() || currentPlan.Identity() == oldPlan.Identity() {
				t.Fatal("integration catalog did not change exactly once")
			}
			detached := current.Authorities()
			detached[0].CheckerIdentity = currentCatalogBoundaryDigest([]byte("mutation"))
			if !reflect.DeepEqual(current.Authorities(), expected) {
				t.Fatal("catalog leaked mutable authorities")
			}
		})
	}
	if _, err := CurrentCheckerCatalog(Profile("unknown")); !errors.Is(err, ErrInvalidCheckerCatalog) {
		t.Fatalf("unknown catalog: %v", err)
	}
	for _, spec := range []struct {
		profile                   Profile
		tenant, repository, owner string
		at                        time.Time
	}{
		{Profile("unknown"), "tenant", "repo", "owner", currentCatalogBoundaryTime()},
		{ProfileLocalSingleNode, "", "repo", "owner", currentCatalogBoundaryTime()},
		{ProfileLocalSingleNode, "tenant", "", "owner", currentCatalogBoundaryTime()},
		{ProfileLocalSingleNode, "tenant", "repo", "", currentCatalogBoundaryTime()},
		{ProfileLocalSingleNode, "tenant", "repo", "owner", time.Time{}},
	} {
		if _, err := NewCurrentPlan(spec.profile, spec.tenant, spec.repository, spec.owner, spec.at); !errors.Is(err, ErrInvalidPlan) {
			t.Fatalf("invalid current plan error changed: %v", err)
		}
	}
}

// Diagnostic source/schema parity only. Neither the browser marker nor this
// structural schema check confers token-creation or runtime authority.
func TestCurrentCatalogBoundaryBrowserDigestAndHistoricalPlanSchemaParity(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "web", "src", "setupApi.ts"))
	if err != nil {
		t.Fatal(err)
	}
	matches := regexp.MustCompile(`(?m)^export const CURRENT_INTEGRATION_PERMISSION_CHECKER_IDENTITY\s*=\s*"([0-9a-f]{64})";`).FindAllSubmatch(source, -1)
	if len(matches) != 1 || string(matches[0][1]) != currentCatalogBoundaryIntegrationIdentity || string(matches[0][1]) != CurrentIntegrationPermissionCheckerIdentity() {
		t.Fatal("unique browser diagnostic digest diverged from native current catalog")
	}
	schemaBytes, err := os.ReadFile(filepath.Join("..", "schemas", "setup", "setup-plan-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if currentCatalogBoundaryDigest(schemaBytes) != "af61eb07c4a82cfea09a8b15fd2745489be529f6eeeb320857b7b3ededb37997" {
		t.Fatal("historical plan schema bytes changed")
	}
	var schema struct {
		ID         string                     `json:"$id"`
		Additional bool                       `json:"additionalProperties"`
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil || schema.ID != "urn:open-trestle:schema:setup:plan:v1" || schema.Additional {
		t.Fatal("historical plan schema contract changed")
	}
	plan := currentCatalogBoundaryNewPlan(t, ProfileLocalSingleNode)
	encoded, err := EncodePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &record); err != nil {
		t.Fatal(err)
	}
	for _, key := range schema.Required {
		if _, ok := record[key]; !ok {
			t.Fatalf("native current plan missing schema field %s", key)
		}
	}
	for key := range record {
		if _, ok := schema.Properties[key]; !ok {
			t.Fatalf("native current plan added undeclared schema field %s", key)
		}
	}
	var version int
	if err := json.Unmarshal(record["schema_version"], &version); err != nil || version != 1 {
		t.Fatal("current plan silently bumped historical wire schema")
	}
}
