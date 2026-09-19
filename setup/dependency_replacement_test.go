package setup

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestReplacingPrerequisiteInvalidatesDependentEvidence(t *testing.T) {
	cases := []struct {
		name       string
		profile    Profile
		upstream   CheckKey
		dependents []CheckKey
	}{
		{"policy", ProfileLocalSingleNode, CheckPolicyValidated, []CheckKey{CheckLocalInferenceValidated, CheckDryRunValidated}},
		{"air-gapped-policy", ProfileAirGapped, CheckPolicyValidated, []CheckKey{CheckLocalInferenceValidated, CheckDryRunValidated}},
		{"hybrid-policy", ProfileControlledHybrid, CheckPolicyValidated, []CheckKey{CheckDryRunValidated}},
		{"postgres", ProfileKubernetesHA, CheckPostgresStorageValidated, []CheckKey{CheckSharedRateLimitValidated, CheckReplicaReconciliationValidated}},
		{"integration", ProfileControlledHybrid, CheckIntegrationPermissionsValidated, []CheckKey{CheckWebhookValidated}},
	}
	for _, test := range cases {
		for _, replacementState := range []CheckState{CheckPassed, CheckBlocked, CheckUnavailable} {
			t.Run(test.name+"/"+string(replacementState), func(t *testing.T) {
				plan, err := NewPlan(test.profile, "tenant-a", "repo-a", "owner", setupTime(0))
				if err != nil {
					t.Fatal(err)
				}
				catalog, err := BuiltInCheckerCatalog(plan.Profile())
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "plan.json")
				store, err := OpenStateFile(path)
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				if err := store.Initialize(context.Background(), plan); err != nil {
					t.Fatal(err)
				}
				for _, requirement := range plan.Requirements() {
					if requirement.Source() == CheckDeterministic {
						continue
					}
					checker, _ := catalog.Resolve(requirement.Key())
					receipt, err := newCheckReceipt(plan, requirement.Key(), checker, CheckPassed, setupDigest("first-"+string(requirement.Key())), RecoveryNone, plan.UpdatedAt().Add(time.Millisecond))
					if err != nil {
						t.Fatal(err)
					}
					plan, err = store.applyReceipt(context.Background(), receipt, catalog)
					if err != nil {
						t.Fatal(err)
					}
				}
				if !plan.Ready() {
					t.Fatal("fixture did not reach ready")
				}
				checker, _ := catalog.Resolve(test.upstream)
				recovery := RecoveryNone
				if replacementState != CheckPassed {
					recovery = recoveryForKey(test.upstream)
				}
				evidence := setupDigest("replacement")
				if replacementState == CheckPassed {
					original, _ := planRequirement(plan, test.upstream)
					evidence = original.EvidenceIdentity()
				}
				replacement, err := newCheckReceipt(plan, test.upstream, checker, replacementState, evidence, recovery, plan.UpdatedAt().Add(time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				changed, err := store.applyReceipt(context.Background(), replacement, catalog)
				if err != nil {
					t.Fatal(err)
				}
				if changed.Ready() {
					t.Error("new prerequisite retained false readiness")
				}
				for _, key := range test.dependents {
					requirement, found := planRequirement(changed, key)
					if !found || requirement.State() != CheckPending || requirement.receiptIdentity != "" || requirement.evidenceIdentity != "" {
						t.Errorf("dependent %s retained stale evidence", key)
					}
				}
				for i, old := range plan.requirements {
					dependent := false
					for _, key := range test.dependents {
						dependent = dependent || key == old.key
					}
					if old.key != test.upstream && !dependent && changed.requirements[i] != old {
						t.Errorf("unrelated requirement %s changed", old.key)
					}
				}
				if len(changed.receipts) != len(plan.receipts)+1 {
					t.Fatal("receipt history lost")
				}
				for i, receipt := range plan.receipts {
					if changed.receipts[i] != receipt {
						t.Fatal("historical receipt rewritten")
					}
				}
				encoded, err := EncodePlan(changed)
				if err != nil {
					t.Fatal(err)
				}
				replayed, err := DecodePlan(encoded)
				if err != nil || replayed.Identity() != changed.Identity() || replayed.Ready() {
					t.Errorf("replay retained readiness or diverged: %v", err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := OpenStateFile(path)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
				loaded, err := reopened.Current(context.Background())
				if err != nil || loaded.Identity() != changed.Identity() || loaded.Ready() {
					t.Errorf("reopen retained readiness or diverged: %v", err)
				}

				// Recreate the old transition with its ordinary unkeyed identity.
				stale := plan
				stale.requirements = append([]Requirement(nil), plan.requirements...)
				index, _ := planRequirementIndex(stale, test.upstream)
				stale.requirements[index] = Requirement{key: replacement.key, source: stale.requirements[index].source, state: replacement.state, checkerIdentity: replacement.checkerIdentity, evidenceIdentity: replacement.evidenceIdentity, receiptIdentity: replacement.identity, recovery: replacement.recovery, checkedAt: replacement.checkedAt}
				stale.previousIdentity = plan.identity
				stale.receipts = append(append([]CheckReceipt(nil), plan.receipts...), replacement)
				stale.revision++
				stale.updatedAt = replacement.checkedAt
				stale.status, stale.ready = deriveStatus(stale.requirements)
				stale.identity = planIdentity(stale)
				legacy, err := json.Marshal(wirePlan(stale, true))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := DecodePlan(legacy); err == nil {
					t.Error("stale dependent history accepted after identity recomputation")
				}
				if replacementState != CheckPassed {
					retry, err := newCheckReceipt(loaded, test.upstream, checker, CheckPassed, setupDigest("recovered"), RecoveryNone, loaded.UpdatedAt().Add(time.Millisecond))
					if err != nil {
						t.Fatal(err)
					}
					loaded, err = reopened.applyReceipt(context.Background(), retry, catalog)
					if err != nil {
						t.Fatal(err)
					}
				}
				for _, key := range test.dependents {
					authority, _ := catalog.Resolve(key)
					retry, err := newCheckReceipt(loaded, key, authority, CheckPassed, setupDigest("rechecked"), RecoveryNone, loaded.UpdatedAt().Add(time.Millisecond))
					if err != nil {
						t.Fatal(err)
					}
					loaded, err = reopened.applyReceipt(context.Background(), retry, catalog)
					if err != nil {
						t.Fatal(err)
					}
				}
				if !loaded.Ready() || loaded.Validate() != nil {
					t.Fatal("fresh dependent checks did not restore readiness")
				}
			})
		}
	}
}
