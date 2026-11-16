package main

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

func TestNoAuthLocalCLICompletesNineTasksWithoutCredentialEnvironment(t *testing.T) {
	for _, chat := range []bool{false, true} {
		name := "responses"
		if chat {
			name = "chat"
		}
		t.Run(name, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{noAuth: true, chatCompletions: chat})
			t.Setenv("OPEN_TRESTLE_PROVIDER_LOCAL_TEST_A", "")
			t.Setenv("OPEN_TRESTLE_PROVIDER_LOCAL_TEST_B", "")
			encoded, err := os.ReadFile(f.policyPath)
			if err != nil {
				t.Fatal(err)
			}
			var policy map[string]any
			if json.Unmarshal(encoded, &policy) != nil || policy["schema_version"] != float64(2) || policy["verification_route_record_identity"] != f.verificationRoute {
				t.Fatal("NO_AUTH CLI fixture lacks explicit v2 verifier authority")
			}
			for _, raw := range policy["connections"].([]any) {
				connection := raw.(map[string]any)
				if connection["credential_mode"] != "none" {
					t.Fatal("CLI did not request explicit NO_AUTH")
				}
				if _, present := connection["credential_environment"]; present {
					t.Fatal("NO_AUTH policy carried credential environment")
				}
			}
			result, _ := localModelExecute(t, f, f.args, 4)
			gc, generated := f.generation.snapshot()
			vc, verified := f.verification.snapshot()
			if result.Status != "findings" || result.CI != "blocked" || result.RunStatus != "succeeded" || result.ComprehensiveClearance || gc != 1 || vc != 1 || len(generated) != 1 || len(verified) != 1 || result.Independence != "distinct_provider" || len(result.Diagnostics.Findings) != 1 || result.Diagnostics.Coverage.VerifiedCount != 1 {
				t.Fatalf("NO_AUTH CLI failed: %s/%s calls %d/%d", result.Status, result.RunStatus, gc, vc)
			}
			keys := []string{}
			for _, task := range result.Tasks {
				keys = append(keys, task.Key)
				if task.Status != "succeeded" || task.Attempts != 1 || task.Output == "" {
					t.Fatal("NO_AUTH task failed or retried")
				}
			}
			slices.Sort(keys)
			if !slices.Equal(keys, []string{"analysis", "candidates", "change", "context", "memory", "readiness", "source-base", "source-head", "verification"}) {
				t.Fatalf("NO_AUTH tasks=%v", keys)
			}
			if result.Policy != f.policyID || result.GenerationRoute != f.generationRoute || result.VerificationRoute != f.verificationRoute || result.Context != generated[0].ContextID || result.VerificationContext != verified[0].ContextID {
				t.Fatal("NO_AUTH bypassed configured route/context identities")
			}
		})
	}
}
