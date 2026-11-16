package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"github.com/georgejieh/open-trestle/setup"
)

func localFullDaemonFixture(t *testing.T) ([]string, func(string) string, evidence.RepositoryIdentity, evidence.RevisionIdentity, evidence.RevisionIdentity, runtimeconfig.RuntimePolicy, runtimeconfig.RouteInventory) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	objects := filepath.Join(root, "repository", ".git", "objects")
	if err := os.MkdirAll(objects, 0700); err != nil {
		t.Fatal(err)
	}
	base := daemonTestRevision(t, objects, []byte("package main\nfunc main() {}\n"))
	head := daemonTestRevision(t, objects, []byte("package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"debug\") }\n"))
	setupPath := filepath.Join(root, "setup.json")
	setupPlan, err := setup.NewPlan(setup.ProfileLocalSingleNode, "tenant-a", "repo-a", "platform-owner", time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	stateFile, err := setup.OpenStateFile(setupPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := stateFile.Initialize(context.Background(), setupPlan); err != nil {
		t.Fatal(err)
	}
	if err := stateFile.Close(); err != nil {
		t.Fatal(err)
	}
	inventoryPath := filepath.Join(root, "routes.json")
	policyPath := filepath.Join(root, "policy.json")
	manifest := base64.StdEncoding.EncodeToString([]byte(`{"fixture":"local-only route contract"}`))
	routes := make([]map[string]any, 2)
	for index, name := range []string{"a", "b"} {
		routes[index] = map[string]any{"zone": "local", "provider_id": "provider-" + name, "adapter_id": "adapter-" + name, "connection_id": "connection-" + name, "model_id": "model-" + name, "model_version": "1", "max_context_tokens": 128000, "max_output_tokens": 8192, "features": []string{"structured_output"}, "content_logging": "disabled", "pricing_known": true, "input_micro_usd_per_million_tokens": 1000, "output_micro_usd_per_million_tokens": 1000, "quality": "tier_3", "registry_revision": 7, "registry_status": "approved", "evidence_manifest_base64": manifest, "operational_revision": 9, "health": "healthy", "quota": "available", "performance_revision": 11, "latency_known": true, "p95_latency_milliseconds": 2500, "latency_sample_count": 100}
	}
	inventoryBytes, _ := json.Marshal(map[string]any{"schema_version": 1, "routes": routes})
	if err := os.WriteFile(inventoryPath, inventoryBytes, 0600); err != nil {
		t.Fatal(err)
	}
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryBytes))
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		records[record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = record.Identity()
	}
	policyBytes, _ := json.Marshal(map[string]any{
		"schema_version": 2, "verification_route_record_identity": records["adapter-b"], "inventory_identity": inventory.Identity(), "review_policy_identity": strings.Repeat("e", 64), "min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"}, "classification": "confidential", "allowed_zones": []string{"local"}, "content_logging_allowed": false, "estimated_input_tokens": 1000, "max_output_tokens": 4096, "max_cost_micro_usd": 1000000, "pinned_route_record_identity": records["adapter-a"], "preferred_route_record_identities": []string{records["adapter-b"]}, "verification_independence": "distinct_provider", "publication_minimum_severity": "medium", "publication_max_inline_findings": 20, "publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true, "connections": []map[string]string{{"implementation": "openai_responses", "adapter_id": "adapter-a", "endpoint": "http://127.0.0.1:11434/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_A"}, {"implementation": "openai_responses", "adapter_id": "adapter-b", "endpoint": "http://127.0.0.1:11435/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_B"}},
	})
	if err := os.WriteFile(policyPath, policyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyBytes), inventory)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--listen", "127.0.0.1:0", "--state-dir", filepath.Join(root, "runtime"), "--tenant", "tenant-a", "--repository", "repo-a", "--setup-state", setupPath, "--expected-setup-root-identity", setupPlan.RootIdentity(), "--local-git-objects-root", objects, "--local-git-repository-authority", "local.test", "--local-git-repository-namespace", "team", "--local-git-repository-name", "repository", "--local-full-review", "--runtime-route-inventory", inventoryPath, "--runtime-policy", policyPath}
	getenv := func(name string) string {
		if name == "OPEN_TRESTLE_API_TOKEN" {
			return "01234567890123456789012345678901"
		}
		return ""
	}
	repository, _ := evidence.NewRepositoryIdentity("local.test", []string{"team"}, "repository")
	return args, getenv, repository, base, head, policy, inventory
}

func TestDaemonFullLocalAdmissionPersistsPendingPlanWithoutModelDispatch(t *testing.T) {
	args, getenv, repository, base, head, policy, inventory := localFullDaemonFixture(t)
	d, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if len(d.supervisors) != 2 {
		t.Fatalf("full admission missing restricted pre-model worker: supervisors=%d", len(d.supervisors))
	}
	server := httptest.NewServer(d.server.Handler)
	defer server.Close()
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := api.SubmitLocalFullReview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := api.GetRunPlan(context.Background(), scope)
	if err != nil || saved.TaskCount() != 9 || saved.PolicyIdentity() != policy.ReviewPolicyIdentity() || receipt.Status() != controlplane.ReviewRunActive {
		t.Fatalf("admission=(%#v,%#v,%v)", receipt, saved, err)
	}
	sourceTask, _ := saved.Task("source-base")
	if _, err := api.ClaimTask(context.Background(), scope, "source-base", sourceTask.HandlerIdentity()); err == nil {
		t.Fatal("admission-only bearer claimed a source task")
	}
	for _, task := range receipt.Tasks() {
		if task.Key() == "candidates" || task.Key() == "verification" || task.Key() == "readiness" {
			if task.Status() != controlplane.TaskRuntimePending {
				t.Fatalf("premature %s: %s", task.Key(), task.Status())
			}
		}
	}
	otherPolicy, _ := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, strings.Repeat("a", 64), inventory.Identity(), policy.Identity(), intent.CreatedAt())
	if _, err := api.SubmitLocalFullReview(context.Background(), otherPolicy); err == nil {
		t.Fatal("policy mismatch accepted")
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatalf("same-plan replay=%v", err)
	}
	missingHead, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("9", 40))
	missingScope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-missing")
	missing, _ := runtimecatalog.NewLocalFullReviewIntent(missingScope, repository, base, missingHead, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if _, err := api.SubmitLocalFullReview(context.Background(), missing); err == nil {
		t.Fatal("missing source was admitted")
	}
	if _, found, err := d.journal.LoadPlan(context.Background(), missingScope); err != nil || found {
		t.Fatalf("missing source opened plan: found=%t err=%v", found, err)
	}
}
