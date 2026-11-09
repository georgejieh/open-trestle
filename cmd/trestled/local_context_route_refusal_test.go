//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"github.com/georgejieh/open-trestle/worker"
)

// routeCapacity sets the generation route's declared context and output and
// the policy's context floor and declared input estimate.
type routeCapacity struct{ context, output, minContext, estimatedInput float64 }

// refusalRouteContextTokens with a 4096-token output allowance and a one-token
// declared input floor lets the pair resolve, while the byte-based estimate of
// every actual request outgrows the route.
const refusalRouteContextTokens = 4097

var everyRequestRefused = routeCapacity{refusalRouteContextTokens, 4096, refusalRouteContextTokens, 1}

func contextRefusalModelWorkerFixture(t *testing.T) ([]string, func(string) string, *daemonBudgetedModelFixture, evidence.RepositoryIdentity, evidence.RevisionIdentity, evidence.RevisionIdentity, runtimeconfig.RuntimePolicy, runtimeconfig.RouteInventory) {
	t.Helper()
	return capacityModelWorkerFixture(t, everyRequestRefused)
}

func capacityModelWorkerFixture(t *testing.T, capacity routeCapacity) ([]string, func(string) string, *daemonBudgetedModelFixture, evidence.RepositoryIdentity, evidence.RevisionIdentity, evidence.RevisionIdentity, runtimeconfig.RuntimePolicy, runtimeconfig.RouteInventory) {
	t.Helper()
	args, getenv, fake, repository, base, head, _, _ := localModelWorkerFixture(t)
	rewrite := func(path string, change func(map[string]any)) []byte {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]any
		if err := json.Unmarshal(raw, &wire); err != nil {
			t.Fatal(err)
		}
		change(wire)
		raw = daemonBudgetedModelJSON(t, wire)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	inventoryBytes := rewrite(fake.inventoryPath, func(wire map[string]any) {
		for _, entry := range wire["routes"].([]any) {
			if route := entry.(map[string]any); route["adapter_id"] == "daemon-adapter-a" {
				route["max_context_tokens"] = capacity.context
				route["max_output_tokens"] = capacity.output
			}
		}
	})
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryBytes))
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		records[record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = record.Identity()
	}
	policyBytes := rewrite(fake.policyPath, func(wire map[string]any) {
		wire["min_context_tokens"] = capacity.minContext
		wire["estimated_input_tokens"] = capacity.estimatedInput
		wire["inventory_identity"] = inventory.Identity()
		wire["verification_route_record_identity"] = records["daemon-adapter-b"]
		wire["pinned_route_record_identity"] = records["daemon-adapter-a"]
		wire["preferred_route_record_identities"] = []string{records["daemon-adapter-b"]}
	})
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyBytes), inventory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtimecatalog.ResolveLocalGenerationRoutePair(policy, inventory); err != nil {
		t.Fatalf("fixture route pair: %v", err)
	}
	return args, getenv, fake, repository, base, head, policy, inventory
}

// assertContextRouteRefusal checks one settled refusal: the context task's
// recorded reason and counts on the API receipt, the failed run, the retained
// packet, no input, marker or route audit, and the expected model call count.
func assertContextRouteRefusal(t *testing.T, d *daemon, api *client.Client, fake *daemonBudgetedModelFixture, scope audit.ReviewScope, statePath string, at time.Time, declared uint32, calls int) {
	t.Helper()
	ctx := context.Background()
	receipt, err := api.GetRun(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	task, found := receipt.Task("context")
	shortfall, counted := task.ContextShortfall()
	if !found || task.Status() != controlplane.TaskRuntimeFailed || task.Failure() != controlplane.RunFailurePolicy || task.FailureReason() != controlplane.TaskFailureReasonRouteContextInsufficient || !counted || task.OutputIdentity() != "" || receipt.Status() != controlplane.ReviewRunFailed || receipt.Failure() != controlplane.RunFailurePolicy {
		t.Fatalf("context refusal receipt: status=%v failure=%v reason=%v counted=%v run=%v", task.Status(), task.Failure(), task.FailureReason(), counted, receipt.Status())
	}
	if shortfall.DeclaredContextTokens != declared || shortfall.MaxOutputTokens != 4096 || shortfall.RequiredTokens != uint64(shortfall.EstimatedInputTokens)+4096 || shortfall.RequiredTokens <= uint64(declared) {
		t.Fatalf("shortfall counts = %+v", shortfall)
	}
	journal := d.journal.(*controlplane.FileRunJournal)
	events, err := journal.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var packet, lease controlplane.RunEvent
	refusals := 0
	for _, event := range events {
		switch event.Kind() {
		case controlplane.RunEventTaskLeased:
			if event.TaskKey() == "context" {
				lease = event
			}
		case controlplane.RunEventContextPacketPrepared:
			packet = event
		case controlplane.RunEventContextInputPrepared, controlplane.RunEventContextInputSettled:
			t.Fatal("refusal created input")
		case controlplane.RunEventTaskFailed:
			refusals++
			if event.PreviousIdentity() != packet.Identity() || event.FailureReason() != controlplane.TaskFailureReasonRouteContextInsufficient || event.OutputIdentity() != "" || !event.RetryAt().IsZero() || !event.OccurredAt().Before(lease.LeaseExpiresAt()) {
				t.Fatal("refusal is not the in-lease settlement of the packet")
			}
		}
	}
	if packet.Kind() != controlplane.RunEventContextPacketPrepared || refusals != 1 {
		t.Fatalf("packet=%v refusals=%d", packet.Kind(), refusals)
	}
	if _, err := d.artifactStore.Get(ctx, scope, packet.PacketDescriptor().ArtifactIdentity, at); err != nil {
		t.Fatalf("refused packet not retained: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(statePath, scope.Identity()+".scope-intent.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refusal marker: %v", err)
	}
	auditRoot, err := os.OpenRoot(filepath.Join(statePath, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditRoot.Close()
	auditEvents, err := audit.ObserveFileStream(ctx, auditRoot, scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range auditEvents {
		if event.Kind() == audit.EventRouteSelected || event.Kind() == audit.EventRouteAttemptClaimed {
			t.Fatal("refusal gained route evidence")
		}
	}
	for _, endpoint := range []*daemonBudgetedModelEndpoint{fake.generation, fake.verification} {
		if got, _, _, failures := endpoint.snapshot(); got != calls || len(failures) != 0 {
			t.Fatalf("model calls=%d, want %d; failures=%v", got, calls, failures)
		}
	}
	diagnostic, err := api.GetDiagnosticSet(ctx, scope)
	if err != nil || diagnostic.Outcome() != diagnostics.FinalOutcomeFailed || len(diagnostic.Findings()) != 0 {
		t.Fatalf("refusal diagnostic=%s err=%v", diagnostic.Outcome(), err)
	}
	refusal, refused := diagnostic.ContextRefusal()
	if want := (diagnostics.ContextRefusal{Reason: diagnostics.ContextRefusalRouteContextInsufficient, RequiredTokens: shortfall.RequiredTokens, EstimatedInputTokens: shortfall.EstimatedInputTokens, MaxOutputTokens: shortfall.MaxOutputTokens, DeclaredContextTokens: shortfall.DeclaredContextTokens}); !refused || refusal != want {
		t.Fatalf("final set refusal = %+v, %v; want %+v", refusal, refused, want)
	}
}

func startContextRefusalDaemon(t *testing.T, args []string, getenv func(string) string, clock *daemonBudgetedHandlerClock) (*daemon, *client.Client, *httptest.Server) {
	t.Helper()
	d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: clock, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	server := httptest.NewServer(d.server.Handler)
	t.Cleanup(server.Close)
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return d, api, server
}

func runLocalFullReviewOnSupervisors(t *testing.T, d *daemon, api *client.Client, run string, repository evidence.RepositoryIdentity, base, head evidence.RevisionIdentity, policy runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, at time.Time) audit.ReviewScope {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", run)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{1, 2, 1} {
		if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
			t.Fatalf("%s: supervisor %d stopped: %v", run, index, err)
		}
	}
	return scope
}

// A context route refusal is an ordinary run outcome: the supervisor settles it
// within the packet lease and keeps serving later runs instead of stopping.
func TestDaemonLocalModelWorkersContextRouteRefusalSettles(t *testing.T) {
	args, getenv, fake, repository, base, head, policy, inventory := contextRefusalModelWorkerFixture(t)
	args = append(args, "--local-model-workers")
	clock := &daemonBudgetedHandlerClock{at: time.Now().UTC().Truncate(time.Millisecond)}
	statePath := daemonTestFlagValue(t, args, "--state-dir")
	d, api, _ := startContextRefusalDaemon(t, args, getenv, clock)
	for _, run := range []string{"run-route-refusal", "run-route-refusal-later"} {
		scope := runLocalFullReviewOnSupervisors(t, d, api, run, repository, base, head, policy, inventory, clock.Now())
		assertContextRouteRefusal(t, d, api, fake, scope, statePath, clock.Now(), refusalRouteContextTokens, 0)
	}
}

// A restart after a settled refusal recovers it without an append while the
// original lease is still live, after it expires, and after the packet's 24-hour
// retention lapses, and serves later runs.
func TestDaemonLocalModelWorkersContextRouteRefusalSurvivesRestart(t *testing.T) {
	for _, mode := range []string{"live-lease", "expired-lease", "retention-lapsed"} {
		t.Run(mode, func(t *testing.T) {
			args, getenv, fake, repository, base, head, policy, inventory := contextRefusalModelWorkerFixture(t)
			args = append(args, "--local-model-workers")
			clock := &daemonBudgetedHandlerClock{at: time.Now().UTC().Truncate(time.Millisecond)}
			statePath := daemonTestFlagValue(t, args, "--state-dir")
			d, api, server := startContextRefusalDaemon(t, args, getenv, clock)
			scope := runLocalFullReviewOnSupervisors(t, d, api, "run-route-refusal", repository, base, head, policy, inventory, clock.Now())
			assertContextRouteRefusal(t, d, api, fake, scope, statePath, clock.Now(), refusalRouteContextTokens, 0)
			before, err := api.GetRun(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			refusedAt := clock.Now()
			server.Close()
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			if mode != "live-lease" {
				clock.mu.Lock()
				clock.at = clock.at.Add(time.Minute)
				if mode == "retention-lapsed" {
					clock.at = clock.at.Add(25 * time.Hour)
				}
				clock.mu.Unlock()
			}
			journalBefore := ownerStartupJournalBytes(t, statePath)
			d, api, _ = startContextRefusalDaemon(t, args, getenv, clock)
			if !reflect.DeepEqual(journalBefore, ownerStartupJournalBytes(t, statePath)) {
				t.Fatal("restart appended to a settled refusal")
			}
			after, err := api.GetRun(context.Background(), scope)
			if err != nil || after.HeadIdentity() != before.HeadIdentity() {
				t.Fatalf("restart changed the refused run: %v", err)
			}
			// The packet bytes stay on disk; after retention the store refuses to
			// serve them, so they are checked as of the refusal.
			assertContextRouteRefusal(t, d, api, fake, scope, statePath, refusedAt, refusalRouteContextTokens, 0)
			later := runLocalFullReviewOnSupervisors(t, d, api, "run-route-refusal-later", repository, base, head, policy, inventory, clock.Now())
			assertContextRouteRefusal(t, d, api, fake, later, statePath, clock.Now(), refusalRouteContextTokens, 0)
		})
	}
}

// largeReviewHead writes a head revision whose review request is larger than
// the fixture's base-to-head request.
func largeReviewHead(t *testing.T, args []string) evidence.RevisionIdentity {
	t.Helper()
	var large bytes.Buffer
	large.WriteString("package main\nimport \"fmt\"\nfunc main() {\n")
	for i := range 40 {
		fmt.Fprintf(&large, "\tfmt.Println(\"debug %04d\")\n", i)
	}
	large.WriteString("}\n")
	return daemonTestRevision(t, daemonTestFlagValue(t, args, "--local-git-objects-root"), large.Bytes())
}

// probeRequiredTokens returns the recorded required context of the large and
// the small review when the route takes neither, under the same policy floors.
func probeRequiredTokens(t *testing.T, floor routeCapacity) (large, small uint64) {
	t.Helper()
	args, getenv, _, repository, base, head, policy, inventory := capacityModelWorkerFixture(t, floor)
	args = append(args, "--local-model-workers")
	largeHead := largeReviewHead(t, args)
	clock := &daemonBudgetedHandlerClock{at: time.Now().UTC().Truncate(time.Millisecond)}
	d, api, _ := startContextRefusalDaemon(t, args, getenv, clock)
	required := func(run string, head evidence.RevisionIdentity) uint64 {
		scope := runLocalFullReviewOnSupervisors(t, d, api, run, repository, base, head, policy, inventory, clock.Now())
		receipt, err := api.GetRun(context.Background(), scope)
		if err != nil {
			t.Fatal(err)
		}
		task, _ := receipt.Task("context")
		shortfall, ok := task.ContextShortfall()
		if !ok {
			t.Fatalf("probe %s was not refused for context", run)
		}
		return shortfall.RequiredTokens
	}
	return required("probe-large", largeHead), required("probe-small", head)
}

// A refused large review and a later completed small review coexist across a
// restart: the refused v4 and the settled v6 are both recovered without an
// append, a new dispatch, or a changed result. A probe measures both requests
// so the route capacity falls between them.
func TestDaemonLocalModelWorkersRefusedRunLaterRunAndRestart(t *testing.T) {
	floor := routeCapacity{12096, 8192, 12096, 8000}
	large, small := probeRequiredTokens(t, floor)
	if large <= small+2 {
		t.Fatalf("large review requires %d tokens, small %d", large, small)
	}
	capacity := floor
	capacity.context = float64((large + small) / 2)
	args, getenv, fake, repository, base, head, policy, inventory := capacityModelWorkerFixture(t, capacity)
	args = append(args, "--local-model-workers")
	largeHead := largeReviewHead(t, args)
	clock := &daemonBudgetedHandlerClock{at: time.Now().UTC().Truncate(time.Millisecond)}
	statePath := daemonTestFlagValue(t, args, "--state-dir")
	d, api, server := startContextRefusalDaemon(t, args, getenv, clock)
	refused := runLocalFullReviewOnSupervisors(t, d, api, "run-large-refused", repository, base, largeHead, policy, inventory, clock.Now())
	assertContextRouteRefusal(t, d, api, fake, refused, statePath, clock.Now(), uint32(capacity.context), 0)
	later := runLocalFullReviewOnSupervisors(t, d, api, "run-small-later", repository, base, head, policy, inventory, clock.Now())
	finals := map[audit.ReviewScope]string{}
	for scope, outcome := range map[audit.ReviewScope]diagnostics.FinalOutcome{refused: diagnostics.FinalOutcomeFailed, later: diagnostics.FinalOutcomeCompleted} {
		final, err := api.GetDiagnosticSet(context.Background(), scope)
		if err != nil || final.Outcome() != outcome {
			t.Fatalf("%s final=%s err=%v", scope.Identity(), final.Outcome(), err)
		}
		finals[scope] = final.Identity()
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, api, _ = startContextRefusalDaemon(t, args, getenv, clock)
	for _, index := range []int{1, 2} {
		if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for scope, identity := range finals {
		final, err := api.GetDiagnosticSet(context.Background(), scope)
		if err != nil || final.Identity() != identity {
			t.Fatalf("restart changed %s result: %v", scope.Identity(), err)
		}
	}
	assertContextRouteRefusal(t, d, api, fake, refused, statePath, clock.Now(), uint32(capacity.context), 1)
}
