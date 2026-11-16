package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

func TestDaemonRestartsAfterOwnerInputSettlement(t *testing.T) {
	args, getenv, repository, base, head, policy, inventory := localFullDaemonFixture(t)
	deps := daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()}
	ctx := context.Background()
	d, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(d.server.Handler)
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-owner-restart")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(ctx, intent); err != nil {
		t.Fatal(err)
	}
	supervisor := d.supervisors[1].(*worker.RepositorySupervisor)
	if worked, err := supervisor.RunOnce(ctx); err != nil || !worked {
		t.Fatalf("owner work=%t err=%v", worked, err)
	}
	receipt, err := api.GetRun(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	task, _ := receipt.Task("context")
	if task.Status() != controlplane.TaskRuntimeSucceeded {
		t.Fatalf("owner context=%s", task.Status())
	}
	fileJournal, ok := d.journal.(*controlplane.FileRunJournal)
	if !ok {
		t.Fatalf("journal type %T", d.journal)
	}
	facts, err := fileJournal.InspectHistoricalContextPackets(ctx)
	if err != nil || len(facts) != 1 {
		t.Fatalf("owner historical facts: %v (%d)", err, len(facts))
	}
	settlement, linked := facts[0].TaskSettlementEvent()
	if !linked || settlement.Kind() != controlplane.RunEventContextInputSettled {
		t.Fatal("historical fact lost the owner v6 settlement")
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatalf("owner settlement restart refused: %v", err)
	}
	defer reopened.Close()
	coordinator, err := controlplane.NewCoordinator(reopened.journal)
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	recovered, _ := state.Task("context")
	if recovered.Status() != controlplane.TaskRuntimeSucceeded || recovered.OutputIdentity() != task.OutputIdentity() {
		t.Fatal("reopened owner context diverged")
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	// Model a stop immediately after the v6 append: no subsequent task
	// availability event can be written while the scope marker still exists.
	streamPath := filepath.Join(daemonTestFlagValue(t, args, "--state-dir"), scope.Identity()+".run.jsonl")
	streamBytes, err := os.ReadFile(streamPath)
	if err != nil {
		t.Fatal(err)
	}
	streamLines := bytes.Split(bytes.TrimSpace(streamBytes), []byte("\n"))
	settlementLine := -1
	for i, line := range streamLines {
		if bytes.Contains(line, []byte(settlement.Identity())) {
			settlementLine = i
			break
		}
	}
	if settlementLine < 0 {
		t.Fatal("persisted v6 event not found")
	}
	if err := os.WriteFile(streamPath, append(bytes.Join(streamLines[:settlementLine+1], []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	// A synthetic persisted marker models a stop after v6 append but before
	// the scope intent's final removal. The isolated owner test injects this
	// interruption during the real effect; this test exercises daemon startup.
	linkedEvent, _ := facts[0].LinkedInputEvent()
	desc := linkedEvent.InputDescriptor()
	preimage, err := json.Marshal(struct{ Version, Plan, Prepared, Lease, Packet, Request, Receipt, Input string }{
		"local-input-settle-v1", facts[0].Plan().Identity(), linkedEvent.Identity(), desc.LeaseIdentity,
		desc.PacketArtifactIdentity, desc.Request.ArtifactIdentity, desc.Receipt.ArtifactIdentity, desc.Input.ArtifactIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(preimage)
	marker := filepath.Join(daemonTestFlagValue(t, args, "--state-dir"), scope.Identity()+".scope-intent.json")
	encoded, err := json.Marshal(struct {
		Version  int    `json:"version"`
		Scope    string `json:"scope"`
		Kind     string `json:"kind"`
		Expected string `json:"expected"`
	}{1, scope.Identity(), "input-settle-v1", hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	fromMarker, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatalf("verified settlement marker was not reconciled: %v", err)
	}
	if err := fromMarker.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verified marker remains: %v", err)
	}
	wrongMarker := bytes.Replace(encoded, []byte(hex.EncodeToString(digest[:])), []byte(strings.Repeat("0", 64)), 1)
	if err := os.WriteFile(marker, append(wrongMarker, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if rejected, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps); rejected != nil || !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		if rejected != nil {
			_ = rejected.Close()
		}
		t.Fatalf("wrong settlement marker admitted: %v", err)
	}
	if _, err := os.Lstat(marker); err != nil {
		t.Fatalf("wrong marker was removed: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	otherScope, _ := audit.NewReviewScope("tenant-a", "repo-a", "unrelated-restart")
	unrelatedMarker := filepath.Join(daemonTestFlagValue(t, args, "--state-dir"), otherScope.Identity()+".scope-intent.json")
	if err := os.WriteFile(unrelatedMarker, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if rejected, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps); rejected != nil || !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		if rejected != nil {
			_ = rejected.Close()
		}
		t.Fatalf("unrelated settlement marker admitted: %v", err)
	}
	if _, err := os.Lstat(unrelatedMarker); err != nil {
		t.Fatalf("unrelated marker removed: %v", err)
	}
	if err := os.Remove(unrelatedMarker); err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(daemonTestFlagValue(t, args, "--state-dir"), "audit", scope.Identity()+".audit.jsonl")
	if err := os.Remove(ledgerPath); err != nil {
		t.Fatal(err)
	}
	if rejected, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps); rejected != nil || !errors.Is(err, errHistoricalInputIntentQuarantinedAtStartup) {
		if rejected != nil {
			_ = rejected.Close()
		}
		t.Fatalf("audit-less owner restart admitted: %v", err)
	}
}
