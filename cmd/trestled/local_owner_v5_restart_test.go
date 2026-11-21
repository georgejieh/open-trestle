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

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

func TestDaemonRecoversCompletedOwnerInputPreparation(t *testing.T) {
	args, getenv, repository, base, head, policy, inventory := localFullDaemonFixture(t)
	sanitizerCalls := 0
	deps := daemonDependencies{clock: httpapi.SystemClock{}, generationSanitizer: countingGenerationSanitizer{GenerationRequestSanitizer: daemonTestGenerationSanitizer(), calls: &sanitizerCalls}, verificationSanitizer: daemonTestVerificationSanitizer()}
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
	if sanitizerCalls != 1 {
		t.Fatalf("initial sanitizer calls=%d, want 1", sanitizerCalls)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	linkedEvent, exists := facts[0].LinkedInputEvent()
	if !exists {
		t.Fatal("missing v5 input")
	}
	desc := linkedEvent.InputDescriptor()
	packet := facts[0].PreparedEvent()
	streamPath := filepath.Join(daemonTestFlagValue(t, args, "--state-dir"), scope.Identity()+".run.jsonl")
	content, err := os.ReadFile(streamPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
	v5line := -1
	for i, line := range lines {
		if bytes.Contains(line, []byte(linkedEvent.Identity())) {
			v5line = i
			break
		}
	}
	if v5line < 0 {
		t.Fatal("v5 line not found")
	}
	if err := os.WriteFile(streamPath, append(bytes.Join(lines[:v5line+1], []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	preimage, err := json.Marshal(struct{ Version, Plan, Lease, Packet, Root, Request, Receipt, Selection, Policy, Pair, Authorizer string }{
		"local-input-prepare-v1", facts[0].Plan().Identity(), desc.LeaseIdentity, packet.Identity(), packet.PacketDescriptor().SourceRootIdentity,
		desc.Request.ArtifactIdentity, desc.Receipt.ArtifactIdentity, desc.SelectionReceiptIdentity, desc.PolicyIdentity, desc.RoutePairIdentity, desc.AuthorizerIdentity,
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(preimage)
	marker := filepath.Join(daemonTestFlagValue(t, args, "--state-dir"), scope.Identity()+".scope-intent.json")
	encoded, err := json.Marshal(struct {
		Version  int    `json:"version"`
		Scope    string `json:"scope"`
		Kind     string `json:"kind"`
		Expected string `json:"expected"`
	}{1, scope.Identity(), "input-prepare-v1", hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(daemonTestFlagValue(t, args, "--state-dir"), "artifacts", scope.Identity()+"-"+desc.Input.ArtifactIdentity+".artifact.json")
	inputBytes, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(inputPath); err != nil {
		t.Fatal(err)
	}
	if rejected, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps); rejected != nil || !errors.Is(err, errHistoricalInputIntentQuarantinedAtStartup) {
		if rejected != nil {
			_ = rejected.Close()
		}
		t.Fatalf("partial v5 effects admitted: %v", err)
	}
	if _, err := os.Lstat(marker); err != nil {
		t.Fatalf("partial marker cleared: %v", err)
	}
	if err := os.WriteFile(inputPath, inputBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	wrongMarker := bytes.Replace(encoded, []byte(hex.EncodeToString(sum[:])), []byte(strings.Repeat("0", 64)), 1)
	if err := os.WriteFile(marker, append(wrongMarker, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if rejected, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps); rejected != nil || !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		if rejected != nil {
			_ = rejected.Close()
		}
		t.Fatalf("wrong v5 marker admitted: %v", err)
	}
	if _, err := os.Lstat(marker); err != nil {
		t.Fatalf("wrong v5 marker was cleared: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if rejected, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps); rejected != nil || !errors.Is(err, errHistoricalInputIntentQuarantinedAtStartup) {
		if rejected != nil {
			_ = rejected.Close()
		}
		t.Fatalf("unmarked v5 admitted: %v", err)
	}
	if err := os.WriteFile(marker, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	missingAuditPath := filepath.Join(daemonTestFlagValue(t, args, "--state-dir"), "audit", scope.Identity()+".audit.jsonl")
	missingAuditBytes, err := os.ReadFile(missingAuditPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(missingAuditPath); err != nil {
		t.Fatal(err)
	}
	if rejected, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps); rejected != nil || !errors.Is(err, errHistoricalInputIntentQuarantinedAtStartup) {
		if rejected != nil {
			_ = rejected.Close()
		}
		t.Fatalf("v5 marker without route audit admitted: %v", err)
	}
	if _, err := os.Lstat(marker); err != nil {
		t.Fatalf("v5 marker cleared without audit: %v", err)
	}
	if err := os.WriteFile(missingAuditPath, missingAuditBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	recoveredDaemon, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatalf("complete-effects v5 marker restart refused: %v", err)
	}
	defer recoveredDaemon.Close()
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("v5 marker not cleared: %v", err)
	}
	coordinator, err := controlplane.NewCoordinator(recoveredDaemon.journal)
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	recoveredTask, _ := state.Task("context")
	if recoveredTask.Status() != controlplane.TaskRuntimeSucceeded || recoveredTask.OutputIdentity() != desc.Input.ArtifactIdentity {
		t.Fatal("v5 restart failed to settle exact input")
	}
	if err := recoveredDaemon.Close(); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(daemonTestFlagValue(t, args, "--state-dir"), "audit", scope.Identity()+".audit.jsonl")
	auditBefore, err := os.ReadFile(auditPath)
	if err != nil || !bytes.Equal(auditBefore, missingAuditBytes) {
		t.Fatalf("route audit duplicated by v5 recovery: %v", err)
	}
	// A second interruption after the append must reprove, not append twice.
	if err := os.WriteFile(marker, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	replayedDaemon, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatalf("post-append input-prepare marker refused: %v", err)
	}
	defer replayedDaemon.Close()
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("post-append marker retained: %v", err)
	}
	replayedCoordinator, err := controlplane.NewCoordinator(replayedDaemon.journal)
	if err != nil {
		t.Fatal(err)
	}
	_, replayedState, err := replayedCoordinator.Resume(ctx, scope)
	if err != nil || replayedState.Revision() != state.Revision() {
		t.Fatalf("v6 settlement repeated after restart: %v", err)
	}
	auditAfter, err := os.ReadFile(auditPath)
	if err != nil || !bytes.Equal(auditBefore, auditAfter) {
		t.Fatalf("route audit duplicated on replay: %v", err)
	}
	if sanitizerCalls != 1 {
		t.Fatalf("input preparation repeated: sanitizer calls=%d", sanitizerCalls)
	}
}
