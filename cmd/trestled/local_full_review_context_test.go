package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/provider"
	reviewcore "github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

type countingGenerationSanitizer struct {
	reviewcore.GenerationRequestSanitizer
	calls *int
}

func (s countingGenerationSanitizer) SanitizeGeneration(ctx context.Context, request provider.Request, scope string) (reviewcore.SanitizedModelRequest, reviewcore.SanitizedEgressReceipt, error) {
	*s.calls++
	return s.GenerationRequestSanitizer.SanitizeGeneration(ctx, request, scope)
}

func TestDaemonFullLocalReviewBuildsBoundContextWithoutGeneration(t *testing.T) {
	args, getenv, repository, base, head, policy, inventory := localFullDaemonFixture(t)
	sanitizerCalls := 0
	deps := daemonDependencies{clock: httpapi.SystemClock{}, generationSanitizer: countingGenerationSanitizer{GenerationRequestSanitizer: testsupport.NewCleanGenerationSanitizer(), calls: &sanitizerCalls}, verificationSanitizer: reviewcore.NewFixedVerificationRequestSanitizer(nil)}
	d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if len(d.supervisors) != 2 {
		t.Fatalf("pre-model worker missing: supervisors=%d", len(d.supervisors))
	}
	supervisor, ok := d.supervisors[1].(*worker.RepositorySupervisor)
	if !ok {
		t.Fatalf("unexpected pre-model worker %T", d.supervisors[1])
	}
	server := httptest.NewServer(d.server.Handler)
	defer server.Close()
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-context")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	worked, err := supervisor.RunOnce(context.Background())
	if err != nil || !worked {
		t.Fatalf("pre-model work=%t err=%v", worked, err)
	}
	// Check physical writes, not just completion events: the old handler wrote
	// a packet before any owner preparation and only then completed the task.
	packetEvents, err := d.journal.Read(context.Background(), scope, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	preparedPackets := map[string]bool{}
	for _, event := range packetEvents {
		if event.TaskKey() == "context" && event.Kind() == controlplane.RunEventContextPacketPrepared {
			preparedPackets[event.PacketDescriptor().ArtifactIdentity] = true
		}
	}
	artifactLeaves, err := filepath.Glob(filepath.Join(daemonTestFlagValue(t, args, "--state-dir"), "artifacts", "*.artifact.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, leaf := range artifactLeaves {
		encoded, readErr := os.ReadFile(leaf)
		if readErr != nil {
			t.Fatal(readErr)
		}
		stored, parseErr := artifact.Parse(encoded)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if stored.Scope().Identity() == scope.Identity() && stored.Kind() == artifact.KindContextPacket && !preparedPackets[stored.Identity()] {
			t.Fatalf("physical context packet %s has no owner journal lineage", stored.Identity())
		}
	}
	receipt, err := api.GetRun(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[string]controlplane.TaskRuntimeStatus{}
	outputs := map[string]string{}
	for _, task := range receipt.Tasks() {
		statuses[task.Key()] = task.Status()
		outputs[task.Key()] = task.OutputIdentity()
	}
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory", "context"} {
		if statuses[key] != controlplane.TaskRuntimeSucceeded {
			t.Fatalf("%s status=%s, want succeeded", key, statuses[key])
		}
	}
	if statuses["candidates"] != controlplane.TaskRuntimeAvailable || statuses["verification"] != controlplane.TaskRuntimePending || statuses["readiness"] != controlplane.TaskRuntimePending {
		t.Fatalf("model tasks advanced: %v", statuses)
	}
	for _, item := range []struct{ key, revision string }{{"source-base", base.Identity()}, {"source-head", head.Identity()}} {
		value, err := d.artifactStore.Get(context.Background(), scope, outputs[item.key], time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := sourcehandler.ParseSnapshotArtifact(value)
		if err != nil || snapshot.RevisionIdentity() != item.revision || snapshot.RepositoryIdentity() != repository.Identity() || snapshot.FileCount() == 0 {
			t.Fatalf("%s snapshot=%#v err=%v", item.key, snapshot, err)
		}
	}
	value, err := d.artifactStore.Get(context.Background(), scope, outputs["context"], time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if value.Kind() != artifact.KindTaskInput {
		t.Fatalf("context output kind=%s, want task_input", value.Kind())
	}
	events, err := d.journal.Read(context.Background(), scope, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	packetIndex, inputIndex, settledIndex := -1, -1, -1
	packetIdentity := ""
	for i, event := range events {
		if event.TaskKey() != "context" {
			continue
		}
		switch event.Kind() {
		case controlplane.RunEventContextPacketPrepared:
			packetIndex, packetIdentity = i, event.PacketDescriptor().ArtifactIdentity
		case controlplane.RunEventContextInputPrepared:
			inputIndex = i
			if event.InputDescriptor().Input.ArtifactIdentity != value.Identity() || event.InputDescriptor().PacketArtifactIdentity != packetIdentity {
				t.Fatal("prepared input does not bind the stored task_input and packet")
			}
		case controlplane.RunEventContextInputSettled:
			settledIndex = i
			if event.OutputIdentity() != value.Identity() {
				t.Fatal("settlement does not bind stored task_input")
			}
		case controlplane.RunEventTaskSucceeded:
			t.Fatal("generic task success after owner packet")
		}
	}
	if packetIndex < 0 || inputIndex <= packetIndex || settledIndex <= inputIndex {
		t.Fatalf("context bypassed owner packet/input preparation: packet=%d input=%d settled=%d", packetIndex, inputIndex, settledIndex)
	}
	packetValue, err := d.artifactStore.Get(context.Background(), scope, packetIdentity, time.Now().UTC())
	if err != nil || packetValue.Kind() != artifact.KindContextPacket {
		t.Fatalf("prepared physical packet: %v", err)
	}
	parsed, err := modelhandler.ParseGenerationInput(value.Payload())
	if err != nil || !parsed.IsSanitized() || parsed.ContextArtifactIdentity() != packetIdentity {
		t.Fatalf("invalid sanitized context handoff: %v", err)
	}

	var packet struct {
		Contract       string `json:"contract"`
		SourceCoverage struct {
			Analyzed int `json:"analyzed"`
			Selected int `json:"selected"`
			Omitted  int `json:"omitted"`
		} `json:"source_coverage"`
		Sources []json.RawMessage `json:"sources"`
	}
	if err := json.Unmarshal(packetValue.Payload(), &packet); err != nil || packet.Contract != "open-trestle/review-context-packet" || packet.SourceCoverage.Selected == 0 || len(packet.Sources) != packet.SourceCoverage.Selected || packet.SourceCoverage.Analyzed != packet.SourceCoverage.Selected+packet.SourceCoverage.Omitted {
		t.Fatalf("context packet coverage=%+v err=%v", packet.SourceCoverage, err)
	}
	worked, err = supervisor.RunOnce(context.Background())
	if err != nil || worked || sanitizerCalls == 0 {
		t.Fatalf("model work escaped restricted catalog: worked=%t err=%v sanitizer_calls=%d", worked, err, sanitizerCalls)
	}
}
