package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/testsupport"
)

func singleBuildRevisionWithUnselected(t *testing.T, objects string, source []byte, extra string) evidence.RevisionIdentity {
	t.Helper()
	blob := daemonWriteLooseObject(t, objects, "blob", source)
	blobBytes, err := hex.DecodeString(blob)
	if err != nil {
		t.Fatal(err)
	}
	extraBytes, err := hex.DecodeString(extra)
	if err != nil {
		t.Fatal(err)
	}
	tree := append([]byte("100644 main.go\x00"), blobBytes...)
	tree = append(tree, []byte("100644 z_unselected.txt\x00")...)
	tree = append(tree, extraBytes...)
	treeID := daemonWriteLooseObject(t, objects, "tree", tree)
	commit := daemonWriteLooseObject(t, objects, "commit", []byte("tree "+treeID+"\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nsource witness\n"))
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, commit)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

type singleBuildDamageSanitizer struct {
	review.GenerationRequestSanitizer
	damage func()
	called bool
}

func (s *singleBuildDamageSanitizer) SanitizeGeneration(ctx context.Context, r provider.Request, scope string) (review.SanitizedModelRequest, review.SanitizedEgressReceipt, error) {
	request, receipt, err := s.GenerationRequestSanitizer.SanitizeGeneration(ctx, r, scope)
	if err == nil {
		s.damage()
		s.called = true
	}
	return request, receipt, err
}

func TestOwnerSanitizerRecheckRejectsUnselectedSourceCorruption(t *testing.T) {
	f := newLocalPacketOwnerFixtureWithUnselected(t, true)
	ctx := context.Background()
	scope := f.request.Plan().Scope()
	packet, err := f.owner.PreparePacket(ctx, f.request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.store.Get(ctx, scope, packet.Descriptor().ArtifactIdentity, f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Sources []struct {
			Path string `json:"path"`
		} `json:"sources"`
	}
	if json.Unmarshal(raw.Payload(), &wire) != nil {
		t.Fatal("packet parse")
	}
	for _, source := range wire.Sources {
		if source.Path == "z_unselected.txt" {
			t.Fatal("damage target selected into packet")
		}
	}
	_, state, err := f.coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	task, _ := state.Task("source-head")
	headArtifact, err := f.store.Get(ctx, scope, task.OutputIdentity(), f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	head, err := sourcehandler.ParseSnapshotArtifact(headArtifact)
	if err != nil {
		t.Fatal(err)
	}
	var damagedID string
	for _, file := range head.Files() {
		if file.Path() == "z_unselected.txt" {
			damagedID = file.ArtifactIdentity()
		}
	}
	if damagedID == "" {
		t.Fatal("unselected source fixture missing")
	}
	paths, err := filepath.Glob(filepath.Join(f.statePath, "artifacts", "*"))
	if err != nil {
		t.Fatal(err)
	}
	damagedPath := ""
	for _, path := range paths {
		if strings.Contains(filepath.Base(path), damagedID) {
			damagedPath = path
		}
	}
	if damagedPath == "" {
		t.Fatal("physical source path missing")
	}
	original, err := os.ReadFile(damagedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(damagedPath, original, 0600)
	before, err := f.journal.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	sanitizer := &singleBuildDamageSanitizer{GenerationRequestSanitizer: testsupport.NewCleanGenerationSanitizer(), damage: func() {
		if err := os.WriteFile(damagedPath, []byte("corrupt source envelope\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}}
	candidate, err := f.owner.SanitizePreparedPacket(ctx, f.request, packet, sanitizer)
	if !sanitizer.called || !errors.Is(err, contexthandler.ErrPacketAuthority) || !strings.Contains(err.Error(), "recheck prepared packet") || candidate.Packet().Artifact().Identity() != "" {
		t.Fatalf("post-scanner source damage admitted or wrong boundary: %v", err)
	}
	after, err := f.journal.Read(ctx, scope, 0, 100)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("damage refusal changed journal", err)
	}
}
