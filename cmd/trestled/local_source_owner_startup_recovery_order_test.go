package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

func TestBuildDaemonRejectsHistoricalPacketBeforeArtifactDeletionRecovery(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	historicalPacketJournal(t, state, false)

	scope, err := audit.NewReviewScope("previous-tenant", "previous-repository", "previous-run")
	if err != nil {
		t.Fatal(err)
	}
	artifactRoot := filepath.Join(state, "artifacts")
	store, err := artifact.NewFileStore(artifactRoot)
	if err != nil {
		t.Fatal(err)
	}
	value, err := artifact.New(scope, artifact.KindDeterministicEvidence, "application/json",
		artifact.ClassificationInternal, artifact.OriginDeterministicTool,
		artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)},
		[]byte(`{"retained":"until-startup-refusal"}`), time.UnixMilli(200), time.UnixMilli(900))
	if err != nil {
		t.Fatal(err)
	}
	if created, err := store.Put(context.Background(), value, time.UnixMilli(201)); err != nil || !created {
		t.Fatalf("seed artifact: created=%t err=%v", created, err)
	}
	payloadPath := filepath.Join(artifactRoot, scope.Identity()+"-"+value.Identity()+".artifact.json")
	receiptPath := filepath.Join(artifactRoot, scope.Identity()+"-"+value.Identity()+".artifact-deleted.json")
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := artifact.Encode(value)
	if err != nil || !bytes.Equal(payload, encoded) {
		t.Fatalf("seeded artifact differs from canonical encoding: err=%v", err)
	}
	authorization, err := artifact.NewDeletionAuthorization(scope, value.Identity(),
		strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64),
		artifact.DeletionExpired, time.UnixMilli(1000), time.UnixMilli(2000))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Delete(context.Background(), authorization, time.UnixMilli(1000))
	if err != nil || receipt.Validate() != nil || receipt.ArtifactIdentity() != value.Identity() {
		t.Fatalf("seed completed deletion: receipt=%v err=%v", receipt, err)
	}
	receiptBytes, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(payloadPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed deletion left payload: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payloadPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(payloadPath); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("restored payload must be private regular file: info=%v err=%v", info, err)
	}

	args := []string{"--listen", "127.0.0.1:0", "--state-dir", state,
		"--tenant", "new-tenant", "--repository", "new-repository"}
	built, err := buildDaemon(context.Background(), args,
		daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"}),
		&bytes.Buffer{})
	if built != nil {
		_ = built.Close()
	}
	if built != nil || !errors.Is(err, controlplane.ErrPreparedContextPacketAtStartup) {
		t.Fatalf("historical packet refusal: daemon=%v err=%v", built, err)
	}
	for _, name := range []string{localSourceOwnerLeaf, "audit", "diagnostics"} {
		if _, err := os.Lstat(filepath.Join(state, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("rejected startup created %s: %v", name, err)
		}
	}
	if after, err := os.ReadFile(payloadPath); errors.Is(err, os.ErrNotExist) {
		t.Errorf("payload absent after daemon refusal: %v", err)
	} else if err != nil || !bytes.Equal(after, payload) {
		t.Errorf("rejected startup changed payload: err=%v", err)
	}
	if after, err := os.ReadFile(receiptPath); err != nil || !bytes.Equal(after, receiptBytes) {
		t.Errorf("rejected startup changed completed deletion receipt: err=%v", err)
	}
	pending, err := artifact.OpenPendingFileStore(artifactRoot)
	if err != nil {
		t.Fatalf("artifact lease not reacquirable without recovery: %v", err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err := controlplane.NewFileRunJournal(state)
	if err != nil {
		t.Fatalf("journal lease not reacquirable: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
}
