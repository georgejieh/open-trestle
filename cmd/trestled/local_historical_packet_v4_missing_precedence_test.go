package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
)

func TestLocalHistoricalPacketEarlierMismatchLaterMissingPrecedence(t *testing.T) {
	ctx := context.Background()
	f := newLocalPacketOwnerFixture(t)
	first, err := f.owner.PreparePacket(ctx, f.request)
	if err != nil {
		t.Fatalf("first physical owner Put: %v", err)
	}
	stored, err := f.store.Get(ctx, f.request.Plan().Scope(), first.Descriptor().ArtifactIdentity, f.clock.Now())
	if err != nil {
		t.Fatalf("first physical owner readback: %v", err)
	}
	firstBytes, err := artifact.Encode(stored)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Kind() != artifact.KindContextPacket || !bytes.Contains(stored.Payload(), []byte("fmt.Println")) ||
		stored.Identity() != first.Descriptor().ArtifactIdentity || stored.PayloadDigest() != first.Descriptor().PayloadDigest ||
		first.Descriptor().SourceRootIdentity != f.rootDigest || first.Descriptor().LeaseIdentity != f.request.Lease().Identity() {
		t.Fatal("first physical packet is not bound to the Git owner and recorded descriptor")
	}
	secondPlan, second := prepareLocalHistoricalSecondScope(t, f, "tenant-a", "repo-a")
	if secondPlan.Scope().Identity() <= f.request.Plan().Scope().Identity() {
		t.Fatal("missing packet must belong to the lexically later scope")
	}
	firstEvents := encodedLocalPacketHistory(t, f.journal, f.request.Plan().Scope())
	secondEvents := encodedLocalPacketHistory(t, f.journal, secondPlan.Scope())
	if err := f.resources.Close(); err != nil {
		t.Fatalf("close original owner resources: %v", err)
	}
	assertLocalHistoricalRawTwoScopes(t, f, first, second, secondPlan, firstBytes, firstEvents, secondEvents)

	firstLeaf := filepath.Join(f.statePath, "artifacts", f.request.Plan().Scope().Identity()+"-"+first.Descriptor().ArtifactIdentity+".artifact.json")
	secondLeaf := filepath.Join(f.statePath, "artifacts", secondPlan.Scope().Identity()+"-"+second.Descriptor().ArtifactIdentity+".artifact.json")
	changed := bytes.Clone(firstBytes)
	marker := []byte(`"payload":"`)
	start := bytes.Index(changed, marker)
	if start < 0 || start+len(marker) >= len(changed) {
		t.Fatal("encoded first packet payload missing")
	}
	at := start + len(marker)
	replacement := byte('A')
	if changed[at] == replacement {
		replacement = 'B'
	}
	changed[at] = replacement
	if !json.Valid(changed) || len(changed) != len(firstBytes) {
		t.Fatal("first mutation lost stable canonical JSON framing or length")
	}
	if _, err := artifact.Parse(changed); !errors.Is(err, artifact.ErrInvalidArtifactIdentity) {
		t.Fatalf("first mutation must invalidate the artifact identity: %v", err)
	}
	originalInfo, err := os.Lstat(firstLeaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstLeaf, changed, 0600); err != nil {
		t.Fatal(err)
	}
	changedInfo, err := os.Lstat(firstLeaf)
	if err != nil || !os.SameFile(originalInfo, changedInfo) || originalInfo.Mode() != changedInfo.Mode() || originalInfo.Size() != changedInfo.Size() {
		t.Fatalf("first mutation changed inode, mode, or size: %v", err)
	}
	if raw, err := os.ReadFile(firstLeaf); err != nil || !bytes.Equal(raw, changed) {
		t.Fatalf("first packet mutation not durable: %v", err)
	}
	if _, err := os.Lstat(secondLeaf); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("later physical packet appeared: %v", err)
	}
	before := snapshotLocalPacketFiles(t, f.statePath)
	boot := &daemon{}
	t.Cleanup(func() {
		if err := boot.Close(); err != nil {
			t.Errorf("cleanup refused boot: %v", err)
		}
	})
	active, journal, owner, bootErr := startLocalSourceOwnerGate(ctx, boot, f.statePath, f.setupPath, &f.setupPlan,
		"tenant-a", "repo-a", f.repository, f.gitRoot, f.objectStore, f.adapter, f.rootDigest, f.clock)
	if active != nil || journal != nil || owner != nil || bootErr == nil {
		t.Fatalf("historical packet refusal must return nil handles: %v %v %v %v", active, journal, owner, bootErr)
	}
	if err := boot.Close(); err != nil {
		t.Fatalf("close refused boot resources: %v", err)
	}
	if after := snapshotLocalPacketFiles(t, f.statePath); !reflect.DeepEqual(before, after) {
		t.Fatal("refused boot changed runtime file names or bytes")
	}
	reopenedJournal, err := controlplane.NewFileRunJournal(f.statePath)
	if err != nil {
		t.Fatalf("reopen raw journal writer: %v", err)
	}
	if got := encodedLocalPacketHistory(t, reopenedJournal, f.request.Plan().Scope()); !reflect.DeepEqual(got, firstEvents) {
		t.Error("first journal stream changed")
	}
	if got := encodedLocalPacketHistory(t, reopenedJournal, secondPlan.Scope()); !reflect.DeepEqual(got, secondEvents) {
		t.Error("second journal stream changed")
	}
	facts, err := reopenedJournal.InspectHistoricalContextPackets(ctx)
	if err != nil || len(facts) != 2 {
		t.Fatalf("raw two-scope replay changed after refusal: %d %v", len(facts), err)
	}
	if err := reopenedJournal.Close(); err != nil {
		t.Fatal(err)
	}
	pending, err := artifact.OpenPendingFileStore(filepath.Join(f.statePath, "artifacts"))
	if err != nil {
		t.Fatalf("reopen pending artifact writer: %v", err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	if after := snapshotLocalPacketFiles(t, f.statePath); !reflect.DeepEqual(before, after) {
		t.Fatal("raw writer reopen changed runtime file names or bytes")
	}
	if raw, err := os.ReadFile(firstLeaf); err != nil || !bytes.Equal(raw, changed) {
		t.Fatalf("first mismatched packet changed after refusal: %v", err)
	}
	if _, err := os.Lstat(secondLeaf); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("later missing packet appeared after refusal: %v", err)
	}
	if !errors.Is(bootErr, errHistoricalPacketMissingAtStartup) ||
		errors.Is(bootErr, errHistoricalPacketMismatchAtStartup) ||
		errors.Is(bootErr, errHistoricalPacketObservedAtStartup) ||
		errors.Is(bootErr, controlplane.ErrPreparedContextPacketAtStartup) ||
		errors.Is(bootErr, errHistoricalInputIntentQuarantinedAtStartup) {
		t.Fatalf("later missing v4 must win globally over earlier mismatched v4: %v", bootErr)
	}
}
