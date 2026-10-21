package controlplane

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHistoricalPacketReplayEventsAreExactAndDefensive(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rooted historical packet scanner is Linux-only")
	}
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "journal")
	journal, fact := rootedHistoricalPacketFixture(t, root, "replay-values")
	actual, err := journal.Read(ctx, fact.Plan().Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	check := func(f HistoricalContextPacketFact) {
		t.Helper()
		events := f.ReplayEvents()
		if len(events) != len(actual) {
			t.Fatalf("events=%d want=%d", len(events), len(actual))
		}
		for i, event := range events {
			got, err := EncodeRunEvent(event)
			if err != nil {
				t.Fatal(err)
			}
			want, err := EncodeRunEvent(actual[i])
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("replay event bytes differ")
			}
			// These tests are in-package so they can exercise private mutable fields.
			events[i].workerIdentity = "changed"
			events[i].preparedArtifact = append(events[i].preparedArtifact, 1)
			if len(events[i].packetDescriptor.DependencyIdentities) > 0 {
				events[i].packetDescriptor.DependencyIdentities[0] = "changed"
			}
		}
		fresh := f.ReplayEvents()
		for i, event := range fresh {
			got, err := EncodeRunEvent(event)
			if err != nil {
				t.Fatal(err)
			}
			want, err := EncodeRunEvent(actual[i])
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("returned events alias retained stream")
			}
		}
		state, err := ReplayReviewRun(f.Plan(), fresh)
		if err != nil || state.HeadIdentity() != f.FinalHeadIdentity() || state.Revision() != f.FinalRevision() {
			t.Fatalf("replay closure: %v", err)
		}
	}
	check(fact)
	err = journal.WithOwnedHistoricalPacketFacts(ctx, func(_ *os.Root, scan HistoricalPacketScan) error {
		return scan(ctx, func(facts []HistoricalContextPacketFact) error {
			if len(facts) != 1 {
				t.Fatal("facts missing")
			}
			check(facts[0])
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if (HistoricalContextPacketFact{}).ReplayEvents() != nil {
		t.Fatal("zero fact returned events")
	}
}

func TestHistoricalPacketReplayEventsRemainProvisional(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rooted historical packet scanner is Linux-only")
	}
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "journal")
	journal, fact := rootedHistoricalPacketFixture(t, root, "replay-drift")
	stream := filepath.Join(root, fact.Plan().Scope().Identity()+runJournalStreamSuffix)
	original, err := os.ReadFile(stream)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(stream, original, 0600); err != nil {
			t.Error(err)
		}
	})
	called := false
	err = journal.WithOwnedHistoricalPacketFacts(ctx, func(_ *os.Root, scan HistoricalPacketScan) error {
		return scan(ctx, func(facts []HistoricalContextPacketFact) error {
			if len(facts) != 1 || len(facts[0].ReplayEvents()) == 0 {
				t.Fatal("provisional events missing")
			}
			called = true
			changed := bytes.Replace(original, []byte(`"run_opened"`), []byte(`"run_failed"`), 1)
			if bytes.Equal(changed, original) {
				t.Fatal("fixture kind absent")
			}
			return os.WriteFile(stream, changed, 0600)
		})
	})
	if !called || err == nil {
		t.Fatalf("late stream drift admitted: called=%t err=%v", called, err)
	}
}

func TestHistoricalPacketReplayEventsCloneSourceAndNestedFields(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rooted historical packet scanner is Linux-only")
	}
	journal, fact := rootedHistoricalPacketFixture(t, filepath.Join(t.TempDir(), "journal"), "source-copy")
	events, err := journal.Read(context.Background(), fact.Plan().Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	state, err := ReplayReviewRun(fact.Plan(), events)
	if err != nil {
		t.Fatal(err)
	}
	facts, overflow, err := historicalFactsForStream(fact.Plan(), events, state, 1)
	if err != nil || overflow || len(facts) != 1 {
		t.Fatalf("facts: %v", err)
	}
	for i := range events {
		events[i].workerIdentity = "source changed"
	}
	for _, event := range facts[0].ReplayEvents() {
		if event.workerIdentity == "source changed" {
			t.Fatal("snapshot aliases source")
		}
	}
	// All mutable nested event fields use the same clone operation, even when
	// this canceled packet fixture has no linked input event.
	event := RunEvent{preparedArtifact: []byte{1}, packetDescriptor: ContextPacketDescriptor{Provenance: []string{"packet"}, DependencyIdentities: []string{"dependency"}}, inputDescriptor: ContextInputDescriptor{Input: ContextInputArtifactDescriptor{Provenance: []string{"input"}}}}
	retained := []RunEvent{cloneHistoricalEvent(event)}
	f := HistoricalContextPacketFact{replay: &retained}
	returned := f.ReplayEvents()
	returned[0].preparedArtifact[0] = 2
	returned[0].packetDescriptor.Provenance[0] = "changed"
	returned[0].packetDescriptor.DependencyIdentities[0] = "changed"
	returned[0].inputDescriptor.Input.Provenance[0] = "changed"
	fresh := f.ReplayEvents()[0]
	if fresh.preparedArtifact[0] != 1 || fresh.packetDescriptor.Provenance[0] != "packet" || fresh.packetDescriptor.DependencyIdentities[0] != "dependency" || fresh.inputDescriptor.Input.Provenance[0] != "input" {
		t.Fatal("nested replay fields alias")
	}
}
