package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestJournalSharedPlanByteParser(t *testing.T) {
	plan := runPlanFixture(t)
	encoded, err := EncodeReviewRunPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseInventoryPlanBytes(plan.Scope().Identity(), encoded)
	if err != nil || got.Identity() != plan.Identity() {
		t.Fatalf("plan=%v err=%v", got.Identity(), err)
	}
	if _, err := parseInventoryPlanBytes("wrong", encoded); !errors.Is(err, ErrInvalidReviewRunPlanEncoding) {
		t.Fatalf("wrong base: %v", err)
	}
	if _, err := parseInventoryPlanBytes(plan.Scope().Identity(), []byte("invalid")); !errors.Is(err, ErrInvalidReviewRunPlanEncoding) {
		t.Fatalf("bad bytes: %v", err)
	}
}

func TestJournalSharedOpenedStreamParser(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	plan := runPlanFixture(t)
	first := runOpenedEventFixture(t, plan)
	second := taskAvailableEventFixture(t, plan, "source", 2, first.Identity())
	if err := journal.SavePlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	for _, event := range []RunEvent{first, second} {
		expected := ""
		if event.Sequence() == 2 {
			expected = first.Identity()
		}
		if err := journal.Append(context.Background(), expected, event); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := os.ReadFile(journal.streamPath(plan.Scope()))
	if err != nil {
		t.Fatal(err)
	}
	check := func(label string, raw []byte, scope bool, want error) {
		t.Helper()
		reader := bytes.NewReader(raw)
		err := probeRunJournalStreamNewline(reader)
		if err == nil {
			var events []RunEvent
			useScope := plan.Scope()
			if !scope {
				useScope = inventoryPlan(t, "other", "repo", "run").Scope()
			}
			events, err = parseRunJournalStream(useScope, reader)
			if want == nil && (err != nil || len(events) != 2 || events[0].Identity() != first.Identity() || events[1].Identity() != second.Identity()) {
				t.Fatalf("%s events=%d err=%v", label, len(events), err)
			}
		}
		if want != nil && !errors.Is(err, want) {
			t.Fatalf("%s err=%v want=%v", label, err, want)
		}
	}
	check("valid", encoded, true, nil)
	check("no newline", encoded[:len(encoded)-1], true, ErrCorruptRunJournalStream)
	check("bad event", []byte("invalid\n"), true, ErrCorruptRunJournalStream)
	check("scope", encoded, false, ErrCorruptRunJournalStream)
	duplicate := append(bytes.Clone(encoded), encoded[:bytes.IndexByte(encoded, '\n')+1]...)
	check("sequence", duplicate, true, ErrCorruptRunJournalStream)
	// The same opened reader can be probed, parsed, and fully counted/hashed.
	reader := bytes.NewReader(encoded)
	if err := probeRunJournalStreamNewline(reader); err != nil {
		t.Fatal(err)
	}
	if offset, err := reader.Seek(0, io.SeekCurrent); err != nil || offset != 0 {
		t.Fatalf("probe offset=%d err=%v", offset, err)
	}
	hash := sha256.New()
	counted := io.TeeReader(reader, hash)
	if _, err := parseRunJournalStream(plan.Scope(), counted); err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(encoded)
	if !bytes.Equal(hash.Sum(nil), wantHash[:]) {
		t.Fatal("stream hash does not cover every byte")
	}
	if remaining := reader.Len(); remaining != 0 {
		t.Fatalf("unconsumed stream bytes=%d", remaining)
	}
}
