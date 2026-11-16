package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

type terminalReadClock struct{ at time.Time }

func (c terminalReadClock) Now() time.Time { return c.at }

type terminalReadFixture struct {
	journal              *controlplane.FileRunJournal
	control              *LocalControl
	scope                audit.ReviewScope
	expected             controlplane.ReviewRunReceipt
	root, stream, marker string
}

func newTerminalReadFixture(t *testing.T, terminal bool) terminalReadFixture {
	t.Helper()
	ctx := context.Background()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "worker-terminal-read")
	if err != nil {
		t.Fatal(err)
	}
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 100, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	memory := controlplane.NewMemoryRunJournal()
	coordinator, err := controlplane.NewCoordinator(memory)
	if err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.Open(ctx, plan, time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	if terminal {
		lease, acquired, err := coordinator.ClaimTask(ctx, plan, task.Key(), task.HandlerIdentity(), "worker", time.UnixMilli(101))
		if err != nil || !acquired {
			t.Fatalf("claim acquired=%t err=%v", acquired, err)
		}
		completion, err := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, time.UnixMilli(102)); err != nil {
			t.Fatal(err)
		}
		state, err = coordinator.SucceedRun(ctx, plan, completion.OutputIdentity(), time.UnixMilli(103))
		if err != nil {
			t.Fatal(err)
		}
	}
	expected, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := controlplane.NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := journal.SavePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	events, err := memory.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if err := journal.Append(ctx, event.PreviousIdentity(), event); err != nil {
			t.Fatal(err)
		}
	}
	control, err := NewLocalControl(journal, terminalReadClock{time.UnixMilli(104)}, "worker-read")
	if err != nil {
		t.Fatal(err)
	}
	return terminalReadFixture{journal: journal, control: control, scope: scope, expected: expected, root: root, stream: filepath.Join(root, scope.Identity()+".run.jsonl"), marker: filepath.Join(root, scope.Identity()+".scope-intent.json")}
}

func terminalReadBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertTerminalReadUnchanged(t *testing.T, f terminalReadFixture, before []byte, receipt controlplane.ReviewRunReceipt, err error) {
	t.Helper()
	if err != nil || receipt.Identity() != f.expected.Identity() {
		t.Fatalf("terminal receipt changed: %v", err)
	}
	if !bytes.Equal(before, terminalReadBytes(t, f.stream)) {
		t.Fatal("terminal stream changed")
	}
	if _, err := os.Lstat(f.marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("terminal read created marker: %v", err)
	}
}

func TestLocalControlTerminalGetRunReadOnlyDirectory(t *testing.T) {
	f := newTerminalReadFixture(t, true)
	before := terminalReadBytes(t, f.stream)
	if err := os.Chmod(f.root, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(f.root, 0700); err != nil {
			t.Error(err)
		}
	})
	receipt, err := f.control.GetRun(context.Background(), f.scope)
	assertTerminalReadUnchanged(t, f, before, receipt, err)
}

type terminalReadMarkerContext struct {
	context.Context
	cancel   context.CancelFunc
	marker   string
	observed atomic.Bool
}

func (c *terminalReadMarkerContext) Err() error {
	if _, err := os.Lstat(c.marker); err == nil {
		c.observed.Store(true)
		c.cancel()
	}
	return c.Context.Err()
}

func TestLocalControlTerminalGetRunNeverStartsCancelableIntent(t *testing.T) {
	f := newTerminalReadFixture(t, true)
	before := terminalReadBytes(t, f.stream)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &terminalReadMarkerContext{Context: parent, cancel: cancel, marker: f.marker}
	receipt, err := f.control.GetRun(ctx, f.scope)
	assertTerminalReadUnchanged(t, f, before, receipt, err)
	if ctx.observed.Load() || parent.Err() != nil {
		t.Fatal("terminal read crossed intent boundary")
	}
}

func TestLocalControlTerminalGetRunPreservesUnresolvedMarker(t *testing.T) {
	f := newTerminalReadFixture(t, true)
	before := terminalReadBytes(t, f.stream)
	marker := []byte("unknown existing effect\n")
	if err := os.WriteFile(f.marker, marker, 0600); err != nil {
		t.Fatal(err)
	}
	_, err := f.control.GetRun(context.Background(), f.scope)
	if !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("unresolved scope bypassed: %v", err)
	}
	if !bytes.Equal(marker, terminalReadBytes(t, f.marker)) || !bytes.Equal(before, terminalReadBytes(t, f.stream)) {
		t.Fatal("unresolved evidence changed")
	}
}

func TestLocalControlActiveGetRunRetainsCanceledIntent(t *testing.T) {
	f := newTerminalReadFixture(t, false)
	before := terminalReadBytes(t, f.stream)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &terminalReadMarkerContext{Context: parent, cancel: cancel, marker: f.marker}
	_, err := f.control.GetRun(ctx, f.scope)
	if !ctx.observed.Load() || !errors.Is(err, controlplane.ErrScopeIntentUnresolved) || !errors.Is(err, controlplane.ErrRunJournalContextDone) {
		t.Fatalf("active uncertainty hidden: %v", err)
	}
	marker := terminalReadBytes(t, f.marker)
	if len(marker) == 0 || !bytes.Equal(before, terminalReadBytes(t, f.stream)) {
		t.Fatal("active canceled evidence changed")
	}
	_, err = f.control.GetRun(context.Background(), f.scope)
	if !errors.Is(err, controlplane.ErrScopeIntentUnresolved) || !bytes.Equal(marker, terminalReadBytes(t, f.marker)) {
		t.Fatalf("active marker not retained: %v", err)
	}
}
