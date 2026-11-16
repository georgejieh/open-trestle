package context

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
)

// Intentionally does not expose the concrete journal's effect section.
type ungatedPacketJournal struct{ controlplane.RunJournal }

type adversarialPacketJournal struct {
	controlplane.RunJournal
	run func(context.Context, func() error) error
}

func (j adversarialPacketJournal) WithEffectSection(ctx context.Context, effect func() error) error {
	return j.run(ctx, effect)
}

type packetForwardThenError struct{ artifact.Store }

func (s packetForwardThenError) Put(ctx context.Context, value artifact.Artifact, at time.Time) (bool, error) {
	created, err := s.Store.Put(ctx, value, at)
	if err != nil {
		return created, err
	}
	if value.Kind() == artifact.KindContextPacket {
		return false, errors.New("reported failure after real packet Put")
	}
	return created, nil
}

func TestPacketAuthorityUnsupportedJournalRefusesBeforeV4(t *testing.T) {
	authority, request, coordinator, store, _, closeFixture, wrapper := newPacketWriterFixture(t, false, false, false, false, false)
	defer closeFixture()
	ungated, err := controlplane.NewCoordinator(ungatedPacketJournal{RunJournal: wrapper})
	if err != nil {
		t.Fatal(err)
	}
	authority.coordinator = ungated
	puts := 0
	authority.store = blockedPacketStore{Store: store, putCount: &puts}
	prepared, err := authority.Prepare(context.Background(), request)
	if !errors.Is(err, ErrPacketAuthority) || prepared.Identity() != "" || puts != 0 {
		t.Fatalf("unsupported journal prepared=%s puts=%d err=%v", prepared.Identity(), puts, err)
	}
	_, state, err := coordinator.Resume(context.Background(), request.Plan().Scope())
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := state.Task("context")
	if _, ok := runtime.PreparedContextPacket(); ok {
		t.Fatal("unsupported journal wrote v4")
	}
}

func TestPacketAuthorityForwardedPutErrorIsNotAbsence(t *testing.T) {
	authority, request, coordinator, store, root, closeFixture, _ := newPacketWriterFixture(t, false, false, false, false, false)
	defer closeFixture()
	authority.store = packetForwardThenError{Store: store}
	prepared, err := authority.Prepare(context.Background(), request)
	if !errors.Is(err, ErrPacketAuthority) || prepared.Identity() == "" {
		t.Fatalf("reported-error intent=%s err=%v", prepared.Identity(), err)
	}
	_, state, err := coordinator.Resume(context.Background(), request.Plan().Scope())
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := state.Task("context")
	checkpoint, ok := runtime.PreparedContextPacket()
	if !ok || checkpoint.Identity() != prepared.Identity() {
		t.Fatal("reported-error lost v4 intent")
	}
	closeFixture()
	reopened, err := artifact.NewFileStore(filepath.Join(root, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	value, err := reopened.Get(context.Background(), request.Plan().Scope(), checkpoint.Descriptor().ArtifactIdentity, time.UnixMilli(230))
	if err != nil || value.Identity() != checkpoint.Descriptor().ArtifactIdentity {
		t.Fatalf("reported Put error is not absence: %v", err)
	}
	reopenedJournal, err := controlplane.NewFileRunJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedJournal.Close()
	resumed, _ := controlplane.NewCoordinator(reopenedJournal)
	_, state, err = resumed.Resume(context.Background(), request.Plan().Scope())
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ = state.Task("context")
	if durable, ok := runtime.PreparedContextPacket(); !ok || durable.Identity() != checkpoint.Identity() {
		t.Fatal("reported-error lost reopened intent")
	}
}

func TestPacketEffectSectionRejectsAdversarialCallbacks(t *testing.T) {
	swallowed := errors.New("effect failed after entry")
	for _, tc := range []struct {
		name      string
		invoke    func(context.Context, func() error) error
		wantCalls int
		wantError error
	}{
		{"omitted", func(context.Context, func() error) error { return nil }, 0, controlplane.ErrInvalidCoordinatorJournal},
		{"twice", func(_ context.Context, effect func() error) error { _ = effect(); _ = effect(); return nil }, 1, controlplane.ErrInvalidCoordinatorJournal},
		{"swallowed_error", func(_ context.Context, effect func() error) error { _ = effect(); return nil }, 1, swallowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			journal := adversarialPacketJournal{run: tc.invoke}
			coordinator, err := controlplane.NewCoordinator(journal)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			got := coordinator.WithPacketEffectSection(context.Background(), func() error {
				calls++
				if tc.name == "swallowed_error" {
					return swallowed
				}
				return nil
			})
			if calls != tc.wantCalls || !errors.Is(got, tc.wantError) {
				t.Fatalf("effect calls=%d err=%v; want %d and %v", calls, got, tc.wantCalls, tc.wantError)
			}
		})
	}
}

func TestPacketEffectSectionRejectsLateAndInFlightCallbacks(t *testing.T) {
	var late func() error
	journal := adversarialPacketJournal{run: func(_ context.Context, effect func() error) error {
		late = effect
		return effect()
	}}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := coordinator.WithPacketEffectSection(context.Background(), func() error { calls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := late(); !errors.Is(err, controlplane.ErrInvalidCoordinatorJournal) || calls != 1 {
		t.Fatalf("late callback: calls=%d err=%v", calls, err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	completed := make(chan error, 1)
	journal.run = func(_ context.Context, effect func() error) error {
		go func() { completed <- effect() }()
		<-entered
		return nil // Misbehaving wrapper returns while its callback remains in-flight.
	}
	coordinator, err = controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	err = coordinator.WithPacketEffectSection(context.Background(), func() error {
		close(entered)
		<-release
		return nil
	})
	close(release)
	if !errors.Is(err, controlplane.ErrInvalidCoordinatorJournal) {
		t.Fatalf("in-flight callback falsely succeeded: %v", err)
	}
	select {
	case callbackErr := <-completed:
		if callbackErr != nil {
			t.Fatal(callbackErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight callback did not finish after release")
	}
}

func TestPacketAuthorityCallbackOmissionRefusesBeforeV4(t *testing.T) {
	authority, request, coordinator, store, _, closeFixture, wrapper := newPacketWriterFixture(t, false, false, false, false, false)
	defer closeFixture()
	omitted, err := controlplane.NewCoordinator(adversarialPacketJournal{
		RunJournal: wrapper,
		run:        func(context.Context, func() error) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	authority.coordinator = omitted
	puts := 0
	authority.store = blockedPacketStore{Store: store, putCount: &puts}
	prepared, err := authority.Prepare(context.Background(), request)
	if !errors.Is(err, ErrPacketAuthority) || prepared.Identity() != "" || puts != 0 {
		t.Fatalf("omitted callback prepared=%s puts=%d err=%v", prepared.Identity(), puts, err)
	}
	_, state, err := coordinator.Resume(context.Background(), request.Plan().Scope())
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := state.Task("context")
	if _, ok := runtime.PreparedContextPacket(); ok {
		t.Fatal("omitted callback wrote v4")
	}
}
