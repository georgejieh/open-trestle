//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

var errBootPacketExpirySanitizer = errors.New("injected boot packet expiry sanitizer refusal")

// The boot fixture needs marker-free v4, not the admitted live second-load branch.
type bootPacketExpirySanitizer struct {
	review.GenerationRequestSanitizer
	injected *bool
}

func (s bootPacketExpirySanitizer) PublicationContentScanner() review.PublicationContentScanner {
	return publicationContentScannerFromGenerationSanitizer(s.GenerationRequestSanitizer)
}

func (s bootPacketExpirySanitizer) SanitizeGeneration(ctx context.Context, request provider.Request, scope string) (review.SanitizedModelRequest, review.SanitizedEgressReceipt, error) {
	sanitized, receipt, err := s.GenerationRequestSanitizer.SanitizeGeneration(ctx, request, scope)
	if err != nil {
		return sanitized, receipt, err
	}
	*s.injected = true
	return sanitized, receipt, errBootPacketExpirySanitizer
}

type scopedLivePacketExpirySanitizer struct {
	review.GenerationRequestSanitizer
	target       string
	expire       func(context.Context) error
	observations chan error
}

func (s scopedLivePacketExpirySanitizer) PublicationContentScanner() review.PublicationContentScanner {
	return publicationContentScannerFromGenerationSanitizer(s.GenerationRequestSanitizer)
}

func (s scopedLivePacketExpirySanitizer) SanitizeGeneration(ctx context.Context, request provider.Request, scope string) (review.SanitizedModelRequest, review.SanitizedEgressReceipt, error) {
	sanitized, receipt, err := s.GenerationRequestSanitizer.SanitizeGeneration(ctx, request, scope)
	if err != nil || scope != s.target {
		return sanitized, receipt, err
	}
	observationErr := s.expire(ctx)
	select {
	case s.observations <- observationErr:
	default:
		return sanitized, receipt, errors.New("live expiry sanitizer repeated")
	}
	if observationErr != nil {
		return sanitized, receipt, observationErr
	}
	return sanitized, receipt, nil
}

func TestDaemonLocalModelWorkersLivePacketExpiryContinues(t *testing.T) {
	args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
	args = append(args, "--local-model-workers")
	clock := &daemonBudgetedHandlerClock{at: time.Now().UTC().Truncate(time.Millisecond)}
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-live-packet")
	if err != nil {
		t.Fatal(err)
	}
	statePath := daemonTestFlagValue(t, args, "--state-dir")
	observations := make(chan error, 1)
	var d *daemon
	var pinnedPacket controlplane.RunEvent
	var pinnedLease controlplane.RunEvent
	var pinnedRevision uint64
	var packetBytes []byte
	sanitizer := scopedLivePacketExpirySanitizer{GenerationRequestSanitizer: daemonTestGenerationSanitizer(), target: scope.Identity(), observations: observations, expire: func(ctx context.Context) error {
		journal := d.journal.(*controlplane.FileRunJournal)
		coordinator, err := controlplane.NewCoordinator(journal)
		if err != nil {
			return err
		}
		plan, state, err := coordinator.Resume(ctx, scope)
		if err != nil {
			return err
		}
		if ctx.Err() != nil || plan.PolicyIdentity() != policy.ReviewPolicyIdentity() || state.Status() != controlplane.ReviewRunActive {
			return errors.New("live callback plan/context mismatch")
		}
		packetHead, present, err := journal.Head(ctx, scope)
		if err != nil || !present || packetHead.Kind() != controlplane.RunEventContextPacketPrepared || state.HeadIdentity() != packetHead.Identity() {
			return fmt.Errorf("callback not exact v4: %w", err)
		}
		task, found := state.Task(packetHead.TaskKey())
		packet, prepared := task.PreparedContextPacket()
		if !found || !prepared || packet.Identity() != packetHead.Identity() || task.Status() != controlplane.TaskRuntimeLeased {
			return errors.New("callback not leased packet owner")
		}
		events, err := journal.Read(ctx, scope, 0, 100)
		if err != nil {
			return err
		}
		for _, event := range events {
			if event.Identity() == packet.Descriptor().LeaseEventIdentity {
				pinnedLease = event
			}
			if event.Kind() == controlplane.RunEventContextInputPrepared || event.Kind() == controlplane.RunEventContextInputSettled {
				return errors.New("callback already has input")
			}
		}
		if pinnedLease.Kind() != controlplane.RunEventTaskLeased || pinnedLease.TaskKey() != task.Key() || pinnedLease.Attempt() != task.Attempts() || pinnedLease.LeaseTokenIdentity() != task.LeaseTokenIdentity() || !pinnedLease.LeaseExpiresAt().Equal(task.LeaseExpiresAt()) {
			return errors.New("callback original lease mismatch")
		}
		value, err := d.artifactStore.Get(ctx, scope, packet.Descriptor().ArtifactIdentity, clock.Now())
		if err != nil || value.Validate() != nil || value.Kind() != artifact.KindContextPacket || value.Identity() != packet.Descriptor().ArtifactIdentity || !task.LeaseExpiresAt().Before(value.ExpiresAt()) || !clock.Now().Before(task.LeaseExpiresAt()) {
			return fmt.Errorf("callback packet not live: %w", err)
		}
		packetBytes, err = artifact.Encode(value)
		if err != nil {
			return err
		}
		marker := filepath.Join(statePath, scope.Identity()+".scope-intent.json")
		if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("callback marker: %w", err)
		}
		pinnedPacket, pinnedRevision = packetHead, state.Revision()
		clock.mu.Lock()
		clock.at = task.LeaseExpiresAt()
		clock.mu.Unlock()
		return nil
	}}
	d, err = buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{clock: clock, generationSanitizer: sanitizer, verificationSanitizer: daemonTestVerificationSanitizer()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	server := httptest.NewServer(d.server.Handler)
	t.Cleanup(func() { server.Close() })
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	worked, err := d.supervisors[1].(*worker.RepositorySupervisor).RunOnce(context.Background())
	if err != nil || !worked {
		t.Fatalf("live expiry supervisor: worked=%v err=%v", worked, err)
	}
	select {
	case err := <-observations:
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("live expiry callback not reached")
	}
	if !clock.Now().Equal(pinnedLease.LeaseExpiresAt()) {
		t.Fatal("not exact original lease expiry")
	}
	journal := d.journal.(*controlplane.FileRunJournal)
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := coordinator.Resume(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	task, found := state.Task(pinnedPacket.TaskKey())
	if !found || task.Status() != controlplane.TaskRuntimeFailed || task.Failure() != controlplane.RunFailurePolicy || task.OutputIdentity() != "" || !task.RetryAt().IsZero() || task.Attempts() != pinnedLease.Attempt() || state.Status() != controlplane.ReviewRunFailed || state.Failure() != controlplane.RunFailurePolicy || state.OutputIdentity() != "" {
		t.Fatal("live expiry did not reach failed/no-output task and run")
	}
	events, err := journal.Read(context.Background(), scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	failures, skips, runFailures := 0, 0, 0
	for _, event := range events {
		switch event.Kind() {
		case controlplane.RunEventContextInputPrepared, controlplane.RunEventContextInputSettled:
			t.Fatal("live expiry created input")
		case controlplane.RunEventTaskFailed:
			failures++
			if event.Sequence() != pinnedRevision+1 || event.PreviousIdentity() != pinnedPacket.Identity() || event.TaskKey() != pinnedPacket.TaskKey() || event.TaskIdentity() != pinnedPacket.TaskIdentity() || event.Attempt() != pinnedLease.Attempt() || event.LeaseTokenIdentity() != pinnedLease.LeaseTokenIdentity() || event.Failure() != controlplane.RunFailurePolicy || event.OutputIdentity() != "" || !event.RetryAt().IsZero() || !event.OccurredAt().Equal(pinnedLease.LeaseExpiresAt()) {
				t.Fatal("wrong live expiry failure event")
			}
		case controlplane.RunEventTaskSkipped:
			skips++
		case controlplane.RunEventFailed:
			runFailures++
		}
	}
	if failures != 1 || skips == 0 || runFailures != 1 {
		t.Fatalf("failure/skip/run events=%d/%d/%d", failures, skips, runFailures)
	}
	diagnostic, err := api.GetDiagnosticSet(context.Background(), scope)
	if err != nil || diagnostic.Outcome() != diagnostics.FinalOutcomeFailed || len(diagnostic.Findings()) != 0 {
		t.Fatalf("live diagnostic=%s err=%v", diagnostic.Outcome(), err)
	}
	value, err := d.artifactStore.Get(context.Background(), scope, pinnedPacket.PacketDescriptor().ArtifactIdentity, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	afterPacket, err := artifact.Encode(value)
	if err != nil || !bytes.Equal(packetBytes, afterPacket) {
		t.Fatal("live packet evidence changed")
	}
	marker := filepath.Join(statePath, scope.Identity()+".scope-intent.json")
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("live marker: %v", err)
	}
	auditRoot, err := os.OpenRoot(filepath.Join(statePath, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditRoot.Close()
	auditEvents, err := audit.ObserveFileStream(context.Background(), auditRoot, scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range auditEvents {
		if event.Kind() == audit.EventRouteSelected || event.Kind() == audit.EventRouteAttemptClaimed {
			t.Fatal("live expiry gained route evidence")
		}
	}
	for _, endpoint := range []*daemonBudgetedModelEndpoint{fake.generation, fake.verification} {
		if calls, _, _, failures := endpoint.snapshot(); calls != 0 || len(failures) != 0 {
			t.Fatalf("live expiry dispatched: calls=%d failures=%v", calls, failures)
		}
	}
	laterScope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-live-packet-later")
	if err != nil {
		t.Fatal(err)
	}
	laterIntent, err := runtimecatalog.NewLocalFullReviewIntent(laterScope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), laterIntent); err != nil {
		t.Fatal(err)
	}
	// The scope-specific sanitizer is clean for this later run, with no state toggle.
	for _, index := range []int{1, 2, 1} {
		if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	later, err := api.GetDiagnosticSet(context.Background(), laterScope)
	if err != nil || later.Outcome() != diagnostics.FinalOutcomeCompleted {
		t.Fatalf("later diagnostic=%s err=%v", later.Outcome(), err)
	}
	for _, endpoint := range []*daemonBudgetedModelEndpoint{fake.generation, fake.verification} {
		if calls, _, _, failures := endpoint.snapshot(); calls != 1 || len(failures) != 0 {
			t.Fatalf("later calls=%d failures=%v", calls, failures)
		}
	}
}
