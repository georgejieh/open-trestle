package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

// Seed actual prepared-nine bytes into an enrolled synthetic owner's state.
// The parser fixture executes only existing synthetic source/deterministic tasks.
func expiryStartupFixture(t *testing.T) recordedNamesFixture {
	t.Helper()
	return expiryStartupFixtureAfter(t, nil)
}

// expiryStartupFixtureAfter lets settle extend the recorded journal before it
// is seeded into the owner's state.
func expiryStartupFixtureAfter(t *testing.T, settle func(*recordedNamesFixture)) recordedNamesFixture {
	t.Helper()
	f := newRecordedNamesFixture(t, nil, "", false)
	if settle != nil {
		settle(&f)
	}
	allowed, err := recordedHistoricalV4Names(f.fact, f.a, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	keep := map[string]bool{}
	for _, id := range allowed {
		keep[id] = true
	}
	if err := f.journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.ownerFixture.resources.Close(); err != nil {
		t.Fatal(err)
	}
	state := f.ownerFixture.statePath
	entries, err := os.ReadDir(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".run-plan.json") || strings.HasSuffix(e.Name(), ".run.jsonl") {
			if err := os.Remove(filepath.Join(state, e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	entries, err = os.ReadDir(f.journalPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".run-plan.json") || strings.HasSuffix(e.Name(), ".run.jsonl") {
			data, err := os.ReadFile(filepath.Join(f.journalPath, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(state, e.Name()), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	artpath := filepath.Join(state, "artifacts")
	entries, err = os.ReadDir(artpath)
	if err != nil {
		t.Fatal(err)
	}
	prefix := f.fact.Plan().Scope().Identity() + "-"
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), ".artifact.json") {
			id := strings.TrimSuffix(strings.TrimPrefix(e.Name(), prefix), ".artifact.json")
			if !keep[id] {
				if err := os.Remove(filepath.Join(artpath, e.Name())); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return f
}

func restartExpiryStartup(t *testing.T, f recordedNamesFixture, at time.Time) (*daemon, *localPacketOwner, error) {
	t.Helper()
	old := f.ownerFixture
	r := &daemon{}
	_, _, owner, err := startLocalSourceOwnerGate(context.Background(), r, old.statePath, old.setupPath, &old.setupPlan, "tenant-a", "repo-a", old.repository, old.gitRoot, old.objectStore, old.adapter, old.rootDigest, localPacketFixtureClock{at})
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r, owner, err
}

func TestCompleteV4ExpiryStartupPreActivateAcceptsCompleteExpiredRecipe(t *testing.T) {
	t.Parallel()
	f := expiryStartupFixture(t)
	_, owner, err := restartExpiryStartup(t, f, f.fact.LeaseEvent().LeaseExpiresAt())
	if err != nil || owner == nil {
		t.Fatalf("marker-free complete expired v4 refused before Activate: %v", err)
	}
}
func TestCompleteV4ExpiryStartupTerminatesAndReproves(t *testing.T) {
	t.Parallel()
	f := expiryStartupFixture(t)
	at := f.fact.LeaseEvent().LeaseExpiresAt()
	r, owner, err := restartExpiryStartup(t, f, at)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := audit.NewFileLedger(filepath.Join(f.ownerFixture.statePath, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err := verifyOwnerExpiredPacketStartup(context.Background(), owner, ledger, f.ownerFixture.gitRoot, f.catalog, f.fact.Plan().PolicyIdentity()); err != nil {
		t.Fatal(err)
	}
	_, state, err := controlplaneCoordinator(t, owner).Resume(context.Background(), f.fact.Plan().Scope())
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision() != f.fact.FinalRevision()+1 {
		t.Fatal("not exactly one expiry failure")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	_, again, err := restartExpiryStartup(t, f, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyOwnerExpiredPacketStartup(context.Background(), again, ledger, f.ownerFixture.gitRoot, f.catalog, f.fact.Plan().PolicyIdentity()); err != nil {
		t.Fatal(err)
	}
	_, next, err := controlplaneCoordinator(t, again).Resume(context.Background(), f.fact.Plan().Scope())
	if err != nil || next.HeadIdentity() != state.HeadIdentity() {
		t.Fatalf("repeat boot changed journal: %v", err)
	}
}

func controlplaneCoordinator(t *testing.T, o *localPacketOwner) *controlplane.Coordinator {
	t.Helper()
	c, err := controlplane.NewCoordinator(o.journal)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCompleteV4ExpiryStartupTimeAndPhysicalRefusals(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"live", "retention-equality", "orphan", "missing", "corrupt", "marker", "wrong-tail"} {
		t.Run(mode, func(t *testing.T) {
			f := expiryStartupFixture(t)
			at := f.fact.LeaseEvent().LeaseExpiresAt()
			state := f.ownerFixture.statePath
			packet := filepath.Join(state, "artifacts", f.fact.Plan().Scope().Identity()+"-"+f.a.Packet.Identity()+".artifact.json")
			var preserved string
			switch mode {
			case "live":
				at = at.Add(-time.Millisecond)
			case "retention-equality":
				at = f.a.Packet.ExpiresAt()
			case "missing":
				if err := os.Remove(packet); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(packet, []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "orphan":
				preserved = filepath.Join(state, "artifacts", f.fact.Plan().Scope().Identity()+"-"+strings.Repeat("a", 64)+".artifact.json")
				if err := os.WriteFile(preserved, []byte("orphan"), 0600); err != nil {
					t.Fatal(err)
				}
			case "marker":
				preserved = filepath.Join(state, f.fact.Plan().Scope().Identity()+".scope-intent.json")
				if err := os.WriteFile(preserved, []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-tail":
				j, err := controlplane.NewFileRunJournal(state)
				if err != nil {
					t.Fatal(err)
				}
				c, err := controlplane.NewCoordinator(j)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := c.CancelRun(context.Background(), f.fact.Plan(), at); err != nil {
					t.Fatal(err)
				}
				if err := j.Close(); err != nil {
					t.Fatal(err)
				}
			}
			before := ownerStartupJournalBytes(t, state)
			r, _, err := restartExpiryStartup(t, f, at)
			if err == nil {
				r.Close()
				t.Fatal("unsafe startup accepted")
			}
			after := ownerStartupJournalBytes(t, state)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("refusal changed journal")
			}
			if preserved != "" {
				if _, err := os.Stat(preserved); err != nil {
					t.Fatal("refusal removed marker/receipt/extra")
				}
			}
		})
	}
}

func TestCompleteV4ExpiryStartupEnrollmentAndAuditRefusals(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"policy", "source", "catalog-0", "catalog-1", "catalog-2", "catalog-3", "catalog-4", "catalog-5", "catalog-6", "catalog-7", "route", "closed-ledger", "head-drift"} {
		t.Run(mode, func(t *testing.T) {
			f := expiryStartupFixture(t)
			_, owner, err := restartExpiryStartup(t, f, f.fact.LeaseEvent().LeaseExpiresAt())
			if err != nil {
				t.Fatal(err)
			}
			ledger, err := audit.NewFileLedger(filepath.Join(f.ownerFixture.statePath, "audit"))
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.Close()
			catalog, policy := f.catalog, f.fact.Plan().PolicyIdentity()
			if mode == "policy" {
				policy = strings.Repeat("a", 64)
			}
			if mode == "source" {
				owner.sourceBinding.RepositoryIdentity = strings.Repeat("a", 64)
			}
			if strings.HasPrefix(mode, "catalog-") {
				index := int(mode[len(mode)-1] - '0')
				handlers := []controlplane.TaskHandler{}
				for i, b := range catalog.Bindings() {
					if i == index {
						b.HandlerIdentity = strings.Repeat("a", 64)
					}
					handlers = append(handlers, recordedNamesBinding{b.Kind, b.HandlerIdentity})
				}
				catalog, err = runtimecatalog.NewPipelineCatalog(controlplane.ReviewRunLocal, handlers)
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "route" {
				e, err := audit.NewEvent(f.fact.Plan().Scope(), 1, "", audit.EventRouteSelected, strings.Repeat("a", 64), nil, f.fact.LeaseEvent().LeaseExpiresAt())
				if err != nil {
					t.Fatal(err)
				}
				if err := ledger.Append(context.Background(), "", e); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "closed-ledger" {
				if err := ledger.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "head-drift" {
				if _, err := controlplaneCoordinator(t, owner).CancelRun(context.Background(), f.fact.Plan(), f.fact.LeaseEvent().LeaseExpiresAt()); err != nil {
					t.Fatal(err)
				}
			}
			before := ownerStartupJournalBytes(t, f.ownerFixture.statePath)
			if err := verifyOwnerExpiredPacketStartup(context.Background(), owner, ledger, f.ownerFixture.gitRoot, catalog, policy); err == nil {
				t.Fatal("invalid proof accepted")
			}
			if !reflect.DeepEqual(before, ownerStartupJournalBytes(t, f.ownerFixture.statePath)) {
				t.Fatal("invalid proof appended")
			}
		})
	}
}

func TestCompleteV4ExpiryStartupClosedInterruptedPrefixes(t *testing.T) {
	t.Parallel()
	for count := 0; count <= 4; count++ {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := expiryStartupFixture(t)
			at := f.fact.LeaseEvent().LeaseExpiresAt()
			r, owner, err := restartExpiryStartup(t, f, at)
			if err != nil {
				t.Fatal(err)
			}
			ledger, err := audit.NewFileLedger(filepath.Join(f.ownerFixture.statePath, "audit"))
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.Close()
			if err := verifyOwnerExpiredPacketStartup(context.Background(), owner, ledger, f.ownerFixture.gitRoot, f.catalog, f.fact.Plan().PolicyIdentity()); err != nil {
				t.Fatal(err)
			}
			c := controlplaneCoordinator(t, owner)
			for i, key := range []string{"candidates", "verification", "readiness"} {
				if i >= count {
					break
				}
				_, state, err := c.Resume(context.Background(), f.fact.Plan().Scope())
				if err != nil {
					t.Fatal(err)
				}
				task, _ := f.fact.Plan().Task(key)
				event, err := controlplane.NewRunEvent(f.fact.Plan(), state.Revision()+1, state.HeadIdentity(), controlplane.RunEventTaskSkipped, task, 0, "", "", time.Time{}, "", controlplane.RunFailureDependency, time.Time{}, at)
				if err != nil {
					t.Fatal(err)
				}
				if err := owner.journal.Append(context.Background(), state.HeadIdentity(), event); err != nil {
					t.Fatal(err)
				}
			}
			if count == 4 {
				if _, err := c.FailRun(context.Background(), f.fact.Plan(), controlplane.RunFailurePolicy, at); err != nil {
					t.Fatal(err)
				}
			}
			_, before, err := c.Resume(context.Background(), f.fact.Plan().Scope())
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			_, again, err := restartExpiryStartup(t, f, at)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyOwnerExpiredPacketStartup(context.Background(), again, ledger, f.ownerFixture.gitRoot, f.catalog, f.fact.Plan().PolicyIdentity()); err != nil {
				t.Fatal(err)
			}
			_, after, err := controlplaneCoordinator(t, again).Resume(context.Background(), f.fact.Plan().Scope())
			if err != nil || before.HeadIdentity() != after.HeadIdentity() {
				t.Fatal("closed prefix reproof appended")
			}
		})
	}
}

func TestCompleteV4ExpiryStartupPhysicalCloseFailureDoesNotAppend(t *testing.T) {
	t.Parallel()
	f := expiryStartupFixture(t)
	old := f.ownerFixture
	r := &daemon{}
	defer r.Close()
	before := ownerStartupJournalBytes(t, old.statePath)
	probe := &historicalGateFaultProbe{closePhysicalFile: func(file *os.File) error { return errors.Join(file.Close(), errors.New("injected close failure")) }}
	_, _, _, err := startLocalSourceOwnerGateWithProbe(context.Background(), r, old.statePath, old.setupPath, &old.setupPlan, "tenant-a", "repo-a", old.repository, old.gitRoot, old.objectStore, old.adapter, old.rootDigest, localPacketFixtureClock{f.fact.LeaseEvent().LeaseExpiresAt()}, probe)
	if err == nil {
		t.Fatal("close failure accepted")
	}
	if !reflect.DeepEqual(before, ownerStartupJournalBytes(t, old.statePath)) {
		t.Fatal("close failure appended")
	}
}

func TestCompleteV4ExpiryStartupNonFullBootCannotBypass(t *testing.T) {
	t.Parallel()
	f := expiryStartupFixture(t)
	old := f.ownerFixture
	before := ownerStartupJournalBytes(t, old.statePath)
	args := []string{"--listen", "127.0.0.1:0", "--state-dir", old.statePath, "--tenant", "tenant-a", "--repository", "repo-a", "--setup-state", old.setupPath, "--expected-setup-root-identity", old.setupPlan.RootIdentity(), "--local-git-objects-root", old.gitRoot.Name(), "--local-git-repository-authority", "local.test", "--local-git-repository-namespace", "team", "--local-git-repository-name", "repository"}
	daemon, err := buildDaemon(context.Background(), args, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"}), &bytes.Buffer{})
	if daemon != nil {
		daemon.Close()
		t.Fatal("nonfull boot accepted")
	}
	if err == nil {
		t.Fatal("nonfull boot no refusal")
	}
	if !reflect.DeepEqual(before, ownerStartupJournalBytes(t, old.statePath)) {
		t.Fatal("nonfull boot appended")
	}
}

func TestCompleteV4ExpiryStartupMixedLinkedV5RefusesBeforeActivation(t *testing.T) {
	t.Parallel()
	f := expiryStartupFixture(t)
	old := f.ownerFixture
	ctx := context.Background()
	j, err := controlplane.NewFileRunJournal(old.statePath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.NewFileStore(filepath.Join(old.statePath, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-linked")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, f.fact.Plan().RequestIdentity(), f.fact.Plan().PolicyIdentity(), controlplane.ReviewRunLocal, f.fact.Plan().Tasks())
	if err != nil {
		t.Fatal(err)
	}
	c, err := controlplane.NewCoordinator(j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Open(ctx, plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	at := time.UnixMilli(200)
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory"} {
		task, _ := plan.Task(key)
		lease, ok, err := c.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", at)
		if err != nil || !ok {
			t.Fatal(err)
		}
		success, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
		if _, err := c.CompleteTask(ctx, plan, lease, success, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		at = at.Add(20 * time.Millisecond)
	}
	task, _ := plan.Task("context")
	lease, ok, err := c.ClaimTask(ctx, plan, "context", task.HandlerIdentity(), "worker", at)
	if err != nil || !ok {
		t.Fatal(err)
	}
	value, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationConfidential, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{strings.Repeat("e", 64)}, []byte(`{"packet":"linked metadata"}`), at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(ctx, value, at); err != nil {
		t.Fatal(err)
	}
	descriptor := controlplane.ContextPacketDescriptor{ArtifactIdentity: value.Identity(), PayloadDigest: value.PayloadDigest(), LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(), Classification: value.Classification().String(), Protection: value.Protection().String(), Provenance: value.Provenance(), SourceRootIdentity: old.rootDigest, SnapshotIdentity: strings.Repeat("e", 64), DependencyIdentities: []string{strings.Repeat("e", 64)}, CreatedAtMilliseconds: at.UnixMilli(), ExpiresAtMilliseconds: value.ExpiresAt().UnixMilli()}
	packet, err := c.PrepareContextPacket(ctx, plan, lease, descriptor, at)
	if err != nil {
		t.Fatal(err)
	}
	makeValue := func(kind artifact.Kind, parents []string) artifact.Artifact {
		v, err := artifact.New(scope, kind, "application/json", value.Classification(), artifact.OriginHost, value.Protection(), parents, []byte(`{"metadata":true}`), at.Add(time.Millisecond), value.ExpiresAt())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Put(ctx, v, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		return v
	}
	request := makeValue(artifact.KindSanitizedModelRequest, []string{value.Identity()})
	receipt := makeValue(artifact.KindSanitizedEgressReceipt, []string{value.Identity(), request.Identity()})
	authorization := strings.Repeat("8", 64)
	input := makeValue(artifact.KindTaskInput, []string{value.Identity(), request.Identity(), receipt.Identity(), authorization})
	desc := func(v artifact.Artifact) controlplane.ContextInputArtifactDescriptor {
		return controlplane.ContextInputArtifactDescriptor{ArtifactIdentity: v.Identity(), PayloadDigest: v.PayloadDigest(), Classification: v.Classification().String(), Protection: v.Protection().String(), Provenance: v.Provenance(), CreatedAtMilliseconds: v.CreatedAt().UnixMilli(), ExpiresAtMilliseconds: v.ExpiresAt().UnixMilli()}
	}
	d := controlplane.ContextInputDescriptor{PacketPreparedEventIdentity: packet.Identity(), PacketArtifactIdentity: value.Identity(), LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(), Request: desc(request), Receipt: desc(receipt), Input: desc(input), ReceiptIdentity: strings.Repeat("4", 64), ScannerHelperDigest: strings.Repeat("5", 64), GenerationInputIdentity: strings.Repeat("7", 64), AuthorizationIdentity: authorization, SelectionReceiptIdentity: strings.Repeat("9", 64), RoutingInputIdentity: strings.Repeat("a", 64), SelectedRecordIdentity: strings.Repeat("b", 64), PolicyIdentity: strings.Repeat("d", 64), RoutePairIdentity: strings.Repeat("e", 64), AuthorizerIdentity: strings.Repeat("f", 64), SanitizerIdentity: strings.Repeat("1", 64), RegistryRevision: 11, PerformanceRevision: 5}
	if _, err := c.PrepareContextInput(ctx, plan, lease, packet, d, at.Add(2*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(old.statePath, scope.Identity()+".run.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := restartExpiryStartup(t, f, f.fact.LeaseEvent().LeaseExpiresAt())
	if err == nil {
		r.Close()
		t.Fatal("mixed startup accepted")
	}
	after, e := os.ReadFile(filepath.Join(old.statePath, scope.Identity()+".run.jsonl"))
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("mixed startup changed linked history")
	}
	if _, err := os.Stat(filepath.Join(old.statePath, "audit")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("mixed startup reached legacy audit recovery")
	}
}

type expiryStartupStepClock struct {
	first, later time.Time
	calls        int
}

func (c *expiryStartupStepClock) Now() time.Time {
	c.calls++
	if c.calls == 1 {
		return c.first
	}
	return c.later
}

func TestCompleteV4ExpiryStartupClockDriftBeforeGateDoesNotAppend(t *testing.T) {
	t.Parallel()
	f := expiryStartupFixture(t)
	_, owner, err := restartExpiryStartup(t, f, f.fact.LeaseEvent().LeaseExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := audit.NewFileLedger(filepath.Join(f.ownerFixture.statePath, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	clock := &expiryStartupStepClock{first: f.fact.LeaseEvent().LeaseExpiresAt(), later: f.a.Packet.ExpiresAt()}
	owner.clock = clock
	before := ownerStartupJournalBytes(t, f.ownerFixture.statePath)
	if err := verifyOwnerExpiredPacketStartup(context.Background(), owner, ledger, f.ownerFixture.gitRoot, f.catalog, f.fact.Plan().PolicyIdentity()); err == nil {
		t.Fatal("time drift accepted")
	}
	if clock.calls != 2 || !reflect.DeepEqual(before, ownerStartupJournalBytes(t, f.ownerFixture.statePath)) {
		t.Fatal("gate did not reject retention drift without append")
	}
}
