package runtimecatalog

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

func deterministicAdmissionFixture(t *testing.T, runID string) (LocalDeterministicReviewIntent, LocalDeterministicReviewAdmissionConfig, controlplane.RunJournal, artifact.Store) {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", runID)
	repository, _ := evidence.NewRepositoryIdentity("local.test", []string{"team"}, "repository")
	base, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	head, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	adapter, _ := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "local-git-loose", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	handlers := []controlplane.TaskHandler{
		handler{controlplane.TaskAcquireSource, strings.Repeat("1", 64)},
		handler{controlplane.TaskBuildChange, strings.Repeat("2", 64)},
		handler{controlplane.TaskInspectDeterministic, strings.Repeat("3", 64)},
	}
	catalog, _ := NewPipelineCatalog(controlplane.ReviewRunLocal, handlers)
	created := time.UnixMilli(1_000).UTC()
	intent, err := NewLocalDeterministicReviewIntent(scope, repository, base, head, created)
	if err != nil {
		t.Fatal(err)
	}
	config := LocalDeterministicReviewAdmissionConfig{Repository: repository, SourceAdapter: adapter, SourceRootIdentity: strings.Repeat("4", 64), ReviewPolicyIdentity: strings.Repeat("5", 64), Classification: artifact.ClassificationInternal, Protection: artifact.ProtectionProcessPrivate, Retention: time.Hour, Catalog: catalog}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 128)
	return intent, config, controlplane.NewMemoryRunJournal(), store
}

func TestLocalDeterministicReviewIntentIsCanonicalAndCarriesNoPathOrRouteAuthority(t *testing.T) {
	intent, _, _, _ := deterministicAdmissionFixture(t, "run-a")
	encoded, err := EncodeLocalDeterministicReviewIntent(intent)
	parsed, parseErr := ParseLocalDeterministicReviewIntent(encoded)
	if err != nil || parseErr != nil || parsed.Identity() != intent.Identity() || parsed.Scope().Identity() != intent.Scope().Identity() || !bytes.Equal(encoded, mustEncodeLocalIntent(t, parsed)) {
		t.Fatalf("round trip=(%#v,%v,%v)", parsed, err, parseErr)
	}
	for _, forbidden := range [][]byte{[]byte("objects_root"), []byte("route"), []byte("credential"), []byte("publication")} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("intent leaked forbidden authority %q: %s", forbidden, encoded)
		}
	}
	mutated := bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":1,"objects_root":"/tmp/repo"`), 1)
	if parsed, err := ParseLocalDeterministicReviewIntent(mutated); err == nil || parsed.Identity() != "" {
		t.Fatalf("path-bearing intent admitted: %#v err=%v", parsed, err)
	}
}
func mustEncodeLocalIntent(t *testing.T, intent LocalDeterministicReviewIntent) []byte {
	t.Helper()
	encoded, err := EncodeLocalDeterministicReviewIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestLocalDeterministicReviewAdmissionPersistsInputsBeforeOpeningIdempotentRun(t *testing.T) {
	intent, config, journal, store := deterministicAdmissionFixture(t, "run-a")
	admitter, err := NewLocalDeterministicReviewAdmitter(journal, store, config)
	if err != nil {
		t.Fatal(err)
	}
	state, err := admitter.Admit(context.Background(), intent, time.UnixMilli(1_001))
	if err != nil || state.Status() != controlplane.ReviewRunActive {
		t.Fatalf("Admit()=(%#v,%v)", state, err)
	}
	plan, found, err := journal.LoadPlan(context.Background(), intent.Scope())
	if err != nil || !found || plan.TaskCount() != 4 || plan.RequestIdentity() == "" {
		t.Fatalf("plan=(found=%t err=%v tasks=%d request=%s want=%s)", found, err, plan.TaskCount(), plan.RequestIdentity(), intent.Identity())
	}
	for _, key := range []string{"source-base", "source-head"} {
		task, _ := plan.Task(key)
		inputArtifact, getErr := store.Get(context.Background(), intent.Scope(), task.InputIdentity(), time.UnixMilli(1_001))
		if getErr != nil || inputArtifact.Kind() != artifact.KindTaskInput {
			t.Fatalf("root input %q=(%#v,%v)", key, inputArtifact, getErr)
		}
	}
	again, err := admitter.Admit(context.Background(), intent, time.UnixMilli(2_000))
	if err != nil || again.Plan().Identity() != state.Plan().Identity() || again.Plan().Scope().Identity() != state.Plan().Scope().Identity() {
		t.Fatalf("idempotent Admit()=(%#v,%v)", again, err)
	}
	otherHead, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("3", 40))
	conflict, _ := NewLocalDeterministicReviewIntent(intent.Scope(), intent.Repository(), intent.BaseRevision(), otherHead, intent.CreatedAt())
	if state, err := admitter.Admit(context.Background(), conflict, time.UnixMilli(1_002)); !errors.Is(err, ErrLocalDeterministicReviewConflict) || state.Plan().Identity() != "" {
		t.Fatalf("conflicting Admit()=(%#v,%v)", state, err)
	}
}

type failingLocalInputStore struct{ artifact.Store }

func (f failingLocalInputStore) Put(context.Context, artifact.Artifact, time.Time) (bool, error) {
	return false, artifact.ErrStoreCapacity
}

func TestLocalDeterministicReviewAdmissionDoesNotOpenRunWhenInputPersistenceFails(t *testing.T) {
	intent, config, journal, store := deterministicAdmissionFixture(t, "run-failure")
	admitter, err := NewLocalDeterministicReviewAdmitter(journal, failingLocalInputStore{store}, config)
	if err != nil {
		t.Fatal(err)
	}
	state, err := admitter.Admit(context.Background(), intent, time.UnixMilli(1_001))
	if !errors.Is(err, artifact.ErrStoreCapacity) || state.Plan().Identity() != "" {
		t.Fatalf("Admit()=(%#v,%v)", state, err)
	}
	if _, found, loadErr := journal.LoadPlan(context.Background(), intent.Scope()); loadErr != nil || found {
		t.Fatalf("run opened after failed root input persistence: found=%t err=%v", found, loadErr)
	}
}

func TestLocalDeterministicReviewAdmissionRejectsStaleNewIntent(t *testing.T) {
	intent, config, journal, store := deterministicAdmissionFixture(t, "run-stale")
	admitter, _ := NewLocalDeterministicReviewAdmitter(journal, store, config)
	state, err := admitter.Admit(context.Background(), intent, intent.CreatedAt().Add(6*time.Minute))
	if !errors.Is(err, ErrLocalDeterministicReviewExpired) || state.Plan().Identity() != "" {
		t.Fatalf("stale Admit()=(%#v,%v)", state, err)
	}
}
