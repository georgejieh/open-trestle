package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/internal/analysis"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestExecuteRepositoryAcquisitionWithProfileBuildsExactBundle(t *testing.T) {
	contents := map[string][]byte{
		"main_test.go":  []byte{0, 'x'},
		"vendor/lib.go": []byte("package vendor\n"),
	}
	fixture := mustExecutionFixtureWithFiles(t, evidence.AcquisitionArtifactManifestAndContent, contents)
	result := fixture.acquiredResult()
	adapter := &fakeSourceAdapter{identity: fixture.adapter, result: result}
	profiled, err := ExecuteRepositoryAcquisitionWithProfile(context.Background(), fixture.request, adapter)
	if err != nil {
		t.Fatalf("ExecuteRepositoryAcquisitionWithProfile() error = %v", err)
	}
	expectedBundle := mustRepositoryProfileBundle(t, fixture.manifest, fixture.contents)
	if profiled.Identity() == "" || !profiled.HasProfile() || profiled.ProfileBundle() != expectedBundle || profiled.Acquisition().Receipt().ManifestIdentity() != expectedBundle.ManifestIdentity() || adapter.calls != 1 {
		t.Fatalf("profiled execution = %#v, calls = %d, bundle = %#v", profiled, adapter.calls, expectedBundle)
	}
	if want := expectedRepositoryAcquisitionProfileExecutionIdentity(profiled); profiled.Identity() != want {
		t.Fatalf("Identity() = %q, want %q", profiled.Identity(), want)
	}
	identity := profiled.Identity()
	result.Contents["main_test.go"][0] = 'X'
	adapter.result.Contents["vendor/lib.go"][0] = 'X'
	if profiled.Identity() != identity || profiled.ProfileBundle() != expectedBundle {
		t.Fatal("source content mutation changed profiled execution")
	}
	ordinaryAdapter := &fakeSourceAdapter{identity: fixture.adapter, result: fixture.acquiredResult()}
	ordinary, err := ExecuteRepositoryAcquisitionWithEvidence(context.Background(), fixture.request, ordinaryAdapter)
	if err != nil || ordinary != profiled.Acquisition() || ordinaryAdapter.calls != 1 {
		t.Fatalf("ordinary execution = (%#v, %v), calls = %d", ordinary, err, ordinaryAdapter.calls)
	}
}

func TestExecuteRepositoryAcquisitionWithProfilePreservesLocalGitEvidence(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	blob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", []byte("package sample\n"))
	tree := localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, []byte("main.go"), blob)
	revision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, tree)
	adapter := mustLocalGitSourceAdapter(t, store)
	request := mustLocalGitAdapterRequest(t, adapter, mustRepositoryIdentity(t), revision, evidence.AcquisitionArtifactManifestAndContent)
	profiled, err := ExecuteRepositoryAcquisitionWithProfile(context.Background(), request, adapter)
	if err != nil || !profiled.HasProfile() || !profiled.Acquisition().HasLocalGitEvidence() || profiled.Acquisition().GitCommitIdentity() == "" || profiled.Acquisition().GitTreeGraphIdentity() == "" || profiled.Acquisition().CorrespondenceIdentity() == "" || profiled.ProfileBundle().ManifestIdentity() != profiled.Acquisition().ManifestIdentity() {
		t.Fatalf("ExecuteRepositoryAcquisitionWithProfile() = (%#v, %v)", profiled, err)
	}
	forwarding := &forwardingSourceAdapter{delegate: adapter}
	forwarded, err := ExecuteRepositoryAcquisitionWithProfile(context.Background(), request, forwarding)
	if err != nil || forwarded.Acquisition().HasLocalGitEvidence() || forwarded.ProfileBundle() != profiled.ProfileBundle() || forwarded.Acquisition().Receipt() != profiled.Acquisition().Receipt() || forwarded.Identity() == profiled.Identity() || forwarding.calls != 1 {
		t.Fatalf("forwarded profile = (%#v, %v), calls = %d", forwarded, err, forwarding.calls)
	}
}

func TestExecuteRepositoryAcquisitionWithProfileReturnsUnprofiledTerminalExecution(t *testing.T) {
	fixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifestAndContent)
	for _, result := range []SourceAdapterResult{
		{Outcome: evidence.AcquisitionOutcomeBlocked, Reason: evidence.AcquisitionReasonPolicyBlocked},
		{Outcome: evidence.AcquisitionOutcomeFailed, Reason: evidence.AcquisitionReasonAdapterFailure},
	} {
		t.Run(string(result.Outcome), func(t *testing.T) {
			adapter := &fakeSourceAdapter{identity: fixture.adapter, result: result}
			profiled, err := ExecuteRepositoryAcquisitionWithProfile(context.Background(), fixture.request, adapter)
			if err != nil || profiled.Identity() == "" || profiled.Identity() != expectedRepositoryAcquisitionProfileExecutionIdentity(profiled) || profiled.Acquisition().Outcome() != result.Outcome || profiled.HasProfile() || profiled.ProfileBundle().Identity() != "" || adapter.calls != 1 {
				t.Fatalf("profiled execution = (%#v, %v), calls = %d", profiled, err, adapter.calls)
			}
			compatibility := &fakeSourceAdapter{identity: fixture.adapter, result: result}
			receipt, err := ExecuteRepositoryAcquisition(context.Background(), fixture.request, compatibility)
			if err != nil || receipt != profiled.Acquisition().Receipt() {
				t.Fatalf("compatibility receipt = (%#v, %v)", receipt, err)
			}
		})
	}
}

func TestExecuteRepositoryAcquisitionWithProfileRejectsBeforeAcquire(t *testing.T) {
	manifestFixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifest)
	manifestAdapter := &fakeSourceAdapter{identity: manifestFixture.adapter, result: manifestFixture.acquiredResult()}
	if profiled, err := ExecuteRepositoryAcquisitionWithProfile(context.Background(), manifestFixture.request, manifestAdapter); err == nil || profiled.Identity() != "" || manifestAdapter.calls != 0 {
		t.Fatalf("manifest profile = (%#v, %v), calls = %d", profiled, err, manifestAdapter.calls)
	}
	contentFixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifestAndContent)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceledAdapter := &fakeSourceAdapter{identity: contentFixture.adapter, result: contentFixture.acquiredResult()}
	if profiled, err := ExecuteRepositoryAcquisitionWithProfile(ctx, contentFixture.request, canceledAdapter); !errors.Is(err, context.Canceled) || profiled.Identity() != "" || canceledAdapter.calls != 0 {
		t.Fatalf("canceled profile = (%#v, %v), calls = %d", profiled, err, canceledAdapter.calls)
	}
	if profiled, err := ExecuteRepositoryAcquisitionWithProfile(context.Background(), contentFixture.request, nil); err == nil || profiled.Identity() != "" {
		t.Fatalf("nil adapter profile = (%#v, %v)", profiled, err)
	}
}

func TestRepositoryAcquisitionProfileExecutionIsDeterministicAndCompact(t *testing.T) {
	firstFixture := mustExecutionFixtureWithFiles(t, evidence.AcquisitionArtifactManifestAndContent, map[string][]byte{"b.go": []byte("b"), "a.go": []byte("a")})
	secondFixture := mustExecutionFixtureWithFiles(t, evidence.AcquisitionArtifactManifestAndContent, map[string][]byte{"a.go": []byte("a"), "b.go": []byte("b")})
	first, firstErr := ExecuteRepositoryAcquisitionWithProfile(context.Background(), firstFixture.request, &fakeSourceAdapter{identity: firstFixture.adapter, result: firstFixture.acquiredResult()})
	second, secondErr := ExecuteRepositoryAcquisitionWithProfile(context.Background(), secondFixture.request, &fakeSourceAdapter{identity: secondFixture.adapter, result: secondFixture.acquiredResult()})
	if firstErr != nil || secondErr != nil || first != second {
		t.Fatalf("profiled executions = (%#v, %v) (%#v, %v)", first, firstErr, second, secondErr)
	}
	emptyFixture := mustExecutionFixtureWithFiles(t, evidence.AcquisitionArtifactManifestAndContent, map[string][]byte{})
	empty, err := ExecuteRepositoryAcquisitionWithProfile(context.Background(), emptyFixture.request, &fakeSourceAdapter{identity: emptyFixture.adapter, result: emptyFixture.acquiredResult()})
	if err != nil || !empty.HasProfile() || empty.ProfileBundle().ManifestIdentity() != empty.Acquisition().Receipt().ManifestIdentity() {
		t.Fatalf("empty profile = (%#v, %v)", empty, err)
	}
	typeOfExecution := reflect.TypeOf(RepositoryAcquisitionProfileExecution{})
	for i := 0; i < typeOfExecution.NumField(); i++ {
		switch typeOfExecution.Field(i).Type.Kind() {
		case reflect.Map, reflect.Pointer, reflect.Slice:
			t.Fatalf("field %q retains %s", typeOfExecution.Field(i).Name, typeOfExecution.Field(i).Type)
		}
	}
	var zero RepositoryAcquisitionProfileExecution
	if zero.Identity() != "" || zero.Acquisition().Identity() != "" || zero.HasProfile() || zero.ProfileBundle().Identity() != "" {
		t.Fatalf("zero profiled execution = %#v", zero)
	}
}

func mustRepositoryProfileBundle(t *testing.T, manifest evidence.RepositoryManifest, contents map[string][]byte) analysis.RepositoryProfileBundle {
	t.Helper()
	profile, err := analysis.NewRepositoryProfile(manifest)
	if err != nil {
		t.Fatalf("NewRepositoryProfile() error = %v", err)
	}
	classification, err := analysis.ClassifyRepositoryManifest(manifest, contents)
	if err != nil {
		t.Fatalf("ClassifyRepositoryManifest() error = %v", err)
	}
	summary, err := analysis.NewRepositoryClassificationSummary(manifest, classification)
	if err != nil {
		t.Fatalf("NewRepositoryClassificationSummary() error = %v", err)
	}
	bundle, err := analysis.NewRepositoryProfileBundle(manifest, profile, classification, summary)
	if err != nil {
		t.Fatalf("NewRepositoryProfileBundle() error = %v", err)
	}
	return bundle
}

func expectedRepositoryAcquisitionProfileExecutionIdentity(profiled RepositoryAcquisitionProfileExecution) string {
	preimage := struct {
		Contract                     string `json:"contract"`
		SchemaVersion                int    `json:"schema_version"`
		AcquisitionExecutionIdentity string `json:"acquisition_execution_identity"`
		ProfilePresent               bool   `json:"profile_present"`
		ProfileBundleIdentity        string `json:"profile_bundle_identity"`
	}{
		Contract:                     "open-trestle/repository-acquisition-profile-execution",
		SchemaVersion:                1,
		AcquisitionExecutionIdentity: profiled.Acquisition().Identity(),
		ProfilePresent:               profiled.HasProfile(),
		ProfileBundleIdentity:        profiled.ProfileBundle().Identity(),
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
