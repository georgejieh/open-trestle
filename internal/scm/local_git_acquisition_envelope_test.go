package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestExecuteLocalGitAcquisitionWithBindingAndProfileBindsOneRuntimeResult(t *testing.T) {
	for _, algorithm := range []evidence.RevisionAlgorithm{evidence.RevisionAlgorithmSHA1, evidence.RevisionAlgorithmSHA256} {
		t.Run(string(algorithm), func(t *testing.T) {
			adapter, request, contents := newLocalGitAcquisitionEnvelopeFixture(t, algorithm, "sample")
			envelope, err := ExecuteLocalGitAcquisitionWithBindingAndProfile(context.Background(), request, adapter)
			if err != nil {
				t.Fatalf("ExecuteLocalGitAcquisitionWithBindingAndProfile() error = %v", err)
			}
			profiled := envelope.ProfiledAcquisition()
			execution := profiled.Acquisition()
			binding := envelope.EvidenceBinding()
			manifestFixture := mustExecutionFixtureWithFiles(t, evidence.AcquisitionArtifactManifestAndContent, contents)
			expectedBundle := mustRepositoryProfileBundle(t, manifestFixture.manifest, manifestFixture.contents)
			if envelope.Identity() == "" || profiled.Identity() == "" || !profiled.HasProfile() || profiled.ProfileBundle() != expectedBundle || binding.Identity() == "" || binding.BindingStatus() != evidence.RepositoryAcquisitionEvidenceStatusSupplied {
				t.Fatalf("envelope = %#v, expected bundle = %#v", envelope, expectedBundle)
			}
			if !execution.HasLocalGitEvidence() || execution.Outcome() != evidence.AcquisitionOutcomeAcquired || binding.RequestIdentity() != execution.RequestIdentity() || binding.ReceiptIdentity() != execution.ReceiptIdentity() || binding.RepositoryIdentity() != execution.Receipt().RepositoryIdentity() || binding.RevisionIdentity() != execution.RevisionIdentity() || binding.SourceAdapterIdentity() != execution.SourceAdapterIdentity() || binding.ManifestIdentity() != execution.ManifestIdentity() || binding.ManifestIdentity() != execution.Receipt().ManifestIdentity() || binding.ManifestIdentity() != profiled.ProfileBundle().ManifestIdentity() || binding.GitCommitIdentity() != execution.GitCommitIdentity() || binding.GitTreeGraphIdentity() != execution.GitTreeGraphIdentity() || binding.CorrespondenceIdentity() != execution.CorrespondenceIdentity() {
				t.Fatalf("joint evidence does not agree: %#v %#v %#v", profiled, execution, binding)
			}
			if envelope.Identity() != expectedLocalGitAcquisitionEnvelopeIdentity(envelope) {
				t.Fatalf("Identity() = %q, want %q", envelope.Identity(), expectedLocalGitAcquisitionEnvelopeIdentity(envelope))
			}
		})
	}
}

func TestExecuteLocalGitAcquisitionWithBindingAndProfileAcceptsEmptyRevision(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	revision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, nil)
	adapter := mustLocalGitSourceAdapter(t, store)
	request := mustLocalGitAdapterRequest(t, adapter, mustRepositoryIdentity(t), revision, evidence.AcquisitionArtifactManifestAndContent)
	envelope, err := ExecuteLocalGitAcquisitionWithBindingAndProfile(context.Background(), request, adapter)
	if err != nil || envelope.Identity() == "" || envelope.EvidenceBinding().Identity() == "" || !envelope.ProfiledAcquisition().HasProfile() || envelope.ProfiledAcquisition().ProfileBundle().ManifestIdentity() != envelope.EvidenceBinding().ManifestIdentity() || envelope.ProfiledAcquisition().Acquisition().Receipt().ContentCoverage() != evidence.ContentCoverageComplete {
		t.Fatalf("empty envelope = (%#v, %v)", envelope, err)
	}
}

func TestLocalGitAcquisitionEnvelopeIdentityAndChildrenMatchExistingAPIs(t *testing.T) {
	adapter, request, _ := newLocalGitAcquisitionEnvelopeFixture(t, evidence.RevisionAlgorithmSHA1, "compatibility")
	envelope, err := ExecuteLocalGitAcquisitionWithBindingAndProfile(context.Background(), request, adapter)
	if err != nil {
		t.Fatalf("ExecuteLocalGitAcquisitionWithBindingAndProfile() error = %v", err)
	}
	execution, binding, err := ExecuteLocalGitAcquisitionWithBinding(context.Background(), request, adapter)
	if err != nil {
		t.Fatalf("ExecuteLocalGitAcquisitionWithBinding() error = %v", err)
	}
	profiled, err := ExecuteRepositoryAcquisitionWithProfile(context.Background(), request, adapter)
	if err != nil {
		t.Fatalf("ExecuteRepositoryAcquisitionWithProfile() error = %v", err)
	}
	if envelope.EvidenceBinding() != binding || envelope.ProfiledAcquisition() != profiled || envelope.ProfiledAcquisition().Acquisition() != execution || envelope.Identity() != expectedLocalGitAcquisitionEnvelopeIdentity(envelope) {
		t.Fatalf("envelope children changed: %#v %#v %#v", envelope, profiled, binding)
	}
	repeated, err := ExecuteLocalGitAcquisitionWithBindingAndProfile(context.Background(), request, adapter)
	if err != nil || repeated != envelope {
		t.Fatalf("repeated envelope = (%#v, %v), want %#v", repeated, err, envelope)
	}
}

func TestExecuteLocalGitAcquisitionWithBindingAndProfileRejectsBeforeRead(t *testing.T) {
	adapter, request, _ := newLocalGitAcquisitionEnvelopeFixture(t, evidence.RevisionAlgorithmSHA1, "rejected")
	manifestRequest := mustLocalGitAdapterRequest(t, adapter, mustRepositoryIdentity(t), request.Revision(), evidence.AcquisitionArtifactManifest)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var nilContext context.Context
	tests := []struct {
		name     string
		ctx      context.Context
		request  evidence.RepositoryAcquisitionRequest
		adapter  *LocalGitSourceAdapter
		isCancel bool
	}{
		{name: "nil context", ctx: nilContext, request: request, adapter: adapter},
		{name: "canceled", ctx: ctx, request: request, adapter: adapter, isCancel: true},
		{name: "nil adapter", ctx: context.Background(), request: request},
		{name: "zero request", ctx: context.Background(), adapter: adapter},
		{name: "manifest only", ctx: context.Background(), request: manifestRequest, adapter: adapter},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope, err := ExecuteLocalGitAcquisitionWithBindingAndProfile(test.ctx, test.request, test.adapter)
			if err == nil || envelope.Identity() != "" || envelope.ProfiledAcquisition().Identity() != "" || envelope.EvidenceBinding().Identity() != "" {
				t.Fatalf("rejected envelope = (%#v, %v)", envelope, err)
			}
			if test.isCancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestExecuteLocalGitAcquisitionWithBindingAndProfileRejectsIncompleteRevision(t *testing.T) {
	repository := mustRepositoryIdentity(t)
	tests := []struct {
		name        string
		mode        evidence.GitTreeMode
		object      string
		writeObject bool
	}{
		{name: "missing object", mode: evidence.GitTreeModeRegular, object: strings.Repeat("8", 40)},
		{name: "symlink", mode: evidence.GitTreeModeSymlink, writeObject: true},
		{name: "gitlink", mode: evidence.GitTreeModeGitlink, object: strings.Repeat("9", 40)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory, store := newLocalGitObjectStoreFixture(t)
			object := test.object
			if test.writeObject {
				object = writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", []byte("target"))
			}
			tree := localTreeEntry(t, evidence.RevisionAlgorithmSHA1, test.mode, []byte("entry"), object)
			revision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, tree)
			adapter := mustLocalGitSourceAdapter(t, store)
			request := mustLocalGitAdapterRequest(t, adapter, repository, revision, evidence.AcquisitionArtifactManifestAndContent)
			envelope, err := ExecuteLocalGitAcquisitionWithBindingAndProfile(context.Background(), request, adapter)
			if err == nil || envelope.Identity() != "" || envelope.ProfiledAcquisition().Identity() != "" || envelope.EvidenceBinding().Identity() != "" {
				t.Fatalf("incomplete envelope = (%#v, %v)", envelope, err)
			}
		})
	}
}

func TestNewLocalGitAcquisitionEnvelopeRejectsMismatchedChildren(t *testing.T) {
	firstAdapter, firstRequest, _ := newLocalGitAcquisitionEnvelopeFixture(t, evidence.RevisionAlgorithmSHA1, "first")
	first, err := ExecuteLocalGitAcquisitionWithBindingAndProfile(context.Background(), firstRequest, firstAdapter)
	if err != nil {
		t.Fatalf("first envelope error = %v", err)
	}
	secondAdapter, secondRequest, _ := newLocalGitAcquisitionEnvelopeFixture(t, evidence.RevisionAlgorithmSHA1, "second")
	second, err := ExecuteLocalGitAcquisitionWithBindingAndProfile(context.Background(), secondRequest, secondAdapter)
	if err != nil {
		t.Fatalf("second envelope error = %v", err)
	}
	for _, test := range []struct {
		name     string
		profiled RepositoryAcquisitionProfileExecution
		binding  evidence.RepositoryAcquisitionEvidenceBinding
	}{
		{name: "zero profile", binding: first.EvidenceBinding()},
		{name: "zero binding", profiled: first.ProfiledAcquisition()},
		{name: "other binding", profiled: first.ProfiledAcquisition(), binding: second.EvidenceBinding()},
		{name: "other profile", profiled: second.ProfiledAcquisition(), binding: first.EvidenceBinding()},
		{name: "altered profile identity", profiled: alterProfiledAcquisition(first.ProfiledAcquisition(), func(profiled *RepositoryAcquisitionProfileExecution) { profiled.identity = "forged" }), binding: first.EvidenceBinding()},
		{name: "rewrapped forged acquisition identity", profiled: rewrapProfiledAcquisitionWithIdentity(t, first.ProfiledAcquisition(), strings.Repeat("a", sha256.Size*2)), binding: first.EvidenceBinding()},
		{name: "altered request", profiled: alterProfiledAcquisition(first.ProfiledAcquisition(), func(profiled *RepositoryAcquisitionProfileExecution) {
			profiled.acquisition.requestIdentity = second.ProfiledAcquisition().Acquisition().RequestIdentity()
		}), binding: first.EvidenceBinding()},
		{name: "altered receipt", profiled: alterProfiledAcquisition(first.ProfiledAcquisition(), func(profiled *RepositoryAcquisitionProfileExecution) {
			profiled.acquisition.receipt = second.ProfiledAcquisition().Acquisition().Receipt()
		}), binding: first.EvidenceBinding()},
		{name: "altered adapter", profiled: alterProfiledAcquisition(first.ProfiledAcquisition(), func(profiled *RepositoryAcquisitionProfileExecution) {
			profiled.acquisition.sourceAdapterIdentity = "forged"
		}), binding: first.EvidenceBinding()},
		{name: "altered manifest", profiled: alterProfiledAcquisition(first.ProfiledAcquisition(), func(profiled *RepositoryAcquisitionProfileExecution) {
			profiled.acquisition.manifestIdentity = second.EvidenceBinding().ManifestIdentity()
		}), binding: first.EvidenceBinding()},
		{name: "altered revision", profiled: alterProfiledAcquisition(first.ProfiledAcquisition(), func(profiled *RepositoryAcquisitionProfileExecution) {
			profiled.acquisition.revisionIdentity = second.EvidenceBinding().RevisionIdentity()
		}), binding: first.EvidenceBinding()},
		{name: "altered commit", profiled: alterProfiledAcquisition(first.ProfiledAcquisition(), func(profiled *RepositoryAcquisitionProfileExecution) {
			profiled.acquisition.gitCommitIdentity = second.EvidenceBinding().GitCommitIdentity()
		}), binding: first.EvidenceBinding()},
		{name: "altered graph", profiled: alterProfiledAcquisition(first.ProfiledAcquisition(), func(profiled *RepositoryAcquisitionProfileExecution) {
			profiled.acquisition.gitTreeGraphIdentity = second.EvidenceBinding().GitTreeGraphIdentity()
		}), binding: first.EvidenceBinding()},
		{name: "altered correspondence", profiled: alterProfiledAcquisition(first.ProfiledAcquisition(), func(profiled *RepositoryAcquisitionProfileExecution) {
			profiled.acquisition.correspondenceIdentity = second.EvidenceBinding().CorrespondenceIdentity()
		}), binding: first.EvidenceBinding()},
		{name: "altered profile bundle", profiled: alterProfiledAcquisition(first.ProfiledAcquisition(), func(profiled *RepositoryAcquisitionProfileExecution) {
			profiled.profileBundle = second.ProfiledAcquisition().ProfileBundle()
		}), binding: first.EvidenceBinding()},
	} {
		t.Run(test.name, func(t *testing.T) {
			envelope, err := newLocalGitAcquisitionEnvelope(test.profiled, test.binding)
			if err == nil || envelope.Identity() != "" || envelope.ProfiledAcquisition().Identity() != "" || envelope.EvidenceBinding().Identity() != "" {
				t.Fatalf("mismatched envelope = (%#v, %v)", envelope, err)
			}
		})
	}
}

func TestLocalGitAcquisitionEnvelopeIsCompact(t *testing.T) {
	assertLocalGitEnvelopeCompactType(t, reflect.TypeOf(LocalGitAcquisitionEnvelope{}), "LocalGitAcquisitionEnvelope", map[reflect.Type]bool{})
	var zero LocalGitAcquisitionEnvelope
	if zero.Identity() != "" || zero.ProfiledAcquisition().Identity() != "" || zero.EvidenceBinding().Identity() != "" {
		t.Fatalf("zero envelope = %#v", zero)
	}
}

func newLocalGitAcquisitionEnvelopeFixture(t *testing.T, algorithm evidence.RevisionAlgorithm, prefix string) (*LocalGitSourceAdapter, evidence.RepositoryAcquisitionRequest, map[string][]byte) {
	t.Helper()
	directory, store := newLocalGitObjectStoreFixture(t)
	readmeContent := []byte(prefix + " readme\n")
	mainContent := []byte("package " + prefix + "\n")
	readme := writeLooseObject(t, directory, algorithm, "blob", readmeContent)
	main := writeLooseObject(t, directory, algorithm, "blob", mainContent)
	nestedTree := writeLooseObject(t, directory, algorithm, "tree", localTreeEntry(t, algorithm, evidence.GitTreeModeRegular, []byte("main.go"), main))
	rootTree := append(localTreeEntry(t, algorithm, evidence.GitTreeModeRegular, []byte("README.md"), readme), localTreeEntry(t, algorithm, evidence.GitTreeModeDirectory, []byte("nested"), nestedTree)...)
	revision := writeLocalRevision(t, directory, algorithm, rootTree)
	adapter := mustLocalGitSourceAdapter(t, store)
	request := mustLocalGitAdapterRequest(t, adapter, mustRepositoryIdentity(t), revision, evidence.AcquisitionArtifactManifestAndContent)
	return adapter, request, map[string][]byte{"README.md": readmeContent, "nested/main.go": mainContent}
}

func alterProfiledAcquisition(profiled RepositoryAcquisitionProfileExecution, alter func(*RepositoryAcquisitionProfileExecution)) RepositoryAcquisitionProfileExecution {
	alter(&profiled)
	return profiled
}

func rewrapProfiledAcquisitionWithIdentity(t *testing.T, profiled RepositoryAcquisitionProfileExecution, identity string) RepositoryAcquisitionProfileExecution {
	t.Helper()
	acquisition := profiled.Acquisition()
	acquisition.identity = identity
	rewrapped, err := newRepositoryAcquisitionProfileExecution(acquisition, profiled.ProfileBundle(), profiled.HasProfile())
	if err != nil {
		t.Fatalf("newRepositoryAcquisitionProfileExecution() error = %v", err)
	}
	return rewrapped
}

func expectedLocalGitAcquisitionEnvelopeIdentity(envelope LocalGitAcquisitionEnvelope) string {
	preimage := struct {
		Contract                             string `json:"contract"`
		SchemaVersion                        int    `json:"schema_version"`
		ProfiledAcquisitionExecutionIdentity string `json:"profiled_acquisition_execution_identity"`
		EvidenceBindingIdentity              string `json:"evidence_binding_identity"`
	}{
		Contract:                             "open-trestle/local-git-acquisition-envelope",
		SchemaVersion:                        1,
		ProfiledAcquisitionExecutionIdentity: envelope.ProfiledAcquisition().Identity(),
		EvidenceBindingIdentity:              envelope.EvidenceBinding().Identity(),
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func assertLocalGitEnvelopeCompactType(t *testing.T, value reflect.Type, path string, seen map[reflect.Type]bool) {
	t.Helper()
	if seen[value] {
		return
	}
	seen[value] = true
	switch value.Kind() {
	case reflect.Map, reflect.Pointer, reflect.Slice, reflect.Interface:
		t.Fatalf("%s retains %s", path, value)
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			assertLocalGitEnvelopeCompactType(t, field.Type, path+"."+field.Name, seen)
		}
	}
}
