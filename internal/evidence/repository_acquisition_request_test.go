package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestNewRepositoryAcquisitionRequestDerivesManifestRequirements(t *testing.T) {
	repository, revision, adapter := mustAcquisitionAuthorities(t, RevisionAlgorithmSHA1, []SourceAdapterCapability{SourceCapabilityReadManifest})
	request, err := NewRepositoryAcquisitionRequest(repository, revision, adapter, AcquisitionArtifactManifest, AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionRequest() error = %v", err)
	}
	if len(request.Identity()) != 64 || request.RepositoryIdentity() != repository.Identity() || request.RevisionIdentity() != revision.Identity() || request.SourceAdapterIdentity() != adapter.Identity() || request.Artifact() != AcquisitionArtifactManifest || request.Effect() != AcquisitionEffectReadOnly {
		t.Fatalf("request = (%q, %q, %q, %q, %q, %q)", request.Identity(), request.RepositoryIdentity(), request.RevisionIdentity(), request.SourceAdapterIdentity(), request.Artifact(), request.Effect())
	}
	want := []SourceAdapterCapability{SourceCapabilityReadManifest}
	if got := request.RequiredCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("RequiredCapabilities() = %v, want %v", got, want)
	}
	repeated, err := NewRepositoryAcquisitionRequest(repository, revision, adapter, AcquisitionArtifactManifest, AcquisitionEffectReadOnly)
	if err != nil || !repositoryAcquisitionRequestsEqual(repeated, request) {
		t.Fatalf("repeated = (%#v, %v), want %#v", repeated, err, request)
	}
}

func TestNewRepositoryAcquisitionRequestDerivesContentRequirements(t *testing.T) {
	repository, revision, adapter := mustAcquisitionAuthorities(t, RevisionAlgorithmSHA256, []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent})
	request, err := NewRepositoryAcquisitionRequest(repository, revision, adapter, AcquisitionArtifactManifestAndContent, AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionRequest() error = %v", err)
	}
	want := []SourceAdapterCapability{SourceCapabilityReadContent, SourceCapabilityReadManifest}
	if got := request.RequiredCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("RequiredCapabilities() = %v, want %v", got, want)
	}
}

func TestRepositoryAcquisitionRequestUsesCanonicalPreimage(t *testing.T) {
	testCases := []struct {
		artifact     RepositoryAcquisitionArtifact
		capabilities []SourceAdapterCapability
		requirements string
	}{
		{artifact: AcquisitionArtifactManifest, capabilities: []SourceAdapterCapability{SourceCapabilityReadManifest}, requirements: `"read_manifest"`},
		{artifact: AcquisitionArtifactManifestAndContent, capabilities: []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent}, requirements: `"read_content","read_manifest"`},
	}
	for _, testCase := range testCases {
		t.Run(string(testCase.artifact), func(t *testing.T) {
			repository, revision, adapter := mustAcquisitionAuthorities(t, RevisionAlgorithmSHA1, testCase.capabilities)
			request, err := NewRepositoryAcquisitionRequest(repository, revision, adapter, testCase.artifact, AcquisitionEffectReadOnly)
			if err != nil {
				t.Fatalf("NewRepositoryAcquisitionRequest() error = %v", err)
			}
			preimage := fmt.Sprintf(`{"contract":"open-trestle/repository-acquisition-request","schema_version":1,"repository_identity":"%s","revision_identity":"%s","source_adapter_identity":"%s","artifact":"%s","effect":"read_only","required_capabilities":[%s]}`, repository.Identity(), revision.Identity(), adapter.Identity(), testCase.artifact, testCase.requirements)
			digest := sha256.Sum256([]byte(preimage))
			if want := hex.EncodeToString(digest[:]); request.Identity() != want {
				t.Fatalf("Identity() = %q, want SHA-256 of %s", request.Identity(), preimage)
			}
		})
	}
}

func TestRepositoryAcquisitionRequestBindsExactAdapterIdentity(t *testing.T) {
	repository, revision, baseAdapter := mustAcquisitionAuthorities(t, RevisionAlgorithmSHA1, []SourceAdapterCapability{SourceCapabilityReadManifest})
	extraAdapter := mustAcquisitionAdapter(t, []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadDiff})
	base, err := NewRepositoryAcquisitionRequest(repository, revision, baseAdapter, AcquisitionArtifactManifest, AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionRequest(base) error = %v", err)
	}
	extra, err := NewRepositoryAcquisitionRequest(repository, revision, extraAdapter, AcquisitionArtifactManifest, AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionRequest(extra) error = %v", err)
	}
	if base.Identity() == extra.Identity() || !reflect.DeepEqual(base.RequiredCapabilities(), extra.RequiredCapabilities()) {
		t.Fatalf("requests = (%#v, %#v), want distinct identities and equal requirements", base, extra)
	}
}

func TestNewRepositoryAcquisitionRequestRejectsMissingCapabilities(t *testing.T) {
	repository := mustAcquisitionRepository(t)
	revision := mustAcquisitionRevision(t, RevisionAlgorithmSHA1)
	testCases := []struct {
		name         string
		artifact     RepositoryAcquisitionArtifact
		capabilities []SourceAdapterCapability
	}{
		{name: "manifest missing manifest", artifact: AcquisitionArtifactManifest, capabilities: []SourceAdapterCapability{SourceCapabilityReadContent}},
		{name: "content missing content", artifact: AcquisitionArtifactManifestAndContent, capabilities: []SourceAdapterCapability{SourceCapabilityReadManifest}},
		{name: "content missing manifest", artifact: AcquisitionArtifactManifestAndContent, capabilities: []SourceAdapterCapability{SourceCapabilityReadContent}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			adapter := mustAcquisitionAdapter(t, testCase.capabilities)
			request, err := NewRepositoryAcquisitionRequest(repository, revision, adapter, testCase.artifact, AcquisitionEffectReadOnly)
			if err == nil || request.Identity() != "" {
				t.Fatalf("NewRepositoryAcquisitionRequest() = (%#v, %v), want zero error result", request, err)
			}
		})
	}
}

func TestNewRepositoryAcquisitionRequestRejectsUnknownArtifactAndEffect(t *testing.T) {
	repository, revision, adapter := mustAcquisitionAuthorities(t, RevisionAlgorithmSHA1, []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent, SourceCapabilityReadDiff})
	testCases := []struct {
		name     string
		artifact RepositoryAcquisitionArtifact
		effect   RepositoryAcquisitionEffect
	}{
		{name: "zero artifact", effect: AcquisitionEffectReadOnly},
		{name: "diff artifact", artifact: RepositoryAcquisitionArtifact("diff"), effect: AcquisitionEffectReadOnly},
		{name: "unknown artifact", artifact: RepositoryAcquisitionArtifact("content"), effect: AcquisitionEffectReadOnly},
		{name: "zero effect", artifact: AcquisitionArtifactManifest},
		{name: "write effect", artifact: AcquisitionArtifactManifest, effect: RepositoryAcquisitionEffect("write")},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request, err := NewRepositoryAcquisitionRequest(repository, revision, adapter, testCase.artifact, testCase.effect)
			if err == nil || request.Identity() != "" {
				t.Fatalf("NewRepositoryAcquisitionRequest() = (%#v, %v), want zero error result", request, err)
			}
		})
	}
}

func TestRepositoryAcquisitionRequestChangesWithBoundAuthorities(t *testing.T) {
	repository, revision, adapter := mustAcquisitionAuthorities(t, RevisionAlgorithmSHA1, []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent})
	base := mustAcquisitionRequest(t, repository, revision, adapter, AcquisitionArtifactManifest)
	otherRepository, err := NewRepositoryIdentity("git.example.com", []string{"other"}, "repo")
	if err != nil {
		t.Fatalf("NewRepositoryIdentity() error = %v", err)
	}
	otherRevision, err := NewRevisionIdentity(RevisionKindGitCommit, RevisionAlgorithmSHA1, "1123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatalf("NewRevisionIdentity() error = %v", err)
	}
	otherAdapter, err := NewSourceAdapterIdentity(SourceAdapterKindGit, "other-git", "1.2.3", []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent})
	if err != nil {
		t.Fatalf("NewSourceAdapterIdentity() error = %v", err)
	}
	requests := []RepositoryAcquisitionRequest{
		base,
		mustAcquisitionRequest(t, otherRepository, revision, adapter, AcquisitionArtifactManifest),
		mustAcquisitionRequest(t, repository, otherRevision, adapter, AcquisitionArtifactManifest),
		mustAcquisitionRequest(t, repository, revision, otherAdapter, AcquisitionArtifactManifest),
		mustAcquisitionRequest(t, repository, revision, adapter, AcquisitionArtifactManifestAndContent),
	}
	identities := make(map[string]struct{}, len(requests))
	for _, request := range requests {
		identities[request.Identity()] = struct{}{}
	}
	if len(identities) != len(requests) {
		t.Fatalf("%d requests produced %d identities", len(requests), len(identities))
	}
}

func TestNewRepositoryAcquisitionRequestRejectsForgedRepository(t *testing.T) {
	repository, revision, adapter := mustAcquisitionAuthorities(t, RevisionAlgorithmSHA1, []SourceAdapterCapability{SourceCapabilityReadManifest})
	forgeries := []RepositoryIdentity{}
	forged := repository
	forged.identity = strings.Repeat("0", 64)
	forgeries = append(forgeries, forged)
	forged = repository
	forged.authority = "other.example.com"
	forgeries = append(forgeries, forged)
	forged = repository
	forged.namespace = []string{"other"}
	forgeries = append(forgeries, forged)
	forged = repository
	forged.name = "other"
	forgeries = append(forgeries, forged)
	for _, forgedRepository := range forgeries {
		request, err := NewRepositoryAcquisitionRequest(forgedRepository, revision, adapter, AcquisitionArtifactManifest, AcquisitionEffectReadOnly)
		if err == nil || request.Identity() != "" {
			t.Fatalf("NewRepositoryAcquisitionRequest() = (%#v, %v), want zero error result", request, err)
		}
	}
	if request, err := NewRepositoryAcquisitionRequest(RepositoryIdentity{}, revision, adapter, AcquisitionArtifactManifest, AcquisitionEffectReadOnly); err == nil || request.Identity() != "" {
		t.Fatalf("NewRepositoryAcquisitionRequest(zero repository) = (%#v, %v)", request, err)
	}
}

func TestNewRepositoryAcquisitionRequestRejectsForgedRevision(t *testing.T) {
	repository, revision, adapter := mustAcquisitionAuthorities(t, RevisionAlgorithmSHA1, []SourceAdapterCapability{SourceCapabilityReadManifest})
	forgeries := []RevisionIdentity{}
	forged := revision
	forged.identity = strings.Repeat("0", 64)
	forgeries = append(forgeries, forged)
	forged = revision
	forged.kind = RevisionKind("git_tag")
	forgeries = append(forgeries, forged)
	forged = revision
	forged.algorithm = RevisionAlgorithmSHA256
	forgeries = append(forgeries, forged)
	forged = revision
	forged.digest = "1123456789abcdef0123456789abcdef01234567"
	forgeries = append(forgeries, forged)
	for _, forgedRevision := range forgeries {
		request, err := NewRepositoryAcquisitionRequest(repository, forgedRevision, adapter, AcquisitionArtifactManifest, AcquisitionEffectReadOnly)
		if err == nil || request.Identity() != "" {
			t.Fatalf("NewRepositoryAcquisitionRequest() = (%#v, %v), want zero error result", request, err)
		}
	}
	if request, err := NewRepositoryAcquisitionRequest(repository, RevisionIdentity{}, adapter, AcquisitionArtifactManifest, AcquisitionEffectReadOnly); err == nil || request.Identity() != "" {
		t.Fatalf("NewRepositoryAcquisitionRequest(zero revision) = (%#v, %v)", request, err)
	}
}

func TestNewRepositoryAcquisitionRequestRejectsForgedAdapter(t *testing.T) {
	repository, revision, adapter := mustAcquisitionAuthorities(t, RevisionAlgorithmSHA1, []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent})
	forgeries := []SourceAdapterIdentity{}
	forged := adapter
	forged.identity = strings.Repeat("0", 64)
	forgeries = append(forgeries, forged)
	forged = adapter
	forged.kind = SourceAdapterKind("scm")
	forgeries = append(forgeries, forged)
	forged = adapter
	forged.name = "other-git"
	forgeries = append(forgeries, forged)
	forged = adapter
	forged.version = "1.2.4"
	forgeries = append(forgeries, forged)
	forged = adapter
	forged.majorVersion = 2
	forgeries = append(forgeries, forged)
	forged = adapter
	forged.capabilities = nil
	forgeries = append(forgeries, forged)
	forged = adapter
	forged.capabilities = []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadManifest}
	forgeries = append(forgeries, forged)
	forged = adapter
	forged.capabilities = []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent}
	forgeries = append(forgeries, forged)
	for _, forgedAdapter := range forgeries {
		request, err := NewRepositoryAcquisitionRequest(repository, revision, forgedAdapter, AcquisitionArtifactManifest, AcquisitionEffectReadOnly)
		if err == nil || request.Identity() != "" {
			t.Fatalf("NewRepositoryAcquisitionRequest() = (%#v, %v), want zero error result", request, err)
		}
	}
	if request, err := NewRepositoryAcquisitionRequest(repository, revision, SourceAdapterIdentity{}, AcquisitionArtifactManifest, AcquisitionEffectReadOnly); err == nil || request.Identity() != "" {
		t.Fatalf("NewRepositoryAcquisitionRequest(zero adapter) = (%#v, %v)", request, err)
	}
}

func TestRepositoryAcquisitionRequestDefensivelyCopiesRequirements(t *testing.T) {
	repository, revision, adapter := mustAcquisitionAuthorities(t, RevisionAlgorithmSHA1, []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent})
	request := mustAcquisitionRequest(t, repository, revision, adapter, AcquisitionArtifactManifestAndContent)
	identity := request.Identity()
	capabilities := request.RequiredCapabilities()
	capabilities[0] = SourceCapabilityReadDiff
	if request.Identity() != identity || !reflect.DeepEqual(request.RequiredCapabilities(), []SourceAdapterCapability{SourceCapabilityReadContent, SourceCapabilityReadManifest}) {
		t.Fatal("capability mutation changed RepositoryAcquisitionRequest")
	}
}

func TestRepositoryAcquisitionRequestBindsSHA1AndSHA256Revisions(t *testing.T) {
	repository := mustAcquisitionRepository(t)
	adapter := mustAcquisitionAdapter(t, []SourceAdapterCapability{SourceCapabilityReadManifest})
	sha1Request := mustAcquisitionRequest(t, repository, mustAcquisitionRevision(t, RevisionAlgorithmSHA1), adapter, AcquisitionArtifactManifest)
	sha256Request := mustAcquisitionRequest(t, repository, mustAcquisitionRevision(t, RevisionAlgorithmSHA256), adapter, AcquisitionArtifactManifest)
	if sha1Request.Identity() == sha256Request.Identity() || sha1Request.Artifact() != sha256Request.Artifact() || sha1Request.Effect() != sha256Request.Effect() {
		t.Fatalf("revision requests = (%#v, %#v)", sha1Request, sha256Request)
	}
}

func TestRepositoryAcquisitionRequestZeroValueIsEmpty(t *testing.T) {
	var request RepositoryAcquisitionRequest
	if request.Identity() != "" || request.RepositoryIdentity() != "" || request.RevisionIdentity() != "" || request.SourceAdapterIdentity() != "" || request.Artifact() != "" || request.Effect() != "" || len(request.RequiredCapabilities()) != 0 {
		t.Fatalf("zero RepositoryAcquisitionRequest = %#v", request)
	}
}

func mustAcquisitionAuthorities(t *testing.T, algorithm RevisionAlgorithm, capabilities []SourceAdapterCapability) (RepositoryIdentity, RevisionIdentity, SourceAdapterIdentity) {
	t.Helper()
	return mustAcquisitionRepository(t), mustAcquisitionRevision(t, algorithm), mustAcquisitionAdapter(t, capabilities)
}

func mustAcquisitionRepository(t *testing.T) RepositoryIdentity {
	t.Helper()
	repository, err := NewRepositoryIdentity("git.example.com", []string{"team"}, "repo")
	if err != nil {
		t.Fatalf("NewRepositoryIdentity() error = %v", err)
	}
	return repository
}

func mustAcquisitionRevision(t *testing.T, algorithm RevisionAlgorithm) RevisionIdentity {
	t.Helper()
	digest := "0123456789abcdef0123456789abcdef01234567"
	if algorithm == RevisionAlgorithmSHA256 {
		digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	}
	revision, err := NewRevisionIdentity(RevisionKindGitCommit, algorithm, digest)
	if err != nil {
		t.Fatalf("NewRevisionIdentity() error = %v", err)
	}
	return revision
}

func mustAcquisitionAdapter(t *testing.T, capabilities []SourceAdapterCapability) SourceAdapterIdentity {
	t.Helper()
	adapter, err := NewSourceAdapterIdentity(SourceAdapterKindGit, "local-git", "1.2.3", capabilities)
	if err != nil {
		t.Fatalf("NewSourceAdapterIdentity() error = %v", err)
	}
	return adapter
}

func mustAcquisitionRequest(t *testing.T, repository RepositoryIdentity, revision RevisionIdentity, adapter SourceAdapterIdentity, artifact RepositoryAcquisitionArtifact) RepositoryAcquisitionRequest {
	t.Helper()
	request, err := NewRepositoryAcquisitionRequest(repository, revision, adapter, artifact, AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionRequest() error = %v", err)
	}
	return request
}

func repositoryAcquisitionRequestsEqual(first, second RepositoryAcquisitionRequest) bool {
	return first.identity == second.identity && first.repositoryIdentity == second.repositoryIdentity && first.revisionIdentity == second.revisionIdentity && first.sourceAdapterIdentity == second.sourceAdapterIdentity && first.artifact == second.artifact && first.effect == second.effect && reflect.DeepEqual(first.requiredCapabilities, second.requiredCapabilities)
}
