package evidence

import "testing"

func TestValidateRepositoryAcquisitionRequest(t *testing.T) {
	for _, algorithm := range []RevisionAlgorithm{RevisionAlgorithmSHA1, RevisionAlgorithmSHA256} {
		repository, revision, adapter := mustAcquisitionAuthorities(t, algorithm, []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent})
		request := mustAcquisitionRequest(t, repository, revision, adapter, AcquisitionArtifactManifestAndContent)
		if err := ValidateRepositoryAcquisitionRequest(request); err != nil {
			t.Fatalf("ValidateRepositoryAcquisitionRequest(%s) error = %v", algorithm, err)
		}
	}
}

func TestValidateRepositoryAcquisitionRequestRejectsForgedState(t *testing.T) {
	repository, revision, adapter := mustAcquisitionAuthorities(t, RevisionAlgorithmSHA1, []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent})
	base := mustAcquisitionRequest(t, repository, revision, adapter, AcquisitionArtifactManifestAndContent)
	forgeries := []RepositoryAcquisitionRequest{{}}
	forged := base
	forged.identity = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	forgeries = append(forgeries, forged)
	forged = base
	forged.repositoryIdentity = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	forgeries = append(forgeries, forged)
	forged = base
	forged.revisionIdentity = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	forgeries = append(forgeries, forged)
	forged = base
	forged.sourceAdapterIdentity = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	forgeries = append(forgeries, forged)
	forged = base
	forged.artifact = AcquisitionArtifactManifest
	forgeries = append(forgeries, forged)
	forged = base
	forged.effect = RepositoryAcquisitionEffect("write")
	forgeries = append(forgeries, forged)
	forged = base
	forged.requiredCapabilities = []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent}
	forgeries = append(forgeries, forged)
	forged = base
	forged.repository.name = "other"
	forgeries = append(forgeries, forged)
	forged = base
	forged.revision.digest = "1123456789abcdef0123456789abcdef01234567"
	forgeries = append(forgeries, forged)
	forged = base
	forged.adapter.version = "1.2.4"
	forgeries = append(forgeries, forged)
	for _, forgedRequest := range forgeries {
		if err := ValidateRepositoryAcquisitionRequest(forgedRequest); err == nil {
			t.Fatalf("ValidateRepositoryAcquisitionRequest(%#v) succeeded", forgedRequest)
		}
	}
}

func TestValidateRepositoryAcquisitionRequestDoesNotMutateInput(t *testing.T) {
	repository, revision, adapter := mustAcquisitionAuthorities(t, RevisionAlgorithmSHA1, []SourceAdapterCapability{SourceCapabilityReadManifest, SourceCapabilityReadContent})
	request := mustAcquisitionRequest(t, repository, revision, adapter, AcquisitionArtifactManifestAndContent)
	identity := request.Identity()
	requirements := request.RequiredCapabilities()
	if err := ValidateRepositoryAcquisitionRequest(request); err != nil {
		t.Fatalf("ValidateRepositoryAcquisitionRequest() error = %v", err)
	}
	if request.Identity() != identity || len(request.RequiredCapabilities()) != len(requirements) {
		t.Fatal("ValidateRepositoryAcquisitionRequest() mutated input")
	}
}
