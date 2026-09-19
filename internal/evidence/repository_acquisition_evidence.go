package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// RepositoryAcquisitionEvidenceStatus identifies the structural binding result.
type RepositoryAcquisitionEvidenceStatus string

// RepositoryAcquisitionEvidenceStatusSupplied identifies structural agreement only.
const RepositoryAcquisitionEvidenceStatusSupplied RepositoryAcquisitionEvidenceStatus = "supplied_evidence_bound"

// Bound receipt hashing to the supplied Git object graph byte budget.
const maxRepositoryAcquisitionEvidenceContentBytes = maxGitTreeGraphTotalObjectBytes

// RepositoryAcquisitionEvidenceBinding records agreement between supplied acquisition and Git evidence.
type RepositoryAcquisitionEvidenceBinding struct {
	identity               string
	requestIdentity        string
	receiptIdentity        string
	repositoryIdentity     string
	revisionIdentity       string
	sourceAdapterIdentity  string
	manifestIdentity       string
	gitCommitIdentity      string
	gitTreeGraphIdentity   string
	correspondenceIdentity string
	bindingStatus          RepositoryAcquisitionEvidenceStatus
}

// BindRepositoryAcquisitionEvidence structurally binds supplied evidence without attesting its origin.
func BindRepositoryAcquisitionEvidence(request RepositoryAcquisitionRequest, receipt RepositoryAcquisitionReceipt, receiptContents map[string][]byte, revision RevisionIdentity, commitVerification GitCommitObjectVerification, commitContent []byte, commit GitCommit, rootTreeVerification GitTreeObjectVerification, rootTreeContent []byte, rootTree GitTree, childTreeContents map[string][]byte, blobContents map[string][]byte, graph GitTreeGraph, manifest RepositoryManifest, correspondence GitManifestCorrespondence) (RepositoryAcquisitionEvidenceBinding, error) {
	canonicalRequest, err := canonicalRepositoryAcquisitionRequest(request)
	if err != nil {
		return RepositoryAcquisitionEvidenceBinding{}, err
	}
	if canonicalRequest.Artifact() != AcquisitionArtifactManifestAndContent || canonicalRequest.Effect() != AcquisitionEffectReadOnly {
		return RepositoryAcquisitionEvidenceBinding{}, fmt.Errorf("repository acquisition request is not eligible for evidence binding")
	}
	canonicalRevision, err := NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	if err != nil || revision != canonicalRevision || canonicalRequest.revision != canonicalRevision {
		return RepositoryAcquisitionEvidenceBinding{}, fmt.Errorf("revision identity does not match repository acquisition request")
	}
	canonicalManifest, err := validateRepositoryAcquisitionEvidenceReceipt(canonicalRequest, receipt, manifest, receiptContents)
	if err != nil {
		return RepositoryAcquisitionEvidenceBinding{}, err
	}
	canonicalReceipt, err := NewRepositoryAcquisitionReceipt(canonicalRequest, AcquisitionOutcomeAcquired, AcquisitionReasonNone, canonicalManifest, receiptContents)
	if err != nil || receipt != canonicalReceipt {
		return RepositoryAcquisitionEvidenceBinding{}, fmt.Errorf("repository acquisition receipt is not the canonical complete acquired result")
	}
	canonicalCorrespondence, err := VerifyGitManifestCorrespondence(canonicalRevision, commitVerification, commitContent, commit, rootTreeVerification, rootTreeContent, rootTree, childTreeContents, blobContents, graph, canonicalManifest)
	if err != nil || correspondence != canonicalCorrespondence {
		return RepositoryAcquisitionEvidenceBinding{}, fmt.Errorf("git manifest correspondence does not match supplied evidence")
	}
	if canonicalReceipt.RequestIdentity() != canonicalRequest.Identity() || canonicalReceipt.RepositoryIdentity() != canonicalRequest.RepositoryIdentity() || canonicalReceipt.RevisionIdentity() != canonicalRevision.Identity() || canonicalReceipt.SourceAdapterIdentity() != canonicalRequest.SourceAdapterIdentity() || canonicalReceipt.ManifestIdentity() != canonicalManifest.Identity() || canonicalCorrespondence.RevisionIdentity() != canonicalRevision.Identity() || canonicalCorrespondence.RepositoryManifestIdentity() != canonicalManifest.Identity() {
		return RepositoryAcquisitionEvidenceBinding{}, fmt.Errorf("acquisition and Git evidence identities do not agree")
	}
	const status = RepositoryAcquisitionEvidenceStatusSupplied
	preimage := struct {
		Contract               string                              `json:"contract"`
		SchemaVersion          int                                 `json:"schema_version"`
		BindingStatus          RepositoryAcquisitionEvidenceStatus `json:"binding_status"`
		RequestIdentity        string                              `json:"request_identity"`
		ReceiptIdentity        string                              `json:"receipt_identity"`
		RepositoryIdentity     string                              `json:"repository_identity"`
		RevisionIdentity       string                              `json:"revision_identity"`
		SourceAdapterIdentity  string                              `json:"source_adapter_identity"`
		ManifestIdentity       string                              `json:"manifest_identity"`
		GitCommitIdentity      string                              `json:"git_commit_identity"`
		GitTreeGraphIdentity   string                              `json:"git_tree_graph_identity"`
		CorrespondenceIdentity string                              `json:"correspondence_identity"`
	}{
		Contract:               "open-trestle/repository-acquisition-evidence-binding",
		SchemaVersion:          1,
		BindingStatus:          status,
		RequestIdentity:        canonicalRequest.Identity(),
		ReceiptIdentity:        canonicalReceipt.Identity(),
		RepositoryIdentity:     canonicalRequest.RepositoryIdentity(),
		RevisionIdentity:       canonicalRevision.Identity(),
		SourceAdapterIdentity:  canonicalRequest.SourceAdapterIdentity(),
		ManifestIdentity:       canonicalManifest.Identity(),
		GitCommitIdentity:      canonicalCorrespondence.GitCommitIdentity(),
		GitTreeGraphIdentity:   canonicalCorrespondence.GitTreeGraphIdentity(),
		CorrespondenceIdentity: canonicalCorrespondence.Identity(),
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RepositoryAcquisitionEvidenceBinding{}, fmt.Errorf("encode repository acquisition evidence binding identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return RepositoryAcquisitionEvidenceBinding{
		identity:               hex.EncodeToString(digest[:]),
		requestIdentity:        preimage.RequestIdentity,
		receiptIdentity:        preimage.ReceiptIdentity,
		repositoryIdentity:     preimage.RepositoryIdentity,
		revisionIdentity:       preimage.RevisionIdentity,
		sourceAdapterIdentity:  preimage.SourceAdapterIdentity,
		manifestIdentity:       preimage.ManifestIdentity,
		gitCommitIdentity:      preimage.GitCommitIdentity,
		gitTreeGraphIdentity:   preimage.GitTreeGraphIdentity,
		correspondenceIdentity: preimage.CorrespondenceIdentity,
		bindingStatus:          status,
	}, nil
}

func validateRepositoryAcquisitionEvidenceReceipt(request RepositoryAcquisitionRequest, receipt RepositoryAcquisitionReceipt, manifest RepositoryManifest, contents map[string][]byte) (RepositoryManifest, error) {
	canonicalManifest, err := NewRepositoryManifest(manifest.Files())
	if err != nil || !repositoryManifestValuesEqual(manifest, canonicalManifest) {
		return RepositoryManifest{}, fmt.Errorf("repository manifest is not canonical")
	}
	if canonicalManifest.TotalSizeBytes() > maxRepositoryAcquisitionEvidenceContentBytes {
		return RepositoryManifest{}, fmt.Errorf("repository acquisition evidence content exceeds %d bytes", maxRepositoryAcquisitionEvidenceContentBytes)
	}
	if receipt.RequestIdentity() != request.Identity() || receipt.RepositoryIdentity() != request.RepositoryIdentity() || receipt.RevisionIdentity() != request.RevisionIdentity() || receipt.SourceAdapterIdentity() != request.SourceAdapterIdentity() || receipt.Artifact() != AcquisitionArtifactManifestAndContent || receipt.Effect() != AcquisitionEffectReadOnly || receipt.Outcome() != AcquisitionOutcomeAcquired || receipt.Reason() != AcquisitionReasonNone || !receipt.HasManifest() || receipt.ManifestIdentity() != canonicalManifest.Identity() || receipt.ContentCoverage() != ContentCoverageComplete {
		return RepositoryManifest{}, fmt.Errorf("repository acquisition receipt is not eligible for evidence binding")
	}
	files := canonicalManifest.Files()
	if len(contents) != len(files) {
		return RepositoryManifest{}, fmt.Errorf("repository acquisition evidence content has %d entries, want %d", len(contents), len(files))
	}
	var totalSizeBytes int64
	for _, file := range files {
		content, exists := contents[file.Path()]
		if !exists || len(content) != file.SizeBytes() {
			return RepositoryManifest{}, fmt.Errorf("repository acquisition evidence content size does not match path %q", file.Path())
		}
		totalSizeBytes, err = checkedRepositoryAcquisitionEvidenceContentAdd(totalSizeBytes, len(content))
		if err != nil {
			return RepositoryManifest{}, err
		}
	}
	if totalSizeBytes != canonicalManifest.TotalSizeBytes() {
		return RepositoryManifest{}, fmt.Errorf("repository acquisition evidence content total does not match manifest")
	}
	return canonicalManifest, nil
}

func checkedRepositoryAcquisitionEvidenceContentAdd(total int64, size int) (int64, error) {
	if total < 0 || size < 0 || total > maxRepositoryAcquisitionEvidenceContentBytes || int64(size) > maxRepositoryAcquisitionEvidenceContentBytes-total {
		return total, fmt.Errorf("repository acquisition evidence content exceeds %d bytes", maxRepositoryAcquisitionEvidenceContentBytes)
	}
	return total + int64(size), nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (b RepositoryAcquisitionEvidenceBinding) Identity() string {
	return b.identity
}

// RequestIdentity returns the exact bound acquisition request identity.
func (b RepositoryAcquisitionEvidenceBinding) RequestIdentity() string {
	return b.requestIdentity
}

// ReceiptIdentity returns the exact bound acquisition receipt identity.
func (b RepositoryAcquisitionEvidenceBinding) ReceiptIdentity() string {
	return b.receiptIdentity
}

// RepositoryIdentity returns the repository identity claimed by the request and receipt.
func (b RepositoryAcquisitionEvidenceBinding) RepositoryIdentity() string {
	return b.repositoryIdentity
}

// RevisionIdentity returns the exact revision identity shared by both evidence chains.
func (b RepositoryAcquisitionEvidenceBinding) RevisionIdentity() string {
	return b.revisionIdentity
}

// SourceAdapterIdentity returns the adapter identity claimed by the request and receipt.
func (b RepositoryAcquisitionEvidenceBinding) SourceAdapterIdentity() string {
	return b.sourceAdapterIdentity
}

// ManifestIdentity returns the exact manifest identity shared by both evidence chains.
func (b RepositoryAcquisitionEvidenceBinding) ManifestIdentity() string {
	return b.manifestIdentity
}

// GitCommitIdentity returns the exact verified Git commit identity.
func (b RepositoryAcquisitionEvidenceBinding) GitCommitIdentity() string {
	return b.gitCommitIdentity
}

// GitTreeGraphIdentity returns the exact verified Git tree graph identity.
func (b RepositoryAcquisitionEvidenceBinding) GitTreeGraphIdentity() string {
	return b.gitTreeGraphIdentity
}

// CorrespondenceIdentity returns the exact Git manifest correspondence identity.
func (b RepositoryAcquisitionEvidenceBinding) CorrespondenceIdentity() string {
	return b.correspondenceIdentity
}

// BindingStatus returns the bounded structural binding status.
func (b RepositoryAcquisitionEvidenceBinding) BindingStatus() RepositoryAcquisitionEvidenceStatus {
	return b.bindingStatus
}
