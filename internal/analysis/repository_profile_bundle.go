package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// RepositoryProfileBundle binds consistent inventory and classification authorities.
type RepositoryProfileBundle struct {
	identity                      string
	manifestIdentity              string
	repositoryProfileIdentity     string
	classificationReceiptIdentity string
	classificationSummaryIdentity string
	classifierVersion             string
}

// NewRepositoryProfileBundle validates and binds a repository authority chain.
func NewRepositoryProfileBundle(manifest evidence.RepositoryManifest, profile RepositoryProfile, classification RepositoryClassificationReceipt, summary RepositoryClassificationSummary) (RepositoryProfileBundle, error) {
	canonicalManifest, err := evidence.NewRepositoryManifest(manifest.Files())
	if err != nil || canonicalManifest.Identity() != manifest.Identity() {
		return RepositoryProfileBundle{}, fmt.Errorf("repository manifest is not canonical")
	}
	canonicalProfile, err := NewRepositoryProfile(canonicalManifest)
	if err != nil || !repositoryProfilesEqual(profile, canonicalProfile) {
		return RepositoryProfileBundle{}, fmt.Errorf("repository profile does not match manifest")
	}
	if classification.ManifestIdentity() != canonicalManifest.Identity() {
		return RepositoryProfileBundle{}, fmt.Errorf("classification receipt does not match manifest")
	}
	if classification.ClassifierVersion() != fileClassificationVersion {
		return RepositoryProfileBundle{}, fmt.Errorf("unsupported classifier version %q", classification.ClassifierVersion())
	}
	canonicalSummary, err := NewRepositoryClassificationSummary(canonicalManifest, classification)
	if err != nil {
		return RepositoryProfileBundle{}, fmt.Errorf("validate classification receipt: %w", err)
	}
	if summary != canonicalSummary {
		return RepositoryProfileBundle{}, fmt.Errorf("classification summary does not match receipt")
	}
	if summary.ManifestIdentity() != canonicalManifest.Identity() || summary.ReceiptIdentity() != classification.Identity() || summary.ClassifierVersion() != fileClassificationVersion || summary.FileCount() != canonicalManifest.FileCount() {
		return RepositoryProfileBundle{}, fmt.Errorf("classification authority chain is inconsistent")
	}
	preimage := struct {
		Contract                      string `json:"contract"`
		SchemaVersion                 int    `json:"schema_version"`
		ManifestIdentity              string `json:"manifest_identity"`
		RepositoryProfileIdentity     string `json:"repository_profile_identity"`
		ClassificationReceiptIdentity string `json:"classification_receipt_identity"`
		ClassificationSummaryIdentity string `json:"classification_summary_identity"`
		Classifier                    string `json:"classifier"`
		ClassifierVersion             string `json:"classifier_version"`
	}{
		Contract:                      "open-trestle/repository-profile-bundle",
		SchemaVersion:                 1,
		ManifestIdentity:              canonicalManifest.Identity(),
		RepositoryProfileIdentity:     canonicalProfile.Identity(),
		ClassificationReceiptIdentity: classification.Identity(),
		ClassificationSummaryIdentity: canonicalSummary.Identity(),
		Classifier:                    fileClassificationName,
		ClassifierVersion:             fileClassificationVersion,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RepositoryProfileBundle{}, fmt.Errorf("encode repository profile bundle identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return RepositoryProfileBundle{
		identity:                      hex.EncodeToString(digest[:]),
		manifestIdentity:              canonicalManifest.Identity(),
		repositoryProfileIdentity:     canonicalProfile.Identity(),
		classificationReceiptIdentity: classification.Identity(),
		classificationSummaryIdentity: canonicalSummary.Identity(),
		classifierVersion:             fileClassificationVersion,
	}, nil
}

func repositoryProfilesEqual(first, second RepositoryProfile) bool {
	if (first.extensionFacts == nil) != (second.extensionFacts == nil) {
		return false
	}
	if first.identity != second.identity || first.manifestIdentity != second.manifestIdentity || first.fileCount != second.fileCount || first.totalSizeBytes != second.totalSizeBytes || len(first.extensionFacts) != len(second.extensionFacts) {
		return false
	}
	for i := range first.extensionFacts {
		if first.extensionFacts[i] != second.extensionFacts[i] {
			return false
		}
	}
	return true
}

// Identity returns the versioned canonical SHA-256 identity.
func (b RepositoryProfileBundle) Identity() string {
	return b.identity
}

// ManifestIdentity returns the exact source manifest identity.
func (b RepositoryProfileBundle) ManifestIdentity() string {
	return b.manifestIdentity
}

// RepositoryProfileIdentity returns the exact inventory profile identity.
func (b RepositoryProfileBundle) RepositoryProfileIdentity() string {
	return b.repositoryProfileIdentity
}

// ClassificationReceiptIdentity returns the exact classification receipt identity.
func (b RepositoryProfileBundle) ClassificationReceiptIdentity() string {
	return b.classificationReceiptIdentity
}

// ClassificationSummaryIdentity returns the exact classification summary identity.
func (b RepositoryProfileBundle) ClassificationSummaryIdentity() string {
	return b.classificationSummaryIdentity
}

// ClassifierVersion returns the identity-bound classifier version.
func (b RepositoryProfileBundle) ClassifierVersion() string {
	return b.classifierVersion
}
