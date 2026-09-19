package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// RepositoryAcquisitionSnapshotExecution retains exact validated content for artifact persistence.
type RepositoryAcquisitionSnapshotExecution struct {
	identity  string
	execution RepositoryAcquisitionExecution
	manifest  evidence.RepositoryManifest
	contents  map[string][]byte
}

// ExecuteRepositoryAcquisitionSnapshot executes a complete-content request and retains an immutable result.
func ExecuteRepositoryAcquisitionSnapshot(
	ctx context.Context,
	request evidence.RepositoryAcquisitionRequest,
	adapter SourceAdapter,
) (RepositoryAcquisitionSnapshotExecution, error) {
	if isNilInterface(ctx) {
		return RepositoryAcquisitionSnapshotExecution{}, fmt.Errorf("repository acquisition context is nil")
	}
	if isNilInterface(adapter) {
		return RepositoryAcquisitionSnapshotExecution{}, fmt.Errorf("source adapter is nil")
	}
	if err := evidence.ValidateRepositoryAcquisitionRequest(request); err != nil {
		return RepositoryAcquisitionSnapshotExecution{}, err
	}
	if request.Artifact() != evidence.AcquisitionArtifactManifestAndContent {
		return RepositoryAcquisitionSnapshotExecution{}, fmt.Errorf("repository snapshot requires manifest and content acquisition")
	}
	if err := ctx.Err(); err != nil {
		return RepositoryAcquisitionSnapshotExecution{}, err
	}
	runtime, err := executeRepositoryAcquisitionWithRetention(
		ctx,
		request,
		adapter,
		repositoryAcquisitionRetainResult,
	)
	if err != nil {
		return RepositoryAcquisitionSnapshotExecution{}, err
	}
	if err := ctx.Err(); err != nil {
		return RepositoryAcquisitionSnapshotExecution{}, err
	}
	snapshot := RepositoryAcquisitionSnapshotExecution{execution: runtime.execution}
	if runtime.execution.Outcome() == evidence.AcquisitionOutcomeAcquired {
		snapshot.manifest = runtime.result.Manifest
		snapshot.contents = runtime.result.Contents
	}
	snapshot.identity = deriveRepositoryAcquisitionSnapshotIdentity(snapshot)
	if err := snapshot.Validate(); err != nil {
		clearContentsMap(snapshot.contents)
		return RepositoryAcquisitionSnapshotExecution{}, err
	}
	return snapshot, nil
}

// Identity returns the canonical execution identity.
func (s RepositoryAcquisitionSnapshotExecution) Identity() string { return s.identity }

// Execution returns the runtime-owned acquisition receipt and lineage.
func (s RepositoryAcquisitionSnapshotExecution) Execution() RepositoryAcquisitionExecution {
	return s.execution
}

// Manifest returns the acquired canonical manifest, or a zero value for a non-acquired result.
func (s RepositoryAcquisitionSnapshotExecution) Manifest() evidence.RepositoryManifest {
	return s.manifest
}

// Contents returns a defensive copy of exact acquired file content.
func (s RepositoryAcquisitionSnapshotExecution) Contents() map[string][]byte {
	if s.contents == nil {
		return nil
	}
	result := make(map[string][]byte, len(s.contents))
	for path, content := range s.contents {
		result[path] = append([]byte(nil), content...)
	}
	return result
}

// Validate verifies receipt, manifest, content, and identity correspondence.
func (s RepositoryAcquisitionSnapshotExecution) Validate() error {
	if s.execution.Identity() == "" || s.execution.ReceiptIdentity() == "" ||
		s.execution.Receipt().Outcome() != s.execution.Outcome() {
		return fmt.Errorf("invalid repository acquisition snapshot execution")
	}
	if s.execution.Outcome() != evidence.AcquisitionOutcomeAcquired {
		if s.manifest.Identity() != "" || s.contents != nil {
			return fmt.Errorf("non-acquired snapshot contains repository content")
		}
	} else if err := validateSnapshotContents(s.execution, s.manifest, s.contents); err != nil {
		return err
	}
	if s.identity != deriveRepositoryAcquisitionSnapshotIdentity(s) {
		return fmt.Errorf("invalid repository acquisition snapshot identity")
	}
	return nil
}

func validateSnapshotContents(
	execution RepositoryAcquisitionExecution,
	manifest evidence.RepositoryManifest,
	contents map[string][]byte,
) error {
	canonical, err := evidence.NewRepositoryManifest(manifest.Files())
	if err != nil || canonical.Identity() != manifest.Identity() ||
		execution.Receipt().ManifestIdentity() != manifest.Identity() ||
		execution.Receipt().ContentCoverage() != evidence.ContentCoverageComplete ||
		contents == nil || len(contents) != manifest.FileCount() {
		return fmt.Errorf("repository acquisition snapshot manifest mismatch")
	}
	var total int64
	for _, expected := range manifest.Files() {
		content, exists := contents[expected.Path()]
		if !exists {
			return fmt.Errorf("repository acquisition snapshot content missing")
		}
		actual, err := evidence.NewRepositoryFile(expected.Path(), content)
		if err != nil || actual.Identity() != expected.Identity() ||
			actual.Digest() != expected.Digest() || actual.SizeBytes() != expected.SizeBytes() {
			return fmt.Errorf("repository acquisition snapshot content mismatch")
		}
		var addErr error
		total, addErr = checkedSourceAdapterResultContentAdd(total, len(content))
		if addErr != nil {
			return addErr
		}
	}
	if total != manifest.TotalSizeBytes() {
		return fmt.Errorf("repository acquisition snapshot content total mismatch")
	}
	return nil
}

func deriveRepositoryAcquisitionSnapshotIdentity(snapshot RepositoryAcquisitionSnapshotExecution) string {
	manifestIdentity := ""
	if snapshot.execution.Outcome() == evidence.AcquisitionOutcomeAcquired {
		manifestIdentity = snapshot.manifest.Identity()
	}
	encoded, err := json.Marshal(struct {
		Contract          string `json:"contract"`
		SchemaVersion     int    `json:"schema_version"`
		ExecutionIdentity string `json:"execution_identity"`
		Outcome           string `json:"outcome"`
		ManifestIdentity  string `json:"manifest_identity"`
	}{
		Contract: "open-trestle/repository-acquisition-snapshot-execution", SchemaVersion: 1,
		ExecutionIdentity: snapshot.execution.Identity(), Outcome: string(snapshot.execution.Outcome()),
		ManifestIdentity: manifestIdentity,
	})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func clearContentsMap(contents map[string][]byte) {
	for _, content := range contents {
		clear(content)
	}
}

func (s RepositoryAcquisitionSnapshotExecution) String() string {
	return "repository acquisition snapshot execution"
}
func (s RepositoryAcquisitionSnapshotExecution) GoString() string {
	return "scm.RepositoryAcquisitionSnapshotExecution{<redacted>}"
}
func (s RepositoryAcquisitionSnapshotExecution) Format(state fmt.State, verb rune) {
	formatted := "repository acquisition snapshot execution"
	if verb == 'q' {
		formatted = `"repository acquisition snapshot execution"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "scm.RepositoryAcquisitionSnapshotExecution{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}
