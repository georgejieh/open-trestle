package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// Bound candidate content before canonical receipt hashing.
const maxSourceAdapterResultContentBytes = 256 << 20

// RepositoryAcquisitionExecution preserves one runtime-owned receipt and validated reported evidence.
type RepositoryAcquisitionExecution struct {
	identity               string
	receipt                evidence.RepositoryAcquisitionReceipt
	requestIdentity        string
	sourceAdapterIdentity  string
	outcome                evidence.RepositoryAcquisitionOutcome
	hasLocalGitEvidence    bool
	revisionIdentity       string
	manifestIdentity       string
	gitCommitIdentity      string
	gitTreeGraphIdentity   string
	correspondenceIdentity string
}

type localGitExecutionEvidence struct {
	repositoryIdentity     string
	revisionIdentity       string
	manifest               evidence.RepositoryManifest
	gitCommitIdentity      string
	gitTreeGraphIdentity   string
	correspondenceIdentity string
	fileCount              int
	totalContentBytes      int64
	binding                string
}

// Identity returns the versioned canonical SHA-256 identity.
func (e RepositoryAcquisitionExecution) Identity() string { return e.identity }

// Receipt returns the exact runtime-owned acquisition receipt.
func (e RepositoryAcquisitionExecution) Receipt() evidence.RepositoryAcquisitionReceipt {
	return e.receipt
}

// ReceiptIdentity returns the canonical receipt identity.
func (e RepositoryAcquisitionExecution) ReceiptIdentity() string { return e.receipt.Identity() }

// RequestIdentity returns the exact acquisition request identity.
func (e RepositoryAcquisitionExecution) RequestIdentity() string { return e.requestIdentity }

// SourceAdapterIdentity returns the exact requested adapter identity.
func (e RepositoryAcquisitionExecution) SourceAdapterIdentity() string {
	return e.sourceAdapterIdentity
}

// Outcome returns the terminal acquisition state.
func (e RepositoryAcquisitionExecution) Outcome() evidence.RepositoryAcquisitionOutcome {
	return e.outcome
}

// HasLocalGitEvidence reports whether validated local Git evidence was preserved.
func (e RepositoryAcquisitionExecution) HasLocalGitEvidence() bool { return e.hasLocalGitEvidence }

// RevisionIdentity returns the preserved local Git revision identity, if present.
func (e RepositoryAcquisitionExecution) RevisionIdentity() string { return e.revisionIdentity }

// ManifestIdentity returns the preserved local Git manifest identity, if present.
func (e RepositoryAcquisitionExecution) ManifestIdentity() string { return e.manifestIdentity }

// GitCommitIdentity returns the preserved verified commit identity, if present.
func (e RepositoryAcquisitionExecution) GitCommitIdentity() string { return e.gitCommitIdentity }

// GitTreeGraphIdentity returns the preserved verified tree-graph identity, if present.
func (e RepositoryAcquisitionExecution) GitTreeGraphIdentity() string { return e.gitTreeGraphIdentity }

// CorrespondenceIdentity returns the preserved graph-to-manifest identity, if present.
func (e RepositoryAcquisitionExecution) CorrespondenceIdentity() string {
	return e.correspondenceIdentity
}

// ExecuteRepositoryAcquisition invokes one adapter and returns its canonical receipt.
func ExecuteRepositoryAcquisition(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter SourceAdapter) (evidence.RepositoryAcquisitionReceipt, error) {
	execution, err := ExecuteRepositoryAcquisitionWithEvidence(ctx, request, adapter)
	if err != nil {
		return evidence.RepositoryAcquisitionReceipt{}, err
	}
	return execution.Receipt(), nil
}

// ExecuteRepositoryAcquisitionWithEvidence invokes one adapter and preserves validated reported evidence.
func ExecuteRepositoryAcquisitionWithEvidence(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter SourceAdapter) (RepositoryAcquisitionExecution, error) {
	if isNilInterface(ctx) {
		return RepositoryAcquisitionExecution{}, fmt.Errorf("repository acquisition context is nil")
	}
	if isNilInterface(adapter) {
		return RepositoryAcquisitionExecution{}, fmt.Errorf("source adapter is nil")
	}
	if err := evidence.ValidateRepositoryAcquisitionRequest(request); err != nil {
		return RepositoryAcquisitionExecution{}, err
	}
	if err := ctx.Err(); err != nil {
		return RepositoryAcquisitionExecution{}, err
	}
	reportedIdentity := adapter.Identity()
	canonicalIdentity, err := evidence.NewSourceAdapterIdentity(reportedIdentity.Kind(), reportedIdentity.Name(), reportedIdentity.Version(), reportedIdentity.Capabilities())
	if err != nil || !sourceAdapterIdentityValuesEqual(reportedIdentity, canonicalIdentity) || canonicalIdentity.Identity() != request.SourceAdapterIdentity() {
		return RepositoryAcquisitionExecution{}, fmt.Errorf("source adapter identity does not match repository acquisition request")
	}
	if err := ctx.Err(); err != nil {
		return RepositoryAcquisitionExecution{}, err
	}
	var result SourceAdapterResult
	var localGitEvidence localGitExecutionEvidence
	var hasLocalGitEvidence bool
	if localAdapter, ok := adapter.(*LocalGitSourceAdapter); ok {
		result, localGitEvidence, hasLocalGitEvidence = localAdapter.acquireWithLocalGitEvidence(ctx, request)
	} else {
		result = adapter.Acquire(ctx, request)
	}
	if err := ctx.Err(); err != nil {
		return RepositoryAcquisitionExecution{}, err
	}
	result, err = snapshotSourceAdapterResult(ctx, request, result)
	if err != nil {
		return RepositoryAcquisitionExecution{}, err
	}
	if err := ctx.Err(); err != nil {
		return RepositoryAcquisitionExecution{}, err
	}
	receipt, err := evidence.NewRepositoryAcquisitionReceipt(request, result.Outcome, result.Reason, result.Manifest, result.Contents)
	if err != nil {
		return RepositoryAcquisitionExecution{}, err
	}
	if err := ctx.Err(); err != nil {
		return RepositoryAcquisitionExecution{}, err
	}
	localGitEvidence, hasLocalGitEvidence, err = snapshotLocalGitExecutionEvidence(ctx, request, adapter, result, receipt, localGitEvidence, hasLocalGitEvidence)
	if err != nil {
		return RepositoryAcquisitionExecution{}, err
	}
	if err := ctx.Err(); err != nil {
		return RepositoryAcquisitionExecution{}, err
	}
	execution, err := newRepositoryAcquisitionExecution(request, receipt, localGitEvidence, hasLocalGitEvidence)
	if err != nil {
		return RepositoryAcquisitionExecution{}, err
	}
	if err := ctx.Err(); err != nil {
		return RepositoryAcquisitionExecution{}, err
	}
	return execution, nil
}

func newLocalGitExecutionEvidence(local LocalGitRevisionResult) (localGitExecutionEvidence, error) {
	execution := localGitExecutionEvidence{
		repositoryIdentity:     local.RepositoryIdentity(),
		revisionIdentity:       local.RevisionIdentity(),
		manifest:               local.Manifest(),
		gitCommitIdentity:      local.GitCommitIdentity(),
		gitTreeGraphIdentity:   local.GitTreeGraphIdentity(),
		correspondenceIdentity: local.CorrespondenceIdentity(),
		fileCount:              local.FileCount(),
		totalContentBytes:      local.TotalContentBytes(),
	}
	binding, err := localGitExecutionEvidenceBinding(execution)
	if err != nil {
		return localGitExecutionEvidence{}, err
	}
	execution.binding = binding
	return execution, nil
}

// localGitExecutionEvidenceBinding is an internal consistency identity, not provenance.
func localGitExecutionEvidenceBinding(local localGitExecutionEvidence) (string, error) {
	preimage := struct {
		Contract               string `json:"contract"`
		SchemaVersion          int    `json:"schema_version"`
		RepositoryIdentity     string `json:"repository_identity"`
		RevisionIdentity       string `json:"revision_identity"`
		ManifestIdentity       string `json:"manifest_identity"`
		GitCommitIdentity      string `json:"git_commit_identity"`
		GitTreeGraphIdentity   string `json:"git_tree_graph_identity"`
		CorrespondenceIdentity string `json:"correspondence_identity"`
		FileCount              int    `json:"file_count"`
		TotalContentBytes      int64  `json:"total_content_bytes"`
	}{
		Contract:               "open-trestle/local-git-execution-evidence-binding",
		SchemaVersion:          1,
		RepositoryIdentity:     local.repositoryIdentity,
		RevisionIdentity:       local.revisionIdentity,
		ManifestIdentity:       local.manifest.Identity(),
		GitCommitIdentity:      local.gitCommitIdentity,
		GitTreeGraphIdentity:   local.gitTreeGraphIdentity,
		CorrespondenceIdentity: local.correspondenceIdentity,
		FileCount:              local.fileCount,
		TotalContentBytes:      local.totalContentBytes,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return "", fmt.Errorf("encode local Git execution evidence binding: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func snapshotLocalGitExecutionEvidence(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter SourceAdapter, result SourceAdapterResult, receipt evidence.RepositoryAcquisitionReceipt, local localGitExecutionEvidence, hasLocalGitEvidence bool) (localGitExecutionEvidence, bool, error) {
	localAdapter, isLocalAdapter := adapter.(*LocalGitSourceAdapter)
	if !hasLocalGitEvidence {
		if isLocalAdapter && result.Outcome == evidence.AcquisitionOutcomeAcquired {
			return localGitExecutionEvidence{}, false, fmt.Errorf("acquired local Git result is missing execution evidence")
		}
		return localGitExecutionEvidence{}, false, nil
	}
	if result.Outcome != evidence.AcquisitionOutcomeAcquired {
		return localGitExecutionEvidence{}, false, fmt.Errorf("non-acquired result must not include local Git evidence")
	}
	if !isLocalAdapter || !isCanonicalLocalGitSourceAdapterIdentity(localAdapter.Identity()) || localAdapter.Identity().Identity() != request.SourceAdapterIdentity() {
		return localGitExecutionEvidence{}, false, fmt.Errorf("local Git evidence requires the requested concrete local Git adapter")
	}
	binding, err := localGitExecutionEvidenceBinding(local)
	if err != nil || binding != local.binding {
		return localGitExecutionEvidence{}, false, fmt.Errorf("local Git evidence binding does not match its result")
	}
	if err := validateLocalGitExecutionEvidence(ctx, request, result, receipt, local); err != nil {
		return localGitExecutionEvidence{}, false, err
	}
	return local, true, nil
}

func validateLocalGitExecutionEvidence(ctx context.Context, request evidence.RepositoryAcquisitionRequest, result SourceAdapterResult, receipt evidence.RepositoryAcquisitionReceipt, local localGitExecutionEvidence) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if result.Outcome != evidence.AcquisitionOutcomeAcquired || result.Reason != evidence.AcquisitionReasonNone || receipt.Outcome() != evidence.AcquisitionOutcomeAcquired || receipt.Reason() != evidence.AcquisitionReasonNone {
		return fmt.Errorf("local Git evidence requires an acquired result")
	}
	if local.repositoryIdentity != request.RepositoryIdentity() || local.revisionIdentity != request.RevisionIdentity() {
		return fmt.Errorf("local Git evidence does not match the acquisition request")
	}
	if !validExecutionIdentity(local.revisionIdentity) || !validExecutionIdentity(local.gitCommitIdentity) || !validExecutionIdentity(local.gitTreeGraphIdentity) || !validExecutionIdentity(local.correspondenceIdentity) {
		return fmt.Errorf("local Git evidence contains an invalid identity")
	}
	canonicalManifest, err := evidence.NewRepositoryManifest(local.manifest.Files())
	if err != nil || !repositoryAcquisitionManifestsEqual(local.manifest, canonicalManifest) {
		return fmt.Errorf("local Git evidence manifest is not canonical")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !repositoryAcquisitionManifestsEqual(local.manifest, result.Manifest) || receipt.ManifestIdentity() != local.manifest.Identity() {
		return fmt.Errorf("local Git evidence manifest does not match the acquired result")
	}
	if receipt.RequestIdentity() != request.Identity() || receipt.RepositoryIdentity() != request.RepositoryIdentity() || receipt.RevisionIdentity() != request.RevisionIdentity() || receipt.SourceAdapterIdentity() != request.SourceAdapterIdentity() {
		return fmt.Errorf("local Git evidence receipt does not match the acquisition request")
	}
	if local.fileCount != local.manifest.FileCount() || local.totalContentBytes != local.manifest.TotalSizeBytes() || local.totalContentBytes < 0 || local.totalContentBytes > maxSourceAdapterResultContentBytes {
		return fmt.Errorf("local Git evidence content summary does not match its manifest")
	}
	switch request.Artifact() {
	case evidence.AcquisitionArtifactManifest:
		if result.Contents != nil || receipt.ContentCoverage() != evidence.ContentCoverageNotRequested {
			return fmt.Errorf("local Git manifest execution must not include content")
		}
	case evidence.AcquisitionArtifactManifestAndContent:
		if receipt.ContentCoverage() != evidence.ContentCoverageComplete {
			return fmt.Errorf("local Git content execution is incomplete")
		}
	default:
		return fmt.Errorf("unsupported repository acquisition artifact %q", request.Artifact())
	}
	return ctx.Err()
}

func newRepositoryAcquisitionExecution(request evidence.RepositoryAcquisitionRequest, receipt evidence.RepositoryAcquisitionReceipt, local localGitExecutionEvidence, hasLocalGitEvidence bool) (RepositoryAcquisitionExecution, error) {
	if receipt.Identity() == "" || receipt.RequestIdentity() != request.Identity() || receipt.SourceAdapterIdentity() != request.SourceAdapterIdentity() {
		return RepositoryAcquisitionExecution{}, fmt.Errorf("repository acquisition receipt does not match its execution")
	}
	execution := RepositoryAcquisitionExecution{
		receipt:               receipt,
		requestIdentity:       request.Identity(),
		sourceAdapterIdentity: request.SourceAdapterIdentity(),
		outcome:               receipt.Outcome(),
		hasLocalGitEvidence:   hasLocalGitEvidence,
	}
	if hasLocalGitEvidence {
		execution.revisionIdentity = local.revisionIdentity
		execution.manifestIdentity = local.manifest.Identity()
		execution.gitCommitIdentity = local.gitCommitIdentity
		execution.gitTreeGraphIdentity = local.gitTreeGraphIdentity
		execution.correspondenceIdentity = local.correspondenceIdentity
	}
	preimage := struct {
		Contract                string                                `json:"contract"`
		SchemaVersion           int                                   `json:"schema_version"`
		RequestIdentity         string                                `json:"request_identity"`
		ReceiptIdentity         string                                `json:"receipt_identity"`
		SourceAdapterIdentity   string                                `json:"source_adapter_identity"`
		Outcome                 evidence.RepositoryAcquisitionOutcome `json:"outcome"`
		LocalGitEvidencePresent bool                                  `json:"local_git_evidence_present"`
		RevisionIdentity        string                                `json:"revision_identity"`
		ManifestIdentity        string                                `json:"manifest_identity"`
		GitCommitIdentity       string                                `json:"git_commit_identity"`
		GitTreeGraphIdentity    string                                `json:"git_tree_graph_identity"`
		CorrespondenceIdentity  string                                `json:"correspondence_identity"`
	}{
		Contract:                "open-trestle/repository-acquisition-execution",
		SchemaVersion:           1,
		RequestIdentity:         execution.requestIdentity,
		ReceiptIdentity:         receipt.Identity(),
		SourceAdapterIdentity:   execution.sourceAdapterIdentity,
		Outcome:                 execution.outcome,
		LocalGitEvidencePresent: execution.hasLocalGitEvidence,
		RevisionIdentity:        execution.revisionIdentity,
		ManifestIdentity:        execution.manifestIdentity,
		GitCommitIdentity:       execution.gitCommitIdentity,
		GitTreeGraphIdentity:    execution.gitTreeGraphIdentity,
		CorrespondenceIdentity:  execution.correspondenceIdentity,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RepositoryAcquisitionExecution{}, fmt.Errorf("encode repository acquisition execution identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	execution.identity = hex.EncodeToString(digest[:])
	return execution, nil
}

func isCanonicalLocalGitSourceAdapterIdentity(identity evidence.SourceAdapterIdentity) bool {
	if identity.Kind() != evidence.SourceAdapterKindGit || identity.Name() != localGitSourceAdapterName || identity.Version() != localGitSourceAdapterVersion {
		return false
	}
	return slices.Equal(identity.Capabilities(), []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadContent, evidence.SourceCapabilityReadManifest})
}

func validExecutionIdentity(identity string) bool {
	if len(identity) != sha256.Size*2 || identity != strings.ToLower(identity) {
		return false
	}
	_, err := hex.DecodeString(identity)
	return err == nil
}

func repositoryAcquisitionManifestsEqual(first, second evidence.RepositoryManifest) bool {
	return first.Identity() == second.Identity() && first.TotalSizeBytes() == second.TotalSizeBytes() && slices.Equal(first.Files(), second.Files())
}

func snapshotSourceAdapterResult(ctx context.Context, request evidence.RepositoryAcquisitionRequest, result SourceAdapterResult) (SourceAdapterResult, error) {
	if err := ctx.Err(); err != nil {
		return SourceAdapterResult{}, err
	}
	if result.Outcome != evidence.AcquisitionOutcomeAcquired || request.Artifact() == evidence.AcquisitionArtifactManifest {
		if len(result.Contents) != 0 {
			return SourceAdapterResult{}, fmt.Errorf("source adapter result must not include content")
		}
		result.Contents = nil
		return result, nil
	}
	if request.Artifact() != evidence.AcquisitionArtifactManifestAndContent {
		return SourceAdapterResult{}, fmt.Errorf("unsupported repository acquisition artifact %q", request.Artifact())
	}
	if len(result.Contents) != result.Manifest.FileCount() {
		return SourceAdapterResult{}, fmt.Errorf("source adapter result has %d content entries, want %d", len(result.Contents), result.Manifest.FileCount())
	}
	var totalSizeBytes int64
	contents := make(map[string][]byte, len(result.Contents))
	for _, file := range result.Manifest.Files() {
		if err := ctx.Err(); err != nil {
			return SourceAdapterResult{}, err
		}
		content, exists := result.Contents[file.Path()]
		if !exists || len(content) != file.SizeBytes() {
			return SourceAdapterResult{}, fmt.Errorf("source adapter result content size does not match path %q", file.Path())
		}
		var err error
		totalSizeBytes, err = checkedSourceAdapterResultContentAdd(totalSizeBytes, len(content))
		if err != nil {
			return SourceAdapterResult{}, err
		}
		contents[file.Path()], err = cloneSourceAdapterResultContent(ctx, content)
		if err != nil {
			return SourceAdapterResult{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return SourceAdapterResult{}, err
	}
	result.Contents = contents
	return result, nil
}

func cloneSourceAdapterResultContent(ctx context.Context, content []byte) ([]byte, error) {
	const chunkBytes = 1 << 20
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cloned := make([]byte, len(content))
	for offset := 0; offset < len(content); offset += chunkBytes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := offset + chunkBytes
		if end > len(content) {
			end = len(content)
		}
		copy(cloned[offset:end], content[offset:end])
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return cloned, nil
}

func checkedSourceAdapterResultContentAdd(total int64, size int) (int64, error) {
	if total < 0 || size < 0 || total > maxSourceAdapterResultContentBytes || int64(size) > maxSourceAdapterResultContentBytes-total {
		return total, fmt.Errorf("source adapter result content exceeds %d bytes", maxSourceAdapterResultContentBytes)
	}
	return total + int64(size), nil
}

func sourceAdapterIdentityValuesEqual(first, second evidence.SourceAdapterIdentity) bool {
	return first.Identity() == second.Identity() && first.Kind() == second.Kind() && first.Name() == second.Name() && first.Version() == second.Version() && first.MajorVersion() == second.MajorVersion() && slices.Equal(first.Capabilities(), second.Capabilities())
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	candidate := reflect.ValueOf(value)
	switch candidate.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return candidate.IsNil()
	default:
		return false
	}
}
