package scm

import (
	"context"
	"fmt"
	"reflect"
	"slices"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// Bound candidate content before canonical receipt hashing.
const maxSourceAdapterResultContentBytes = 256 << 20

// ExecuteRepositoryAcquisition invokes one adapter and constructs its canonical receipt.
func ExecuteRepositoryAcquisition(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter SourceAdapter) (evidence.RepositoryAcquisitionReceipt, error) {
	if isNilInterface(ctx) {
		return evidence.RepositoryAcquisitionReceipt{}, fmt.Errorf("repository acquisition context is nil")
	}
	if isNilInterface(adapter) {
		return evidence.RepositoryAcquisitionReceipt{}, fmt.Errorf("source adapter is nil")
	}
	if err := evidence.ValidateRepositoryAcquisitionRequest(request); err != nil {
		return evidence.RepositoryAcquisitionReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return evidence.RepositoryAcquisitionReceipt{}, err
	}
	reportedIdentity := adapter.Identity()
	canonicalIdentity, err := evidence.NewSourceAdapterIdentity(reportedIdentity.Kind(), reportedIdentity.Name(), reportedIdentity.Version(), reportedIdentity.Capabilities())
	if err != nil || !sourceAdapterIdentityValuesEqual(reportedIdentity, canonicalIdentity) || canonicalIdentity.Identity() != request.SourceAdapterIdentity() {
		return evidence.RepositoryAcquisitionReceipt{}, fmt.Errorf("source adapter identity does not match repository acquisition request")
	}
	if err := ctx.Err(); err != nil {
		return evidence.RepositoryAcquisitionReceipt{}, err
	}
	result := adapter.Acquire(ctx, request)
	if err := ctx.Err(); err != nil {
		return evidence.RepositoryAcquisitionReceipt{}, err
	}
	result, err = snapshotSourceAdapterResult(request, result)
	if err != nil {
		return evidence.RepositoryAcquisitionReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return evidence.RepositoryAcquisitionReceipt{}, err
	}
	receipt, err := evidence.NewRepositoryAcquisitionReceipt(request, result.Outcome, result.Reason, result.Manifest, result.Contents)
	if err != nil {
		return evidence.RepositoryAcquisitionReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return evidence.RepositoryAcquisitionReceipt{}, err
	}
	return receipt, nil
}

func snapshotSourceAdapterResult(request evidence.RepositoryAcquisitionRequest, result SourceAdapterResult) (SourceAdapterResult, error) {
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
		content, exists := result.Contents[file.Path()]
		if !exists || len(content) != file.SizeBytes() {
			return SourceAdapterResult{}, fmt.Errorf("source adapter result content size does not match path %q", file.Path())
		}
		var err error
		totalSizeBytes, err = checkedSourceAdapterResultContentAdd(totalSizeBytes, len(content))
		if err != nil {
			return SourceAdapterResult{}, err
		}
		contents[file.Path()] = append([]byte{}, content...)
	}
	result.Contents = contents
	return result, nil
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
