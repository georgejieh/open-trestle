package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Bounds exact-content digest work to 64 MiB per supplied side.
const maxRepositoryFileDeltaExecutionDigestBytes = 64 << 20

// RepositoryFileDeltaContent distinguishes an absent side from an existing empty file.
type RepositoryFileDeltaContent struct {
	Present bool
	Content []byte
}

// RepositoryFileDeltaExecutionStatus identifies one terminal delta result.
type RepositoryFileDeltaExecutionStatus string

const (
	// RepositoryFileDeltaExecutionStatusSupported identifies generated file evidence.
	RepositoryFileDeltaExecutionStatusSupported RepositoryFileDeltaExecutionStatus = "supported"
	// RepositoryFileDeltaExecutionStatusUnsupported identifies an explicit unsupported result.
	RepositoryFileDeltaExecutionStatusUnsupported RepositoryFileDeltaExecutionStatus = "unsupported"
)

// RepositoryFileDeltaUnsupportedReason identifies why file evidence is absent.
type RepositoryFileDeltaUnsupportedReason string

const (
	// RepositoryFileDeltaUnsupportedReasonNone identifies a supported result.
	RepositoryFileDeltaUnsupportedReasonNone RepositoryFileDeltaUnsupportedReason = "none"
	// RepositoryFileDeltaUnsupportedReasonAddedFile identifies path addition.
	RepositoryFileDeltaUnsupportedReasonAddedFile RepositoryFileDeltaUnsupportedReason = "added_file"
	// RepositoryFileDeltaUnsupportedReasonRemovedFile identifies path removal.
	RepositoryFileDeltaUnsupportedReasonRemovedFile RepositoryFileDeltaUnsupportedReason = "removed_file"
	// RepositoryFileDeltaUnsupportedReasonContent identifies unsupported bytes.
	RepositoryFileDeltaUnsupportedReasonContent RepositoryFileDeltaUnsupportedReason = "unsupported_content"
	// RepositoryFileDeltaUnsupportedReasonResourceLimit identifies bounded generation refusal.
	RepositoryFileDeltaUnsupportedReasonResourceLimit RepositoryFileDeltaUnsupportedReason = "resource_limit"
)

// RepositoryFileDeltaExecution records one opaque compact content-processing result.
type RepositoryFileDeltaExecution struct {
	identity                    string
	path                        string
	repositoryFileDeltaIdentity string
	status                      RepositoryFileDeltaExecutionStatus
	reason                      RepositoryFileDeltaUnsupportedReason
	fileChange                  FileChange
	lineMap                     LineMap
}

// ExecuteRepositoryFileDelta consumes explicit sides and returns no source bytes.
func ExecuteRepositoryFileDelta(entry RepositoryFileDelta, base, head RepositoryFileDeltaContent) (RepositoryFileDeltaExecution, error) {
	canonicalEntry, err := canonicalRepositoryFileDeltaExecutionEntry(entry)
	if err != nil {
		return RepositoryFileDeltaExecution{}, err
	}
	baseFile, hasBaseFile := canonicalEntry.BaseFile()
	headFile, hasHeadFile := canonicalEntry.HeadFile()
	if !base.Present && len(base.Content) != 0 || !head.Present && len(head.Content) != 0 || base.Present != hasBaseFile || head.Present != hasHeadFile {
		return RepositoryFileDeltaExecution{}, fmt.Errorf("repository file delta content shape does not match entry")
	}
	if (hasBaseFile && len(base.Content) != baseFile.SizeBytes()) || (hasHeadFile && len(head.Content) != headFile.SizeBytes()) {
		return RepositoryFileDeltaExecution{}, fmt.Errorf("repository file delta content size does not match entry")
	}
	if (hasBaseFile && len(base.Content) > maxRepositoryFileDeltaExecutionDigestBytes) || (hasHeadFile && len(head.Content) > maxRepositoryFileDeltaExecutionDigestBytes) {
		return RepositoryFileDeltaExecution{}, UnifiedDiffGenerationResourceLimit
	}
	if hasBaseFile {
		actual, err := NewRepositoryFile(canonicalEntry.Path(), base.Content)
		if err != nil || actual != baseFile {
			return RepositoryFileDeltaExecution{}, fmt.Errorf("base content does not match repository file delta")
		}
	}
	if hasHeadFile {
		actual, err := NewRepositoryFile(canonicalEntry.Path(), head.Content)
		if err != nil || actual != headFile {
			return RepositoryFileDeltaExecution{}, fmt.Errorf("head content does not match repository file delta")
		}
	}
	if (hasBaseFile && len(base.Content) > maxUnifiedDiffContentBytes) || (hasHeadFile && len(head.Content) > maxUnifiedDiffContentBytes) {
		return newRepositoryFileDeltaExecution(canonicalEntry, RepositoryFileDeltaExecutionStatusUnsupported, RepositoryFileDeltaUnsupportedReasonResourceLimit, FileChange{}, LineMap{})
	}
	switch canonicalEntry.Kind() {
	case RepositoryFileDeltaAdded:
		return newRepositoryFileDeltaExecution(canonicalEntry, RepositoryFileDeltaExecutionStatusUnsupported, RepositoryFileDeltaUnsupportedReasonAddedFile, FileChange{}, LineMap{})
	case RepositoryFileDeltaRemoved:
		return newRepositoryFileDeltaExecution(canonicalEntry, RepositoryFileDeltaExecutionStatusUnsupported, RepositoryFileDeltaUnsupportedReasonRemovedFile, FileChange{}, LineMap{})
	case RepositoryFileDeltaModified:
		return executeModifiedRepositoryFileDelta(canonicalEntry, base.Content, head.Content)
	default:
		return RepositoryFileDeltaExecution{}, fmt.Errorf("unsupported repository file delta kind %q", canonicalEntry.Kind())
	}
}

func executeModifiedRepositoryFileDelta(entry RepositoryFileDelta, baseContent, headContent []byte) (RepositoryFileDeltaExecution, error) {
	patch, err := GenerateUnifiedFileDiff(entry.Path(), baseContent, headContent)
	if err != nil {
		reason := RepositoryFileDeltaUnsupportedReasonNone
		switch {
		case errors.Is(err, UnifiedDiffGenerationUnsupportedContent):
			reason = RepositoryFileDeltaUnsupportedReasonContent
		case errors.Is(err, UnifiedDiffGenerationResourceLimit):
			reason = RepositoryFileDeltaUnsupportedReasonResourceLimit
		default:
			return RepositoryFileDeltaExecution{}, fmt.Errorf("generate repository file delta: %w", err)
		}
		return newRepositoryFileDeltaExecution(entry, RepositoryFileDeltaExecutionStatusUnsupported, reason, FileChange{}, LineMap{})
	}
	fileChange, lineMap, err := ParseUnifiedFileDiff(entry.Path(), baseContent, headContent, patch)
	patch = nil
	if err != nil {
		return RepositoryFileDeltaExecution{}, err
	}
	return newRepositoryFileDeltaExecution(entry, RepositoryFileDeltaExecutionStatusSupported, RepositoryFileDeltaUnsupportedReasonNone, fileChange, lineMap)
}

func canonicalRepositoryFileDeltaExecutionEntry(entry RepositoryFileDelta) (RepositoryFileDelta, error) {
	base, _ := entry.BaseFile()
	head, _ := entry.HeadFile()
	canonical, err := newRepositoryFileDelta(entry.Kind(), base, head)
	if err != nil || canonical != entry {
		return RepositoryFileDelta{}, fmt.Errorf("repository file delta is not canonical")
	}
	return canonical, nil
}

func newRepositoryFileDeltaExecution(entry RepositoryFileDelta, status RepositoryFileDeltaExecutionStatus, reason RepositoryFileDeltaUnsupportedReason, fileChange FileChange, lineMap LineMap) (RepositoryFileDeltaExecution, error) {
	canonicalEntry, err := canonicalRepositoryFileDeltaExecutionEntry(entry)
	if err != nil {
		return RepositoryFileDeltaExecution{}, err
	}
	if status == RepositoryFileDeltaExecutionStatusSupported {
		baseFile, hasBase := canonicalEntry.BaseFile()
		headFile, hasHead := canonicalEntry.HeadFile()
		if reason != RepositoryFileDeltaUnsupportedReasonNone || canonicalEntry.Kind() != RepositoryFileDeltaModified || !hasBase || !hasHead || fileChange.Identity() == "" || lineMap.Identity() == "" || fileChange.Path() != canonicalEntry.Path() || fileChange.BaseDigest() != baseFile.Digest() || fileChange.HeadDigest() != headFile.Digest() || lineMap.FileChangeIdentity() != fileChange.Identity() || lineMap.Path() != canonicalEntry.Path() {
			return RepositoryFileDeltaExecution{}, fmt.Errorf("supported repository file delta execution is invalid")
		}
	} else if status == RepositoryFileDeltaExecutionStatusUnsupported {
		if !validRepositoryFileDeltaUnsupportedReason(canonicalEntry.Kind(), reason) || fileChange.Identity() != "" || lineMap.Identity() != "" {
			return RepositoryFileDeltaExecution{}, fmt.Errorf("unsupported repository file delta execution is invalid")
		}
	} else {
		return RepositoryFileDeltaExecution{}, fmt.Errorf("invalid repository file delta execution status %q", status)
	}
	preimage := struct {
		Contract                    string                               `json:"contract"`
		SchemaVersion               int                                  `json:"schema_version"`
		Path                        string                               `json:"path"`
		RepositoryFileDeltaIdentity string                               `json:"repository_file_delta_identity"`
		Status                      RepositoryFileDeltaExecutionStatus   `json:"status"`
		Reason                      RepositoryFileDeltaUnsupportedReason `json:"reason"`
		FileChangeIdentity          string                               `json:"file_change_identity"`
		LineMapIdentity             string                               `json:"line_map_identity"`
	}{
		Contract: "open-trestle/repository-file-delta-execution", SchemaVersion: 1,
		Path: canonicalEntry.Path(), RepositoryFileDeltaIdentity: canonicalEntry.Identity(),
		Status: status, Reason: reason, FileChangeIdentity: fileChange.Identity(), LineMapIdentity: lineMap.Identity(),
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RepositoryFileDeltaExecution{}, err
	}
	digest := sha256.Sum256(encoded)
	return RepositoryFileDeltaExecution{
		identity: hex.EncodeToString(digest[:]), path: canonicalEntry.Path(), repositoryFileDeltaIdentity: canonicalEntry.Identity(),
		status: status, reason: reason, fileChange: fileChange, lineMap: lineMap,
	}, nil
}

func validRepositoryFileDeltaUnsupportedReason(kind RepositoryFileDeltaKind, reason RepositoryFileDeltaUnsupportedReason) bool {
	if reason == RepositoryFileDeltaUnsupportedReasonResourceLimit {
		return kind == RepositoryFileDeltaAdded || kind == RepositoryFileDeltaModified || kind == RepositoryFileDeltaRemoved
	}
	switch kind {
	case RepositoryFileDeltaAdded:
		return reason == RepositoryFileDeltaUnsupportedReasonAddedFile
	case RepositoryFileDeltaRemoved:
		return reason == RepositoryFileDeltaUnsupportedReasonRemovedFile
	case RepositoryFileDeltaModified:
		return reason == RepositoryFileDeltaUnsupportedReasonContent || reason == RepositoryFileDeltaUnsupportedReasonResourceLimit
	default:
		return false
	}
}

// Identity returns the versioned canonical SHA-256 identity.
func (e RepositoryFileDeltaExecution) Identity() string { return e.identity }

// Path returns the exact workspace-relative path.
func (e RepositoryFileDeltaExecution) Path() string { return e.path }

// RepositoryFileDeltaIdentity returns the processed delta-entry identity.
func (e RepositoryFileDeltaExecution) RepositoryFileDeltaIdentity() string {
	return e.repositoryFileDeltaIdentity
}

// Status returns the terminal supported or unsupported state.
func (e RepositoryFileDeltaExecution) Status() RepositoryFileDeltaExecutionStatus { return e.status }

// Reason returns the unsupported reason or none for supported evidence.
func (e RepositoryFileDeltaExecution) Reason() RepositoryFileDeltaUnsupportedReason { return e.reason }

// FileChange returns generated modified-file evidence, if supported.
func (e RepositoryFileDeltaExecution) FileChange() FileChange { return cloneFileChange(e.fileChange) }

// LineMap returns generated line evidence, if supported.
func (e RepositoryFileDeltaExecution) LineMap() LineMap { return cloneLineMap(e.lineMap) }
