package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	// Caps cumulative per-entry generation work within one execution.
	maxLocalGitChangeEntries = 64
	// Allows one retained result map beside one binding-bounded acquisition.
	maxLocalGitChangeRetainedBytes = 2 * maxLocalGitBindingRetainedContentBytes
)

// LocalGitChangeExecutionError identifies a bounded batch failure.
type LocalGitChangeExecutionError string

// LocalGitChangeExecutionResourceLimit identifies an over-bound delta batch.
const LocalGitChangeExecutionResourceLimit LocalGitChangeExecutionError = "resource_limit"

// Error returns the stable batch failure category.
func (e LocalGitChangeExecutionError) Error() string { return string(e) }

// LocalGitChangeExecution binds one acquisition pair to opaque per-entry executions.
type LocalGitChangeExecution struct {
	identity        string
	acquisitionPair LocalGitAcquisitionPair
	hasChange       bool
	change          evidence.Change
	entryExecutions []evidence.RepositoryFileDeltaExecution
}

type localGitChangeEndpoint func(context.Context, evidence.RepositoryAcquisitionRequest, *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, map[string][]byte, error)

type localGitFileDeltaExecutor func(evidence.RepositoryFileDelta, evidence.RepositoryFileDeltaContent, evidence.RepositoryFileDeltaContent) (evidence.RepositoryFileDeltaExecution, error)

// ExecuteLocalGitChange builds compact accounted change evidence from two acquisitions.
func ExecuteLocalGitChange(ctx context.Context, baseRequest, headRequest evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitChangeExecution, error) {
	return executeLocalGitChange(ctx, baseRequest, headRequest, adapter, executeLocalGitAcquisitionEnvelopeWithOwnedContent, evidence.ExecuteRepositoryFileDelta)
}

func executeLocalGitChangeWithEndpoint(ctx context.Context, baseRequest, headRequest evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter, endpoint localGitChangeEndpoint) (LocalGitChangeExecution, error) {
	return executeLocalGitChange(ctx, baseRequest, headRequest, adapter, endpoint, evidence.ExecuteRepositoryFileDelta)
}

func executeLocalGitChange(ctx context.Context, baseRequest, headRequest evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter, endpoint localGitChangeEndpoint, fileExecutor localGitFileDeltaExecutor) (LocalGitChangeExecution, error) {
	if err := validateLocalGitAcquisitionPairInputs(ctx, baseRequest, headRequest, adapter); err != nil {
		return LocalGitChangeExecution{}, err
	}
	if endpoint == nil || fileExecutor == nil {
		return LocalGitChangeExecution{}, fmt.Errorf("local Git change executor is nil")
	}
	baseEnvelope, baseManifest, baseContents, err := endpoint(ctx, baseRequest, adapter)
	if err != nil {
		return LocalGitChangeExecution{}, err
	}
	defer clearLocalGitChangeContents(baseContents)
	if err := ctx.Err(); err != nil {
		return LocalGitChangeExecution{}, err
	}
	headEnvelope, headManifest := baseEnvelope, baseManifest
	var headContents map[string][]byte
	if baseRequest.Identity() != headRequest.Identity() {
		headEnvelope, headManifest, headContents, err = endpoint(ctx, headRequest, adapter)
		if err != nil {
			return LocalGitChangeExecution{}, err
		}
		defer clearLocalGitChangeContents(headContents)
	}
	if err := ctx.Err(); err != nil {
		return LocalGitChangeExecution{}, err
	}
	if baseManifest.TotalSizeBytes() > maxLocalGitChangeRetainedBytes-headManifest.TotalSizeBytes() {
		return LocalGitChangeExecution{}, LocalGitChangeExecutionResourceLimit
	}
	delta, err := evidence.NewRepositoryManifestDelta(baseManifest, headManifest)
	if err != nil {
		return LocalGitChangeExecution{}, err
	}
	pair, err := newLocalGitAcquisitionPair(baseEnvelope, headEnvelope, delta)
	if err != nil {
		return LocalGitChangeExecution{}, err
	}
	if delta.ChangedFileCount() > maxLocalGitChangeEntries {
		return LocalGitChangeExecution{}, LocalGitChangeExecutionResourceLimit
	}
	execution, err := buildLocalGitChangeExecution(ctx, pair, baseContents, headContents, fileExecutor)
	if err != nil {
		return LocalGitChangeExecution{}, err
	}
	if err := ctx.Err(); err != nil {
		return LocalGitChangeExecution{}, err
	}
	return execution, nil
}

func executeLocalGitAcquisitionEnvelopeWithOwnedContent(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, map[string][]byte, error) {
	runtime, err := executeRepositoryAcquisitionWithRetention(ctx, request, adapter, repositoryAcquisitionRetainBindingInputs)
	if err != nil {
		return LocalGitAcquisitionEnvelope{}, evidence.RepositoryManifest{}, nil, err
	}
	defer clearRepositoryAcquisitionRuntimeResult(&runtime)
	envelope, err := buildLocalGitAcquisitionEnvelope(ctx, request, runtime)
	if err != nil {
		return LocalGitAcquisitionEnvelope{}, evidence.RepositoryManifest{}, nil, err
	}
	manifest, err := evidence.NewRepositoryManifest(runtime.result.Manifest.Files())
	if err != nil || manifest.Identity() != envelope.EvidenceBinding().ManifestIdentity() {
		return LocalGitAcquisitionEnvelope{}, evidence.RepositoryManifest{}, nil, fmt.Errorf("local Git acquisition content does not match envelope")
	}
	contents := runtime.result.Contents
	runtime.result.Contents = nil
	return envelope, manifest, contents, nil
}

func buildLocalGitChangeExecution(ctx context.Context, pair LocalGitAcquisitionPair, baseContents, headContents map[string][]byte, fileExecutor localGitFileDeltaExecutor) (LocalGitChangeExecution, error) {
	entries := pair.ManifestDelta().Entries()
	pruneLocalGitChangeContents(entries, baseContents, headContents)
	entryExecutions := make([]evidence.RepositoryFileDeltaExecution, 0, len(entries))
	fileChanges := make([]evidence.FileChange, 0, len(entries))
	lineMaps := make([]evidence.LineMap, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return LocalGitChangeExecution{}, err
		}
		baseContent, hasBaseContent := takeLocalGitChangeContent(baseContents, entry.Path())
		headContent, hasHeadContent := takeLocalGitChangeContent(headContents, entry.Path())
		entryExecution, err := fileExecutor(
			entry,
			evidence.RepositoryFileDeltaContent{Present: hasBaseContent, Content: baseContent},
			evidence.RepositoryFileDeltaContent{Present: hasHeadContent, Content: headContent},
		)
		baseContent = nil
		headContent = nil
		if err != nil {
			return LocalGitChangeExecution{}, err
		}
		entryExecutions = append(entryExecutions, entryExecution)
		if entryExecution.Status() == evidence.RepositoryFileDeltaExecutionStatusSupported {
			fileChanges = append(fileChanges, entryExecution.FileChange())
			lineMaps = append(lineMaps, entryExecution.LineMap())
		}
	}
	if len(baseContents) != 0 || len(headContents) != 0 {
		return LocalGitChangeExecution{}, fmt.Errorf("local Git change content was not completely consumed")
	}
	var change evidence.Change
	hasChange := len(fileChanges) > 0
	if hasChange {
		var err error
		change, err = evidence.NewChange(fileChanges, lineMaps)
		if err != nil {
			return LocalGitChangeExecution{}, err
		}
	}
	return newLocalGitChangeExecution(pair, change, hasChange, entryExecutions)
}

func pruneLocalGitChangeContents(entries []evidence.RepositoryFileDelta, baseContents, headContents map[string][]byte) {
	basePaths := make(map[string]struct{}, len(entries))
	headPaths := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if _, ok := entry.BaseFile(); ok {
			basePaths[entry.Path()] = struct{}{}
		}
		if _, ok := entry.HeadFile(); ok {
			headPaths[entry.Path()] = struct{}{}
		}
	}
	for path := range baseContents {
		if _, keep := basePaths[path]; !keep {
			baseContents[path] = nil
			delete(baseContents, path)
		}
	}
	for path := range headContents {
		if _, keep := headPaths[path]; !keep {
			headContents[path] = nil
			delete(headContents, path)
		}
	}
}

func takeLocalGitChangeContent(contents map[string][]byte, path string) ([]byte, bool) {
	content, ok := contents[path]
	if ok {
		delete(contents, path)
	}
	return content, ok
}

func clearLocalGitChangeContents(contents map[string][]byte) {
	for path := range contents {
		contents[path] = nil
		delete(contents, path)
	}
}

func newLocalGitChangeExecution(pair LocalGitAcquisitionPair, change evidence.Change, hasChange bool, entryExecutions []evidence.RepositoryFileDeltaExecution) (LocalGitChangeExecution, error) {
	canonicalPair, err := newLocalGitAcquisitionPair(pair.BaseEnvelope(), pair.HeadEnvelope(), pair.ManifestDelta())
	if err != nil || canonicalPair.Identity() != pair.Identity() {
		return LocalGitChangeExecution{}, fmt.Errorf("local Git acquisition pair is not canonical")
	}
	changeIdentity := ""
	if hasChange {
		canonicalChange, err := evidence.NewChange(change.FileChanges(), change.LineMaps())
		if err != nil || canonicalChange.Identity() != change.Identity() {
			return LocalGitChangeExecution{}, fmt.Errorf("change is not canonical")
		}
		changeIdentity = change.Identity()
	} else if change.Identity() != "" {
		return LocalGitChangeExecution{}, fmt.Errorf("absent change must be zero")
	}
	entries := pair.ManifestDelta().Entries()
	if len(entryExecutions) != len(entries) {
		return LocalGitChangeExecution{}, fmt.Errorf("entry executions do not account for every delta entry")
	}
	type entryWire struct {
		Path     string `json:"path"`
		Identity string `json:"identity"`
	}
	preimage := struct {
		Contract                string      `json:"contract"`
		SchemaVersion           int         `json:"schema_version"`
		AcquisitionPairIdentity string      `json:"acquisition_pair_identity"`
		ChangePresent           bool        `json:"change_present"`
		ChangeIdentity          string      `json:"change_identity"`
		EntryExecutions         []entryWire `json:"entry_executions"`
	}{
		Contract: "open-trestle/local-git-change-execution", SchemaVersion: 1,
		AcquisitionPairIdentity: pair.Identity(), ChangePresent: hasChange, ChangeIdentity: changeIdentity,
		EntryExecutions: make([]entryWire, len(entryExecutions)),
	}
	supportedCount := 0
	for i, entryExecution := range entryExecutions {
		if entryExecution.Identity() == "" || entryExecution.Path() != entries[i].Path() || entryExecution.RepositoryFileDeltaIdentity() != entries[i].Identity() {
			return LocalGitChangeExecution{}, fmt.Errorf("entry execution %d does not match delta", i)
		}
		if entryExecution.Status() == evidence.RepositoryFileDeltaExecutionStatusSupported {
			if !hasChange {
				return LocalGitChangeExecution{}, fmt.Errorf("supported entry execution %d requires a change", i)
			}
			fileChange, ok := change.FileChangeForPath(entryExecution.Path())
			if !ok || fileChange.Identity() != entryExecution.FileChange().Identity() {
				return LocalGitChangeExecution{}, fmt.Errorf("entry execution %d does not match file change", i)
			}
			lineMap, ok := change.LineMapForPath(entryExecution.Path())
			if !ok || lineMap.Identity() != entryExecution.LineMap().Identity() {
				return LocalGitChangeExecution{}, fmt.Errorf("entry execution %d does not match line map", i)
			}
			supportedCount++
		} else {
			if entryExecution.FileChange().Identity() != "" || entryExecution.LineMap().Identity() != "" {
				return LocalGitChangeExecution{}, fmt.Errorf("unsupported entry execution %d includes evidence", i)
			}
			if hasChange {
				if _, exists := change.FileChangeForPath(entryExecution.Path()); exists {
					return LocalGitChangeExecution{}, fmt.Errorf("unsupported entry execution %d appears in change", i)
				}
			}
		}
		preimage.EntryExecutions[i] = entryWire{Path: entryExecution.Path(), Identity: entryExecution.Identity()}
	}
	if hasChange && supportedCount != len(change.FileChanges()) {
		return LocalGitChangeExecution{}, fmt.Errorf("supported entry executions do not cover change")
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return LocalGitChangeExecution{}, err
	}
	digest := sha256.Sum256(encoded)
	return LocalGitChangeExecution{
		identity: hex.EncodeToString(digest[:]), acquisitionPair: pair, hasChange: hasChange,
		change: change, entryExecutions: append([]evidence.RepositoryFileDeltaExecution(nil), entryExecutions...),
	}, nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (e LocalGitChangeExecution) Identity() string { return e.identity }

// AcquisitionPair returns the exact ordered local Git acquisitions.
func (e LocalGitChangeExecution) AcquisitionPair() LocalGitAcquisitionPair {
	return e.acquisitionPair
}

// HasChange reports whether at least one entry produced supported evidence.
func (e LocalGitChangeExecution) HasChange() bool { return e.hasChange }

// Change returns the compact supported-file aggregate, if present.
func (e LocalGitChangeExecution) Change() evidence.Change { return e.change }

// EntryExecutions returns one opaque result for every manifest-delta entry.
func (e LocalGitChangeExecution) EntryExecutions() []evidence.RepositoryFileDeltaExecution {
	return append([]evidence.RepositoryFileDeltaExecution(nil), e.entryExecutions...)
}
