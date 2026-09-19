package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

type localGitChangeStatus string

const (
	localGitChangeStatusComplete    localGitChangeStatus = "complete"
	localGitChangeStatusNoChange    localGitChangeStatus = "no_change"
	localGitChangeStatusPartial     localGitChangeStatus = "partial"
	localGitChangeStatusUnsupported localGitChangeStatus = "unsupported"
)

type localGitChangeOptions struct {
	objectsRoot string
}

type localGitChangeEntryResult struct {
	Path                        string `json:"path"`
	Kind                        string `json:"kind"`
	Status                      string `json:"status"`
	Reason                      string `json:"reason"`
	RepositoryFileDeltaIdentity string `json:"repository_file_delta_identity"`
	ExecutionIdentity           string `json:"execution_identity"`
	FileChangeIdentity          string `json:"file_change_identity"`
	LineMapIdentity             string `json:"line_map_identity"`
}

type localGitChangeResult struct {
	Contract                string                      `json:"contract"`
	SchemaVersion           int                         `json:"schema_version"`
	Status                  localGitChangeStatus        `json:"status"`
	ChangeExecutionIdentity string                      `json:"change_execution_identity"`
	AcquisitionPairIdentity string                      `json:"acquisition_pair_identity"`
	RepositoryIdentity      string                      `json:"repository_identity"`
	SourceAdapterIdentity   string                      `json:"source_adapter_identity"`
	BaseRevisionIdentity    string                      `json:"base_revision_identity"`
	HeadRevisionIdentity    string                      `json:"head_revision_identity"`
	BaseEnvelopeIdentity    string                      `json:"base_envelope_identity"`
	HeadEnvelopeIdentity    string                      `json:"head_envelope_identity"`
	ManifestDeltaIdentity   string                      `json:"manifest_delta_identity"`
	ChangePresent           bool                        `json:"change_present"`
	ChangeIdentity          string                      `json:"change_identity"`
	ChangedFileCount        int                         `json:"changed_file_count"`
	SupportedFileCount      int                         `json:"supported_file_count"`
	UnsupportedFileCount    int                         `json:"unsupported_file_count"`
	Entries                 []localGitChangeEntryResult `json:"entries"`
}

func runLocalGitChange(args []string, stdout, stderr io.Writer) int {
	return runLocalGitChangeWithOpener(args, stdout, stderr, openLocalGitRoot)
}

func runLocalGitChangeWithOpener(args []string, stdout, stderr io.Writer, opener localGitRootOpener) int {
	options, repository, baseRevision, headRevision, err := parseLocalGitChangeOptions(args)
	if err != nil {
		fmt.Fprintf(stderr, "local-git change: %v\n", err)
		writeLocalGitChangeUsage(stderr)
		return 2
	}
	handle, err := opener(options.objectsRoot)
	if err != nil {
		fmt.Fprintln(stderr, "open object root: unavailable")
		return 1
	}
	if handle.close == nil {
		if handle.root != nil {
			_ = handle.root.Close()
		}
		fmt.Fprintln(stderr, "open object root: invalid root handle")
		return 1
	}
	if handle.root == nil {
		closeErr := handle.close()
		fmt.Fprint(stderr, "open object root: invalid root handle")
		if closeErr != nil {
			fmt.Fprint(stderr, "; close object root: failed")
		}
		fmt.Fprintln(stderr)
		return 1
	}
	encoded, resultCode, changeErr := buildLocalGitChangeResult(handle.root, repository, baseRevision, headRevision)
	closeErr := handle.close()
	if changeErr != nil {
		fmt.Fprint(stderr, "change local Git: failed")
		if closeErr != nil {
			fmt.Fprint(stderr, "; close object root: failed")
		}
		fmt.Fprintln(stderr)
		return 1
	}
	if closeErr != nil {
		fmt.Fprintln(stderr, "close object root: failed")
		return 1
	}
	written, err := stdout.Write(encoded)
	if err == nil && written != len(encoded) {
		err = io.ErrShortWrite
	}
	if err != nil {
		fmt.Fprintln(stderr, "write result: failed")
		return 1
	}
	return resultCode
}

func parseLocalGitChangeOptions(args []string) (localGitChangeOptions, evidence.RepositoryIdentity, evidence.RevisionIdentity, evidence.RevisionIdentity, error) {
	if len(args) != 14 {
		return localGitChangeOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("exactly seven flag-value pairs are required")
	}
	values := make(map[string]string, 7)
	allowed := map[string]bool{
		"--objects-root": true, "--repository-authority": true, "--repository-namespace": true,
		"--repository-name": true, "--revision-algorithm": true,
		"--base-revision-digest": true, "--head-revision-digest": true,
	}
	for index := 0; index < len(args); index += 2 {
		name, value := args[index], args[index+1]
		if !allowed[name] {
			return localGitChangeOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("unknown flag")
		}
		if _, exists := values[name]; exists {
			return localGitChangeOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("duplicate flag")
		}
		if value == "" {
			return localGitChangeOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("flag %q requires a non-empty value", name)
		}
		values[name] = value
	}
	for name := range allowed {
		if _, exists := values[name]; !exists {
			return localGitChangeOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("missing flag %q", name)
		}
	}
	repository, err := evidence.NewRepositoryIdentity(values["--repository-authority"], strings.Split(values["--repository-namespace"], "/"), values["--repository-name"])
	if err != nil {
		return localGitChangeOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("repository identity is invalid")
	}
	algorithm := evidence.RevisionAlgorithm(values["--revision-algorithm"])
	baseRevision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, algorithm, values["--base-revision-digest"])
	if err != nil {
		return localGitChangeOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("base revision identity is invalid")
	}
	headRevision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, algorithm, values["--head-revision-digest"])
	if err != nil {
		return localGitChangeOptions{}, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("head revision identity is invalid")
	}
	return localGitChangeOptions{objectsRoot: values["--objects-root"]}, repository, baseRevision, headRevision, nil
}

func buildLocalGitChangeResult(root *os.Root, repository evidence.RepositoryIdentity, baseRevision, headRevision evidence.RevisionIdentity) ([]byte, int, error) {
	store, err := scm.NewLocalGitObjectStore(root, repository)
	if err != nil {
		return nil, 0, err
	}
	adapter, err := scm.NewLocalGitSourceAdapter(store)
	if err != nil {
		return nil, 0, err
	}
	baseRequest, err := evidence.NewRepositoryAcquisitionRequest(repository, baseRevision, adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		return nil, 0, err
	}
	headRequest, err := evidence.NewRepositoryAcquisitionRequest(repository, headRevision, adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		return nil, 0, err
	}
	execution, err := scm.ExecuteLocalGitChange(context.Background(), baseRequest, headRequest, adapter)
	if err != nil {
		return nil, 0, err
	}
	result, resultCode, err := newLocalGitChangeResult(execution)
	if err != nil {
		return nil, 0, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, 0, fmt.Errorf("encode local Git change result: %w", err)
	}
	return append(encoded, '\n'), resultCode, nil
}

func newLocalGitChangeResult(execution scm.LocalGitChangeExecution) (localGitChangeResult, int, error) {
	if execution.Identity() == "" {
		return localGitChangeResult{}, 0, fmt.Errorf("local Git change execution is required")
	}
	pair := execution.AcquisitionPair()
	baseBinding := pair.BaseEnvelope().EvidenceBinding()
	headBinding := pair.HeadEnvelope().EvidenceBinding()
	delta := pair.ManifestDelta()
	entryExecutions := execution.EntryExecutions()
	if pair.Identity() == "" || delta.Identity() == "" || len(entryExecutions) != delta.ChangedFileCount() || baseBinding.RepositoryIdentity() != headBinding.RepositoryIdentity() || baseBinding.SourceAdapterIdentity() != headBinding.SourceAdapterIdentity() || delta.BaseManifestIdentity() != baseBinding.ManifestIdentity() || delta.HeadManifestIdentity() != headBinding.ManifestIdentity() {
		return localGitChangeResult{}, 0, fmt.Errorf("local Git change execution identities do not agree")
	}
	entries := make([]localGitChangeEntryResult, len(entryExecutions))
	supported, unsupported := 0, 0
	for index, entryExecution := range entryExecutions {
		deltaEntry, ok := delta.Entry(entryExecution.Path())
		if !ok || entryExecution.Identity() == "" || entryExecution.RepositoryFileDeltaIdentity() != deltaEntry.Identity() {
			return localGitChangeResult{}, 0, fmt.Errorf("local Git change entry does not match manifest delta")
		}
		if entryExecution.Status() == evidence.RepositoryFileDeltaExecutionStatusSupported {
			if entryExecution.FileChange().Identity() == "" || entryExecution.LineMap().Identity() == "" {
				return localGitChangeResult{}, 0, fmt.Errorf("supported local Git change entry lacks evidence")
			}
			supported++
		} else if entryExecution.Status() == evidence.RepositoryFileDeltaExecutionStatusUnsupported {
			if entryExecution.FileChange().Identity() != "" || entryExecution.LineMap().Identity() != "" {
				return localGitChangeResult{}, 0, fmt.Errorf("unsupported local Git change entry includes evidence")
			}
			unsupported++
		} else {
			return localGitChangeResult{}, 0, fmt.Errorf("local Git change entry has invalid status")
		}
		entries[index] = localGitChangeEntryResult{
			Path: entryExecution.Path(), Kind: string(deltaEntry.Kind()), Status: string(entryExecution.Status()),
			Reason: string(entryExecution.Reason()), RepositoryFileDeltaIdentity: deltaEntry.Identity(),
			ExecutionIdentity: entryExecution.Identity(), FileChangeIdentity: entryExecution.FileChange().Identity(),
			LineMapIdentity: entryExecution.LineMap().Identity(),
		}
	}
	status, resultCode := localGitChangeStatusComplete, 0
	switch {
	case len(entries) == 0:
		status = localGitChangeStatusNoChange
	case unsupported == 0:
		status = localGitChangeStatusComplete
	case supported > 0:
		status, resultCode = localGitChangeStatusPartial, 3
	default:
		status, resultCode = localGitChangeStatusUnsupported, 3
	}
	change := execution.Change()
	changeIdentity := ""
	if execution.HasChange() {
		changeIdentity = change.Identity()
		if changeIdentity == "" || supported == 0 || len(change.FileChanges()) != supported {
			return localGitChangeResult{}, 0, fmt.Errorf("local Git change aggregate is missing")
		}
		for _, entry := range entries {
			fileChange, hasFileChange := change.FileChangeForPath(entry.Path)
			lineMap, hasLineMap := change.LineMapForPath(entry.Path)
			if entry.Status == string(evidence.RepositoryFileDeltaExecutionStatusSupported) {
				if !hasFileChange || !hasLineMap || fileChange.Identity() != entry.FileChangeIdentity || lineMap.Identity() != entry.LineMapIdentity {
					return localGitChangeResult{}, 0, fmt.Errorf("local Git change aggregate does not match entries")
				}
			} else if hasFileChange || hasLineMap {
				return localGitChangeResult{}, 0, fmt.Errorf("unsupported local Git entry appears in change")
			}
		}
	} else if change.Identity() != "" || supported != 0 {
		return localGitChangeResult{}, 0, fmt.Errorf("local Git change aggregate is inconsistent")
	}
	return localGitChangeResult{
		Contract: "open-trestle/local-git-change-result", SchemaVersion: 2, Status: status,
		ChangeExecutionIdentity: execution.Identity(), AcquisitionPairIdentity: pair.Identity(),
		RepositoryIdentity: baseBinding.RepositoryIdentity(), SourceAdapterIdentity: baseBinding.SourceAdapterIdentity(),
		BaseRevisionIdentity: baseBinding.RevisionIdentity(), HeadRevisionIdentity: headBinding.RevisionIdentity(),
		BaseEnvelopeIdentity: pair.BaseEnvelope().Identity(), HeadEnvelopeIdentity: pair.HeadEnvelope().Identity(),
		ManifestDeltaIdentity: delta.Identity(), ChangePresent: execution.HasChange(), ChangeIdentity: changeIdentity,
		ChangedFileCount: len(entries), SupportedFileCount: supported, UnsupportedFileCount: unsupported, Entries: entries,
	}, resultCode, nil
}

func writeLocalGitChangeUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle local-git change --objects-root PATH --repository-authority AUTHORITY --repository-namespace SEGMENT[/SEGMENT...] --repository-name NAME --revision-algorithm sha1|sha256 --base-revision-digest FULL_LOWERCASE_HEX --head-revision-digest FULL_LOWERCASE_HEX")
}
