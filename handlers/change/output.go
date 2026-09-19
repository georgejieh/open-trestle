package change

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	maximumChangedEntries     = 4096
	maximumChangePayloadBytes = 16 << 20
)

var (
	ErrInvalidHandler = errors.New("invalid change model handler")
	ErrInvalidResult  = errors.New("invalid change model result")
)

type Range struct{ startLine, endLine int }

func (r Range) StartLine() int { return r.startLine }
func (r Range) EndLine() int   { return r.endLine }

type Entry struct {
	path, kind, deltaIdentity, status, reason, executionIdentity, fileChangeIdentity, lineMapIdentity string
	baseIdentity, baseDigest                                                                          string
	baseSize                                                                                          int
	headIdentity, headDigest                                                                          string
	headSize                                                                                          int
	ranges                                                                                            []Range
}

func (e Entry) Path() string              { return e.path }
func (e Entry) Kind() string              { return e.kind }
func (e Entry) Status() string            { return e.status }
func (e Entry) Reason() string            { return e.reason }
func (e Entry) Ranges() []Range           { return append([]Range(nil), e.ranges...) }
func (e Entry) Identity() string          { return e.deltaIdentity }
func (e Entry) ExecutionIdentity() string { return e.executionIdentity }
func (e Entry) HeadIdentity() string      { return e.headIdentity }
func (e Entry) HeadDigest() string        { return e.headDigest }
func (e Entry) HeadSizeBytes() int        { return e.headSize }

type Result struct {
	identity, artifactIdentity, scopeIdentity, baseSnapshotArtifact, headSnapshotArtifact, baseSnapshotIdentity, headSnapshotIdentity, repositoryIdentity, baseRevisionIdentity, headRevisionIdentity, sourceAdapterIdentity, baseManifestIdentity, headManifestIdentity, deltaIdentity string
	repository                                                                                                                                                                                                                                                                          evidence.RepositoryIdentity
	baseRevision, headRevision                                                                                                                                                                                                                                                          evidence.RevisionIdentity
	entries                                                                                                                                                                                                                                                                             []Entry
}

func (r Result) Identity() string                        { return r.identity }
func (r Result) ArtifactIdentity() string                { return r.artifactIdentity }
func (r Result) ScopeIdentity() string                   { return r.scopeIdentity }
func (r Result) BaseSnapshotArtifactIdentity() string    { return r.baseSnapshotArtifact }
func (r Result) BaseSnapshotIdentity() string            { return r.baseSnapshotIdentity }
func (r Result) HeadSnapshotArtifactIdentity() string    { return r.headSnapshotArtifact }
func (r Result) Repository() evidence.RepositoryIdentity { return r.repository }
func (r Result) BaseRevision() evidence.RevisionIdentity { return r.baseRevision }
func (r Result) HeadRevision() evidence.RevisionIdentity { return r.headRevision }
func (r Result) DeltaIdentity() string                   { return r.deltaIdentity }
func (r Result) HeadSnapshotIdentity() string            { return r.headSnapshotIdentity }
func (r Result) HeadManifestIdentity() string            { return r.headManifestIdentity }
func (r Result) SourceAdapterIdentity() string           { return r.sourceAdapterIdentity }
func (r Result) Entries() []Entry                        { return append([]Entry(nil), r.entries...) }
func (r Result) String() string                          { return "change model result" }
func (r Result) GoString() string                        { return "change.Result{<redacted>}" }
func (r Result) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "change model result", "change.Result{<redacted>}")
}

type rangeWire struct {
	StartLine int `json:"start_line"`
	EndLine   int `json:"end_line"`
}
type entryWire struct {
	Path               string      `json:"path"`
	Kind               string      `json:"kind"`
	DeltaIdentity      string      `json:"delta_identity"`
	BaseIdentity       string      `json:"base_identity"`
	BaseDigest         string      `json:"base_digest"`
	BaseSize           int         `json:"base_size"`
	HeadIdentity       string      `json:"head_identity"`
	HeadDigest         string      `json:"head_digest"`
	HeadSize           int         `json:"head_size"`
	Status             string      `json:"status"`
	Reason             string      `json:"reason"`
	ExecutionIdentity  string      `json:"execution_identity"`
	FileChangeIdentity string      `json:"file_change_identity"`
	LineMapIdentity    string      `json:"line_map_identity"`
	Ranges             []rangeWire `json:"ranges"`
}
type resultWire struct {
	Contract              string                     `json:"contract"`
	SchemaVersion         int                        `json:"schema_version"`
	Identity              string                     `json:"identity"`
	BaseSnapshotArtifact  string                     `json:"base_snapshot_artifact"`
	HeadSnapshotArtifact  string                     `json:"head_snapshot_artifact"`
	BaseSnapshotIdentity  string                     `json:"base_snapshot_identity"`
	HeadSnapshotIdentity  string                     `json:"head_snapshot_identity"`
	RepositoryAuthority   string                     `json:"repository_authority"`
	RepositoryNamespace   []string                   `json:"repository_namespace"`
	RepositoryName        string                     `json:"repository_name"`
	RepositoryIdentity    string                     `json:"repository_identity"`
	BaseRevisionKind      evidence.RevisionKind      `json:"base_revision_kind"`
	BaseRevisionAlgorithm evidence.RevisionAlgorithm `json:"base_revision_algorithm"`
	BaseRevisionDigest    string                     `json:"base_revision_digest"`
	BaseRevisionIdentity  string                     `json:"base_revision_identity"`
	HeadRevisionKind      evidence.RevisionKind      `json:"head_revision_kind"`
	HeadRevisionAlgorithm evidence.RevisionAlgorithm `json:"head_revision_algorithm"`
	HeadRevisionDigest    string                     `json:"head_revision_digest"`
	HeadRevisionIdentity  string                     `json:"head_revision_identity"`
	SourceAdapterIdentity string                     `json:"source_adapter_identity"`
	BaseManifestIdentity  string                     `json:"base_manifest_identity"`
	HeadManifestIdentity  string                     `json:"head_manifest_identity"`
	DeltaIdentity         string                     `json:"delta_identity"`
	Entries               []entryWire                `json:"entries"`
}

func newResult(baseArtifact, headArtifact artifact.Artifact, baseSnapshot, headSnapshot source.Snapshot, repository evidence.RepositoryIdentity, baseRevision, headRevision evidence.RevisionIdentity, delta evidence.RepositoryManifestDelta, executions []evidence.RepositoryFileDeltaExecution, extraRanges map[string][]evidence.SourceRange) (Result, error) {
	if baseArtifact.Validate() != nil || headArtifact.Validate() != nil || baseSnapshot.ArtifactIdentity() != baseArtifact.Identity() || headSnapshot.ArtifactIdentity() != headArtifact.Identity() || repository.Identity() != baseSnapshot.RepositoryIdentity() || repository.Identity() != headSnapshot.RepositoryIdentity() || baseRevision.Identity() != baseSnapshot.RevisionIdentity() || headRevision.Identity() != headSnapshot.RevisionIdentity() || baseSnapshot.SourceAdapterIdentity() != headSnapshot.SourceAdapterIdentity() || delta.BaseManifestIdentity() != baseSnapshot.ManifestIdentity() || delta.HeadManifestIdentity() != headSnapshot.ManifestIdentity() || len(executions) != len(delta.Entries()) || len(executions) > maximumChangedEntries {
		return Result{}, ErrInvalidResult
	}
	entries := make([]Entry, len(executions))
	deltaEntries := delta.Entries()
	seenExtraRanges := 0
	for index, execution := range executions {
		entry := deltaEntries[index]
		if execution.Path() != entry.Path() || execution.RepositoryFileDeltaIdentity() != entry.Identity() {
			return Result{}, ErrInvalidResult
		}
		value := Entry{path: entry.Path(), kind: string(entry.Kind()), deltaIdentity: entry.Identity(), status: string(execution.Status()), reason: string(execution.Reason()), executionIdentity: execution.Identity()}
		if file, ok := entry.BaseFile(); ok {
			value.baseIdentity, value.baseDigest, value.baseSize = file.Identity(), file.Digest(), file.SizeBytes()
		}
		if file, ok := entry.HeadFile(); ok {
			value.headIdentity, value.headDigest, value.headSize = file.Identity(), file.Digest(), file.SizeBytes()
		}
		ranges, hasExtraRanges := extraRanges[entry.Path()]
		if hasExtraRanges {
			seenExtraRanges++
		}
		if execution.Status() == evidence.RepositoryFileDeltaExecutionStatusSupported {
			change := execution.FileChange()
			lineMap := execution.LineMap()
			value.fileChangeIdentity, value.lineMapIdentity = change.Identity(), lineMap.Identity()
			ranges = change.ChangedRanges()
		}
		for _, sourceRange := range ranges {
			if sourceRange.Path() != entry.Path() {
				return Result{}, ErrInvalidResult
			}
			value.ranges = append(value.ranges, Range{sourceRange.StartLine(), sourceRange.EndLine()})
		}
		entries[index] = value
	}
	if seenExtraRanges != len(extraRanges) {
		return Result{}, ErrInvalidResult
	}
	result := Result{baseSnapshotArtifact: baseArtifact.Identity(), headSnapshotArtifact: headArtifact.Identity(), baseSnapshotIdentity: baseSnapshot.Identity(), headSnapshotIdentity: headSnapshot.Identity(), repository: repository, repositoryIdentity: repository.Identity(), baseRevision: baseRevision, headRevision: headRevision, baseRevisionIdentity: baseRevision.Identity(), headRevisionIdentity: headRevision.Identity(), sourceAdapterIdentity: baseSnapshot.SourceAdapterIdentity(), baseManifestIdentity: baseSnapshot.ManifestIdentity(), headManifestIdentity: headSnapshot.ManifestIdentity(), deltaIdentity: delta.Identity(), entries: entries}
	result.identity = deriveIdentity(result)
	if result.validate(false) != nil {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}
func (r Result) validate(requireArtifact bool) error {
	if r.repository.Identity() != r.repositoryIdentity || r.baseRevision.Identity() != r.baseRevisionIdentity || r.headRevision.Identity() != r.headRevisionIdentity || r.baseRevisionIdentity == r.headRevisionIdentity || !validDigest(r.baseSnapshotArtifact) || !validDigest(r.headSnapshotArtifact) || !validDigest(r.baseSnapshotIdentity) || !validDigest(r.headSnapshotIdentity) || !validDigest(r.sourceAdapterIdentity) || !validDigest(r.baseManifestIdentity) || !validDigest(r.headManifestIdentity) || !validDigest(r.deltaIdentity) || len(r.entries) > maximumChangedEntries || requireArtifact && (!validDigest(r.artifactIdentity) || !validDigest(r.scopeIdentity)) {
		return ErrInvalidResult
	}
	previous := ""
	for _, entry := range r.entries {
		if entry.path <= previous || !validEntry(entry) {
			return ErrInvalidResult
		}
		previous = entry.path
	}
	if r.identity != deriveIdentity(r) {
		return ErrInvalidResult
	}
	return nil
}
func validEntry(e Entry) bool {
	if _, err := evidence.NewSourceRange(e.path, 1, 1); err != nil {
		return false
	}
	if !validDigest(e.deltaIdentity) || !validDigest(e.executionIdentity) || (e.kind != "added" && e.kind != "modified" && e.kind != "removed") || (e.status != "supported" && e.status != "unsupported") {
		return false
	}
	hasBase, hasHead := e.baseIdentity != "", e.headIdentity != ""
	if hasBase != (e.kind != "added") || hasHead != (e.kind != "removed") {
		return false
	}
	if hasBase && (!validDigest(e.baseIdentity) || !validDigest(e.baseDigest) || e.baseSize < 0 || e.baseSize > 10<<20) || hasHead && (!validDigest(e.headIdentity) || !validDigest(e.headDigest) || e.headSize < 0 || e.headSize > 10<<20) {
		return false
	}
	supported := e.status == "supported"
	if supported {
		if e.kind != "added" && e.kind != "modified" || e.reason != "none" || !validDigest(e.fileChangeIdentity) || !validDigest(e.lineMapIdentity) || len(e.ranges) == 0 {
			return false
		}
	} else {
		if e.fileChangeIdentity != "" || e.lineMapIdentity != "" {
			return false
		}
		validReason := e.reason == "resource_limit" || e.kind == "added" && (e.reason == "added_file" || e.reason == "unsupported_content") || e.kind == "removed" && e.reason == "removed_file" || e.kind == "modified" && e.reason == "unsupported_content"
		if !validReason || e.kind != "added" && len(e.ranges) != 0 {
			return false
		}
	}
	previous := 0
	for _, value := range e.ranges {
		sourceRange, err := evidence.NewSourceRange(e.path, value.startLine, value.endLine)
		if err != nil || sourceRange.StartLine() <= previous {
			return false
		}
		previous = sourceRange.EndLine()
	}
	return true
}

func encodeResult(r Result) ([]byte, error) {
	if r.validate(false) != nil {
		return nil, ErrInvalidResult
	}
	encoded, err := json.Marshal(toWire(r))
	if err != nil || len(encoded) > maximumChangePayloadBytes {
		return nil, ErrInvalidResult
	}
	return encoded, nil
}

// ResultArtifactReferences returns the source snapshot artifacts named by a canonical change result.
// The result is not trusted until ParseResultArtifact binds it to those snapshots.
func ResultArtifactReferences(value artifact.Artifact) (string, string, error) {
	if value.Validate() != nil || value.Kind() != artifact.KindChangeModel || value.MediaType() != "application/json" || value.Origin() != artifact.OriginDeterministicTool {
		return "", "", ErrInvalidResult
	}
	payload := value.Payload()
	if len(payload) == 0 || len(payload) > maximumChangePayloadBytes {
		return "", "", ErrInvalidResult
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire resultWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return "", "", ErrInvalidResult
	}
	canonical, _ := json.Marshal(wire)
	if !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/change-model-result" || wire.SchemaVersion != 1 || !validDigest(wire.BaseSnapshotArtifact) || !validDigest(wire.HeadSnapshotArtifact) || wire.BaseSnapshotArtifact == wire.HeadSnapshotArtifact {
		return "", "", ErrInvalidResult
	}
	return wire.BaseSnapshotArtifact, wire.HeadSnapshotArtifact, nil
}

func ParseResultArtifact(value, baseArtifact, headArtifact artifact.Artifact) (Result, error) {
	if value.Validate() != nil || value.Kind() != artifact.KindChangeModel || value.MediaType() != "application/json" || value.Origin() != artifact.OriginDeterministicTool || baseArtifact.Identity() == headArtifact.Identity() || !slices.Contains(value.Provenance(), baseArtifact.Identity()) || !slices.Contains(value.Provenance(), headArtifact.Identity()) || value.Scope().Identity() != baseArtifact.Scope().Identity() || value.Scope().Identity() != headArtifact.Scope().Identity() || value.Classification() != baseArtifact.Classification() || value.Classification() != headArtifact.Classification() || value.Protection() != baseArtifact.Protection() || value.Protection() != headArtifact.Protection() {
		return Result{}, ErrInvalidResult
	}
	baseSnapshot, err := source.ParseSnapshotArtifact(baseArtifact)
	if err != nil {
		return Result{}, ErrInvalidResult
	}
	headSnapshot, err := source.ParseSnapshotArtifact(headArtifact)
	if err != nil {
		return Result{}, ErrInvalidResult
	}
	payload := value.Payload()
	if len(payload) == 0 || len(payload) > maximumChangePayloadBytes {
		return Result{}, ErrInvalidResult
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire resultWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Result{}, ErrInvalidResult
	}
	canonical, _ := json.Marshal(wire)
	if !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/change-model-result" || wire.SchemaVersion != 1 {
		return Result{}, ErrInvalidResult
	}
	repository, err := evidence.NewRepositoryIdentity(wire.RepositoryAuthority, wire.RepositoryNamespace, wire.RepositoryName)
	if err != nil || repository.Identity() != wire.RepositoryIdentity {
		return Result{}, ErrInvalidResult
	}
	baseRevision, err := evidence.NewRevisionIdentity(wire.BaseRevisionKind, wire.BaseRevisionAlgorithm, wire.BaseRevisionDigest)
	if err != nil || baseRevision.Identity() != wire.BaseRevisionIdentity {
		return Result{}, ErrInvalidResult
	}
	headRevision, err := evidence.NewRevisionIdentity(wire.HeadRevisionKind, wire.HeadRevisionAlgorithm, wire.HeadRevisionDigest)
	if err != nil || headRevision.Identity() != wire.HeadRevisionIdentity {
		return Result{}, ErrInvalidResult
	}
	result := fromWire(wire, repository, baseRevision, headRevision)
	result.artifactIdentity = value.Identity()
	result.scopeIdentity = value.Scope().Identity()
	if result.baseSnapshotArtifact != baseArtifact.Identity() || result.headSnapshotArtifact != headArtifact.Identity() || result.baseSnapshotIdentity != baseSnapshot.Identity() || result.headSnapshotIdentity != headSnapshot.Identity() || result.repositoryIdentity != baseSnapshot.RepositoryIdentity() || result.repositoryIdentity != headSnapshot.RepositoryIdentity() || result.baseRevisionIdentity != baseSnapshot.RevisionIdentity() || result.headRevisionIdentity != headSnapshot.RevisionIdentity() || result.sourceAdapterIdentity != baseSnapshot.SourceAdapterIdentity() || result.sourceAdapterIdentity != headSnapshot.SourceAdapterIdentity() || result.baseManifestIdentity != baseSnapshot.ManifestIdentity() || result.headManifestIdentity != headSnapshot.ManifestIdentity() || result.validate(true) != nil {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}
func toWire(r Result) resultWire {
	entries := make([]entryWire, len(r.entries))
	for i, e := range r.entries {
		ranges := make([]rangeWire, len(e.ranges))
		for j, v := range e.ranges {
			ranges[j] = rangeWire{v.startLine, v.endLine}
		}
		entries[i] = entryWire{e.path, e.kind, e.deltaIdentity, e.baseIdentity, e.baseDigest, e.baseSize, e.headIdentity, e.headDigest, e.headSize, e.status, e.reason, e.executionIdentity, e.fileChangeIdentity, e.lineMapIdentity, ranges}
	}
	return resultWire{"open-trestle/change-model-result", 1, r.identity, r.baseSnapshotArtifact, r.headSnapshotArtifact, r.baseSnapshotIdentity, r.headSnapshotIdentity, r.repository.Authority(), r.repository.Namespace(), r.repository.Name(), r.repositoryIdentity, r.baseRevision.Kind(), r.baseRevision.Algorithm(), r.baseRevision.Digest(), r.baseRevisionIdentity, r.headRevision.Kind(), r.headRevision.Algorithm(), r.headRevision.Digest(), r.headRevisionIdentity, r.sourceAdapterIdentity, r.baseManifestIdentity, r.headManifestIdentity, r.deltaIdentity, entries}
}
func fromWire(w resultWire, repository evidence.RepositoryIdentity, base, head evidence.RevisionIdentity) Result {
	entries := make([]Entry, len(w.Entries))
	for i, e := range w.Entries {
		ranges := make([]Range, len(e.Ranges))
		for j, r := range e.Ranges {
			ranges[j] = Range{r.StartLine, r.EndLine}
		}
		entries[i] = Entry{e.Path, e.Kind, e.DeltaIdentity, e.Status, e.Reason, e.ExecutionIdentity, e.FileChangeIdentity, e.LineMapIdentity, e.BaseIdentity, e.BaseDigest, e.BaseSize, e.HeadIdentity, e.HeadDigest, e.HeadSize, ranges}
	}
	return Result{identity: w.Identity, baseSnapshotArtifact: w.BaseSnapshotArtifact, headSnapshotArtifact: w.HeadSnapshotArtifact, baseSnapshotIdentity: w.BaseSnapshotIdentity, headSnapshotIdentity: w.HeadSnapshotIdentity, repository: repository, repositoryIdentity: w.RepositoryIdentity, baseRevision: base, headRevision: head, baseRevisionIdentity: w.BaseRevisionIdentity, headRevisionIdentity: w.HeadRevisionIdentity, sourceAdapterIdentity: w.SourceAdapterIdentity, baseManifestIdentity: w.BaseManifestIdentity, headManifestIdentity: w.HeadManifestIdentity, deltaIdentity: w.DeltaIdentity, entries: entries}
}
func deriveIdentity(r Result) string {
	wire := toWire(r)
	wire.Identity = ""
	encoded, _ := json.Marshal(wire)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) || strings.Trim(value, "0") == "" {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
func writeRedacted(state fmt.State, verb rune, plain, detailed string) {
	value := plain
	if verb == 'q' {
		value = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		value = detailed
	}
	_, _ = state.Write([]byte(value))
}
