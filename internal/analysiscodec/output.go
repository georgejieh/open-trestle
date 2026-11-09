package analysiscodec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

const (
	MaxEvidenceItems            = 8192
	maximumEvidencePayloadBytes = 16 << 20
)

var (
	ErrInvalidResult = errors.New("invalid deterministic evidence result")
)

type Item struct {
	evidenceID, bindingIdentity, changeEntryIdentity, changeExecutionIdentity, path, digest, fileIdentity, fileDigest string
	startLine, endLine, sliceBytes                                                                                    int
	// headLine is set only on the removed-lines record of a deletion point:
	// the head line beside which its base lines were removed, which is the
	// start line of that point's deleted_lines gap. It is 0 on every other
	// record.
	headLine int
}

// HeadLine returns, for the removed-lines record of a deletion point, the head
// line beside which its base lines were removed; 0 otherwise.
func (i Item) HeadLine() int { return i.headLine }

func (i Item) EvidenceID() string          { return i.evidenceID }
func (i Item) BindingIdentity() string     { return i.bindingIdentity }
func (i Item) ChangeEntryIdentity() string { return i.changeEntryIdentity }
func (i Item) Path() string                { return i.path }
func (i Item) StartLine() int              { return i.startLine }
func (i Item) EndLine() int                { return i.endLine }
func (i Item) Digest() string              { return i.digest }
func (i Item) FileIdentity() string        { return i.fileIdentity }
func (i Item) FileDigest() string          { return i.fileDigest }
func (i Item) SliceBytes() int             { return i.sliceBytes }
func (i Item) EvidenceItem() (evidence.EvidenceItem, error) {
	sourceRange, err := evidence.NewSourceRange(i.path, i.startLine, i.endLine)
	if err != nil {
		return evidence.EvidenceItem{}, err
	}
	return evidence.NewEvidenceItem(i.evidenceID, evidence.EvidenceKindSource, i.digest, sourceRange)
}

// Observation is one exact deterministic rule match. It is not an independently verified finding.
type Observation struct {
	identity, fingerprint, checkIdentity, evidenceID, path, digest, fileIdentity, fileDigest string
	startLine, endLine, sliceBytes                                                           int
}

func NewItem(entry changecodec.Entry, binding evidence.SourceSliceBinding) (Item, error) {
	rangeValue := binding.SourceRange()
	if binding.Validate() != nil || rangeValue.Path() != entry.Path() || binding.RepositoryFileIdentity() != entry.HeadIdentity() || binding.RepositoryFileDigest() != entry.HeadDigest() || !containsRange(entry.Ranges(), rangeValue.StartLine(), rangeValue.EndLine()) {
		return Item{}, ErrInvalidResult
	}
	return Item{evidenceID: binding.Identity(), bindingIdentity: binding.Identity(), changeEntryIdentity: entry.Identity(), changeExecutionIdentity: entry.ExecutionIdentity(), path: entry.Path(), startLine: rangeValue.StartLine(), endLine: rangeValue.EndLine(), digest: binding.SliceDigest(), fileIdentity: binding.RepositoryFileIdentity(), fileDigest: binding.RepositoryFileDigest(), sliceBytes: binding.SliceBytes()}, nil
}

// DeletionContextReason labels a deletion point inside a deletion-only entry.
// The gap's lines are the head lines on either side of the removed base lines.
// Version 6 supplies no removed text; version 7 binds it as removed-lines
// records or records a RemovedLinesLimitReason gap.
const DeletionContextReason = "deleted_lines"

// RemovedLinesLimitReason labels the removed base lines of one deletion point
// that exceed the per-point or per-entry bound and are therefore not bound as
// removed-lines evidence. Unlike every other ranged gap, its lines are base
// lines: the exact base range that was removed.
const RemovedLinesLimitReason = "removed_lines_limit"

// NewDeletionContextItem binds unchanged head lines around a deletion point of
// a deletion-only entry (reason no_changed_head_lines). Such an entry has no
// changed head range, so the item is not contained in one; it is valid only in
// a version 6 or 7 result together with a deleted_lines gap for the same entry.
func NewDeletionContextItem(entry changecodec.Entry, binding evidence.SourceSliceBinding) (Item, error) {
	rangeValue := binding.SourceRange()
	if binding.Validate() != nil || !deletionOnlyEntry(entry) || rangeValue.Path() != entry.Path() || binding.RepositoryFileIdentity() != entry.HeadIdentity() || binding.RepositoryFileDigest() != entry.HeadDigest() {
		return Item{}, ErrInvalidResult
	}
	return Item{evidenceID: binding.Identity(), bindingIdentity: binding.Identity(), changeEntryIdentity: entry.Identity(), changeExecutionIdentity: entry.ExecutionIdentity(), path: entry.Path(), startLine: rangeValue.StartLine(), endLine: rangeValue.EndLine(), digest: binding.SliceDigest(), fileIdentity: binding.RepositoryFileIdentity(), fileDigest: binding.RepositoryFileDigest(), sliceBytes: binding.SliceBytes()}, nil
}

// NewRemovedLinesItem binds the exact base lines removed at one deletion point
// of a deletion-only entry. Its range and file are the base range and base file,
// not head lines, so it is never a changed range. headLine is the head line
// beside which the lines were removed: the start line of the point's
// deleted_lines gap. It is valid only in a version 7 result together with
// deletion-point context for the entry.
func NewRemovedLinesItem(entry changecodec.Entry, binding evidence.SourceSliceBinding, headLine int) (Item, error) {
	rangeValue := binding.SourceRange()
	if binding.Validate() != nil || !deletionOnlyEntry(entry) || rangeValue.Path() != entry.Path() || binding.RepositoryFileDigest() != entry.BaseDigest() || headLine < 1 || headLine > MaxLine {
		return Item{}, ErrInvalidResult
	}
	return Item{evidenceID: binding.Identity(), bindingIdentity: binding.Identity(), changeEntryIdentity: entry.Identity(), changeExecutionIdentity: entry.ExecutionIdentity(), path: entry.Path(), startLine: rangeValue.StartLine(), endLine: rangeValue.EndLine(), digest: binding.SliceDigest(), fileIdentity: binding.RepositoryFileIdentity(), fileDigest: binding.RepositoryFileDigest(), sliceBytes: binding.SliceBytes(), headLine: headLine}, nil
}

// MaxLine bounds every recorded line number.
const MaxLine = 1_000_000

// NewWholeFileRemovedLinesItem binds one chunk of the removed base text of an
// entry with no head line left: a deletion-only entry whose head file is
// empty, or a removed file. The entry keeps its whole-entry gap; the chunks
// and at most one trailing removed_lines_limit gap cover its base lines from
// line 1. A chunk names no head line.
func NewWholeFileRemovedLinesItem(entry changecodec.Entry, binding evidence.SourceSliceBinding) (Item, error) {
	rangeValue := binding.SourceRange()
	if binding.Validate() != nil || !deletionOnlyEntry(entry) && !removedFileEntry(entry) || rangeValue.Path() != entry.Path() || binding.RepositoryFileDigest() != entry.BaseDigest() {
		return Item{}, ErrInvalidResult
	}
	return Item{evidenceID: binding.Identity(), bindingIdentity: binding.Identity(), changeEntryIdentity: entry.Identity(), changeExecutionIdentity: entry.ExecutionIdentity(), path: entry.Path(), startLine: rangeValue.StartLine(), endLine: rangeValue.EndLine(), digest: binding.SliceDigest(), fileIdentity: binding.RepositoryFileIdentity(), fileDigest: binding.RepositoryFileDigest(), sliceBytes: binding.SliceBytes()}, nil
}

// removedFileEntry reports a removed file: it has base content and no head.
func removedFileEntry(entry changecodec.Entry) bool {
	return entry.Kind() == "removed" && entry.Reason() == "removed_file" && len(entry.Ranges()) == 0
}

func deletionOnlyEntry(entry changecodec.Entry) bool {
	return entry.Reason() == "no_changed_head_lines" && entry.Kind() == "modified" && entry.Status() == "unsupported" && len(entry.Ranges()) == 0
}

func NewObservationFromBinding(check DeterministicCheck, entry changecodec.Entry, binding evidence.SourceSliceBinding) (Observation, error) {
	rangeValue := binding.SourceRange()
	contained := false
	for _, changed := range entry.Ranges() {
		if changed.StartLine() <= rangeValue.StartLine() && rangeValue.EndLine() <= changed.EndLine() {
			contained = true
			break
		}
	}
	if check.Validate() != nil || binding.Validate() != nil || rangeValue.Path() != entry.Path() || binding.RepositoryFileIdentity() != entry.HeadIdentity() || binding.RepositoryFileDigest() != entry.HeadDigest() || !contained {
		return Observation{}, ErrInvalidResult
	}
	observation := Observation{checkIdentity: check.Identity(), evidenceID: binding.Identity(), path: entry.Path(), startLine: rangeValue.StartLine(), endLine: rangeValue.EndLine(), digest: binding.SliceDigest(), fileIdentity: binding.RepositoryFileIdentity(), fileDigest: binding.RepositoryFileDigest(), sliceBytes: binding.SliceBytes()}
	observation.fingerprint = hashObservationValue(struct {
		Rule      string `json:"rule"`
		Path      string `json:"path"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
	}{check.Key(), observation.path, observation.startLine, observation.endLine})
	observation.identity = deriveObservationIdentity(observation)
	return observation, nil
}
func (o Observation) Identity() string      { return o.identity }
func (o Observation) Fingerprint() string   { return o.fingerprint }
func (o Observation) CheckIdentity() string { return o.checkIdentity }
func (o Observation) EvidenceID() string    { return o.evidenceID }
func (o Observation) Path() string          { return o.path }
func (o Observation) StartLine() int        { return o.startLine }
func (o Observation) EndLine() int          { return o.endLine }
func (o Observation) Digest() string        { return o.digest }
func (o Observation) FileIdentity() string  { return o.fileIdentity }
func (o Observation) FileDigest() string    { return o.fileDigest }
func (o Observation) SliceBytes() int       { return o.sliceBytes }
func (o Observation) String() string        { return "deterministic review observation" }
func (o Observation) GoString() string      { return "analysis.Observation{<redacted>}" }
func deriveObservationIdentity(o Observation) string {
	return hashObservationValue(struct {
		Fingerprint  string `json:"fingerprint"`
		Check        string `json:"check"`
		Evidence     string `json:"evidence"`
		Path         string `json:"path"`
		StartLine    int    `json:"start_line"`
		EndLine      int    `json:"end_line"`
		Digest       string `json:"digest"`
		FileIdentity string `json:"file_identity"`
		FileDigest   string `json:"file_digest"`
		SliceBytes   int    `json:"slice_bytes"`
	}{o.fingerprint, o.checkIdentity, o.evidenceID, o.path, o.startLine, o.endLine, o.digest, o.fileIdentity, o.fileDigest, o.sliceBytes})
}
func hashObservationValue(value any) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

type Gap struct {
	changeEntryIdentity, changeExecutionIdentity, path, reason string
	startLine, endLine                                         int
}

func NewGap(entry changecodec.Entry, start, end int, reason string) Gap {
	return Gap{changeEntryIdentity: entry.Identity(), changeExecutionIdentity: entry.ExecutionIdentity(), path: entry.Path(), startLine: start, endLine: end, reason: reason}
}

func (g Gap) Path() string   { return g.path }
func (g Gap) StartLine() int { return g.startLine }
func (g Gap) EndLine() int   { return g.endLine }
func (g Gap) Reason() string { return g.reason }

type Result struct {
	identity, artifactIdentity, scopeIdentity, changeArtifactIdentity, changeIdentity, repositoryIdentity, headRevisionIdentity, headSnapshotArtifactIdentity, headSnapshotIdentity, headManifestIdentity string
	schemaVersion, changedEntries, changedRanges                                                                                                                                                          int
	items                                                                                                                                                                                                 []Item
	removed                                                                                                                                                                                               []Item
	gaps                                                                                                                                                                                                  []Gap
	checks                                                                                                                                                                                                []DeterministicCheck
	observations                                                                                                                                                                                          []Observation
	semanticProfile                                                                                                                                                                                       semanticimpact.Profile
}

func (r Result) Identity() string                       { return r.identity }
func (r Result) ArtifactIdentity() string               { return r.artifactIdentity }
func (r Result) ScopeIdentity() string                  { return r.scopeIdentity }
func (r Result) ChangeArtifactIdentity() string         { return r.changeArtifactIdentity }
func (r Result) ChangeIdentity() string                 { return r.changeIdentity }
func (r Result) HeadSnapshotArtifactIdentity() string   { return r.headSnapshotArtifactIdentity }
func (r Result) HeadSnapshotIdentity() string           { return r.headSnapshotIdentity }
func (r Result) HeadManifestIdentity() string           { return r.headManifestIdentity }
func (r Result) SchemaVersion() int                     { return r.schemaVersion }
func (r Result) Items() []Item                          { return append([]Item(nil), r.items...) }
func (r Result) RemovedLines() []Item                   { return append([]Item(nil), r.removed...) }
func (r Result) Gaps() []Gap                            { return append([]Gap(nil), r.gaps...) }
func (r Result) Checks() []DeterministicCheck           { return append([]DeterministicCheck(nil), r.checks...) }
func (r Result) Observations() []Observation            { return append([]Observation(nil), r.observations...) }
func (r Result) SemanticImpact() semanticimpact.Profile { return r.semanticProfile }
func (r Result) String() string                         { return "deterministic evidence result" }
func (r Result) GoString() string                       { return "analysis.Result{<redacted>}" }
func (r Result) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "deterministic evidence result", "analysis.Result{<redacted>}")
}

type itemWire struct {
	EvidenceID              string `json:"evidence_id"`
	BindingIdentity         string `json:"binding_identity"`
	ChangeEntryIdentity     string `json:"change_entry_identity"`
	ChangeExecutionIdentity string `json:"change_execution_identity"`
	Path                    string `json:"path"`
	StartLine               int    `json:"start_line"`
	EndLine                 int    `json:"end_line"`
	Digest                  string `json:"digest"`
	FileIdentity            string `json:"file_identity"`
	FileDigest              string `json:"file_digest"`
	SliceBytes              int    `json:"slice_bytes"`
	// HeadLine appears only on the removed-lines record of a deletion point.
	HeadLine int `json:"head_line,omitempty"`
}
type gapWire struct {
	ChangeEntryIdentity     string `json:"change_entry_identity"`
	ChangeExecutionIdentity string `json:"change_execution_identity"`
	Path                    string `json:"path"`
	StartLine               int    `json:"start_line"`
	EndLine                 int    `json:"end_line"`
	Reason                  string `json:"reason"`
}
type deterministicCheckWire struct {
	Identity         string `json:"identity"`
	Key              string `json:"key"`
	RuleVersion      uint16 `json:"rule_version"`
	ChangeIdentity   string `json:"change_identity"`
	State            string `json:"state"`
	ApplicableFiles  uint32 `json:"applicable_files"`
	ApplicableRanges uint32 `json:"applicable_ranges"`
	CheckedFiles     uint32 `json:"checked_files"`
	CheckedRanges    uint32 `json:"checked_ranges"`
	Matches          uint32 `json:"matches"`
}
type observationWire struct {
	Identity      string `json:"identity"`
	Fingerprint   string `json:"fingerprint"`
	CheckIdentity string `json:"check_identity"`
	EvidenceID    string `json:"evidence_id"`
	Path          string `json:"path"`
	StartLine     int    `json:"start_line"`
	EndLine       int    `json:"end_line"`
	Digest        string `json:"digest"`
	FileIdentity  string `json:"file_identity"`
	FileDigest    string `json:"file_digest"`
	SliceBytes    int    `json:"slice_bytes"`
}
type resultWire struct {
	Contract                     string                   `json:"contract"`
	SchemaVersion                int                      `json:"schema_version"`
	Identity                     string                   `json:"identity"`
	ChangeArtifactIdentity       string                   `json:"change_artifact_identity"`
	ChangeIdentity               string                   `json:"change_identity"`
	RepositoryIdentity           string                   `json:"repository_identity"`
	HeadRevisionIdentity         string                   `json:"head_revision_identity"`
	HeadSnapshotArtifactIdentity string                   `json:"head_snapshot_artifact_identity"`
	HeadSnapshotIdentity         string                   `json:"head_snapshot_identity"`
	HeadManifestIdentity         string                   `json:"head_manifest_identity"`
	ChangedEntries               int                      `json:"changed_entries"`
	ChangedRanges                int                      `json:"changed_ranges"`
	EvidenceItems                int                      `json:"evidence_items"`
	CoverageGaps                 int                      `json:"coverage_gaps"`
	Items                        []itemWire               `json:"items"`
	RemovedLines                 []itemWire               `json:"removed_lines,omitempty"`
	Gaps                         []gapWire                `json:"gaps"`
	Checks                       []deterministicCheckWire `json:"checks,omitempty"`
	Observations                 []observationWire        `json:"observations"`
	SemanticImpact               json.RawMessage          `json:"semantic_impact"`
}

func (w resultWire) MarshalJSON() ([]byte, error) {
	type current resultWire
	if w.SchemaVersion == 7 {
		// Version 7 always carries removed_lines, even when every deletion
		// point's removed text was recorded as a removed_lines_limit gap.
		if w.Observations == nil {
			w.Observations = []observationWire{}
		}
		if w.RemovedLines == nil {
			w.RemovedLines = []itemWire{}
		}
		type versionSeven struct {
			Contract                     string                   `json:"contract"`
			SchemaVersion                int                      `json:"schema_version"`
			Identity                     string                   `json:"identity"`
			ChangeArtifactIdentity       string                   `json:"change_artifact_identity"`
			ChangeIdentity               string                   `json:"change_identity"`
			RepositoryIdentity           string                   `json:"repository_identity"`
			HeadRevisionIdentity         string                   `json:"head_revision_identity"`
			HeadSnapshotArtifactIdentity string                   `json:"head_snapshot_artifact_identity"`
			HeadSnapshotIdentity         string                   `json:"head_snapshot_identity"`
			HeadManifestIdentity         string                   `json:"head_manifest_identity"`
			ChangedEntries               int                      `json:"changed_entries"`
			ChangedRanges                int                      `json:"changed_ranges"`
			EvidenceItems                int                      `json:"evidence_items"`
			CoverageGaps                 int                      `json:"coverage_gaps"`
			Items                        []itemWire               `json:"items"`
			RemovedLines                 []itemWire               `json:"removed_lines"`
			Gaps                         []gapWire                `json:"gaps"`
			Checks                       []deterministicCheckWire `json:"checks,omitempty"`
			Observations                 []observationWire        `json:"observations"`
			SemanticImpact               json.RawMessage          `json:"semantic_impact"`
		}
		return json.Marshal(versionSeven{w.Contract, w.SchemaVersion, w.Identity, w.ChangeArtifactIdentity, w.ChangeIdentity, w.RepositoryIdentity, w.HeadRevisionIdentity, w.HeadSnapshotArtifactIdentity, w.HeadSnapshotIdentity, w.HeadManifestIdentity, w.ChangedEntries, w.ChangedRanges, w.EvidenceItems, w.CoverageGaps, w.Items, w.RemovedLines, w.Gaps, w.Checks, w.Observations, w.SemanticImpact})
	}
	if observationVersion(w.SchemaVersion) {
		if w.Observations == nil {
			w.Observations = []observationWire{}
		}
		return json.Marshal(current(w))
	}
	type legacy struct {
		Contract                     string                   `json:"contract"`
		SchemaVersion                int                      `json:"schema_version"`
		Identity                     string                   `json:"identity"`
		ChangeArtifactIdentity       string                   `json:"change_artifact_identity"`
		ChangeIdentity               string                   `json:"change_identity"`
		RepositoryIdentity           string                   `json:"repository_identity"`
		HeadRevisionIdentity         string                   `json:"head_revision_identity"`
		HeadSnapshotArtifactIdentity string                   `json:"head_snapshot_artifact_identity"`
		HeadSnapshotIdentity         string                   `json:"head_snapshot_identity"`
		HeadManifestIdentity         string                   `json:"head_manifest_identity"`
		ChangedEntries               int                      `json:"changed_entries"`
		ChangedRanges                int                      `json:"changed_ranges"`
		EvidenceItems                int                      `json:"evidence_items"`
		CoverageGaps                 int                      `json:"coverage_gaps"`
		Items                        []itemWire               `json:"items"`
		Gaps                         []gapWire                `json:"gaps"`
		Checks                       []deterministicCheckWire `json:"checks,omitempty"`
		SemanticImpact               json.RawMessage          `json:"semantic_impact"`
	}
	return json.Marshal(legacy{w.Contract, w.SchemaVersion, w.Identity, w.ChangeArtifactIdentity, w.ChangeIdentity, w.RepositoryIdentity, w.HeadRevisionIdentity, w.HeadSnapshotArtifactIdentity, w.HeadSnapshotIdentity, w.HeadManifestIdentity, w.ChangedEntries, w.ChangedRanges, w.EvidenceItems, w.CoverageGaps, w.Items, w.Gaps, w.Checks, w.SemanticImpact})
}

// observationVersion reports whether a result version records the exact
// static-check observations array (version 4 and later).
func observationVersion(version int) bool { return version >= 4 && version <= 7 }

func NewResult(changeArtifact artifact.Artifact, change changecodec.Result, headArtifact artifact.Artifact, head sourceoutput.Snapshot, items []Item, gaps []Gap, checks []DeterministicCheck, observations []Observation, semanticProfile semanticimpact.Profile) (Result, error) {
	return NewResultWithRemovedLines(changeArtifact, change, headArtifact, head, items, nil, gaps, checks, observations, semanticProfile)
}

// NewResultWithRemovedLines additionally records the removed base lines of
// deletion points. Removed-lines records or removed_lines_limit gaps make the
// result version 7; without them a result keeps its version 4, 5 or 6 bytes.
func NewResultWithRemovedLines(changeArtifact artifact.Artifact, change changecodec.Result, headArtifact artifact.Artifact, head sourceoutput.Snapshot, items, removed []Item, gaps []Gap, checks []DeterministicCheck, observations []Observation, semanticProfile semanticimpact.Profile) (Result, error) {
	schemaVersion := 4
	changedRanges := 0
	deletionOnly := map[string]bool{}
	for _, entry := range change.Entries() {
		changedRanges += len(entry.Ranges())
		if entry.Reason() == "no_changed_head_lines" {
			schemaVersion = 5
			deletionOnly[entry.Identity()] = true
		}
	}
	// Version 6 adds deletion-point context: items and deleted_lines gaps on a
	// deletion-only entry. Without them a result keeps its version 4 or 5 bytes.
	for _, item := range items {
		if deletionOnly[item.changeEntryIdentity] {
			schemaVersion = 6
		}
	}
	// Version 7 adds the removed base text of deletion points.
	if len(removed) > 0 {
		schemaVersion = 7
	}
	for _, gap := range gaps {
		if gap.reason == RemovedLinesLimitReason {
			schemaVersion = 7
		}
	}
	result := Result{schemaVersion: schemaVersion, changeArtifactIdentity: changeArtifact.Identity(), changeIdentity: change.Identity(), repositoryIdentity: change.Repository().Identity(), headRevisionIdentity: change.HeadRevision().Identity(), headSnapshotArtifactIdentity: headArtifact.Identity(), headSnapshotIdentity: head.Identity(), headManifestIdentity: head.ManifestIdentity(), changedEntries: len(change.Entries()), changedRanges: changedRanges, items: append([]Item(nil), items...), removed: append([]Item(nil), removed...), gaps: append([]Gap(nil), gaps...), checks: append([]DeterministicCheck(nil), checks...), observations: append([]Observation(nil), observations...), semanticProfile: semanticProfile}
	sort.Slice(result.items, func(i, j int) bool { return itemKey(result.items[i]) < itemKey(result.items[j]) })
	sort.Slice(result.removed, func(i, j int) bool { return itemKey(result.removed[i]) < itemKey(result.removed[j]) })
	sort.Slice(result.gaps, func(i, j int) bool { return gapKey(result.gaps[i]) < gapKey(result.gaps[j]) })
	sort.Slice(result.observations, func(i, j int) bool {
		return observationKey(result.observations[i]) < observationKey(result.observations[j])
	})
	result.identity = deriveIdentity(result)
	if result.validate(false, change) != nil {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}
func (r Result) validate(requireArtifact bool, change changecodec.Result) error {
	if change.Identity() != r.changeIdentity || change.ArtifactIdentity() != r.changeArtifactIdentity || change.Repository().Identity() != r.repositoryIdentity || change.HeadRevision().Identity() != r.headRevisionIdentity || change.HeadSnapshotArtifactIdentity() != r.headSnapshotArtifactIdentity || change.HeadSnapshotIdentity() != r.headSnapshotIdentity || change.HeadManifestIdentity() != r.headManifestIdentity || r.changedEntries != len(change.Entries()) || len(r.items) > MaxEvidenceItems || len(r.removed) > MaxEvidenceItems || len(r.gaps) > MaxEvidenceItems || len(r.observations) > MaxEvidenceItems || r.semanticProfile.BaseSnapshotIdentity() != change.BaseSnapshotIdentity() || r.semanticProfile.HeadSnapshotIdentity() != change.HeadSnapshotIdentity() || r.semanticProfile.ChangeModelIdentity() != change.Identity() || requireArtifact && (!validDigest(r.artifactIdentity) || !validDigest(r.scopeIdentity)) {
		return ErrInvalidResult
	}
	validChecks := r.schemaVersion == 2 && len(r.checks) == 0 && len(r.observations) == 0 || r.schemaVersion == 3 && len(r.checks) == 1 && len(r.observations) == 0 || observationVersion(r.schemaVersion) && len(r.checks) == 1
	if !validChecks {
		return ErrInvalidResult
	}
	for _, check := range r.checks {
		if check.Validate() != nil || check.ChangeIdentity() != change.Identity() || check.Key() != staticDebugCheckKey {
			return ErrInvalidResult
		}
	}
	if observationVersion(r.schemaVersion) && uint32(len(r.observations)) != r.checks[0].MatchCount() {
		return ErrInvalidResult
	}
	entryByIdentity := make(map[string]changecodec.Entry, r.changedEntries)
	changedRanges := 0
	for _, entry := range change.Entries() {
		entryByIdentity[entry.Identity()] = entry
		changedRanges += len(entry.Ranges())
	}
	previousObservation := ""
	for _, observation := range r.observations {
		key := observationKey(observation)
		if key <= previousObservation || !validObservation(observation, r.checks[0], entryByIdentity) {
			return ErrInvalidResult
		}
		previousObservation = key
	}
	if r.changedRanges != changedRanges {
		return ErrInvalidResult
	}
	previous := ""
	seen := make(map[string]struct{}, len(r.items))
	covered := make(map[string]int, len(r.items)+len(r.gaps))
	wholeEntryGap := make(map[string]bool)
	deletionItems, deletionGaps := make(map[string]int), make(map[string]int)
	deletionPoints := make(map[string]bool)
	for _, item := range r.items {
		key := itemKey(item)
		if key <= previous || !validItem(item, entryByIdentity, r.schemaVersion) {
			return ErrInvalidResult
		}
		if deletionOnlyEntry(entryByIdentity[item.changeEntryIdentity]) {
			deletionItems[item.changeEntryIdentity]++
		}
		if _, ok := seen[item.evidenceID]; ok {
			return ErrInvalidResult
		}
		seen[item.evidenceID] = struct{}{}
		covered[coverageKey(item.changeEntryIdentity, item.startLine, item.endLine)]++
		previous = key
	}
	// Removed-lines records and removed_lines_limit gaps use base lines, so they
	// never enter head coverage. Each removed base range is accounted for once.
	removedText := make(map[string][]Item)
	previous = ""
	for _, item := range r.removed {
		key := itemKey(item)
		if r.schemaVersion != 7 || key <= previous || !validRemovedItem(item, entryByIdentity) {
			return ErrInvalidResult
		}
		if _, ok := seen[item.evidenceID]; ok {
			return ErrInvalidResult
		}
		seen[item.evidenceID] = struct{}{}
		removedText[item.changeEntryIdentity] = append(removedText[item.changeEntryIdentity], item)
		previous = key
	}
	previous = ""
	for _, gap := range r.gaps {
		key := gapKey(gap)
		if key <= previous || !validGap(gap, entryByIdentity, r.schemaVersion, change.SchemaVersion()) {
			return ErrInvalidResult
		}
		previous = key
		if gap.reason == RemovedLinesLimitReason {
			// A limit gap is marked by a negative head line so that whole-file
			// accounting can tell it from a bound chunk.
			removedText[gap.changeEntryIdentity] = append(removedText[gap.changeEntryIdentity], Item{startLine: gap.startLine, endLine: gap.endLine, headLine: -1})
			continue
		}
		if gap.reason == DeletionContextReason {
			deletionGaps[gap.changeEntryIdentity]++
			deletionPoints[coverageKey(gap.changeEntryIdentity, gap.startLine, 0)] = true
		}
		if gap.startLine == 0 {
			wholeEntryGap[gap.changeEntryIdentity] = true
		} else {
			covered[coverageKey(gap.changeEntryIdentity, gap.startLine, gap.endLine)]++
		}
	}
	// Version 6 exists only to carry deletion-point context, and version 7 to
	// carry removed text: of deletion points, which never appears without that
	// context, or of a whole file with no head line left. Version 7 accounts
	// for removed text on every entry that carries it.
	if r.schemaVersion == 6 && len(deletionItems) == 0 || r.schemaVersion == 7 && len(deletionItems) == 0 && len(removedText) == 0 {
		return ErrInvalidResult
	}
	for identity, ranges := range removedText {
		if wholeEntryGap[identity] {
			// A whole file with no head line left: chunks cover its base lines
			// from line 1, with at most one trailing removed_lines_limit gap.
			if !wholeFileBaseRanges(ranges) {
				return ErrInvalidResult
			}
			continue
		}
		if deletionItems[identity] == 0 || deletionGaps[identity] == 0 || !disjointBaseRanges(ranges) {
			return ErrInvalidResult
		}
	}
	// The removed text of a deletion point names the head line of that
	// point's deleted_lines gap; whole-file removed text names none.
	for _, item := range r.removed {
		if wholeEntryGap[item.changeEntryIdentity] != (item.headLine == 0) || item.headLine != 0 && !deletionPoints[coverageKey(item.changeEntryIdentity, item.headLine, 0)] {
			return ErrInvalidResult
		}
	}
	if r.schemaVersion == 7 {
		for identity := range deletionItems {
			if len(removedText[identity]) == 0 {
				return ErrInvalidResult
			}
		}
	}
	for _, entry := range change.Entries() {
		if wholeEntryGap[entry.Identity()] {
			for key, count := range covered {
				if strings.HasPrefix(key, entry.Identity()+"\x00") && count != 0 {
					return ErrInvalidResult
				}
			}
			continue
		}
		if len(entry.Ranges()) == 0 {
			// A deletion-only entry without its whole-entry gap must carry
			// deletion-point context: at least one item and one deleted_lines gap.
			if !wholeEntryGap[entry.Identity()] && (!deletionOnlyEntry(entry) || deletionItems[entry.Identity()] == 0 || deletionGaps[entry.Identity()] == 0) {
				return ErrInvalidResult
			}
			continue
		}
		for _, value := range entry.Ranges() {
			if covered[coverageKey(entry.Identity(), value.StartLine(), value.EndLine())] != 1 {
				return ErrInvalidResult
			}
		}
	}
	if r.identity != deriveIdentity(r) {
		return ErrInvalidResult
	}
	return nil
}
func validItem(item Item, entries map[string]changecodec.Entry, schemaVersion int) bool {
	entry, ok := entries[item.changeEntryIdentity]
	if !ok || entry.ExecutionIdentity() != item.changeExecutionIdentity || entry.Path() != item.path || entry.HeadIdentity() != item.fileIdentity || entry.HeadDigest() != item.fileDigest || item.evidenceID != item.bindingIdentity || !validDigest(item.evidenceID) || !validDigest(item.digest) || item.sliceBytes <= 0 || item.sliceBytes > 1<<20 || item.headLine != 0 {
		return false
	}
	sourceRange, err := evidence.NewSourceRange(item.path, item.startLine, item.endLine)
	deletionContext := (schemaVersion == 6 || schemaVersion == 7) && deletionOnlyEntry(entry)
	if err != nil || !deletionContext && !containsRange(entry.Ranges(), item.startLine, item.endLine) {
		return false
	}
	evidenceItem, err := evidence.NewEvidenceItem(item.evidenceID, evidence.EvidenceKindSource, item.digest, sourceRange)
	if err != nil || evidenceItem.ID() != item.evidenceID {
		return false
	}
	return deriveBindingIdentity(item) == item.bindingIdentity
}

// validRemovedItem checks one removed-lines record against the base side of
// its deletion-only entry. The record carries base lines of the base file.
func validRemovedItem(item Item, entries map[string]changecodec.Entry) bool {
	entry, ok := entries[item.changeEntryIdentity]
	if !ok || !deletionOnlyEntry(entry) && !(removedFileEntry(entry) && item.headLine == 0) || entry.ExecutionIdentity() != item.changeExecutionIdentity || entry.Path() != item.path || entry.BaseDigest() != item.fileDigest || item.evidenceID != item.bindingIdentity || !validDigest(item.evidenceID) || !validDigest(item.digest) || !validDigest(item.fileIdentity) || item.sliceBytes <= 0 || item.sliceBytes > 1<<20 || item.headLine < 0 || item.headLine > MaxLine {
		return false
	}
	sourceRange, err := evidence.NewSourceRange(item.path, item.startLine, item.endLine)
	if err != nil {
		return false
	}
	evidenceItem, err := evidence.NewEvidenceItem(item.evidenceID, evidence.EvidenceKindSource, item.digest, sourceRange)
	if err != nil || evidenceItem.ID() != item.evidenceID {
		return false
	}
	return deriveBindingIdentity(item) == item.bindingIdentity
}

// wholeFileBaseRanges reports whether the removed base ranges of a whole file,
// chunks and limit gaps together, tile its base lines from line 1 with at
// most one limit gap, which comes last.
func wholeFileBaseRanges(ranges []Item) bool {
	ordered := append([]Item(nil), ranges...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].startLine < ordered[j].startLine })
	next := 1
	for index, value := range ordered {
		limit := value.headLine < 0
		if value.startLine != next || limit && index != len(ordered)-1 {
			return false
		}
		next = value.endLine + 1
	}
	return true
}

// disjointBaseRanges reports whether the removed base ranges of one entry,
// records and limit gaps together, never overlap.
func disjointBaseRanges(ranges []Item) bool {
	ordered := append([]Item(nil), ranges...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].startLine < ordered[j].startLine })
	for index := 1; index < len(ordered); index++ {
		if ordered[index].startLine <= ordered[index-1].endLine {
			return false
		}
	}
	return true
}

func validGap(gap Gap, entries map[string]changecodec.Entry, schemaVersion, changeSchemaVersion int) bool {
	entry, ok := entries[gap.changeEntryIdentity]
	if !ok || entry.ExecutionIdentity() != gap.changeExecutionIdentity || entry.Path() != gap.path {
		return false
	}
	if entry.Reason() == "no_changed_head_lines" {
		if changeSchemaVersion != 2 || !deletionOnlyEntry(entry) {
			return false
		}
		if gap.reason == DeletionContextReason {
			_, err := evidence.NewSourceRange(gap.path, gap.startLine, gap.endLine)
			return (schemaVersion == 6 || schemaVersion == 7) && err == nil
		}
		if gap.reason == RemovedLinesLimitReason {
			_, err := evidence.NewSourceRange(gap.path, gap.startLine, gap.endLine)
			return schemaVersion == 7 && err == nil
		}
		return (schemaVersion == 5 || schemaVersion == 6 || schemaVersion == 7) && gap.startLine == 0 && gap.endLine == 0 && gap.reason == entry.Reason()
	}
	if gap.reason == RemovedLinesLimitReason {
		// The unbound tail of a removed file's base text, at its base lines.
		_, err := evidence.NewSourceRange(gap.path, gap.startLine, gap.endLine)
		return schemaVersion == 7 && removedFileEntry(entry) && err == nil
	}
	if gap.startLine == 0 && gap.endLine == 0 {
		if gap.reason == "evidence_limit" {
			return true
		}
		if len(entry.Ranges()) != 0 {
			return false
		}
		return entry.Kind() == "removed" && gap.reason == "removed_file" || entry.Kind() == "added" && gap.reason == "empty_added_file" || entry.Kind() == "modified" && gap.reason == entry.Reason() && (gap.reason == "unsupported_content" || gap.reason == "resource_limit")
	}
	if gap.reason != "slice_resource_limit" && gap.reason != "resource_limit" {
		return false
	}
	_, err := evidence.NewSourceRange(gap.path, gap.startLine, gap.endLine)
	return err == nil && containsRange(entry.Ranges(), gap.startLine, gap.endLine)
}

func validObservation(observation Observation, check DeterministicCheck, entries map[string]changecodec.Entry) bool {
	if observation.identity != deriveObservationIdentity(observation) || observation.checkIdentity != check.Identity() || !validDigest(observation.identity) || !validDigest(observation.fingerprint) || !validDigest(observation.evidenceID) || !validDigest(observation.digest) || !validDigest(observation.fileIdentity) || !validDigest(observation.fileDigest) || observation.sliceBytes <= 0 || observation.sliceBytes > 1<<20 {
		return false
	}
	entryFound := false
	for _, entry := range entries {
		if entry.Path() != observation.path || entry.HeadIdentity() != observation.fileIdentity || entry.HeadDigest() != observation.fileDigest {
			continue
		}
		for _, value := range entry.Ranges() {
			if value.StartLine() <= observation.startLine && observation.endLine <= value.EndLine() {
				entryFound = true
			}
		}
	}
	if !entryFound {
		return false
	}
	item := Item{evidenceID: observation.evidenceID, bindingIdentity: observation.evidenceID, path: observation.path, startLine: observation.startLine, endLine: observation.endLine, digest: observation.digest, fileIdentity: observation.fileIdentity, fileDigest: observation.fileDigest, sliceBytes: observation.sliceBytes}
	return deriveBindingIdentity(item) == observation.evidenceID
}

func containsRange(ranges []changecodec.Range, start, end int) bool {
	for _, value := range ranges {
		if value.StartLine() == start && value.EndLine() == end {
			return true
		}
	}
	return false
}
func EncodeResult(result Result) ([]byte, error) {
	if result.identity == "" {
		return nil, ErrInvalidResult
	}
	encoded, err := json.Marshal(toWire(result))
	if err != nil || len(encoded) > maximumEvidencePayloadBytes {
		return nil, ErrInvalidResult
	}
	return encoded, nil
}
func ParseResultArtifact(value, changeArtifact, baseArtifact, headArtifact artifact.Artifact) (Result, error) {
	change, err := changecodec.ParseResultArtifact(changeArtifact, baseArtifact, headArtifact)
	if err != nil {
		return Result{}, ErrInvalidResult
	}
	return ParseResultArtifactWithChange(value, changeArtifact, change)
}

// ParseResultArtifactWithChange reuses an immutable parsed change result bound
// to the exact artifact. Storage freshness remains the caller's responsibility.
func ParseResultArtifactWithChange(value, changeArtifact artifact.Artifact, change changecodec.Result) (Result, error) {
	if changeArtifact.Validate() != nil || changeArtifact.Kind() != artifact.KindChangeModel || changeArtifact.MediaType() != "application/json" || changeArtifact.Origin() != artifact.OriginDeterministicTool || change.ScopeIdentity() == "" || change.ScopeIdentity() != changeArtifact.Scope().Identity() || change.ArtifactIdentity() != changeArtifact.Identity() {
		return Result{}, ErrInvalidResult
	}
	if value.Validate() != nil || value.Kind() != artifact.KindDeterministicEvidence || value.MediaType() != "application/json" || value.Origin() != artifact.OriginDeterministicTool || value.Scope().Identity() != changeArtifact.Scope().Identity() || value.Classification() != changeArtifact.Classification() || value.Protection() != changeArtifact.Protection() || !contains(value.Provenance(), changeArtifact.Identity()) {
		return Result{}, ErrInvalidResult
	}
	if !contains(value.Provenance(), change.Identity()) || !contains(value.Provenance(), change.HeadSnapshotArtifactIdentity()) || !contains(value.Provenance(), change.HeadSnapshotIdentity()) {
		return Result{}, ErrInvalidResult
	}
	payload := value.Payload()
	if len(payload) == 0 || len(payload) > maximumEvidencePayloadBytes {
		return Result{}, ErrInvalidResult
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire resultWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Result{}, ErrInvalidResult
	}
	canonical, _ := json.Marshal(wire)
	validVersion := wire.SchemaVersion == 2 && len(wire.Checks) == 0 && len(wire.Observations) == 0 || wire.SchemaVersion == 3 && len(wire.Checks) == 1 && len(wire.Observations) == 0 || observationVersion(wire.SchemaVersion) && len(wire.Checks) == 1
	if !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/deterministic-evidence-result" || !validVersion || wire.EvidenceItems != len(wire.Items) || wire.CoverageGaps != len(wire.Gaps) {
		return Result{}, ErrInvalidResult
	}
	semanticProfile, err := semanticimpact.DecodeProfile(wire.SemanticImpact)
	if err != nil {
		return Result{}, ErrInvalidResult
	}
	checks := make([]DeterministicCheck, len(wire.Checks))
	for index, value := range wire.Checks {
		state, stateErr := parseDeterministicCheckState(value.State)
		if stateErr != nil || value.Key != staticDebugCheckKey || value.RuleVersion != staticDebugCheckRuleVersion {
			return Result{}, ErrInvalidResult
		}
		checks[index], err = NewDeterministicCheck(value.ChangeIdentity, state, value.ApplicableFiles, value.ApplicableRanges, value.CheckedFiles, value.CheckedRanges, value.Matches)
		if err != nil || checks[index].Identity() != value.Identity {
			return Result{}, ErrInvalidResult
		}
	}
	observations := make([]Observation, len(wire.Observations))
	for index, value := range wire.Observations {
		observations[index] = Observation{identity: value.Identity, fingerprint: value.Fingerprint, checkIdentity: value.CheckIdentity, evidenceID: value.EvidenceID, path: value.Path, startLine: value.StartLine, endLine: value.EndLine, digest: value.Digest, fileIdentity: value.FileIdentity, fileDigest: value.FileDigest, sliceBytes: value.SliceBytes}
	}
	result := fromWire(wire, checks, observations, semanticProfile)
	result.artifactIdentity = value.Identity()
	result.scopeIdentity = value.Scope().Identity()
	if result.validate(true, change) != nil {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}
func itemWireValues(values []Item) []itemWire {
	items := make([]itemWire, len(values))
	for i, v := range values {
		items[i] = itemWire{EvidenceID: v.evidenceID, BindingIdentity: v.bindingIdentity, ChangeEntryIdentity: v.changeEntryIdentity, ChangeExecutionIdentity: v.changeExecutionIdentity, Path: v.path, StartLine: v.startLine, EndLine: v.endLine, Digest: v.digest, FileIdentity: v.fileIdentity, FileDigest: v.fileDigest, SliceBytes: v.sliceBytes, HeadLine: v.headLine}
	}
	return items
}
func itemValues(values []itemWire) []Item {
	items := make([]Item, len(values))
	for i, v := range values {
		items[i] = Item{evidenceID: v.EvidenceID, bindingIdentity: v.BindingIdentity, changeEntryIdentity: v.ChangeEntryIdentity, changeExecutionIdentity: v.ChangeExecutionIdentity, path: v.Path, startLine: v.StartLine, endLine: v.EndLine, digest: v.Digest, fileIdentity: v.FileIdentity, fileDigest: v.FileDigest, sliceBytes: v.SliceBytes, headLine: v.HeadLine}
	}
	return items
}
func toWire(r Result) resultWire {
	items := itemWireValues(r.items)
	var removed []itemWire
	if len(r.removed) > 0 {
		removed = itemWireValues(r.removed)
	}
	gaps := make([]gapWire, len(r.gaps))
	for i, v := range r.gaps {
		gaps[i] = gapWire{ChangeEntryIdentity: v.changeEntryIdentity, ChangeExecutionIdentity: v.changeExecutionIdentity, Path: v.path, StartLine: v.startLine, EndLine: v.endLine, Reason: v.reason}
	}
	checks := make([]deterministicCheckWire, len(r.checks))
	for index, check := range r.checks {
		checks[index] = deterministicCheckWire{Identity: check.Identity(), Key: check.Key(), RuleVersion: check.RuleVersion(), ChangeIdentity: check.ChangeIdentity(), State: check.State().String(), ApplicableFiles: check.ApplicableFiles(), ApplicableRanges: check.ApplicableRanges(), CheckedFiles: check.CheckedFiles(), CheckedRanges: check.CheckedRanges(), Matches: check.MatchCount()}
	}
	observations := make([]observationWire, len(r.observations))
	for index, observation := range r.observations {
		observations[index] = observationWire{Identity: observation.identity, Fingerprint: observation.fingerprint, CheckIdentity: observation.checkIdentity, EvidenceID: observation.evidenceID, Path: observation.path, StartLine: observation.startLine, EndLine: observation.endLine, Digest: observation.digest, FileIdentity: observation.fileIdentity, FileDigest: observation.fileDigest, SliceBytes: observation.sliceBytes}
	}
	semanticEncoded, _ := semanticimpact.EncodeProfile(r.semanticProfile)
	return resultWire{Contract: "open-trestle/deterministic-evidence-result", SchemaVersion: r.schemaVersion, Identity: r.identity, ChangeArtifactIdentity: r.changeArtifactIdentity, ChangeIdentity: r.changeIdentity, RepositoryIdentity: r.repositoryIdentity, HeadRevisionIdentity: r.headRevisionIdentity, HeadSnapshotArtifactIdentity: r.headSnapshotArtifactIdentity, HeadSnapshotIdentity: r.headSnapshotIdentity, HeadManifestIdentity: r.headManifestIdentity, ChangedEntries: r.changedEntries, ChangedRanges: r.changedRanges, EvidenceItems: len(r.items), CoverageGaps: len(r.gaps), Items: items, RemovedLines: removed, Gaps: gaps, Checks: checks, Observations: observations, SemanticImpact: semanticEncoded}
}
func fromWire(w resultWire, checks []DeterministicCheck, observations []Observation, semanticProfile semanticimpact.Profile) Result {
	items := itemValues(w.Items)
	var removed []Item
	if len(w.RemovedLines) > 0 {
		removed = itemValues(w.RemovedLines)
	}
	gaps := make([]Gap, len(w.Gaps))
	for i, v := range w.Gaps {
		gaps[i] = Gap{changeEntryIdentity: v.ChangeEntryIdentity, changeExecutionIdentity: v.ChangeExecutionIdentity, path: v.Path, startLine: v.StartLine, endLine: v.EndLine, reason: v.Reason}
	}
	return Result{identity: w.Identity, schemaVersion: w.SchemaVersion, changeArtifactIdentity: w.ChangeArtifactIdentity, changeIdentity: w.ChangeIdentity, repositoryIdentity: w.RepositoryIdentity, headRevisionIdentity: w.HeadRevisionIdentity, headSnapshotArtifactIdentity: w.HeadSnapshotArtifactIdentity, headSnapshotIdentity: w.HeadSnapshotIdentity, headManifestIdentity: w.HeadManifestIdentity, changedEntries: w.ChangedEntries, changedRanges: w.ChangedRanges, items: items, removed: removed, gaps: gaps, checks: append([]DeterministicCheck(nil), checks...), observations: append([]Observation(nil), observations...), semanticProfile: semanticProfile}
}
func deriveIdentity(r Result) string {
	wire := toWire(r)
	wire.Identity = ""
	encoded, _ := json.Marshal(wire)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func deriveBindingIdentity(item Item) string {
	encoded, _ := json.Marshal(struct {
		Contract    string `json:"contract"`
		Version     int    `json:"version"`
		File        string `json:"file"`
		FileDigest  string `json:"file_digest"`
		Path        string `json:"path"`
		Start       int    `json:"start"`
		End         int    `json:"end"`
		SliceDigest string `json:"slice_digest"`
		SliceBytes  int    `json:"slice_bytes"`
	}{"open-trestle/source-slice-binding", 1, item.fileIdentity, item.fileDigest, item.path, item.startLine, item.endLine, item.digest, item.sliceBytes})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func coverageKey(identity string, start, end int) string {
	return fmt.Sprintf("%s\x00%09d\x00%09d", identity, start, end)
}
func itemKey(i Item) string { return fmt.Sprintf("%s\x00%09d\x00%09d", i.path, i.startLine, i.endLine) }
func observationKey(o Observation) string {
	return fmt.Sprintf("%s\x00%09d\x00%09d\x00%s", o.path, o.startLine, o.endLine, o.fingerprint)
}
func gapKey(g Gap) string {
	return fmt.Sprintf("%s\x00%09d\x00%09d\x00%s", g.path, g.startLine, g.endLine, g.reason)
}
func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) || strings.Trim(value, "0") == "" {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
func contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
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
