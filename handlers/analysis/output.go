package analysis

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
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	"github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

const (
	maximumEvidenceItems        = 8192
	maximumEvidencePayloadBytes = 16 << 20
)

var (
	ErrInvalidHandler = errors.New("invalid deterministic evidence handler")
	ErrInvalidResult  = errors.New("invalid deterministic evidence result")
)

type Item struct {
	evidenceID, bindingIdentity, changeEntryIdentity, changeExecutionIdentity, path, digest, fileIdentity, fileDigest string
	startLine, endLine, sliceBytes                                                                                    int
}

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

type Gap struct {
	changeEntryIdentity, changeExecutionIdentity, path, reason string
	startLine, endLine                                         int
}

func (g Gap) Path() string   { return g.path }
func (g Gap) StartLine() int { return g.startLine }
func (g Gap) EndLine() int   { return g.endLine }
func (g Gap) Reason() string { return g.reason }

type Result struct {
	identity, artifactIdentity, scopeIdentity, changeArtifactIdentity, changeIdentity, repositoryIdentity, headRevisionIdentity, headSnapshotArtifactIdentity, headSnapshotIdentity, headManifestIdentity string
	schemaVersion, changedEntries, changedRanges                                                                                                                                                          int
	items                                                                                                                                                                                                 []Item
	gaps                                                                                                                                                                                                  []Gap
	checks                                                                                                                                                                                                []DeterministicCheck
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
func (r Result) Gaps() []Gap                            { return append([]Gap(nil), r.gaps...) }
func (r Result) Checks() []DeterministicCheck           { return append([]DeterministicCheck(nil), r.checks...) }
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
	Gaps                         []gapWire                `json:"gaps"`
	Checks                       []deterministicCheckWire `json:"checks,omitempty"`
	SemanticImpact               json.RawMessage          `json:"semantic_impact"`
}

func newResult(changeArtifact artifact.Artifact, change changehandler.Result, headArtifact artifact.Artifact, head source.Snapshot, items []Item, gaps []Gap, checks []DeterministicCheck, semanticProfile semanticimpact.Profile) (Result, error) {
	changedRanges := 0
	for _, entry := range change.Entries() {
		changedRanges += len(entry.Ranges())
	}
	result := Result{schemaVersion: 3, changeArtifactIdentity: changeArtifact.Identity(), changeIdentity: change.Identity(), repositoryIdentity: change.Repository().Identity(), headRevisionIdentity: change.HeadRevision().Identity(), headSnapshotArtifactIdentity: headArtifact.Identity(), headSnapshotIdentity: head.Identity(), headManifestIdentity: head.ManifestIdentity(), changedEntries: len(change.Entries()), changedRanges: changedRanges, items: append([]Item(nil), items...), gaps: append([]Gap(nil), gaps...), checks: append([]DeterministicCheck(nil), checks...), semanticProfile: semanticProfile}
	sort.Slice(result.items, func(i, j int) bool { return itemKey(result.items[i]) < itemKey(result.items[j]) })
	sort.Slice(result.gaps, func(i, j int) bool { return gapKey(result.gaps[i]) < gapKey(result.gaps[j]) })
	result.identity = deriveIdentity(result)
	if result.validate(false, change) != nil {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}
func (r Result) validate(requireArtifact bool, change changehandler.Result) error {
	if change.Identity() != r.changeIdentity || change.ArtifactIdentity() != r.changeArtifactIdentity || change.Repository().Identity() != r.repositoryIdentity || change.HeadRevision().Identity() != r.headRevisionIdentity || change.HeadSnapshotArtifactIdentity() != r.headSnapshotArtifactIdentity || change.HeadSnapshotIdentity() != r.headSnapshotIdentity || change.HeadManifestIdentity() != r.headManifestIdentity || r.changedEntries != len(change.Entries()) || len(r.items) > maximumEvidenceItems || len(r.gaps) > maximumEvidenceItems || r.semanticProfile.BaseSnapshotIdentity() != change.BaseSnapshotIdentity() || r.semanticProfile.HeadSnapshotIdentity() != change.HeadSnapshotIdentity() || r.semanticProfile.ChangeModelIdentity() != change.Identity() || requireArtifact && (!validDigest(r.artifactIdentity) || !validDigest(r.scopeIdentity)) {
		return ErrInvalidResult
	}
	validChecks := r.schemaVersion == 2 && len(r.checks) == 0 || r.schemaVersion == 3 && len(r.checks) == 1
	if !validChecks {
		return ErrInvalidResult
	}
	for _, check := range r.checks {
		if check.Validate() != nil || check.ChangeIdentity() != change.Identity() || check.Key() != staticDebugCheckKey {
			return ErrInvalidResult
		}
	}
	entryByIdentity := make(map[string]changehandler.Entry, r.changedEntries)
	changedRanges := 0
	for _, entry := range change.Entries() {
		entryByIdentity[entry.Identity()] = entry
		changedRanges += len(entry.Ranges())
	}
	if r.changedRanges != changedRanges {
		return ErrInvalidResult
	}
	previous := ""
	seen := make(map[string]struct{}, len(r.items))
	covered := make(map[string]int, len(r.items)+len(r.gaps))
	wholeEntryGap := make(map[string]bool)
	for _, item := range r.items {
		key := itemKey(item)
		if key <= previous || !validItem(item, entryByIdentity) {
			return ErrInvalidResult
		}
		if _, ok := seen[item.evidenceID]; ok {
			return ErrInvalidResult
		}
		seen[item.evidenceID] = struct{}{}
		covered[coverageKey(item.changeEntryIdentity, item.startLine, item.endLine)]++
		previous = key
	}
	previous = ""
	for _, gap := range r.gaps {
		key := gapKey(gap)
		if key <= previous || !validGap(gap, entryByIdentity) {
			return ErrInvalidResult
		}
		if gap.startLine == 0 {
			wholeEntryGap[gap.changeEntryIdentity] = true
		} else {
			covered[coverageKey(gap.changeEntryIdentity, gap.startLine, gap.endLine)]++
		}
		previous = key
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
			if !wholeEntryGap[entry.Identity()] {
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
func validItem(item Item, entries map[string]changehandler.Entry) bool {
	entry, ok := entries[item.changeEntryIdentity]
	if !ok || entry.ExecutionIdentity() != item.changeExecutionIdentity || entry.Path() != item.path || entry.HeadIdentity() != item.fileIdentity || entry.HeadDigest() != item.fileDigest || item.evidenceID != item.bindingIdentity || !validDigest(item.evidenceID) || !validDigest(item.digest) || item.sliceBytes <= 0 || item.sliceBytes > 1<<20 {
		return false
	}
	sourceRange, err := evidence.NewSourceRange(item.path, item.startLine, item.endLine)
	if err != nil || !containsRange(entry.Ranges(), item.startLine, item.endLine) {
		return false
	}
	evidenceItem, err := evidence.NewEvidenceItem(item.evidenceID, evidence.EvidenceKindSource, item.digest, sourceRange)
	if err != nil || evidenceItem.ID() != item.evidenceID {
		return false
	}
	return deriveBindingIdentity(item) == item.bindingIdentity
}
func validGap(gap Gap, entries map[string]changehandler.Entry) bool {
	entry, ok := entries[gap.changeEntryIdentity]
	if !ok || entry.ExecutionIdentity() != gap.changeExecutionIdentity || entry.Path() != gap.path {
		return false
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

func containsRange(ranges []changehandler.Range, start, end int) bool {
	for _, value := range ranges {
		if value.StartLine() == start && value.EndLine() == end {
			return true
		}
	}
	return false
}
func encodeResult(result Result) ([]byte, error) {
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
	if value.Validate() != nil || value.Kind() != artifact.KindDeterministicEvidence || value.MediaType() != "application/json" || value.Origin() != artifact.OriginDeterministicTool || value.Scope().Identity() != changeArtifact.Scope().Identity() || value.Classification() != changeArtifact.Classification() || value.Protection() != changeArtifact.Protection() || !contains(value.Provenance(), changeArtifact.Identity()) {
		return Result{}, ErrInvalidResult
	}
	change, err := changehandler.ParseResultArtifact(changeArtifact, baseArtifact, headArtifact)
	if err != nil || !contains(value.Provenance(), change.Identity()) || !contains(value.Provenance(), headArtifact.Identity()) || !contains(value.Provenance(), change.HeadSnapshotIdentity()) {
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
	validVersion := wire.SchemaVersion == 2 && len(wire.Checks) == 0 || wire.SchemaVersion == 3 && len(wire.Checks) == 1
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
	result := fromWire(wire, checks, semanticProfile)
	result.artifactIdentity = value.Identity()
	result.scopeIdentity = value.Scope().Identity()
	if result.validate(true, change) != nil {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}
func toWire(r Result) resultWire {
	items := make([]itemWire, len(r.items))
	for i, v := range r.items {
		items[i] = itemWire{EvidenceID: v.evidenceID, BindingIdentity: v.bindingIdentity, ChangeEntryIdentity: v.changeEntryIdentity, ChangeExecutionIdentity: v.changeExecutionIdentity, Path: v.path, StartLine: v.startLine, EndLine: v.endLine, Digest: v.digest, FileIdentity: v.fileIdentity, FileDigest: v.fileDigest, SliceBytes: v.sliceBytes}
	}
	gaps := make([]gapWire, len(r.gaps))
	for i, v := range r.gaps {
		gaps[i] = gapWire{ChangeEntryIdentity: v.changeEntryIdentity, ChangeExecutionIdentity: v.changeExecutionIdentity, Path: v.path, StartLine: v.startLine, EndLine: v.endLine, Reason: v.reason}
	}
	checks := make([]deterministicCheckWire, len(r.checks))
	for index, check := range r.checks {
		checks[index] = deterministicCheckWire{Identity: check.Identity(), Key: check.Key(), RuleVersion: check.RuleVersion(), ChangeIdentity: check.ChangeIdentity(), State: check.State().String(), ApplicableFiles: check.ApplicableFiles(), ApplicableRanges: check.ApplicableRanges(), CheckedFiles: check.CheckedFiles(), CheckedRanges: check.CheckedRanges(), Matches: check.MatchCount()}
	}
	semanticEncoded, _ := semanticimpact.EncodeProfile(r.semanticProfile)
	return resultWire{Contract: "open-trestle/deterministic-evidence-result", SchemaVersion: r.schemaVersion, Identity: r.identity, ChangeArtifactIdentity: r.changeArtifactIdentity, ChangeIdentity: r.changeIdentity, RepositoryIdentity: r.repositoryIdentity, HeadRevisionIdentity: r.headRevisionIdentity, HeadSnapshotArtifactIdentity: r.headSnapshotArtifactIdentity, HeadSnapshotIdentity: r.headSnapshotIdentity, HeadManifestIdentity: r.headManifestIdentity, ChangedEntries: r.changedEntries, ChangedRanges: r.changedRanges, EvidenceItems: len(r.items), CoverageGaps: len(r.gaps), Items: items, Gaps: gaps, Checks: checks, SemanticImpact: semanticEncoded}
}
func fromWire(w resultWire, checks []DeterministicCheck, semanticProfile semanticimpact.Profile) Result {
	items := make([]Item, len(w.Items))
	for i, v := range w.Items {
		items[i] = Item{evidenceID: v.EvidenceID, bindingIdentity: v.BindingIdentity, changeEntryIdentity: v.ChangeEntryIdentity, changeExecutionIdentity: v.ChangeExecutionIdentity, path: v.Path, startLine: v.StartLine, endLine: v.EndLine, digest: v.Digest, fileIdentity: v.FileIdentity, fileDigest: v.FileDigest, sliceBytes: v.SliceBytes}
	}
	gaps := make([]Gap, len(w.Gaps))
	for i, v := range w.Gaps {
		gaps[i] = Gap{changeEntryIdentity: v.ChangeEntryIdentity, changeExecutionIdentity: v.ChangeExecutionIdentity, path: v.Path, startLine: v.StartLine, endLine: v.EndLine, reason: v.Reason}
	}
	return Result{identity: w.Identity, schemaVersion: w.SchemaVersion, changeArtifactIdentity: w.ChangeArtifactIdentity, changeIdentity: w.ChangeIdentity, repositoryIdentity: w.RepositoryIdentity, headRevisionIdentity: w.HeadRevisionIdentity, headSnapshotArtifactIdentity: w.HeadSnapshotArtifactIdentity, headSnapshotIdentity: w.HeadSnapshotIdentity, headManifestIdentity: w.HeadManifestIdentity, changedEntries: w.ChangedEntries, changedRanges: w.ChangedRanges, items: items, gaps: gaps, checks: append([]DeterministicCheck(nil), checks...), semanticProfile: semanticProfile}
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
