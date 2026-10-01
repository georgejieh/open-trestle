package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	"github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

const maximumEvidenceSourceBytes = 64 << 20

type Handler struct {
	identity        string
	store           artifact.Store
	diagnosticStore diagnostics.Store
	clock           artifact.Clock
}

func NewHandler(store artifact.Store, clock artifact.Clock) (*Handler, error) {
	return newHandler(store, nil, clock)
}

// NewHandlerWithDiagnostics adds deterministic-only diagnostic projection for a terminal local run.
func NewHandlerWithDiagnostics(store artifact.Store, diagnosticStore diagnostics.Store, clock artifact.Clock) (*Handler, error) {
	if nilInterface(diagnosticStore) {
		return nil, ErrInvalidHandler
	}
	return newHandler(store, diagnosticStore, clock)
}
func newHandler(store artifact.Store, diagnosticStore diagnostics.Store, clock artifact.Clock) (*Handler, error) {
	if nilInterface(store) || nilInterface(clock) {
		return nil, ErrInvalidHandler
	}
	handler := &Handler{store: store, diagnosticStore: diagnosticStore, clock: clock}
	handler.identity = deriveHandlerIdentity(!nilInterface(diagnosticStore))
	return handler, nil
}
func (h *Handler) HandlerIdentity() string {
	if h == nil {
		return ""
	}
	return h.identity
}
func (h *Handler) Kind() controlplane.TaskKind {
	if h == nil {
		return 0
	}
	return controlplane.TaskInspectDeterministic
}
func (h *Handler) Validate() error {
	if h == nil || nilInterface(h.store) || nilInterface(h.clock) || h.identity != deriveHandlerIdentity(!nilInterface(h.diagnosticStore)) {
		return ErrInvalidHandler
	}
	return nil
}
func deriveHandlerIdentity(projectDiagnostics bool) string {
	encoded, _ := json.Marshal(struct {
		Contract             string `json:"contract"`
		SchemaVersion        int    `json:"schema_version"`
		DiagnosticProjection bool   `json:"diagnostic_projection"`
	}{"open-trestle/deterministic-evidence-handler", 4, projectDiagnostics})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func (h *Handler) Execute(ctx context.Context, request controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if nilInterface(ctx) || h.Validate() != nil || request.Validate() != nil || request.Task().Kind() != controlplane.TaskInspectDeterministic || request.Task().HandlerIdentity() != h.identity || !equalStrings(request.Task().Dependencies(), []string{"change"}) {
		return failure(controlplane.RunFailureInvalidInput)
	}
	if ctx.Err() != nil {
		return failure(controlplane.RunFailureCanceled)
	}
	at := h.clock.Now().UTC()
	if at.UnixMilli() <= 0 || at.After(request.Lease().ExpiresAt()) {
		return failure(controlplane.RunFailureCanceled)
	}
	dependency, ok := request.DependencyOutput("change")
	if !ok || !dependency.Available() {
		return failure(controlplane.RunFailureInvalidInput)
	}
	changeArtifact, err := h.store.Get(ctx, request.Plan().Scope(), dependency.OutputIdentity(), at)
	if err != nil {
		return failure(readFailure(ctx, err))
	}
	baseID, headID, err := changehandler.ResultArtifactReferences(changeArtifact)
	if err != nil {
		return failure(controlplane.RunFailureInvalidInput)
	}
	baseArtifact, err := h.store.Get(ctx, request.Plan().Scope(), baseID, at)
	if err != nil {
		return failure(readFailure(ctx, err))
	}
	headArtifact, err := h.store.Get(ctx, request.Plan().Scope(), headID, at)
	if err != nil {
		return failure(readFailure(ctx, err))
	}
	change, err := changehandler.ParseResultArtifact(changeArtifact, baseArtifact, headArtifact)
	if err != nil {
		return failure(controlplane.RunFailureInvalidInput)
	}
	base, err := source.ParseSnapshotArtifact(baseArtifact)
	if err != nil || base.Identity() != change.BaseSnapshotIdentity() {
		return failure(controlplane.RunFailureInvalidInput)
	}
	head, err := source.ParseSnapshotArtifact(headArtifact)
	if err != nil || head.Identity() != change.HeadSnapshotIdentity() {
		return failure(controlplane.RunFailureInvalidInput)
	}
	references := make(map[string]source.FileReference, head.FileCount())
	for _, reference := range head.Files() {
		references[reference.Path()] = reference
	}
	items := make([]Item, 0)
	matchItems := make([]Item, 0)
	gaps := make([]Gap, 0)
	workUnits := 0
	for _, entry := range change.Entries() {
		if len(entry.Ranges()) == 0 {
			workUnits++
		} else {
			workUnits += len(entry.Ranges())
		}
	}
	evidenceLimit := workUnits > maximumEvidenceItems
	loaded := 0
	var applicableFiles, applicableRanges, checkedFiles, checkedRanges, matches uint32
	expires := minimumTime(changeArtifact.ExpiresAt(), baseArtifact.ExpiresAt(), headArtifact.ExpiresAt())
	for _, entry := range change.Entries() {
		if ctx.Err() != nil {
			return failure(controlplane.RunFailureCanceled)
		}
		ranges := entry.Ranges()
		applicable := path.Ext(entry.Path()) == ".go" && len(ranges) > 0
		if applicable {
			applicableFiles++
			applicableRanges += uint32(len(ranges))
		}
		if evidenceLimit {
			gaps = append(gaps, newGap(entry, 0, 0, "evidence_limit"))
			continue
		}
		if len(ranges) == 0 {
			reason := entry.Reason()
			if entry.Kind() == "added" {
				reason = "empty_added_file"
			}
			gaps = append(gaps, newGap(entry, 0, 0, reason))
			continue
		}
		reference, ok := references[entry.Path()]
		if !ok || reference.Digest() != entry.HeadDigest() {
			return failure(controlplane.RunFailureInvalidInput)
		}
		if loaded+reference.SizeBytes() > maximumEvidenceSourceBytes {
			for _, value := range ranges {
				gaps = append(gaps, newGap(entry, value.StartLine(), value.EndLine(), "resource_limit"))
			}
			continue
		}
		fileArtifact, err := h.store.Get(ctx, request.Plan().Scope(), reference.ArtifactIdentity(), at)
		if err != nil {
			return failure(readFailure(ctx, err))
		}
		file, err := source.ParseFileArtifact(fileArtifact, head, reference)
		if err != nil {
			return failure(controlplane.RunFailureInvalidInput)
		}
		content := file.Content()
		loaded += len(content)
		if fileArtifact.ExpiresAt().Before(expires) {
			expires = fileArtifact.ExpiresAt()
		}
		repositoryFile, err := evidence.NewRepositoryFile(entry.Path(), content)
		if err != nil || repositoryFile.Identity() != entry.HeadIdentity() {
			clear(content)
			return failure(controlplane.RunFailureInvalidInput)
		}
		sourceRanges := make([]evidence.SourceRange, len(ranges))
		for index, value := range ranges {
			sourceRanges[index], err = evidence.NewSourceRange(entry.Path(), value.StartLine(), value.EndLine())
			if err != nil {
				clear(content)
				return failure(controlplane.RunFailureInvalidInput)
			}
		}
		if applicable {
			matchedRanges, checkErr := review.FindStaticDebugOutputRanges(content, entry.Path(), sourceRanges)
			if checkErr == nil {
				checkedFiles++
				checkedRanges += uint32(len(sourceRanges))
				matches += uint32(len(matchedRanges))
				for _, matched := range matchedRanges {
					if len(matchItems) >= diagnostics.MaxDeterministicObservations {
						clear(content)
						return failure(controlplane.RunFailureResourceLimit)
					}
					slice, ok := physicalLineSlice(content, matched.StartLine(), matched.EndLine())
					if !ok {
						clear(content)
						return failure(controlplane.RunFailureInvalidInput)
					}
					binding, bindErr := evidence.BindSourceSlice(repositoryFile, content, matched, slice)
					if bindErr != nil {
						clear(content)
						return failure(controlplane.RunFailureResourceLimit)
					}
					matchItems = append(matchItems, Item{evidenceID: binding.Identity(), bindingIdentity: binding.Identity(), changeEntryIdentity: entry.Identity(), changeExecutionIdentity: entry.ExecutionIdentity(), path: entry.Path(), startLine: matched.StartLine(), endLine: matched.EndLine(), digest: binding.SliceDigest(), fileIdentity: binding.RepositoryFileIdentity(), fileDigest: binding.RepositoryFileDigest(), sliceBytes: binding.SliceBytes()})
				}
			}
		}
		for index, value := range ranges {
			sourceRange := sourceRanges[index]
			slice, ok := physicalLineSlice(content, value.StartLine(), value.EndLine())
			if !ok {
				clear(content)
				return failure(controlplane.RunFailureInvalidInput)
			}
			binding, err := evidence.BindSourceSlice(repositoryFile, content, sourceRange, slice)
			if err != nil {
				gaps = append(gaps, newGap(entry, value.StartLine(), value.EndLine(), "slice_resource_limit"))
				continue
			}
			items = append(items, Item{evidenceID: binding.Identity(), bindingIdentity: binding.Identity(), changeEntryIdentity: entry.Identity(), changeExecutionIdentity: entry.ExecutionIdentity(), path: entry.Path(), startLine: value.StartLine(), endLine: value.EndLine(), digest: binding.SliceDigest(), fileIdentity: binding.RepositoryFileIdentity(), fileDigest: binding.RepositoryFileDigest(), sliceBytes: binding.SliceBytes()})
		}
		clear(content)
	}
	semanticProfile, semanticExpires, err := buildSemanticProfile(ctx, h.store, request.Plan().Scope(), at, base, head, change)
	if err != nil {
		if errors.Is(err, semanticimpact.ErrImpactLimit) {
			return failure(controlplane.RunFailureResourceLimit)
		}
		if errors.Is(err, semanticimpact.ErrInvalidInput) {
			return failure(controlplane.RunFailureInvalidInput)
		}
		return failure(readFailure(ctx, err))
	}
	if semanticExpires.Before(expires) {
		expires = semanticExpires
	}
	check, err := newStaticDebugCheck(change.Identity(), applicableFiles, applicableRanges, checkedFiles, checkedRanges, matches)
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	observations := make([]Observation, len(matchItems))
	for index, item := range matchItems {
		observations[index], err = newObservation(check, item)
		if err != nil {
			return failure(controlplane.RunFailureInternal)
		}
	}
	result, err := newResult(changeArtifact, change, headArtifact, head, items, gaps, []DeterministicCheck{check}, observations, semanticProfile)
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	payload, err := encodeResult(result)
	if err != nil {
		return failure(controlplane.RunFailureResourceLimit)
	}
	provenance := []string{changeArtifact.Identity(), change.Identity(), headArtifact.Identity(), head.Identity()}
	sort.Strings(provenance)
	output, err := artifact.New(request.Plan().Scope(), artifact.KindDeterministicEvidence, "application/json", changeArtifact.Classification(), artifact.OriginDeterministicTool, changeArtifact.Protection(), provenance, payload, at, expires)
	if err != nil {
		return failure(controlplane.RunFailureResourceLimit)
	}
	var projected diagnostics.Set
	if !nilInterface(h.diagnosticStore) {
		projected, err = buildDiagnosticSet(request.Plan().Scope(), change, result, check, observations)
		if err != nil {
			return failure(diagnosticWriteFailure(ctx, err))
		}
	}
	if _, err := h.store.Put(ctx, output, at); err != nil {
		return failure(writeFailure(ctx, err))
	}
	if !nilInterface(h.diagnosticStore) {
		if _, err := h.diagnosticStore.PutDiagnosticSet(ctx, projected); err != nil {
			return failure(diagnosticWriteFailure(ctx, err))
		}
	}
	completion, err := controlplane.NewTaskSuccess(output.Identity())
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	return completion
}
func buildDiagnosticSet(scope audit.ReviewScope, change changehandler.Result, result Result, check DeterministicCheck, observations []Observation) (diagnostics.Set, error) {
	if len(observations) > diagnostics.MaxDeterministicObservations {
		return diagnostics.Set{}, diagnostics.ErrSetResourceLimit
	}
	state := diagnostics.CheckPassed
	switch check.State() {
	case CheckFailed:
		state = diagnostics.CheckFailed
	case CheckIncomplete:
		state = diagnostics.CheckIncomplete
	case CheckNotApplicable:
		state = diagnostics.CheckNotApplicable
	}
	projectedCheck, err := diagnostics.NewDeterministicCheck(check.Identity(), result.Identity(), change.Identity(), state, check.ApplicableFiles(), check.ApplicableRanges(), check.CheckedFiles(), check.CheckedRanges(), check.MatchCount())
	if err != nil {
		return diagnostics.Set{}, err
	}
	projectedObservations := make([]diagnostics.DeterministicObservation, len(observations))
	for index, observation := range observations {
		projectedObservations[index], err = diagnostics.NewDeterministicObservation(observation.Identity(), observation.Fingerprint(), result.Identity(), projectedCheck.Identity(), "Debug output left in source", "The deterministic static rule matched this exact changed range; human review is required.", diagnostics.SeverityWarning, observation.Path(), uint32(observation.StartLine()), uint32(observation.EndLine()), []string{observation.EvidenceID()})
		if err != nil {
			return diagnostics.Set{}, err
		}
	}
	set, err := diagnostics.NewSetWithDeterministicObservations(scope, result.HeadSnapshotIdentity(), change.HeadRevision().Digest(), result.Identity(), []diagnostics.DeterministicCheck{projectedCheck}, projectedObservations)
	if err != nil {
		return diagnostics.Set{}, err
	}
	return set, nil
}
func diagnosticWriteFailure(ctx context.Context, err error) controlplane.RunFailure {
	if ctx.Err() != nil {
		return controlplane.RunFailureCanceled
	}
	if errors.Is(err, diagnostics.ErrSetResourceLimit) || errors.Is(err, artifact.ErrStoreCapacity) {
		return controlplane.RunFailureResourceLimit
	}
	if errors.Is(err, diagnostics.ErrSetConflict) {
		return controlplane.RunFailureInvalidInput
	}
	return controlplane.RunFailureInternal
}

func newGap(entry changehandler.Entry, start, end int, reason string) Gap {
	return Gap{changeEntryIdentity: entry.Identity(), changeExecutionIdentity: entry.ExecutionIdentity(), path: entry.Path(), startLine: start, endLine: end, reason: reason}
}
func physicalLineSlice(content []byte, startLine, endLine int) ([]byte, bool) {
	if len(content) == 0 || startLine < 1 || endLine < startLine {
		return nil, false
	}
	line, startOffset := 1, -1
	if startLine == 1 {
		startOffset = 0
	}
	for offset, value := range content {
		if value != '\n' {
			continue
		}
		if line == endLine && startOffset >= 0 {
			return content[startOffset : offset+1], true
		}
		line++
		if line == startLine && offset+1 < len(content) {
			startOffset = offset + 1
		}
	}
	if line == endLine && startOffset >= 0 && startOffset < len(content) {
		return content[startOffset:], true
	}
	return nil, false
}
func minimumTime(values ...time.Time) time.Time {
	result := values[0]
	for _, value := range values[1:] {
		if value.Before(result) {
			result = value
		}
	}
	return result
}
func equalStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for i := range first {
		if first[i] != second[i] {
			return false
		}
	}
	return true
}
func readFailure(ctx context.Context, err error) controlplane.RunFailure {
	if ctx.Err() != nil {
		return controlplane.RunFailureCanceled
	}
	if errors.Is(err, artifact.ErrArtifactNotFound) || errors.Is(err, artifact.ErrArtifactExpired) {
		return controlplane.RunFailureInvalidInput
	}
	if errors.Is(err, artifact.ErrStoreCapacity) {
		return controlplane.RunFailureResourceLimit
	}
	return controlplane.RunFailureInternal
}
func writeFailure(ctx context.Context, err error) controlplane.RunFailure {
	if ctx.Err() != nil {
		return controlplane.RunFailureCanceled
	}
	if errors.Is(err, artifact.ErrStoreCapacity) {
		return controlplane.RunFailureResourceLimit
	}
	return controlplane.RunFailureInternal
}
func failure(kind controlplane.RunFailure) controlplane.TaskCompletion {
	value, _ := controlplane.NewTaskFailure(kind)
	return value
}
func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	ref := reflect.ValueOf(value)
	switch ref.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return ref.IsNil()
	default:
		return false
	}
}
func (h *Handler) String() string   { return "deterministic evidence task handler" }
func (h *Handler) GoString() string { return "analysis.Handler{<redacted>}" }
func (h *Handler) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "deterministic evidence task handler", "analysis.Handler{<redacted>}")
}

var _ controlplane.TaskHandler = (*Handler)(nil)
