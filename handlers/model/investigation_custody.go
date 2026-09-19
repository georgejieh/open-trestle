package model

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
)

type investigationCapture struct {
	store   artifact.Store
	scope   audit.ReviewScope
	mu      sync.Mutex
	allowed map[string]artifact.Artifact
	got     map[string]artifact.Artifact
}

func (s *investigationCapture) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	s.mu.Lock()
	expected, ok := s.allowed[id]
	s.mu.Unlock()
	if !ok || scope != s.scope {
		return artifact.Artifact{}, ErrInvestigation
	}
	value, err := s.store.Get(ctx, scope, id, at)
	if err != nil {
		return artifact.Artifact{}, err
	}
	if !toolRecordSameArtifact(value, expected) {
		return artifact.Artifact{}, ErrInvestigation
	}
	if value.Kind() == artifact.KindSourceFile {
		s.mu.Lock()
		s.got[id] = value
		s.mu.Unlock()
	}
	return value, nil
}
func (s *investigationCapture) captured(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.got[id]
	return ok
}

type investigationHeldTool struct {
	operation  InvestigationToolOperation
	invocation InvestigationToolInvocation
	result     InvestigationToolResult
	artifact   artifact.Artifact
}

// InvestigationGenerationCustody is a live controller-owned witness, never a decoded success.
type InvestigationGenerationCustody struct {
	owner                                        *Investigation
	context                                      review.InvestigationGenerationContext
	contextArtifact, input, result, turnArtifact artifact.Artifact
	turn                                         gateway.InvestigationTurnRecord
	inputValue                                   AdmittedInvestigationGenerationInput
	resultValue                                  AdmittedInvestigationGenerationResult
	tools                                        []investigationHeldTool
	sources                                      []review.ContextSource
	expires                                      time.Time
}

func (w *InvestigationGenerationCustody) live(at time.Time) bool {
	if w == nil || w.owner == nil {
		return false
	}
	c := w.owner
	c.mu.Lock()
	bad := c.closed || c.closing || c.failed || c.finalCustody != w
	c.mu.Unlock()
	if bad || c.root.Err() != nil || !time.Now().Before(c.wallDeadline) {
		return false
	}
	now := c.options.Clock.Now()
	if !now.Before(w.expires) {
		c.cancel()
		return false
	}
	return at.UnixMilli() > 0 && now.UnixMilli() > 0 && now.Before(w.expires) && at.Before(w.expires) && !at.Before(w.contextArtifact.CreatedAt()) && c.acquisitionLive(now)
}
func (c *Investigation) acquisitionLive(at time.Time) bool {
	a := c.options.Acquisition
	if a == nil || a.owner == nil {
		return false
	}
	h := a.owner
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.closing || a.headIdentity != c.options.HeadSnapshotArtifactIdentity || a.scopeIdentity != c.options.Scope.Identity() || h.planIdentity != a.planIdentity || at.Before(a.created) || !at.Before(a.expires) {
		return false
	}
	for _, slot := range h.slots {
		if slot.handle == a {
			return true
		}
	}
	return false
}
func (c *Investigation) sourceView(ids []string) bool {
	if len(ids) > 128 {
		return false
	}
	remaining := (16 << 20) - c.head.PayloadSizeBytes()
	if remaining < 0 {
		return false
	}
	seen := map[string]bool{}
	for id := range c.retained {
		seen[id] = true
	}
	for _, id := range ids {
		seen[id] = true
	}
	for id := range seen {
		value, ok := c.files[id]
		if !ok {
			return false
		}
		n := value.PayloadSizeBytes()
		if n <= 0 || n > remaining/2 {
			return false
		}
		remaining -= 2 * n
	}
	return len(seen) <= 128
}
func (c *Investigation) holdSource(s review.ContextSource, fileID string) error {
	if !c.capture.captured(fileID) || s.Validate() != nil || !s.HasSliceBinding() {
		return ErrInvestigation
	}
	value, ok := c.files[fileID]
	if !ok {
		return ErrInvestigation
	}
	c.retained[fileID] = value
	for _, prior := range c.candidates {
		if prior.SliceBinding().Identity() == s.SliceBinding().Identity() {
			return nil
		}
	}
	if len(c.candidates) >= 128 {
		return ErrInvestigation
	}
	c.candidates = append(c.candidates, s)
	return nil
}
func (c *Investigation) selectedSnapshot(sources []review.ContextSource) (review.ReviewSnapshot, error) {
	type row struct {
		Path  string `json:"path"`
		Start int    `json:"start"`
		End   int    `json:"end"`
		File  string `json:"file"`
	}
	rows := make([]row, 0, len(sources))
	ranges := make([]evidence.SourceRange, 0, len(sources))
	for _, s := range sources {
		b := s.SliceBinding()
		r := b.SourceRange()
		rows = append(rows, row{r.Path(), r.StartLine(), r.EndLine(), b.RepositoryFileIdentity()})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		return a.End < b.End
	})
	rows = slices.Compact(rows)
	for _, row := range rows {
		r, err := evidence.NewSourceRange(row.Path, row.Start, row.End)
		if err != nil {
			return review.ReviewSnapshot{}, err
		}
		ranges = append(ranges, r)
	}
	encoded, _ := json.Marshal(struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Manifest string `json:"manifest"`
		Ranges   []row  `json:"ranges"`
	}{"open-trestle/acquired-review-range-set", 1, c.snapshot.ManifestIdentity(), rows})
	return review.NewReviewSnapshot(c.options.InitialSnapshot.Workspace(), artifactPayloadHash(encoded), ranges)
}
func (c *Investigation) rebuildContext(turn uint8, prior gateway.InvestigationTurnRecord, newIDs []string) (review.InvestigationGenerationContext, error) {
	packet := c.options.InitialContext
	snapshot := c.options.InitialSnapshot
	if turn > 1 {
		selected, err := review.SelectContextSources(c.candidates, c.limits)
		if err != nil {
			return review.InvestigationGenerationContext{}, err
		}
		snapshot, err = c.selectedSnapshot(selected.SelectedSources())
		if err != nil {
			return review.InvestigationGenerationContext{}, err
		}
		packet, err = review.NewContextPacketWithAccounting(c.options.Scope, c.options.MemoryScope, snapshot, review.ContextTaskCandidateGeneration, c.candidates, c.options.InitialContext.Retrievals(), c.options.InitialContext.SourceOmissions(), c.limits)
		if err != nil {
			return review.InvestigationGenerationContext{}, err
		}
	}
	state := review.InvestigationContextState{Turn: turn, ScannedBytes: c.scanned, ReturnedBytes: c.returned, ToolCallsUsed: uint8(len(c.tools)), NewResultArtifactIdentities: append([]string(nil), newIDs...)}
	if turn > 1 {
		state.PreviousRequestIdentity = prior.RequestIdentity()
		state.PreviousOutcomeIdentity = prior.Outcome().Identity()
	}
	for _, tool := range c.tools {
		annotation, err := review.NewInvestigationResultAnnotation(tool.artifact.Identity(), tool.artifact.Payload())
		if err != nil {
			return review.InvestigationGenerationContext{}, err
		}
		state.Results = append(state.Results, annotation)
	}
	return review.NewInvestigationGenerationContext(c.binding, packet, snapshot, state)
}
func (c *Investigation) contextArtifact(value review.InvestigationGenerationContext, at time.Time) (artifact.Artifact, error) {
	request, err := value.ProviderRequest()
	if err != nil {
		return artifact.Artifact{}, err
	}
	provenance := []string{c.head.Identity(), c.binding.Identity(), c.options.Policy.Identity()}
	sort.Strings(provenance)
	return artifact.New(c.options.Scope, artifact.KindContextPacket, "application/json", c.head.Classification(), artifact.OriginHost, c.head.Protection(), provenance, request.Payload(), at, c.expires)
}
func (c *Investigation) readInitial(ctx context.Context) error {
	files := []string{}
	for _, s := range c.options.InitialContext.Sources() {
		ref, ok := c.byPath[s.EvidenceItem().SourceRange().Path()]
		if !ok || !c.options.MemoryScope.AllowsPath(ref.Path()) {
			return ErrInvestigation
		}
		files = append(files, ref.ArtifactIdentity())
	}
	if !c.sourceView(files) {
		return ErrInvestigation
	}
	var total uint64
	for _, s := range c.options.InitialContext.Sources() {
		r := s.EvidenceItem().SourceRange()
		ref := c.byPath[r.Path()]
		n := uint64(ref.SizeBytes())
		if n > c.options.Policy.MaxScannedBytes()-total || r.EndLine()-r.StartLine()+1 > c.readerLimits.MaxLines {
			return ErrInvestigation
		}
		total += n
	}
	for _, s := range c.options.InitialContext.Sources() {
		r := s.EvidenceItem().SourceRange()
		ref := c.byPath[r.Path()]
		if uint64(ref.SizeBytes()) > c.options.Policy.MaxScannedBytes()-c.scanned {
			return ErrInvestigation
		}
		c.reservedScan = uint64(ref.SizeBytes())
		read, err := c.reader.Read(ctx, ref.Ref(), r.StartLine(), r.EndLine())
		if err != nil {
			return err
		}
		c.scanned += read.ScannedBytes()
		c.reservedScan = 0
		if read.ScannedBytes() != uint64(ref.SizeBytes()) || read.Binding().Identity() != s.SliceBinding().Identity() || !bytes.Equal(read.Content(), s.Content()) {
			return ErrInvestigation
		}
		if !c.capture.captured(ref.ArtifactIdentity()) || s.Validate() != nil {
			return ErrInvestigation
		}
		c.retained[ref.ArtifactIdentity()] = c.files[ref.ArtifactIdentity()]
		c.candidates = append(c.candidates, s)
	}
	return nil
}
func (w *InvestigationGenerationCustody) String() string {
	return "live investigation generation custody"
}
func (w *InvestigationGenerationCustody) GoString() string {
	return "model.InvestigationGenerationCustody{<redacted>}"
}
