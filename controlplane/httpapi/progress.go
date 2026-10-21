package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	analysis "github.com/georgejieh/open-trestle/handlers/analysis"
	change "github.com/georgejieh/open-trestle/handlers/change"
	contextreader "github.com/georgejieh/open-trestle/handlers/context"
	model "github.com/georgejieh/open-trestle/handlers/model"
)

const (
	maxProgressArtifacts = 10
)

// WithProgressArtifacts returns a server clone with exact, read-only artifact retrieval.
// Configure the clone before serving requests.
func (s *Server) WithProgressArtifacts(reader artifact.Reader) (*Server, error) {
	if s == nil || reader == nil {
		return nil, ErrInvalidServer
	}
	value := reflect.ValueOf(reader)
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		if value.IsNil() {
			return nil, ErrInvalidServer
		}
	}
	clone := *s
	clone.progressArtifacts = reader
	return &clone, nil
}

type progressAxis struct {
	State            string `json:"state"`
	ArtifactIdentity string `json:"artifact_identity,omitempty"`
	Files            *int   `json:"files,omitempty"`
	Ranges           *int   `json:"ranges,omitempty"`
	ApplicableFiles  *int   `json:"applicable_files,omitempty"`
	ApplicableRanges *int   `json:"applicable_ranges,omitempty"`
	CheckedFiles     *int   `json:"checked_files,omitempty"`
	CheckedRanges    *int   `json:"checked_ranges,omitempty"`
	Observations     *int   `json:"observations,omitempty"`
	Analyzed         *int   `json:"analyzed,omitempty"`
	Selected         *int   `json:"selected,omitempty"`
	Omitted          *int   `json:"omitted,omitempty"`
	Candidates       *int   `json:"candidates,omitempty"`
	Verified         *int   `json:"verified,omitempty"`
	Rejected         *int   `json:"rejected,omitempty"`
	Inconclusive     *int   `json:"inconclusive,omitempty"`
}
type runProgress struct {
	Change        progressAxis `json:"change"`
	Deterministic progressAxis `json:"deterministic"`
	Context       progressAxis `json:"context"`
	Verification  progressAxis `json:"verification"`
}

func progressCount(value int) *int { return &value }
func taskProgressAxis(receipt controlplane.ReviewRunReceipt, kind controlplane.TaskKind) (progressAxis, string) {
	axis := progressAxis{State: "not_run"}
	id := ""
	seen := false
	for _, task := range receipt.Tasks() {
		if task.Kind() != kind {
			continue
		}
		if seen {
			return progressAxis{State: "unavailable"}, ""
		}
		seen = true
		if task.Status() == controlplane.TaskRuntimeSucceeded {
			id = task.OutputIdentity()
			axis = progressAxis{State: "unavailable", ArtifactIdentity: id}
		} else if task.Status() == controlplane.TaskRuntimeFailed || task.Status() == controlplane.TaskRuntimeSkipped {
			axis.State = "unavailable"
		}
	}
	return axis, id
}
func (s *Server) handleRunProgress(ctx context.Context, writer http.ResponseWriter, request *http.Request, requestID string, principal Principal, scope audit.ReviewScope, at time.Time) {
	if request.Method != http.MethodGet {
		writeMethodNotAllowed(writer, requestID, http.MethodGet)
		return
	}
	if !principalAllowsScope(principal, scope) || !principal.HasCapability(CapabilityRunRead) {
		writeForbidden(writer, requestID)
		return
	}
	if !requestHasEmptyBody(request) {
		writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "This endpoint does not accept a request body.")
		return
	}
	before, err := s.coordinator.Receipt(ctx, scope)
	if err != nil {
		s.writeCoordinatorError(writer, requestID, err)
		return
	}
	progress := s.readRunProgress(ctx, before, at)
	after, err := s.coordinator.Receipt(ctx, scope)
	if err != nil {
		s.writeCoordinatorError(writer, requestID, err)
		return
	}
	if before.Identity() != after.Identity() {
		writeAPIError(writer, http.StatusConflict, requestID, "progress_changed", "The review run advanced while progress was read.")
		return
	}
	encodedRun, err := controlplane.EncodeReviewRunReceipt(before)
	if err != nil {
		s.writeCoordinatorError(writer, requestID, err)
		return
	}
	response := struct {
		Contract      string          `json:"contract"`
		SchemaVersion int             `json:"schema_version"`
		RequestID     string          `json:"request_id"`
		Run           json.RawMessage `json:"run"`
		Progress      runProgress     `json:"progress"`
	}{"open-trestle/run-progress-response", 1, requestID, encodedRun, progress}
	encoded, err := json.Marshal(response)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "Progress could not be read.")
		return
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

type progressReads struct {
	reader artifact.Reader
	scope  audit.ReviewScope
	at     time.Time
	values map[string]artifact.Artifact
	loads  int
}

func (r *progressReads) get(ctx context.Context, id string) (artifact.Artifact, error) {
	if value, ok := r.values[id]; ok {
		return value, nil
	}
	if r.reader == nil || r.loads >= maxProgressArtifacts {
		return artifact.Artifact{}, ErrInvalidServer
	}
	r.loads++
	value, err := r.reader.Get(ctx, r.scope, id, r.at)
	if err != nil {
		return artifact.Artifact{}, err
	}
	if value.Identity() != id || value.Scope().Identity() != r.scope.Identity() || value.Validate() != nil || r.at.Before(value.CreatedAt()) || !r.at.Before(value.ExpiresAt()) {
		return artifact.Artifact{}, ErrInvalidServer
	}
	r.values[id] = value
	return value, nil
}
func (s *Server) readRunProgress(ctx context.Context, receipt controlplane.ReviewRunReceipt, at time.Time) runProgress {
	changeAxis, changeID := taskProgressAxis(receipt, controlplane.TaskBuildChange)
	analysisAxis, analysisID := taskProgressAxis(receipt, controlplane.TaskInspectDeterministic)
	contextAxis, contextID := taskProgressAxis(receipt, controlplane.TaskAssembleContext)
	verificationAxis, verificationID := taskProgressAxis(receipt, controlplane.TaskVerifyCandidates)
	progress := runProgress{changeAxis, analysisAxis, contextAxis, verificationAxis}
	reads := &progressReads{reader: s.progressArtifacts, scope: receipt.Scope(), at: at, values: make(map[string]artifact.Artifact)}
	if changeID == "" {
		return progress
	}
	changeArtifact, err := reads.get(ctx, changeID)
	if err != nil {
		return progress
	}
	baseID, headID, err := change.ResultArtifactReferences(changeArtifact)
	if err != nil || !progressSourcesMatch(receipt, baseID, headID) {
		return progress
	}
	base, err := reads.get(ctx, baseID)
	if err != nil {
		return progress
	}
	head, err := reads.get(ctx, headID)
	if err != nil {
		return progress
	}
	changed, err := change.ParseResultArtifact(changeArtifact, base, head)
	if err != nil {
		return progress
	}
	ranges := 0
	for _, entry := range changed.Entries() {
		ranges += len(entry.Ranges())
	}
	progress.Change.State = "available"
	progress.Change.Files, progress.Change.Ranges = progressCount(len(changed.Entries())), progressCount(ranges)
	if analysisID == "" {
		return progress
	}
	evidence, err := reads.get(ctx, analysisID)
	if err != nil {
		return progress
	}
	analyzed, err := analysis.ParseResultArtifact(evidence, changeArtifact, base, head)
	if err != nil {
		return progress
	}
	progress.Deterministic.State = "available"
	checks := analyzed.Checks()
	if len(checks) == 1 {
		c := checks[0]
		if !c.Complete() {
			progress.Deterministic.State = "partial"
		}
		progress.Deterministic.ApplicableFiles, progress.Deterministic.ApplicableRanges = progressCount(int(c.ApplicableFiles())), progressCount(int(c.ApplicableRanges()))
		progress.Deterministic.CheckedFiles, progress.Deterministic.CheckedRanges = progressCount(int(c.CheckedFiles())), progressCount(int(c.CheckedRanges()))
	}
	if analyzed.SchemaVersion() >= 4 {
		progress.Deterministic.Observations = progressCount(len(analyzed.Observations()))
	}
	if contextID == "" {
		return progress
	}
	output, err := reads.get(ctx, contextID)
	if err != nil {
		return progress
	}
	coverage, err := contextreader.ReadRecordedSourceCoverage(ctx, progressScopedReads{reads}, at, output, evidence, changeArtifact, base, head)
	if err != nil {
		return progress
	}
	packet := coverage.PacketArtifact()
	packetID := packet.Identity()
	progress.Context.State = "available"
	progress.Context.ArtifactIdentity = packetID
	progress.Context.Analyzed, progress.Context.Selected, progress.Context.Omitted = progressCount(coverage.Analyzed()), progressCount(coverage.Selected()), progressCount(coverage.Omitted())
	_, generationID := taskProgressAxis(receipt, controlplane.TaskGenerateCandidates)
	if generationID == "" {
		return progress
	}
	generationArtifact, err := reads.get(ctx, generationID)
	if err != nil {
		return progress
	}
	inputID, referencedPacket, err := model.GenerationResultReferences(generationArtifact)
	if err != nil || referencedPacket != packetID || contextID != packetID && contextID != inputID {
		return progress
	}
	inputArtifact, err := reads.get(ctx, inputID)
	if err != nil {
		return progress
	}
	if _, err = model.ParseGenerationResultArtifact(generationArtifact, inputArtifact, packet); err != nil {
		return progress
	}
	if verificationID == "" {
		return progress
	}
	verificationArtifact, err := reads.get(ctx, verificationID)
	if err != nil {
		return progress
	}
	referencedGeneration, err := model.VerificationResultReferences(verificationArtifact)
	if err != nil || referencedGeneration != generationID {
		return progress
	}
	requestID, receiptID, egress, err := model.VerificationResultEgressReferences(verificationArtifact)
	if err != nil {
		return progress
	}
	var authorities []model.VerificationEgressArtifacts
	if egress {
		requestArtifact, err := reads.get(ctx, requestID)
		if err != nil {
			return progress
		}
		receiptArtifact, err := reads.get(ctx, receiptID)
		if err != nil {
			return progress
		}
		authorities = []model.VerificationEgressArtifacts{{SanitizedRequest: requestArtifact, Receipt: receiptArtifact}}
	}
	verified, err := model.ParseVerificationResultArtifact(verificationArtifact, generationArtifact, inputArtifact, packet, authorities...)
	if err != nil {
		return progress
	}
	findings := verified.VerifiedFindings()
	progress.Verification.State = "available"
	progress.Verification.Candidates, progress.Verification.Verified = progressCount(int(findings.CandidateCount())), progressCount(int(findings.VerifiedCount()))
	progress.Verification.Rejected, progress.Verification.Inconclusive = progressCount(int(findings.RejectedCount())), progressCount(int(findings.InconclusiveCount()))
	return progress
}
func progressSourcesMatch(receipt controlplane.ReviewRunReceipt, base, head string) bool {
	hasBase, hasHead := false, false
	for _, task := range receipt.Tasks() {
		if task.Kind() == controlplane.TaskAcquireSource && task.Status() == controlplane.TaskRuntimeSucceeded {
			hasBase = hasBase || task.OutputIdentity() == base
			hasHead = hasHead || task.OutputIdentity() == head
		}
	}
	return hasBase && hasHead
}

type progressScopedReads struct{ reads *progressReads }

func (r progressScopedReads) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	if scope.Identity() != r.reads.scope.Identity() || !at.Equal(r.reads.at) {
		return artifact.Artifact{}, ErrInvalidServer
	}
	return r.reads.get(ctx, id)
}
