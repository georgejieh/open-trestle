package publication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/review"
	"io"
	"reflect"
	"sort"
	"time"
)

const maximumReadinessBytes = 64 << 10

var (
	ErrInvalidReadinessHandler = errors.New("invalid publication readiness handler")
	ErrInvalidReadinessResult  = errors.New("invalid publication readiness result")
)

type ReadinessHandler struct {
	identity             string
	store                artifact.Store
	diagnosticStore      diagnostics.Store
	clock                artifact.Clock
	reviewPolicyIdentity string
	publicationPolicy    review.PublicationPolicy
	pipeline             *modelhandler.InvestigationPipeline
}

func NewReadinessHandler(store artifact.Store, diagnosticStore diagnostics.Store, clock artifact.Clock, reviewPolicyIdentity string, policy review.PublicationPolicy) (*ReadinessHandler, error) {
	if nilInterface(store) || nilInterface(diagnosticStore) || nilInterface(clock) || !validDigest(reviewPolicyIdentity) || policy.Validate() != nil {
		return nil, ErrInvalidReadinessHandler
	}
	h := &ReadinessHandler{store: store, diagnosticStore: diagnosticStore, clock: clock, reviewPolicyIdentity: reviewPolicyIdentity, publicationPolicy: policy}
	h.identity = deriveHandlerIdentity(reviewPolicyIdentity, policy.Identity())
	return h, nil
}
func NewInvestigationReadinessHandler(store artifact.Store, diagnosticStore diagnostics.Store, clock artifact.Clock, reviewPolicyIdentity string, policy review.PublicationPolicy, pipeline *modelhandler.InvestigationPipeline) (*ReadinessHandler, error) {
	if nilInterface(store) || nilInterface(diagnosticStore) || nilInterface(clock) || !validDigest(reviewPolicyIdentity) || policy.Validate() != nil || pipeline == nil || pipeline.Validate() != nil {
		return nil, ErrInvalidReadinessHandler
	}
	profile := pipeline.Profile()
	if profile.ReviewPolicyIdentity() != reviewPolicyIdentity || profile.PublicationPolicyIdentity() != policy.Identity() {
		return nil, ErrInvalidReadinessHandler
	}
	identity, err := pipeline.HandlerIdentity(controlplane.TaskEvaluatePublication)
	if err != nil || !validDigest(identity) {
		return nil, ErrInvalidReadinessHandler
	}
	return &ReadinessHandler{identity: identity, store: store, diagnosticStore: diagnosticStore, clock: clock, reviewPolicyIdentity: reviewPolicyIdentity, publicationPolicy: policy, pipeline: pipeline}, nil
}
func (h *ReadinessHandler) HandlerIdentity() string {
	if h == nil {
		return ""
	}
	if h.pipeline != nil {
		identity, err := h.pipeline.HandlerIdentity(controlplane.TaskEvaluatePublication)
		if err != nil {
			return ""
		}
		return identity
	}
	return h.identity
}
func (h *ReadinessHandler) Kind() controlplane.TaskKind {
	if h == nil {
		return 0
	}
	return controlplane.TaskEvaluatePublication
}
func (h *ReadinessHandler) Validate() error {
	if h == nil || nilInterface(h.store) || nilInterface(h.diagnosticStore) || nilInterface(h.clock) || !validDigest(h.reviewPolicyIdentity) || h.publicationPolicy.Validate() != nil {
		return ErrInvalidReadinessHandler
	}
	if h.pipeline != nil {
		identity, err := h.pipeline.HandlerIdentity(controlplane.TaskEvaluatePublication)
		profile := h.pipeline.Profile()
		if h.pipeline.Validate() != nil || err != nil || !validDigest(identity) || h.identity != identity || profile.ReviewPolicyIdentity() != h.reviewPolicyIdentity || profile.PublicationPolicyIdentity() != h.publicationPolicy.Identity() {
			return ErrInvalidReadinessHandler
		}
		return nil
	}
	if h.identity != deriveHandlerIdentity(h.reviewPolicyIdentity, h.publicationPolicy.Identity()) {
		return ErrInvalidReadinessHandler
	}
	return nil
}
func deriveHandlerIdentity(reviewPolicy, publicationPolicy string) string {
	encoded, _ := json.Marshal(struct {
		Contract          string `json:"contract"`
		Version           int    `json:"version"`
		ReviewPolicy      string `json:"review_policy"`
		PublicationPolicy string `json:"publication_policy"`
	}{"open-trestle/publication-readiness-handler", 5, reviewPolicy, publicationPolicy})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

type Result struct {
	identity, artifactIdentity, verificationArtifactIdentity, verificationResultIdentity, publicationPolicyIdentity, readinessIdentity string
	status                                                                                                                             review.PublicationReadinessStatus
	verified, rejected, inconclusive, belowThreshold                                                                                   uint8
	inline, summary                                                                                                                    int
}

func (r Result) Identity() string                          { return r.identity }
func (r Result) ArtifactIdentity() string                  { return r.artifactIdentity }
func (r Result) ReadinessIdentity() string                 { return r.readinessIdentity }
func (r Result) Status() review.PublicationReadinessStatus { return r.status }
func (r Result) Ready() bool                               { return r.status == review.PublicationAdvisoryReady }
func (r Result) String() string                            { return "publication readiness result" }
func (r Result) GoString() string                          { return "publication.Result{<redacted>}" }
func (r Result) Format(s fmt.State, v rune) {
	writeRedacted(s, v, "publication readiness result", "publication.Result{<redacted>}")
}

type resultWire struct {
	Contract                     string `json:"contract"`
	SchemaVersion                int    `json:"schema_version"`
	Identity                     string `json:"identity"`
	VerificationArtifactIdentity string `json:"verification_artifact_identity"`
	VerificationResultIdentity   string `json:"verification_result_identity"`
	PublicationPolicyIdentity    string `json:"publication_policy_identity"`
	ReadinessIdentity            string `json:"readiness_identity"`
	Status                       string `json:"status"`
	Verified                     uint8  `json:"verified"`
	Rejected                     uint8  `json:"rejected"`
	Inconclusive                 uint8  `json:"inconclusive"`
	BelowThreshold               uint8  `json:"below_threshold"`
	Inline                       int    `json:"inline"`
	SummaryOnly                  int    `json:"summary_only"`
}

func newResult(artifactID string, verification modelhandler.VerificationResult, readiness review.PublicationReadiness) Result {
	r := Result{verificationArtifactIdentity: artifactID, verificationResultIdentity: verification.Identity(), publicationPolicyIdentity: readiness.PolicyIdentity(), readinessIdentity: readiness.Identity(), status: readiness.Status(), verified: readiness.VerifiedCount(), rejected: readiness.RejectedCount(), inconclusive: readiness.InconclusiveCount(), belowThreshold: readiness.BelowThresholdCount(), inline: len(readiness.InlineFindings()), summary: readiness.SummaryOnlyCount()}
	r.identity = deriveResultIdentity(r)
	return r
}
func (r Result) validate(verificationArtifact artifact.Artifact, verification modelhandler.VerificationResult, policy review.PublicationPolicy) error {
	readiness, err := review.EvaluatePublicationReadiness(policy, verification.IndependentReceipt(), verification.VerifiedFindings())
	if err != nil || r.verificationArtifactIdentity != verificationArtifact.Identity() || r.verificationResultIdentity != verification.Identity() || r.publicationPolicyIdentity != policy.Identity() || r.readinessIdentity != readiness.Identity() || r.status != readiness.Status() || r.verified != readiness.VerifiedCount() || r.rejected != readiness.RejectedCount() || r.inconclusive != readiness.InconclusiveCount() || r.belowThreshold != readiness.BelowThresholdCount() || r.inline != len(readiness.InlineFindings()) || r.summary != readiness.SummaryOnlyCount() || r.identity != deriveResultIdentity(r) {
		return ErrInvalidReadinessResult
	}
	return nil
}
func toWire(r Result) resultWire {
	return resultWire{"open-trestle/publication-readiness-result", 1, r.identity, r.verificationArtifactIdentity, r.verificationResultIdentity, r.publicationPolicyIdentity, r.readinessIdentity, r.status.String(), r.verified, r.rejected, r.inconclusive, r.belowThreshold, r.inline, r.summary}
}
func deriveResultIdentity(r Result) string {
	wire := toWire(r)
	wire.Identity = ""
	encoded, _ := json.Marshal(wire)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func encodeResult(r Result) ([]byte, error) {
	encoded, err := json.Marshal(toWire(r))
	if err != nil || len(encoded) > maximumReadinessBytes {
		return nil, ErrInvalidReadinessResult
	}
	return encoded, nil
}
func parseResult(value artifact.Artifact, verificationArtifact artifact.Artifact, verification modelhandler.VerificationResult, policy review.PublicationPolicy) (Result, error) {
	if value.Validate() != nil || value.Kind() != artifact.KindPublicationPlan || value.MediaType() != "application/json" || value.Origin() != artifact.OriginPolicy || value.Scope().Identity() != verificationArtifact.Scope().Identity() || value.Classification() != verificationArtifact.Classification() || value.Protection() != verificationArtifact.Protection() || !contains(value.Provenance(), verificationArtifact.Identity()) || !contains(value.Provenance(), policy.Identity()) {
		return Result{}, ErrInvalidReadinessResult
	}
	payload := value.Payload()
	if len(payload) == 0 || len(payload) > maximumReadinessBytes {
		return Result{}, ErrInvalidReadinessResult
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire resultWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Result{}, ErrInvalidReadinessResult
	}
	canonical, _ := json.Marshal(wire)
	status, err := review.ParsePublicationReadinessStatus(wire.Status)
	if err != nil || !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/publication-readiness-result" || wire.SchemaVersion != 1 {
		return Result{}, ErrInvalidReadinessResult
	}
	r := Result{identity: wire.Identity, artifactIdentity: value.Identity(), verificationArtifactIdentity: wire.VerificationArtifactIdentity, verificationResultIdentity: wire.VerificationResultIdentity, publicationPolicyIdentity: wire.PublicationPolicyIdentity, readinessIdentity: wire.ReadinessIdentity, status: status, verified: wire.Verified, rejected: wire.Rejected, inconclusive: wire.Inconclusive, belowThreshold: wire.BelowThreshold, inline: wire.Inline, summary: wire.SummaryOnly}
	if r.validate(verificationArtifact, verification, policy) != nil {
		return Result{}, ErrInvalidReadinessResult
	}
	return r, nil
}
func (h *ReadinessHandler) Execute(ctx context.Context, request controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if nilInterface(ctx) || h.Validate() != nil || request.Validate() != nil || request.Task().Kind() != controlplane.TaskEvaluatePublication || request.Task().HandlerIdentity() != h.identity || request.Plan().PolicyIdentity() != h.reviewPolicyIdentity || !equalStrings(request.Task().Dependencies(), []string{"analysis", "change", "verification"}) {
		return failure(controlplane.RunFailureInvalidInput)
	}
	if ctx.Err() != nil {
		return failure(controlplane.RunFailureCanceled)
	}
	at := h.clock.Now().UTC()
	if at.UnixMilli() <= 0 || at.After(request.Lease().ExpiresAt()) {
		return failure(controlplane.RunFailureCanceled)
	}
	verificationDependency, ok := request.DependencyOutput("verification")
	if !ok || !verificationDependency.Available() {
		return failure(controlplane.RunFailureInvalidInput)
	}
	changeDependency, ok := request.DependencyOutput("change")
	if !ok || !changeDependency.Available() {
		return failure(controlplane.RunFailureInvalidInput)
	}
	analysisDependency, ok := request.DependencyOutput("analysis")
	if !ok || !analysisDependency.Available() {
		return failure(controlplane.RunFailureInvalidInput)
	}
	verificationArtifact, err := h.store.Get(ctx, request.Plan().Scope(), verificationDependency.OutputIdentity(), at)
	if err != nil {
		return failure(readFailure(ctx, err))
	}
	changeArtifact, err := h.store.Get(ctx, request.Plan().Scope(), changeDependency.OutputIdentity(), at)
	if err != nil {
		return failure(readFailure(ctx, err))
	}
	analysisArtifact, err := h.store.Get(ctx, request.Plan().Scope(), analysisDependency.OutputIdentity(), at)
	if err != nil {
		return failure(readFailure(ctx, err))
	}
	baseSnapshotID, headSnapshotID, err := changehandler.ResultArtifactReferences(changeArtifact)
	if err != nil {
		return failure(controlplane.RunFailureInvalidInput)
	}
	baseSnapshotArtifact, err := h.store.Get(ctx, request.Plan().Scope(), baseSnapshotID, at)
	if err != nil {
		return failure(readFailure(ctx, err))
	}
	headSnapshotArtifact, err := h.store.Get(ctx, request.Plan().Scope(), headSnapshotID, at)
	if err != nil {
		return failure(readFailure(ctx, err))
	}
	changeResult, err := changehandler.ParseResultArtifact(changeArtifact, baseSnapshotArtifact, headSnapshotArtifact)
	if err != nil || changeArtifact.Classification() != verificationArtifact.Classification() || changeArtifact.Protection() != verificationArtifact.Protection() {
		return failure(controlplane.RunFailureInvalidInput)
	}
	analysisResult, err := analysishandler.ParseResultArtifact(analysisArtifact, changeArtifact, baseSnapshotArtifact, headSnapshotArtifact)
	if err != nil || analysisArtifact.Classification() != verificationArtifact.Classification() || analysisArtifact.Protection() != verificationArtifact.Protection() {
		return failure(controlplane.RunFailureInvalidInput)
	}
	deterministicChecks, err := diagnosticDeterministicChecks(analysisResult, changeResult)
	if err != nil {
		return failure(controlplane.RunFailureInvalidInput)
	}
	var generationArtifact, inputArtifact, contextArtifact artifact.Artifact
	var verification modelhandler.VerificationResult
	var investigationExpires time.Time
	if h.pipeline != nil {
		view, err := h.pipeline.ForReadiness(ctx, request)
		if err != nil {
			return failure(readFailure(ctx, err))
		}
		if view.PlanIdentity() != request.Plan().Identity() || view.ScopeIdentity() != request.Plan().Scope().Identity() || view.AnalysisArtifactIdentity() != analysisArtifact.Identity() || view.ChangeArtifactIdentity() != changeArtifact.Identity() || view.HeadSnapshotArtifactIdentity() != headSnapshotArtifact.Identity() || view.VerificationArtifact().Identity() != verificationArtifact.Identity() {
			return failure(controlplane.RunFailureInvalidInput)
		}
		initialContext := view.InitialContextArtifact()
		if initialContext.Validate() != nil || initialContext.Kind() != artifact.KindContextPacket || initialContext.Scope().Identity() != request.Plan().Scope().Identity() || !contains(initialContext.Provenance(), analysisArtifact.Identity()) || !contains(initialContext.Provenance(), changeArtifact.Identity()) || !contains(initialContext.Provenance(), headSnapshotArtifact.Identity()) {
			return failure(controlplane.RunFailureInvalidInput)
		}
		generation, hasGeneration := view.Generation()
		var hasVerification bool
		verification, hasVerification = view.Verification()
		if !hasGeneration || !hasVerification || verification.Validate() != nil || verification.ArtifactIdentity() != verificationArtifact.Identity() || verification.GenerationArtifactIdentity() != generation.ResultArtifact().Identity() {
			return failure(controlplane.RunFailureInvalidInput)
		}
		generationArtifact, inputArtifact, contextArtifact = generation.ResultArtifact(), generation.InputArtifact(), generation.ContextArtifact()
		if generationArtifact.Validate() != nil || inputArtifact.Validate() != nil || contextArtifact.Validate() != nil {
			return failure(controlplane.RunFailureInvalidInput)
		}
		investigationExpires = minimumTime(initialContext.ExpiresAt(), view.ContextIntentArtifact().ExpiresAt())
	} else {
		generationID, err := modelhandler.VerificationResultReferences(verificationArtifact)
		if err != nil {
			return failure(controlplane.RunFailureInvalidInput)
		}
		generationArtifact, err = h.store.Get(ctx, request.Plan().Scope(), generationID, at)
		if err != nil {
			return failure(readFailure(ctx, err))
		}
		inputID, contextID, err := modelhandler.GenerationResultReferences(generationArtifact)
		if err != nil {
			return failure(controlplane.RunFailureInvalidInput)
		}
		inputArtifact, err = h.store.Get(ctx, request.Plan().Scope(), inputID, at)
		if err != nil {
			return failure(readFailure(ctx, err))
		}
		contextArtifact, err = h.store.Get(ctx, request.Plan().Scope(), contextID, at)
		if err != nil {
			return failure(readFailure(ctx, err))
		}
		verification, err = modelhandler.ParseVerificationResultArtifact(verificationArtifact, generationArtifact, inputArtifact, contextArtifact)
		if err != nil || !contains(contextArtifact.Provenance(), analysisArtifact.Identity()) || !contains(contextArtifact.Provenance(), changeArtifact.Identity()) || !contains(contextArtifact.Provenance(), headSnapshotArtifact.Identity()) {
			return failure(controlplane.RunFailureInvalidInput)
		}
	}
	if _, _, err := review.MaterializeDiagnosticSetWithDeterministicChecks(
		ctx, h.diagnosticStore, request.Plan().Scope(), changeResult.HeadRevision().Digest(),
		verification.IndependentReceipt(), verification.VerifiedFindings(), verification.VerificationContext().SourceCoverage(), deterministicChecks,
	); err != nil {
		return failure(diagnosticWriteFailure(ctx, err))
	}
	readiness, err := review.EvaluatePublicationReadiness(h.publicationPolicy, verification.IndependentReceipt(), verification.VerifiedFindings())
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	result := newResult(verificationArtifact.Identity(), verification, readiness)
	if result.validate(verificationArtifact, verification, h.publicationPolicy) != nil {
		return failure(controlplane.RunFailureInternal)
	}
	payload, err := encodeResult(result)
	if err != nil {
		return failure(controlplane.RunFailureResourceLimit)
	}
	expires := minimumTime(
		verificationArtifact.ExpiresAt(), generationArtifact.ExpiresAt(), inputArtifact.ExpiresAt(), contextArtifact.ExpiresAt(),
		analysisArtifact.ExpiresAt(), changeArtifact.ExpiresAt(), baseSnapshotArtifact.ExpiresAt(), headSnapshotArtifact.ExpiresAt(),
	)
	if h.pipeline != nil {
		expires = minimumTime(expires, investigationExpires)
	}
	provenance := []string{
		verificationArtifact.Identity(), verification.Identity(), verification.IndependentReceipt().Identity(), verification.VerifiedFindings().Identity(),
		analysisArtifact.Identity(), analysisResult.Identity(), analysisResult.Checks()[0].Identity(), deterministicChecks[0].Identity(),
		changeArtifact.Identity(), changeResult.Identity(), changeResult.HeadRevision().Identity(), h.publicationPolicy.Identity(), h.reviewPolicyIdentity,
	}
	sort.Strings(provenance)
	output, err := artifact.New(request.Plan().Scope(), artifact.KindPublicationPlan, "application/json", verificationArtifact.Classification(), artifact.OriginPolicy, verificationArtifact.Protection(), provenance, payload, at, expires)
	if err != nil {
		return failure(controlplane.RunFailureResourceLimit)
	}
	if _, err := h.store.Put(ctx, output, at); err != nil {
		return failure(writeFailure(ctx, err))
	}
	completion, err := controlplane.NewTaskSuccess(output.Identity())
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	return completion
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
func diagnosticDeterministicChecks(analysis analysishandler.Result, change changehandler.Result) ([]diagnostics.DeterministicCheck, error) {
	checks := analysis.Checks()
	if analysis.SchemaVersion() != 3 || len(checks) != 1 || analysis.ChangeIdentity() != change.Identity() {
		return nil, ErrInvalidReadinessResult
	}
	check, err := diagnosticDeterministicCheck(checks[0], analysis.Identity(), change.Identity())
	if err != nil {
		return nil, err
	}
	return []diagnostics.DeterministicCheck{check}, nil
}

func diagnosticDeterministicCheck(source analysishandler.DeterministicCheck, analysisIdentity, changeIdentity string) (diagnostics.DeterministicCheck, error) {
	var state diagnostics.DeterministicCheckState
	switch source.State() {
	case analysishandler.CheckPassed:
		state = diagnostics.CheckPassed
	case analysishandler.CheckFailed:
		state = diagnostics.CheckFailed
	case analysishandler.CheckIncomplete:
		state = diagnostics.CheckIncomplete
	case analysishandler.CheckNotApplicable:
		state = diagnostics.CheckNotApplicable
	default:
		return diagnostics.DeterministicCheck{}, ErrInvalidReadinessResult
	}
	check, err := diagnostics.NewDeterministicCheck(source.Identity(), analysisIdentity, changeIdentity, state, source.ApplicableFiles(), source.ApplicableRanges(), source.CheckedFiles(), source.CheckedRanges(), source.MatchCount())
	if err != nil {
		return diagnostics.DeterministicCheck{}, ErrInvalidReadinessResult
	}
	return check, nil
}

func diagnosticWriteFailure(ctx context.Context, err error) controlplane.RunFailure {
	if ctx.Err() != nil || errors.Is(err, diagnostics.ErrStoreContextDone) {
		return controlplane.RunFailureCanceled
	}
	if errors.Is(err, diagnostics.ErrStoreCapacity) || errors.Is(err, artifact.ErrStoreCapacity) {
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
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func nilInterface(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	default:
		return false
	}
}
func validDigest(v string) bool {
	if len(v) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(v)
	return err == nil && hex.EncodeToString(decoded) == v && v != "0000000000000000000000000000000000000000000000000000000000000000"
}
func contains(v []string, target string) bool {
	for _, x := range v {
		if x == target {
			return true
		}
	}
	return false
}
func minimumTime(v ...time.Time) time.Time {
	r := v[0]
	for _, x := range v[1:] {
		if x.Before(r) {
			r = x
		}
	}
	return r
}
func writeRedacted(s fmt.State, v rune, p, d string) {
	x := p
	if v == 'q' {
		x = fmt.Sprintf("%q", p)
	} else if v == 'v' && s.Flag('#') {
		x = d
	}
	_, _ = s.Write([]byte(x))
}

var _ controlplane.TaskHandler = (*ReadinessHandler)(nil)
