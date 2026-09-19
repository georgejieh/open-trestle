package model

import (
	"context"
	"encoding/json"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
)

// These types are distinct from historical no-tool claims. No public constructor
// or byte decoder can mint their physical admission.
type AdmittedInvestigationGenerationInput struct {
	witness       *InvestigationGenerationCustody
	identity      string
	snapshot      review.ReviewSnapshot
	evidence      []evidence.EvidenceItem
	authorization gateway.RouteAttemptAuthorization
}

func (i AdmittedInvestigationGenerationInput) Identity() string { return i.identity }
func (i AdmittedInvestigationGenerationInput) ContextIdentity() string {
	if i.witness == nil {
		return ""
	}
	return i.witness.context.Identity()
}
func (i AdmittedInvestigationGenerationInput) Snapshot() review.ReviewSnapshot { return i.snapshot }
func (i AdmittedInvestigationGenerationInput) EvidenceItems() []evidence.EvidenceItem {
	return append([]evidence.EvidenceItem(nil), i.evidence...)
}
func (i AdmittedInvestigationGenerationInput) Authorization() gateway.RouteAttemptAuthorization {
	return i.authorization
}
func (i AdmittedInvestigationGenerationInput) Validate() error {
	if i.witness == nil || i.witness.owner == nil || !i.witness.live(i.witness.owner.options.Clock.Now()) || i.identity != i.witness.inputValue.identity {
		return ErrInvestigationArtifacts
	}
	return nil
}

type AdmittedInvestigationGenerationResult struct {
	witness    *InvestigationGenerationCustody
	identity   string
	candidates review.CandidateBatch
	execution  gateway.RouteExecutionRecord
}

func (r AdmittedInvestigationGenerationResult) Identity() string { return r.identity }
func (r AdmittedInvestigationGenerationResult) ContextIdentity() string {
	if r.witness == nil {
		return ""
	}
	return r.witness.context.Identity()
}
func (r AdmittedInvestigationGenerationResult) Candidates() review.CandidateBatch {
	return r.candidates
}
func (r AdmittedInvestigationGenerationResult) RouteExecution() gateway.RouteExecutionRecord {
	return r.execution
}
func (r AdmittedInvestigationGenerationResult) Turn() gateway.InvestigationTurnRecord {
	if r.witness == nil {
		return gateway.InvestigationTurnRecord{}
	}
	return r.witness.turn
}
func (r AdmittedInvestigationGenerationResult) Validate() error {
	if r.witness == nil || r.witness.owner == nil || !r.witness.live(r.witness.owner.options.Clock.Now()) || r.identity != r.witness.resultValue.identity {
		return ErrInvestigationArtifacts
	}
	return nil
}

func ParseAdmittedInvestigationGenerationInputArtifact(value artifact.Artifact, w *InvestigationGenerationCustody, at time.Time) (AdmittedInvestigationGenerationInput, error) {
	if w == nil || !w.live(at) || !toolRecordSameArtifact(value, w.input) {
		return AdmittedInvestigationGenerationInput{}, ErrInvestigationArtifacts
	}
	return w.inputValue, nil
}
func ParseAdmittedInvestigationGenerationResultArtifact(value, input, turn artifact.Artifact, w *InvestigationGenerationCustody, at time.Time) (AdmittedInvestigationGenerationResult, error) {
	if w == nil || !w.live(at) || !toolRecordSameArtifact(value, w.result) || !toolRecordSameArtifact(input, w.input) || !toolRecordSameArtifact(turn, w.turnArtifact) {
		return AdmittedInvestigationGenerationResult{}, ErrInvestigationArtifacts
	}
	return w.resultValue, nil
}
func (c *Investigation) finishGeneration(ctx context.Context, turn gateway.InvestigationTurnRecord, turnArtifact artifact.Artifact) (InvestigationGeneration, error) {
	request, err := c.current.ProviderRequest()
	if err != nil {
		return InvestigationGeneration{}, err
	}
	if request.Identity() != turn.RequestIdentity() || turn.Authorization().RouteRecordIdentity() != c.pin {
		return InvestigationGeneration{}, ErrInvestigation
	}
	candidates, err := review.ParseCandidateBatch(turn.Dispatch().Response(), c.current.Snapshot(), c.current.EvidenceItems())
	if err != nil {
		return InvestigationGeneration{}, err
	}
	output, err := gateway.NewSuccessfulRouteOutputReceipt(gateway.RouteOutputCandidateBatch, c.current.Identity(), candidates.Identity(), request, turn.Authorization(), turn.Outcome())
	if err != nil {
		return InvestigationGeneration{}, err
	}
	execution, err := gateway.NewRouteExecutionRecord(turn.Authorization(), turn.Outcome(), turn.Reconciliation(), output)
	if err != nil {
		return InvestigationGeneration{}, err
	}
	w := &InvestigationGenerationCustody{owner: c, context: c.current, contextArtifact: c.currentArtifact, turnArtifact: turnArtifact, turn: turn, tools: append([]investigationHeldTool(nil), c.tools...), sources: append([]review.ContextSource(nil), c.candidates...), expires: c.expires}
	// Use the existing v2 field vocabulary, not its NO-TOOL validators.
	claims := InvestigationGenerationInput{scope: c.options.Scope.Identity(), contextArtifact: c.currentArtifact.Identity(), contextIdentity: c.current.Identity(), memoryScope: c.options.MemoryScope.Identity(), memoryIdentity: c.options.InitialContext.MemoryIdentity(), schemaIdentity: artifactPayloadHash(review.InvestigationOutputSchema()), session: c.binding.Identity(), policy: c.options.Policy.Identity(), owner: c.ownerIdentity, headArtifact: c.head.Identity(), headSnapshot: c.snapshot.Identity(), headManifest: c.snapshot.ManifestIdentity(), initialContext: c.options.InitialContext.Identity(), snapshot: c.current.Snapshot(), evidence: c.current.EvidenceItems(), authorization: turn.Authorization()}
	values, err := claims.values()
	if err != nil {
		return InvestigationGeneration{}, err
	}
	tools := []string{}
	for _, tool := range c.tools {
		tools = append(tools, tool.artifact.Identity())
	}
	values["tool_result_artifact_identities"] = tools
	delete(values, "identity")
	raw, err := json.Marshal(values)
	if err != nil {
		return InvestigationGeneration{}, err
	}
	claims.identity = artifactPayloadHash(raw)
	values["identity"] = claims.identity
	raw, err = json.Marshal(values)
	if err != nil || len(raw) > maximumGenerationInputBytes {
		return InvestigationGeneration{}, ErrInvestigation
	}
	input, err := c.newArtifact(artifact.KindTaskInput, artifact.OriginHost, []string{c.currentArtifact.Identity(), c.head.Identity(), c.binding.Identity(), c.ownerIdentity, turn.Authorization().Identity()}, raw)
	if err != nil {
		return InvestigationGeneration{}, err
	}
	if err = c.put(ctx, input); err != nil {
		return InvestigationGeneration{}, err
	}
	w.input = input
	resultClaims := InvestigationGenerationResult{inputArtifact: input.Identity(), turnArtifact: turnArtifact.Identity(), previous: turn.PreviousTurnIdentity(), input: claims, turn: turn, candidates: candidates, execution: execution}
	values, err = resultClaims.values()
	if err != nil {
		return InvestigationGeneration{}, err
	}
	values["tool_result_artifact_identities"] = tools
	delete(values, "identity")
	raw, err = json.Marshal(values)
	if err != nil {
		return InvestigationGeneration{}, err
	}
	resultClaims.identity = artifactPayloadHash(raw)
	values["identity"] = resultClaims.identity
	raw, err = json.Marshal(values)
	if err != nil || len(raw) > maximumGenerationResultBytes {
		return InvestigationGeneration{}, ErrInvestigation
	}
	result, err := c.newArtifact(artifact.KindCandidateBatch, artifact.OriginModel, investigationResultProvenance(resultClaims), raw)
	if err != nil {
		return InvestigationGeneration{}, err
	}
	if err = c.put(ctx, result); err != nil {
		return InvestigationGeneration{}, err
	}
	w.result = result
	w.inputValue = AdmittedInvestigationGenerationInput{w, claims.identity, claims.snapshot, claims.evidence, claims.authorization}
	w.resultValue = AdmittedInvestigationGenerationResult{w, resultClaims.identity, candidates, execution}
	if c.live(ctx) != nil {
		return InvestigationGeneration{}, ErrInvestigation
	}
	c.mu.Lock()
	c.finalCustody = w
	c.mu.Unlock()
	return InvestigationGeneration{w}, nil
}
func (i AdmittedInvestigationGenerationInput) String() string { return "admitted investigation input" }
func (i AdmittedInvestigationGenerationInput) GoString() string {
	return "model.AdmittedInvestigationGenerationInput{<redacted>}"
}
func (r AdmittedInvestigationGenerationResult) String() string {
	return "admitted investigation result"
}
func (r AdmittedInvestigationGenerationResult) GoString() string {
	return "model.AdmittedInvestigationGenerationResult{<redacted>}"
}
