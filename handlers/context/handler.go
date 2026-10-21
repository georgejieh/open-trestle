package context

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/analysiscodec"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/memorycodec"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/secretscan"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

const (
	maximumContextRepositoryBytes   = 256 << 20
	maximumContextCandidates        = 128
	maximumContextSourceBytes       = 256 << 10
	maximumContextPacketSourceBytes = 128 << 10
)

var ErrInvalidHandler = errors.New("invalid context assembly handler")

type GenerationAuthorizer interface {
	Identity() string
	Authorize(context.Context, audit.ReviewScope, provider.Request, string, time.Time) (gateway.RouteAttemptAuthorization, error)
}

// ContextAbstentionPreparer records the exact artifact before any durable Put.
type ContextAbstentionPreparer interface {
	PrepareContextAbstention(context.Context, controlplane.ReviewRunPlan, controlplane.TaskLease, []byte, controlplane.RunFailure, time.Time) (controlplane.PreparedContextAbstention, error)
}

type Handler struct {
	identity   string
	store      artifact.Store
	clock      artifact.Clock
	authorizer GenerationAuthorizer
	sanitizer  review.GenerationRequestSanitizer
	pipeline   *modelhandler.InvestigationPipeline
	packetOnly bool
	preparer   ContextAbstentionPreparer
}

func NewHandler(store artifact.Store, clock artifact.Clock, authorizer GenerationAuthorizer, sanitizer review.GenerationRequestSanitizer) (*Handler, error) {
	if nilInterface(store) || nilInterface(clock) || nilInterface(authorizer) || !validDigest(authorizer.Identity()) || nilInterface(sanitizer) || !validDigest(sanitizer.Identity()) {
		return nil, ErrInvalidHandler
	}
	h := &Handler{store: store, clock: clock, authorizer: authorizer, sanitizer: sanitizer}
	sanitizerIdentity := sanitizer.Identity()
	h.identity = deriveHandlerIdentity(authorizer.Identity(), sanitizerIdentity)
	return h, nil
}

// NewPacketOnlyHandler persists source-bound context without granting route authority.
func NewPacketOnlyHandler(store artifact.Store, clock artifact.Clock) (*Handler, error) {
	if nilInterface(store) || nilInterface(clock) {
		return nil, ErrInvalidHandler
	}
	return &Handler{identity: packetOnlyHandlerIdentity(), store: store, clock: clock, packetOnly: true}, nil
}

func packetOnlyHandlerIdentity() string {
	digest := sha256.Sum256([]byte("open-trestle/context-packet-only-handler-v2"))
	return hex.EncodeToString(digest[:])
}

// NewJournaledPacketOnlyHandler first records a recoverable intent for abstentions.
func NewJournaledPacketOnlyHandler(store artifact.Store, clock artifact.Clock, preparer ContextAbstentionPreparer) (*Handler, error) {
	if nilInterface(store) || nilInterface(clock) || nilInterface(preparer) {
		return nil, ErrInvalidHandler
	}
	return &Handler{identity: journaledPacketOnlyHandlerIdentity(), store: store, clock: clock, packetOnly: true, preparer: preparer}, nil
}

func journaledPacketOnlyHandlerIdentity() string {
	digest := sha256.Sum256([]byte("open-trestle/context-packet-only-handler-v3-journaled-abstention"))
	return hex.EncodeToString(digest[:])
}

func NewInvestigationHandler(store artifact.Store, clock artifact.Clock, pipeline *modelhandler.InvestigationPipeline) (*Handler, error) {
	if nilInterface(store) || nilInterface(clock) || pipeline == nil || pipeline.Validate() != nil {
		return nil, ErrInvalidHandler
	}
	identity, err := pipeline.HandlerIdentity(controlplane.TaskAssembleContext)
	if err != nil || !validDigest(identity) {
		return nil, ErrInvalidHandler
	}
	return &Handler{identity: identity, store: store, clock: clock, pipeline: pipeline}, nil
}
func (h *Handler) HandlerIdentity() string {
	if h == nil {
		return ""
	}
	if h.pipeline != nil {
		identity, err := h.pipeline.HandlerIdentity(controlplane.TaskAssembleContext)
		if err != nil {
			return ""
		}
		return identity
	}
	return h.identity
}
func (h *Handler) Kind() controlplane.TaskKind {
	if h == nil {
		return 0
	}
	return controlplane.TaskAssembleContext
}
func (h *Handler) Validate() error {
	if h == nil || nilInterface(h.store) || nilInterface(h.clock) {
		return ErrInvalidHandler
	}
	if h.packetOnly {
		legacy := h.identity == packetOnlyHandlerIdentity() && nilInterface(h.preparer)
		journaled := h.identity == journaledPacketOnlyHandlerIdentity() && !nilInterface(h.preparer)
		if (!legacy && !journaled) || !nilInterface(h.authorizer) || !nilInterface(h.sanitizer) || h.pipeline != nil {
			return ErrInvalidHandler
		}
		return nil
	}
	if h.pipeline != nil {
		identity, err := h.pipeline.HandlerIdentity(controlplane.TaskAssembleContext)
		if h.pipeline.Validate() != nil || err != nil || !validDigest(identity) || h.identity != identity || !nilInterface(h.authorizer) || !nilInterface(h.sanitizer) {
			return ErrInvalidHandler
		}
		return nil
	}
	if nilInterface(h.authorizer) || !validDigest(h.authorizer.Identity()) {
		return ErrInvalidHandler
	}
	if nilInterface(h.sanitizer) || !validDigest(h.sanitizer.Identity()) || h.identity != deriveHandlerIdentity(h.authorizer.Identity(), h.sanitizer.Identity()) {
		return ErrInvalidHandler
	}
	return nil
}
func deriveHandlerIdentity(authorizer, sanitizer string) string {
	encoded, _ := json.Marshal(struct {
		Contract   string `json:"contract"`
		Version    int    `json:"version"`
		Authorizer string `json:"authorizer"`
		Sanitizer  string `json:"sanitizer,omitempty"`
	}{"open-trestle/context-assembly-handler", 5, authorizer, sanitizer})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (h *Handler) Execute(ctx context.Context, request controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if nilInterface(ctx) || h.Validate() != nil || request.Validate() != nil || request.Task().Kind() != controlplane.TaskAssembleContext || request.Task().HandlerIdentity() != h.identity || request.Task().MaxAttempts() != 1 || !equalStrings(request.Task().Dependencies(), []string{"analysis", "memory"}) {
		return failure(controlplane.RunFailureInvalidInput)
	}
	if ctx.Err() != nil {
		return failure(controlplane.RunFailureCanceled)
	}
	// A journaled packet-only worker cannot persist a packet or abstention
	// outside the daemon owner's scope-intent effect. Until it carries the
	// owner-bound settlement protocol, fail before source assembly or Put.
	if h.packetOnly && h.preparer != nil {
		return failure(controlplane.RunFailurePolicy)
	}
	at := h.clock.Now().UTC()
	if at.UnixMilli() <= 0 || at.After(request.Lease().ExpiresAt()) {
		return failure(controlplane.RunFailureCanceled)
	}
	assembly, providerRequest, abstention, assemblyFailure := h.assemble(ctx, request, at)
	if assemblyFailure != 0 {
		if abstention == nil || !h.packetOnly {
			return failure(assemblyFailure)
		}
		completion, err := controlplane.NewContextTaskFailureWithOutput(assemblyFailure, request.Plan(), request.Task(), abstention.Identity())
		if err != nil || validateContextAbstentionArtifact(*abstention, request) != nil {
			return failure(controlplane.RunFailureInternal)
		}
		if h.preparer != nil {
			encoded, err := artifact.Encode(*abstention)
			if err != nil {
				return failure(controlplane.RunFailureResourceLimit)
			}
			prepared, err := h.preparer.PrepareContextAbstention(ctx, request.Plan(), request.Lease(), encoded, assemblyFailure, at)
			if err != nil || prepared.ArtifactIdentity() != abstention.Identity() {
				return failure(controlplane.RunFailureInternal)
			}
		}
		if _, err := h.store.Put(ctx, *abstention, at); err != nil {
			return failure(writeFailure(ctx, err))
		}
		stored, err := h.store.Get(ctx, request.Plan().Scope(), abstention.Identity(), at)
		if err != nil {
			return failure(readFailure(ctx, err))
		}
		if validateContextAbstentionArtifact(stored, request) != nil || stored.Identity() != completion.OutputIdentity() {
			return failure(controlplane.RunFailureInvalidInput)
		}
		return completion
	}
	if h.packetOnly {
		contextArtifact := assembly.InitialContextArtifact
		if _, err := h.store.Put(ctx, contextArtifact, at); err != nil {
			return failure(writeFailure(ctx, err))
		}
		completion, err := controlplane.NewTaskSuccess(contextArtifact.Identity())
		if err != nil {
			return failure(controlplane.RunFailureInternal)
		}
		return completion
	}
	if h.pipeline != nil {
		intent, err := h.pipeline.PrepareContext(ctx, request, assembly)
		if err != nil {
			return failure(writeFailure(ctx, err))
		}
		completion, err := controlplane.NewTaskSuccess(intent.Identity())
		if err != nil {
			return failure(controlplane.RunFailureInternal)
		}
		return completion
	}
	packet, snapshot := assembly.Packet, assembly.Snapshot
	contextArtifact := assembly.InitialContextArtifact
	analysisArtifact, memoryArtifact := assembly.AnalysisArtifact, assembly.MemoryArtifact
	dispatchRequest := providerRequest
	var err error
	var sanitizedRequestArtifact, receiptArtifact artifact.Artifact
	sanitized, receipt, sanitizeErr := h.sanitizer.SanitizeGeneration(ctx, providerRequest, request.Plan().Scope().Identity())
	if sanitizeErr != nil {
		if ctx.Err() != nil {
			return failure(controlplane.RunFailureCanceled)
		}
		switch review.SanitizedEgressFailure(sanitizeErr) {
		case secretscan.FailureResourceLimit:
			return failure(controlplane.RunFailureResourceLimit)
		case secretscan.FailureCanceled:
			return failure(controlplane.RunFailureCanceled)
		case secretscan.FailureInvalidInput:
			return failure(controlplane.RunFailureInvalidInput)
		default:
			return failure(controlplane.RunFailurePolicy)
		}
	}
	dispatchRequest, err = sanitized.ProviderRequest()
	if err != nil {
		return failure(controlplane.RunFailurePolicy)
	}
	sanitizedRequestArtifact, receiptArtifact, err = review.NewSanitizedEgressArtifacts(contextArtifact, sanitized, receipt, h.sanitizer.ExpectedBinaryDigests(), at)
	if err != nil {
		return failure(controlplane.RunFailureInvalidInput)
	}
	authorization, err := h.authorizer.Authorize(ctx, request.Plan().Scope(), dispatchRequest, request.Plan().PolicyIdentity(), at)
	if err != nil {
		if ctx.Err() != nil {
			return failure(controlplane.RunFailureCanceled)
		}
		return failure(controlplane.RunFailurePolicy)
	}
	if authorization.Validate() != nil || authorization.RequestIdentity() != dispatchRequest.Identity() || authorization.ReviewScopeIdentity() != request.Plan().Scope().Identity() {
		return failure(controlplane.RunFailurePolicy)
	}
	input, err := modelhandler.NewSanitizedGenerationInput(contextArtifact, packet, snapshot, sanitizedRequestArtifact, receiptArtifact, h.sanitizer.ExpectedBinaryDigests(), authorization)
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	inputArtifact, err := modelhandler.NewGenerationInputArtifact(input, contextArtifact, []string{analysisArtifact.Identity(), memoryArtifact.Identity(), request.Plan().PolicyIdentity(), h.authorizer.Identity()}, at)
	if err != nil {
		return failure(controlplane.RunFailureResourceLimit)
	}
	if _, err := h.store.Put(ctx, contextArtifact, at); err != nil {
		return failure(writeFailure(ctx, err))
	}
	if _, err := h.store.Put(ctx, sanitizedRequestArtifact, at); err != nil {
		return failure(writeFailure(ctx, err))
	}
	if _, err := h.store.Put(ctx, receiptArtifact, at); err != nil {
		return failure(writeFailure(ctx, err))
	}
	if _, err := h.store.Put(ctx, inputArtifact, at); err != nil {
		return failure(writeFailure(ctx, err))
	}
	completion, err := controlplane.NewTaskSuccess(inputArtifact.Identity())
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	return completion
}

// InspectAbstention reuses the context assembler without persisting its output.
// The daemon owner must reassemble and verify under its scope intent before Put.
func (h *Handler) InspectAbstention(ctx context.Context, request controlplane.TaskExecutionRequest, at time.Time) (artifact.Artifact, controlplane.RunFailure, error) {
	if h == nil || h.Validate() != nil || ctx == nil || ctx.Err() != nil || request.Validate() != nil || request.Task().Kind() != controlplane.TaskAssembleContext || request.Task().HandlerIdentity() != PacketAuthorityHandlerIdentity() {
		return artifact.Artifact{}, 0, ErrPacketAuthority
	}
	_, _, value, failureCode := h.assembleAt(ctx, request, at, at)
	if failureCode == 0 {
		return artifact.Artifact{}, 0, nil
	}
	if value == nil || validateContextAbstentionArtifact(*value, request) != nil || (failureCode != controlplane.RunFailurePolicy && failureCode != controlplane.RunFailureResourceLimit) {
		return artifact.Artifact{}, 0, ErrPacketAuthority
	}
	return *value, failureCode, nil
}

func (h *Handler) assemble(ctx context.Context, request controlplane.TaskExecutionRequest, at time.Time) (modelhandler.InvestigationAssembly, provider.Request, *artifact.Artifact, controlplane.RunFailure) {
	return h.assembleAt(ctx, request, at, at)
}

func (h *Handler) assembleAt(ctx context.Context, request controlplane.TaskExecutionRequest, readAt, createdAt time.Time) (modelhandler.InvestigationAssembly, provider.Request, *artifact.Artifact, controlplane.RunFailure) {
	analysisDependency, ok := request.DependencyOutput("analysis")
	if !ok || !analysisDependency.Available() {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	memoryDependency, ok := request.DependencyOutput("memory")
	if !ok || !memoryDependency.Available() {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	analysisArtifact, err := h.store.Get(ctx, request.Plan().Scope(), analysisDependency.OutputIdentity(), readAt)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, readFailure(ctx, err)
	}
	memoryArtifact, err := h.store.Get(ctx, request.Plan().Scope(), memoryDependency.OutputIdentity(), readAt)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, readFailure(ctx, err)
	}
	changeID, err := analysisChangeArtifactIdentity(analysisArtifact)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	changeArtifact, err := h.store.Get(ctx, request.Plan().Scope(), changeID, readAt)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, readFailure(ctx, err)
	}
	baseID, headID, err := changecodec.ResultArtifactReferences(changeArtifact)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	baseArtifact, err := h.store.Get(ctx, request.Plan().Scope(), baseID, readAt)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, readFailure(ctx, err)
	}
	headArtifact, err := h.store.Get(ctx, request.Plan().Scope(), headID, readAt)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, readFailure(ctx, err)
	}
	_, err = changecodec.ParseResultArtifact(changeArtifact, baseArtifact, headArtifact)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	analysis, err := analysiscodec.ParseResultArtifact(analysisArtifact, changeArtifact, baseArtifact, headArtifact)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	memoryResult, err := memorycodec.ParseResultArtifact(memoryArtifact, changeArtifact, baseArtifact, headArtifact)
	if err != nil || memoryResult.ChangeArtifactIdentity() != analysis.ChangeArtifactIdentity() || memoryResult.PolicyIdentity() != request.Plan().PolicyIdentity() {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	head, err := sourceoutput.ParseSnapshotArtifact(headArtifact)
	if err != nil || head.Identity() != analysis.HeadSnapshotIdentity() || head.ManifestIdentity() != analysis.HeadManifestIdentity() {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	memoryScope, err := memoryResult.MemoryScope()
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	queries := memoryResult.Queries()
	if len(queries) == 0 && !h.packetOnly {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailurePolicy
	}
	retrievals := make([]memorycore.LexicalRetrieval, len(queries))
	memoryItems := 0
	for index, query := range queries {
		retrievals[index], err = query.Retrieval(memoryScope, memoryResult.AsOf())
		if err != nil {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		memoryItems += len(retrievals[index].Items())
	}
	contents, manifest, expires, loadFailure := h.loadHead(ctx, request.Plan().Scope(), head, readAt, minimumTime(analysisArtifact.ExpiresAt(), memoryArtifact.ExpiresAt(), changeArtifact.ExpiresAt(), baseArtifact.ExpiresAt(), headArtifact.ExpiresAt()))
	if loadFailure != 0 {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, loadFailure
	}
	defer clearContents(contents)
	omissions := make([]review.ContextSourceOmission, 0, len(analysis.Gaps()))
	for _, gap := range analysis.Gaps() {
		omission, omissionErr := review.NewContextSourceOmission(gap.Path(), gap.StartLine(), gap.EndLine(), "analysis_"+gap.Reason())
		if omissionErr != nil {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		omissions = append(omissions, omission)
	}
	semanticProfile := analysis.SemanticImpact()
	for _, gap := range semanticProfile.Gaps() {
		omission, omissionErr := review.NewContextSourceOmission(gap.Path(), 0, 0, "semantic_"+string(gap.Reason()))
		if omissionErr != nil {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		omissions = append(omissions, omission)
	}
	candidates := make([]review.ContextSource, 0, maximumContextCandidates)
	for _, item := range analysis.Items() {
		content, exists := contents[item.Path()]
		if !exists {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		repositoryFile, err := evidence.NewRepositoryFile(item.Path(), content)
		if err != nil || repositoryFile.Identity() != item.FileIdentity() || repositoryFile.Digest() != item.FileDigest() {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		rangeValue, err := evidence.NewSourceRange(item.Path(), item.StartLine(), item.EndLine())
		if err != nil {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		slice, ok := physicalLineSlice(content, item.StartLine(), item.EndLine())
		if !ok {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		binding, err := evidence.BindSourceSlice(repositoryFile, content, rangeValue, slice)
		if err != nil || binding.Identity() != item.BindingIdentity() || binding.SliceBytes() != item.SliceBytes() {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		reason := ""
		switch {
		case !memoryScope.AllowsPath(item.Path()):
			reason = "path_not_authorized"
		case !strings.HasSuffix(item.Path(), ".go"):
			reason = "unsupported_language"
		case len(slice) > maximumContextSourceBytes:
			reason = "source_size_limit"
		case len(candidates) >= maximumContextCandidates:
			reason = "candidate_limit"
		}
		if reason != "" {
			omission, omissionErr := review.NewContextSourceOmission(item.Path(), item.StartLine(), item.EndLine(), reason)
			if omissionErr != nil {
				return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInternal
			}
			omissions = append(omissions, omission)
			continue
		}
		evidenceItem, err := item.EvidenceItem()
		if err != nil {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		source, err := review.NewBoundContextSource(review.ContextStageChangedHunk, memorycore.TaintRepositoryControlled, evidenceItem, slice, binding)
		if err != nil {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		candidates = append(candidates, source)
	}
	candidates, omissions, semanticFailure := appendSemanticCandidates(contents, memoryScope, semanticProfile, candidates, omissions)
	if semanticFailure != 0 {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, semanticFailure
	}
	makeAbstention := func(reason string, failureCode controlplane.RunFailure, sourceOmissions []review.ContextSourceOmission) (*artifact.Artifact, controlplane.RunFailure) {
		value, err := newContextAbstentionArtifact(request, analysisArtifact, memoryArtifact, changeArtifact, headArtifact, head.Identity(), sourceOmissions, reason, failureCode, createdAt, expires)
		if err != nil {
			return nil, controlplane.RunFailureResourceLimit
		}
		return &value, failureCode
	}
	if len(candidates) == 0 {
		reason := "all_sources_omitted"
		if len(omissions) == 0 {
			reason = "no_source_changes"
		}
		unsupportedOnly := len(omissions) > 0
		for _, omission := range omissions {
			if omission.Reason() != "unsupported_language" && omission.Reason() != "semantic_unsupported_language" {
				unsupportedOnly = false
			}
		}
		if unsupportedOnly {
			reason = "unsupported_language"
		}
		abstention, failureCode := makeAbstention(reason, controlplane.RunFailurePolicy, omissions)
		return modelhandler.InvestigationAssembly{}, provider.Request{}, abstention, failureCode
	}
	limits, _ := review.NewContextLimits(maximumContextPacketSourceBytes, uint8(min(50, memoryItems)))
	selection, err := review.SelectContextSources(candidates, limits)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureResourceLimit
	}
	if selection.SelectedCount() == 0 {
		for _, candidate := range candidates {
			rangeValue := candidate.EvidenceItem().SourceRange()
			omission, err := review.NewContextSourceOmission(rangeValue.Path(), rangeValue.StartLine(), rangeValue.EndLine(), "packet_budget")
			if err != nil {
				return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
			}
			omissions = append(omissions, omission)
		}
		abstention, failureCode := makeAbstention("packet_budget_zero_selection", controlplane.RunFailureResourceLimit, omissions)
		return modelhandler.InvestigationAssembly{}, provider.Request{}, abstention, failureCode
	}
	ranges := make([]evidence.SourceRange, selection.SelectedCount())
	for index, source := range selection.SelectedSources() {
		ranges[index] = source.EvidenceItem().SourceRange()
	}
	snapshot, err := review.NewAcquiredReviewPipelineSnapshot(request.Plan().Scope().ReviewRunID(), manifest, ranges)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	packet, err := review.NewContextPacketWithAccounting(request.Plan().Scope(), memoryScope, snapshot, review.ContextTaskCandidateGeneration, candidates, retrievals, omissions, limits)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	providerRequest, err := packet.ProviderRequest()
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureInternal
	}
	contextProvenance := []string{analysisArtifact.Identity(), memoryArtifact.Identity(), changeArtifact.Identity(), headArtifact.Identity(), analysis.Identity(), memoryResult.Identity()}
	sort.Strings(contextProvenance)
	contextArtifact, err := artifact.New(request.Plan().Scope(), artifact.KindContextPacket, "application/json", analysisArtifact.Classification(), artifact.OriginHost, analysisArtifact.Protection(), contextProvenance, providerRequest.Payload(), createdAt, expires)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, nil, controlplane.RunFailureResourceLimit
	}
	return modelhandler.InvestigationAssembly{
		Packet: packet, Snapshot: snapshot, MemoryScope: memoryScope,
		InitialContextArtifact: contextArtifact,
		AnalysisArtifact:       analysisArtifact, MemoryArtifact: memoryArtifact, ChangeArtifact: changeArtifact,
		BaseSnapshotArtifact: baseArtifact, HeadSnapshotArtifact: headArtifact,
	}, providerRequest, nil, 0
}

func (h *Handler) loadHead(ctx context.Context, scope audit.ReviewScope, head sourceoutput.Snapshot, at, expires time.Time) (map[string][]byte, evidence.RepositoryManifest, time.Time, controlplane.RunFailure) {
	contents := make(map[string][]byte, head.FileCount())
	files := make([]evidence.RepositoryFile, 0, head.FileCount())
	loaded := 0
	for _, reference := range head.Files() {
		if ctx.Err() != nil {
			clearContents(contents)
			return nil, evidence.RepositoryManifest{}, time.Time{}, controlplane.RunFailureCanceled
		}
		if loaded > maximumContextRepositoryBytes-reference.SizeBytes() {
			clearContents(contents)
			return nil, evidence.RepositoryManifest{}, time.Time{}, controlplane.RunFailureResourceLimit
		}
		value, err := h.store.Get(ctx, scope, reference.ArtifactIdentity(), at)
		if err != nil {
			clearContents(contents)
			return nil, evidence.RepositoryManifest{}, time.Time{}, readFailure(ctx, err)
		}
		file, err := sourceoutput.ParseFileArtifact(value, head, reference)
		if err != nil {
			clearContents(contents)
			return nil, evidence.RepositoryManifest{}, time.Time{}, controlplane.RunFailureInvalidInput
		}
		content := file.Content()
		repositoryFile, err := evidence.NewRepositoryFile(reference.Path(), content)
		if err != nil || repositoryFile.Digest() != reference.Digest() || repositoryFile.SizeBytes() != reference.SizeBytes() {
			clear(content)
			clearContents(contents)
			return nil, evidence.RepositoryManifest{}, time.Time{}, controlplane.RunFailureInvalidInput
		}
		contents[reference.Path()] = content
		files = append(files, repositoryFile)
		loaded += len(content)
		if value.ExpiresAt().Before(expires) {
			expires = value.ExpiresAt()
		}
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	if err != nil || manifest.Identity() != head.ManifestIdentity() {
		clearContents(contents)
		return nil, evidence.RepositoryManifest{}, time.Time{}, controlplane.RunFailureInvalidInput
	}
	return contents, manifest, expires, 0
}

func analysisChangeArtifactIdentity(value artifact.Artifact) (string, error) {
	if value.Kind() != artifact.KindDeterministicEvidence {
		return "", ErrInvalidHandler
	}
	var wire struct {
		ChangeArtifactIdentity string `json:"change_artifact_identity"`
	}
	if json.Unmarshal(value.Payload(), &wire) != nil || !validDigest(wire.ChangeArtifactIdentity) {
		return "", ErrInvalidHandler
	}
	return wire.ChangeArtifactIdentity, nil
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
func clearContents(values map[string][]byte) {
	for _, value := range values {
		clear(value)
	}
}
func validDigest(value string) bool {
	if len(value) != 64 || value == "0000000000000000000000000000000000000000000000000000000000000000" {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
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
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
func (h *Handler) String() string   { return "context assembly task handler" }
func (h *Handler) GoString() string { return "context.Handler{<redacted>}" }
func (h *Handler) Format(state fmt.State, verb rune) {
	value := "context assembly task handler"
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = "context.Handler{<redacted>}"
	}
	_, _ = state.Write([]byte(value))
}

var _ controlplane.TaskHandler = (*Handler)(nil)
