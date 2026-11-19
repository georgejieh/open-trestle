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
	specialist review.ContextSpecialist
	intent     ChangeIntentSource
	// index and budget are bound by WithRepositoryContext; without them a
	// packet records the index as unavailable and keeps the default budget.
	index  IndexContextSource
	budget review.ContextBudget
}

func NewHandler(store artifact.Store, clock artifact.Clock, authorizer GenerationAuthorizer, sanitizer review.GenerationRequestSanitizer) (*Handler, error) {
	if nilInterface(store) || nilInterface(clock) || nilInterface(authorizer) || !validDigest(authorizer.Identity()) || nilInterface(sanitizer) || !validDigest(sanitizer.Identity()) {
		return nil, ErrInvalidHandler
	}
	h := &Handler{store: store, clock: clock, authorizer: authorizer, sanitizer: sanitizer}
	h.identity = h.deriveIdentity()
	return h, nil
}

// WithChangeIntent returns a copy of a route-granting handler that also reads
// the change's author-stated intent from source and carries it in the
// packet's stated_intent object, fitted to the source byte budget the selected
// sources leave. The source's identity is bound into the handler identity.
func (h *Handler) WithChangeIntent(source ChangeIntentSource) (*Handler, error) {
	if h == nil || h.Validate() != nil || h.packetOnly || h.pipeline != nil || h.intent != nil || nilInterface(source) || !validDigest(source.Identity()) {
		return nil, ErrInvalidHandler
	}
	value := *h
	value.intent = source
	value.identity = value.deriveIdentity()
	return &value, nil
}

// WithRepositoryContext returns a copy of a route-granting handler that fits
// every packet to budget, which the caller derives from the routes' context
// windows (see review.RouteContextBudget), and asks source, when not nil, for
// index context. The source identity and the budget are bound into the
// handler identity.
func (h *Handler) WithRepositoryContext(source IndexContextSource, budget review.ContextBudget) (*Handler, error) {
	if h == nil || h.Validate() != nil || h.packetOnly || h.pipeline != nil || h.index != nil || h.budget != (review.ContextBudget{}) || !nilInterface(source) && !validDigest(source.Identity()) {
		return nil, ErrInvalidHandler
	}
	if _, err := budget.Limits(0); err != nil {
		return nil, ErrInvalidHandler
	}
	value := *h
	value.index, value.budget = source, budget
	value.identity = value.deriveIdentity()
	return &value, nil
}

func (h *Handler) deriveIdentity() string {
	intent, index := "", ""
	if !nilInterface(h.intent) {
		intent = h.intent.Identity()
	}
	if !nilInterface(h.index) {
		index = h.index.Identity()
	}
	return deriveHandlerIdentity(h.authorizer.Identity(), h.sanitizer.Identity(), h.specialist, intent, index, h.budget)
}

// contextBudget is the bound budget, or the default.
func (h *Handler) contextBudget() review.ContextBudget {
	if h.budget == (review.ContextBudget{}) {
		return review.DefaultContextBudget()
	}
	return h.budget
}

// NewSpecialistHandler is NewHandler for one packaged specialist profile. Its
// candidate-generation packet carries the optional specialist block of context
// schema version 7, and its handler identity binds the profile and catalog identities.
func NewSpecialistHandler(store artifact.Store, clock artifact.Clock, authorizer GenerationAuthorizer, sanitizer review.GenerationRequestSanitizer, specialist review.ContextSpecialist) (*Handler, error) {
	if specialist.IsZero() || specialist.Validate() != nil {
		return nil, ErrInvalidHandler
	}
	h, err := NewHandler(store, clock, authorizer, sanitizer)
	if err != nil {
		return nil, err
	}
	h.specialist = specialist
	h.identity = h.deriveIdentity()
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
		if (!legacy && !journaled) || !nilInterface(h.authorizer) || !nilInterface(h.sanitizer) || h.pipeline != nil || !h.specialist.IsZero() || !nilInterface(h.intent) || !nilInterface(h.index) {
			return ErrInvalidHandler
		}
		return nil
	}
	if h.pipeline != nil {
		identity, err := h.pipeline.HandlerIdentity(controlplane.TaskAssembleContext)
		if h.pipeline.Validate() != nil || err != nil || !validDigest(identity) || h.identity != identity || !nilInterface(h.authorizer) || !nilInterface(h.sanitizer) || !h.specialist.IsZero() || !nilInterface(h.intent) || !nilInterface(h.index) {
			return ErrInvalidHandler
		}
		return nil
	}
	if nilInterface(h.authorizer) || !validDigest(h.authorizer.Identity()) {
		return ErrInvalidHandler
	}
	if !nilInterface(h.intent) && !validDigest(h.intent.Identity()) || !nilInterface(h.index) && !validDigest(h.index.Identity()) {
		return ErrInvalidHandler
	}
	if nilInterface(h.sanitizer) || !validDigest(h.sanitizer.Identity()) || h.identity != h.deriveIdentity() {
		return ErrInvalidHandler
	}
	if !h.specialist.IsZero() && h.specialist.Validate() != nil {
		return ErrInvalidHandler
	}
	return nil
}

// contextAssemblyHandlerVersion versions the route-granting context handler.
// Version 6 assembled version 7 generation contexts, admits non-Go changed text
// through the text fallback, and adds root repository instruction files from the
// base snapshot (used only when the head is byte-identical) as repository_context
// sources. Version 7 assembles version 8 generation contexts. A plan that
// recorded an earlier identity is not executed by this handler, so a run that
// straddles an upgrade fails closed instead of rebuilding different packet
// bytes; its recorded artifacts stay readable through the recorded-readback
// validators. Version 8 assembles version 9 generation contexts, with
// deterministic pattern hygiene and, when a change intent source is bound,
// the stated intent. Version 9 assembles version 10 generation contexts: it
// replaces the semantic-impact reference candidates with index context from
// a bound IndexContextSource, fits every packet to a budget, and records a
// context manifest.
const contextAssemblyHandlerVersion = 9

// deriveHandlerIdentity omits the specialist, intent-source, index-source and
// budget fields when none is bound.
func deriveHandlerIdentity(authorizer, sanitizer string, specialist review.ContextSpecialist, intent, index string, budget review.ContextBudget) string {
	type budgetWire struct {
		Basis          string `json:"basis"`
		RouteTokens    uint32 `json:"route_context_tokens"`
		OutputTokens   uint32 `json:"output_tokens"`
		MaxSourceBytes uint32 `json:"max_source_bytes"`
	}
	var bound *budgetWire
	if budget != (review.ContextBudget{}) {
		bound = &budgetWire{budget.Basis, budget.RouteContextTokens, budget.OutputTokens, budget.MaxSourceBytes}
	}
	encoded, _ := json.Marshal(struct {
		Contract          string      `json:"contract"`
		Version           int         `json:"version"`
		Authorizer        string      `json:"authorizer"`
		Sanitizer         string      `json:"sanitizer,omitempty"`
		SpecialistProfile string      `json:"specialist_profile_identity,omitempty"`
		SpecialistCatalog string      `json:"specialist_catalog_identity,omitempty"`
		ChangeIntent      string      `json:"change_intent_source_identity,omitempty"`
		IndexContext      string      `json:"index_context_source_identity,omitempty"`
		Budget            *budgetWire `json:"context_budget,omitempty"`
	}{"open-trestle/context-assembly-handler", contextAssemblyHandlerVersion, authorizer, sanitizer, specialist.ProfileIdentity(), specialist.CatalogIdentity(), intent, index, bound})
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
	assembly, providerRequest, abstention, failureCode := h.assembleAt(ctx, request, at, at)
	return assembly.InvestigationAssembly, providerRequest, abstention, failureCode
}

type contextAssembly struct {
	modelhandler.InvestigationAssembly
	base, head sourceoutput.Snapshot
}

func (h *Handler) assembleAt(ctx context.Context, request controlplane.TaskExecutionRequest, readAt, createdAt time.Time) (contextAssembly, provider.Request, *artifact.Artifact, controlplane.RunFailure) {
	analysisDependency, ok := request.DependencyOutput("analysis")
	if !ok || !analysisDependency.Available() {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	memoryDependency, ok := request.DependencyOutput("memory")
	if !ok || !memoryDependency.Available() {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	analysisArtifact, err := h.store.Get(ctx, request.Plan().Scope(), analysisDependency.OutputIdentity(), readAt)
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, readFailure(ctx, err)
	}
	memoryArtifact, err := h.store.Get(ctx, request.Plan().Scope(), memoryDependency.OutputIdentity(), readAt)
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, readFailure(ctx, err)
	}
	changeID, err := analysisChangeArtifactIdentity(analysisArtifact)
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	changeArtifact, err := h.store.Get(ctx, request.Plan().Scope(), changeID, readAt)
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, readFailure(ctx, err)
	}
	baseID, headID, err := changecodec.ResultArtifactReferences(changeArtifact)
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	baseArtifact, err := h.store.Get(ctx, request.Plan().Scope(), baseID, readAt)
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, readFailure(ctx, err)
	}
	headArtifact, err := h.store.Get(ctx, request.Plan().Scope(), headID, readAt)
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, readFailure(ctx, err)
	}
	base, err := sourceoutput.ParseSnapshotArtifact(baseArtifact)
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	head, err := sourceoutput.ParseSnapshotArtifact(headArtifact)
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	change, err := changecodec.ParseResultArtifactWithSnapshots(changeArtifact, base, head)
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	analysis, err := analysiscodec.ParseResultArtifactWithChange(analysisArtifact, changeArtifact, change)
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	memoryResult, err := memorycodec.ParseResultArtifactWithChange(memoryArtifact, changeArtifact, change)
	if err != nil || memoryResult.ChangeArtifactIdentity() != analysis.ChangeArtifactIdentity() || memoryResult.PolicyIdentity() != request.Plan().PolicyIdentity() {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	if head.Identity() != analysis.HeadSnapshotIdentity() || head.ManifestIdentity() != analysis.HeadManifestIdentity() {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	memoryScope, err := memoryResult.MemoryScope()
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	queries := memoryResult.Queries()
	if len(queries) == 0 && !h.packetOnly {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailurePolicy
	}
	retrievals := make([]memorycore.LexicalRetrieval, len(queries))
	memoryItems := 0
	for index, query := range queries {
		retrievals[index], err = query.Retrieval(memoryScope, memoryResult.AsOf())
		if err != nil {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		memoryItems += len(retrievals[index].Items())
	}
	contents, manifest, expires, loadFailure := h.loadHead(ctx, request.Plan().Scope(), head, readAt, minimumTime(analysisArtifact.ExpiresAt(), memoryArtifact.ExpiresAt(), changeArtifact.ExpiresAt(), baseArtifact.ExpiresAt(), headArtifact.ExpiresAt()))
	if loadFailure != 0 {
		return contextAssembly{}, provider.Request{}, nil, loadFailure
	}
	defer clearContents(contents)
	omissions := make([]review.ContextSourceOmission, 0, len(analysis.Gaps()))
	for _, gap := range analysis.Gaps() {
		omission, omissionErr := review.NewContextSourceOmission(gap.Path(), gap.StartLine(), gap.EndLine(), "analysis_"+gap.Reason())
		if omissionErr != nil {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		omissions = append(omissions, omission)
	}
	for _, gap := range analysis.SemanticImpact().Gaps() {
		omission, omissionErr := review.NewContextSourceOmission(gap.Path(), 0, 0, "semantic_"+string(gap.Reason()))
		if omissionErr != nil {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		omissions = append(omissions, omission)
	}
	candidates := make([]review.ContextSource, 0, maximumContextCandidates)
	for _, item := range analysis.Items() {
		content, exists := contents[item.Path()]
		if !exists {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		repositoryFile, err := evidence.NewRepositoryFile(item.Path(), content)
		if err != nil || repositoryFile.Identity() != item.FileIdentity() || repositoryFile.Digest() != item.FileDigest() {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		rangeValue, err := evidence.NewSourceRange(item.Path(), item.StartLine(), item.EndLine())
		if err != nil {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		slice, ok := physicalLineSlice(content, item.StartLine(), item.EndLine())
		if !ok {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		binding, err := evidence.BindSourceSlice(repositoryFile, content, rangeValue, slice)
		if err != nil || binding.Identity() != item.BindingIdentity() || binding.SliceBytes() != item.SliceBytes() {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		reason := ""
		switch {
		case !memoryScope.AllowsPath(item.Path()):
			reason = "path_not_authorized"
		case !strings.HasSuffix(item.Path(), ".go") && excludedFallbackPath(item.Path()):
			reason = "excluded_path"
		case !strings.HasSuffix(item.Path(), ".go") && !isFallbackText(slice):
			reason = "non_text_content"
		case len(slice) > maximumContextSourceBytes:
			reason = "source_size_limit"
		case len(candidates) >= maximumContextCandidates:
			reason = "candidate_limit"
		}
		if reason != "" {
			omission, omissionErr := review.NewContextSourceOmission(item.Path(), item.StartLine(), item.EndLine(), reason)
			if omissionErr != nil {
				return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInternal
			}
			omissions = append(omissions, omission)
			continue
		}
		evidenceItem, err := item.EvidenceItem()
		if err != nil {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		source, err := review.NewBoundContextSource(review.ContextStageChangedHunk, memorycore.TaintRepositoryControlled, evidenceItem, slice, binding)
		if err != nil {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		candidates = append(candidates, source)
	}
	makeAbstention := func(reason string, failureCode controlplane.RunFailure, sourceOmissions []review.ContextSourceOmission) (*artifact.Artifact, controlplane.RunFailure) {
		value, err := newContextAbstentionArtifact(request, analysisArtifact, memoryArtifact, changeArtifact, headArtifact, head.Identity(), sourceOmissions, reason, failureCode, createdAt, expires)
		if err != nil {
			return nil, controlplane.RunFailureResourceLimit
		}
		return &value, failureCode
	}
	abstainAllOmitted := func() (contextAssembly, provider.Request, *artifact.Artifact, controlplane.RunFailure) {
		reason := "all_sources_omitted"
		if len(omissions) == 0 {
			reason = "no_source_changes"
		}
		unsupportedOnly := len(omissions) > 0
		for _, omission := range omissions {
			switch omission.Reason() {
			case "unsupported_language", "semantic_unsupported_language", "excluded_path", "non_text_content":
			default:
				unsupportedOnly = false
			}
		}
		if unsupportedOnly {
			reason = "unsupported_language"
		}
		abstention, failureCode := makeAbstention(reason, controlplane.RunFailurePolicy, omissions)
		return contextAssembly{}, provider.Request{}, abstention, failureCode
	}
	abstainZeroSelection := func() (contextAssembly, provider.Request, *artifact.Artifact, controlplane.RunFailure) {
		for _, candidate := range candidates {
			rangeValue := candidate.EvidenceItem().SourceRange()
			omission, err := review.NewContextSourceOmission(rangeValue.Path(), rangeValue.StartLine(), rangeValue.EndLine(), "packet_budget")
			if err != nil {
				return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
			}
			omissions = append(omissions, omission)
		}
		abstention, failureCode := makeAbstention("packet_budget_zero_selection", controlplane.RunFailureResourceLimit, omissions)
		return contextAssembly{}, provider.Request{}, abstention, failureCode
	}
	// The removed text of an emptied or removed file is reviewable on its own:
	// a change that only removes files is reviewed from that text. The removed
	// text of a deletion point is supplied only beside its head context, so it
	// never turns an all-omitted change into a reviewable packet.
	wholeFileRemoved := false
	for _, item := range analysis.RemovedLines() {
		wholeFileRemoved = wholeFileRemoved || item.HeadLine() == 0
	}
	if len(candidates) == 0 && !wholeFileRemoved {
		return abstainAllOmitted()
	}
	// The investigation pipeline keeps the fixed bounds its own contract
	// checks; every other packet fits the bound budget.
	budget := h.contextBudget()
	limits, _ := budget.Limits(uint8(min(50, memoryItems)))
	if h.pipeline != nil {
		limits, _ = review.NewContextLimits(maximumContextPacketSourceBytes, uint8(min(50, memoryItems)))
	}
	var selection review.ContextSourceSelection
	if len(candidates) > 0 {
		selection, err = review.SelectContextSources(candidates, limits)
		if err != nil {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureResourceLimit
		}
		if selection.SelectedCount() == 0 {
			return abstainZeroSelection()
		}
	}
	if removed := analysis.RemovedLines(); len(removed) > 0 {
		var removedFailure controlplane.RunFailure
		candidates, omissions, removedFailure = h.appendRemovedLinesCandidates(ctx, request.Plan().Scope(), readAt, base, removed, memoryScope, candidates, omissions, &expires)
		if removedFailure != 0 {
			return contextAssembly{}, provider.Request{}, nil, removedFailure
		}
		if len(candidates) == 0 {
			return abstainAllOmitted()
		}
		candidates, selection, omissions, removedFailure = fitRemovedLinesCandidates(candidates, limits, omissions)
		if removedFailure != 0 {
			return contextAssembly{}, provider.Request{}, nil, removedFailure
		}
		if selection.SelectedCount() == 0 {
			return abstainZeroSelection()
		}
	}
	// Instruction files are added only after the abstention decisions so they can
	// never turn an all-omitted or zero-selection change into a reviewable
	// packet. They come from the base tree and are kept only when they fit after
	// every changed source, so they never become selection omissions.
	withInstructions, omissions, instructionFailure := appendRepositoryInstructionCandidates(base.Files(), contents, memoryScope, candidates, omissions)
	if instructionFailure != 0 {
		return contextAssembly{}, provider.Request{}, nil, instructionFailure
	}
	if len(withInstructions) > len(candidates) {
		var instructions []review.ContextSource
		instructions, omissions, instructionFailure = fitRepositoryInstructionCandidates(selection, withInstructions[len(candidates):], omissions, limits)
		if instructionFailure != 0 {
			return contextAssembly{}, provider.Request{}, nil, instructionFailure
		}
		candidates = append(candidates, instructions...)
		selection, err = review.SelectContextSources(candidates, limits)
		if err != nil {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureResourceLimit
		}
	}
	// The stated intent comes next: it fills the source budget the selected
	// sources left, so changed code keeps priority, and a cut is marked.
	var intent review.StatedIntent
	if !nilInterface(h.intent) {
		stated, err := h.intent.StatedIntent(ctx, change.Repository(), change.BaseRevision(), change.HeadRevision())
		if err != nil {
			if ctx.Err() != nil {
				return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureCanceled
			}
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
		intent = stated.Fit(int(limits.MaxSourceBytes()) - int(selection.SelectedBytes()))
	}
	// Index context fills what is left, in its fixed priority order.
	// Without a usable repository index, the plan comes from the snapshots
	// this handler already loaded.
	plan, planFailure := h.indexContextPlan(ctx, change.Repository(), change.BaseRevision(), change.HeadRevision())
	if planFailure == 0 && plan.State != review.ContextIndexUsed {
		plan, planFailure = h.boundedSnapshotContextPlan(ctx, request.Plan().Scope(), readAt, base, change, contents, &expires)
	}
	if planFailure != 0 {
		return contextAssembly{}, provider.Request{}, nil, planFailure
	}
	if h.pipeline != nil {
		plan = investigationPlan(plan)
	}
	var fit indexContextFit
	{
		free := int(limits.MaxSourceBytes()) - int(selection.SelectedBytes()) - intent.TextBytes()
		fit, planFailure = fitIndexContext(plan, contents, memoryScope, selection.SelectedSources(), free, review.MaxSelectedContextSources-selection.SelectedCount(), maximumContextCandidates-len(candidates))
		if planFailure != 0 {
			return contextAssembly{}, provider.Request{}, nil, planFailure
		}
		if len(fit.sources) > 0 {
			candidates = append(candidates, fit.sources...)
			selection, err = review.SelectContextSources(candidates, limits)
			if err != nil {
				return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureResourceLimit
			}
		}
	}
	// The review snapshot holds head ranges only. Removed base lines carry base
	// line numbers and are never snapshot ranges; a change that only removes
	// files has a snapshot with no head range.
	ranges := make([]evidence.SourceRange, 0, selection.SelectedCount())
	for _, source := range selection.SelectedSources() {
		if source.Stage() != review.ContextStageRemovedLines {
			ranges = append(ranges, source.EvidenceItem().SourceRange())
		}
	}
	snapshot, err := review.NewAcquiredReviewPipelineSnapshot(request.Plan().Scope().ReviewRunID(), manifest, ranges)
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	if omissions, err = collapseOmissions(omissions); err != nil {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureResourceLimit
	}
	packet, err := review.NewContextPacketWithAccounting(request.Plan().Scope(), memoryScope, snapshot, review.ContextTaskCandidateGeneration, candidates, retrievals, omissions, limits)
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
	}
	if !h.specialist.IsZero() {
		packet, err = packet.WithSpecialist(h.specialist)
		if err != nil {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
	}
	// Deterministic evidence first: pattern hygiene and the stated intent are
	// data in the packet, never instructions, and neither changes the selected
	// sources. The investigation pipeline builds its own context and gets
	// neither.
	if h.pipeline == nil {
		report, hygieneFailure := h.patternHygieneReport(ctx, request.Plan().Scope(), readAt, base, change, contents, &expires)
		if hygieneFailure != 0 {
			return contextAssembly{}, provider.Request{}, nil, hygieneFailure
		}
		packet, err = packet.WithPatternHygiene(review.NewContextPatternHygiene(report, packet.Sources()))
		if err != nil {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
	}
	if !intent.IsZero() {
		packet, err = packet.WithStatedIntent(intent)
		if err != nil {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
	}
	if h.pipeline == nil {
		changed, notListed := manifestDefinitions(plan, packet.Sources())
		packet, err = packet.WithContextManifest(review.ContextManifestSpec{Budget: budget, Plan: plan, Included: fit.included, Omitted: fit.omitted, Changed: changed, ChangedNotListed: notListed})
		if err != nil {
			return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInvalidInput
		}
	}
	providerRequest, err := packet.ProviderRequest()
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureInternal
	}
	contextProvenance := []string{analysisArtifact.Identity(), memoryArtifact.Identity(), changeArtifact.Identity(), headArtifact.Identity(), analysis.Identity(), memoryResult.Identity()}
	sort.Strings(contextProvenance)
	contextArtifact, err := artifact.New(request.Plan().Scope(), artifact.KindContextPacket, "application/json", analysisArtifact.Classification(), artifact.OriginHost, analysisArtifact.Protection(), contextProvenance, providerRequest.Payload(), createdAt, expires)
	if err != nil {
		return contextAssembly{}, provider.Request{}, nil, controlplane.RunFailureResourceLimit
	}
	return contextAssembly{InvestigationAssembly: modelhandler.InvestigationAssembly{
		Packet: packet, Snapshot: snapshot, MemoryScope: memoryScope,
		InitialContextArtifact: contextArtifact,
		AnalysisArtifact:       analysisArtifact, MemoryArtifact: memoryArtifact, ChangeArtifact: changeArtifact,
		BaseSnapshotArtifact: baseArtifact, HeadSnapshotArtifact: headArtifact,
	}, base: base, head: head}, providerRequest, nil, 0
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
		repositoryFile := file.RepositoryFile()
		if repositoryFile.Path() != reference.Path() || repositoryFile.Digest() != reference.Digest() || repositoryFile.SizeBytes() != reference.SizeBytes() {
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
