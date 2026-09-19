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
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
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

type Handler struct {
	identity   string
	store      artifact.Store
	clock      artifact.Clock
	authorizer GenerationAuthorizer
	pipeline   *modelhandler.InvestigationPipeline
}

func NewHandler(store artifact.Store, clock artifact.Clock, authorizer GenerationAuthorizer) (*Handler, error) {
	if nilInterface(store) || nilInterface(clock) || nilInterface(authorizer) || !validDigest(authorizer.Identity()) {
		return nil, ErrInvalidHandler
	}
	h := &Handler{store: store, clock: clock, authorizer: authorizer}
	h.identity = deriveHandlerIdentity(authorizer.Identity())
	return h, nil
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
	if h.pipeline != nil {
		identity, err := h.pipeline.HandlerIdentity(controlplane.TaskAssembleContext)
		if h.pipeline.Validate() != nil || err != nil || !validDigest(identity) || h.identity != identity || !nilInterface(h.authorizer) {
			return ErrInvalidHandler
		}
		return nil
	}
	if nilInterface(h.authorizer) || !validDigest(h.authorizer.Identity()) || h.identity != deriveHandlerIdentity(h.authorizer.Identity()) {
		return ErrInvalidHandler
	}
	return nil
}
func deriveHandlerIdentity(authorizer string) string {
	encoded, _ := json.Marshal(struct {
		Contract   string `json:"contract"`
		Version    int    `json:"version"`
		Authorizer string `json:"authorizer"`
	}{"open-trestle/context-assembly-handler", 4, authorizer})
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
	at := h.clock.Now().UTC()
	if at.UnixMilli() <= 0 || at.After(request.Lease().ExpiresAt()) {
		return failure(controlplane.RunFailureCanceled)
	}
	assembly, providerRequest, assemblyFailure := h.assemble(ctx, request, at)
	if assemblyFailure != 0 {
		return failure(assemblyFailure)
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
	authorization, err := h.authorizer.Authorize(ctx, request.Plan().Scope(), providerRequest, request.Plan().PolicyIdentity(), at)
	if err != nil {
		if ctx.Err() != nil {
			return failure(controlplane.RunFailureCanceled)
		}
		return failure(controlplane.RunFailurePolicy)
	}
	if authorization.Validate() != nil || authorization.RequestIdentity() != providerRequest.Identity() || authorization.ReviewScopeIdentity() != request.Plan().Scope().Identity() {
		return failure(controlplane.RunFailurePolicy)
	}
	input, err := modelhandler.NewGenerationInput(contextArtifact, packet, snapshot, authorization)
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
	if _, err := h.store.Put(ctx, inputArtifact, at); err != nil {
		return failure(writeFailure(ctx, err))
	}
	completion, err := controlplane.NewTaskSuccess(inputArtifact.Identity())
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	return completion
}

func (h *Handler) assemble(ctx context.Context, request controlplane.TaskExecutionRequest, at time.Time) (modelhandler.InvestigationAssembly, provider.Request, controlplane.RunFailure) {
	analysisDependency, ok := request.DependencyOutput("analysis")
	if !ok || !analysisDependency.Available() {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
	}
	memoryDependency, ok := request.DependencyOutput("memory")
	if !ok || !memoryDependency.Available() {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
	}
	analysisArtifact, err := h.store.Get(ctx, request.Plan().Scope(), analysisDependency.OutputIdentity(), at)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, readFailure(ctx, err)
	}
	memoryArtifact, err := h.store.Get(ctx, request.Plan().Scope(), memoryDependency.OutputIdentity(), at)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, readFailure(ctx, err)
	}
	changeID, err := analysisChangeArtifactIdentity(analysisArtifact)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
	}
	changeArtifact, err := h.store.Get(ctx, request.Plan().Scope(), changeID, at)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, readFailure(ctx, err)
	}
	baseID, headID, err := changehandler.ResultArtifactReferences(changeArtifact)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
	}
	baseArtifact, err := h.store.Get(ctx, request.Plan().Scope(), baseID, at)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, readFailure(ctx, err)
	}
	headArtifact, err := h.store.Get(ctx, request.Plan().Scope(), headID, at)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, readFailure(ctx, err)
	}
	_, err = changehandler.ParseResultArtifact(changeArtifact, baseArtifact, headArtifact)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
	}
	analysis, err := analysishandler.ParseResultArtifact(analysisArtifact, changeArtifact, baseArtifact, headArtifact)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
	}
	memoryResult, err := memoryhandler.ParseResultArtifact(memoryArtifact, changeArtifact, baseArtifact, headArtifact)
	if err != nil || memoryResult.ChangeArtifactIdentity() != analysis.ChangeArtifactIdentity() || memoryResult.PolicyIdentity() != request.Plan().PolicyIdentity() {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
	}
	head, err := sourcehandler.ParseSnapshotArtifact(headArtifact)
	if err != nil || head.Identity() != analysis.HeadSnapshotIdentity() || head.ManifestIdentity() != analysis.HeadManifestIdentity() {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
	}
	memoryScope, err := memoryResult.MemoryScope()
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
	}
	queries := memoryResult.Queries()
	if len(queries) == 0 {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailurePolicy
	}
	retrievals := make([]memorycore.LexicalRetrieval, len(queries))
	memoryItems := 0
	for index, query := range queries {
		retrievals[index], err = query.Retrieval(memoryScope, memoryResult.AsOf())
		if err != nil {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
		}
		memoryItems += len(retrievals[index].Items())
	}
	contents, manifest, expires, loadFailure := h.loadHead(ctx, request.Plan().Scope(), head, at, minimumTime(analysisArtifact.ExpiresAt(), memoryArtifact.ExpiresAt(), changeArtifact.ExpiresAt(), baseArtifact.ExpiresAt(), headArtifact.ExpiresAt()))
	if loadFailure != 0 {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, loadFailure
	}
	defer clearContents(contents)
	omissions := make([]review.ContextSourceOmission, 0, len(analysis.Gaps()))
	for _, gap := range analysis.Gaps() {
		omission, omissionErr := review.NewContextSourceOmission(gap.Path(), gap.StartLine(), gap.EndLine(), "analysis_"+gap.Reason())
		if omissionErr != nil {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
		}
		omissions = append(omissions, omission)
	}
	semanticProfile := analysis.SemanticImpact()
	for _, gap := range semanticProfile.Gaps() {
		omission, omissionErr := review.NewContextSourceOmission(gap.Path(), 0, 0, "semantic_"+string(gap.Reason()))
		if omissionErr != nil {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
		}
		omissions = append(omissions, omission)
	}
	candidates := make([]review.ContextSource, 0, maximumContextCandidates)
	for _, item := range analysis.Items() {
		content, exists := contents[item.Path()]
		if !exists {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
		}
		repositoryFile, err := evidence.NewRepositoryFile(item.Path(), content)
		if err != nil || repositoryFile.Identity() != item.FileIdentity() || repositoryFile.Digest() != item.FileDigest() {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
		}
		rangeValue, err := evidence.NewSourceRange(item.Path(), item.StartLine(), item.EndLine())
		if err != nil {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
		}
		slice, ok := physicalLineSlice(content, item.StartLine(), item.EndLine())
		if !ok {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
		}
		binding, err := evidence.BindSourceSlice(repositoryFile, content, rangeValue, slice)
		if err != nil || binding.Identity() != item.BindingIdentity() || binding.SliceBytes() != item.SliceBytes() {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
		}
		reason := ""
		switch {
		case !memoryScope.AllowsPath(item.Path()):
			reason = "path_not_authorized"
		case len(slice) > maximumContextSourceBytes:
			reason = "source_size_limit"
		case len(candidates) >= maximumContextCandidates:
			reason = "candidate_limit"
		}
		if reason != "" {
			omission, omissionErr := review.NewContextSourceOmission(item.Path(), item.StartLine(), item.EndLine(), reason)
			if omissionErr != nil {
				return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInternal
			}
			omissions = append(omissions, omission)
			continue
		}
		evidenceItem, err := item.EvidenceItem()
		if err != nil {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
		}
		source, err := review.NewBoundContextSource(review.ContextStageChangedHunk, memorycore.TaintRepositoryControlled, evidenceItem, slice, binding)
		if err != nil {
			return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
		}
		candidates = append(candidates, source)
	}
	candidates, omissions, semanticFailure := appendSemanticCandidates(contents, memoryScope, semanticProfile, candidates, omissions)
	if semanticFailure != 0 {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, semanticFailure
	}
	if len(candidates) == 0 {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailurePolicy
	}
	limits, _ := review.NewContextLimits(maximumContextPacketSourceBytes, uint8(min(50, memoryItems)))
	selection, err := review.SelectContextSources(candidates, limits)
	if err != nil || selection.SelectedCount() == 0 {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureResourceLimit
	}
	ranges := make([]evidence.SourceRange, selection.SelectedCount())
	for index, source := range selection.SelectedSources() {
		ranges[index] = source.EvidenceItem().SourceRange()
	}
	snapshot, err := review.NewAcquiredReviewPipelineSnapshot(request.Plan().Scope().ReviewRunID(), manifest, ranges)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
	}
	packet, err := review.NewContextPacketWithAccounting(request.Plan().Scope(), memoryScope, snapshot, review.ContextTaskCandidateGeneration, candidates, retrievals, omissions, limits)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInvalidInput
	}
	providerRequest, err := packet.ProviderRequest()
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureInternal
	}
	contextProvenance := []string{analysisArtifact.Identity(), memoryArtifact.Identity(), changeArtifact.Identity(), headArtifact.Identity(), analysis.Identity(), memoryResult.Identity()}
	sort.Strings(contextProvenance)
	contextArtifact, err := artifact.New(request.Plan().Scope(), artifact.KindContextPacket, "application/json", analysisArtifact.Classification(), artifact.OriginHost, analysisArtifact.Protection(), contextProvenance, providerRequest.Payload(), at, expires)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, provider.Request{}, controlplane.RunFailureResourceLimit
	}
	return modelhandler.InvestigationAssembly{
		Packet: packet, Snapshot: snapshot, MemoryScope: memoryScope,
		InitialContextArtifact: contextArtifact,
		AnalysisArtifact:       analysisArtifact, MemoryArtifact: memoryArtifact, ChangeArtifact: changeArtifact,
		BaseSnapshotArtifact: baseArtifact, HeadSnapshotArtifact: headArtifact,
	}, providerRequest, 0
}

func (h *Handler) loadHead(ctx context.Context, scope audit.ReviewScope, head sourcehandler.Snapshot, at, expires time.Time) (map[string][]byte, evidence.RepositoryManifest, time.Time, controlplane.RunFailure) {
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
		file, err := sourcehandler.ParseFileArtifact(value, head, reference)
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
