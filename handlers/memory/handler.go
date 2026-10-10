package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/memorycodec"
	"reflect"
	"sort"
	"strings"
	"time"
)

type Retriever interface {
	Search(context.Context, memorycore.Scope, memorycore.LexicalQuery) (memorycore.LexicalRetrieval, error)
}
type Handler struct {
	identity                                   string
	store                                      artifact.Store
	clock                                      artifact.Clock
	retriever                                  Retriever
	retrieverIdentity, policyIdentity, actorID string
	pathPrefixes                               []string
	queryLimit, totalLimit                     uint8
}

func NewHandler(store artifact.Store, clock artifact.Clock, retriever Retriever, retrieverIdentity, policyIdentity, actorID string, pathPrefixes []string, queryLimit, totalLimit uint8) (*Handler, error) {
	placeholder, err := memorycore.NewScope("tenant", "repository", actorID, memorycore.RefVisibilityExact, strings.Repeat("a", 64), pathPrefixes)
	if nilInterface(store) || nilInterface(clock) || nilInterface(retriever) || err != nil || !validDigest(retrieverIdentity) || !validDigest(policyIdentity) || queryLimit == 0 || queryLimit > maximumQueries || totalLimit == 0 || totalLimit > maximumRecords {
		return nil, ErrInvalidHandler
	}
	handler := &Handler{store: store, clock: clock, retriever: retriever, retrieverIdentity: retrieverIdentity, policyIdentity: policyIdentity, actorID: actorID, pathPrefixes: placeholder.PathPrefixes(), queryLimit: queryLimit, totalLimit: totalLimit}
	handler.identity = deriveHandlerIdentity(handler)
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
	return controlplane.TaskRetrieveContext
}
func (h *Handler) Validate() error {
	if h == nil || nilInterface(h.store) || nilInterface(h.clock) || nilInterface(h.retriever) || !validDigest(h.retrieverIdentity) || !validDigest(h.policyIdentity) || h.queryLimit == 0 || h.queryLimit > maximumQueries || h.totalLimit == 0 || h.totalLimit > maximumRecords || h.identity != deriveHandlerIdentity(h) {
		return ErrInvalidHandler
	}
	return nil
}
func deriveHandlerIdentity(h *Handler) string {
	encoded, _ := json.Marshal(struct {
		Contract  string   `json:"contract"`
		Version   int      `json:"version"`
		Retriever string   `json:"retriever"`
		Policy    string   `json:"policy"`
		Actor     string   `json:"actor"`
		Prefixes  []string `json:"prefixes"`
		Queries   uint8    `json:"queries"`
		Records   uint8    `json:"records"`
	}{"open-trestle/memory-retrieval-handler", 1, h.retrieverIdentity, h.policyIdentity, h.actorID, h.pathPrefixes, h.queryLimit, h.totalLimit})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func (h *Handler) Execute(ctx context.Context, request controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if nilInterface(ctx) || h.Validate() != nil || request.Validate() != nil || request.Task().Kind() != controlplane.TaskRetrieveContext || request.Task().HandlerIdentity() != h.identity || !equalStrings(request.Task().Dependencies(), []string{"change"}) || request.Plan().PolicyIdentity() != h.policyIdentity {
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
	scope, err := memorycore.NewScope(request.Plan().Scope().TenantID(), request.Plan().Scope().RepositoryID(), h.actorID, memorycore.RefVisibilityExact, change.HeadRevision().Identity(), h.pathPrefixes)
	if err != nil {
		return failure(controlplane.RunFailureInvalidInput)
	}
	queries := make([]Query, 0, h.queryLimit)
	omissions := make([]Omission, 0)
	records := 0
	expires := at.Add(time.Hour)
	for _, entry := range change.Entries() {
		if ctx.Err() != nil {
			return failure(controlplane.RunFailureCanceled)
		}
		if !scope.AllowsPath(entry.Path()) {
			omission, err := memorycodec.NewOmission(entry.Path(), "path_not_authorized")
			if err != nil {
				return failure(controlplane.RunFailureInternal)
			}
			omissions = append(omissions, omission)
			continue
		}
		if len(queries) >= int(h.queryLimit) {
			omission, err := memorycodec.NewOmission(entry.Path(), "query_limit")
			if err != nil {
				return failure(controlplane.RunFailureInternal)
			}
			omissions = append(omissions, omission)
			continue
		}
		remaining := int(h.totalLimit) - records
		if remaining <= 0 {
			omission, err := memorycodec.NewOmission(entry.Path(), "result_limit")
			if err != nil {
				return failure(controlplane.RunFailureInternal)
			}
			omissions = append(omissions, omission)
			continue
		}
		query, err := memorycore.NewLexicalQuery(scope, entry.Path(), nil, nil, at, uint8(remaining))
		if err != nil {
			return failure(controlplane.RunFailureInvalidInput)
		}
		retrieval, err := h.retriever.Search(ctx, scope, query)
		if err != nil {
			return failure(retrievalFailure(ctx, err))
		}
		if retrieval.Validate() != nil || retrieval.Query().Identity() != query.Identity() || retrieval.ScopeIdentity() != scope.Identity() {
			return failure(controlplane.RunFailureInternal)
		}
		for _, value := range retrieval.Items() {
			record := value.Record()
			for _, candidate := range []int64{record.ValidUntilUnixMilliseconds(), record.StaleAfterUnixMilliseconds()} {
				if candidate > at.UnixMilli() && time.UnixMilli(candidate).Before(expires) {
					expires = time.UnixMilli(candidate)
				}
			}
		}
		wireQuery, err := memorycodec.NewQuery(scope, query, retrieval)
		if err != nil {
			return failure(controlplane.RunFailureInternal)
		}
		queries = append(queries, wireQuery)
		records += len(retrieval.Items())
	}
	result, err := newResult(changeArtifact, change, h.policyIdentity, h.retrieverIdentity, scope, at, queries, omissions)
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	payload, err := encodeResult(result, change)
	if err != nil {
		return failure(controlplane.RunFailureResourceLimit)
	}
	for _, value := range []time.Time{changeArtifact.ExpiresAt(), baseArtifact.ExpiresAt(), headArtifact.ExpiresAt()} {
		if value.Before(expires) {
			expires = value
		}
	}
	provenance := []string{changeArtifact.Identity(), change.Identity(), h.policyIdentity, scope.Identity(), h.retrieverIdentity}
	sort.Strings(provenance)
	output, err := artifact.New(request.Plan().Scope(), artifact.KindRetrievalResult, "application/json", changeArtifact.Classification(), artifact.OriginMemory, changeArtifact.Protection(), provenance, payload, at, expires)
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
func retrievalFailure(ctx context.Context, err error) controlplane.RunFailure {
	if ctx.Err() != nil || errors.Is(err, memorycore.ErrMemoryContextDone) {
		return controlplane.RunFailureCanceled
	}
	if errors.Is(err, memorycore.ErrMemoryIndexCapacity) {
		return controlplane.RunFailureResourceLimit
	}
	return controlplane.RunFailureInternal
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
func (h *Handler) String() string   { return "memory retrieval task handler" }
func (h *Handler) GoString() string { return "memory.Handler{<redacted>}" }
func (h *Handler) Format(s fmt.State, v rune) {
	writeRedacted(s, v, "memory retrieval task handler", "memory.Handler{<redacted>}")
}

var _ controlplane.TaskHandler = (*Handler)(nil)
