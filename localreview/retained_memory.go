package localreview

import (
	"context"
	"time"

	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// retainedMemoryRetriever exposes search, not mutation, to the memory handler.
type retainedMemoryRetriever struct {
	index *memory.LexicalIndex
	scope memory.Scope
}

// newRetainedMemoryRetriever indexes a snapshot after Session validates its bindings.
func newRetainedMemoryRetriever(input runtimeconfig.RetainedMemoryInput) (*retainedMemoryRetriever, error) {
	scope, records := input.Scope(), input.Records()
	if input.Identity() == "" || scope.Validate() != nil || len(records) == 0 || len(records) > 16 {
		return nil, ErrInvalidSession
	}
	index := memory.NewLexicalIndex()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, record := range records {
		if _, added, err := index.Add(ctx, scope, record); err != nil || !added {
			return nil, ErrInvalidSession
		}
	}
	return &retainedMemoryRetriever{index: index, scope: scope}, nil
}

func (r *retainedMemoryRetriever) Search(ctx context.Context, scope memory.Scope, query memory.LexicalQuery) (memory.LexicalRetrieval, error) {
	if r == nil || r.index == nil {
		return memory.LexicalRetrieval{}, memory.ErrInvalidMemoryIndex
	}
	if scope.Validate() != nil || scope.Identity() != r.scope.Identity() {
		return memory.LexicalRetrieval{}, memory.ErrMemoryQueryScopeMismatch
	}
	return r.index.Search(ctx, scope, query)
}

func validateRetainedMemory(o SessionOptions, headIdentity string, at time.Time) error {
	if o.RetainedMemoryInput == nil || o.Egress != EgressLocalOnly {
		return runtimeconfig.ErrInvalidRetainedMemoryInput
	}
	scope, err := memory.NewScope(o.TenantID, o.RepositoryID, "local-reviewer", memory.RefVisibilityExact, headIdentity, []string{"."})
	if err != nil {
		return runtimeconfig.ErrInvalidRetainedMemoryInput
	}
	return o.RetainedMemoryInput.ValidateFor(scope, o.Repository, o.Policy, at)
}
