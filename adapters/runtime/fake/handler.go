// Package fake provides deterministic review-run handlers without external effects.
package fake

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/georgejieh/open-trestle/controlplane"
)

var ErrInvalidHandlerConfiguration = errors.New("invalid fake task handler configuration")

// Handler returns one configured closed completion for its exact identity and kind.
type Handler struct {
	mu         sync.Mutex
	identity   string
	kind       controlplane.TaskKind
	completion controlplane.TaskCompletion
	calls      int
}

func NewHandler(identity string, kind controlplane.TaskKind, completion controlplane.TaskCompletion) (*Handler, error) {
	if controlplane.ValidateHandlerIdentity(identity) != nil {
		return nil, ErrInvalidHandlerConfiguration
	}
	if err := kind.Validate(); err != nil {
		return nil, err
	}
	if err := completion.Validate(); err != nil {
		return nil, err
	}
	return &Handler{identity: identity, kind: kind, completion: completion}, nil
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
	return h.kind
}
func (h *Handler) Execute(ctx context.Context, request controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if h == nil || ctx == nil || ctx.Err() != nil || request.Validate() != nil || request.Task().HandlerIdentity() != h.identity || request.Task().Kind() != h.kind {
		failure, _ := controlplane.NewTaskFailure(controlplane.RunFailureInvalidInput)
		return failure
	}
	h.mu.Lock()
	h.calls++
	completion := h.completion
	h.mu.Unlock()
	return completion
}
func (h *Handler) CallCount() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}
func (h *Handler) String() string   { return "fake review task handler" }
func (h *Handler) GoString() string { return "fake.Handler{<redacted>}" }
func (h *Handler) Format(state fmt.State, verb rune) {
	formatted := "fake review task handler"
	if verb == 'q' {
		formatted = `"fake review task handler"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "fake.Handler{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

var _ controlplane.TaskHandler = (*Handler)(nil)
