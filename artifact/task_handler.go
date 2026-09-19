package artifact

import (
	"context"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"reflect"
	"sort"
	"time"
)

var ErrInvalidTaskHandler = errors.New("invalid artifact-validating task handler")

// Reader retrieves one exact scoped artifact.
type Reader interface {
	Get(context.Context, audit.ReviewScope, string, time.Time) (Artifact, error)
}

// Clock supplies artifact retention evaluation time.
type Clock interface{ Now() time.Time }

// ValidatedTaskHandler fences an approved handler with durable input and output checks.
type ValidatedTaskHandler struct {
	inner                   controlplane.TaskHandler
	reader                  Reader
	clock                   Clock
	handlerIdentity         string
	kind                    controlplane.TaskKind
	inputKinds, outputKinds []Kind
}

func NewValidatedTaskHandler(inner controlplane.TaskHandler, reader Reader, clock Clock, inputKinds, outputKinds []Kind) (*ValidatedTaskHandler, error) {
	if isNilHandler(inner) || isNilReader(reader) || clock == nil || controlplane.ValidateHandlerIdentity(inner.HandlerIdentity()) != nil || inner.Kind().Validate() != nil {
		return nil, ErrInvalidTaskHandler
	}
	inputs, err := canonicalKinds(inputKinds)
	if err != nil {
		return nil, err
	}
	outputs, err := canonicalKinds(outputKinds)
	if err != nil {
		return nil, err
	}
	return &ValidatedTaskHandler{inner: inner, reader: reader, clock: clock, handlerIdentity: inner.HandlerIdentity(), kind: inner.Kind(), inputKinds: inputs, outputKinds: outputs}, nil
}
func (h *ValidatedTaskHandler) HandlerIdentity() string {
	if h == nil {
		return ""
	}
	return h.handlerIdentity
}
func (h *ValidatedTaskHandler) Kind() controlplane.TaskKind {
	if h == nil {
		return 0
	}
	return h.kind
}
func (h *ValidatedTaskHandler) Execute(ctx context.Context, request controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if h == nil || ctx == nil || ctx.Err() != nil || request.Validate() != nil || h.inner.HandlerIdentity() != h.handlerIdentity || h.inner.Kind() != h.kind {
		return taskFailure(controlplane.RunFailureInternal)
	}
	scope := request.Plan().Scope()
	inputIdentities := []string{request.Task().InputIdentity()}
	if dependencies := request.DependencyOutputs(); len(dependencies) != 0 {
		inputIdentities = make([]string, 0, len(dependencies))
		for _, dependency := range dependencies {
			if dependency.Available() {
				inputIdentities = append(inputIdentities, dependency.OutputIdentity())
			}
		}
	}
	inputs := make([]Artifact, len(inputIdentities))
	for index, identity := range inputIdentities {
		input, err := h.reader.Get(ctx, scope, identity, h.clock.Now())
		if err != nil {
			return taskFailure(controlplane.RunFailureInternal)
		}
		if !kindAllowed(h.inputKinds, input.Kind()) {
			return taskFailure(controlplane.RunFailureInvalidInput)
		}
		inputs[index] = input
	}
	completion := h.inner.Execute(ctx, request)
	if completion.Validate() != nil {
		return taskFailure(controlplane.RunFailureInternal)
	}
	if completion.Status() == controlplane.TaskCompletionFailed {
		return completion
	}
	output, err := h.reader.Get(ctx, scope, completion.OutputIdentity(), h.clock.Now())
	if err != nil {
		return taskFailure(controlplane.RunFailureInternal)
	}
	if !kindAllowed(h.outputKinds, output.Kind()) {
		return taskFailure(controlplane.RunFailureInvalidInput)
	}
	for _, input := range inputs {
		if !hasProvenance(output.Provenance(), input.Identity()) {
			return taskFailure(controlplane.RunFailureInvalidInput)
		}
	}
	return completion
}
func (h *ValidatedTaskHandler) String() string   { return "artifact-validating task handler" }
func (h *ValidatedTaskHandler) GoString() string { return "artifact.ValidatedTaskHandler{<redacted>}" }
func (h *ValidatedTaskHandler) Format(state fmt.State, verb rune) {
	value := "artifact-validating task handler"
	if verb == 'q' {
		value = `"artifact-validating task handler"`
	} else if verb == 'v' && state.Flag('#') {
		value = "artifact.ValidatedTaskHandler{<redacted>}"
	}
	_, _ = state.Write([]byte(value))
}
func canonicalKinds(values []Kind) ([]Kind, error) {
	if len(values) == 0 || len(values) > 10 {
		return nil, ErrInvalidTaskHandler
	}
	canonical := append([]Kind(nil), values...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i] < canonical[j] })
	for index, value := range canonical {
		if value.String() == "" || index > 0 && value == canonical[index-1] {
			return nil, ErrInvalidTaskHandler
		}
	}
	return canonical, nil
}
func kindAllowed(values []Kind, value Kind) bool {
	index := sort.Search(len(values), func(index int) bool { return values[index] >= value })
	return index < len(values) && values[index] == value
}
func hasProvenance(values []string, identity string) bool {
	index := sort.SearchStrings(values, identity)
	return index < len(values) && values[index] == identity
}

func taskFailure(failure controlplane.RunFailure) controlplane.TaskCompletion {
	completion, _ := controlplane.NewTaskFailure(failure)
	return completion
}
func isNilHandler(handler controlplane.TaskHandler) bool {
	if handler == nil {
		return true
	}
	value := reflect.ValueOf(handler)
	return value.Kind() == reflect.Ptr && value.IsNil()
}
func isNilReader(reader Reader) bool {
	if reader == nil {
		return true
	}
	value := reflect.ValueOf(reader)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

var _ controlplane.TaskHandler = (*ValidatedTaskHandler)(nil)
