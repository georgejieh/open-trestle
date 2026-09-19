package fake

import (
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/controlplane"
	"strings"
	"testing"
)

func TestNewHandlerValidatesConfiguration(t *testing.T) {
	completion, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
	handler, err := NewHandler(strings.Repeat("d", 64), controlplane.TaskAcquireSource, completion)
	if err != nil || handler.HandlerIdentity() != strings.Repeat("d", 64) || handler.Kind() != controlplane.TaskAcquireSource || handler.CallCount() != 0 || fmt.Sprint(handler) != "fake review task handler" {
		t.Fatalf("handler=(%#v,%v)", handler, err)
	}
	if invalid, err := NewHandler("bad", controlplane.TaskAcquireSource, completion); !errors.Is(err, ErrInvalidHandlerConfiguration) || invalid != nil {
		t.Fatalf("invalid=(%#v,%v)", invalid, err)
	}
}
func TestHandlerFailsClosedForInvalidRequest(t *testing.T) {
	completion, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
	handler, _ := NewHandler(strings.Repeat("d", 64), controlplane.TaskAcquireSource, completion)
	result := handler.Execute(nil, controlplane.TaskExecutionRequest{})
	if result.Status() != controlplane.TaskCompletionFailed || result.Failure() != controlplane.RunFailureInvalidInput || handler.CallCount() != 0 {
		t.Fatalf("result=%#v calls=%d", result, handler.CallCount())
	}
}
