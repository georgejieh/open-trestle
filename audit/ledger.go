package audit

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
)

const maxAuditReadEvents = 1_000

var (
	// ErrInvalidAuditLedger identifies a missing ledger implementation.
	ErrInvalidAuditLedger = errors.New("invalid audit ledger")
	// ErrInvalidAuditContext identifies a nil operation context.
	ErrInvalidAuditContext = errors.New("invalid audit context")
	// ErrAuditContextDone identifies an operation canceled before it changed or returned state.
	ErrAuditContextDone = errors.New("audit context done")
	// ErrInvalidAuditExpectedHead identifies a malformed optimistic-concurrency token.
	ErrInvalidAuditExpectedHead = errors.New("invalid audit expected head")
	// ErrAuditHeadConflict identifies a stream changed since the caller observed its head.
	ErrAuditHeadConflict = errors.New("audit head conflict")
	// ErrAuditChainMismatch identifies an event whose sequence or predecessor is not next.
	ErrAuditChainMismatch = errors.New("audit chain mismatch")
	// ErrInvalidAuditReadLimit identifies an unbounded or excessive read request.
	ErrInvalidAuditReadLimit = errors.New("invalid audit read limit")
)

// Ledger appends and reads immutable events under an atomic per-scope head check.
type Ledger interface {
	Append(context.Context, string, Event) error
	Head(context.Context, ReviewScope) (Event, bool, error)
	Read(context.Context, ReviewScope, uint64, uint16) ([]Event, error)
}

// MemoryLedger provides the ledger contract for local ephemeral use and conformance tests.
type MemoryLedger struct {
	mu      sync.RWMutex
	streams map[string][]Event
}

// NewMemoryLedger creates an empty concurrency-safe ledger.
func NewMemoryLedger() *MemoryLedger {
	return &MemoryLedger{streams: make(map[string][]Event)}
}

// Append atomically checks the expected head and appends exactly the next event.
func (l *MemoryLedger) Append(ctx context.Context, expectedHead string, event Event) error {
	if l == nil {
		return ErrInvalidAuditLedger
	}
	if err := validateAuditContext(ctx); err != nil {
		return err
	}
	if expectedHead != "" && !validAuditIdentity(expectedHead) {
		return ErrInvalidAuditExpectedHead
	}
	if err := event.Validate(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := auditContextDone(ctx); err != nil {
		return err
	}
	if l.streams == nil {
		l.streams = make(map[string][]Event)
	}
	stream := l.streams[event.Scope().Identity()]
	currentHead := ""
	if len(stream) != 0 {
		currentHead = stream[len(stream)-1].Identity()
	}
	if expectedHead != currentHead {
		return ErrAuditHeadConflict
	}
	expectedSequence := uint64(len(stream)) + 1
	if event.Sequence() != expectedSequence || event.PreviousIdentity() != currentHead {
		return ErrAuditChainMismatch
	}
	l.streams[event.Scope().Identity()] = append(stream, cloneEvent(event))
	return nil
}

// Head returns the current event for one exact scope.
func (l *MemoryLedger) Head(ctx context.Context, scope ReviewScope) (Event, bool, error) {
	if l == nil {
		return Event{}, false, ErrInvalidAuditLedger
	}
	if err := validateAuditContext(ctx); err != nil {
		return Event{}, false, err
	}
	if err := scope.Validate(); err != nil {
		return Event{}, false, err
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if err := auditContextDone(ctx); err != nil {
		return Event{}, false, err
	}
	stream := l.streams[scope.Identity()]
	if len(stream) == 0 {
		return Event{}, false, nil
	}
	return cloneEvent(stream[len(stream)-1]), true, nil
}

// Read returns events after the supplied sequence, bounded by limit.
func (l *MemoryLedger) Read(ctx context.Context, scope ReviewScope, afterSequence uint64, limit uint16) ([]Event, error) {
	if l == nil {
		return nil, ErrInvalidAuditLedger
	}
	if err := validateAuditContext(ctx); err != nil {
		return nil, err
	}
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if limit == 0 || limit > maxAuditReadEvents {
		return nil, ErrInvalidAuditReadLimit
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if err := auditContextDone(ctx); err != nil {
		return nil, err
	}
	stream := l.streams[scope.Identity()]
	if afterSequence >= uint64(len(stream)) {
		return nil, nil
	}
	start := int(afterSequence)
	end := start + int(limit)
	if end > len(stream) {
		end = len(stream)
	}
	result := make([]Event, end-start)
	for index := range result {
		result[index] = cloneEvent(stream[start+index])
	}
	return result, nil
}

func cloneEvent(event Event) Event {
	event.causalParentIdentities = append([]string(nil), event.causalParentIdentities...)
	return event
}

func validateAuditContext(ctx context.Context) error {
	if isNilInterface(ctx) {
		return ErrInvalidAuditContext
	}
	return auditContextDone(ctx)
}

func auditContextDone(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditContextDone, err)
	}
	return nil
}

func isNilInterface(candidate any) bool {
	if candidate == nil {
		return true
	}
	value := reflect.ValueOf(candidate)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
