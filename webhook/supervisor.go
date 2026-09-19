package webhook

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxSupervisorQueue      = 4096
	maxSupervisorRetries    = 10
	maxSupervisorDeliveries = 10_000
	minimumSupervisorDelay  = 10 * time.Millisecond
	maximumSupervisorDelay  = time.Minute
)

var (
	// ErrInvalidSupervisor identifies unsafe durable-inbox processing configuration.
	ErrInvalidSupervisor = errors.New("invalid webhook supervisor")
	// ErrSupervisorRunning identifies concurrent use of one supervisor.
	ErrSupervisorRunning = errors.New("webhook supervisor already running")
	// ErrSupervisorUnavailable identifies exhausted bounded processing retries.
	ErrSupervisorUnavailable = errors.New("webhook supervisor unavailable")
)

// DeliveryNotice is a content-free hint that a durable delivery may need processing.
type DeliveryNotice struct {
	Scope            RepositoryScope
	Source           Source
	DeduplicationKey string
}

func (n DeliveryNotice) Validate() error {
	if n.Scope.Validate() != nil || n.Source.Validate() != nil || !validWebhookDigest(n.DeduplicationKey) {
		return ErrInvalidSupervisor
	}
	return nil
}

// DeliveryNotifier accepts a best-effort content-free wake-up after durable intake.
type DeliveryNotifier interface{ Notify(DeliveryNotice) bool }

// SupervisorClock supplies processing time.
type SupervisorClock interface{ Now() time.Time }

// SupervisorOptions bounds queueing and retry behavior.
type SupervisorOptions struct {
	QueueCapacity  uint16
	MaximumRetries uint8
	RetryDelay     time.Duration
	Clock          SupervisorClock
}

// Supervisor reconciles a durable repository inbox into idempotent review runs.
type Supervisor struct {
	store     Store
	processor *Processor
	scope     RepositoryScope
	source    Source
	options   SupervisorOptions
	notices   chan DeliveryNotice
	wake      chan struct{}
	overflow  atomic.Bool
	running   atomic.Bool
	ready     chan struct{}
	readyOnce sync.Once
}

// NewSupervisor fixes one bounded processor to one repository and webhook protocol.
func NewSupervisor(store Store, processor *Processor, scope RepositoryScope, source Source, options SupervisorOptions) (*Supervisor, error) {
	validQueue := options.QueueCapacity > 0 && options.QueueCapacity <= maxSupervisorQueue
	validRetries := options.MaximumRetries > 0 && options.MaximumRetries <= maxSupervisorRetries
	validDelay := options.RetryDelay >= minimumSupervisorDelay && options.RetryDelay <= maximumSupervisorDelay
	if isNilStore(store) || processor == nil || scope.Validate() != nil || source.Validate() != nil || !validQueue || !validRetries || !validDelay || nilSupervisorClock(options.Clock) {
		return nil, ErrInvalidSupervisor
	}
	return &Supervisor{
		store: store, processor: processor, scope: scope, source: source, options: options,
		notices: make(chan DeliveryNotice, options.QueueCapacity), wake: make(chan struct{}, 1), ready: make(chan struct{}),
	}, nil
}

// Notify queues a best-effort hint without blocking webhook acknowledgment.
func (s *Supervisor) Notify(notice DeliveryNotice) bool {
	if s == nil || notice.Validate() != nil || notice.Scope.Identity() != s.scope.Identity() || notice.Source != s.source {
		return false
	}
	select {
	case s.notices <- notice:
		return true
	default:
		s.overflow.Store(true)
		select {
		case s.wake <- struct{}{}:
		default:
		}
		return false
	}
}

// Ready closes after the initial durable reconciliation succeeds.
func (s *Supervisor) Ready() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.ready
}

// Run reconciles durable intake and processes new hints until cancellation.
func (s *Supervisor) Run(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalidSupervisor
	}
	if !s.running.CompareAndSwap(false, true) {
		return ErrSupervisorRunning
	}
	defer s.running.Store(false)
	if err := s.retry(ctx, s.reconcile); err != nil {
		return err
	}
	s.readyOnce.Do(func() { close(s.ready) })
	for {
		select {
		case <-ctx.Done():
			return nil
		case notice := <-s.notices:
			if err := s.retry(ctx, func(operationContext context.Context) error { return s.processNotice(operationContext, notice) }); err != nil {
				return err
			}
			if s.overflow.Swap(false) {
				if err := s.retry(ctx, s.reconcile); err != nil {
					return err
				}
			}
		case <-s.wake:
			s.overflow.Store(false)
			if err := s.retry(ctx, s.reconcile); err != nil {
				return err
			}
		}
	}
}

func (s *Supervisor) reconcile(ctx context.Context) error {
	cursor := ""
	total := 0
	for {
		page, err := s.store.List(ctx, s.scope, s.source, cursor, 100)
		if err != nil {
			return err
		}
		for _, stored := range page {
			if total >= maxSupervisorDeliveries {
				return ErrInvalidSupervisor
			}
			if stored.Validate() != nil {
				return ErrInvalidSupervisor
			}
			if _, _, err := s.processor.Process(ctx, stored, s.options.Clock.Now().UTC()); err != nil && !errors.Is(err, ErrPreparedInputsExpired) {
				return err
			}
			total++
			if total > maxSupervisorDeliveries {
				return ErrInvalidSupervisor
			}
		}
		if len(page) < 100 {
			return nil
		}
		cursor = page[len(page)-1].Delivery().DeduplicationKey()
	}
}
func (s *Supervisor) processNotice(ctx context.Context, notice DeliveryNotice) error {
	stored, found, err := s.store.Get(ctx, s.scope, s.source, notice.DeduplicationKey)
	if errors.Is(err, ErrDeliveryExpired) {
		return nil
	}
	if err != nil || !found {
		return err
	}
	if stored.Validate() != nil {
		return ErrInvalidSupervisor
	}
	_, _, err = s.processor.Process(ctx, stored, s.options.Clock.Now().UTC())
	if errors.Is(err, ErrPreparedInputsExpired) {
		return nil
	}
	return err
}
func (s *Supervisor) retry(ctx context.Context, operation func(context.Context) error) error {
	for attempt := uint8(0); attempt < s.options.MaximumRetries; attempt++ {
		if ctx.Err() != nil {
			return nil
		}
		if err := operation(ctx); err == nil {
			return nil
		}
		if attempt+1 == s.options.MaximumRetries {
			break
		}
		delay := s.options.RetryDelay << attempt
		if delay > maximumSupervisorDelay {
			delay = maximumSupervisorDelay
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
	return ErrSupervisorUnavailable
}
func nilSupervisorClock(clock SupervisorClock) bool {
	if clock == nil {
		return true
	}
	value := reflect.ValueOf(clock)
	return value.Kind() == reflect.Ptr && value.IsNil()
}
func (s *Supervisor) String() string   { return "webhook supervisor" }
func (s *Supervisor) GoString() string { return "webhook.Supervisor{<redacted>}" }
func (s *Supervisor) Format(state fmt.State, verb rune) {
	formatted := "webhook supervisor"
	if verb == 'q' {
		formatted = fmt.Sprintf("%q", formatted)
	} else if verb == 'v' && state.Flag('#') {
		formatted = "webhook.Supervisor{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

var _ DeliveryNotifier = (*Supervisor)(nil)
