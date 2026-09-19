package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	maxRouteRetryAttempts          uint8  = 5
	maxRouteRetryDelayMilliseconds uint32 = 300_000
	maxRouteRetryAfterMilliseconds uint32 = 900_000
	maxRouteRetryJitterBasisPoints uint16 = 5_000
	retryBasisPoints               uint64 = 10_000
)

var (
	// ErrInvalidRouteFailureClass identifies an unknown adapter-classified failure.
	ErrInvalidRouteFailureClass = errors.New("invalid route failure class")
	// ErrInvalidRouteReplaySafety identifies an unknown effect replay guarantee.
	ErrInvalidRouteReplaySafety = errors.New("invalid route replay safety")
	// ErrInvalidRouteRetryReason identifies an unknown retry decision reason.
	ErrInvalidRouteRetryReason = errors.New("invalid route retry reason")
	// ErrInvalidRouteRetryAttempts identifies an unsupported policy attempt cap.
	ErrInvalidRouteRetryAttempts = errors.New("invalid route retry attempts")
	// ErrInvalidRouteRetryDelay identifies malformed backoff bounds.
	ErrInvalidRouteRetryDelay = errors.New("invalid route retry delay")
	// ErrInvalidRouteRetryJitter identifies an unsupported jitter fraction.
	ErrInvalidRouteRetryJitter = errors.New("invalid route retry jitter")
	// ErrInvalidRouteRetryAfter identifies malformed Retry-After input or policy bounds.
	ErrInvalidRouteRetryAfter = errors.New("invalid route retry after")
	// ErrInvalidRouteRetryPolicyIdentity identifies a policy identity that does not match its fields.
	ErrInvalidRouteRetryPolicyIdentity = errors.New("invalid route retry policy identity")
	// ErrInvalidRouteRetryAttemptCount identifies a runtime attempt count outside its policy.
	ErrInvalidRouteRetryAttemptCount = errors.New("invalid route retry attempt count")
	// ErrInvalidRouteRetryDecision identifies inconsistent retry output fields.
	ErrInvalidRouteRetryDecision = errors.New("invalid route retry decision")
)

// RouteFailureClass is an adapter-provided semantic failure category.
type RouteFailureClass uint8

const (
	RouteFailureTransport RouteFailureClass = iota + 1
	RouteFailureRateLimited
	RouteFailureProviderServer
	RouteFailureTimeout
	RouteFailureConnection
	RouteFailureInvalidResponse
	RouteFailureAuthentication
	RouteFailureAuthorization
	RouteFailurePolicyDenied
	RouteFailureBudgetExhausted
	RouteFailureCancelled
)

// String returns the stable failure token or an empty string for unknown values.
func (c RouteFailureClass) String() string {
	switch c {
	case RouteFailureTransport:
		return "transport"
	case RouteFailureRateLimited:
		return "rate_limited"
	case RouteFailureProviderServer:
		return "provider_server"
	case RouteFailureTimeout:
		return "timeout"
	case RouteFailureConnection:
		return "connection"
	case RouteFailureInvalidResponse:
		return "invalid_response"
	case RouteFailureAuthentication:
		return "authentication"
	case RouteFailureAuthorization:
		return "authorization"
	case RouteFailurePolicyDenied:
		return "policy_denied"
	case RouteFailureBudgetExhausted:
		return "budget_exhausted"
	case RouteFailureCancelled:
		return "cancelled"
	default:
		return ""
	}
}

// ParseRouteFailureClass parses one exact stable failure token.
func ParseRouteFailureClass(value string) (RouteFailureClass, error) {
	for candidate := RouteFailureTransport; candidate <= RouteFailureCancelled; candidate++ {
		if candidate.String() == value {
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("parse route failure class: %w", ErrInvalidRouteFailureClass)
}

// Validate verifies that the failure class is recognized.
func (c RouteFailureClass) Validate() error {
	if c.String() == "" {
		return ErrInvalidRouteFailureClass
	}
	return nil
}

// RouteReplaySafety records the executor's proof about replaying one failed operation.
type RouteReplaySafety uint8

const (
	RouteReplayNoSideEffect RouteReplaySafety = iota + 1
	RouteReplayIdempotent
	RouteReplayIdempotencyKey
	RouteReplayNotDispatched
	RouteReplayUnsafe
	RouteReplayOutcomeUnknown
)

// String returns the stable replay-safety token or an empty string for unknown values.
func (s RouteReplaySafety) String() string {
	switch s {
	case RouteReplayNoSideEffect:
		return "no_side_effect"
	case RouteReplayIdempotent:
		return "idempotent"
	case RouteReplayIdempotencyKey:
		return "idempotency_key"
	case RouteReplayNotDispatched:
		return "not_dispatched"
	case RouteReplayUnsafe:
		return "unsafe"
	case RouteReplayOutcomeUnknown:
		return "outcome_unknown"
	default:
		return ""
	}
}

// ParseRouteReplaySafety parses one exact stable replay-safety token.
func ParseRouteReplaySafety(value string) (RouteReplaySafety, error) {
	for candidate := RouteReplayNoSideEffect; candidate <= RouteReplayOutcomeUnknown; candidate++ {
		if candidate.String() == value {
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("parse route replay safety: %w", ErrInvalidRouteReplaySafety)
}

// Validate verifies that the replay-safety class is recognized.
func (s RouteReplaySafety) Validate() error {
	if s.String() == "" {
		return ErrInvalidRouteReplaySafety
	}
	return nil
}

func (s RouteReplaySafety) permitsAutomaticRetry() bool {
	switch s {
	case RouteReplayNoSideEffect, RouteReplayIdempotent, RouteReplayIdempotencyKey, RouteReplayNotDispatched:
		return true
	default:
		return false
	}
}

// RouteRetryReason identifies the stable outcome of retry evaluation.
type RouteRetryReason uint8

const (
	RouteRetryTransientFailure RouteRetryReason = iota + 1
	RouteRetryAttemptsExhausted
	RouteRetryPermanentFailure
	RouteRetryUnsafeReplay
	RouteRetryAfterTooLong
)

// String returns the stable decision token or an empty string for unknown values.
func (r RouteRetryReason) String() string {
	switch r {
	case RouteRetryTransientFailure:
		return "transient_failure"
	case RouteRetryAttemptsExhausted:
		return "attempts_exhausted"
	case RouteRetryPermanentFailure:
		return "permanent_failure"
	case RouteRetryUnsafeReplay:
		return "unsafe_replay"
	case RouteRetryAfterTooLong:
		return "retry_after_too_long"
	default:
		return ""
	}
}

// ParseRouteRetryReason parses one exact stable decision token.
func ParseRouteRetryReason(value string) (RouteRetryReason, error) {
	for candidate := RouteRetryTransientFailure; candidate <= RouteRetryAfterTooLong; candidate++ {
		if candidate.String() == value {
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("parse route retry reason: %w", ErrInvalidRouteRetryReason)
}

// Validate verifies that the retry reason is recognized.
func (r RouteRetryReason) Validate() error {
	if r.String() == "" {
		return ErrInvalidRouteRetryReason
	}
	return nil
}

// RouteRetryPolicy binds bounded attempts, exponential delay, jitter, and Retry-After limits.
type RouteRetryPolicy struct {
	identity                  string
	maxAttempts               uint8
	baseDelayMilliseconds     uint32
	maxDelayMilliseconds      uint32
	jitterBasisPoints         uint16
	maxRetryAfterMilliseconds uint32
}

// NewRouteRetryPolicy creates a retry-enabled policy.
func NewRouteRetryPolicy(maxAttempts uint8, baseDelayMilliseconds, maxDelayMilliseconds uint32, jitterBasisPoints uint16, maxRetryAfterMilliseconds uint32) (RouteRetryPolicy, error) {
	if maxAttempts < 2 || maxAttempts > maxRouteRetryAttempts {
		return RouteRetryPolicy{}, ErrInvalidRouteRetryAttempts
	}
	policy := RouteRetryPolicy{
		maxAttempts:               maxAttempts,
		baseDelayMilliseconds:     baseDelayMilliseconds,
		maxDelayMilliseconds:      maxDelayMilliseconds,
		jitterBasisPoints:         jitterBasisPoints,
		maxRetryAfterMilliseconds: maxRetryAfterMilliseconds,
	}
	if err := validateRouteRetryPolicyFields(policy); err != nil {
		return RouteRetryPolicy{}, err
	}
	policy.identity = deriveRouteRetryPolicyIdentity(policy)
	return policy, nil
}

// NewNoRouteRetryPolicy creates the canonical single-attempt policy.
func NewNoRouteRetryPolicy() RouteRetryPolicy {
	policy := RouteRetryPolicy{maxAttempts: 1}
	policy.identity = deriveRouteRetryPolicyIdentity(policy)
	return policy
}

// Identity returns the canonical SHA-256 policy identity.
func (p RouteRetryPolicy) Identity() string { return p.identity }

// MaxAttempts returns the total attempt cap, including the initial attempt.
func (p RouteRetryPolicy) MaxAttempts() uint8 { return p.maxAttempts }

// BaseDelayMilliseconds returns the first retry's nominal delay.
func (p RouteRetryPolicy) BaseDelayMilliseconds() uint32 { return p.baseDelayMilliseconds }

// MaxDelayMilliseconds returns the inclusive backoff and jitter cap.
func (p RouteRetryPolicy) MaxDelayMilliseconds() uint32 { return p.maxDelayMilliseconds }

// JitterBasisPoints returns the symmetric jitter fraction.
func (p RouteRetryPolicy) JitterBasisPoints() uint16 { return p.jitterBasisPoints }

// MaxRetryAfterMilliseconds returns the largest accepted server-directed delay.
func (p RouteRetryPolicy) MaxRetryAfterMilliseconds() uint32 { return p.maxRetryAfterMilliseconds }

// String returns a redacted retry-policy description.
func (p RouteRetryPolicy) String() string { return "route retry policy" }

// GoString returns a redacted Go-syntax retry-policy description.
func (p RouteRetryPolicy) GoString() string { return "gateway.RouteRetryPolicy{<redacted>}" }

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (p RouteRetryPolicy) Format(state fmt.State, verb rune) {
	formatted := "route retry policy"
	if verb == 'q' {
		formatted = `"route retry policy"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteRetryPolicy{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies policy bounds and content-derived identity.
func (p RouteRetryPolicy) Validate() error {
	if err := validateRouteRetryPolicyFields(p); err != nil {
		return err
	}
	if p.identity != deriveRouteRetryPolicyIdentity(p) {
		return ErrInvalidRouteRetryPolicyIdentity
	}
	return nil
}

func validateRouteRetryPolicyFields(policy RouteRetryPolicy) error {
	if policy.maxAttempts == 1 {
		if policy.baseDelayMilliseconds != 0 || policy.maxDelayMilliseconds != 0 || policy.jitterBasisPoints != 0 || policy.maxRetryAfterMilliseconds != 0 {
			return ErrInvalidRouteRetryDelay
		}
		return nil
	}
	if policy.maxAttempts < 2 || policy.maxAttempts > maxRouteRetryAttempts {
		return ErrInvalidRouteRetryAttempts
	}
	if policy.baseDelayMilliseconds == 0 || policy.baseDelayMilliseconds > maxRouteRetryDelayMilliseconds || policy.maxDelayMilliseconds < policy.baseDelayMilliseconds || policy.maxDelayMilliseconds > maxRouteRetryDelayMilliseconds {
		return ErrInvalidRouteRetryDelay
	}
	if policy.jitterBasisPoints > maxRouteRetryJitterBasisPoints {
		return ErrInvalidRouteRetryJitter
	}
	if policy.maxRetryAfterMilliseconds < policy.maxDelayMilliseconds || policy.maxRetryAfterMilliseconds > maxRouteRetryAfterMilliseconds {
		return ErrInvalidRouteRetryAfter
	}
	return nil
}

func deriveRouteRetryPolicyIdentity(policy RouteRetryPolicy) string {
	preimage := struct {
		Contract                  string `json:"contract"`
		Version                   int    `json:"version"`
		MaxAttempts               uint8  `json:"max_attempts"`
		BaseDelayMilliseconds     uint32 `json:"base_delay_milliseconds"`
		MaxDelayMilliseconds      uint32 `json:"max_delay_milliseconds"`
		JitterBasisPoints         uint16 `json:"jitter_basis_points"`
		MaxRetryAfterMilliseconds uint32 `json:"max_retry_after_milliseconds"`
	}{
		Contract:                  "open-trestle/route-retry-policy",
		Version:                   1,
		MaxAttempts:               policy.maxAttempts,
		BaseDelayMilliseconds:     policy.baseDelayMilliseconds,
		MaxDelayMilliseconds:      policy.maxDelayMilliseconds,
		JitterBasisPoints:         policy.jitterBasisPoints,
		MaxRetryAfterMilliseconds: policy.maxRetryAfterMilliseconds,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// RouteRetryDecision records whether and when one failed operation may retry.
type RouteRetryDecision struct {
	shouldRetry              bool
	reason                   RouteRetryReason
	minimumDelayMilliseconds uint32
	maximumDelayMilliseconds uint32
}

// ShouldRetry reports whether another attempt is allowed.
func (d RouteRetryDecision) ShouldRetry() bool { return d.shouldRetry }

// Reason returns the stable decision reason.
func (d RouteRetryDecision) Reason() RouteRetryReason { return d.reason }

// MinimumDelayMilliseconds returns the inclusive scheduler delay floor.
func (d RouteRetryDecision) MinimumDelayMilliseconds() uint32 { return d.minimumDelayMilliseconds }

// MaximumDelayMilliseconds returns the inclusive scheduler delay ceiling.
func (d RouteRetryDecision) MaximumDelayMilliseconds() uint32 { return d.maximumDelayMilliseconds }

// String returns a redacted retry-decision description.
func (d RouteRetryDecision) String() string { return "route retry decision" }

// GoString returns a redacted Go-syntax retry-decision description.
func (d RouteRetryDecision) GoString() string { return "gateway.RouteRetryDecision{<redacted>}" }

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (d RouteRetryDecision) Format(state fmt.State, verb rune) {
	formatted := "route retry decision"
	if verb == 'q' {
		formatted = `"route retry decision"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteRetryDecision{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies that retry permission, reason, and delay bounds agree.
func (d RouteRetryDecision) Validate() error {
	if err := d.reason.Validate(); err != nil {
		return err
	}
	if d.shouldRetry {
		if d.reason != RouteRetryTransientFailure || d.minimumDelayMilliseconds == 0 || d.maximumDelayMilliseconds < d.minimumDelayMilliseconds {
			return ErrInvalidRouteRetryDecision
		}
		return nil
	}
	if d.reason == RouteRetryTransientFailure || d.minimumDelayMilliseconds != 0 || d.maximumDelayMilliseconds != 0 {
		return ErrInvalidRouteRetryDecision
	}
	return nil
}

// EvaluateRouteRetry classifies one failed attempt without parsing vendor error text.
func evaluateRouteRetry(policy RouteRetryPolicy, failure RouteFailureClass, safety RouteReplaySafety, attemptsStarted uint8, retryAfterMilliseconds uint32) (RouteRetryDecision, error) {
	if err := policy.Validate(); err != nil {
		return RouteRetryDecision{}, err
	}
	if err := failure.Validate(); err != nil {
		return RouteRetryDecision{}, err
	}
	if err := safety.Validate(); err != nil {
		return RouteRetryDecision{}, err
	}
	if attemptsStarted == 0 || attemptsStarted > policy.maxAttempts {
		return RouteRetryDecision{}, ErrInvalidRouteRetryAttemptCount
	}
	if retryAfterMilliseconds != 0 && failure != RouteFailureRateLimited {
		return RouteRetryDecision{}, ErrInvalidRouteRetryAfter
	}
	if attemptsStarted == policy.maxAttempts {
		return newRouteNoRetryDecision(RouteRetryAttemptsExhausted), nil
	}
	if !routeFailureIsTransient(failure) {
		return newRouteNoRetryDecision(RouteRetryPermanentFailure), nil
	}
	if !safety.permitsAutomaticRetry() {
		return newRouteNoRetryDecision(RouteRetryUnsafeReplay), nil
	}
	minimum, maximum := routeRetryDelayRange(policy, attemptsStarted)
	if retryAfterMilliseconds != 0 {
		if retryAfterMilliseconds > policy.maxRetryAfterMilliseconds {
			return newRouteNoRetryDecision(RouteRetryAfterTooLong), nil
		}
		if retryAfterMilliseconds > minimum {
			minimum = retryAfterMilliseconds
		}
		if retryAfterMilliseconds > maximum {
			maximum = retryAfterMilliseconds
		}
	}
	return newRouteRetryDecision(minimum, maximum), nil
}

func routeFailureIsTransient(failure RouteFailureClass) bool {
	switch failure {
	case RouteFailureTransport, RouteFailureRateLimited, RouteFailureProviderServer, RouteFailureTimeout, RouteFailureConnection:
		return true
	default:
		return false
	}
}

func routeRetryDelayRange(policy RouteRetryPolicy, attemptsStarted uint8) (uint32, uint32) {
	nominal := uint64(policy.baseDelayMilliseconds)
	for attempt := uint8(1); attempt < attemptsStarted; attempt++ {
		nominal *= 2
		if nominal >= uint64(policy.maxDelayMilliseconds) {
			nominal = uint64(policy.maxDelayMilliseconds)
			break
		}
	}
	jitter := uint64(policy.jitterBasisPoints)
	minimum := nominal * (retryBasisPoints - jitter) / retryBasisPoints
	maximum := (nominal*(retryBasisPoints+jitter) + retryBasisPoints - 1) / retryBasisPoints
	if minimum == 0 {
		minimum = 1
	}
	if maximum > uint64(policy.maxDelayMilliseconds) {
		maximum = uint64(policy.maxDelayMilliseconds)
	}
	return uint32(minimum), uint32(maximum)
}

func newRouteRetryDecision(minimum, maximum uint32) RouteRetryDecision {
	return RouteRetryDecision{shouldRetry: true, reason: RouteRetryTransientFailure, minimumDelayMilliseconds: minimum, maximumDelayMilliseconds: maximum}
}

func newRouteNoRetryDecision(reason RouteRetryReason) RouteRetryDecision {
	return RouteRetryDecision{reason: reason}
}
