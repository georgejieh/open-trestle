package gateway

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestRouteFailureClassRoundTrips(t *testing.T) {
	values := []struct {
		value RouteFailureClass
		token string
	}{
		{RouteFailureTransport, "transport"},
		{RouteFailureRateLimited, "rate_limited"},
		{RouteFailureProviderServer, "provider_server"},
		{RouteFailureTimeout, "timeout"},
		{RouteFailureConnection, "connection"},
		{RouteFailureInvalidResponse, "invalid_response"},
		{RouteFailureAuthentication, "authentication"},
		{RouteFailureAuthorization, "authorization"},
		{RouteFailurePolicyDenied, "policy_denied"},
		{RouteFailureBudgetExhausted, "budget_exhausted"},
		{RouteFailureCancelled, "cancelled"},
	}
	for _, test := range values {
		parsed, err := ParseRouteFailureClass(test.token)
		if err != nil || parsed != test.value || parsed.String() != test.token || parsed.Validate() != nil {
			t.Fatalf("failure class %q = (%v, %v, %q)", test.token, parsed, err, parsed.String())
		}
	}
	for _, token := range []string{"", "unknown", " timeout", "TIMEOUT"} {
		if parsed, err := ParseRouteFailureClass(token); !errors.Is(err, ErrInvalidRouteFailureClass) || parsed != 0 {
			t.Fatalf("ParseRouteFailureClass(%q) = (%v, %v)", token, parsed, err)
		}
	}
}

func TestRouteReplaySafetyRoundTrips(t *testing.T) {
	values := []struct {
		value RouteReplaySafety
		token string
	}{
		{RouteReplayNoSideEffect, "no_side_effect"},
		{RouteReplayIdempotent, "idempotent"},
		{RouteReplayIdempotencyKey, "idempotency_key"},
		{RouteReplayNotDispatched, "not_dispatched"},
		{RouteReplayUnsafe, "unsafe"},
		{RouteReplayOutcomeUnknown, "outcome_unknown"},
	}
	for _, test := range values {
		parsed, err := ParseRouteReplaySafety(test.token)
		if err != nil || parsed != test.value || parsed.String() != test.token || parsed.Validate() != nil {
			t.Fatalf("replay safety %q = (%v, %v, %q)", test.token, parsed, err, parsed.String())
		}
	}
	if parsed, err := ParseRouteReplaySafety("unknown"); !errors.Is(err, ErrInvalidRouteReplaySafety) || parsed != 0 {
		t.Fatalf("ParseRouteReplaySafety() = (%v, %v)", parsed, err)
	}
}

func TestRouteRetryReasonRoundTrips(t *testing.T) {
	values := []struct {
		value RouteRetryReason
		token string
	}{
		{RouteRetryTransientFailure, "transient_failure"},
		{RouteRetryAttemptsExhausted, "attempts_exhausted"},
		{RouteRetryPermanentFailure, "permanent_failure"},
		{RouteRetryUnsafeReplay, "unsafe_replay"},
		{RouteRetryAfterTooLong, "retry_after_too_long"},
	}
	for _, test := range values {
		parsed, err := ParseRouteRetryReason(test.token)
		if err != nil || parsed != test.value || parsed.String() != test.token || parsed.Validate() != nil {
			t.Fatalf("retry reason %q = (%v, %v, %q)", test.token, parsed, err, parsed.String())
		}
	}
	if parsed, err := ParseRouteRetryReason(""); !errors.Is(err, ErrInvalidRouteRetryReason) || parsed != 0 {
		t.Fatalf("ParseRouteRetryReason() = (%v, %v)", parsed, err)
	}
}

func TestRouteRetryPolicyRoundTripsAndBindsIdentity(t *testing.T) {
	policy, err := NewRouteRetryPolicy(5, 100, 250, 1_000, 5_000)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Identity() == "" || policy.MaxAttempts() != 5 || policy.BaseDelayMilliseconds() != 100 || policy.MaxDelayMilliseconds() != 250 || policy.JitterBasisPoints() != 1_000 || policy.MaxRetryAfterMilliseconds() != 5_000 || policy.Validate() != nil {
		t.Fatal("retry policy did not round trip")
	}
	noRetry := NewNoRouteRetryPolicy()
	if noRetry.Identity() == "" || noRetry.MaxAttempts() != 1 || noRetry.BaseDelayMilliseconds() != 0 || noRetry.Validate() != nil || noRetry.Identity() == policy.Identity() {
		t.Fatal("no-retry policy is not canonical")
	}
	other, _ := NewRouteRetryPolicy(4, 100, 250, 1_000, 5_000)
	if other.Identity() == policy.Identity() {
		t.Fatal("attempt cap did not affect identity")
	}
	forged := policy
	forged.identity = strings.Repeat("0", 64)
	if forged.Validate() != ErrInvalidRouteRetryPolicyIdentity {
		t.Fatal("forged retry policy identity accepted")
	}
}

func TestNewRouteRetryPolicyRejectsInvalidBounds(t *testing.T) {
	for _, test := range []struct {
		name       string
		attempts   uint8
		base       uint32
		maximum    uint32
		jitter     uint16
		retryAfter uint32
		want       error
	}{
		{name: "attempts low", attempts: 1, base: 1, maximum: 1, retryAfter: 1, want: ErrInvalidRouteRetryAttempts},
		{name: "attempts high", attempts: 6, base: 1, maximum: 1, retryAfter: 1, want: ErrInvalidRouteRetryAttempts},
		{name: "base zero", attempts: 2, maximum: 1, retryAfter: 1, want: ErrInvalidRouteRetryDelay},
		{name: "base high", attempts: 2, base: maxRouteRetryDelayMilliseconds + 1, maximum: maxRouteRetryDelayMilliseconds + 1, retryAfter: maxRouteRetryDelayMilliseconds + 1, want: ErrInvalidRouteRetryDelay},
		{name: "maximum below base", attempts: 2, base: 2, maximum: 1, retryAfter: 2, want: ErrInvalidRouteRetryDelay},
		{name: "jitter", attempts: 2, base: 1, maximum: 1, jitter: maxRouteRetryJitterBasisPoints + 1, retryAfter: 1, want: ErrInvalidRouteRetryJitter},
		{name: "retry after below delay", attempts: 2, base: 1, maximum: 2, retryAfter: 1, want: ErrInvalidRouteRetryAfter},
		{name: "retry after high", attempts: 2, base: 1, maximum: 2, retryAfter: maxRouteRetryAfterMilliseconds + 1, want: ErrInvalidRouteRetryAfter},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewRouteRetryPolicy(test.attempts, test.base, test.maximum, test.jitter, test.retryAfter)
			if !errors.Is(err, test.want) || policy.Identity() != "" {
				t.Fatalf("NewRouteRetryPolicy() = (%#v, %v), want %v", policy, err, test.want)
			}
		})
	}
	if err := (RouteRetryPolicy{}).Validate(); !errors.Is(err, ErrInvalidRouteRetryAttempts) {
		t.Fatalf("zero policy Validate() = %v", err)
	}
}

func TestEvaluateRouteRetryAllowsOnlyTransientSafeFailures(t *testing.T) {
	policy, _ := NewRouteRetryPolicy(3, 100, 1_000, 0, 5_000)
	transient := []RouteFailureClass{RouteFailureTransport, RouteFailureRateLimited, RouteFailureProviderServer, RouteFailureTimeout, RouteFailureConnection}
	for _, failure := range transient {
		decision, err := evaluateRouteRetry(policy, failure, RouteReplayNoSideEffect, 1, 0)
		if err != nil || !decision.ShouldRetry() || decision.Reason() != RouteRetryTransientFailure || decision.MinimumDelayMilliseconds() != 100 || decision.MaximumDelayMilliseconds() != 100 || decision.Validate() != nil {
			t.Fatalf("transient %v = (%#v, %v)", failure, decision, err)
		}
	}
	permanent := []RouteFailureClass{RouteFailureInvalidResponse, RouteFailureAuthentication, RouteFailureAuthorization, RouteFailurePolicyDenied, RouteFailureBudgetExhausted, RouteFailureCancelled}
	for _, failure := range permanent {
		decision, err := evaluateRouteRetry(policy, failure, RouteReplayNoSideEffect, 1, 0)
		if err != nil || decision.ShouldRetry() || decision.Reason() != RouteRetryPermanentFailure || decision.MinimumDelayMilliseconds() != 0 || decision.MaximumDelayMilliseconds() != 0 {
			t.Fatalf("permanent %v = (%#v, %v)", failure, decision, err)
		}
	}
}

func TestEvaluateRouteRetryEnforcesReplaySafetyAndAttemptCap(t *testing.T) {
	policy, _ := NewRouteRetryPolicy(3, 100, 1_000, 0, 5_000)
	for _, safety := range []RouteReplaySafety{RouteReplayNoSideEffect, RouteReplayIdempotent, RouteReplayIdempotencyKey, RouteReplayNotDispatched} {
		decision, err := evaluateRouteRetry(policy, RouteFailureTimeout, safety, 1, 0)
		if err != nil || !decision.ShouldRetry() {
			t.Fatalf("safe replay %v = (%#v, %v)", safety, decision, err)
		}
	}
	for _, safety := range []RouteReplaySafety{RouteReplayUnsafe, RouteReplayOutcomeUnknown} {
		decision, err := evaluateRouteRetry(policy, RouteFailureTimeout, safety, 1, 0)
		if err != nil || decision.ShouldRetry() || decision.Reason() != RouteRetryUnsafeReplay {
			t.Fatalf("unsafe replay %v = (%#v, %v)", safety, decision, err)
		}
	}
	decision, err := evaluateRouteRetry(policy, RouteFailureTimeout, RouteReplayNoSideEffect, 3, 0)
	if err != nil || decision.ShouldRetry() || decision.Reason() != RouteRetryAttemptsExhausted {
		t.Fatalf("exhausted = (%#v, %v)", decision, err)
	}
	noRetry := NewNoRouteRetryPolicy()
	decision, err = evaluateRouteRetry(noRetry, RouteFailureTimeout, RouteReplayNoSideEffect, 1, 0)
	if err != nil || decision.ShouldRetry() || decision.Reason() != RouteRetryAttemptsExhausted {
		t.Fatalf("no retry = (%#v, %v)", decision, err)
	}
}

func TestEvaluateRouteRetryReturnsBoundedBackoffRanges(t *testing.T) {
	policy, _ := NewRouteRetryPolicy(5, 100, 250, 1_000, 5_000)
	for _, test := range []struct {
		attempts uint8
		minimum  uint32
		maximum  uint32
	}{
		{attempts: 1, minimum: 90, maximum: 110},
		{attempts: 2, minimum: 180, maximum: 220},
		{attempts: 3, minimum: 225, maximum: 250},
		{attempts: 4, minimum: 225, maximum: 250},
	} {
		decision, err := evaluateRouteRetry(policy, RouteFailureTimeout, RouteReplayNoSideEffect, test.attempts, 0)
		if err != nil || decision.MinimumDelayMilliseconds() != test.minimum || decision.MaximumDelayMilliseconds() != test.maximum {
			t.Fatalf("attempt %d = (%#v, %v)", test.attempts, decision, err)
		}
	}
}

func TestEvaluateRouteRetryHonorsBoundedRateLimitRetryAfter(t *testing.T) {
	policy, _ := NewRouteRetryPolicy(3, 100, 1_000, 1_000, 5_000)
	short, err := evaluateRouteRetry(policy, RouteFailureRateLimited, RouteReplayNoSideEffect, 1, 50)
	if err != nil || !short.ShouldRetry() || short.MinimumDelayMilliseconds() != 90 || short.MaximumDelayMilliseconds() != 110 {
		t.Fatalf("short Retry-After = (%#v, %v)", short, err)
	}
	decision, err := evaluateRouteRetry(policy, RouteFailureRateLimited, RouteReplayNoSideEffect, 1, 2_000)
	if err != nil || !decision.ShouldRetry() || decision.MinimumDelayMilliseconds() != 2_000 || decision.MaximumDelayMilliseconds() != 2_000 {
		t.Fatalf("bounded Retry-After = (%#v, %v)", decision, err)
	}
	decision, err = evaluateRouteRetry(policy, RouteFailureRateLimited, RouteReplayNoSideEffect, 1, 5_001)
	if err != nil || decision.ShouldRetry() || decision.Reason() != RouteRetryAfterTooLong {
		t.Fatalf("oversized Retry-After = (%#v, %v)", decision, err)
	}
}

func TestEvaluateRouteRetryRejectsInvalidInputs(t *testing.T) {
	policy, _ := NewRouteRetryPolicy(3, 100, 1_000, 0, 5_000)
	for _, test := range []struct {
		name       string
		policy     RouteRetryPolicy
		failure    RouteFailureClass
		safety     RouteReplaySafety
		attempts   uint8
		retryAfter uint32
		want       error
	}{
		{name: "policy", failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, attempts: 1, want: ErrInvalidRouteRetryAttempts},
		{name: "failure", policy: policy, safety: RouteReplayNoSideEffect, attempts: 1, want: ErrInvalidRouteFailureClass},
		{name: "safety", policy: policy, failure: RouteFailureTimeout, attempts: 1, want: ErrInvalidRouteReplaySafety},
		{name: "attempt zero", policy: policy, failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, want: ErrInvalidRouteRetryAttemptCount},
		{name: "attempt high", policy: policy, failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, attempts: 4, want: ErrInvalidRouteRetryAttemptCount},
		{name: "retry after misuse", policy: policy, failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, attempts: 1, retryAfter: 1, want: ErrInvalidRouteRetryAfter},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision, err := evaluateRouteRetry(test.policy, test.failure, test.safety, test.attempts, test.retryAfter)
			if !errors.Is(err, test.want) || decision != (RouteRetryDecision{}) {
				t.Fatalf("evaluateRouteRetry() = (%#v, %v), want %v", decision, err, test.want)
			}
		})
	}
}

func TestRouteRetryTypesHaveClosedSurfaceAndRedactedFormatting(t *testing.T) {
	policy, _ := NewRouteRetryPolicy(3, 100, 1_000, 0, 5_000)
	decision, _ := evaluateRouteRetry(policy, RouteFailureTimeout, RouteReplayNoSideEffect, 1, 0)
	if reflect.TypeOf(policy).NumField() != 6 || reflect.TypeOf(decision).NumField() != 4 {
		t.Fatal("retry type surface changed")
	}
	for _, value := range []any{policy, decision} {
		for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%d", "%x"} {
			formatted := fmt.Sprintf(format, value)
			if strings.Contains(formatted, policy.Identity()) {
				t.Fatalf("format %q exposed policy identity: %q", format, formatted)
			}
		}
	}
}
