package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrInvalidRouteDispatchContext identifies a nil dispatch context.
	ErrInvalidRouteDispatchContext = errors.New("invalid route dispatch context")
	// ErrRouteDispatchContextDone identifies authorization that was not dispatched because its context was done.
	ErrRouteDispatchContextDone = errors.New("route dispatch context done")
	// ErrInvalidRouteDispatcher identifies a missing adapter implementation.
	ErrInvalidRouteDispatcher = errors.New("invalid route dispatcher")
	// ErrRouteDispatchAdapterMismatch identifies an adapter implementation other than the authorized adapter.
	ErrRouteDispatchAdapterMismatch = errors.New("route dispatch adapter mismatch")
	// ErrRouteDispatchRequestMismatch identifies request content other than the authorized request.
	ErrRouteDispatchRequestMismatch = errors.New("route dispatch request mismatch")
	// ErrInvalidRouteDispatchStatus identifies an unknown dispatch result state.
	ErrInvalidRouteDispatchStatus = errors.New("invalid route dispatch status")
	// ErrInvalidRouteDispatchResult identifies inconsistent or malformed adapter output.
	ErrInvalidRouteDispatchResult = errors.New("invalid route dispatch result")
	// ErrInvalidRouteDispatchResultIdentity identifies an adapter result identity inconsistent with its fields.
	ErrInvalidRouteDispatchResultIdentity = errors.New("invalid route dispatch result identity")
	// ErrRouteDispatchAuthorizationMismatch identifies a result attached to another or no authorization.
	ErrRouteDispatchAuthorizationMismatch = errors.New("route dispatch authorization mismatch")
)

// RouteDispatchRequest is an exact authorized provider request. Its valid values can
// only be created by DispatchAuthorizedRoute.
type RouteDispatchRequest struct {
	authorization RouteAttemptAuthorization
	request       provider.Request
}

// Authorization returns the exact route attempt authorization.
func (r RouteDispatchRequest) Authorization() RouteAttemptAuthorization { return r.authorization }

// Request returns the immutable provider request.
func (r RouteDispatchRequest) Request() provider.Request { return r.request }

func (r RouteDispatchRequest) String() string   { return "route dispatch request" }
func (r RouteDispatchRequest) GoString() string { return "gateway.RouteDispatchRequest{<redacted>}" }
func (r RouteDispatchRequest) Format(state fmt.State, verb rune) {
	formatted := "route dispatch request"
	if verb == 'q' {
		formatted = `"route dispatch request"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteDispatchRequest{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies the authorization and exact request identity.
func (r RouteDispatchRequest) Validate() error {
	if err := r.authorization.Validate(); err != nil {
		return err
	}
	if err := r.request.Validate(); err != nil {
		return err
	}
	if r.request.Identity() != r.authorization.RequestIdentity() {
		return ErrRouteDispatchRequestMismatch
	}
	return nil
}

// RouteDispatcher is the narrow provider adapter execution boundary. Implementations
// must translate all provider behavior into a closed RouteDispatchResult.
type RouteDispatcher interface {
	AdapterID() string
	ConfigurationIdentity() string
	DispatchRoute(context.Context, RouteDispatchRequest) RouteDispatchResult
}

// DispatchAuthorizedRoute releases request content only to the exact authorized adapter.
func DispatchAuthorizedRoute(ctx context.Context, dispatcher RouteDispatcher, authorization RouteAttemptAuthorization, request provider.Request) (RouteDispatchResult, error) {
	if isNilInterfaceValue(ctx) {
		return RouteDispatchResult{}, ErrInvalidRouteDispatchContext
	}
	if err := ctx.Err(); err != nil {
		return RouteDispatchResult{}, fmt.Errorf("%w: %v", ErrRouteDispatchContextDone, err)
	}
	if isNilRouteDispatcher(dispatcher) {
		return RouteDispatchResult{}, ErrInvalidRouteDispatcher
	}
	dispatchRequest := RouteDispatchRequest{authorization: authorization, request: request}
	if err := dispatchRequest.Validate(); err != nil {
		return RouteDispatchResult{}, err
	}
	if dispatcher.AdapterID() != authorization.RouteReference().AdapterID() {
		return RouteDispatchResult{}, ErrRouteDispatchAdapterMismatch
	}
	result := dispatcher.DispatchRoute(ctx, dispatchRequest)
	if err := result.Validate(); err != nil {
		return RouteDispatchResult{}, fmt.Errorf("%w: %v", ErrInvalidRouteDispatchResult, err)
	}
	if result.AuthorizationIdentity() != "" {
		return RouteDispatchResult{}, ErrInvalidRouteDispatchResult
	}
	if result.Status() == RouteDispatchSucceeded && result.Response().Capability() != request.Capability() {
		return RouteDispatchResult{}, ErrInvalidRouteDispatchResult
	}
	result.authorizationIdentity = authorization.Identity()
	result.identity = deriveRouteDispatchResultIdentity(result)
	if err := result.Validate(); err != nil {
		return RouteDispatchResult{}, fmt.Errorf("%w: %v", ErrInvalidRouteDispatchResult, err)
	}
	return result, nil
}

func isNilRouteDispatcher(dispatcher RouteDispatcher) bool {
	return isNilInterfaceValue(dispatcher)
}

func isNilInterfaceValue(candidate any) bool {
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

// RouteDispatchStatus identifies the closed result of one adapter call.
type RouteDispatchStatus uint8

const (
	RouteDispatchSucceeded RouteDispatchStatus = iota + 1
	RouteDispatchFailed
)

func (s RouteDispatchStatus) String() string {
	switch s {
	case RouteDispatchSucceeded:
		return "succeeded"
	case RouteDispatchFailed:
		return "failed"
	default:
		return ""
	}
}

// ParseRouteDispatchStatus parses one exact stable dispatch status token.
func ParseRouteDispatchStatus(value string) (RouteDispatchStatus, error) {
	for status := RouteDispatchSucceeded; status <= RouteDispatchFailed; status++ {
		if status.String() == value {
			return status, nil
		}
	}
	return 0, fmt.Errorf("parse route dispatch status: %w", ErrInvalidRouteDispatchStatus)
}

func (s RouteDispatchStatus) Validate() error {
	if s.String() == "" {
		return ErrInvalidRouteDispatchStatus
	}
	return nil
}

// RouteDispatchResult is content-addressed normalized adapter output.
type RouteDispatchResult struct {
	identity               string
	authorizationIdentity  string
	status                 RouteDispatchStatus
	response               provider.Response
	failure                RouteFailureClass
	replaySafety           RouteReplaySafety
	usage                  provider.RouteTokenUsage
	retryAfterMilliseconds uint32
}

// NewSuccessfulRouteDispatchResult records one validated provider response.
func NewSuccessfulRouteDispatchResult(response provider.Response) (RouteDispatchResult, error) {
	result := RouteDispatchResult{status: RouteDispatchSucceeded, response: response, usage: response.Usage()}
	if err := result.validateFields(); err != nil {
		return RouteDispatchResult{}, err
	}
	result.identity = deriveRouteDispatchResultIdentity(result)
	return result, nil
}

// NewFailedRouteDispatchResult records one closed provider failure classification.
func NewFailedRouteDispatchResult(failure RouteFailureClass, safety RouteReplaySafety, usage provider.RouteTokenUsage, retryAfterMilliseconds uint32) (RouteDispatchResult, error) {
	result := RouteDispatchResult{
		status: RouteDispatchFailed, failure: failure, replaySafety: safety,
		usage: usage, retryAfterMilliseconds: retryAfterMilliseconds,
	}
	if err := result.validateFields(); err != nil {
		return RouteDispatchResult{}, err
	}
	result.identity = deriveRouteDispatchResultIdentity(result)
	return result, nil
}

func (r RouteDispatchResult) Identity() string                { return r.identity }
func (r RouteDispatchResult) AuthorizationIdentity() string   { return r.authorizationIdentity }
func (r RouteDispatchResult) Status() RouteDispatchStatus     { return r.status }
func (r RouteDispatchResult) Response() provider.Response     { return r.response }
func (r RouteDispatchResult) Failure() RouteFailureClass      { return r.failure }
func (r RouteDispatchResult) ReplaySafety() RouteReplaySafety { return r.replaySafety }
func (r RouteDispatchResult) Usage() provider.RouteTokenUsage { return r.usage }
func (r RouteDispatchResult) RetryAfterMilliseconds() uint32  { return r.retryAfterMilliseconds }
func (r RouteDispatchResult) String() string                  { return "route dispatch result" }
func (r RouteDispatchResult) GoString() string                { return "gateway.RouteDispatchResult{<redacted>}" }
func (r RouteDispatchResult) Format(state fmt.State, verb rune) {
	formatted := "route dispatch result"
	if verb == 'q' {
		formatted = `"route dispatch result"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteDispatchResult{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies the closed status fields and content-derived identity.
func (r RouteDispatchResult) Validate() error {
	if err := r.validateFields(); err != nil {
		return err
	}
	if r.identity != deriveRouteDispatchResultIdentity(r) {
		return ErrInvalidRouteDispatchResultIdentity
	}
	return nil
}

func (r RouteDispatchResult) validateFields() error {
	if r.authorizationIdentity != "" && !validRequestIdentity(r.authorizationIdentity) {
		return ErrRouteDispatchAuthorizationMismatch
	}
	if err := r.status.Validate(); err != nil {
		return err
	}
	if err := r.usage.Validate(); err != nil {
		return err
	}
	if r.status == RouteDispatchSucceeded {
		if err := r.response.Validate(); err != nil {
			return err
		}
		if r.usage != r.response.Usage() || r.failure != 0 || r.replaySafety != 0 || r.retryAfterMilliseconds != 0 {
			return ErrInvalidRouteDispatchResult
		}
		return nil
	}
	if r.response.Identity() != "" {
		return ErrInvalidRouteDispatchResult
	}
	if err := r.failure.Validate(); err != nil {
		return err
	}
	if err := r.replaySafety.Validate(); err != nil {
		return err
	}
	if r.retryAfterMilliseconds != 0 && r.failure != RouteFailureRateLimited {
		return ErrInvalidRouteRetryAfter
	}
	return nil
}

func deriveRouteDispatchResultIdentity(result RouteDispatchResult) string {
	preimage := struct {
		Contract      string `json:"contract"`
		Version       int    `json:"version"`
		Authorization string `json:"authorization"`
		Status        string `json:"status"`
		Response      string `json:"response"`
		Failure       string `json:"failure"`
		ReplaySafety  string `json:"replay_safety"`
		UsageKnown    bool   `json:"usage_known"`
		InputTokens   uint32 `json:"input_tokens"`
		OutputTokens  uint32 `json:"output_tokens"`
		CachedTokens  uint32 `json:"cached_tokens"`
		RetryAfter    uint32 `json:"retry_after_milliseconds"`
	}{
		Contract: "open-trestle/route-dispatch-result", Version: 1,
		Authorization: result.authorizationIdentity, Status: result.status.String(), Response: result.response.Identity(),
		Failure: result.failure.String(), ReplaySafety: result.replaySafety.String(),
		UsageKnown: result.usage.IsKnown(), InputTokens: result.usage.InputTokens(),
		OutputTokens: result.usage.OutputTokens(), CachedTokens: result.usage.CachedInputTokens(),
		RetryAfter: result.retryAfterMilliseconds,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// NewRouteAttemptOutcomeFromDispatch converts one closed adapter result into a terminal attempt record.
func NewRouteAttemptOutcomeFromDispatch(authorization RouteAttemptAuthorization, result RouteDispatchResult, durationMilliseconds uint64) (RouteAttemptOutcome, error) {
	if err := authorization.Validate(); err != nil {
		return RouteAttemptOutcome{}, err
	}
	if err := result.Validate(); err != nil {
		return RouteAttemptOutcome{}, err
	}
	if result.AuthorizationIdentity() != authorization.Identity() {
		return RouteAttemptOutcome{}, ErrRouteDispatchAuthorizationMismatch
	}
	if result.Status() == RouteDispatchSucceeded {
		return NewSuccessfulRouteAttemptOutcome(authorization, result.Response().Identity(), result.Usage(), durationMilliseconds)
	}
	return NewFailedRouteAttemptOutcome(authorization, result.Failure(), result.ReplaySafety(), result.Usage(), result.RetryAfterMilliseconds(), durationMilliseconds)
}
