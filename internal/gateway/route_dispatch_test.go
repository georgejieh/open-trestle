package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

type recordingRouteDispatcher struct {
	adapterID             string
	configurationIdentity string
	result                RouteDispatchResult
	calls                 int
	request               RouteDispatchRequest
}

func (d *recordingRouteDispatcher) AdapterID() string { return d.adapterID }
func (d *recordingRouteDispatcher) ConfigurationIdentity() string {
	if d.configurationIdentity != "" {
		return d.configurationIdentity
	}
	return strings.Repeat("a", 64)
}
func (d *recordingRouteDispatcher) DispatchRoute(_ context.Context, request RouteDispatchRequest) RouteDispatchResult {
	d.calls++
	d.request = request
	return d.result
}

func successfulDispatchResult(t *testing.T) RouteDispatchResult {
	t.Helper()
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(`{"summary":"ok","findings":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	usage, _ := provider.NewRouteTokenUsage(100, 20, 0)
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewSuccessfulRouteDispatchResult(response)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDispatchAuthorizedRouteUsesExactAdapterAndRequest(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	dispatcher := &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID(), result: successfulDispatchResult(t)}
	result, err := DispatchAuthorizedRoute(context.Background(), dispatcher, authorization, request)
	if err != nil {
		t.Fatal(err)
	}
	if dispatcher.calls != 1 || dispatcher.request.Authorization().Identity() != authorization.Identity() || dispatcher.request.Request().Identity() != request.Identity() || dispatcher.request.Validate() != nil || result.Identity() == "" || result.AuthorizationIdentity() != authorization.Identity() || result.Status() != RouteDispatchSucceeded || result.Validate() != nil {
		t.Fatalf("dispatch did not preserve authority: calls=%d request=%#v result=%#v", dispatcher.calls, dispatcher.request, result)
	}
	if fmt.Sprint(dispatcher.request) != "route dispatch request" || fmt.Sprintf("%#v", dispatcher.request) != "gateway.RouteDispatchRequest{<redacted>}" {
		t.Fatalf("dispatch request formatting leaked: %v / %#v", dispatcher.request, dispatcher.request)
	}
}

func TestDispatchAuthorizedRouteRejectsBeforeAdapterCall(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	otherRequest, _ := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte("other"))
	tests := []struct {
		name          string
		ctx           context.Context
		dispatcher    RouteDispatcher
		authorization RouteAttemptAuthorization
		request       provider.Request
		want          error
	}{
		{"nil context", nil, &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID()}, authorization, request, ErrInvalidRouteDispatchContext},
		{"done context", canceledContext(), &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID()}, authorization, request, ErrRouteDispatchContextDone},
		{"invalid authorization", context.Background(), &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID()}, RouteAttemptAuthorization{}, request, ErrInvalidRouteAttemptKind},
		{"request mismatch", context.Background(), &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID()}, authorization, otherRequest, ErrRouteDispatchRequestMismatch},
		{"adapter mismatch", context.Background(), &recordingRouteDispatcher{adapterID: "wrong-adapter"}, authorization, request, ErrRouteDispatchAdapterMismatch},
		{"nil dispatcher", context.Background(), nil, authorization, request, ErrInvalidRouteDispatcher},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := DispatchAuthorizedRoute(test.ctx, test.dispatcher, test.authorization, test.request)
			if !errors.Is(err, test.want) || result.Identity() != "" {
				t.Fatalf("DispatchAuthorizedRoute() = (%#v, %v), want %v", result, err, test.want)
			}
			if dispatcher, ok := test.dispatcher.(*recordingRouteDispatcher); ok && dispatcher.calls != 0 {
				t.Fatalf("adapter called %d times", dispatcher.calls)
			}
		})
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestDispatchAuthorizedRouteRejectsMalformedAdapterResult(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	dispatcher := &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID()}
	result, err := DispatchAuthorizedRoute(context.Background(), dispatcher, authorization, request)
	if !errors.Is(err, ErrInvalidRouteDispatchResult) || result.Identity() != "" || dispatcher.calls != 1 {
		t.Fatalf("malformed result = (%#v, %v), calls=%d", result, err, dispatcher.calls)
	}
}

func TestRouteDispatchFailureIsClosedAndConvertsToOutcome(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	usage := provider.NewUnknownRouteTokenUsage()
	rawFailure, err := NewFailedRouteDispatchResult(RouteFailureRateLimited, RouteReplayNoSideEffect, usage, 900)
	if err != nil || rawFailure.Identity() == "" || rawFailure.AuthorizationIdentity() != "" || rawFailure.Status() != RouteDispatchFailed || rawFailure.Failure() != RouteFailureRateLimited || rawFailure.ReplaySafety() != RouteReplayNoSideEffect || rawFailure.RetryAfterMilliseconds() != 900 || rawFailure.Usage() != usage || rawFailure.Validate() != nil {
		t.Fatalf("raw failure result = (%#v, %v)", rawFailure, err)
	}
	dispatcher := &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID(), result: rawFailure}
	failure, err := DispatchAuthorizedRoute(context.Background(), dispatcher, authorization, request)
	if err != nil || failure.AuthorizationIdentity() != authorization.Identity() {
		t.Fatalf("bound failure result = (%#v, %v)", failure, err)
	}
	outcome, err := NewRouteAttemptOutcomeFromDispatch(authorization, failure, 75)
	if err != nil || outcome.Status() != RouteAttemptFailed || outcome.AuthorizationIdentity() != authorization.Identity() || outcome.ResponseIdentity() != "" || outcome.Failure() != RouteFailureRateLimited || outcome.RetryAfterMilliseconds() != 900 || outcome.Validate() != nil {
		t.Fatalf("failure outcome = (%#v, %v)", outcome, err)
	}
	if result, err := NewFailedRouteDispatchResult(RouteFailureTimeout, RouteReplayNoSideEffect, usage, 1); !errors.Is(err, ErrInvalidRouteRetryAfter) || result.Identity() != "" {
		t.Fatalf("invalid retry-after result = (%#v, %v)", result, err)
	}
}

func TestSuccessfulDispatchOutcomeBindsResponseIdentity(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	rawResult := successfulDispatchResult(t)
	dispatcher := &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID(), result: rawResult}
	result, err := DispatchAuthorizedRoute(context.Background(), dispatcher, authorization, request)
	if err != nil {
		t.Fatal(err)
	}
	if unbound, err := NewRouteAttemptOutcomeFromDispatch(authorization, rawResult, 25); !errors.Is(err, ErrRouteDispatchAuthorizationMismatch) || unbound.Identity() != "" {
		t.Fatalf("unbound outcome = (%#v, %v)", unbound, err)
	}
	outcome, err := NewRouteAttemptOutcomeFromDispatch(authorization, result, 25)
	if err != nil || outcome.ResponseIdentity() != result.Response().Identity() || outcome.Usage() != result.Response().Usage() || outcome.Status() != RouteAttemptSucceeded || outcome.Validate() != nil {
		t.Fatalf("success outcome = (%#v, %v)", outcome, err)
	}
	otherAuthorization := authorization
	otherAuthorization.requestIdentity = strings.Repeat("d", 64)
	otherAuthorization.identity = deriveRouteAttemptAuthorizationIdentity(otherAuthorization)
	if otherAuthorization.Validate() != nil {
		t.Fatal("test authorization is invalid")
	}
	if crossWired, err := NewRouteAttemptOutcomeFromDispatch(otherAuthorization, result, 25); !errors.Is(err, ErrRouteDispatchAuthorizationMismatch) || crossWired.Identity() != "" {
		t.Fatalf("cross-wired outcome = (%#v, %v)", crossWired, err)
	}
	forged := result
	forged.identity = strings.Repeat("f", 64)
	if forged.Validate() != ErrInvalidRouteDispatchResultIdentity {
		t.Fatal("forged result identity accepted")
	}
	if fmt.Sprint(result) != "route dispatch result" || fmt.Sprintf("%#v", result) != "gateway.RouteDispatchResult{<redacted>}" {
		t.Fatalf("result formatting leaked: %v / %#v", result, result)
	}
}
