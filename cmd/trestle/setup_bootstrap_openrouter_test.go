package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// All OpenRouter values are synthetic fixtures from fakeOpenRouter.

func TestSetupBootstrapOpenRouterRecordsWhatTheAPIReported(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	for _, test := range []struct {
		provider, retention, limitation string
		version                         float64
	}{
		{"openrouter-zdr", "required_per_request", "openrouter_api_reported_model_facts_not_verified", 8},
		{"openrouter", "not_required_by_open_trestle", "zero_data_retention_not_required_by_open_trestle", 2},
	} {
		t.Run(test.provider, func(t *testing.T) {
			args, dir := remoteBootstrapArgs(t, test.provider)
			result, _ := remoteBootstrapInvoke(t, args, 0)
			if result.DataRetention != test.retention || !slices.Contains(result.Limitations, test.limitation) || slices.Contains(result.Limitations, "no_network_or_model_call_during_setup") || !slices.Contains(result.Limitations, "openrouter_public_api_read_no_model_call_during_setup") {
				t.Fatalf("result does not label the route: %+v", result)
			}
			saved := initReadOpenRouterSetup(t, dir)
			if saved.policy["schema_version"] != test.version || !strings.Contains(saved.raw, `"max_context_tokens":128000`) || !strings.Contains(saved.raw, `"max_output_tokens":16000`) {
				t.Fatalf("detected facts not recorded: %s", saved.raw)
			}
			if test.provider == "openrouter" {
				initAssertNotLabelledZDR(t, saved, "")
				member := saved.manifests[0]["openrouter_route"].(map[string]any)
				if member["observation"].(map[string]any)["authority_label"] == "" || member["zdr_endpoints_listed"] == nil {
					t.Fatalf("route observation lost: %v", member)
				}
				return
			}
			connections := saved.policy["connections"].([]any)
			for _, raw := range connections {
				connection := raw.(map[string]any)
				authority := connection["brokered_route_authority"].(map[string]any)
				if connection["request_profile"] != "openrouter_zdr_chat_v2" || len(authority) != 5 || authority["provider_slugs"] == nil {
					t.Fatalf("connection lost the observed authority: %v", connection)
				}
			}
		})
	}
}

// A repeated init with the same observation writes the same bytes; a later
// observation is a different declaration and needs a new directory.
func TestSetupBootstrapOpenRouterRepeatIsIdempotentPerObservation(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	args, _ := remoteBootstrapArgs(t, "openrouter-zdr")
	invoke := func(clock setupClock) (int, string) {
		var stdout, stderr bytes.Buffer
		code := runSetupBootstrapWithContext(context.Background(), args, &stdout, &stderr, clock)
		return code, stdout.String() + stderr.String()
	}
	clock := fixedSetupClock{at: time.Date(2026, 11, 10, 21, 0, 0, 0, time.UTC)}
	if first, out := invoke(clock); first != 0 {
		t.Fatalf("first init exit=%d %s", first, out)
	}
	if again, out := invoke(clock); again != 0 {
		t.Fatalf("repeat with the same observation exit=%d %s", again, out)
	}
	if later, out := invoke(fixedSetupClock{at: clock.at.Add(time.Minute)}); later != 4 || !strings.Contains(out, "already exists with different content") {
		t.Fatalf("a later observation overwrote or was not refused clearly: exit=%d %s", later, out)
	}
}

// openRouterRefusingTransport answers every model request with HTTP 404, as
// OpenRouter does when no endpoint may take the request.
type openRouterRefusingTransport struct{ requests int }

func (r *openRouterRefusingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	r.requests++
	return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"error":{"message":"synthetic provider text that must never be shown"}}`)), Request: request}, nil
}

func TestOpenRouterNotFoundNamesTheZDRSetting(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	args, _ := remoteBootstrapArgs(t, "openrouter-zdr")
	ready, _ := remoteBootstrapInvoke(t, args, 0)
	transport := &openRouterRefusingTransport{}
	localReviewModelHTTPClient = &http.Client{Transport: transport, Timeout: time.Minute}
	localReviewModelHTTPClientIdentity = localModelDigest([]byte("offline refusing OpenRouter fixture"))
	t.Cleanup(func() { localReviewModelHTTPClient, localReviewModelHTTPClientIdentity = nil, "" })
	var stdout, stderr bytes.Buffer
	code := run(ready.ReviewCommand[1:], &stdout, &stderr)
	text := stdout.String() + stderr.String()
	if code != 4 || transport.requests != 1 || !strings.Contains(text, "failure: policy (task candidates): provider_no_allowed_endpoint") || !strings.Contains(text, "OpenRouter account or key settings") || strings.Contains(text, "synthetic provider text") {
		t.Fatalf("OpenRouter 404 exit=%d requests=%d:\n%s", code, transport.requests, text)
	}
}

func TestSetupBootstrapOpenRouterUnreachableAPINeedsTypedFacts(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	args, dir := remoteBootstrapArgs(t, "openrouter-zdr")
	api := initEvidenceTransport.(*fakeOpenRouterAPI)
	api.models = ""
	refused, stderr := remoteBootstrapInvoke(t, args, 4)
	if !strings.Contains(stderr, "OpenRouter's API could not be read") || !strings.Contains(strings.Join(refused.Messages, " "), "--context-tokens, --output-tokens") {
		t.Fatalf("unreachable API without facts: %+v %s", refused, stderr)
	}
	typed := append(args, "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "3000000", "--output-micro-usd-per-million-tokens", "15000000")
	ready, _ := remoteBootstrapInvoke(t, typed, 0)
	if ready.DataRetention != "required_per_request" {
		t.Fatalf("typed fallback lost the ZDR requirement: %+v", ready)
	}
	for _, manifest := range initReadOpenRouterSetup(t, filepath.Clean(dir)).manifests {
		witness := manifest["openrouter_privacy"].(map[string]any)
		if witness["observation"] != nil || witness["provider_slug_source"] != "none" {
			t.Fatalf("an unobserved witness claimed an observation: %v", witness)
		}
	}
	encoded, _ := json.Marshal(ready)
	if strings.Contains(string(encoded), "as reported by OpenRouter") {
		t.Fatal("the result claimed an API report it did not have")
	}
}
