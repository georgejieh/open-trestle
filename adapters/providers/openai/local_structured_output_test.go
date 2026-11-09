package openai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

func localStructuredConfig(t *testing.T) Config {
	t.Helper()
	return Config{Protocol: ProtocolChatCompletions, LocalStructuredOutput: true, AdapterID: "openai-responses", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZoneLocal, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "http://127.0.0.1:1/v1", Credentials: &credentialProvider{key: testKey(t)}, CredentialIdentity: strings.Repeat("a", 64)}
}

func TestLocalStructuredOutputWireAndIdentity(t *testing.T) {
	config := localStructuredConfig(t)
	a, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	config.LocalStructuredOutput = false
	legacy, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.ConfigurationIdentity() == a.ConfigurationIdentity() {
		t.Fatal("option not identity bound")
	}
	investigation := structuredInvestigationRequest(t)
	for _, raw := range []provider.Request{testRawModelRequest(t), testRawVerificationRequest(t, "literal"), investigation} {
		instructions, err := review.TrustedModelRequestInstructions(raw.Payload())
		if err != nil {
			t.Fatal(err)
		}
		for _, adapter := range []*Adapter{legacy, a} {
			request, err := adapter.newRequest(context.Background(), testKey(t), "model", 100, instructions, raw.Payload())
			if err != nil {
				t.Fatal(err)
			}
			content, err := io.ReadAll(request.Body)
			request.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]json.RawMessage
			if json.Unmarshal(content, &wire) != nil {
				t.Fatal("invalid wire")
			}
			if adapter == legacy {
				expected, _ := json.Marshal(struct {
					Model     string               `json:"model"`
					Messages  []chatRequestMessage `json:"messages"`
					MaxTokens uint32               `json:"max_tokens"`
					Stream    bool                 `json:"stream"`
				}{"model", []chatRequestMessage{{"system", instructions}, {"user", string(raw.Payload())}}, 100, false})
				if !bytes.Equal(content, expected) {
					t.Fatal("legacy wire bytes changed")
				}
				continue
			}
			if len(wire) != 5 || string(wire["max_tokens"]) != "100" || string(wire["stream"]) != "false" {
				t.Fatalf("wire %s", content)
			}
			var format struct {
				Type       string `json:"type"`
				JSONSchema struct {
					Name   string          `json:"name"`
					Strict bool            `json:"strict"`
					Schema json.RawMessage `json:"schema"`
				} `json:"json_schema"`
			}
			if json.Unmarshal(wire["response_format"], &format) != nil || format.Type != "json_schema" || !format.JSONSchema.Strict || format.JSONSchema.Name != "open_trestle_review" {
				t.Fatal("unbound response format")
			}
			schema, err := review.TrustedModelRequestOutputSchema(raw.Payload())
			if err != nil || !bytes.Equal(schema, format.JSONSchema.Schema) {
				t.Fatal("schema changed")
			}
			var messages []chatRequestMessage
			if json.Unmarshal(wire["messages"], &messages) != nil || len(messages) != 2 || messages[0].Content != instructions || messages[1].Content != string(raw.Payload()) {
				t.Fatal("payload changed")
			}
		}
	}
	a.localStructuredOutput = false
	if a.Validate() == nil {
		t.Fatal("option mutation retained identity")
	}
}

func TestLocalStructuredOutputRefusesUnsupportedConfiguration(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Protocol = ProtocolResponses },
		func(c *Config) { c.Protocol = "" },
		func(c *Config) { c.Endpoint = "http://localhost:1/v1" },
		func(c *Config) { c.Endpoint = "http://127.1:1/v1" },
		func(c *Config) {
			c.Zone = provider.ProviderZonePrivateRemote
			c.Endpoint = "https://api.example.test/v1"
		},
		func(c *Config) { c.RequestProfile = RequestProfileOpenRouterZDRChatV1 },
	} {
		config := localStructuredConfig(t)
		mutate(&config)
		if _, err := New(config); err == nil {
			t.Fatal("unsupported option accepted")
		}
		if config.Credentials.(*credentialProvider).calls.Load() != 0 {
			t.Fatal("configuration retrieved credentials")
		}
	}
}

func structuredInvestigationRequest(t *testing.T) provider.Request {
	t.Helper()
	payload, err := json.Marshal(struct {
		Contract            string          `json:"contract"`
		SchemaVersion       int             `json:"schema_version"`
		ReviewScopeIdentity string          `json:"review_scope_identity"`
		Task                string          `json:"task"`
		InstructionsID      string          `json:"instructions_identity"`
		Schema              json.RawMessage `json:"output_schema"`
		Identity            string          `json:"output_schema_identity"`
	}{"open-trestle/review-context-packet", 6, strings.Repeat("c", 64), review.ContextTaskCandidateGeneration.String(), "9676adfdd8a31389a68dfb995bed16c98a6f6688f8931f1ef1dc1a6fa170792f", review.InvestigationOutputSchema(), "77367fd94611f87d36e4490729096db927b8d27b9d687a4b6ab515db70e2bbc4"})
	if err != nil {
		t.Fatal(err)
	}
	request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", payload)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

type structuredForbiddenTransport struct{ calls int }

func (r *structuredForbiddenTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return nil, ErrInvalidConfig
}

func TestLocalStructuredOutputRejectsMaliciousSchemaBeforeCredentials(t *testing.T) {
	config := localStructuredConfig(t)
	transport := &structuredForbiddenTransport{}
	config.HTTPClient = &http.Client{Transport: transport}
	config.HTTPClientIdentity = strings.Repeat("b", 64)
	a, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	raw := structuredInvestigationRequest(t)
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw.Payload(), &fields) != nil {
		t.Fatal("request")
	}
	fields["output_schema"] = json.RawMessage(`{"type":"object","additionalProperties":true}`)
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	malicious, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", encoded)
	if err != nil {
		t.Fatal(err)
	}
	result := a.execute(context.Background(), testRoute(t, "model", ""), 100, malicious)
	if result.Failure() != gateway.RouteFailureInvalidResponse || result.ReplaySafety() != gateway.RouteReplayNotDispatched || config.Credentials.(*credentialProvider).calls.Load() != 0 || transport.calls != 0 {
		t.Fatal("untrusted schema reached credentials/transport")
	}
}

func TestLocalStructuredOutputFalsePreservesLocalIdentityPreimages(t *testing.T) {
	for _, noAuth := range []bool{false, true} {
		config := localStructuredConfig(t)
		config.LocalStructuredOutput = false
		if noAuth {
			config.CredentialMode = CredentialModeNone
			config.Credentials = nil
			config.CredentialIdentity = ""
		}
		a, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		preimage, _ := json.Marshal(struct {
			Contract   string `json:"contract"`
			Version    int    `json:"version"`
			Adapter    string `json:"adapter"`
			Provider   string `json:"provider"`
			Connection string `json:"connection"`
			Zone       string `json:"zone"`
			Logging    string `json:"logging"`
			Endpoint   string `json:"endpoint"`
			Credential string `json:"credential"`
			HTTPClient string `json:"http_client"`
			Timeout    int64  `json:"timeout_milliseconds"`
		}{"open-trestle/openai-chat-completions-adapter", 1, config.AdapterID, config.ProviderID, config.ConnectionID, config.Zone.String(), config.ContentLoggingMode.String(), config.Endpoint, config.CredentialIdentity, defaultHTTPClientIdentity(), defaultRequestTimeout.Milliseconds()})
		if noAuth {
			preimage, _ = json.Marshal(struct {
				Contract      string          `json:"contract"`
				Version       int             `json:"version"`
				Configuration json.RawMessage `json:"configuration"`
				Protocol      Protocol        `json:"protocol"`
				Mode          CredentialMode  `json:"credential_mode"`
			}{"open-trestle/openai-no-auth-adapter", 1, preimage, ProtocolChatCompletions, CredentialModeNone})
		}
		digest := sha256.Sum256(preimage)
		if a.ConfigurationIdentity() != hex.EncodeToString(digest[:]) {
			t.Fatal("false changed legacy local identity")
		}
		config.LocalStructuredOutput = true
		enabled, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		wrapper, _ := json.Marshal(struct {
			Contract      string          `json:"contract"`
			Version       int             `json:"version"`
			Configuration json.RawMessage `json:"configuration"`
			Enabled       bool            `json:"local_structured_output"`
		}{"open-trestle/openai-local-structured-output-adapter", 1, preimage, true})
		digest = sha256.Sum256(wrapper)
		if enabled.ConfigurationIdentity() != hex.EncodeToString(digest[:]) {
			t.Fatal("true identity wrapper differs")
		}
	}
}
