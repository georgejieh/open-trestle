package openai

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

type consoleProfileClock struct{ at time.Time }

func (c *consoleProfileClock) Now() time.Time { return c.at }

type consoleProfileTransport struct{ calls int }

func (r *consoleProfileTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return nil, ErrInvalidConfig
}

func consoleProfileConfig(t *testing.T) (Config, provider.RouteReference, *consoleProfileClock, *credentialProvider, *consoleProfileTransport) {
	t.Helper()
	route, err := provider.NewRouteReference(provider.ProviderZoneBrokeredRemote, "opencode-console", "go-adapter", "primary/go", "model", "")
	if err != nil {
		t.Fatal(err)
	}
	clock := &consoleProfileClock{at: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	credentials := &credentialProvider{key: testKey(t)}
	transport := &consoleProfileTransport{}
	config := Config{Protocol: ProtocolChatCompletions, RequestProfile: RequestProfileOpenCodeConsoleChatV1, CredentialMode: CredentialModeBearer, AdapterID: route.AdapterID(), ProviderID: route.ProviderID(), ConnectionID: route.ConnectionID(), Zone: route.Zone(), ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "https://opencode.ai/inference/openai/v1", Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64), HTTPClient: &http.Client{Transport: transport, Timeout: time.Minute}, HTTPClientIdentity: strings.Repeat("b", 64), Clock: clock, OpenCodeConsoleAuthority: &OpenCodeConsoleRouteAuthority{Route: route, RouteRecordIdentity: strings.Repeat("c", 64), EvidenceIdentity: strings.Repeat("d", 64), AccountPolicyIdentity: strings.Repeat("e", 64), CredentialIdentity: strings.Repeat("a", 64), TenantID: "tenant-a", RepositoryID: "repository-a", ValidFrom: clock.at.Add(-time.Minute), ValidUntil: clock.at.Add(time.Minute)}}
	return config, route, clock, credentials, transport
}

func TestOpenCodeConsoleProfileClonesAuthorityAndRejectsUnprovedOrExpiredBeforeKey(t *testing.T) {
	for _, expired := range []bool{false, true} {
		config, route, clock, credentials, transport := consoleProfileConfig(t)
		adapter, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		identity := adapter.ConfigurationIdentity()
		config.OpenCodeConsoleAuthority.RepositoryID = "another-repository"
		if adapter.Validate() != nil || adapter.ConfigurationIdentity() != identity {
			t.Fatal("caller mutated retained authority")
		}
		if expired {
			clock.at = adapter.openCodeConsoleAuthority.ValidUntil
		}
		result := adapter.execute(context.Background(), route, 100, testRequest(t))
		if result.Status() != gateway.RouteDispatchFailed || result.ReplaySafety() != gateway.RouteReplayNotDispatched || credentials.calls.Load() != 0 || transport.calls != 0 {
			t.Fatal("unproved/expired Console dispatch reached effect")
		}
	}
}

func TestOpenCodeConsoleProfileRefusesMixedOrWrongAuthority(t *testing.T) {
	for _, name := range []string{"missing", "mixed", "endpoint", "provider", "protocol", "credential", "window", "scope"} {
		t.Run(name, func(t *testing.T) {
			config, _, _, credentials, transport := consoleProfileConfig(t)
			switch name {
			case "missing":
				config.OpenCodeConsoleAuthority = nil
			case "mixed":
				config.OpenRouterAuthority = &OpenRouterRouteAuthority{}
			case "endpoint":
				config.Endpoint = "https://opencode.ai/inference/go/openai/v1"
			case "provider":
				config.ProviderID = "openrouter"
			case "protocol":
				config.Protocol = ProtocolResponses
			case "credential":
				config.OpenCodeConsoleAuthority.CredentialIdentity = strings.Repeat("f", 64)
			case "window":
				config.OpenCodeConsoleAuthority.ValidUntil = config.OpenCodeConsoleAuthority.ValidFrom
			case "scope":
				config.OpenCodeConsoleAuthority.RepositoryID = ""
			}
			if _, err := New(config); err == nil {
				t.Fatal("invalid Console authority accepted")
			}
			if credentials.calls.Load() != 0 || transport.calls != 0 {
				t.Fatal("constructor caused effect")
			}
		})
	}
}

func TestOpenCodeConsoleProfileRefusesFreeSelectors(t *testing.T) {
	for _, selector := range []string{"big-pickle", "glm-5.3-flash-free", "beam-free"} {
		config, _, _, _, _ := consoleProfileConfig(t)
		route, err := provider.NewRouteReference(config.Zone, config.ProviderID, config.AdapterID, config.ConnectionID, selector, "")
		if err != nil {
			t.Fatal(err)
		}
		config.OpenCodeConsoleAuthority.Route = route
		if _, err := New(config); err == nil {
			t.Fatal("free selector admitted by paid Console profile")
		}
	}
}
