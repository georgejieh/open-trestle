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

type goProfileClock struct{ at time.Time }

func (c *goProfileClock) Now() time.Time { return c.at }

type goProfileTransport struct{ calls int }

func (r *goProfileTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return nil, ErrInvalidConfig
}

func goProfileConfig(t *testing.T) (Config, provider.RouteReference, *goProfileClock, *credentialProvider, *goProfileTransport) {
	t.Helper()
	route, err := provider.NewRouteReference(provider.ProviderZoneBrokeredRemote, "opencode-go", "go-adapter", "primary/go", "model", "")
	if err != nil {
		t.Fatal(err)
	}
	clock := &goProfileClock{at: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	credentials := &credentialProvider{key: testKey(t)}
	transport := &goProfileTransport{}
	config := Config{Protocol: ProtocolChatCompletions, RequestProfile: RequestProfileOpenCodeGoChatV1, CredentialMode: CredentialModeBearer, AdapterID: route.AdapterID(), ProviderID: route.ProviderID(), ConnectionID: route.ConnectionID(), Zone: route.Zone(), ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "https://opencode.ai/inference/go/openai/v1", Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64), HTTPClient: &http.Client{Transport: transport, Timeout: time.Minute}, HTTPClientIdentity: strings.Repeat("b", 64), Clock: clock, OpenCodeGoAuthority: &OpenCodeGoRouteAuthority{Route: route, RouteRecordIdentity: strings.Repeat("c", 64), EvidenceIdentity: strings.Repeat("d", 64), AccountPolicyIdentity: strings.Repeat("e", 64), CredentialIdentity: strings.Repeat("a", 64), TenantID: "tenant-a", RepositoryID: "repository-a", ValidFrom: clock.at.Add(-time.Minute), ValidUntil: clock.at.Add(time.Minute)}}
	return config, route, clock, credentials, transport
}

func TestOpenCodeGoProfileClonesAuthorityAndRejectsUnprovedOrExpiredBeforeKey(t *testing.T) {
	for _, expired := range []bool{false, true} {
		config, route, clock, credentials, transport := goProfileConfig(t)
		adapter, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		identity := adapter.ConfigurationIdentity()
		config.OpenCodeGoAuthority.RepositoryID = "another-repository"
		if adapter.Validate() != nil || adapter.ConfigurationIdentity() != identity {
			t.Fatal("caller mutated retained authority")
		}
		if expired {
			clock.at = adapter.openCodeGoAuthority.ValidUntil
		}
		result := adapter.execute(context.Background(), route, 100, testRequest(t))
		if result.Status() != gateway.RouteDispatchFailed || result.ReplaySafety() != gateway.RouteReplayNotDispatched || credentials.calls.Load() != 0 || transport.calls != 0 {
			t.Fatal("unproved/expired Go dispatch reached effect")
		}
	}
}

func TestOpenCodeGoProfileRefusesMixedOrWrongAuthority(t *testing.T) {
	for _, name := range []string{"missing", "mixed", "endpoint", "provider", "protocol", "credential", "window", "scope"} {
		t.Run(name, func(t *testing.T) {
			config, _, _, credentials, transport := goProfileConfig(t)
			switch name {
			case "missing":
				config.OpenCodeGoAuthority = nil
			case "mixed":
				config.OpenRouterAuthority = &OpenRouterRouteAuthority{}
			case "endpoint":
				config.Endpoint = "https://opencode.ai/inference/openai/v1"
			case "provider":
				config.ProviderID = "openrouter"
			case "protocol":
				config.Protocol = ProtocolResponses
			case "credential":
				config.OpenCodeGoAuthority.CredentialIdentity = strings.Repeat("f", 64)
			case "window":
				config.OpenCodeGoAuthority.ValidUntil = config.OpenCodeGoAuthority.ValidFrom
			case "scope":
				config.OpenCodeGoAuthority.RepositoryID = ""
			}
			if _, err := New(config); err == nil {
				t.Fatal("invalid Go authority accepted")
			}
			if credentials.calls.Load() != 0 || transport.calls != 0 {
				t.Fatal("constructor caused effect")
			}
		})
	}
}
