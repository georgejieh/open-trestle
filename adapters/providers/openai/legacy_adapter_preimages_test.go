package openai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/georgejieh/open-trestle/internal/provider"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestOpenRouterProfileDoesNotRehashLegacyBearerAdapters(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolResponses, ProtocolChatCompletions} {
		t.Run(string(protocol), func(t *testing.T) {
			credentials := &credentialProvider{key: testKey(t)}
			config := Config{
				Protocol:  protocol,
				AdapterID: "legacy", ProviderID: "direct", ConnectionID: "primary/direct",
				Zone: provider.ProviderZonePrivateRemote, ContentLoggingMode: provider.ContentLoggingDisabled,
				Endpoint:    "https://direct.example.test/v1",
				Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64),
				HTTPClient:         &http.Client{Transport: http.DefaultTransport, Timeout: 2 * time.Minute},
				HTTPClientIdentity: strings.Repeat("b", 64),
			}
			adapter, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			contract, version := "open-trestle/openai-responses-adapter", 4
			if protocol == ProtocolChatCompletions {
				contract, version = "open-trestle/openai-chat-completions-adapter", 1
			}
			preimage, err := json.Marshal(struct {
				Contract            string `json:"contract"`
				Version             int    `json:"version"`
				Adapter             string `json:"adapter"`
				Provider            string `json:"provider"`
				Connection          string `json:"connection"`
				Zone                string `json:"zone"`
				Logging             string `json:"logging"`
				Endpoint            string `json:"endpoint"`
				Credential          string `json:"credential"`
				HTTPClient          string `json:"http_client"`
				TimeoutMilliseconds int64  `json:"timeout_milliseconds"`
			}{contract, version, "legacy", "direct", "primary/direct", "private_remote", "disabled", "https://direct.example.test/v1", strings.Repeat("a", 64), strings.Repeat("b", 64), 120000})
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(preimage)
			if adapter.ConfigurationIdentity() != hex.EncodeToString(digest[:]) || credentials.calls.Load() != 0 {
				t.Fatal("legacy configuration preimage changed or credentials read")
			}
		})
	}
}
