package modelcatalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/runtimecatalog"
)

func TestRefreshCredentialAuthorityBeforeRead(t *testing.T) {
	for _, test := range []struct{ name, raw string }{
		{"v1_reference", `{"schema_version":1,"sources":[{"id":"s","kind":"openai_models","url":"http://127.0.0.1:1/models","credential_environment":"OPEN_TRESTLE_PROVIDER_METADATA"}]}`},
		{"v1_empty", `{"schema_version":1,"sources":[{"id":"s","kind":"openai_models","url":"http://127.0.0.1:1/models","credential_environment":""}]}`},
		{"null", `{"schema_version":2,"sources":[{"id":"s","kind":"openai_models","url":"http://127.0.0.1:1/models","credential_environment":null}]}`},
		{"alias", `{"schema_version":2,"sources":[{"id":"s","kind":"openai_models","url":"http://127.0.0.1:1/models","Credential_Environment":"OPEN_TRESTLE_PROVIDER_METADATA"}]}`},
		{"secret_not_reference", `{"schema_version":2,"sources":[{"id":"s","kind":"openai_models","url":"http://127.0.0.1:1/models","credential_environment":"literal-secret"}]}`},
		{"remote_without_optin", `{"schema_version":2,"sources":[{"id":"s","kind":"openai_models","url":"https://example.com/models","credential_environment":"OPEN_TRESTLE_PROVIDER_METADATA"}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			sources, current, proposal := paths(t)
			if err := os.WriteFile(sources, []byte(test.raw), 0600); err != nil {
				t.Fatal(err)
			}
			reads := 0
			resolver, _ := runtimecatalog.NewEnvironmentOpenAICredentialResolver(func(string) string { reads++; return "synthetic-key" })
			if _, err := RefreshWithCredentials(context.Background(), sources, current, proposal, false, resolver); err == nil {
				t.Fatal("invalid credential authority accepted")
			}
			if reads != 0 {
				t.Fatal("invalid authority read a credential")
			}
			if _, err := os.Stat(proposal); !os.IsNotExist(err) {
				t.Fatal("invalid authority staged a proposal")
			}
		})
	}
}

func TestAuthenticatedRefreshFailurePreservesSnapshot(t *testing.T) {
	const ref = "OPEN_TRESTLE_PROVIDER_METADATA"
	response := `{"data":[{"id":"Exact/Model:tag"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-key" {
			t.Error("missing metadata credential")
		}
		if response == "fail" {
			http.Error(w, "private-provider-body", 401)
			return
		}
		w.Write([]byte(response))
	}))
	defer server.Close()
	sources, current, proposal := paths(t)
	writeJSON(t, sources, Manifest{SchemaVersion: 2, Sources: []Source{{ID: "s", Kind: "openai_models", URL: server.URL + "/models", CredentialEnvironment: ref}}})
	reads := 0
	resolver, _ := runtimecatalog.NewEnvironmentOpenAICredentialResolver(func(string) string { reads++; return "synthetic-key" })
	review, err := RefreshWithCredentials(context.Background(), sources, current, proposal, false, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(context.Background(), sources, current, proposal, review.ProposalDigest, "absent"); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, current)
	os.Remove(proposal)
	response = "fail"
	review, err = RefreshWithCredentials(context.Background(), sources, current, proposal, false, resolver)
	if err != nil || len(review.Failures) != 1 || len(review.Diff.Removed) != 0 {
		t.Fatal("failed metadata lost last good snapshot")
	}
	if strings.Contains(string(mustRead(t, proposal)), "private-provider-body") {
		t.Fatal("provider error leaked")
	}
	if err = Apply(context.Background(), sources, current, proposal, review.ProposalDigest, Digest(before)); err != nil {
		t.Fatal(err)
	}
	var applied Catalog
	if json.Unmarshal(mustRead(t, current), &applied) != nil || applied.Sources[0].Models[0].Selector != "Exact/Model:tag" || reads != 2 {
		t.Fatal("snapshot or credential read boundaries changed")
	}
}

func TestAuthenticatedRefreshNeverDowngradesMissingCredential(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.Write([]byte(`{"data":[]}`)) }))
	defer server.Close()
	for _, value := range []string{"", "unsafe key", "unsafe\r\nHeader:value"} {
		sources, current, proposal := paths(t)
		writeJSON(t, sources, Manifest{SchemaVersion: 2, Sources: []Source{{ID: "s", Kind: "openai_models", URL: server.URL + "/models", CredentialEnvironment: "OPEN_TRESTLE_PROVIDER_METADATA"}}})
		resolver, _ := runtimecatalog.NewEnvironmentOpenAICredentialResolver(func(string) string { return value })
		review, err := RefreshWithCredentials(context.Background(), sources, current, proposal, false, resolver)
		if err != nil || len(review.Failures) != 1 || requests != 0 {
			t.Fatal("unavailable credential caused unauthenticated request")
		}
	}
}

func TestAuthenticatedRefreshWithoutResolverDoesNotRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.Write([]byte(`{"data":[]}`)) }))
	defer server.Close()
	sources, current, proposal := paths(t)
	writeJSON(t, sources, Manifest{SchemaVersion: 2, Sources: []Source{{ID: "s", Kind: "openai_models", URL: server.URL + "/models", CredentialEnvironment: "OPEN_TRESTLE_PROVIDER_METADATA"}}})
	review, err := Refresh(context.Background(), sources, current, proposal, false)
	if err != nil || len(review.Failures) != 1 || requests != 0 {
		t.Fatal("missing resolver caused a request or hid source failure")
	}
}

func TestCredentialReferenceCannotCrossMetadataOrigins(t *testing.T) {
	sources, current, proposal := paths(t)
	writeJSON(t, sources, Manifest{SchemaVersion: 2, Sources: []Source{
		{ID: "one", Kind: "openai_models", URL: "https://one.example/models", CredentialEnvironment: "OPEN_TRESTLE_PROVIDER_METADATA"},
		{ID: "two", Kind: "openai_models", URL: "https://two.example/models", CredentialEnvironment: "OPEN_TRESTLE_PROVIDER_METADATA"},
	}})
	reads := 0
	resolver, _ := runtimecatalog.NewEnvironmentOpenAICredentialResolver(func(string) string { reads++; return "synthetic-key" })
	if _, err := RefreshWithCredentials(context.Background(), sources, current, proposal, true, resolver); err == nil || reads != 0 {
		t.Fatal("credential reference crossed origins")
	}
}
