package openai

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestNoAuthAuthorityMutationAndTypedNilFailClosed(t *testing.T) {
	config := Config{CredentialMode: CredentialModeNone, AdapterID: "openai-responses", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZoneLocal, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "http://127.0.0.1:1/v1"}
	a, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	a.credentialMode = CredentialModeBearer
	if a.Validate() == nil {
		t.Fatal("mutating none into bearer preserved authority")
	}
	var credentials *credentialProvider
	config.Credentials = credentials
	if _, err := New(config); err == nil {
		t.Fatal("typed-nil credentials conflicted with none but were accepted")
	}
	config.Credentials = nil
	config.CredentialIdentity = strings.Repeat("a", 64)
	if _, err := New(config); err == nil {
		t.Fatal("none retained credential identity")
	}
}
