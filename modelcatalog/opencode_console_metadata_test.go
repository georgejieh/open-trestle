package modelcatalog

import (
	"encoding/json"
	"testing"
)

func TestOpenCodeConsoleNamedSourceUsesExistingAuthenticatedManifest(t *testing.T) {
	raw := mustRead(t, "testdata/named_metadata/opencode_console_sources.json")
	var value Manifest
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if len(value.Sources) != 1 || value.SchemaVersion != 2 || value.Sources[0] != (Source{ID: "opencode-console", Kind: "openai_models", URL: "https://opencode.ai/inference/v1/models", CredentialEnvironment: "OPEN_TRESTLE_PROVIDER_OPENCODE_CONSOLE"}) {
		t.Fatal("Console metadata source authority changed")
	}
	if err := validateManifest(value, false); err == nil {
		t.Fatal("remote source accepted without opt-in")
	}
	if err := validateManifest(value, true); err != nil {
		t.Fatal(err)
	}
}
