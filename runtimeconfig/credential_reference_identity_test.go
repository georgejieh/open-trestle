package runtimeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// The exported derivation is the one every policy connection records, so a
// spending limit keyed by it matches the connections of every setup that
// names the same key variable.
func TestCredentialReferenceIdentityMatchesTheConnectionDerivation(t *testing.T) {
	const name = "OPEN_TRESTLE_PROVIDER_OPENROUTER"
	sum := sha256.Sum256([]byte("open-trestle/provider-credential-environment/" + name))
	identity, ok := CredentialReferenceIdentity(name)
	if !ok || identity != hex.EncodeToString(sum[:]) || identity != credentialEnvironmentIdentity(name) {
		t.Fatalf("identity=%q ok=%v", identity, ok)
	}
	if !ValidCredentialEnvironment(name) {
		t.Fatal("a valid key variable name was refused")
	}
	for _, refused := range []string{"", "OPEN_TRESTLE_PROVIDER_", "OPEN_TRESTLE_PROVIDER_lower", "sk-or-v1-0123456789", "OTHER_PREFIX_OPENROUTER"} {
		if identity, ok := CredentialReferenceIdentity(refused); ok || identity != "" || ValidCredentialEnvironment(refused) {
			t.Fatalf("%q was admitted as a key variable name", refused)
		}
	}
}
