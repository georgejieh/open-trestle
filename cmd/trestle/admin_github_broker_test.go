//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	githubadapter "github.com/georgejieh/open-trestle/adapters/scm/github"
)

func TestSetupBrokerBoundaryAdminBrokerPureSevenKeyIdentity(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	// Public admin has no getenv dependency. Poison env and retain observable
	// no-owner/no-HTTP oracles; do not claim an injected key-read measurement.
	f.setenv(t)
	t.Setenv("OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY", "synthetic-invalid-key-must-remain-unused")
	t.Setenv("OPEN_TRESTLE_GITHUB_API_TOKEN", "synthetic-static-must-not-affect-offline-admin")
	lane, err := githubadapter.NewIssuanceAuthority(f.configuration.Authority(), githubadapter.IssuancePurposeSetup)
	if err != nil {
		t.Fatal("native pure setup lane identity failed")
	}
	permission, err := githubadapter.BrokeredPermissionAuthorityIdentity(f.configuration.Authority(), setupGitHubPermissionUserCredentialIdentity(), 30*time.Second)
	if err != nil {
		t.Fatal("native pure permission identity failed")
	}
	var stdout, stderr bytes.Buffer
	code := runGitHubAdmin([]string{"permissions", "identity", "--broker-config", f.descriptor}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatal("actual broker-config admin entrypoint failed")
	}
	want := fmt.Sprintf("{\"contract\":\"open-trestle/github-permission-admin-result\",\"schema_version\":2,\"status\":\"configuration_only\",\"operation\":\"identity\",\"broker_authority_identity\":%q,\"setup_issuance_authority_identity\":%q,\"permission_authority_identity\":%q}\n", f.configuration.AuthorityIdentity(), lane.Identity(), permission)
	if stdout.String() != want {
		t.Fatal("admin v2 wire bytes/order/newline differ from frozen seven-key contract")
	}
	var got map[string]json.RawMessage
	if json.Unmarshal(stdout.Bytes(), &got) != nil || len(got) != 7 {
		t.Fatal("admin v2 output shape differs")
	}
	for _, key := range []string{"broker_authority_identity", "setup_issuance_authority_identity", "permission_authority_identity"} {
		var identity string
		if json.Unmarshal(got[key], &identity) != nil || !validAdminDigest(identity) {
			t.Fatal("admin identity not nonzero lowercase HEX64")
		}
	}
	wireType := reflect.TypeOf(setupGitHubPermissionAdminBrokerResult{})
	wantTags := []string{"contract", "schema_version", "status", "operation", "broker_authority_identity", "setup_issuance_authority_identity", "permission_authority_identity"}
	if wireType.NumField() != len(wantTags) {
		t.Fatal("admin result declaration field count drift")
	}
	for i, tag := range wantTags {
		if wireType.Field(i).Tag.Get("json") != tag {
			t.Fatal("admin result declaration tag/order drift")
		}
	}
	for _, private := range []string{f.descriptor, f.attempts, f.pin, "owner/repo", "tenant-a", "repo-a", "authorization_generation", "allow_token_creation", "app_id", "installation_id"} {
		if strings.Contains(stdout.String(), private) {
			t.Fatal("configuration-only admin disclosed descriptor detail")
		}
	}
	f.noEffects(t)
	f.redacted(t, stdout.Bytes())
	f.redacted(t, stderr.Bytes())
	// Read-only operation is repeatable with the exact same bytes and no fence.
	stdout.Reset()
	if code := runGitHubPermissionAdminIdentity([]string{"--broker-config", f.descriptor}, &stdout, &stderr); code != 0 || stdout.String() != want {
		t.Fatal("offline identity unexpectedly consumed generation")
	}
	f.noEffects(t)
}

func TestSetupBrokerBoundaryAdminLegacyV1ExactOutput(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	f.setenv(t)
	t.Setenv("OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY", "synthetic-invalid-key-must-remain-unused")
	// Legacy identity is pure and remains v1. The numeric synthetic endpoint
	// gives an observable no-issuer oracle even if the old path regresses.
	endpoint := f.server.URL + "/api/v3"
	identity, err := githubadapter.PermissionAuthorityIdentity(endpoint, "2026-03-10", 42, "owner/repo", setupGitHubPermissionUserCredentialIdentity(), setupGitHubPermissionRuntimeCredentialIdentity(), 30*time.Second)
	if err != nil {
		t.Fatal("legacy pure identity derivation failed")
	}
	var stdout, stderr bytes.Buffer
	if code := runGitHubAdmin([]string{"permissions", "identity", "--api-endpoint", endpoint, "--api-version", "2026-03-10", "--installation-id", "42", "--repository-full-name", "owner/repo"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatal("legacy identity command failed")
	}
	want := fmt.Sprintf("{\"contract\":\"open-trestle/github-permission-admin-result\",\"schema_version\":1,\"status\":\"valid\",\"operation\":\"identity\",\"permission_authority_identity\":%q}\n", identity)
	if stdout.String() != want {
		t.Fatal("legacy v1 output bytes/order/newline changed")
	}
	f.noEffects(t)
	f.redacted(t, stdout.Bytes())
}

func TestSetupBrokerBoundaryAdminBrokerPresenceAndProtectedLoadRefusals(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	for _, name := range []string{"empty-broker-path", "mixed-endpoint-empty", "mixed-version-empty", "mixed-installation-zero", "mixed-repository-empty", "unprotected-descriptor", "old-api-year"} {
		t.Run(name, func(t *testing.T) {
			args := []string{"--broker-config", f.descriptor}
			want := 2
			switch name {
			case "empty-broker-path":
				args = []string{"--broker-config="}
			case "mixed-endpoint-empty":
				args = []string{"--broker-config", filepath.Join(f.root, "missing.json"), "--api-endpoint="}
			case "mixed-version-empty":
				args = []string{"--broker-config", filepath.Join(f.root, "missing.json"), "--api-version="}
			case "mixed-installation-zero":
				args = []string{"--broker-config", filepath.Join(f.root, "missing.json"), "--installation-id=0"}
			case "mixed-repository-empty":
				args = []string{"--broker-config", filepath.Join(f.root, "missing.json"), "--repository-full-name="}
			case "unprotected-descriptor":
				if os.Chmod(f.descriptor, 0o666) != nil {
					t.Fatal("synthetic descriptor mode change failed")
				}
				defer func() {
					if os.Chmod(f.descriptor, 0o600) != nil {
						t.Error("descriptor protection restore failed")
					}
				}()
				want = 1
			case "old-api-year":
				f.writeDescriptor(t, strings.Repeat("d", 64), "1999-03-10")
				if f.configuration.Validate() != nil {
					t.Fatal("source config should accept exact valid old date")
				}
				want = 1
			}
			var stdout, stderr bytes.Buffer
			if code := runGitHubPermissionAdminIdentity(args, &stdout, &stderr); code != want || stdout.Len() != 0 {
				t.Fatal("admin presence/protected-load/minimum-year gate mismatch")
			}
			f.noEffects(t)
			f.redacted(t, stderr.Bytes())
		})
	}
}
