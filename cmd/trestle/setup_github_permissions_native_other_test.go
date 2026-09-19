//go:build !unix

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	githubadapter "github.com/georgejieh/open-trestle/adapters/scm/github"
	githubruntime "github.com/georgejieh/open-trestle/internal/githubruntime"
)

// Portable roots already checked pure legacy identity/non-execution or webhook
// prerequisites. Native protected ownership is not supported here. Exercise the
// actual protected API and require its closed refusal, never fake a success.
func runSetupGitHubPermissionNativeTest(t *testing.T, name string) {
	t.Helper()
	switch name {
	case "probe-defers-and-separates", "probe-authority-and-shared-token", "probe-classifies-outcomes", "cli-permission-receipt", "tui-permission-receipt", "probe-changed-configuration", "cli-webhook-after-permission", "tui-webhook-after-permission":
	default:
		t.Fatal("unknown native permission companion case")
	}
	root := filepath.Join(t.TempDir(), "protected")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	attempts := filepath.Join(root, "attempts")
	if err := os.Mkdir(attempts, 0o700); err != nil {
		t.Fatal(err)
	}
	wire := map[string]any{
		"contract": "open-trestle/github-source-broker", "schema_version": 1,
		"tenant_id": "tenant-a", "repository_id": "repo-a", "repository_full_name": "owner/repo",
		"github_repository_id": 99, "installation_id": 42, "app_id": 7,
		"repository_authority": "github.com", "api_endpoint": "https://api.github.com", "api_version": "2026-03-10",
		"archive_authorities": []string{"codeload.github.com"}, "app_key_version": "synthetic-key-1",
		"app_public_key_sha256": strings.Repeat("a", 64), "credential_environment": "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY",
		"authorization_generation": strings.Repeat("d", 64), "ownership_mode": "single_host_exclusive",
		"attempt_state_directory": attempts, "allow_token_creation": true, "allow_demand_renewal": true,
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "broker.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	configuration, err := githubruntime.LoadConfig(ctx, path)
	if !errors.Is(err, githubadapter.ErrInvalidBrokerConfig) || configuration.AuthorityIdentity() != "" {
		t.Fatal("unsupported protected ownership unexpectedly acquired broker configuration authority")
	}
	entries, err := os.ReadDir(attempts)
	if err != nil || len(entries) != 0 {
		t.Fatal("protected refusal created credential owner state")
	}
}
