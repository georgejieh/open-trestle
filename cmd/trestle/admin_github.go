package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	githubadapter "github.com/georgejieh/open-trestle/adapters/scm/github"
	githubwebhook "github.com/georgejieh/open-trestle/adapters/webhook/github"
	githubruntime "github.com/georgejieh/open-trestle/internal/githubruntime"
)

func runGitHubAdmin(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 || args[1] != "identity" {
		writeAdminUsage(stderr)
		return 2
	}
	switch args[0] {
	case "permissions":
		return runGitHubPermissionAdminIdentity(args[2:], stdout, stderr)
	case "webhook":
		return runGitHubWebhookAdminIdentity(args[2:], stdout, stderr)
	default:
		writeAdminUsage(stderr)
		return 2
	}
}

type setupGitHubPermissionAdminBrokerResult struct {
	Contract                       string `json:"contract"`
	SchemaVersion                  int    `json:"schema_version"`
	Status                         string `json:"status"`
	Operation                      string `json:"operation"`
	BrokerAuthorityIdentity        string `json:"broker_authority_identity"`
	SetupIssuanceAuthorityIdentity string `json:"setup_issuance_authority_identity"`
	PermissionAuthorityIdentity    string `json:"permission_authority_identity"`
}

func runGitHubPermissionAdminIdentity(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trestle admin github permissions identity", flag.ContinueOnError)
	flags.SetOutput(stderr)
	brokerConfig := flags.String("broker-config", "", "protected source broker descriptor for configuration-only identity")
	endpoint := flags.String("api-endpoint", "", "exact GitHub API endpoint")
	version := flags.String("api-version", "", "exact GitHub API version")
	installation := flags.Uint64("installation-id", 0, "GitHub App installation identifier")
	repository := flags.String("repository-full-name", "", "lowercase owner/repository")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		writeAdminUsage(stderr)
		return 2
	}
	brokerPresent, legacyPresent := false, false
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "broker-config":
			brokerPresent = true
		case "api-endpoint", "api-version", "installation-id", "repository-full-name":
			legacyPresent = true
		}
	})
	if brokerPresent {
		if *brokerConfig == "" || legacyPresent {
			writeAdminUsage(stderr)
			return 2
		}
		configuration, err := githubruntime.LoadConfig(context.Background(), *brokerConfig)
		if err != nil || !validSetupGitHubPermissionBrokerConfiguration(configuration) {
			fmt.Fprintln(stderr, "GitHub permission administration failed")
			return 1
		}
		lane, laneErr := githubadapter.NewIssuanceAuthority(configuration.Authority(), githubadapter.IssuancePurposeSetup)
		permission, permissionErr := githubadapter.BrokeredPermissionAuthorityIdentity(configuration.Authority(), setupGitHubPermissionUserCredentialIdentity(), 30*time.Second)
		if laneErr != nil || permissionErr != nil {
			fmt.Fprintln(stderr, "GitHub permission administration failed")
			return 1
		}
		result := setupGitHubPermissionAdminBrokerResult{
			Contract: "open-trestle/github-permission-admin-result", SchemaVersion: 2,
			Status: "configuration_only", Operation: "identity",
			BrokerAuthorityIdentity: configuration.AuthorityIdentity(), SetupIssuanceAuthorityIdentity: lane.Identity(),
			PermissionAuthorityIdentity: permission,
		}
		if json.NewEncoder(stdout).Encode(result) != nil {
			fmt.Fprintln(stderr, "write result failed")
			return 1
		}
		return 0
	}
	if *endpoint == "" || *version == "" || *installation == 0 || *repository == "" {
		writeAdminUsage(stderr)
		return 2
	}
	identity, err := deriveSetupGitHubPermissionAuthority(setupGitHubPermissionConfiguration{apiEndpoint: *endpoint, apiVersion: *version, installationID: *installation, repositoryFullName: *repository})
	if err != nil {
		fmt.Fprintln(stderr, "GitHub permission administration failed")
		return 1
	}
	result := struct {
		Contract                    string `json:"contract"`
		SchemaVersion               int    `json:"schema_version"`
		Status                      string `json:"status"`
		Operation                   string `json:"operation"`
		PermissionAuthorityIdentity string `json:"permission_authority_identity"`
	}{"open-trestle/github-permission-admin-result", 1, "valid", "identity", identity}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}
func runGitHubWebhookAdminIdentity(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trestle admin github webhook identity", flag.ContinueOnError)
	flags.SetOutput(stderr)
	tenant := flags.String("tenant", "", "tenant identifier")
	repository := flags.String("repository", "", "repository identifier")
	keyID := flags.String("key-id", "", "non-secret webhook key identifier")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *tenant == "" || *repository == "" || *keyID == "" {
		writeAdminUsage(stderr)
		return 2
	}
	configuration := setupGitHubWebhookConfiguration{*tenant, *repository, *keyID}
	authority, err := deriveSetupGitHubWebhookAuthority(configuration)
	scope, scopeErr := webhookScope(configuration)
	verifier := ""
	if scopeErr == nil {
		verifier, scopeErr = githubwebhook.VerifierConfigurationIdentity(scope, *keyID)
	}
	if err != nil || scopeErr != nil {
		fmt.Fprintln(stderr, "GitHub webhook administration failed")
		return 1
	}
	result := struct {
		Contract                      string `json:"contract"`
		SchemaVersion                 int    `json:"schema_version"`
		Status                        string `json:"status"`
		Operation                     string `json:"operation"`
		WebhookAuthorityIdentity      string `json:"webhook_authority_identity"`
		VerifierConfigurationIdentity string `json:"verifier_configuration_identity"`
	}{"open-trestle/github-webhook-admin-result", 1, "valid", "identity", authority, verifier}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}
