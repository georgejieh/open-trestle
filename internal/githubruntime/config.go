// Package githubruntime owns protected GitHub installation broker composition.
package githubruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"unicode/utf8"

	github "github.com/georgejieh/open-trestle/adapters/scm/github"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

const maxBrokerConfigurationBytes = 64 * 1024

// Configuration is a captured, immutable protected descriptor.
type Configuration struct {
	authority github.InstallationBrokerAuthority
	snapshot  [sha256.Size]byte
}

func (c Configuration) String() string             { return "[redacted GitHub broker configuration]" }
func (c Configuration) GoString() string           { return c.String() }
func (c Configuration) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, c.String()) }

func (c Configuration) Validate() error {
	if c.snapshot == ([sha256.Size]byte{}) || c.authority.Validate() != nil {
		return github.ErrInvalidBrokerConfig
	}
	return nil
}

func (c Configuration) Authority() github.InstallationBrokerAuthority { return c.authority }
func (c Configuration) AuthorityIdentity() string {
	if c.Validate() != nil {
		return ""
	}
	return c.authority.Identity()
}

func LoadConfig(ctx context.Context, path string) (Configuration, error) {
	content, err := readBrokerConfiguration(ctx, path)
	if err != nil {
		return Configuration{}, err
	}
	c, err := decodeBrokerConfiguration(content)
	if err != nil {
		return Configuration{}, err
	}
	if ctx.Err() != nil {
		return Configuration{}, github.ErrBrokerUnavailable
	}
	return c, nil
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func sameConfigurationFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() &&
		a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) &&
		a.Mode().IsRegular() && a.Mode().Perm()&0022 == 0 &&
		fileauthority.TrustedOwner(a) && fileauthority.TrustedOwner(b)
}

func readBrokerConfiguration(ctx context.Context, path string) ([]byte, error) {
	if nilDependency(ctx) || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, github.ErrInvalidBrokerConfig
	}
	var previous []byte
	var pin os.FileInfo
	for pass := 0; pass < 2; pass++ {
		if ctx.Err() != nil {
			return nil, github.ErrBrokerUnavailable
		}
		file, err := fileauthority.OpenReadOnly(path)
		if err != nil {
			return nil, github.ErrInvalidBrokerConfig
		}
		before, statErr := file.Stat()
		if statErr != nil || before.Size() < 1 || before.Size() > maxBrokerConfigurationBytes {
			_ = file.Close()
			return nil, github.ErrInvalidBrokerConfig
		}
		content, readErr := io.ReadAll(io.LimitReader(file, maxBrokerConfigurationBytes+1))
		after, afterErr := file.Stat()
		closeErr := file.Close()
		current, currentErr := os.Lstat(path)
		if readErr != nil || afterErr != nil || closeErr != nil || currentErr != nil ||
			len(content) < 1 || len(content) > maxBrokerConfigurationBytes ||
			!sameConfigurationFile(before, after) || !sameConfigurationFile(after, current) ||
			int64(len(content)) != after.Size() || fileauthority.CheckDirectory(filepath.Dir(path)) != nil {
			return nil, github.ErrInvalidBrokerConfig
		}
		if pass != 0 && (!sameConfigurationFile(pin, after) || !bytes.Equal(previous, content)) {
			return nil, github.ErrInvalidBrokerConfig
		}
		previous, pin = content, after
	}
	if ctx.Err() != nil {
		return nil, github.ErrBrokerUnavailable
	}
	return previous, nil
}

type brokerDescriptor struct {
	Contract                string   `json:"contract"`
	SchemaVersion           uint64   `json:"schema_version"`
	TenantID                string   `json:"tenant_id"`
	RepositoryID            string   `json:"repository_id"`
	RepositoryFullName      string   `json:"repository_full_name"`
	GitHubRepositoryID      uint64   `json:"github_repository_id"`
	InstallationID          uint64   `json:"installation_id"`
	AppID                   uint64   `json:"app_id"`
	RepositoryAuthority     string   `json:"repository_authority"`
	APIEndpoint             string   `json:"api_endpoint"`
	APIVersion              string   `json:"api_version"`
	ArchiveAuthorities      []string `json:"archive_authorities"`
	AppKeyVersion           string   `json:"app_key_version"`
	AppPublicKeySHA256      string   `json:"app_public_key_sha256"`
	CredentialEnvironment   string   `json:"credential_environment"`
	AuthorizationGeneration string   `json:"authorization_generation"`
	OwnershipMode           string   `json:"ownership_mode"`
	AttemptStateDirectory   string   `json:"attempt_state_directory"`
	AllowTokenCreation      bool     `json:"allow_token_creation"`
	AllowDemandRenewal      bool     `json:"allow_demand_renewal"`
}

func (d brokerDescriptor) String() string             { return "[redacted GitHub broker descriptor]" }
func (d brokerDescriptor) GoString() string           { return d.String() }
func (d brokerDescriptor) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, d.String()) }

func decodeBrokerConfiguration(content []byte) (Configuration, error) {
	if len(content) < 1 || len(content) > maxBrokerConfigurationBytes || !utf8.Valid(content) {
		return Configuration{}, github.ErrInvalidBrokerConfig
	}
	fields := map[string]bool{
		"contract": false, "schema_version": false, "tenant_id": false,
		"repository_id": false, "repository_full_name": false, "github_repository_id": false,
		"installation_id": false, "app_id": false, "repository_authority": false,
		"api_endpoint": false, "api_version": false, "archive_authorities": false,
		"app_key_version": false, "app_public_key_sha256": false, "credential_environment": false,
		"authorization_generation": false, "ownership_mode": false, "attempt_state_directory": false,
		"allow_token_creation": false, "allow_demand_renewal": false,
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return Configuration{}, github.ErrInvalidBrokerConfig
	}
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		seen, known := fields[key]
		if err != nil || !ok || !known || seen {
			return Configuration{}, github.ErrInvalidBrokerConfig
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return Configuration{}, github.ErrInvalidBrokerConfig
		}
		fields[key] = true
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return Configuration{}, github.ErrInvalidBrokerConfig
	}
	var trailing json.RawMessage
	if decoder.Decode(&trailing) != io.EOF {
		return Configuration{}, github.ErrInvalidBrokerConfig
	}
	for _, present := range fields {
		if !present {
			return Configuration{}, github.ErrInvalidBrokerConfig
		}
	}
	var d brokerDescriptor
	if json.Unmarshal(content, &d) != nil || d.Contract != "open-trestle/github-source-broker" || d.SchemaVersion != 1 {
		return Configuration{}, github.ErrInvalidBrokerConfig
	}
	authority, err := github.NewInstallationBrokerAuthority(github.BrokerAuthorityConfig{
		TenantID: d.TenantID, RepositoryID: d.RepositoryID, RepositoryFullName: d.RepositoryFullName,
		GitHubRepositoryID: d.GitHubRepositoryID, InstallationID: d.InstallationID, AppID: d.AppID,
		RepositoryAuthority: d.RepositoryAuthority, APIEndpoint: d.APIEndpoint, APIVersion: d.APIVersion,
		ArchiveAuthorities: d.ArchiveAuthorities, AppKeyVersion: d.AppKeyVersion,
		AppPublicKeySHA256: d.AppPublicKeySHA256, CredentialEnvironment: d.CredentialEnvironment,
		AuthorizationGeneration: d.AuthorizationGeneration, OwnershipMode: d.OwnershipMode,
		AttemptStateDirectory: d.AttemptStateDirectory,
		AllowTokenCreation:    d.AllowTokenCreation, AllowDemandRenewal: d.AllowDemandRenewal,
	})
	if err != nil {
		return Configuration{}, github.ErrInvalidBrokerConfig
	}
	c := Configuration{authority: authority, snapshot: sha256.Sum256(content)}
	if c.Validate() != nil {
		return Configuration{}, github.ErrInvalidBrokerConfig
	}
	return c, nil
}
