package main

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"

	githubsource "github.com/georgejieh/open-trestle/adapters/scm/github"
	"github.com/georgejieh/open-trestle/artifact"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/githubruntime"
)

type githubSourceConfiguration struct {
	broker                                                        githubruntime.Configuration
	brokerConfigured                                              bool
	expectedAuthority, tenantID, repositoryID, repositoryFullName string
	staticToken                                                   string
}

type githubSourceRuntime struct {
	adapter     *githubsource.Adapter
	handler     *sourcehandler.Handler
	credentials *githubruntime.Runtime
}

func loadGitHubSourceConfiguration(ctx context.Context,
	brokerConfigPath, staticToken, tenantID, repositoryID, repositoryFullName,
	expectedAuthority string, localWorkers bool) (githubSourceConfiguration, error) {
	if ctx == nil {
		return githubSourceConfiguration{}, ErrInvalidDaemonConfiguration
	}
	if err := ctx.Err(); err != nil {
		return githubSourceConfiguration{}, err
	}
	configuration := githubSourceConfiguration{
		expectedAuthority: strings.Clone(expectedAuthority), tenantID: strings.Clone(tenantID),
		repositoryID: strings.Clone(repositoryID), repositoryFullName: strings.Clone(repositoryFullName),
		staticToken: strings.Clone(staticToken),
	}
	if brokerConfigPath == "" {
		if expectedAuthority != "" || staticToken != "" && !localWorkers {
			return githubSourceConfiguration{}, ErrInvalidDaemonConfiguration
		}
		return configuration, nil
	}
	if !localWorkers || staticToken != "" || !daemonNonzeroDigest(expectedAuthority) {
		return githubSourceConfiguration{}, ErrInvalidDaemonConfiguration
	}
	broker, err := githubruntime.LoadConfig(ctx, brokerConfigPath)
	if err != nil || broker.Validate() != nil || broker.AuthorityIdentity() != expectedAuthority {
		return githubSourceConfiguration{}, ErrInvalidDaemonConfiguration
	}
	authority := broker.Authority().Configuration()
	if authority.TenantID != tenantID || authority.RepositoryID != repositoryID || authority.RepositoryFullName != repositoryFullName || authority.RepositoryAuthority != "github.com" {
		return githubSourceConfiguration{}, ErrInvalidDaemonConfiguration
	}
	if err := ctx.Err(); err != nil {
		return githubSourceConfiguration{}, err
	}
	configuration.broker = broker
	configuration.brokerConfigured = true
	return configuration, nil
}

func buildGitHubSource(ctx context.Context, c githubSourceConfiguration,
	getenv func(string) string, store artifact.Store,
	clock githubsource.BrokerClock) (*githubSourceRuntime, error) {
	if getenv == nil {
		return nil, ErrInvalidDaemonConfiguration
	}
	for _, dependency := range []any{ctx, store, clock} {
		if dependency == nil {
			return nil, ErrInvalidDaemonConfiguration
		}
		value := reflect.ValueOf(dependency)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if value.IsNil() {
				return nil, ErrInvalidDaemonConfiguration
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	configuration := githubsource.Config{RepositoryAuthority: "github.com", ArchiveAuthorities: []string{"codeload.github.com"}}
	source := &githubSourceRuntime{}
	built := false
	defer func() {
		if !built {
			_ = source.Close()
		}
	}()
	if c.brokerConfigured {
		if c.staticToken != "" || c.broker.Validate() != nil || c.broker.AuthorityIdentity() != c.expectedAuthority {
			return nil, ErrInvalidDaemonConfiguration
		}
		authority := c.broker.Authority().Configuration()
		if authority.TenantID != c.tenantID || authority.RepositoryID != c.repositoryID || authority.RepositoryFullName != c.repositoryFullName || authority.RepositoryAuthority != "github.com" {
			return nil, ErrInvalidDaemonConfiguration
		}
		credentials, err := githubruntime.Open(ctx, c.broker, c.expectedAuthority, githubsource.IssuancePurposeRuntime, getenv, clock)
		if err != nil {
			return nil, err
		}
		source.credentials = credentials
		configuration.APIEndpoint = authority.APIEndpoint
		configuration.APIVersion = authority.APIVersion
		configuration.ArchiveAuthorities = authority.ArchiveAuthorities
		configuration.InstallationBroker = credentials.Broker()
		if configuration.InstallationBroker == nil {
			return nil, githubsource.ErrBrokerClosed
		}
	} else {
		if c.expectedAuthority != "" {
			return nil, ErrInvalidDaemonConfiguration
		}
		if c.staticToken != "" {
			token, err := githubsource.NewToken([]byte(c.staticToken))
			if err != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			configuration.Credentials = staticGitHubTokenProvider{token: token}
		}
	}
	adapter, err := githubsource.New(configuration)
	if err != nil {
		return nil, ErrInvalidDaemonConfiguration
	}
	handler, err := sourcehandler.NewHandler(store, adapter, clock)
	if err != nil {
		return nil, ErrInvalidDaemonConfiguration
	}
	source.adapter, source.handler = adapter, handler
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	built = true
	return source, nil
}

func (r *githubSourceRuntime) Close() error {
	if r == nil || r.credentials == nil {
		return nil
	}
	return r.credentials.Close()
}

func (c githubSourceConfiguration) String() string { return "GitHub source configuration" }
func (c githubSourceConfiguration) GoString() string {
	return "main.githubSourceConfiguration{<redacted>}"
}
func (c githubSourceConfiguration) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "GitHub source configuration")
}
func (r githubSourceRuntime) String() string   { return "GitHub source runtime" }
func (r githubSourceRuntime) GoString() string { return "main.githubSourceRuntime{<redacted>}" }
func (r githubSourceRuntime) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "GitHub source runtime")
}
