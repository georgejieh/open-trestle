package runtimecatalog

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
)

// EnvironmentOpenAICredentialResolver creates request-time providers without reading credential values.
type EnvironmentOpenAICredentialResolver struct{ environment func(string) string }

// NewEnvironmentOpenAICredentialResolver binds one environment reader without accessing it.
func NewEnvironmentOpenAICredentialResolver(environment func(string) string) (EnvironmentOpenAICredentialResolver, error) {
	if environment == nil {
		return EnvironmentOpenAICredentialResolver{}, ErrInvalidRouteAuthority
	}
	return EnvironmentOpenAICredentialResolver{environment}, nil
}
func (r EnvironmentOpenAICredentialResolver) ResolveOpenAICredentials(reference string) (openai.APIKeyProvider, error) {
	if r.environment == nil || !validProviderCredentialReference(reference) {
		return nil, ErrInvalidRouteAuthority
	}
	return &environmentOpenAIProvider{strings.Clone(reference), r.environment}, nil
}
func (r EnvironmentOpenAICredentialResolver) String() string {
	return "environment OpenAI credential resolver"
}
func (r EnvironmentOpenAICredentialResolver) GoString() string {
	return "runtimecatalog.EnvironmentOpenAICredentialResolver{<redacted>}"
}
func (r EnvironmentOpenAICredentialResolver) Format(state fmt.State, verb rune) {
	writeRuntimeCatalogFormat(state, verb, r.String(), r.GoString())
}

type environmentOpenAIProvider struct {
	reference   string
	environment func(string) string
}

func (p *environmentOpenAIProvider) Retrieve(ctx context.Context) (openai.APIKey, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || p.environment == nil || !validProviderCredentialReference(p.reference) {
		return openai.APIKey{}, openai.ErrCredentialsUnavailable
	}
	value := p.environment(p.reference)
	if ctx.Err() != nil {
		return openai.APIKey{}, openai.ErrCredentialsUnavailable
	}
	key, err := openai.NewAPIKey([]byte(value))
	if err != nil {
		return openai.APIKey{}, errors.Join(openai.ErrCredentialsUnavailable, err)
	}
	return key, nil
}
func (p *environmentOpenAIProvider) String() string { return "environment OpenAI credential provider" }
func (p *environmentOpenAIProvider) GoString() string {
	return "runtimecatalog.environmentOpenAIProvider{<redacted>}"
}
func (p *environmentOpenAIProvider) Format(state fmt.State, verb rune) {
	writeRuntimeCatalogFormat(state, verb, p.String(), p.GoString())
}
func validProviderCredentialReference(value string) bool {
	if len(value) < 23 || len(value) > 128 || !strings.HasPrefix(value, "OPEN_TRESTLE_PROVIDER_") {
		return false
	}
	for _, r := range value {
		if r != '_' && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
func writeRuntimeCatalogFormat(state fmt.State, verb rune, plain, goValue string) {
	value := plain
	if verb == 'q' {
		value = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		value = goValue
	}
	_, _ = state.Write([]byte(value))
}
