package github

import (
	"context"
	"errors"
	"fmt"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/review"
)

var ErrInvalidPublicationTokenProvider = errors.New("invalid GitHub publication token provider")

type ScopedPublicationToken struct {
	Scope          audit.ReviewScope
	TargetIdentity string
	Token          Token
}
type StaticPublicationTokenProvider struct{ tokens map[string]Token }

func NewStaticPublicationTokenProvider(entries []ScopedPublicationToken) (*StaticPublicationTokenProvider, error) {
	if len(entries) == 0 || len(entries) > 256 {
		return nil, ErrInvalidPublicationTokenProvider
	}
	provider := &StaticPublicationTokenProvider{tokens: make(map[string]Token, len(entries))}
	for _, entry := range entries {
		if entry.Scope.Validate() != nil || !validDigest(entry.TargetIdentity) || entry.Token.Validate() != nil {
			return nil, ErrInvalidPublicationTokenProvider
		}
		key := publicationTokenKey(entry.Scope.Identity(), entry.TargetIdentity)
		if _, exists := provider.tokens[key]; exists {
			return nil, ErrInvalidPublicationTokenProvider
		}
		provider.tokens[key] = entry.Token
	}
	return provider, nil
}
func (p *StaticPublicationTokenProvider) RetrievePublicationToken(ctx context.Context, scope audit.ReviewScope, target review.PublicationTarget) (Token, error) {
	if ctx == nil || ctx.Err() != nil || p == nil || scope.Validate() != nil || target.Validate() != nil {
		return Token{}, ErrPublicationCredentialsUnavailable
	}
	token, ok := p.tokens[publicationTokenKey(scope.Identity(), target.Identity())]
	if !ok || token.Validate() != nil {
		return Token{}, ErrPublicationCredentialsUnavailable
	}
	return token, nil
}
func publicationTokenKey(scope, target string) string    { return scope + "\x00" + target }
func (p *StaticPublicationTokenProvider) String() string { return "GitHub publication token provider" }
func (p *StaticPublicationTokenProvider) GoString() string {
	return "github.StaticPublicationTokenProvider{<redacted>}"
}
func (p *StaticPublicationTokenProvider) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "GitHub publication token provider", "github.StaticPublicationTokenProvider{<redacted>}")
}

var _ PublicationTokenProvider = (*StaticPublicationTokenProvider)(nil)
