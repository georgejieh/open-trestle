// Package auth checks API credentials.
package auth

import (
	"net/http"
	"strings"
)

// Authenticator accepts requests that carry one shared bearer token.
type Authenticator struct {
	token string
}

// New returns an Authenticator for token. An empty token accepts no request.
func New(token string) *Authenticator {
	return &Authenticator{token: token}
}

// Authorized reports whether r carries the configured bearer token.
func (a *Authenticator) Authorized(r *http.Request) bool {
	if a.token == "" {
		return false
	}
	presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	return presented == a.token
}
