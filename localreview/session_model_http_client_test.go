package localreview

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// The optional policy-approved transport must never replace the numeric-loopback
// local-only client, so supplying it with local-only egress refuses construction.
func TestSessionRefusesModelHTTPClientWithLocalOnlyEgress(t *testing.T) {
	f := newRmModelFixture(t, rmModelFixtureOptions{})
	for _, test := range []struct {
		name     string
		client   *http.Client
		identity string
	}{
		{"client", &http.Client{}, strings.Repeat("a", 64)},
		{"identity only", nil, strings.Repeat("a", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := rmOptions(t, f, rmNewClock())
			o.ModelHTTPClient, o.ModelHTTPClientIdentity = test.client, test.identity
			if session, err := NewSession(o); session != nil || !errors.Is(err, ErrInvalidSession) {
				t.Fatal("local-only session accepted a replacement model transport")
			}
		})
	}
}
