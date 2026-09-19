package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
)

type publicationCredentials struct {
	token         Token
	scope, target string
	calls         int
}

func (p *publicationCredentials) RetrievePublicationToken(_ context.Context, scope audit.ReviewScope, target review.PublicationTarget) (Token, error) {
	p.calls++
	p.scope = scope.Identity()
	p.target = target.Identity()
	return p.token, nil
}

type publicationGuard struct {
	mu               sync.Mutex
	claimed          map[string]string
	completed        map[string]string
	scope, operation string
	calls            int
}

func (g *publicationGuard) Identity() string { return strings.Repeat("f", 64) }
func (g *publicationGuard) IdempotencyGuarantee() review.PublisherIdempotencyGuarantee {
	return review.PublisherExactOperationKey
}
func (g *publicationGuard) ClaimPublicationAttempt(_ context.Context, scope audit.ReviewScope, operation, attempt, request string, _ time.Time) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	g.scope, g.operation = scope.Identity(), operation
	if prior, ok := g.claimed[attempt]; ok {
		return false, func() error {
			if prior != request {
				return review.ErrPublicationAttemptGuardConflict
			}
			return nil
		}()
	}
	g.claimed[attempt] = request
	return true, nil
}
func (g *publicationGuard) CompletePublicationAttempt(_ context.Context, _ audit.ReviewScope, attempt, result string, _ time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.completed[attempt] = result
	return nil
}

type publicationFixedClock struct{ at time.Time }

func (c publicationFixedClock) Now() time.Time { return c.at }
func githubPublicationTarget(t *testing.T) (audit.ReviewScope, review.PublicationTarget) {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant", "repository", "run")
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"octocat"}, "hello-world")
	head, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	target, err := review.NewPublicationTarget("github-review-v1", repository, "12", head)
	if err != nil {
		t.Fatal(err)
	}
	return scope, target
}
func TestPublicationAdapterResolvesHead(t *testing.T) {
	scope, target := githubPublicationTarget(t)
	var mu sync.Mutex
	gets := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("X-GitHub-Api-Version") != defaultAPIVersion {
			t.Errorf("headers=%v", r.Header)
		}
		if r.Method != http.MethodGet || r.URL.Path != "/repos/octocat/hello-world/pulls/12" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		gets++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"head":{"sha":"%s"}}`, strings.Repeat("a", 40))
	}))
	defer server.Close()
	token, _ := NewToken([]byte("test-token"))
	credentials := &publicationCredentials{token: token}
	guard := &publicationGuard{claimed: map[string]string{}, completed: map[string]string{}}
	adapter, err := NewPublicationAdapter(PublicationConfig{PublisherID: "github-review-v1", RepositoryAuthority: "github.com", APIEndpoint: server.URL, Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64), AttemptGuard: guard, HTTPClient: server.Client(), HTTPClientIdentity: strings.Repeat("b", 64), Clock: publicationFixedClock{time.UnixMilli(100)}, ClockIdentity: strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	head := adapter.resolveTargetHead(context.Background(), scope, target)
	if head.Status() != review.PublicationHeadResolved || head.CurrentHead().Identity() != target.HeadRevision().Identity() {
		t.Fatalf("head=%#v", head)
	}
	mu.Lock()
	defer mu.Unlock()
	if gets != 1 || credentials.calls != 1 || guard.calls != 0 || credentials.scope != scope.Identity() || credentials.target != target.Identity() {
		t.Fatalf("calls=%d/%d/%d", gets, credentials.calls, guard.calls)
	}
	if fmt.Sprintf("%#v", adapter) != "github.PublicationAdapter{<redacted>}" {
		t.Fatal("format")
	}
}
func TestPublicationMarkdownEscapesUntrustedEffects(t *testing.T) {
	value := escapeMarkdown("@maintainer ![image](https://example.invalid/x) <details> *bold*")
	for _, unsafe := range []string{"@maintainer", "![image]", "<details>", "*bold*"} {
		if strings.Contains(value, unsafe) {
			t.Fatalf("unsafe %q in %q", unsafe, value)
		}
	}
}
func decodeJSONReader(reader io.Reader, target any) error {
	content, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	return json.Unmarshal(content, target)
}

func TestStaticPublicationTokenProviderRequiresExactScopeAndTarget(t *testing.T) {
	scope, target := githubPublicationTarget(t)
	token, _ := NewToken([]byte("test-token"))
	provider, err := NewStaticPublicationTokenProvider([]ScopedPublicationToken{{Scope: scope, TargetIdentity: target.Identity(), Token: token}})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := provider.RetrievePublicationToken(context.Background(), scope, target)
	if err != nil || loaded.value != "test-token" {
		t.Fatalf("loaded=(%v,%v)", loaded, err)
	}
	other, _ := audit.NewReviewScope("tenant", "repository", "other")
	if _, err := provider.RetrievePublicationToken(context.Background(), other, target); !errors.Is(err, ErrPublicationCredentialsUnavailable) {
		t.Fatalf("cross scope=%v", err)
	}
	if strings.Contains(fmt.Sprintf("%#v", provider), "test-token") {
		t.Fatal("credential leaked")
	}
}

func TestPublicationAdapterConfigurationIdentityBindsConnectionAuthority(t *testing.T) {
	token, _ := NewToken([]byte("test-token"))
	credentials := &publicationCredentials{token: token}
	newAdapter := func(endpoint, credential string) *PublicationAdapter {
		guard := &publicationGuard{claimed: map[string]string{}, completed: map[string]string{}}
		adapter, err := NewPublicationAdapter(PublicationConfig{PublisherID: "github-review-v1", RepositoryAuthority: "github.com", APIEndpoint: endpoint, Credentials: credentials, CredentialIdentity: credential, AttemptGuard: guard})
		if err != nil {
			t.Fatal(err)
		}
		return adapter
	}
	first := newAdapter("https://api.github.com", strings.Repeat("a", 64))
	second := newAdapter("https://github.example.test", strings.Repeat("a", 64))
	third := newAdapter("https://api.github.com", strings.Repeat("b", 64))
	if first.ConfigurationIdentity() == second.ConfigurationIdentity() || first.ConfigurationIdentity() == third.ConfigurationIdentity() {
		t.Fatal("publication connection authority omitted from configuration identity")
	}
	guard := &publicationGuard{claimed: map[string]string{}, completed: map[string]string{}}
	if adapter, err := NewPublicationAdapter(PublicationConfig{PublisherID: "github-review-v1", RepositoryAuthority: "github.com", Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64), AttemptGuard: guard, HTTPClient: &http.Client{Timeout: time.Second}}); !errors.Is(err, ErrInvalidPublicationConfig) || adapter != nil {
		t.Fatalf("unidentified custom client=(%#v,%v)", adapter, err)
	}
}
