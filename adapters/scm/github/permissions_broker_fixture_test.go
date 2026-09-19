package github

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const permissionBrokerInstallation = `{"id":42,"account":{"login":"Owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"read","pull_requests":"read"},"events":["pull_request"],"suspended_at":null}`
const permissionBrokerAppInstallation = `{"id":42,"app_id":7,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"read","pull_requests":"read"},"events":["pull_request"],"suspended_at":null}`
const permissionBrokerRepositories = `[{"id":99,"full_name":"owner/repo"}]`
const permissionBrokerIssuedToken = "permission-fixture-issued-installation-token"

type permissionBrokerKey struct {
	key *rsa.PrivateKey
	pem []byte
	pin string
}

func permissionBrokerNewKey(t *testing.T) *permissionBrokerKey {
	t.Helper()
	key, encoded, pin := newFixtureAppKey(t)
	return &permissionBrokerKey{key: key, pem: encoded, pin: pin}
}

type permissionBrokerOptions struct {
	basePath     string
	installation string
	pages        []string
	status       int
	headers      map[string]string
	repositories string
	issuedToken  string
}

type permissionBrokerFixture struct {
	key                                                         *permissionBrokerKey
	options                                                     permissionBrokerOptions
	at, expires                                                 time.Time
	server                                                      *httptest.Server
	broker                                                      *InstallationTokenBroker
	inspector                                                   *PermissionInspector
	guard                                                       *permissionBrokerGuard
	mu                                                          sync.Mutex
	events, failures                                            []string
	paths                                                       map[string]int
	headerChecks, userCalls, keyReads, userGETs, appGETs, posts int
}

type permissionBrokerUserProvider struct{ fixture *permissionBrokerFixture }

func (p *permissionBrokerUserProvider) Retrieve(ctx context.Context) (Token, error) {
	f := p.fixture
	f.mu.Lock()
	defer f.mu.Unlock()
	f.userCalls++
	f.events = append(f.events, "user credential")
	if ctx.Err() != nil {
		return Token{}, ctx.Err()
	}
	return NewToken([]byte("github-token"))
}

type permissionBrokerGuard struct {
	fixture                     *permissionBrokerFixture
	authority                   IssuanceAuthority
	reserved, completed         IssuanceAttempt
	disposition                 IssuanceDisposition
	expires                     time.Time
	reserves, completes, closes int
}

func (g *permissionBrokerGuard) AuthorityIdentity() string { return g.authority.Identity() }
func (g *permissionBrokerGuard) Validate() error           { return g.authority.Validate() }
func (g *permissionBrokerGuard) Reserve(ctx context.Context, attempt IssuanceAttempt) (bool, error) {
	f := g.fixture
	f.mu.Lock()
	defer f.mu.Unlock()
	g.reserves++
	f.events = append(f.events, "Reserve")
	if ctx.Err() != nil || g.reserves != 1 || attempt.Validate() != nil || attempt.AuthorityIdentity() != g.authority.Identity() || attempt.Sequence() != 1 {
		f.failures = append(f.failures, "invalid or repeated reservation")
		return false, errors.New("fixture reservation refused")
	}
	g.reserved = attempt
	return true, nil
}

func (g *permissionBrokerGuard) Complete(_ context.Context, attempt IssuanceAttempt, disposition IssuanceDisposition, expires time.Time) error {
	f := g.fixture
	f.mu.Lock()
	defer f.mu.Unlock()
	g.completes++
	g.completed, g.disposition, g.expires = attempt, disposition, expires
	f.events = append(f.events, "Complete")
	// Record any outcome. Rejecting an accepted malformed grant here would mask a parser defect.
	return nil
}

func (g *permissionBrokerGuard) Close() error {
	f := g.fixture
	f.mu.Lock()
	defer f.mu.Unlock()
	g.closes++
	return nil
}

func permissionBrokerNewFixture(t *testing.T, key *permissionBrokerKey, options permissionBrokerOptions) *permissionBrokerFixture {
	t.Helper()
	if options.installation == "" {
		options.installation = permissionBrokerInstallation
	}
	if options.pages == nil {
		options.pages = []string{`{"total_count":1,"installations":[` + options.installation + `]}`}
	}
	if options.status == 0 {
		options.status = http.StatusOK
	}
	if options.repositories == "" {
		options.repositories = permissionBrokerRepositories
	}
	if options.issuedToken == "" {
		options.issuedToken = permissionBrokerIssuedToken
	}
	for _, body := range append(append([]string(nil), options.pages...), options.repositories) {
		if len(body) > 1<<20 {
			t.Fatal("fixture response exceeds one MiB")
		}
	}
	at := time.Now().UTC().Truncate(time.Second)
	f := &permissionBrokerFixture{key: key, options: options, at: at, expires: at.Add(time.Hour), paths: make(map[string]int)}
	f.server = httptest.NewServer(http.HandlerFunc(f.permissionBrokerServeHTTP))
	t.Cleanup(f.server.Close)
	authority := brokerAuthorityFixture(t, f.server.URL+options.basePath, key.pin)
	lane, err := NewIssuanceAuthority(authority, IssuancePurposeSetup)
	if err != nil {
		t.Fatal(err)
	}
	f.guard = &permissionBrokerGuard{fixture: f, authority: lane}
	signer, err := NewAppSigner(authority, func(environment string) string {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.keyReads++
		f.events = append(f.events, "key")
		if environment != "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY" || f.keyReads != 1 {
			f.failures = append(f.failures, "unexpected key read")
			return ""
		}
		return string(key.pem)
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	f.broker, err = NewInstallationTokenBroker(ctx, InstallationBrokerConfig{Authority: authority, IssuanceAuthority: lane, Signer: signer, Guard: f.guard, Clock: fixtureBrokerClock{at: at}})
	if err != nil {
		_ = signer.Close()
		_ = f.guard.Close()
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		err := f.broker.Close()
		cancel()
		f.mu.Lock()
		defer f.mu.Unlock()
		if err != nil || f.guard.closes != 1 || len(f.failures) != 0 {
			t.Errorf("broker cleanup err=%v closes=%d fixture failures=%v", err, f.guard.closes, f.failures)
		}
	})
	f.inspector, err = NewPermissionInspector(PermissionConfig{
		APIEndpoint: f.server.URL + options.basePath, APIVersion: "2026-03-10", InstallationID: 42,
		RepositoryFullName: "owner/repo", UserCredentialIdentity: strings.Repeat("a", 64),
		UserCredentials: &permissionBrokerUserProvider{fixture: f}, RuntimeBroker: f.broker,
		RuntimeCredentials: nil, RuntimeCredentialIdentity: "", Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.events) != 0 || len(f.paths) != 0 || f.userCalls != 0 || f.keyReads != 0 {
		t.Fatal("construction consumed credentials or HTTP")
	}
	return f
}

func (f *permissionBrokerFixture) permissionBrokerServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reject := func(message string) {
		f.failures = append(f.failures, message)
		http.Error(w, "fixture rejected request", http.StatusBadRequest)
	}
	path := r.Method + " " + r.URL.RequestURI()
	f.paths[path]++
	if f.paths[path] != 1 {
		reject("replayed request")
		return
	}
	if len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("X-GitHub-Api-Version")) != 1 || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || r.Header.Get("Accept") != "application/vnd.github+json" {
		reject("missing or wrong authority headers")
		return
	}
	for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Api-Key"} {
		if len(r.Header.Values(name)) != 0 {
			reject("unexpected credential header")
			return
		}
	}
	authorization := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	for name, values := range r.Header {
		for _, value := range values {
			if strings.Contains(value, "-----BEGIN RSA PRIVATE KEY-----") || (!strings.EqualFold(name, "Authorization") && (strings.Contains(value, authorization) || strings.Contains(value, "github-token") || strings.Contains(value, f.options.issuedToken))) {
				reject("credential leaked into an unrelated header")
				return
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == f.options.basePath+"/user/installations" {
		page := f.userGETs + 1
		query := r.URL.Query()
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer github-token" || r.Header.Get("User-Agent") != "open-trestle/setup-permission-inspector" || len(query) != 2 || !reflect.DeepEqual(query["per_page"], []string{"100"}) || !reflect.DeepEqual(query["page"], []string{strconv.Itoa(page)}) || page > len(f.options.pages) || f.keyReads != 0 || f.appGETs != 0 || f.posts != 0 {
			reject("user request authority, page or order mismatch")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			reject("user GET contained a body")
			return
		}
		f.headerChecks++
		f.userGETs++
		f.events = append(f.events, fmt.Sprintf("user GET %d", page))
		for name, value := range f.options.headers {
			w.Header().Set(name, value)
		}
		w.WriteHeader(f.options.status)
		_, _ = io.WriteString(w, f.options.pages[page-1])
		return
	}
	if fixtureAppJWTError(r, &f.key.key.PublicKey, 7, f.at) != nil || r.URL.RawQuery != "" || r.Header.Get("User-Agent") != "open-trestle/github-installation-broker" {
		reject("issuer JWT, query or user agent mismatch")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == f.options.basePath+"/app/installations/42":
		if f.userGETs != len(f.options.pages) || f.keyReads != 1 || f.appGETs != 0 || f.posts != 0 || f.guard.reserves != 0 {
			reject("App GET repeated or reordered")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			reject("App GET contained a body")
			return
		}
		f.headerChecks++
		f.appGETs++
		f.events = append(f.events, "App GET")
		_, _ = io.WriteString(w, permissionBrokerAppInstallation)
	case r.Method == http.MethodPost && r.URL.Path == f.options.basePath+"/app/installations/42/access_tokens":
		if f.appGETs != 1 || f.guard.reserves != 1 || f.posts != 0 || r.Header.Get("Content-Type") != "application/json" {
			reject("POST before reservation or repeated")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		var got map[string]any
		want := map[string]any{"repository_ids": []any{float64(99)}, "permissions": map[string]any{"contents": "read", "metadata": "read", "pull_requests": "read"}}
		if err != nil || len(body) > 4096 || json.Unmarshal(body, &got) != nil || !reflect.DeepEqual(got, want) {
			reject("issuance body not exactly narrowed")
			return
		}
		f.headerChecks++
		f.posts++
		f.events = append(f.events, "issuer POST")
		token, _ := json.Marshal(f.options.issuedToken)
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"token":%s,"expires_at":%q,"permissions":{"metadata":"read","contents":"read","pull_requests":"read"},"repository_selection":"selected","repositories":%s}`, token, f.expires.Format(time.RFC3339), f.options.repositories)
	default:
		reject("unexpected method or route")
	}
}

func (f *permissionBrokerFixture) permissionBrokerAssertEffects(t *testing.T, pages int, issued, accepted bool) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	wantEvents := []string{"user credential"}
	wantPaths := make(map[string]int)
	for page := 1; page <= pages; page++ {
		wantEvents = append(wantEvents, fmt.Sprintf("user GET %d", page))
		wantPaths[fmt.Sprintf("GET %s/user/installations?page=%d&per_page=100", f.options.basePath, page)] = 1
	}
	wantKey, wantRequests := 0, pages
	if issued {
		wantKey = 1
		wantRequests += 2
		wantEvents = append(wantEvents, "key", "App GET", "Reserve", "issuer POST", "Complete")
		wantPaths["GET "+f.options.basePath+"/app/installations/42"] = 1
		wantPaths["POST "+f.options.basePath+"/app/installations/42/access_tokens"] = 1
	}
	if len(f.failures) != 0 || !reflect.DeepEqual(f.events, wantEvents) || !reflect.DeepEqual(f.paths, wantPaths) || f.headerChecks != wantRequests || f.userGETs != pages || f.userCalls != 1 || f.keyReads != wantKey || f.appGETs != wantKey || f.posts != wantKey || f.guard.reserves != wantKey || f.guard.completes != wantKey {
		t.Fatalf("events=%v want=%v paths=%v headers=%d user=%d key=%d GET=%d POST=%d reserve=%d complete=%d failures=%v", f.events, wantEvents, f.paths, f.headerChecks, f.userCalls, f.keyReads, f.appGETs, f.posts, f.guard.reserves, f.guard.completes, f.failures)
	}
	if !issued {
		if f.guard.reserved.Identity() != "" || f.guard.completed.Identity() != "" {
			t.Fatal("visibility failure caused an issuance attempt")
		}
		return
	}
	g := f.guard
	if g.reserved.Validate() != nil || g.completed.Validate() != nil || g.reserved.Identity() != g.completed.Identity() || g.reserved.AuthorityIdentity() != g.authority.Identity() || g.completed.AuthorityIdentity() != g.authority.Identity() || g.reserved.Sequence() != 1 || !g.reserved.StartedAt().Equal(f.at) || !g.completed.StartedAt().Equal(f.at) {
		t.Fatal("guard did not record the exact broker-created setup attempt")
	}
	if accepted {
		if g.disposition != IssuanceAccepted || !g.expires.Equal(f.expires) {
			t.Fatal("valid actual grant was not completed with returned expiry")
		}
	} else if g.disposition != IssuanceUnknown || !g.expires.IsZero() {
		t.Fatal("invalid HTTP 201 grant was accepted or not fenced as unknown")
	}
}
