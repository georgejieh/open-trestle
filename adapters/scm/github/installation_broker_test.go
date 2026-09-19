package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

type fixtureBrokerClock struct{ at time.Time }

func (c fixtureBrokerClock) Now() time.Time { return c.at }

type brokerFixtureTrace struct {
	mu       sync.Mutex
	events   []string
	failures []string
	requests []*http.Request
}

type brokerIssuerFixture struct {
	key         *rsa.PrivateKey
	pem         []byte
	pin         string
	at, expires time.Time
	server      *httptest.Server
	trace       *brokerFixtureTrace
}

func newFixtureAppKey(t *testing.T) (*rsa.PrivateKey, []byte, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(public)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, encoded, hex.EncodeToString(digest[:])
}

func newBrokerIssuerFixture(t *testing.T, at time.Time) *brokerIssuerFixture {
	t.Helper()
	key, encoded, pin := newFixtureAppKey(t)
	f := &brokerIssuerFixture{key: key, pem: encoded, pin: pin, at: at, expires: at.Add(time.Hour), trace: &brokerFixtureTrace{}}
	f.server = httptest.NewServer(f)
	t.Cleanup(f.server.Close)
	return f
}

func fixtureAppJWTError(r *http.Request, key *rsa.PublicKey, appID uint64, at time.Time) error {
	denied := errors.New("invalid fixture App JWT")
	if len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return denied
	}
	parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
	if len(parts) != 3 {
		return denied
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return denied
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return denied
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return denied
	}
	var h map[string]any
	if json.Unmarshal(header, &h) != nil || !reflect.DeepEqual(h, map[string]any{"alg": "RS256", "typ": "JWT"}) {
		return denied
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil || len(claims) != 3 {
		return denied
	}
	var issuer string
	var iat, exp int64
	if json.Unmarshal(claims["iss"], &issuer) != nil || issuer != fmt.Sprint(appID) || json.Unmarshal(claims["iat"], &iat) != nil || iat != at.Unix()-60 || json.Unmarshal(claims["exp"], &exp) != nil || exp != at.Unix()+300 {
		return denied
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return denied
	}
	return nil
}

func verifyFixtureAppJWT(t *testing.T, r *http.Request, key *rsa.PublicKey, appID uint64, at time.Time) {
	t.Helper()
	if err := fixtureAppJWTError(r, key, appID, at); err != nil {
		t.Error(err)
	}
}

func (f *brokerIssuerFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.trace.mu.Lock()
	defer f.trace.mu.Unlock()
	f.trace.requests = append(f.trace.requests, r.Clone(context.Background()))
	reject := func(message string) {
		f.trace.failures = append(f.trace.failures, message)
		http.Error(w, "fixture rejected request", http.StatusBadRequest)
	}
	if fixtureAppJWTError(r, &f.key.PublicKey, 7, f.at) != nil || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || r.URL.RawQuery != "" {
		reject("issuer JWT, API version or query mismatch")
		return
	}
	for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Api-Key"} {
		if len(r.Header.Values(name)) != 0 {
			reject("unexpected credential header")
			return
		}
	}
	jwt := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	for name, values := range r.Header {
		for _, value := range values {
			if strings.Contains(value, "fixture-issued-installation-token") || strings.Contains(value, "-----BEGIN RSA PRIVATE KEY-----") || (!strings.EqualFold(name, "Authorization") && strings.Contains(value, jwt)) {
				reject("credential leaked into an unrelated header")
				return
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v3/app/installations/42":
		if len(f.trace.events) != 0 {
			reject("GET repeated or reordered")
			return
		}
		f.trace.events = append(f.trace.events, "GET")
		_, _ = io.WriteString(w, `{"id":42,"app_id":7,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"read","pull_requests":"read"},"events":["pull_request"],"suspended_at":null}`)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v3/app/installations/42/access_tokens":
		if !reflect.DeepEqual(f.trace.events, []string{"GET", "Reserve"}) || r.Header.Get("Content-Type") != "application/json" {
			reject("POST before reservation or repeated")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		var got map[string]any
		want := map[string]any{"repository_ids": []any{float64(99)}, "permissions": map[string]any{"contents": "read", "metadata": "read", "pull_requests": "read"}}
		if err != nil || len(body) > 4096 || json.Unmarshal(body, &got) != nil || !reflect.DeepEqual(got, want) {
			reject("issuance request not exactly narrowed")
			return
		}
		f.trace.events = append(f.trace.events, "POST")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "fixture-issued-installation-token", "expires_at": f.expires.Format(time.RFC3339), "permissions": want["permissions"], "repository_selection": "selected", "repositories": []any{map[string]any{"id": 99, "full_name": "owner/repo"}}})
	default:
		reject("unexpected issuer method or path")
	}
}

func brokerAuthorityFixture(t *testing.T, endpoint, publicKeyDigest string) InstallationBrokerAuthority {
	t.Helper()
	authority, err := NewInstallationBrokerAuthority(BrokerAuthorityConfig{
		TenantID: "tenant-a", RepositoryID: "repo-a", RepositoryFullName: "owner/repo", GitHubRepositoryID: 99, InstallationID: 42, AppID: 7,
		RepositoryAuthority: "github.com", APIEndpoint: endpoint, APIVersion: "2026-03-10", ArchiveAuthorities: []string{"codeload.github.com"},
		AppKeyVersion: "fixture-key-1", AppPublicKeySHA256: publicKeyDigest, CredentialEnvironment: "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY",
		AuthorizationGeneration: strings.Repeat("d", 64), OwnershipMode: "single_host_exclusive", AttemptStateDirectory: filepath.Join(t.TempDir(), "attempts"),
		AllowTokenCreation: true, AllowDemandRenewal: true,
	})
	if err != nil || authority.Validate() != nil {
		t.Fatalf("broker authority: %v", err)
	}
	return authority
}

type memoryIssuanceGuard struct {
	authority   IssuanceAuthority
	trace       *brokerFixtureTrace
	reserved    IssuanceAttempt
	completed   IssuanceAttempt
	disposition IssuanceDisposition
	expires     time.Time
	closes      int
}

func newMemoryIssuanceGuard(authority IssuanceAuthority) *memoryIssuanceGuard {
	return &memoryIssuanceGuard{authority: authority, trace: &brokerFixtureTrace{}}
}
func (g *memoryIssuanceGuard) AuthorityIdentity() string { return g.authority.Identity() }
func (g *memoryIssuanceGuard) Validate() error           { return g.authority.Validate() }
func (g *memoryIssuanceGuard) Reserve(ctx context.Context, attempt IssuanceAttempt) (bool, error) {
	g.trace.mu.Lock()
	defer g.trace.mu.Unlock()
	if ctx.Err() != nil || attempt.Validate() != nil || attempt.AuthorityIdentity() != g.authority.Identity() || attempt.Sequence() != 1 || g.reserved.Identity() != "" || !reflect.DeepEqual(g.trace.events, []string{"GET"}) {
		return false, errors.New("fixture reservation refused")
	}
	g.reserved = attempt
	g.trace.events = append(g.trace.events, "Reserve")
	return true, nil
}
func (g *memoryIssuanceGuard) Complete(ctx context.Context, attempt IssuanceAttempt, disposition IssuanceDisposition, expires time.Time) error {
	g.trace.mu.Lock()
	defer g.trace.mu.Unlock()
	if ctx.Err() != nil || attempt.Validate() != nil || attempt.Identity() != g.reserved.Identity() || attempt.AuthorityIdentity() != g.authority.Identity() || disposition != IssuanceAccepted || expires.IsZero() || g.completed.Identity() != "" || !reflect.DeepEqual(g.trace.events, []string{"GET", "Reserve", "POST"}) {
		return errors.New("fixture completion refused")
	}
	g.completed, g.disposition, g.expires = attempt, disposition, expires
	g.trace.events = append(g.trace.events, "Complete")
	return nil
}
func (g *memoryIssuanceGuard) Close() error {
	g.trace.mu.Lock()
	defer g.trace.mu.Unlock()
	g.closes++
	return nil
}

func TestInstallationBrokerBindsAuthenticatedIssuance(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	f := newBrokerIssuerFixture(t, at)
	for _, wrongPin := range []bool{false, true} {
		name := "success"
		if wrongPin {
			name = "wrong-public-pin"
		}
		t.Run(name, func(t *testing.T) {
			pin := f.pin
			if wrongPin {
				replacement := byte('0')
				if pin[0] == replacement {
					replacement = '1'
				}
				pin = string(replacement) + pin[1:]
			}
			authority := brokerAuthorityFixture(t, f.server.URL+"/api/v3", pin)
			lane, err := NewIssuanceAuthority(authority, IssuancePurposeRuntime)
			if err != nil {
				t.Fatal(err)
			}
			guard := newMemoryIssuanceGuard(lane)
			guard.trace = f.trace
			var keyMu sync.Mutex
			keyReads := 0
			unexpectedRead := false
			signer, err := NewAppSigner(authority, func(environment string) string {
				keyMu.Lock()
				defer keyMu.Unlock()
				keyReads++
				if environment != "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY" {
					unexpectedRead = true
					return ""
				}
				return string(f.pem)
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			f.trace.mu.Lock()
			beforeHTTP := len(f.trace.requests)
			f.trace.mu.Unlock()
			broker, err := NewInstallationTokenBroker(ctx, InstallationBrokerConfig{Authority: authority, IssuanceAuthority: lane, Signer: signer, Guard: guard, Clock: fixtureBrokerClock{at: at}})
			if err != nil {
				_ = signer.Close()
				_ = guard.Close()
				t.Fatalf("broker construction: %v", err)
			}
			t.Cleanup(func() {
				if err := broker.Close(); err != nil {
					t.Errorf("broker close: %v", err)
				}
			})
			if signer.Validate() != nil || broker.Validate() != nil || broker.AuthorityIdentity() != authority.Identity() || broker.IssuanceAuthorityIdentity() != lane.Identity() || broker.Purpose() != IssuancePurposeRuntime || signer.AuthorityIdentity() != authority.Identity() {
				t.Fatal("broker owner authority mismatch")
			}
			keyMu.Lock()
			initialReads := keyReads
			keyMu.Unlock()
			f.trace.mu.Lock()
			constructedHTTP := len(f.trace.requests) - beforeHTTP
			f.trace.mu.Unlock()
			if initialReads != 0 || constructedHTTP != 0 {
				t.Fatal("construction consumed credentials or HTTP")
			}
			repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
			if err != nil {
				t.Fatal(err)
			}
			op, err := broker.beginSource(ctx, repository)
			if err != nil {
				t.Fatal(err)
			}
			defer op.Close()
			keyMu.Lock()
			initialReads = keyReads
			keyMu.Unlock()
			f.trace.mu.Lock()
			constructedHTTP = len(f.trace.requests) - beforeHTTP
			f.trace.mu.Unlock()
			if initialReads != 0 || constructedHTTP != 0 {
				t.Fatal("source admission consumed a credential or performed HTTP")
			}
			lease, err := broker.borrow(op)
			if lease != nil {
				defer lease.release()
			}
			keyMu.Lock()
			loaded := keyReads
			unexpected := unexpectedRead
			keyMu.Unlock()
			f.trace.mu.Lock()
			requests := append([]*http.Request(nil), f.trace.requests[beforeHTTP:]...)
			f.trace.mu.Unlock()
			if wrongPin {
				if lease != nil || !errors.Is(err, ErrBrokerDenied) || len(requests) != 0 || loaded != 1 || unexpected {
					t.Fatal("wrong public pin did not deny before HTTP")
				}
				f.trace.mu.Lock()
				reserved := guard.reserved.Identity()
				completed := guard.completed.Identity()
				f.trace.mu.Unlock()
				if reserved != "" || completed != "" {
					t.Fatal("wrong pin reserved issuance")
				}
				return
			}
			if err != nil || lease == nil {
				t.Fatalf("native issuance did not yield lease: %v", err)
			}
			if lease.validate(at) != nil || loaded != 1 || unexpected || len(requests) != 2 {
				t.Fatal("native lease or lazy key count mismatch")
			}
			f.trace.mu.Lock()
			events := append([]string(nil), f.trace.events...)
			failures := append([]string(nil), f.trace.failures...)
			reserved, completed, disposition, expires := guard.reserved, guard.completed, guard.disposition, guard.expires
			f.trace.events = append(f.trace.events, "usable lease")
			f.trace.mu.Unlock()
			if len(failures) != 0 || !reflect.DeepEqual(events, []string{"GET", "Reserve", "POST", "Complete"}) {
				t.Fatal("issuer and guard effect order mismatch")
			}
			if reserved.Validate() != nil || completed.Validate() != nil || reserved.Identity() != completed.Identity() || reserved.AuthorityIdentity() != lane.Identity() || completed.AuthorityIdentity() != lane.Identity() || reserved.Sequence() != 1 || !reserved.StartedAt().Equal(at) || !completed.StartedAt().Equal(at) || disposition != IssuanceAccepted || !expires.Equal(f.expires) {
				t.Fatal("accepted attempt/lane/expiry did not bind actual response")
			}
			for _, request := range requests {
				verifyFixtureAppJWT(t, request, &f.key.PublicKey, 7, at)
			}
			request, err := http.NewRequestWithContext(op.Context(), http.MethodGet, f.server.URL+"/api/v3/repos/owner/repo/git/commits/"+strings.Repeat("a", 40), nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
			bound, cleanup, err := lease.bindSourceRequest(request)
			if err != nil || bound == nil || cleanup == nil {
				t.Fatalf("native lease source binding: %v", err)
			}
			defer cleanup()
			if bound == request || request.Header.Get("Authorization") != "" || len(bound.Header.Values("Authorization")) != 1 || bound.Header.Get("Authorization") != "Bearer fixture-issued-installation-token" || bound.Method != http.MethodGet || bound.URL.String() != request.URL.String() || bound.Header.Get("X-GitHub-Api-Version") != "2026-03-10" {
				t.Fatal("lease did not bind only the exact source request and issued token")
			}
			deadline, hasDeadline := bound.Context().Deadline()
			callerDeadline, _ := ctx.Deadline()
			if !hasDeadline || !deadline.After(time.Now()) || deadline.After(callerDeadline) || deadline.After(expires.Add(-30*time.Second)) || deadline.After(time.Now().Add(2*time.Minute)) {
				t.Fatal("source request deadline not bounded by caller, source timeout and grant")
			}
			for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Api-Key"} {
				if len(bound.Header.Values(name)) != 0 {
					t.Fatal("unexpected source credential header")
				}
			}
			cleanup()
			if bound.Context().Err() == nil || lease.validate(at) == nil {
				t.Fatal("binding cleanup did not cancel and release the actual lease")
			}
			lease.release()
			op.Close()
			if err := broker.Close(); err != nil {
				t.Fatal(err)
			}
			f.trace.mu.Lock()
			closes := guard.closes
			finalHTTP := len(f.trace.requests) - beforeHTTP
			f.trace.mu.Unlock()
			if closes != 1 || finalHTTP != 2 {
				t.Fatal("owner close repeated a guard effect or HTTP")
			}
		})
	}
}
