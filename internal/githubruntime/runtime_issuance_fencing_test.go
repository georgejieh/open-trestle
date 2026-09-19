//go:build unix

package githubruntime

import (
	"bytes"
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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	github "github.com/georgejieh/open-trestle/adapters/scm/github"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

const (
	guardBoundaryUserToken     = "fixture-guard-user-token"
	guardBoundaryIssuedToken   = "fixture-guard-issued-installation-token"
	guardBoundaryInvalidMarker = "not a valid owner record\n"
)

type guardBoundaryClock struct{ at time.Time }

func (c guardBoundaryClock) Now() time.Time { return c.at }

type guardBoundaryCounts struct {
	keyReads, userReads, requests, userGETs, issuerGETs, posts int
	accepted, dropped, mutated, failures                       int
}

type guardBoundaryFixture struct {
	key                     *rsa.PrivateKey
	encoded, pin            string
	at                      time.Time
	server                  *httptest.Server
	mu                      sync.Mutex
	counts                  guardBoundaryCounts
	failures                []string
	jwts                    []string
	directory, marker, mode string
}

type guardBoundaryUserProvider struct{ fixture *guardBoundaryFixture }

func (p *guardBoundaryUserProvider) Retrieve(ctx context.Context) (github.Token, error) {
	p.fixture.mu.Lock()
	p.fixture.counts.userReads++
	p.fixture.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return github.Token{}, err
	}
	return github.NewToken([]byte(guardBoundaryUserToken))
}

func guardBoundaryKey(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("synthetic RSA generation failed")
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal("synthetic public key encoding failed")
	}
	pin := sha256.Sum256(public)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, string(encoded), hex.EncodeToString(pin[:])
}

func guardBoundaryNewFixture(t *testing.T, key *rsa.PrivateKey, encoded, pin, mode string) *guardBoundaryFixture {
	t.Helper()
	f := &guardBoundaryFixture{key: key, encoded: encoded, pin: pin, mode: mode, at: time.Now().UTC().Truncate(time.Second)}
	f.server = httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)
	endpoint, err := url.Parse(f.server.URL)
	if err != nil || net.ParseIP(endpoint.Hostname()) == nil || !net.ParseIP(endpoint.Hostname()).IsLoopback() {
		t.Fatal("fixture must use numeric loopback")
	}
	return f
}

func (f *guardBoundaryFixture) getenv(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts.keyReads++
	if name != "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY" {
		f.failures = append(f.failures, "unexpected environment name")
		f.counts.failures++
		return ""
	}
	return f.encoded
}

func (f *guardBoundaryFixture) snapshot(t *testing.T) guardBoundaryCounts {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.failures) != 0 {
		t.Errorf("fixture protocol failures: %v", f.failures)
	}
	return f.counts
}

func guardBoundaryJWT(r *http.Request, key *rsa.PublicKey, at time.Time) bool {
	if len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
	if len(parts) != 3 {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	var h map[string]any
	if json.Unmarshal(header, &h) != nil || !reflect.DeepEqual(h, map[string]any{"alg": "RS256", "typ": "JWT"}) {
		return false
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil || len(claims) != 3 {
		return false
	}
	var issuer string
	var iat, exp int64
	if json.Unmarshal(claims["iss"], &issuer) != nil || issuer != "7" || json.Unmarshal(claims["iat"], &iat) != nil || iat != at.Unix()-60 || json.Unmarshal(claims["exp"], &exp) != nil || exp != at.Unix()+300 {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil
}

func (f *guardBoundaryFixture) headersSeparated(r *http.Request, user bool) bool {
	for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Api-Key"} {
		if len(r.Header.Values(name)) != 0 {
			return false
		}
	}
	if len(r.Header.Values("Authorization")) != 1 || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || r.Header.Get("Accept") != "application/vnd.github+json" {
		return false
	}
	if user && r.Header.Get("Authorization") != "Bearer "+guardBoundaryUserToken {
		return false
	}
	if !user && !guardBoundaryJWT(r, &f.key.PublicKey, f.at) {
		return false
	}
	current := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	for name, values := range r.Header {
		for _, value := range values {
			if strings.Contains(value, guardBoundaryIssuedToken) || strings.Contains(value, "-----BEGIN") || strings.Contains(value, f.encoded) {
				return false
			}
			if strings.Contains(value, guardBoundaryUserToken) && !(user && strings.EqualFold(name, "Authorization")) {
				return false
			}
			if !strings.EqualFold(name, "Authorization") && strings.Contains(value, current) {
				return false
			}
			for _, jwt := range f.jwts {
				if strings.Contains(value, jwt) && (user || !strings.EqualFold(name, "Authorization")) {
					return false
				}
			}
		}
	}
	return true
}

func (f *guardBoundaryFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts.requests++
	if r.Method == http.MethodPost {
		f.counts.posts++
	}
	reject := func(reason string) {
		f.failures = append(f.failures, reason)
		f.counts.failures++
		http.Error(w, "fixture rejected request", http.StatusBadRequest)
	}
	user := r.Method == http.MethodGet && r.URL.Path == "/api/v3/user/installations"
	if !f.headersSeparated(r, user) {
		reject("credential headers or JWT mismatch")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	installation := `{"id":42,"app_id":7,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"read","pull_requests":"read"},"events":["pull_request"],"suspended_at":null}`
	if user {
		f.counts.userGETs++
		if r.URL.Query().Encode() != "page=1&per_page=100" {
			reject("unexpected user pagination")
			return
		}
		visible := strings.Replace(installation, `,"app_id":7`, "", 1)
		_, _ = io.WriteString(w, `{"total_count":1,"installations":[`+visible+`]}`)
		return
	}
	f.jwts = append(f.jwts, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if r.URL.RawQuery != "" {
		reject("unexpected issuer query")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v3/app/installations/42":
		f.counts.issuerGETs++
		if f.counts.issuerGETs != 1 || f.counts.posts != 0 || f.counts.userGETs < 1 {
			reject("repeated or reordered issuer GET")
			return
		}
		_, _ = io.WriteString(w, installation)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v3/app/installations/42/access_tokens":
		if f.counts.posts != 1 || f.counts.issuerGETs != 1 || r.Header.Get("Content-Type") != "application/json" {
			reject("repeated or reordered issuer POST")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		var got map[string]any
		want := map[string]any{"repository_ids": []any{float64(99)}, "permissions": map[string]any{"contents": "read", "metadata": "read", "pull_requests": "read"}}
		if err != nil || len(body) > 4096 || json.Unmarshal(body, &got) != nil || !reflect.DeepEqual(got, want) {
			reject("issuance body not exactly narrowed")
			return
		}
		records, err := guardBoundaryReadRecords(f.directory)
		if err != nil || len(records) != 2 || len(records[f.marker]) == 0 {
			reject("POST arrived without owner and separate durable reservation")
			return
		}
		f.counts.accepted++
		if f.mode == "drop-response" {
			hijacker, ok := w.(http.Hijacker)
			if !ok || r.ProtoMajor != 1 {
				reject("HTTP/1 hijacking unavailable")
				return
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				reject("HTTP/1 hijack failed")
				return
			}
			if err := connection.Close(); err != nil {
				f.failures = append(f.failures, "hijacked connection close failed")
				f.counts.failures++
				return
			}
			f.counts.dropped++
			return
		}
		if f.mode == "mutate-owner-before-201" {
			if guardBoundaryCorruptMarker(filepath.Join(f.directory, f.marker)) != nil {
				reject("fixture owner mutation failed")
				return
			}
			f.counts.mutated++
		}
		w.WriteHeader(http.StatusCreated)
		if json.NewEncoder(w).Encode(map[string]any{"token": guardBoundaryIssuedToken, "expires_at": f.at.Add(time.Hour).Format(time.RFC3339), "repository_selection": "selected", "permissions": want["permissions"], "repositories": []any{map[string]any{"id": 99, "full_name": "owner/repo"}}}) != nil {
			f.failures = append(f.failures, "valid grant response write failed")
			f.counts.failures++
		}
	default:
		reject("unexpected route or method")
	}
}

func guardBoundaryLoad(t *testing.T, ctx context.Context, directory string, f *guardBoundaryFixture) Configuration {
	t.Helper()
	if fileauthority.CheckDirectory(directory) != nil {
		t.Fatal("unsafe native temporary root; use a trusted test environment")
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatal("fixture root must be protected 0700")
	}
	attempts := filepath.Join(directory, "attempts")
	if os.Mkdir(attempts, 0o700) != nil || fileauthority.CheckDirectory(attempts) != nil {
		t.Fatal("protected attempts directory failed")
	}
	info, err = os.Lstat(attempts)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatal("attempts directory must be protected 0700")
	}
	endpoint, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal("fixture endpoint failed")
	}
	descriptor := map[string]any{
		"contract": "open-trestle/github-source-broker", "schema_version": 1,
		"tenant_id": "tenant-a", "repository_id": "repo-a", "repository_full_name": "owner/repo", "github_repository_id": 99,
		"repository_authority": "github.com", "api_endpoint": f.server.URL + "/api/v3", "api_version": "2026-03-10", "archive_authorities": []string{endpoint.Host},
		"installation_id": 42, "app_id": 7, "app_key_version": "fixture-key-1", "app_public_key_sha256": f.pin,
		"credential_environment": "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY", "authorization_generation": strings.Repeat("d", 64),
		"ownership_mode": "single_host_exclusive", "attempt_state_directory": attempts,
		"allow_token_creation": true, "allow_demand_renewal": true,
	}
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal("fixture descriptor encoding failed")
	}
	path := filepath.Join(directory, "broker.json")
	if os.WriteFile(path, encoded, 0o600) != nil {
		t.Fatal("fixture descriptor write failed")
	}
	info, err = os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("fixture descriptor must be 0600")
	}
	configuration, err := LoadConfig(ctx, path)
	if err != nil || configuration.Validate() != nil || configuration.AuthorityIdentity() == "" || configuration.Authority().Identity() != configuration.AuthorityIdentity() {
		t.Fatal("real protected configuration load failed")
	}
	if entries, err := os.ReadDir(attempts); err != nil || len(entries) != 0 {
		t.Fatal("configuration load created guard records")
	}
	f.mu.Lock()
	f.directory = attempts
	f.mu.Unlock()
	return configuration
}

func guardBoundaryOpen(t *testing.T, ctx context.Context, configuration Configuration, f *guardBoundaryFixture) *Runtime {
	t.Helper()
	runtime, err := Open(ctx, configuration, configuration.AuthorityIdentity(), github.IssuancePurposeSetup, f.getenv, guardBoundaryClock{f.at})
	if runtime != nil {
		t.Cleanup(func() { guardBoundaryClose(t, runtime, f.mode == "mutate-owner-before-201") })
	}
	if err != nil || runtime == nil || runtime.Broker() == nil || runtime.Broker().Validate() != nil {
		t.Fatal("real setup runtime construction failed")
	}
	if runtime.Broker().AuthorityIdentity() != configuration.AuthorityIdentity() || runtime.Broker().Purpose() != github.IssuancePurposeSetup {
		t.Fatal("real runtime authority mismatch")
	}
	counts := f.snapshot(t)
	if counts != (guardBoundaryCounts{}) {
		t.Fatal("runtime construction performed credential or HTTP effects")
	}
	records := guardBoundaryRecords(t, f)
	if len(records) != 1 {
		t.Fatal("real Open did not create exactly one owner marker")
	}
	for name := range records {
		f.mu.Lock()
		f.marker = name
		f.mu.Unlock()
	}
	return runtime
}

func guardBoundaryInspector(t *testing.T, configuration Configuration, runtime *Runtime, f *guardBoundaryFixture) *github.PermissionInspector {
	t.Helper()
	bound := configuration.Authority().Configuration()
	inspector, err := github.NewPermissionInspector(github.PermissionConfig{
		APIEndpoint: bound.APIEndpoint, APIVersion: bound.APIVersion, InstallationID: bound.InstallationID,
		RepositoryFullName: bound.RepositoryFullName, UserCredentialIdentity: strings.Repeat("a", 64),
		UserCredentials: &guardBoundaryUserProvider{f}, RuntimeBroker: runtime.Broker(), Timeout: 5 * time.Second,
	})
	expected, authorityErr := github.BrokeredPermissionAuthorityIdentity(configuration.Authority(), strings.Repeat("a", 64), 5*time.Second)
	if err != nil || authorityErr != nil || inspector == nil || inspector.Validate() != nil || inspector.AuthorityIdentity() != expected {
		t.Fatal("real permission inspector construction failed")
	}
	if f.snapshot(t) != (guardBoundaryCounts{}) {
		t.Fatal("inspector construction performed credential or HTTP effects")
	}
	return inspector
}

func guardBoundaryReadRecords(directory string) (map[string][]byte, error) {
	if fileauthority.CheckDirectory(directory) != nil {
		return nil, errors.New("untrusted fixture guard directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) > 513 {
		return nil, errors.New("invalid fixture guard record count")
	}
	records := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		file, err := fileauthority.OpenReadOnly(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, errors.New("untrusted fixture guard record")
		}
		info, statErr := file.Stat()
		content, readErr := io.ReadAll(io.LimitReader(file, 4097))
		closeErr := file.Close()
		if statErr != nil || readErr != nil || closeErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || len(content) < 1 || len(content) > 4096 {
			return nil, errors.New("invalid fixture guard record metadata")
		}
		records[entry.Name()] = content
	}
	return records, nil
}

func guardBoundaryRecords(t *testing.T, f *guardBoundaryFixture) map[string][]byte {
	t.Helper()
	f.mu.Lock()
	directory := f.directory
	secrets := append([]string{guardBoundaryUserToken, guardBoundaryIssuedToken, "-----BEGIN", f.encoded}, f.jwts...)
	f.mu.Unlock()
	records, err := guardBoundaryReadRecords(directory)
	if err != nil {
		t.Fatal("protected guard record inspection failed")
	}
	for name, content := range records {
		for _, secret := range secrets {
			if strings.Contains(name, secret) || bytes.Contains(content, []byte(secret)) {
				t.Fatal("guard record leaked a credential")
			}
		}
	}
	return records
}

func guardBoundaryCorruptMarker(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, writeErr := io.WriteString(file, guardBoundaryInvalidMarker)
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(writeErr, syncErr, closeErr)
}

func guardBoundaryClose(t *testing.T, runtime *Runtime, allowIncomplete bool) {
	t.Helper()
	err := runtime.Close()
	if err != nil && !(allowIncomplete && errors.Is(err, github.ErrBrokerCloseIncomplete)) {
		t.Error("runtime cleanup failed")
	}
	if runtime.Broker() != nil {
		t.Error("closed runtime still exposes broker")
	}
	if !errors.Is(runtime.Close(), err) {
		t.Error("repeated Close changed terminal result")
	}
}

func guardBoundaryRefuseOpen(t *testing.T, ctx context.Context, configuration Configuration, f *guardBoundaryFixture) {
	t.Helper()
	before := f.snapshot(t)
	records := guardBoundaryRecords(t, f)
	runtime, err := Open(ctx, configuration, configuration.AuthorityIdentity(), github.IssuancePurposeSetup, f.getenv, guardBoundaryClock{f.at})
	if runtime != nil {
		guardBoundaryClose(t, runtime, f.mode == "mutate-owner-before-201")
	}
	if runtime != nil || !errors.Is(err, github.ErrIssuanceFenced) {
		t.Fatal("same-generation real Open did not refuse with issuance fence")
	}
	if f.snapshot(t) != before {
		t.Fatal("refused Open retrieved credentials or performed HTTP")
	}
	if !reflect.DeepEqual(records, guardBoundaryRecords(t, f)) {
		t.Fatal("failed constructor modified durable markers")
	}
}

func guardBoundarySuccess(t *testing.T, ctx context.Context, inspector *github.PermissionInspector, f *guardBoundaryFixture) {
	t.Helper()
	observation, err := inspector.Inspect(ctx)
	if err != nil || observation.Validate() != nil || observation.Identity() == "" || observation.AuthorityIdentity() != inspector.AuthorityIdentity() {
		t.Fatal("native grant and real guard did not yield valid observation")
	}
	counts := f.snapshot(t)
	if counts.keyReads != 1 || counts.userReads != counts.userGETs || counts.issuerGETs != 1 || counts.posts != 1 || counts.accepted != 1 || counts.failures != 0 || counts.requests != counts.userGETs+2 {
		t.Fatal("native issuance effects mismatch")
	}
	if len(guardBoundaryRecords(t, f)) != 3 {
		t.Fatal("observation preceded separate owner, reservation and completion records")
	}
}

func guardBoundaryFenced(t *testing.T, ctx context.Context, inspector *github.PermissionInspector, f *guardBoundaryFixture) {
	t.Helper()
	observation, err := inspector.Inspect(ctx)
	if !errors.Is(err, github.ErrPermissionMismatch) || !reflect.DeepEqual(observation, github.PermissionObservation{}) || observation.Identity() != "" || observation.AuthorityIdentity() != "" || observation.Validate() == nil {
		t.Fatal("fenced issuance yielded observation or wrong terminal failure")
	}
	f.mu.Lock()
	secrets := append([]string{guardBoundaryUserToken, guardBoundaryIssuedToken, "-----BEGIN", f.encoded}, f.jwts...)
	f.mu.Unlock()
	for _, secret := range secrets {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("terminal error leaked a credential")
		}
	}
}

func TestRuntimeIssuanceFencesDurableOwnerBoundary(t *testing.T) {
	key, encoded, pin := guardBoundaryKey(t)
	for _, name := range []string{"native-success", "simultaneous-owner", "accepted-close-reopen", "malformed-owner", "drop-response", "mutate-owner-before-201"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			t.Cleanup(cancel)
			temporary := t.TempDir()
			if fileauthority.CheckDirectory(temporary) != nil {
				t.Fatal("unsafe native temporary root; use a trusted test environment")
			}
			directory := filepath.Join(temporary, "protected")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal("protected fixture directory creation failed")
			}
			f := guardBoundaryNewFixture(t, key, encoded, pin, name)
			configuration := guardBoundaryLoad(t, ctx, directory, f)
			runtime := guardBoundaryOpen(t, ctx, configuration, f)
			ownerRecords := guardBoundaryRecords(t, f)
			if name == "malformed-owner" {
				guardBoundaryClose(t, runtime, false)
				if !reflect.DeepEqual(ownerRecords, guardBoundaryRecords(t, f)) {
					t.Fatal("Close removed or modified owner marker")
				}
				for marker := range ownerRecords {
					if guardBoundaryCorruptMarker(filepath.Join(configuration.Authority().Configuration().AttemptStateDirectory, marker)) != nil {
						t.Fatal("fixture malformed marker write failed")
					}
				}
				malformed := guardBoundaryRecords(t, f)
				for _, content := range malformed {
					if string(content) != guardBoundaryInvalidMarker {
						t.Fatal("fixture marker is not malformed")
					}
				}
				guardBoundaryRefuseOpen(t, ctx, configuration, f)
				if f.snapshot(t) != (guardBoundaryCounts{}) {
					t.Fatal("malformed marker reached credentials or HTTP")
				}
				return
			}
			inspector := guardBoundaryInspector(t, configuration, runtime, f)
			if name == "simultaneous-owner" {
				guardBoundaryRefuseOpen(t, ctx, configuration, f)
				if runtime.Broker() == nil || runtime.Broker().Validate() != nil {
					t.Fatal("failed contender broke original owner")
				}
			}
			if name == "drop-response" || name == "mutate-owner-before-201" {
				guardBoundaryFenced(t, ctx, inspector, f)
				before := f.snapshot(t)
				if before.keyReads != 1 || before.userReads != 1 || before.userGETs != 1 || before.issuerGETs != 1 || before.posts != 1 || before.accepted != 1 || before.requests != 3 || before.failures != 0 {
					t.Fatal("unknown outcome did not follow one authenticated POST")
				}
				if name == "drop-response" && (before.dropped != 1 || before.mutated != 0) {
					t.Fatal("response was not dropped after acceptance")
				}
				if name == "mutate-owner-before-201" && (before.mutated != 1 || before.dropped != 0) {
					t.Fatal("owner was not mutated before valid 201")
				}
				records := guardBoundaryRecords(t, f)
				if len(records) < 2 {
					t.Fatal("unknown outcome lost durable reservation")
				}
				for marker, original := range ownerRecords {
					want := original
					if name == "mutate-owner-before-201" {
						want = []byte(guardBoundaryInvalidMarker)
					}
					if !bytes.Equal(records[marker], want) {
						t.Fatal("unknown outcome removed or restored owner marker")
					}
				}
				guardBoundaryFenced(t, ctx, inspector, f)
				after := f.snapshot(t)
				if after.posts != 1 || after.issuerGETs != 1 || after.keyReads != 1 || after.accepted != 1 || after.failures != 0 || after.userGETs < before.userGETs || after.userGETs > before.userGETs+1 || after.userReads != after.userGETs || after.requests != after.userGETs+2 {
					t.Fatal("foreground retry repeated issuance or unexpected effects")
				}
				if !reflect.DeepEqual(records, guardBoundaryRecords(t, f)) {
					t.Fatal("foreground retry changed durable fence")
				}
				guardBoundaryClose(t, runtime, name == "mutate-owner-before-201")
				if f.snapshot(t) != after {
					t.Fatal("Close performed credential or HTTP effects")
				}
				if !reflect.DeepEqual(records, guardBoundaryRecords(t, f)) {
					t.Fatal("Close changed unknown-outcome markers")
				}
				guardBoundaryRefuseOpen(t, ctx, configuration, f)
				return
			}
			guardBoundarySuccess(t, ctx, inspector, f)
			if f.snapshot(t).userGETs != 1 {
				t.Fatal("first inspection repeated user visibility GET")
			}
			guardBoundarySuccess(t, ctx, inspector, f)
			if f.snapshot(t).userGETs != 2 {
				t.Fatal("second inspection did not use foreground visibility and cached native grant")
			}
			records := guardBoundaryRecords(t, f)
			for marker, content := range ownerRecords {
				if !bytes.Equal(records[marker], content) {
					t.Fatal("native issuance changed owner marker")
				}
			}
			beforeClose := f.snapshot(t)
			guardBoundaryClose(t, runtime, false)
			if f.snapshot(t) != beforeClose {
				t.Fatal("accepted Close performed credential or HTTP effects")
			}
			if !reflect.DeepEqual(records, guardBoundaryRecords(t, f)) {
				t.Fatal("accepted Close removed or modified durable markers")
			}
			if name == "accepted-close-reopen" {
				guardBoundaryRefuseOpen(t, ctx, configuration, f)
			}
		})
	}
}
