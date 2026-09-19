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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const grantValidationInstallation = `{"id":42,"app_id":7,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"read","pull_requests":"read"},"events":["pull_request"],"suspended_at":null}`
const grantValidationPermissions = `{"metadata":"read","contents":"read","pull_requests":"read"}`
const grantValidationRepositories = `[{"id":99,"full_name":"owner/repo"}]`
const grantValidationToken = "fixture-issued-installation-token"

type grantValidationClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *grantValidationClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *grantValidationClock) set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = at
}

type grantValidationCompletion struct {
	attempt     IssuanceAttempt
	disposition IssuanceDisposition
	expires     time.Time
}

// This guard records outcomes without deciding whether a response grants authority.
type grantValidationGuard struct {
	authority    IssuanceAuthority
	trace        *brokerFixtureTrace
	reservations []IssuanceAttempt
	completions  []grantValidationCompletion
	closes       int
}

func (g *grantValidationGuard) AuthorityIdentity() string { return g.authority.Identity() }
func (g *grantValidationGuard) Validate() error           { return g.authority.Validate() }
func (g *grantValidationGuard) Reserve(_ context.Context, attempt IssuanceAttempt) (bool, error) {
	g.trace.mu.Lock()
	defer g.trace.mu.Unlock()
	g.reservations = append(g.reservations, attempt)
	g.trace.events = append(g.trace.events, "Reserve")
	return true, nil
}
func (g *grantValidationGuard) Complete(_ context.Context, attempt IssuanceAttempt, disposition IssuanceDisposition, expires time.Time) error {
	g.trace.mu.Lock()
	defer g.trace.mu.Unlock()
	g.completions = append(g.completions, grantValidationCompletion{attempt, disposition, expires})
	g.trace.events = append(g.trace.events, "Complete")
	return nil
}
func (g *grantValidationGuard) Close() error {
	g.trace.mu.Lock()
	defer g.trace.mu.Unlock()
	g.closes++
	return nil
}

type grantValidationReply struct {
	body      string
	status    int
	media     string
	oversize  bool
	shortBody bool
}

type grantValidationCase struct {
	name  string
	get   bool
	valid bool
	reply grantValidationReply
}

func grantValidationBody(expires time.Time) string {
	return fmt.Sprintf(`{"token":%q,"expires_at":%q,"permissions":%s,"repository_selection":"selected","repositories":%s}`, grantValidationToken, expires.Format(time.RFC3339), grantValidationPermissions, grantValidationRepositories)
}

func grantValidationCases(t *testing.T, at, received time.Time) []grantValidationCase {
	t.Helper()
	baseline := grantValidationBody(at.Add(time.Hour))
	cases := []grantValidationCase{{name: "valid-issued-token-control", valid: true, reply: grantValidationReply{body: baseline}}}
	add := func(name string, get bool, body string) {
		cases = append(cases, grantValidationCase{name: name, get: get, reply: grantValidationReply{body: body}})
	}
	replace := func(body, old, replacement string) string {
		if strings.Count(body, old) != 1 {
			t.Fatalf("fixture mutation is not unique: %s", old)
		}
		return strings.Replace(body, old, replacement, 1)
	}
	for _, mutation := range []struct{ name, old, replacement string }{
		{"wrong-app-id", `"app_id":7`, `"app_id":8`},
		{"missing-app-id", `"app_id":7,`, ``},
		{"wrong-installation-id", `"id":42`, `"id":43`},
		{"missing-installation-id", `"id":42,`, ``},
		{"owner-mismatch", `"login":"owner"`, `"login":"other"`},
		{"suspended", `"suspended_at":null`, `"suspended_at":"2026-01-01T00:00:00Z"`},
		{"missing-permission", `,"pull_requests":"read"`, ``},
		{"missing-permissions", `"permissions":` + grantValidationPermissions + `,`, ``},
		{"excess-permission", `"metadata":"read"`, `"metadata":"read","issues":"read"`},
		{"write-permission", `"contents":"read"`, `"contents":"write"`},
	} {
		add("get/"+mutation.name, true, replace(grantValidationInstallation, mutation.old, mutation.replacement))
	}
	for _, mutation := range []struct{ name, old, replacement string }{
		{"wrong-permission", `"contents":"read"`, `"contents":"write"`},
		{"missing-permission", `,"pull_requests":"read"`, ``},
		{"missing-permissions", `"permissions":` + grantValidationPermissions + `,`, ``},
		{"extra-permission", `"metadata":"read"`, `"metadata":"read","issues":"read"`},
		{"duplicate-permission", `"contents":"read"`, `"contents":"read","contents":"read"`},
		{"duplicate-permission-conflicting", `"contents":"read"`, `"contents":"write","contents":"read"`},
		{"duplicate-permissions-member", `"permissions":` + grantValidationPermissions, `"permissions":` + grantValidationPermissions + `,"permissions":` + grantValidationPermissions},
		{"wrong-repository", grantValidationRepositories, `[{"id":100,"full_name":"other/project"}]`},
		{"missing-repository", grantValidationRepositories, `[]`},
		{"missing-repositories-member", `,"repositories":` + grantValidationRepositories, ``},
		{"extra-repository", grantValidationRepositories, `[{"id":99,"full_name":"owner/repo"},{"id":100,"full_name":"owner/extra"}]`},
		{"duplicate-repository", grantValidationRepositories, `[{"id":99,"full_name":"owner/repo"},{"id":99,"full_name":"owner/repo"}]`},
		{"repository-id-mismatch", `"id":99`, `"id":100`},
		{"repository-name-mismatch", `"full_name":"owner/repo"`, `"full_name":"owner/other"`},
		{"missing-repository-id", `"id":99,`, ``},
		{"missing-repository-name", `,"full_name":"owner/repo"`, ``},
		{"duplicate-repository-id", `"id":99`, `"id":99,"id":99`},
	} {
		add("post/"+mutation.name, false, replace(baseline, mutation.old, mutation.replacement))
	}
	add("post/null-json", false, `null`)
	add("post/malformed-json", false, `{!}`)
	add("post/truncated-json", false, baseline[:len(baseline)-1])
	for _, expiry := range []struct {
		name string
		at   time.Time
	}{
		{"expired", received.Add(-time.Second)},
		{"below-receive-plus-five-minutes", received.Add(5*time.Minute - time.Second)},
		{"exactly-receive-plus-five-minutes", received.Add(5 * time.Minute)},
		{"beyond-attempt-plus-3660-seconds", at.Add(3661 * time.Second)},
	} {
		add("post/"+expiry.name, false, grantValidationBody(expiry.at))
	}
	cases = append(cases,
		grantValidationCase{name: "post/truncated-http-body", reply: grantValidationReply{body: baseline, shortBody: true}},
		grantValidationCase{name: "post/oversize-json", reply: grantValidationReply{body: baseline, oversize: true}},
		grantValidationCase{name: "post/unsupported-success-status", reply: grantValidationReply{body: baseline, status: http.StatusOK}},
		grantValidationCase{name: "post/unsupported-error-status", reply: grantValidationReply{body: baseline, status: http.StatusInternalServerError}},
		grantValidationCase{name: "post/unsupported-media", reply: grantValidationReply{body: baseline, media: "text/plain"}},
	)
	return cases
}

type grantValidationIssuer struct {
	key          *rsa.PublicKey
	at, received time.Time
	clock        *grantValidationClock
	trace        *brokerFixtureTrace
	test         grantValidationCase
}

func (f *grantValidationIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.trace.mu.Lock()
	defer f.trace.mu.Unlock()
	f.trace.requests = append(f.trace.requests, r.Clone(context.Background()))
	reject := func(reason string) {
		f.trace.failures = append(f.trace.failures, reason)
		http.Error(w, "fixture request rejected", http.StatusBadRequest)
	}
	if fixtureAppJWTError(r, f.key, 7, f.at) != nil || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" {
		reject("JWT, API version or URL mismatch")
		return
	}
	for _, header := range []string{"Cookie", "Proxy-Authorization", "X-Api-Key"} {
		if len(r.Header.Values(header)) != 0 {
			reject("unexpected credential header")
			return
		}
	}
	reply := grantValidationReply{body: grantValidationInstallation, status: http.StatusOK}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v3/app/installations/42":
		f.trace.events = append(f.trace.events, "GET")
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			reject("installation GET had a body")
			return
		}
		if f.test.get {
			reply = f.test.reply
			reply.status = http.StatusOK
		}
	case r.Method == http.MethodPost && r.URL.Path == "/api/v3/app/installations/42/access_tokens":
		f.trace.events = append(f.trace.events, "POST")
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		var got map[string]any
		want := map[string]any{"repository_ids": []any{float64(99)}, "permissions": map[string]any{"metadata": "read", "contents": "read", "pull_requests": "read"}}
		if err != nil || len(body) > 4096 || r.Header.Get("Content-Type") != "application/json" || json.Unmarshal(body, &got) != nil || !reflect.DeepEqual(got, want) {
			reject("POST grant request was not exactly narrowed")
			return
		}
		for _, field := range []string{"repository_ids", "permissions", "metadata", "contents", "pull_requests"} {
			if strings.Count(string(body), `"`+field+`"`) != 1 {
				reject("duplicate or noncanonical POST request field")
				return
			}
		}
		reply = grantValidationReply{body: grantValidationBody(f.at.Add(time.Hour))}
		if !f.test.get {
			reply = f.test.reply
		}
		if reply.status == 0 {
			reply.status = http.StatusCreated
		}
		f.clock.set(f.received)
	default:
		reject("unexpected method or route")
		return
	}
	if reply.media == "" {
		reply.media = "application/json"
	}
	w.Header().Set("Content-Type", reply.media)
	if reply.shortBody {
		w.Header().Set("Content-Length", fmt.Sprint(len(reply.body)+8))
	}
	w.WriteHeader(reply.status)
	if _, err := io.WriteString(w, reply.body); err != nil {
		return
	}
	if reply.oversize {
		// A valid JSON document plus whitespace must still obey the wire byte limit.
		chunk := strings.Repeat(" ", 1024)
		for remaining := (1 << 20) + 1 - len(reply.body); remaining > 0; {
			n := len(chunk)
			if remaining < n {
				n = remaining
			}
			written, err := io.WriteString(w, chunk[:n])
			if err != nil || written != n {
				return
			}
			remaining -= written
		}
	}
}

func grantValidationRequireClosedError(t *testing.T, err error) {
	t.Helper()
	// Invalid reserved replies can be definite denial or unknown, not one pinned class.
	for _, closed := range []error{ErrBrokerDenied, ErrBrokerMismatch, ErrBrokerUnavailable, ErrIssuanceFenced} {
		if errors.Is(err, closed) && err.Error() == closed.Error() {
			return
		}
	}
	t.Error("invalid issuer reply did not return a closed denial/unavailable/fenced error")
}

func TestInstallationBrokerValidatesNativeGrant(t *testing.T) {
	key, pem, pin := newFixtureAppKey(t)
	at := time.Now().UTC().Truncate(time.Second)
	received := at.Add(2 * time.Second)
	for _, tc := range grantValidationCases(t, at, received) {
		t.Run(tc.name, func(t *testing.T) {
			trace := &brokerFixtureTrace{}
			clock := &grantValidationClock{at: at}
			issuer := &grantValidationIssuer{key: &key.PublicKey, at: at, received: received, clock: clock, trace: trace, test: tc}
			server := httptest.NewServer(issuer)
			defer server.Close()
			authority := brokerAuthorityFixture(t, server.URL+"/api/v3", pin)
			lane, err := NewIssuanceAuthority(authority, IssuancePurposeRuntime)
			if err != nil {
				t.Fatal(err)
			}
			guard := &grantValidationGuard{authority: lane, trace: trace}
			var keyMu sync.Mutex
			keyReads := 0
			unexpectedKeyRead := false
			signer, err := NewAppSigner(authority, func(name string) string {
				keyMu.Lock()
				defer keyMu.Unlock()
				keyReads++
				if name != "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY" {
					unexpectedKeyRead = true
					return ""
				}
				return string(pem)
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			broker, err := NewInstallationTokenBroker(ctx, InstallationBrokerConfig{Authority: authority, IssuanceAuthority: lane, Signer: signer, Guard: guard, Clock: clock})
			if err != nil {
				_ = signer.Close()
				_ = guard.Close()
				t.Fatalf("broker API/fixture construction: %v", err)
			}
			defer func() {
				if err := broker.Close(); err != nil {
					t.Errorf("broker cleanup: %v", err)
				}
				trace.mu.Lock()
				defer trace.mu.Unlock()
				if guard.closes != 1 {
					t.Error("broker did not close its guard exactly once")
				}
			}()
			repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
			if err != nil {
				t.Fatal(err)
			}
			op, err := broker.beginSource(ctx, repository)
			if err != nil {
				t.Fatalf("source operation fixture: %v", err)
			}
			defer op.Close()
			keyMu.Lock()
			initialReads := keyReads
			keyMu.Unlock()
			trace.mu.Lock()
			initialHTTP := len(trace.requests)
			trace.mu.Unlock()
			if initialReads != 0 || initialHTTP != 0 {
				t.Fatal("construction or admission consumed credentials or HTTP")
			}
			lease, borrowErr := broker.borrow(op)
			if lease != nil {
				defer lease.release()
			}
			if tc.valid {
				if borrowErr != nil || lease == nil {
					t.Fatalf("valid native grant did not yield a lease: %v", borrowErr)
				}
				if lease.validate(received) != nil {
					t.Fatal("valid native lease was unusable")
				}
				request, err := http.NewRequestWithContext(op.Context(), http.MethodGet, server.URL+"/api/v3/repos/owner/repo/git/commits/"+strings.Repeat("a", 40), nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
				bound, cleanup, err := lease.bindSourceRequest(request)
				if cleanup != nil {
					defer cleanup()
				}
				if err != nil || bound == nil || cleanup == nil {
					t.Fatalf("valid grant could not bind a source request: %v", err)
				}
				if bound == request || request.Header.Get("Authorization") != "" || len(bound.Header.Values("Authorization")) != 1 || bound.Header.Get("Authorization") != "Bearer "+grantValidationToken || bound.URL.String() != request.URL.String() || bound.Method != request.Method {
					t.Error("lease did not bind exactly the actual issued token to a cloned source request")
				}
				deadline, ok := bound.Context().Deadline()
				callerDeadline, _ := ctx.Deadline()
				if !ok || !deadline.After(time.Now()) || deadline.After(callerDeadline) || deadline.After(at.Add(time.Hour-30*time.Second)) {
					t.Error("lease source binding did not retain a bounded usable deadline")
				}
				cleanup()
				if bound.Context().Err() == nil || lease.validate(received) == nil {
					t.Error("source binding cleanup did not cancel and release the lease")
				}
			} else {
				grantValidationRequireClosedError(t, borrowErr)
				if lease != nil {
					t.Error("invalid issuer reply returned a lease")
					lease.release()
				}
				if !tc.get {
					// A foreground retry must not dispatch an uncertain reserved POST again.
					retryLease, retryErr := broker.borrow(op)
					if retryLease != nil {
						retryLease.release()
						t.Error("invalid reserved reply yielded a lease on retry")
					}
					grantValidationRequireClosedError(t, retryErr)
				}
			}
			keyMu.Lock()
			loaded, unexpected := keyReads, unexpectedKeyRead
			keyMu.Unlock()
			if loaded != 1 || unexpected {
				t.Error("issuer did not use exactly one synthetic App key read")
			}
			trace.mu.Lock()
			events := append([]string(nil), trace.events...)
			failures := append([]string(nil), trace.failures...)
			requests := append([]*http.Request(nil), trace.requests...)
			reservations := append([]IssuanceAttempt(nil), guard.reservations...)
			completions := append([]grantValidationCompletion(nil), guard.completions...)
			trace.mu.Unlock()
			if len(failures) != 0 {
				t.Errorf("issuer request protocol failures: %v", failures)
			}
			for _, request := range requests {
				verifyFixtureAppJWT(t, request, &key.PublicKey, 7, at)
			}
			if tc.get {
				if len(requests) != 1 || len(reservations) != 0 || len(completions) != 0 || !reflect.DeepEqual(events, []string{"GET"}) {
					t.Errorf("invalid GET reached reservation/POST or replayed: %v", events)
				}
				return
			}
			if len(requests) != 2 || len(reservations) != 1 || len(completions) != 1 || !reflect.DeepEqual(events, []string{"GET", "Reserve", "POST", "Complete"}) {
				t.Fatalf("native grant path skipped, reordered or replayed an effect: %v", events)
			}
			attempt, completed := reservations[0], completions[0]
			if attempt.Validate() != nil || attempt.AuthorityIdentity() != lane.Identity() || attempt.Sequence() != 1 || !attempt.StartedAt().Equal(at) || completed.attempt.Validate() != nil || completed.attempt.Identity() != attempt.Identity() {
				t.Error("guard observations did not bind the native issuance attempt")
			}
			if tc.valid {
				if completed.disposition != IssuanceAccepted || !completed.expires.Equal(at.Add(time.Hour)) {
					t.Error("valid native grant lacked accepted completion with actual expiry")
				}
			} else if (completed.disposition != IssuanceRejected && completed.disposition != IssuanceUnknown) || !completed.expires.IsZero() {
				t.Error("invalid native grant recorded an accepted or non-closed outcome")
			}
		})
	}
}
