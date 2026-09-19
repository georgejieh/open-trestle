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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// Native timers remain real. Forward jumps exercise only injected policy time.
// Old bindings are released before these jumps; native elapsed time is not simulated.
type lifecycleBoundaryClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *lifecycleBoundaryClock) Now() time.Time   { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *lifecycleBoundaryClock) set(at time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.at = at }

type lifecycleBoundaryCompletion struct {
	attempt     IssuanceAttempt
	disposition IssuanceDisposition
	expires     time.Time
}
type lifecycleBoundaryFixture struct {
	mu                                   sync.Mutex
	clock                                *lifecycleBoundaryClock
	at, expires                          time.Time
	key                                  *rsa.PublicKey
	pem                                  []byte
	lane                                 IssuanceAuthority
	broker                               *InstallationTokenBroker
	server                               *httptest.Server
	ctx                                  context.Context
	cancel                               context.CancelFunc
	events, failures                     []string
	attempts                             []IssuanceAttempt
	completions                          []lifecycleBoundaryCompletion
	reads, requests, gets, posts, closes int
	blockGET                             bool
	redirect                             string
	token                                string
	invalidGrant                         bool
	entered, release, handlerDone        chan struct{}
	enterOnce, releaseOnce, handlerOnce  sync.Once
}

// This recording guard never converts a bad response into a fixture guard error.
// Its assertions run on the foreground test goroutine after native borrow.
func (f *lifecycleBoundaryFixture) AuthorityIdentity() string { return f.lane.Identity() }
func (f *lifecycleBoundaryFixture) Validate() error           { return f.lane.Validate() }
func (f *lifecycleBoundaryFixture) Reserve(_ context.Context, a IssuanceAttempt) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts = append(f.attempts, a)
	f.events = append(f.events, "Reserve")
	return true, nil
}
func (f *lifecycleBoundaryFixture) Complete(_ context.Context, a IssuanceAttempt, d IssuanceDisposition, expires time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completions = append(f.completions, lifecycleBoundaryCompletion{a, d, expires})
	f.events = append(f.events, "Complete")
	return nil
}
func (f *lifecycleBoundaryFixture) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	return nil
}
func (f *lifecycleBoundaryFixture) unblock() { f.releaseOnce.Do(func() { close(f.release) }) }

func (f *lifecycleBoundaryFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	if r.Method == http.MethodPost {
		f.posts++
	}
	reject := func(reason string) {
		f.failures = append(f.failures, reason)
		f.mu.Unlock()
		http.Error(w, "fixture request rejected", http.StatusBadRequest)
	}
	if fixtureAppJWTError(r, f.key, 7, f.clock.Now()) != nil || r.ProtoMajor != 1 || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || r.URL.RawQuery != "" || r.URL.RawPath != "" {
		reject("JWT, HTTP/1, API version or URL mismatch")
		return
	}
	for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Api-Key"} {
		if len(r.Header.Values(name)) != 0 {
			reject("unexpected credential header")
			return
		}
	}
	isGET := r.Method == http.MethodGet && r.URL.Path == "/api/v3/app/installations/42"
	isPOST := r.Method == http.MethodPost && r.URL.Path == "/api/v3/app/installations/42/access_tokens"
	if !isGET && !isPOST {
		reject("unexpected issuer route")
		return
	}
	if isGET {
		f.gets++
		f.events = append(f.events, "GET")
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			reject("GET body")
			return
		}
	} else {
		f.events = append(f.events, "POST")
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		var got struct {
			RepositoryIDs []uint64          `json:"repository_ids"`
			Permissions   map[string]string `json:"permissions"`
		}
		if err != nil || len(body) > 4096 || json.Unmarshal(body, &got) != nil || r.Header.Get("Content-Type") != "application/json" || len(got.RepositoryIDs) != 1 || got.RepositoryIDs[0] != 99 || len(got.Permissions) != 3 || got.Permissions["metadata"] != "read" || got.Permissions["contents"] != "read" || got.Permissions["pull_requests"] != "read" {
			reject("POST not narrowed")
			return
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(body, &fields) != nil || len(fields) != 2 {
			reject("POST extra members")
			return
		}
		for _, field := range []string{"repository_ids", "permissions", "metadata", "contents", "pull_requests"} {
			if strings.Count(string(body), `"`+field+`"`) != 1 {
				reject("POST duplicate member")
				return
			}
		}
	}
	block, redirect := f.blockGET && isGET, f.redirect
	expires, token, invalid := f.expires, f.token, f.invalidGrant
	f.mu.Unlock()
	if block {
		defer f.handlerOnce.Do(func() { close(f.handlerDone) })
		f.enterOnce.Do(func() { close(f.entered) })
		select {
		case <-f.release:
		case <-r.Context().Done():
			return
		}
		if r.Context().Err() != nil {
			return
		}
	}
	if isGET && redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if isGET {
		_, _ = io.WriteString(w, `{"id":42,"app_id":7,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"read","pull_requests":"read"},"events":["pull_request"],"suspended_at":null}`)
		return
	}
	w.WriteHeader(http.StatusCreated)
	contents := "read"
	if invalid {
		contents = "write"
	}
	_, _ = fmt.Fprintf(w, `{"token":%q,"expires_at":%q,"permissions":{"metadata":"read","contents":%q,"pull_requests":"read"},"repository_selection":"selected","repositories":[{"id":99,"full_name":"owner/repo"}]}`, token, expires.Format(time.RFC3339), contents)
}

func lifecycleBoundaryNew(t *testing.T, key *rsa.PrivateKey, pem []byte, pin string, block bool, redirect string) *lifecycleBoundaryFixture {
	t.Helper()
	at := time.Now() // Keep the native monotonic component.
	f := &lifecycleBoundaryFixture{at: at, expires: at.Add(time.Hour).UTC().Truncate(time.Second), key: &key.PublicKey, pem: pem, blockGET: block, redirect: redirect, entered: make(chan struct{}), release: make(chan struct{}), handlerDone: make(chan struct{})}
	f.token = "fixture-issued-installation-token"
	f.clock = &lifecycleBoundaryClock{at: at}
	f.ctx, f.cancel = context.WithTimeout(context.Background(), 15*time.Second)
	f.server = httptest.NewServer(f)
	t.Cleanup(f.server.Close)
	authority := brokerAuthorityFixture(t, f.server.URL+"/api/v3", pin)
	lane, err := NewIssuanceAuthority(authority, IssuancePurposeRuntime)
	if err != nil {
		t.Fatal(err)
	}
	f.lane = lane
	signer, err := NewAppSigner(authority, func(name string) string {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.reads++
		if name != "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY" {
			f.failures = append(f.failures, "unexpected key callback name")
			return ""
		}
		return string(f.pem)
	})
	if err != nil {
		f.cancel()
		t.Fatal(err)
	}
	f.broker, err = NewInstallationTokenBroker(f.ctx, InstallationBrokerConfig{Authority: authority, IssuanceAuthority: lane, Signer: signer, Guard: f, Clock: f.clock})
	if err != nil {
		f.cancel()
		_ = signer.Close()
		_ = f.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.unblock()
		f.cancel()
		if err := f.broker.Close(); err != nil {
			t.Errorf("broker cleanup: %v", err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.closes != 1 {
			t.Error("guard not closed exactly once")
		}
		if len(f.failures) != 0 {
			t.Errorf("fixture protocol failures: %v", f.failures)
		}
	})
	f.counts(t, 0, 0, 0, 0, 0)
	return f
}
func lifecycleBoundaryRepository(t *testing.T, owner, name string) evidence.RepositoryIdentity {
	t.Helper()
	r, err := evidence.NewRepositoryIdentity("github.com", []string{owner}, name)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func (f *lifecycleBoundaryFixture) operation(t *testing.T) *brokerOperation {
	t.Helper()
	op, err := f.broker.beginSource(f.ctx, lifecycleBoundaryRepository(t, "owner", "repo"))
	if err != nil {
		t.Fatalf("source admission: %v", err)
	}
	t.Cleanup(op.Close)
	return op
}
func (f *lifecycleBoundaryFixture) lease(t *testing.T, op *brokerOperation) *installationLease {
	t.Helper()
	lease, err := f.broker.borrow(op)
	if lease != nil {
		t.Cleanup(lease.release)
	}
	if err != nil || lease == nil {
		t.Fatalf("valid native grant: %v", err)
	}
	if err := lease.validate(f.clock.Now()); err != nil {
		t.Fatalf("valid lease: %v", err)
	}
	return lease
}
func (f *lifecycleBoundaryFixture) request(t *testing.T, op *brokerOperation) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(op.Context(), http.MethodGet, f.server.URL+"/api/v3/repos/owner/repo/git/commits/"+strings.Repeat("a", 40), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	return r
}
func (f *lifecycleBoundaryFixture) bind(t *testing.T, op *brokerOperation, lease *installationLease) (*http.Request, func()) {
	t.Helper()
	r := f.request(t, op)
	bound, cleanup, err := lease.bindSourceRequest(r)
	if cleanup != nil {
		t.Cleanup(cleanup)
	}
	if err != nil || bound == nil || cleanup == nil {
		t.Fatalf("valid source binding: %v", err)
	}
	if bound == r || r.Header.Get("Authorization") != "" || bound.Header.Get("Authorization") != "Bearer "+f.token || len(bound.Header.Values("Authorization")) != 1 {
		t.Fatal("issued token binding mismatch")
	}
	deadline, ok := bound.Context().Deadline()
	caller, callerOK := op.Context().Deadline()
	if !ok || !callerOK || !deadline.Equal(caller) || !deadline.After(time.Now()) || bound.Context().Err() != nil {
		t.Fatal("exact native caller deadline not retained")
	}
	return bound, cleanup
}
func (f *lifecycleBoundaryFixture) counts(t *testing.T, reads, gets, posts, reserves, completes int) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reads != reads || f.gets != gets || f.posts != posts || f.requests != gets+posts || len(f.attempts) != reserves || len(f.completions) != completes || len(f.failures) != 0 {
		t.Fatalf("effect counts: key=%d GET=%d POST=%d requests=%d reserve=%d complete=%d failures=%v", f.reads, f.gets, f.posts, f.requests, len(f.attempts), len(f.completions), f.failures)
	}
}
func (f *lifecycleBoundaryFixture) accepted(t *testing.T) {
	t.Helper()
	f.counts(t, 1, 1, 1, 1, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Join(f.events, ",") != "GET,Reserve,POST,Complete" {
		t.Fatal("native issuer/reservation order")
	}
	a, c := f.attempts[0], f.completions[0]
	if a.Validate() != nil || a.AuthorityIdentity() != f.lane.Identity() || a.Sequence() != 1 || !a.StartedAt().Equal(f.at) || c.attempt.Identity() != a.Identity() || c.disposition != IssuanceAccepted || !c.expires.Equal(f.expires) {
		t.Fatal("accepted attempt/lane/expiry mismatch")
	}
}
func lifecycleBoundaryRefused(t *testing.T, lease *installationLease, err error) {
	t.Helper()
	if lease != nil {
		lease.release()
		t.Fatal("refused borrow returned a lease")
	}
	if err == nil {
		t.Fatal("refused borrow returned no error")
	}
	for _, sentinel := range []error{ErrBrokerDenied, ErrBrokerMismatch, ErrBrokerUnavailable, ErrBrokerClosed, ErrIssuanceFenced} {
		if errors.Is(err, sentinel) && err.Error() == sentinel.Error() {
			return
		}
	}
	t.Fatal("borrow did not return closed error vocabulary")
}

// Only fixture response/clock state changes. No broker, grant, or lease fields.
func (f *lifecycleBoundaryFixture) policy(at, expires time.Time, token string, invalid bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clock.set(at)
	f.expires = expires
	f.token = token
	f.invalidGrant = invalid
}
func (f *lifecycleBoundaryFixture) renewed(t *testing.T, started, expires time.Time, accepted bool) {
	t.Helper()
	f.counts(t, 1, 2, 2, 2, 2)
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Join(f.events, ",") != "GET,Reserve,POST,Complete,GET,Reserve,POST,Complete" {
		t.Fatal("renewal did not repeat complete authenticated cycle")
	}
	a, c := f.attempts[1], f.completions[1]
	if a.Validate() != nil || a.Sequence() != 2 || a.AuthorityIdentity() != f.lane.Identity() || !a.StartedAt().Equal(started) || a.Identity() == f.attempts[0].Identity() || c.attempt.Identity() != a.Identity() {
		t.Fatal("fresh renewal attempt mismatch")
	}
	if accepted {
		if c.disposition != IssuanceAccepted || !c.expires.Equal(expires) {
			t.Fatal("valid renewal was not completed accepted")
		}
	} else if c.disposition == IssuanceAccepted || !c.expires.IsZero() {
		t.Fatal("invalid renewal was completed accepted")
	}
}

type lifecycleBoundaryBorrowResult struct {
	lease *installationLease
	err   error
}

func (f *lifecycleBoundaryFixture) blockedBorrow(t *testing.T, op *brokerOperation) <-chan lifecycleBoundaryBorrowResult {
	t.Helper()
	result := make(chan lifecycleBoundaryBorrowResult, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		lease, err := f.broker.borrow(op)
		result <- lifecycleBoundaryBorrowResult{lease, err}
	}()
	t.Cleanup(func() {
		f.unblock()
		f.cancel()
		<-joined
		select {
		case r := <-result:
			if r.lease != nil {
				r.lease.release()
			}
		default:
		}
		// Join the fixture handler too, including early test assertion failures.
		select {
		case <-f.entered:
			<-f.handlerDone
		default:
		}
	})
	select {
	case <-f.entered:
	case <-f.ctx.Done():
		t.Fatal("issuer GET did not reach channel barrier")
	}
	return result
}

func TestInstallationBrokerLifecycleBoundaries(t *testing.T) {
	key, pem, pin := newFixtureAppKey(t) // One synthetic RSA-2048 key, serial cases.
	t.Run("cached-grant-and-explicit-validation-boundaries", func(t *testing.T) {
		f := lifecycleBoundaryNew(t, key, pem, pin, false, "")
		op := f.operation(t)
		first := f.lease(t, op)
		old, cleanup := f.bind(t, op, first)
		f.accepted(t)
		originalDeadline, _ := old.Context().Deadline()
		secondOp := f.operation(t)
		second := f.lease(t, secondOp)
		newer, release := f.bind(t, secondOp, second)
		if newer.Header.Get("Authorization") != old.Header.Get("Authorization") {
			t.Fatal("cached grant changed")
		}
		if d, _ := old.Context().Deadline(); !d.Equal(originalDeadline) || old.Context().Err() != nil {
			t.Fatal("second borrow mutated first binding")
		}
		// Explicit validate(at) is a value-boundary oracle, not native time travel.
		cutoff := f.expires.Add(-30 * time.Second)
		if first.validate(cutoff.Add(-time.Nanosecond)) != nil {
			t.Fatal("lease invalid just before conservative cutoff")
		}
		if first.validate(cutoff) == nil || first.validate(f.expires) == nil {
			t.Fatal("lease accepted exact cutoff or absolute expiration")
		}
		release()
		cleanup()
		if old.Context().Err() == nil || first.validate(f.at) == nil {
			t.Fatal("cleanup did not cancel/release")
		}
		first.release()
		second.release()
		op.Close()
		secondOp.Close()
		f.accepted(t)
	})
	for _, name := range []string{"renewal-at-five-minutes", "invalid-renewal-no-fallback", "expired-cache-needs-fresh-grant"} {
		t.Run("controlled-policy-clock/"+name, func(t *testing.T) {
			f := lifecycleBoundaryNew(t, key, pem, pin, false, "")
			op := f.operation(t)
			lease := f.lease(t, op)
			old, cleanup := f.bind(t, op, lease)
			originalHeader := old.Header.Get("Authorization")
			originalDeadline, _ := old.Context().Deadline()
			firstExpiry := f.expires
			f.accepted(t)
			cleanup()
			op.Close()
			// No live old request crosses this logical clock jump.
			if old.Context().Err() == nil {
				t.Fatal("old binding not canceled before policy jump")
			}
			// Above cutoff positive control: >5 minutes remain in both absolute
			// and conservative domains. This is injected policy time, not a wait.
			before := firstExpiry.Add(-5*time.Minute - 31*time.Second)
			f.policy(before, firstExpiry, f.token, false)
			cachedOp := f.operation(t)
			cached := f.lease(t, cachedOp)
			_, release := f.bind(t, cachedOp, cached)
			release()
			cachedOp.Close()
			f.accepted(t)
			renewalAt := firstExpiry.Add(-5 * time.Minute)
			if name == "expired-cache-needs-fresh-grant" {
				renewalAt = firstExpiry.Add(time.Second)
			}
			invalid := name == "invalid-renewal-no-fallback"
			nextExpiry := renewalAt.Add(time.Hour).UTC().Truncate(time.Second)
			f.policy(renewalAt, nextExpiry, "fixture-renewed-installation-token", invalid)
			// Policy-clock movement alone must not invoke credentials or HTTP.
			f.counts(t, 1, 1, 1, 1, 1)
			newOp := f.operation(t)
			next, err := f.broker.borrow(newOp)
			if next != nil {
				t.Cleanup(next.release)
			}
			if invalid {
				lifecycleBoundaryRefused(t, next, err)
				retry, retryErr := f.broker.borrow(newOp)
				lifecycleBoundaryRefused(t, retry, retryErr)
				f.renewed(t, renewalAt, nextExpiry, false)
			} else {
				if err != nil || next == nil {
					t.Fatalf("controlled-clock fresh renewal: %v", err)
				}
				if next.validate(renewalAt) != nil {
					t.Fatal("renewed lease invalid")
				}
				bound, release := f.bind(t, newOp, next)
				if bound.Header.Get("Authorization") != "Bearer fixture-renewed-installation-token" || bound.Header.Get("Authorization") == originalHeader {
					t.Fatal("renewal reused old token")
				}
				release()
				f.renewed(t, renewalAt, nextExpiry, true)
			}
			if d, _ := old.Context().Deadline(); !d.Equal(originalDeadline) || old.Header.Get("Authorization") != originalHeader {
				t.Fatal("renewal mutated old request snapshot")
			}
		})
	}
	t.Run("controlled-policy-clock/too-early-renewal-keeps-valid-cache", func(t *testing.T) {
		// Independent native grants keep an earlier terminal cutoff refusal from
		// masking the absolute-expiry check. Both lifetimes stay below 30 minutes.
		for _, margin := range []time.Duration{30 * time.Second, 0} {
			f := lifecycleBoundaryNew(t, key, pem, pin, false, "")
			expires := f.at.Add(10 * time.Minute).UTC().Truncate(time.Second)
			f.policy(f.at, expires, f.token, false)
			op := f.operation(t)
			lease := f.lease(t, op)
			old, cleanup := f.bind(t, op, lease)
			originalHeader := old.Header.Get("Authorization")
			originalDeadline, _ := old.Context().Deadline()
			cleanup()
			op.Close()
			if old.Context().Err() == nil {
				t.Fatal("old binding not canceled before policy jump")
			}
			f.accepted(t)
			// The minimum interval prevents issuance, not use of a valid cache.
			// Test both <=5m remaining and 1ns before the conservative cutoff.
			for _, at := range []time.Time{expires.Add(-5 * time.Minute), expires.Add(-30*time.Second - time.Nanosecond)} {
				f.policy(at, expires, f.token, false)
				cachedOp := f.operation(t)
				cached := f.lease(t, cachedOp)
				bound, release := f.bind(t, cachedOp, cached)
				if bound.Header.Get("Authorization") != originalHeader {
					t.Fatal("minimum interval changed the still-valid cached token")
				}
				release()
				cachedOp.Close()
				f.accepted(t)
			}
			f.policy(expires.Add(-margin), expires, f.token, false)
			refusedOp := f.operation(t)
			refused, err := f.broker.borrow(refusedOp)
			lifecycleBoundaryRefused(t, refused, err)
			retry, retryErr := f.broker.borrow(refusedOp)
			lifecycleBoundaryRefused(t, retry, retryErr)
			refusedOp.Close()
			f.accepted(t) // No new GET, reserve, POST or completion at either boundary.
			if d, _ := old.Context().Deadline(); !d.Equal(originalDeadline) || old.Header.Get("Authorization") != originalHeader {
				t.Fatal("policy samples mutated the released request snapshot")
			}
			if err := f.broker.Close(); err != nil {
				t.Fatalf("interval boundary fixture cleanup: %v", err)
			}
		}
	})
	t.Run("one-lease-and-cross-bindings", func(t *testing.T) {
		f := lifecycleBoundaryNew(t, key, pem, pin, false, "")
		op := f.operation(t)
		lease := f.lease(t, op)
		duplicate, err := f.broker.borrow(op)
		lifecycleBoundaryRefused(t, duplicate, err)
		bound, cleanup := f.bind(t, op, lease)
		cleanup()
		if bound.Context().Err() == nil {
			t.Fatal("cleanup did not cancel binding")
		}
		lease = f.lease(t, op) // Positive: cleanup admits the next lease.
		lease.release()
		other := lifecycleBoundaryNew(t, key, pem, pin, false, "")
		wrongOwner, err := other.broker.borrow(op)
		lifecycleBoundaryRefused(t, wrongOwner, err)
		other.counts(t, 0, 0, 0, 0, 0)
		otherOp := other.operation(t)
		for _, repo := range []evidence.RepositoryIdentity{lifecycleBoundaryRepository(t, "other", "repo"), lifecycleBoundaryRepository(t, "owner", "other")} {
			wrong, err := f.broker.beginSource(f.ctx, repo)
			if wrong != nil {
				wrong.Close()
				t.Fatal("wrong repository admitted")
			}
			if err == nil {
				t.Fatal("wrong repository accepted")
			}
		}
		mutations := []struct {
			name   string
			change func(*http.Request)
		}{
			{"owner", func(r *http.Request) { r.URL.Path = strings.Replace(r.URL.Path, "/owner/", "/other/", 1) }},
			{"repo", func(r *http.Request) { r.URL.Path = strings.Replace(r.URL.Path, "/repo/", "/other/", 1) }},
			{"path", func(r *http.Request) { r.URL.Path = "/api/v3/user" }},
			{"base", func(r *http.Request) { r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api/v3") }},
			{"origin", func(r *http.Request) { r.URL.Host = "127.0.0.1:1" }},
			{"method", func(r *http.Request) { r.Method = http.MethodPost }},
			{"version", func(r *http.Request) { r.Header.Set("X-GitHub-Api-Version", "2022-11-28") }},
			{"authorization", func(r *http.Request) { r.Header.Set("Authorization", "Bearer fixture-caller-token") }},
			{"context-owner", func(r *http.Request) { *r = *r.WithContext(otherOp.Context()) }},
		}
		for _, mutation := range mutations {
			lease = f.lease(t, op)
			r := f.request(t, op)
			mutation.change(r)
			rejected, release, err := lease.bindSourceRequest(r)
			if release != nil {
				release()
			}
			lease.release()
			if err == nil || rejected != nil {
				t.Fatalf("wrong %s binding accepted", mutation.name)
			}
			control := f.lease(t, op)
			_, finish := f.bind(t, op, control)
			finish()
		}
		lease.release()
		fresh := f.lease(t, op)
		_, release := f.bind(t, op, fresh)
		release()
		f.accepted(t)
	})
	t.Run("whole-operation-capacity", func(t *testing.T) {
		f := lifecycleBoundaryNew(t, key, pem, pin, false, "")
		ops := make([]*brokerOperation, 32)
		for i := range ops {
			ops[i] = f.operation(t)
		}
		f.counts(t, 0, 0, 0, 0, 0)
		refuse := func() {
			extra, err := f.broker.beginSource(f.ctx, lifecycleBoundaryRepository(t, "owner", "repo"))
			if extra != nil {
				extra.Close()
				t.Fatal("33rd whole-source operation admitted")
			}
			if !errors.Is(err, ErrBrokerUnavailable) {
				t.Fatal("capacity did not return unavailable")
			}
		}
		refuse()
		f.counts(t, 0, 0, 0, 0, 0)
		lease := f.lease(t, ops[0])
		_, cleanup := f.bind(t, ops[0], lease)
		cleanup()
		refuse() // Releasing metadata lease cannot release whole acquisition slot.
		ops[0].Close()
		replacement := f.operation(t)
		again := f.lease(t, replacement)
		_, release := f.bind(t, replacement, again)
		release()
		refuse()
		f.accepted(t)
	})
	t.Run("single-native-issuer-no-wait-queue", func(t *testing.T) {
		f := lifecycleBoundaryNew(t, key, pem, pin, true, "")
		first := f.operation(t)
		result := f.blockedBorrow(t, first)
		other := f.operation(t)
		ctx, cancel := context.WithTimeout(other.Context(), 500*time.Millisecond)
		defer cancel()
		// The caller deadline distinguishes immediate unavailable from a waiter.
		probe, err := f.broker.beginSource(ctx, lifecycleBoundaryRepository(t, "owner", "repo"))
		if err != nil {
			t.Fatal(err)
		}
		defer probe.Close()
		lease, err := f.broker.borrow(probe)
		lifecycleBoundaryRefused(t, lease, err)
		if !errors.Is(err, ErrBrokerUnavailable) || ctx.Err() != nil {
			t.Fatal("concurrent borrow queued instead of bounded unavailable")
		}
		f.counts(t, 1, 1, 0, 0, 0)
		f.unblock()
		var got lifecycleBoundaryBorrowResult
		select {
		case got = <-result:
		case <-f.ctx.Done():
			t.Fatal("released issuer did not return")
		}
		if got.lease != nil {
			defer got.lease.release()
		}
		if got.err != nil || got.lease == nil {
			t.Fatalf("released issuer positive control: %v", got.err)
		}
		_, cleanup := f.bind(t, first, got.lease)
		cleanup()
		cached := f.lease(t, other)
		_, release := f.bind(t, other, cached)
		release()
		f.accepted(t)
	})
	t.Run("cancel-before-post", func(t *testing.T) {
		f := lifecycleBoundaryNew(t, key, pem, pin, true, "")
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		op, err := f.broker.beginSource(ctx, lifecycleBoundaryRepository(t, "owner", "repo"))
		if err != nil {
			t.Fatal(err)
		}
		defer op.Close()
		result := f.blockedBorrow(t, op)
		cancel()
		f.unblock()
		select {
		case got := <-result:
			lifecycleBoundaryRefused(t, got.lease, got.err)
		case <-f.ctx.Done():
			t.Fatal("canceled issuer did not return")
		}
		<-f.handlerDone
		f.counts(t, 1, 1, 0, 0, 0)
		// The same channel-controlled protocol succeeds in the preceding case.
	})
	t.Run("backward-clock-no-old-cache-fallback", func(t *testing.T) {
		f := lifecycleBoundaryNew(t, key, pem, pin, false, "")
		op := f.operation(t)
		lease := f.lease(t, op)
		_, cleanup := f.bind(t, op, lease)
		cleanup()
		f.accepted(t)
		// Deliberate clock fault only; not a simulated native elapsed interval.
		f.clock.set(f.at.Add(-time.Nanosecond))
		refused, err := f.broker.borrow(op)
		lifecycleBoundaryRefused(t, refused, err)
		refused, err = f.broker.borrow(op)
		lifecycleBoundaryRefused(t, refused, err)
		f.accepted(t)
	})
	t.Run("cooperative-close-cancels-and-closes-admission", func(t *testing.T) {
		f := lifecycleBoundaryNew(t, key, pem, pin, false, "")
		op := f.operation(t)
		lease := f.lease(t, op)
		bound, cleanup := f.bind(t, op, lease)
		done := make(chan struct{})
		go func() { defer close(done); <-op.Context().Done(); cleanup(); op.Close() }()
		t.Cleanup(func() { f.cancel(); <-done })
		if err := f.broker.Close(); err != nil {
			t.Fatalf("cooperative Close: %v", err)
		}
		<-done
		if op.Context().Err() == nil || bound.Context().Err() == nil || f.broker.Validate() == nil {
			t.Fatal("Close did not cancel owned operation/binding")
		}
		closed, err := f.broker.beginSource(f.ctx, lifecycleBoundaryRepository(t, "owner", "repo"))
		if closed != nil {
			closed.Close()
			t.Fatal("Close reopened admission")
		}
		if !errors.Is(err, ErrBrokerClosed) {
			t.Fatal("future admission not closed")
		}
		if err := f.broker.Close(); err != nil {
			t.Fatal("repeated Close changed result")
		}
		f.accepted(t)
	})
	t.Run("owned-issuer-refuses-redirect", func(t *testing.T) {
		var mu sync.Mutex
		requests, authorization := 0, 0
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requests++
			authorization += len(r.Header.Values("Authorization"))
			mu.Unlock()
			http.Error(w, "redirect target must not be reached", http.StatusBadRequest)
		}))
		defer target.Close()
		f := lifecycleBoundaryNew(t, key, pem, pin, false, target.URL+"/capture")
		op := f.operation(t)
		lease, err := f.broker.borrow(op)
		lifecycleBoundaryRefused(t, lease, err)
		f.counts(t, 1, 1, 0, 0, 0)
		mu.Lock()
		hits, credentials := requests, authorization
		mu.Unlock()
		if hits != 0 || credentials != 0 {
			t.Fatal("owned issuer followed redirect or leaked Authorization")
		}
		// Other cases prove actual native HTTP/1 issuance, not a transport stub.
		// This is issuer-only: bound source requests are deliberately undispatched.
	})
}
