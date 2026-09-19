package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// The callback deliberately ignores cancellation until the test releases it.
// This checks honest incomplete cleanup, not preemption or token erasure.
func TestInstallationBrokerBlockedKeyCloseProbe(t *testing.T) {
	_, encoded, pin := newFixtureAppKey(t)
	var mu sync.Mutex
	keyReads, requests := 0, 0
	wrongName := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		http.Error(w, "unexpected request after cancellation", http.StatusForbidden)
	}))
	defer server.Close()
	authority := brokerAuthorityFixture(t, server.URL+"/api/v3", pin)
	lane, err := NewIssuanceAuthority(authority, IssuancePurposeSetup)
	if err != nil {
		t.Fatal(err)
	}
	// This existing fixture guard always accepts native attempts. It cannot
	// hide unexpected issuer activity behind an injected guard refusal.
	guard := &lifecycleBoundaryFixture{lane: lane}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce, enterOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	owner, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	signer, err := NewAppSigner(authority, func(name string) string {
		mu.Lock()
		keyReads++
		wrongName = wrongName || name != "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY"
		mu.Unlock()
		enterOnce.Do(func() { close(entered) })
		<-release
		return string(encoded)
	})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewInstallationTokenBroker(owner, InstallationBrokerConfig{
		Authority: authority, IssuanceAuthority: lane, Signer: signer,
		Guard: guard, Clock: fixtureBrokerClock{at: time.Now()},
	})
	if err != nil {
		_ = signer.Close()
		_ = guard.Close()
		t.Fatal(err)
	}
	op, err := broker.beginInspection(owner, authority.Identity())
	if err != nil {
		_ = broker.Close()
		t.Fatal(err)
	}
	type outcome struct {
		lease *installationLease
		err   error
	}
	result := make(chan outcome, 1)
	borrowed, closed := make(chan struct{}), make(chan struct{})
	closeResult := make(chan error, 1)
	closeStarted := false
	// Register before starting work. This also joins both workers on assertion
	// failure; no goroutine-count or arbitrary-kernel-call guarantee is claimed.
	defer func() {
		unblock()
		cancel()
		<-borrowed
		if closeStarted {
			<-closed
		}
		select {
		case out := <-result:
			if out.lease != nil {
				out.lease.release()
			}
		default:
		}
		op.Close()
		if err := broker.Close(); err != nil {
			t.Errorf("released callback did not drain: %v", err)
		}
	}()
	go func() {
		defer close(borrowed)
		defer op.Close()
		lease, err := broker.borrow(op)
		result <- outcome{lease, err}
	}()
	select {
	case <-entered:
	case <-owner.Done():
		t.Fatal("key callback did not enter")
	}
	closeStarted = true
	go func() { defer close(closed); closeResult <- broker.Close() }()
	select {
	case <-op.Context().Done():
	case <-owner.Done():
		t.Fatal("Close did not cancel the owned operation")
	}
	if !errors.Is(broker.Validate(), ErrBrokerClosed) {
		t.Fatal("Close did not close admission")
	}
	refused, err := broker.beginInspection(context.Background(), authority.Identity())
	if refused != nil {
		refused.Close()
		t.Fatal("closed owner admitted a new operation")
	}
	if !errors.Is(err, ErrBrokerClosed) {
		t.Fatal("closed admission returned wrong error")
	}
	select {
	case err := <-closeResult:
		if !errors.Is(err, ErrBrokerCloseIncomplete) {
			t.Fatal("blocked callback was reported as successful cleanup")
		}
	case <-owner.Done():
		t.Fatal("Close did not return within the bounded fixture lifetime")
	}
	<-closed
	select {
	case <-borrowed:
		t.Fatal("callback unexpectedly returned before explicit release")
	default:
	}
	guard.mu.Lock()
	premature := guard.closes != 0 || len(guard.attempts) != 0 || len(guard.completions) != 0
	guard.mu.Unlock()
	if premature {
		t.Fatal("resources or issuance advanced before blocked callback released")
	}
	mu.Lock()
	reads, hits, bad := keyReads, requests, wrongName
	mu.Unlock()
	if reads != 1 || hits != 0 || bad {
		t.Fatal("blocked operation performed unexpected key or HTTP effects")
	}
	unblock()
	var out outcome
	select {
	case out = <-result:
	case <-owner.Done():
		t.Fatal("released callback did not return")
	}
	if out.lease != nil {
		out.lease.release()
		t.Fatal("canceled callback returned a usable lease")
	}
	if out.err == nil {
		t.Fatal("canceled callback returned success")
	}
	<-borrowed
	// A later Close may finish after actual drain. Admission must stay closed;
	// the earlier incomplete result was not a promise of a permanent failure.
	if err := broker.Close(); err != nil {
		t.Fatalf("actual drain did not complete: %v", err)
	}
	if !errors.Is(broker.Validate(), ErrBrokerClosed) {
		t.Fatal("drain reopened admission")
	}
	guard.mu.Lock()
	exact := guard.closes == 1 && len(guard.attempts) == 0 && len(guard.completions) == 0
	guard.mu.Unlock()
	mu.Lock()
	reads, hits, bad = keyReads, requests, wrongName
	mu.Unlock()
	if !exact || reads != 1 || hits != 0 || bad {
		t.Fatal("drain repeated effects or failed exact resource cleanup")
	}
}
