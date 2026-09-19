package githubruntime

import (
	"context"
	"fmt"
	"io"
	"sync"

	github "github.com/georgejieh/open-trestle/adapters/scm/github"
)

// Runtime owns one broker; adapters only borrow its pointer.
type Runtime struct{ state *runtimeState }

type runtimeState struct {
	mu       sync.Mutex
	broker   *github.InstallationTokenBroker
	closing  bool
	done     chan struct{}
	closeErr error
}

func (r Runtime) String() string                   { return "[redacted GitHub broker runtime]" }
func (r Runtime) GoString() string                 { return r.String() }
func (r Runtime) Format(s fmt.State, _ rune)       { _, _ = io.WriteString(s, r.String()) }
func (r *runtimeState) String() string             { return "[redacted GitHub broker runtime state]" }
func (r *runtimeState) GoString() string           { return r.String() }
func (r *runtimeState) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }

func Open(lifetime context.Context, c Configuration, expectedAuthority string,
	purpose github.IssuancePurpose, getenv func(string) string,
	clock github.BrokerClock) (*Runtime, error) {
	if nilDependency(lifetime) || getenv == nil || nilDependency(clock) || c.Validate() != nil {
		return nil, github.ErrInvalidBrokerConfig
	}
	if lifetime.Err() != nil {
		return nil, github.ErrBrokerUnavailable
	}
	common := c.Authority()
	if expectedAuthority == "" || expectedAuthority != common.Identity() {
		return nil, github.ErrBrokerMismatch
	}
	lane, err := github.NewIssuanceAuthority(common, purpose)
	if err != nil || lane.Validate() != nil || lane.BrokerAuthorityIdentity() != common.Identity() {
		return nil, github.ErrInvalidBrokerConfig
	}
	guard, err := openLocalIssuanceGuard(lifetime, common.Configuration().AttemptStateDirectory, lane, common)
	if err != nil {
		return nil, err
	}
	signer, err := github.NewAppSigner(common, getenv)
	if err != nil {
		if guard.Close() != nil {
			return nil, github.ErrBrokerCloseIncomplete
		}
		return nil, err
	}
	broker, err := github.NewInstallationTokenBroker(lifetime, github.InstallationBrokerConfig{
		Authority: common, IssuanceAuthority: lane, Signer: signer, Guard: guard, Clock: clock,
	})
	if err != nil {
		signerErr := signer.Close()
		guardErr := guard.Close()
		if signerErr != nil || guardErr != nil {
			return nil, github.ErrBrokerCloseIncomplete
		}
		return nil, err
	}
	if lifetime.Err() != nil {
		if broker.Close() != nil {
			return nil, github.ErrBrokerCloseIncomplete
		}
		return nil, github.ErrBrokerUnavailable
	}
	return &Runtime{state: &runtimeState{broker: broker, done: make(chan struct{})}}, nil
}

func (r *Runtime) Broker() *github.InstallationTokenBroker {
	if r == nil || r.state == nil {
		return nil
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return nil
	}
	return s.broker
}

func (r *Runtime) Close() error {
	if r == nil || r.state == nil {
		return nil
	}
	s := r.state
	s.mu.Lock()
	if s.closing {
		done := s.done
		s.mu.Unlock()
		select {
		case <-done:
			return s.closeErr
		default:
			return github.ErrBrokerCloseIncomplete
		}
	}
	s.closing = true
	broker := s.broker
	s.broker = nil
	s.mu.Unlock()
	err := broker.Close()
	s.mu.Lock()
	s.closeErr = err
	close(s.done)
	s.mu.Unlock()
	return err
}
