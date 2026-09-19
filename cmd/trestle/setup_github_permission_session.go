package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	githubadapter "github.com/georgejieh/open-trestle/adapters/scm/github"
	githubruntime "github.com/georgejieh/open-trestle/internal/githubruntime"
)

type setupGitHubPermissionHostConfiguration struct {
	broker                  githubruntime.Configuration
	configured              bool
	expectedBrokerAuthority string
}

func loadSetupGitHubPermissionHostConfiguration(ctx context.Context, brokerConfigPath, expectedBrokerAuthority, staticToken string) (setupGitHubPermissionHostConfiguration, error) {
	if setupGitHubPermissionNil(ctx) {
		return setupGitHubPermissionHostConfiguration{}, githubadapter.ErrInvalidBrokerConfig
	}
	if brokerConfigPath == "" {
		c := setupGitHubPermissionHostConfiguration{expectedBrokerAuthority: expectedBrokerAuthority}
		return c, c.Validate()
	}
	if staticToken != "" || !validAdminDigest(expectedBrokerAuthority) {
		return setupGitHubPermissionHostConfiguration{}, githubadapter.ErrInvalidBrokerConfig
	}
	broker, err := githubruntime.LoadConfig(ctx, brokerConfigPath)
	if err != nil {
		return setupGitHubPermissionHostConfiguration{}, setupGitHubPermissionClosedError(err)
	}
	c := setupGitHubPermissionHostConfiguration{broker: broker, configured: true, expectedBrokerAuthority: expectedBrokerAuthority}
	if err := c.Validate(); err != nil {
		return setupGitHubPermissionHostConfiguration{}, err
	}
	return c, nil
}

func (c setupGitHubPermissionHostConfiguration) Validate() error {
	if !c.configured {
		if c.expectedBrokerAuthority != "" || c.broker.AuthorityIdentity() != "" {
			return githubadapter.ErrInvalidBrokerConfig
		}
		return nil
	}
	if !validSetupGitHubPermissionBrokerConfiguration(c.broker) || !validAdminDigest(c.expectedBrokerAuthority) {
		return githubadapter.ErrInvalidBrokerConfig
	}
	if c.expectedBrokerAuthority != c.broker.AuthorityIdentity() {
		return githubadapter.ErrBrokerMismatch
	}
	return nil
}

func validSetupGitHubPermissionBrokerConfiguration(c githubruntime.Configuration) bool {
	if c.Validate() != nil {
		return false
	}
	version := c.Authority().Configuration().APIVersion
	// The protected source authority already checks the exact date. Setup's
	// PermissionInspector additionally requires a year of at least 2000.
	return len(version) == 10 && version[:4] >= "2000"
}

func (c setupGitHubPermissionHostConfiguration) String() string {
	return "[redacted setup GitHub permission host]"
}
func (c setupGitHubPermissionHostConfiguration) GoString() string { return c.String() }
func (c setupGitHubPermissionHostConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, c.String())
}

type setupGitHubPermissionSessionPhase uint8

const (
	setupGitHubPermissionSessionIdle setupGitHubPermissionSessionPhase = iota + 1
	setupGitHubPermissionSessionOpening
	setupGitHubPermissionSessionReady
	setupGitHubPermissionSessionFailed
	setupGitHubPermissionSessionClosing
	setupGitHubPermissionSessionClosed
)

type setupGitHubPermissionSession struct {
	configuration     githubruntime.Configuration
	authorityIdentity string
	lifetime          context.Context
	cancel            context.CancelFunc
	getenv            func(string) string
	clock             githubadapter.BrokerClock
	mu                sync.Mutex
	phase             setupGitHubPermissionSessionPhase
	runtime           *githubruntime.Runtime
	openErr           error
	openDone          chan struct{}
	closeDone         chan struct{}
	closeResultSet    bool
	closeErr          error
}

func newSetupGitHubPermissionSession(lifetime context.Context, c githubruntime.Configuration, getenv func(string) string, clock githubadapter.BrokerClock) (*setupGitHubPermissionSession, error) {
	if setupGitHubPermissionNil(lifetime) || getenv == nil || setupGitHubPermissionNil(clock) || !validSetupGitHubPermissionBrokerConfiguration(c) {
		return nil, githubadapter.ErrInvalidBrokerConfig
	}
	if lifetime.Err() != nil {
		return nil, githubadapter.ErrBrokerUnavailable
	}
	owned, cancel := context.WithCancel(lifetime)
	return &setupGitHubPermissionSession{
		configuration: c, authorityIdentity: c.AuthorityIdentity(), lifetime: owned,
		cancel: cancel, getenv: getenv, clock: clock, phase: setupGitHubPermissionSessionIdle,
		closeDone: make(chan struct{}),
	}, nil
}

func (s *setupGitHubPermissionSession) broker(ctx context.Context, expectedBrokerAuthority string) (*githubadapter.InstallationTokenBroker, error) {
	if s == nil || setupGitHubPermissionNil(ctx) || s.lifetime == nil || s.configuration.Validate() != nil {
		return nil, githubadapter.ErrInvalidBrokerConfig
	}
	if expectedBrokerAuthority != s.authorityIdentity || !validAdminDigest(expectedBrokerAuthority) {
		return nil, githubadapter.ErrBrokerMismatch
	}
	if s.lifetime.Err() != nil {
		return nil, githubadapter.ErrBrokerClosed
	}
	if ctx.Err() != nil {
		return nil, githubadapter.ErrBrokerUnavailable
	}
	s.mu.Lock()
	if s.lifetime.Err() != nil {
		s.mu.Unlock()
		return nil, githubadapter.ErrBrokerClosed
	}
	switch s.phase {
	case setupGitHubPermissionSessionReady:
		// Runtime.Broker and native validation use only short ownership locks.
		// An invalid owned broker is never replaced with a second Runtime.
		broker := s.runtime.Broker()
		if broker == nil {
			s.mu.Unlock()
			return nil, githubadapter.ErrBrokerClosed
		}
		err := broker.Validate()
		if err == nil && (broker.AuthorityIdentity() != s.authorityIdentity || broker.Purpose() != githubadapter.IssuancePurposeSetup) {
			err = githubadapter.ErrBrokerMismatch
		}
		s.mu.Unlock()
		if err != nil {
			return nil, setupGitHubPermissionClosedError(err)
		}
		if ctx.Err() != nil {
			return nil, githubadapter.ErrBrokerUnavailable
		}
		return broker, nil
	case setupGitHubPermissionSessionFailed:
		err := s.openErr
		s.mu.Unlock()
		return nil, err
	case setupGitHubPermissionSessionOpening:
		s.mu.Unlock()
		return nil, githubadapter.ErrBrokerUnavailable
	case setupGitHubPermissionSessionClosing, setupGitHubPermissionSessionClosed:
		s.mu.Unlock()
		return nil, githubadapter.ErrBrokerClosed
	case setupGitHubPermissionSessionIdle:
		if ctx.Err() != nil {
			s.mu.Unlock()
			return nil, githubadapter.ErrBrokerUnavailable
		}
		s.phase = setupGitHubPermissionSessionOpening
		s.openDone = make(chan struct{})
	default:
		s.mu.Unlock()
		return nil, githubadapter.ErrInvalidBrokerConfig
	}
	lifetime, configuration, authority := s.lifetime, s.configuration, s.authorityIdentity
	getenv, clock := s.getenv, s.clock
	s.mu.Unlock()

	// Only this admitted opener owns any unpublished Runtime. Request context
	// cancellation never becomes the credential owner's lifetime.
	runtime, openErr := githubruntime.Open(lifetime, configuration, authority, githubadapter.IssuancePurposeSetup, getenv, clock)
	if openErr != nil {
		openErr = setupGitHubPermissionClosedError(openErr)
	}
	if runtime == nil && openErr == nil {
		openErr = githubadapter.ErrBrokerUnavailable
	}
	s.mu.Lock()
	if openErr == nil && s.phase == setupGitHubPermissionSessionOpening && lifetime.Err() == nil {
		s.runtime = runtime
		s.phase = setupGitHubPermissionSessionReady
		close(s.openDone)
		s.mu.Unlock()
		if ctx.Err() != nil {
			return nil, githubadapter.ErrBrokerUnavailable
		}
		broker := runtime.Broker()
		if broker == nil || lifetime.Err() != nil {
			return nil, githubadapter.ErrBrokerClosed
		}
		return broker, nil
	}
	s.mu.Unlock()

	// Close/cancellation won publication, or native construction failed.
	// Cleanup belongs to this opener and occurs before openDone is signalled.
	if runtime != nil {
		if err := runtime.Close(); err != nil {
			openErr = githubadapter.ErrBrokerCloseIncomplete
		}
		runtime = nil
	}
	if openErr == nil {
		openErr = githubadapter.ErrBrokerClosed
	}
	s.mu.Lock()
	s.openErr = openErr
	if s.phase == setupGitHubPermissionSessionOpening {
		s.phase = setupGitHubPermissionSessionFailed
	}
	close(s.openDone)
	s.mu.Unlock()
	return nil, openErr
}

func (s *setupGitHubPermissionSession) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closeResultSet {
		err := s.closeErr
		s.mu.Unlock()
		return err
	}
	if s.phase == setupGitHubPermissionSessionClosing {
		s.mu.Unlock()
		// This per-call result is not the first closer's memoized result.
		return githubadapter.ErrBrokerCloseIncomplete
	}
	if s.cancel == nil || s.closeDone == nil {
		s.mu.Unlock()
		return githubadapter.ErrInvalidBrokerConfig
	}
	opening := s.phase == setupGitHubPermissionSessionOpening
	openDone, runtime, cancel := s.openDone, s.runtime, s.cancel
	s.runtime = nil
	s.phase = setupGitHubPermissionSessionClosing
	s.mu.Unlock()
	cancel()

	var closeErr error
	if opening {
		// The opener cleans its own unpublished Runtime. Never add a second
		// closer goroutine or a second native Close budget on this path.
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-openDone:
			s.mu.Lock()
			if errors.Is(s.openErr, githubadapter.ErrBrokerCloseIncomplete) {
				closeErr = githubadapter.ErrBrokerCloseIncomplete
			}
			s.mu.Unlock()
		case <-timer.C:
			closeErr = githubadapter.ErrBrokerCloseIncomplete
		}
		timer.Stop()
	} else if runtime != nil {
		if err := runtime.Close(); err != nil {
			closeErr = githubadapter.ErrBrokerCloseIncomplete
		}
	} else {
		s.mu.Lock()
		if errors.Is(s.openErr, githubadapter.ErrBrokerCloseIncomplete) {
			closeErr = githubadapter.ErrBrokerCloseIncomplete
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	s.phase = setupGitHubPermissionSessionClosed
	s.closeErr, s.closeResultSet = closeErr, true
	s.getenv, s.clock, s.runtime = nil, nil, nil
	close(s.closeDone)
	s.mu.Unlock()
	return closeErr
}

func (s *setupGitHubPermissionSession) String() string {
	return "[redacted setup GitHub permission session]"
}
func (s *setupGitHubPermissionSession) GoString() string { return s.String() }
func (s *setupGitHubPermissionSession) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, s.String())
}

func setupGitHubPermissionNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func setupGitHubPermissionClosedError(err error) error {
	for _, sentinel := range []error{
		githubadapter.ErrInvalidBrokerConfig, githubadapter.ErrBrokerMismatch,
		githubadapter.ErrBrokerDenied, githubadapter.ErrBrokerUnavailable,
		githubadapter.ErrBrokerClosed, githubadapter.ErrBrokerCloseIncomplete,
		githubadapter.ErrIssuanceFenced,
	} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return githubadapter.ErrBrokerUnavailable
}
