package githubruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	github "github.com/georgejieh/open-trestle/adapters/scm/github"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

const maxIssuanceRecordBytes = 4096

type localIssuanceGuard struct{ state *localGuardState }

type localGuardState struct {
	authority     github.IssuanceAuthority
	common        github.InstallationBrokerAuthority
	directory     string
	pin           os.FileInfo
	ownerPin      os.FileInfo
	directoryFile *os.File
	ownerName     string
	recordPrefix  string
	mu            sync.Mutex
	closed        bool
	fenced        bool
	busy          bool
	finalizing    bool
	lastSequence  uint16
	lastStartedAt time.Time
	pending       github.IssuanceAttempt
	done          chan struct{}
	closeErr      error
}

func (g localIssuanceGuard) String() string             { return "[redacted GitHub issuance guard]" }
func (g localIssuanceGuard) GoString() string           { return g.String() }
func (g localIssuanceGuard) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, g.String()) }
func (g *localGuardState) String() string               { return "[redacted GitHub issuance guard state]" }
func (g *localGuardState) GoString() string             { return g.String() }
func (g *localGuardState) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, g.String()) }

var _ github.IssuanceAttemptGuard = (*localIssuanceGuard)(nil)

type issuanceOwnerRecord struct {
	Contract                string `json:"contract"`
	SchemaVersion           uint64 `json:"schema_version"`
	AuthorityIdentity       string `json:"authority_identity"`
	BrokerAuthorityIdentity string `json:"broker_authority_identity"`
	AuthorizationGeneration string `json:"authorization_generation"`
}

func (r issuanceOwnerRecord) String() string             { return "[redacted GitHub issuance owner record]" }
func (r issuanceOwnerRecord) GoString() string           { return r.String() }
func (r issuanceOwnerRecord) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }

func openLocalIssuanceGuard(ctx context.Context, directory string,
	authority github.IssuanceAuthority, common github.InstallationBrokerAuthority) (*localIssuanceGuard, error) {
	if nilDependency(ctx) || authority.Validate() != nil || common.Validate() != nil ||
		common.Identity() != authority.BrokerAuthorityIdentity() {
		return nil, github.ErrInvalidBrokerConfig
	}
	lane, err := github.NewIssuanceAuthority(common, authority.Purpose())
	if err != nil || lane.Identity() != authority.Identity() {
		return nil, github.ErrInvalidBrokerConfig
	}
	configuration := common.Configuration()
	if directory != configuration.AttemptStateDirectory || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, github.ErrInvalidBrokerConfig
	}
	if ctx.Err() != nil {
		return nil, github.ErrBrokerUnavailable
	}
	if fileauthority.CheckDirectory(directory) != nil {
		return nil, github.ErrInvalidBrokerConfig
	}
	pin, err := os.Lstat(directory)
	if err != nil {
		return nil, github.ErrInvalidBrokerConfig
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return nil, github.ErrIssuanceFenced
	}
	nameDigest := sha256.Sum256([]byte(authority.Identity()))
	g := &localIssuanceGuard{state: &localGuardState{
		authority: authority, common: common, directory: directory, pin: pin,
		directoryFile: directoryFile, ownerName: "owner-" + hex.EncodeToString(nameDigest[:]) + ".json",
		recordPrefix: hex.EncodeToString(nameDigest[:]), done: make(chan struct{}),
	}}
	if err := g.validateDirectory(); err != nil {
		if g.Close() != nil {
			return nil, github.ErrBrokerCloseIncomplete
		}
		return nil, err
	}
	content, err := json.Marshal(issuanceOwnerRecord{
		Contract: "open-trestle/github-installation-issuance-owner", SchemaVersion: 1,
		AuthorityIdentity: authority.Identity(), BrokerAuthorityIdentity: common.Identity(),
		AuthorizationGeneration: configuration.AuthorizationGeneration,
	})
	if err != nil {
		if g.Close() != nil {
			return nil, github.ErrBrokerCloseIncomplete
		}
		return nil, github.ErrInvalidBrokerConfig
	}
	if err := g.writeExclusiveRecord(ctx, g.state.ownerName, content); err != nil {
		if g.Close() != nil {
			return nil, github.ErrBrokerCloseIncomplete
		}
		return nil, err
	}
	if ctx.Err() != nil {
		if g.Close() != nil {
			return nil, github.ErrBrokerCloseIncomplete
		}
		return nil, github.ErrBrokerUnavailable
	}
	return g, nil
}

func (g *localIssuanceGuard) AuthorityIdentity() string {
	if g == nil || g.state == nil {
		return ""
	}
	return g.state.authority.Identity()
}

func (g *localIssuanceGuard) Validate() error {
	if g == nil || g.state == nil {
		return github.ErrInvalidBrokerConfig
	}
	s := g.state
	s.mu.Lock()
	closed, fenced := s.closed, s.fenced
	s.mu.Unlock()
	if closed {
		return github.ErrBrokerClosed
	}
	if fenced {
		return github.ErrIssuanceFenced
	}
	if s.authority.Validate() != nil || s.common.Validate() != nil ||
		s.authority.BrokerAuthorityIdentity() != s.common.Identity() ||
		s.directory != s.common.Configuration().AttemptStateDirectory || s.directoryFile == nil || s.pin == nil {
		return github.ErrInvalidBrokerConfig
	}
	return nil
}

func (g *localIssuanceGuard) validateDirectory() error {
	if err := g.Validate(); err != nil {
		return err
	}
	s := g.state
	if fileauthority.CheckDirectory(s.directory) != nil {
		return github.ErrIssuanceFenced
	}
	current, err := os.Lstat(s.directory)
	opened, statErr := s.directoryFile.Stat()
	if err != nil || statErr != nil || !current.IsDir() || !opened.IsDir() ||
		!os.SameFile(s.pin, current) || !os.SameFile(s.pin, opened) ||
		current.Mode() != s.pin.Mode() || opened.Mode() != s.pin.Mode() ||
		current.Mode().Perm()&0022 != 0 || !fileauthority.TrustedOwner(current) || !fileauthority.TrustedOwner(opened) {
		return github.ErrIssuanceFenced
	}
	if s.ownerPin != nil {
		owner, ownerErr := os.Lstat(filepath.Join(s.directory, s.ownerName))
		if ownerErr != nil || !sameConfigurationFile(s.ownerPin, owner) || owner.Mode().Perm() != 0600 {
			return github.ErrIssuanceFenced
		}
	}
	return g.Validate()
}

func (g *localIssuanceGuard) writeExclusiveRecord(ctx context.Context, name string, content []byte) error {
	if nilDependency(ctx) {
		return github.ErrInvalidBrokerConfig
	}
	if err := g.Validate(); err != nil {
		return err
	}
	if !g.validRecordName(name) || len(content) == 0 || len(content) > maxIssuanceRecordBytes {
		return github.ErrInvalidBrokerConfig
	}
	if ctx.Err() != nil {
		return github.ErrBrokerUnavailable
	}
	if err := g.validateDirectory(); err != nil {
		return err
	}
	path := filepath.Join(g.state.directory, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return github.ErrIssuanceFenced
	}
	// A partial or uncertain marker remains a fence; it is never unlinked.
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !fileauthority.TrustedOwner(info) {
		_ = file.Close()
		return github.ErrIssuanceFenced
	}
	written, writeErr := file.Write(content)
	syncErr := file.Sync()
	after, afterErr := file.Stat()
	closeErr := file.Close()
	directorySyncErr := g.state.directoryFile.Sync()
	current, currentErr := os.Lstat(path)
	if writeErr != nil || written != len(content) || syncErr != nil || afterErr != nil || closeErr != nil ||
		directorySyncErr != nil || currentErr != nil || !os.SameFile(info, after) || !os.SameFile(info, current) ||
		!sameConfigurationFile(after, current) || after.Mode().Perm() != 0600 || after.Size() != int64(len(content)) {
		return github.ErrIssuanceFenced
	}
	if name == g.state.ownerName {
		g.state.ownerPin = after
	}
	if err := g.validateDirectory(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return github.ErrBrokerUnavailable
	}
	return nil
}

type issuanceAttemptRecord struct {
	Contract                string     `json:"contract"`
	SchemaVersion           uint64     `json:"schema_version"`
	AuthorityIdentity       string     `json:"authority_identity"`
	BrokerAuthorityIdentity string     `json:"broker_authority_identity"`
	AuthorizationGeneration string     `json:"authorization_generation"`
	AttemptIdentity         string     `json:"attempt_identity"`
	Sequence                uint16     `json:"sequence"`
	StartedAt               time.Time  `json:"started_at"`
	State                   string     `json:"state"`
	ExpiresAt               *time.Time `json:"expires_at,omitempty"`
}

func (r issuanceAttemptRecord) String() string             { return "[redacted GitHub issuance attempt record]" }
func (r issuanceAttemptRecord) GoString() string           { return r.String() }
func (r issuanceAttemptRecord) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }

func (g *localIssuanceGuard) validRecordName(name string) bool {
	if name == g.state.ownerName {
		return true
	}
	for _, kind := range []string{"pending", "terminal"} {
		prefix := kind + "-" + g.state.recordPrefix + "-"
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".json") {
			continue
		}
		text := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".json")
		sequence, err := strconv.Atoi(text)
		return err == nil && sequence >= 1 && sequence <= 256 && text == fmt.Sprintf("%03d", sequence)
	}
	return false
}

func (g *localIssuanceGuard) writeAttemptRecord(ctx context.Context, attempt github.IssuanceAttempt, state string, expiry time.Time) error {
	s := g.state
	record := issuanceAttemptRecord{
		Contract: "open-trestle/github-installation-issuance-attempt", SchemaVersion: 1,
		AuthorityIdentity: s.authority.Identity(), BrokerAuthorityIdentity: s.common.Identity(),
		AuthorizationGeneration: s.common.Configuration().AuthorizationGeneration,
		AttemptIdentity:         attempt.Identity(), Sequence: attempt.Sequence(), StartedAt: attempt.StartedAt().UTC(), State: state,
	}
	if !expiry.IsZero() {
		value := expiry.UTC()
		record.ExpiresAt = &value
	}
	content, err := json.Marshal(record)
	if err != nil {
		return github.ErrIssuanceFenced
	}
	kind := "terminal"
	if state == "pending" {
		kind = "pending"
	}
	name := fmt.Sprintf("%s-%s-%03d.json", kind, s.recordPrefix, attempt.Sequence())
	return g.writeExclusiveRecord(ctx, name, content)
}

func (g *localIssuanceGuard) fence() {
	s := g.state
	s.mu.Lock()
	s.fenced = true
	s.mu.Unlock()
}

func (g *localIssuanceGuard) Reserve(ctx context.Context, attempt github.IssuanceAttempt) (bool, error) {
	if nilDependency(ctx) {
		return false, github.ErrInvalidBrokerConfig
	}
	if err := g.Validate(); err != nil {
		return false, err
	}
	if attempt.Validate() != nil || attempt.AuthorityIdentity() != g.AuthorityIdentity() {
		return false, github.ErrBrokerMismatch
	}
	if ctx.Err() != nil {
		g.fence()
		return false, github.ErrIssuanceFenced
	}
	s := g.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false, github.ErrBrokerClosed
	}
	if s.fenced {
		s.mu.Unlock()
		return false, github.ErrIssuanceFenced
	}
	if s.busy {
		s.mu.Unlock()
		return false, github.ErrBrokerUnavailable
	}
	if s.lastSequence >= 256 || attempt.Sequence() != s.lastSequence+1 || s.pending.Identity() != "" ||
		!s.lastStartedAt.IsZero() && attempt.StartedAt().Before(s.lastStartedAt) {
		s.fenced = true
		s.mu.Unlock()
		return false, github.ErrIssuanceFenced
	}
	s.busy = true
	s.mu.Unlock()
	defer g.finishWork()
	if err := g.writeAttemptRecord(ctx, attempt, "pending", time.Time{}); err != nil {
		g.fence()
		return false, github.ErrIssuanceFenced
	}
	canceled := ctx.Err() != nil
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.fenced = true
		return false, github.ErrBrokerClosed
	}
	if s.fenced || canceled {
		s.fenced = true
		return false, github.ErrIssuanceFenced
	}
	s.lastSequence = attempt.Sequence()
	s.lastStartedAt = attempt.StartedAt()
	s.pending = attempt
	return true, nil
}

func (g *localIssuanceGuard) Complete(ctx context.Context, attempt github.IssuanceAttempt,
	disposition github.IssuanceDisposition, expiry time.Time) error {
	if nilDependency(ctx) {
		return github.ErrInvalidBrokerConfig
	}
	if err := g.Validate(); err != nil {
		return err
	}
	if attempt.Validate() != nil || attempt.AuthorityIdentity() != g.AuthorityIdentity() {
		return github.ErrBrokerMismatch
	}
	state := ""
	switch disposition {
	case github.IssuanceAccepted:
		state = "accepted"
	case github.IssuanceRejected:
		state = "rejected"
	case github.IssuanceUnknown:
		state = "unknown"
	}
	if state == "" || disposition == github.IssuanceAccepted &&
		(expiry.IsZero() || !expiry.After(attempt.StartedAt()) || expiry.After(attempt.StartedAt().Add(time.Hour+time.Minute))) ||
		disposition != github.IssuanceAccepted && !expiry.IsZero() {
		g.fence()
		return github.ErrBrokerMismatch
	}
	if ctx.Err() != nil {
		g.fence()
		return github.ErrIssuanceFenced
	}
	s := g.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return github.ErrBrokerClosed
	}
	if s.fenced {
		s.mu.Unlock()
		return github.ErrIssuanceFenced
	}
	if s.busy {
		s.mu.Unlock()
		return github.ErrBrokerUnavailable
	}
	if s.pending.Identity() == "" || s.pending.Identity() != attempt.Identity() || s.lastSequence != attempt.Sequence() {
		s.fenced = true
		s.mu.Unlock()
		return github.ErrIssuanceFenced
	}
	s.busy = true
	s.mu.Unlock()
	defer g.finishWork()
	if err := g.writeAttemptRecord(ctx, attempt, state, expiry); err != nil {
		g.fence()
		return github.ErrIssuanceFenced
	}
	canceled := ctx.Err() != nil
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.fenced = true
		return github.ErrBrokerClosed
	}
	if s.fenced || canceled {
		s.fenced = true
		return github.ErrIssuanceFenced
	}
	s.pending = github.IssuanceAttempt{}
	if disposition != github.IssuanceAccepted {
		s.fenced = true
	}
	return nil
}

func (g *localIssuanceGuard) finishWork() {
	s := g.state
	s.mu.Lock()
	s.busy = false
	s.mu.Unlock()
	g.finalizeClose()
}

func (g *localIssuanceGuard) finalizeClose() {
	s := g.state
	s.mu.Lock()
	if !s.closed || s.busy || s.finalizing {
		s.mu.Unlock()
		return
	}
	s.finalizing = true
	s.mu.Unlock()
	var err error
	if s.directoryFile != nil && s.directoryFile.Close() != nil {
		err = github.ErrBrokerCloseIncomplete
	}
	s.mu.Lock()
	s.closeErr = err
	close(s.done)
	s.mu.Unlock()
}

func (g *localIssuanceGuard) Close() error {
	if g == nil || g.state == nil {
		return nil
	}
	s := g.state
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	g.finalizeClose()
	select {
	case <-s.done:
		return s.closeErr
	default:
		return github.ErrBrokerCloseIncomplete
	}
}
