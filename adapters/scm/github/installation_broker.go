package github

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	providerconfig "github.com/georgejieh/open-trestle/internal/provider"
)

var (
	ErrInvalidBrokerConfig   = errors.New("invalid GitHub installation broker configuration")
	ErrBrokerDenied          = errors.New("GitHub installation broker denied")
	ErrBrokerMismatch        = errors.New("GitHub installation broker authority mismatch")
	ErrBrokerUnavailable     = errors.New("GitHub installation broker unavailable")
	ErrBrokerClosed          = errors.New("GitHub installation broker closed")
	ErrBrokerCloseIncomplete = errors.New("GitHub installation broker cleanup incomplete")
	ErrIssuanceFenced        = errors.New("GitHub installation issuance requires reauthorization")
)

type BrokerClock interface{ Now() time.Time }
type SystemBrokerClock struct{}

func (SystemBrokerClock) Now() time.Time { return time.Now() }

// BrokerAuthorityConfig contains public host configuration, never credential bytes.
type BrokerAuthorityConfig struct {
	TenantID, RepositoryID, RepositoryFullName                    string
	GitHubRepositoryID, InstallationID, AppID                     uint64
	RepositoryAuthority, APIEndpoint, APIVersion                  string
	ArchiveAuthorities                                            []string
	AppKeyVersion, AppPublicKeySHA256, CredentialEnvironment      string
	AuthorizationGeneration, OwnershipMode, AttemptStateDirectory string
	AllowTokenCreation, AllowDemandRenewal                        bool
}

type InstallationBrokerAuthority struct {
	config   BrokerAuthorityConfig
	identity string
}

// This policy version binds the complete signer, grant, transport and renewal contract.
const installationBrokerPolicy = "open-trestle/github-installation-broker/v1;RS256;typ=JWT;iss=decimal-app-id-string;iat=-60s;exp=+300s;RSA=2048..4096;PEM=single-PKCS1-or-PKCS8-16KiB;pin=PKIX-SHA256;selected-singleton-repository;contents=read;metadata=read;pull_requests=read;event=pull_request;unsuspended;GET-installation-before-POST;durable-reserve-before-POST;durable-accepted-before-use;no-retry;unknown-fences;single-host-exclusive;setup-runtime-lanes;attempts=256;issuer-timeout=30s;source-timeout=120s;source-operations=32;setup-operations=1;leases-per-operation=1;inflight-issuance=1;cached-grants=1;expiry-min=300s;expiry-max=3660s;use-margin=30s;renewal-demand-only=300s;minimum-issue-interval=1800s;no-proxy;no-cookies;no-redirect-follow;HTTP1;TLS12-system-roots;header-max=1MiB;response-max=1MiB;close-budget=5s"

func NewInstallationBrokerAuthority(config BrokerAuthorityConfig) (InstallationBrokerAuthority, error) {
	endpoint, err := providerconfig.ParseServiceEndpoint(config.APIEndpoint)
	if err != nil {
		return InstallationBrokerAuthority{}, ErrInvalidBrokerConfig
	}
	if _, err := providerconfig.ClassifyServiceEndpoint(config.APIEndpoint); err != nil {
		return InstallationBrokerAuthority{}, ErrInvalidBrokerConfig
	}
	config.APIEndpoint = strings.TrimSuffix(endpoint.String(), "/")
	config.ArchiveAuthorities = append([]string(nil), config.ArchiveAuthorities...)
	if validateBrokerAuthorityConfig(config) != nil {
		return InstallationBrokerAuthority{}, ErrInvalidBrokerConfig
	}
	return InstallationBrokerAuthority{config: config, identity: brokerDigest(installationBrokerPolicy, config)}, nil
}

func validateBrokerAuthorityConfig(c BrokerAuthorityConfig) error {
	if !validBrokerIdentifier(c.TenantID) || !validBrokerIdentifier(c.RepositoryID) || !validRepositoryFullName(c.RepositoryFullName) || c.RepositoryAuthority != "github.com" || !validAPIVersion(c.APIVersion) ||
		c.GitHubRepositoryID == 0 || c.GitHubRepositoryID > maxPermissionIdentifier || c.InstallationID == 0 || c.InstallationID > maxPermissionIdentifier || c.AppID == 0 || c.AppID > maxPermissionIdentifier ||
		!validBrokerIdentifier(c.AppKeyVersion) || !validDigest(c.AppPublicKeySHA256) || !validDigest(c.AuthorizationGeneration) || c.CredentialEnvironment != "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY" || c.OwnershipMode != "single_host_exclusive" || !c.AllowTokenCreation || !c.AllowDemandRenewal ||
		!filepath.IsAbs(c.AttemptStateDirectory) || filepath.Clean(c.AttemptStateDirectory) != c.AttemptStateDirectory || len(c.AttemptStateDirectory) > 4096 || strings.ContainsAny(c.AttemptStateDirectory, "\x00\r\n") {
		return ErrInvalidBrokerConfig
	}
	endpoint, err := providerconfig.ParseServiceEndpoint(c.APIEndpoint)
	if err != nil || strings.HasSuffix(endpoint.String(), "/") {
		return ErrInvalidBrokerConfig
	}
	if _, err := providerconfig.ClassifyServiceEndpoint(c.APIEndpoint); err != nil {
		return ErrInvalidBrokerConfig
	}
	canonical, _, err := canonicalArchiveAuthorities(c.ArchiveAuthorities)
	if err != nil {
		return ErrInvalidBrokerConfig
	}
	for n, authority := range canonical {
		if authority != c.ArchiveAuthorities[n] {
			return ErrInvalidBrokerConfig
		}
		if _, err := providerconfig.ClassifyServiceEndpoint("https://" + authority); err != nil {
			return ErrInvalidBrokerConfig
		}
	}
	return nil
}

func validBrokerIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.') {
			return false
		}
	}
	return true
}

func brokerDigest(contract string, value any) string {
	wire, err := json.Marshal(struct {
		Contract string
		Value    any
	}{contract, value})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

func (a InstallationBrokerAuthority) Validate() error {
	if validateBrokerAuthorityConfig(a.config) != nil || a.identity == "" || a.identity != brokerDigest(installationBrokerPolicy, a.config) {
		return ErrInvalidBrokerConfig
	}
	return nil
}
func (a InstallationBrokerAuthority) Identity() string { return a.identity }
func (a InstallationBrokerAuthority) Configuration() BrokerAuthorityConfig {
	config := a.config
	config.ArchiveAuthorities = append([]string(nil), config.ArchiveAuthorities...)
	return config
}

type IssuancePurpose string

const (
	IssuancePurposeSetup   IssuancePurpose = "setup"
	IssuancePurposeRuntime IssuancePurpose = "runtime"
)

type IssuanceAuthority struct {
	broker   InstallationBrokerAuthority
	purpose  IssuancePurpose
	identity string
}

func NewIssuanceAuthority(broker InstallationBrokerAuthority, purpose IssuancePurpose) (IssuanceAuthority, error) {
	if broker.Validate() != nil || purpose != IssuancePurposeSetup && purpose != IssuancePurposeRuntime {
		return IssuanceAuthority{}, ErrInvalidBrokerConfig
	}
	return IssuanceAuthority{broker: broker, purpose: purpose, identity: brokerDigest("open-trestle/github-issuance-lane/v1", []string{broker.Identity(), string(purpose)})}, nil
}
func (a IssuanceAuthority) Validate() error {
	expected, err := NewIssuanceAuthority(a.broker, a.purpose)
	if err != nil || a.identity != expected.identity {
		return ErrInvalidBrokerConfig
	}
	return nil
}
func (a IssuanceAuthority) Identity() string                { return a.identity }
func (a IssuanceAuthority) BrokerAuthorityIdentity() string { return a.broker.Identity() }
func (a IssuanceAuthority) Purpose() IssuancePurpose        { return a.purpose }

type IssuanceAttempt struct {
	authority IssuanceAuthority
	sequence  uint16
	startedAt time.Time
	identity  string
}

func newIssuanceAttempt(authority IssuanceAuthority, sequence uint16, startedAt time.Time) (IssuanceAttempt, error) {
	if authority.Validate() != nil || sequence == 0 || sequence > 256 || startedAt.IsZero() || startedAt.Unix() <= 0 {
		return IssuanceAttempt{}, ErrBrokerMismatch
	}
	identity := brokerDigest("open-trestle/github-issuance-attempt/v1", struct {
		Lane      string
		Sequence  uint16
		StartedAt time.Time
	}{authority.Identity(), sequence, startedAt.UTC()})
	if identity == "" {
		return IssuanceAttempt{}, ErrBrokerMismatch
	}
	return IssuanceAttempt{authority: authority, sequence: sequence, startedAt: startedAt, identity: identity}, nil
}
func (a IssuanceAttempt) Validate() error {
	expected, err := newIssuanceAttempt(a.authority, a.sequence, a.startedAt)
	if err != nil || a.identity != expected.identity {
		return ErrBrokerMismatch
	}
	return nil
}
func (a IssuanceAttempt) Identity() string          { return a.identity }
func (a IssuanceAttempt) AuthorityIdentity() string { return a.authority.Identity() }
func (a IssuanceAttempt) Sequence() uint16          { return a.sequence }
func (a IssuanceAttempt) StartedAt() time.Time      { return a.startedAt }

type IssuanceDisposition uint8

const (
	IssuanceAccepted IssuanceDisposition = iota + 1
	IssuanceRejected
	IssuanceUnknown
)

type IssuanceAttemptGuard interface {
	AuthorityIdentity() string
	Validate() error
	Reserve(context.Context, IssuanceAttempt) (bool, error)
	Complete(context.Context, IssuanceAttempt, IssuanceDisposition, time.Time) error
	Close() error
}

type InstallationBrokerConfig struct {
	Authority         InstallationBrokerAuthority
	IssuanceAuthority IssuanceAuthority
	Signer            *AppSigner
	Guard             IssuanceAttemptGuard
	Clock             BrokerClock
}

type InstallationTokenBroker struct{ *installationBrokerState }

type installationBrokerState struct {
	authority               InstallationBrokerAuthority
	lane                    IssuanceAuthority
	clock                   BrokerClock
	lifetime                context.Context
	cancel                  context.CancelFunc
	sourceClient            *http.Client
	sourceTransport         *http.Transport
	issuerClient            *http.Client
	issuerTransport         *http.Transport
	mu                      *sync.Mutex
	signer                  *AppSigner
	guard                   IssuanceAttemptGuard
	operations              map[*brokerOperation]struct{}
	closed, finalizing      bool
	done                    chan struct{}
	closeErr                error
	closeDeadline           time.Time
	issuing, samplingClock  bool
	sequence                uint16
	lastClock, lastAccepted time.Time
	terminalErr             error
	cached                  *installationGrant
}

func NewInstallationTokenBroker(lifetime context.Context, config InstallationBrokerConfig) (*InstallationTokenBroker, error) {
	if nilInterface(lifetime) || lifetime.Err() != nil || config.Authority.Validate() != nil || config.IssuanceAuthority.Validate() != nil ||
		config.IssuanceAuthority.BrokerAuthorityIdentity() != config.Authority.Identity() || config.Signer == nil || config.Signer.Validate() != nil || config.Signer.AuthorityIdentity() != config.Authority.Identity() ||
		nilInterface(config.Guard) || nilInterface(config.Clock) {
		return nil, ErrInvalidBrokerConfig
	}
	if config.Guard.Validate() != nil || config.Guard.AuthorityIdentity() != config.IssuanceAuthority.Identity() {
		return nil, ErrInvalidBrokerConfig
	}
	if lifetime.Err() != nil {
		return nil, ErrInvalidBrokerConfig
	}
	config.Signer.mu.Lock()
	if config.Signer.closed || config.Signer.claimed {
		config.Signer.mu.Unlock()
		return nil, ErrInvalidBrokerConfig
	}
	config.Signer.claimed = true
	config.Signer.mu.Unlock()
	owner, cancel := context.WithCancel(lifetime)
	sourceClient, sourceTransport := newBrokerClient(brokerSourceClient)
	issuerClient, issuerTransport := newBrokerClient(brokerIssuerClient)
	return &InstallationTokenBroker{installationBrokerState: &installationBrokerState{mu: new(sync.Mutex), authority: config.Authority, lane: config.IssuanceAuthority, clock: config.Clock, lifetime: owner, cancel: cancel,
		sourceClient: sourceClient, sourceTransport: sourceTransport, issuerClient: issuerClient, issuerTransport: issuerTransport,
		signer: config.Signer, guard: config.Guard, operations: make(map[*brokerOperation]struct{}), done: make(chan struct{})}}, nil
}
func (b *InstallationTokenBroker) AuthorityIdentity() string {
	if b == nil || b.installationBrokerState == nil {
		return ""
	}
	return b.authority.Identity()
}
func (b *InstallationTokenBroker) IssuanceAuthorityIdentity() string {
	if b == nil || b.installationBrokerState == nil {
		return ""
	}
	return b.lane.Identity()
}
func (b *InstallationTokenBroker) Purpose() IssuancePurpose {
	if b == nil || b.installationBrokerState == nil {
		return ""
	}
	return b.lane.Purpose()
}
func (b *InstallationTokenBroker) Validate() error {
	if b == nil || b.installationBrokerState == nil {
		return ErrInvalidBrokerConfig
	}
	b.mu.Lock()
	closed := b.closed || b.lifetime == nil || b.lifetime.Err() != nil
	signer, guard := b.signer, b.guard
	b.mu.Unlock()
	if closed {
		return ErrBrokerClosed
	}
	if b.authority.Validate() != nil || b.lane.Validate() != nil || b.lane.BrokerAuthorityIdentity() != b.authority.Identity() || signer == nil || nilInterface(guard) || nilInterface(b.clock) || signer.AuthorityIdentity() != b.authority.Identity() || guard.AuthorityIdentity() != b.lane.Identity() ||
		b.sourceClient == nil || b.sourceClient.Transport != b.sourceTransport || b.sourceClient.Jar != nil || b.sourceClient.Timeout != defaultRequestTimeout || !validPermissionTransport(b.sourceTransport) ||
		b.issuerClient == nil || b.issuerClient.Transport != b.issuerTransport || b.issuerClient.Jar != nil || b.issuerClient.Timeout != 30*time.Second || !validPermissionTransport(b.issuerTransport) {
		return ErrInvalidBrokerConfig
	}
	if err := signer.Validate(); err != nil {
		return err
	}
	if guard.Validate() != nil {
		return ErrIssuanceFenced
	}
	b.mu.Lock()
	closed = b.closed || b.lifetime.Err() != nil
	b.mu.Unlock()
	if closed {
		return ErrBrokerClosed
	}
	return nil
}

func (b *InstallationTokenBroker) Close() error {
	if b == nil || b.installationBrokerState == nil {
		return nil
	}
	if b.cancel == nil || b.done == nil {
		return ErrInvalidBrokerConfig
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	b.mu.Lock()
	if !b.closed {
		b.closeDeadline = time.Now().Add(5 * time.Second)
	}
	b.closed = true
	b.cached = nil
	b.mu.Unlock()
	b.cancel()
	b.finalize()
	select {
	case <-b.done:
		b.mu.Lock()
		err := b.closeErr
		b.mu.Unlock()
		return err
	case <-timer.C:
		return ErrBrokerCloseIncomplete
	}
}

// The last operation performs cleanup; there is no background finalizer.
func (b *InstallationTokenBroker) finalize() {
	b.mu.Lock()
	if !b.closed || b.finalizing || len(b.operations) != 0 || b.issuing {
		b.mu.Unlock()
		return
	}
	b.finalizing = true
	signer, guard := b.signer, b.guard
	b.signer, b.guard = nil, nil
	b.mu.Unlock()
	b.sourceTransport.CloseIdleConnections()
	b.issuerTransport.CloseIdleConnections()
	signerErr := signer.Close()
	guardErr := guard.Close()
	b.mu.Lock()
	if signerErr != nil || guardErr != nil {
		b.closeErr = ErrBrokerCloseIncomplete
	}
	close(b.done)
	b.mu.Unlock()
}

type brokerOperationContextKey struct{}
type brokerOperation struct {
	owner               *InstallationTokenBroker
	purpose             IssuancePurpose
	repository          evidence.RepositoryIdentity
	ctx                 context.Context
	cancel              context.CancelFunc
	stop                func() bool
	once                *sync.Once
	closing, borrowing  bool
	lease               *installationLease
	permissionAuthority string
}

func (b *InstallationTokenBroker) beginSource(ctx context.Context, repository evidence.RepositoryIdentity) (*brokerOperation, error) {
	if b == nil || b.installationBrokerState == nil {
		return nil, ErrInvalidBrokerConfig
	}
	namespace := repository.Namespace()
	expected, err := evidence.NewRepositoryIdentity(repository.Authority(), namespace, repository.Name())
	if err != nil || repository.Identity() != expected.Identity() || len(namespace) != 1 || repository.Authority() != b.authority.config.RepositoryAuthority || namespace[0]+"/"+repository.Name() != b.authority.config.RepositoryFullName {
		return nil, ErrBrokerMismatch
	}
	return b.beginOperation(ctx, IssuancePurposeRuntime, repository)
}
func (b *InstallationTokenBroker) beginInspection(ctx context.Context, expectedAuthority string) (*brokerOperation, error) {
	if b == nil || expectedAuthority != b.AuthorityIdentity() {
		return nil, ErrBrokerMismatch
	}
	return b.beginOperation(ctx, IssuancePurposeSetup, evidence.RepositoryIdentity{})
}
func (b *InstallationTokenBroker) beginOperation(ctx context.Context, purpose IssuancePurpose, repository evidence.RepositoryIdentity) (*brokerOperation, error) {
	if nilInterface(ctx) || ctx.Err() != nil {
		return nil, ErrBrokerUnavailable
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	if b.Purpose() != purpose {
		return nil, ErrBrokerMismatch
	}
	child, cancel := context.WithCancel(ctx)
	op := &brokerOperation{owner: b, purpose: purpose, repository: repository, cancel: cancel, once: new(sync.Once)}
	op.ctx = context.WithValue(child, brokerOperationContextKey{}, op)
	op.stop = context.AfterFunc(b.lifetime, cancel)
	limit := 32
	if purpose == IssuancePurposeSetup {
		limit = 1
	}
	b.mu.Lock()
	var err error
	if b.closed || b.lifetime.Err() != nil {
		err = ErrBrokerClosed
	} else if child.Err() != nil || len(b.operations) >= limit {
		err = ErrBrokerUnavailable
	} else {
		b.operations[op] = struct{}{}
	}
	b.mu.Unlock()
	if err != nil {
		op.stop()
		cancel()
		return nil, err
	}
	return op, nil
}
func (o *brokerOperation) Context() context.Context {
	if o == nil {
		return nil
	}
	return o.ctx
}
func (o *brokerOperation) Close() {
	if o == nil || o.once == nil {
		return
	}
	o.once.Do(func() {
		o.stop()
		o.cancel()
		o.owner.mu.Lock()
		o.closing = true
		if o.lease == nil && !o.borrowing {
			delete(o.owner.operations, o)
		}
		o.owner.mu.Unlock()
		o.owner.finalize()
	})
}
func operationFromContext(ctx context.Context, b *InstallationTokenBroker) (*brokerOperation, error) {
	if nilInterface(ctx) || b == nil {
		return nil, ErrBrokerMismatch
	}
	op, ok := ctx.Value(brokerOperationContextKey{}).(*brokerOperation)
	if !ok || op == nil || op.owner != b || op.purpose != b.Purpose() {
		return nil, ErrBrokerMismatch
	}
	b.mu.Lock()
	_, active := b.operations[op]
	active = active && !op.closing
	closed := b.closed || b.lifetime.Err() != nil
	b.mu.Unlock()
	if closed {
		return nil, ErrBrokerClosed
	}
	if !active {
		return nil, ErrBrokerMismatch
	}
	if ctx.Err() != nil || op.ctx.Err() != nil {
		return nil, ErrBrokerUnavailable
	}
	return op, nil
}

// Clock callbacks run outside the owner mutex and have a no-wait sampling gate.
func (b *InstallationTokenBroker) sampleClock() (time.Time, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return time.Time{}, ErrBrokerClosed
	}
	if b.samplingClock {
		b.mu.Unlock()
		return time.Time{}, ErrBrokerUnavailable
	}
	b.samplingClock = true
	b.mu.Unlock()
	at := b.clock.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.samplingClock = false
	if b.closed {
		return time.Time{}, ErrBrokerClosed
	}
	if at.IsZero() || at.Unix() <= 0 || !b.lastClock.IsZero() && (at.Before(b.lastClock) || at.UTC().Before(b.lastClock.UTC())) {
		b.terminalErr = ErrBrokerMismatch
		b.cached = nil
		return time.Time{}, ErrBrokerMismatch
	}
	b.lastClock = at
	return at, nil
}

func (b *InstallationTokenBroker) borrow(op *brokerOperation) (*installationLease, error) {
	if op == nil || op.owner != b {
		return nil, ErrBrokerMismatch
	}
	if _, err := operationFromContext(op.Context(), b); err != nil {
		return nil, err
	}
	b.mu.Lock()
	if b.closed || op.closing {
		b.mu.Unlock()
		return nil, ErrBrokerClosed
	}
	if op.borrowing || op.lease != nil {
		b.mu.Unlock()
		return nil, ErrBrokerUnavailable
	}
	if b.terminalErr != nil {
		err := b.terminalErr
		b.mu.Unlock()
		return nil, err
	}
	op.borrowing = true
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		op.borrowing = false
		if op.closing && op.lease == nil {
			delete(b.operations, op)
		}
		b.mu.Unlock()
		b.finalize()
	}()
	at, err := b.sampleClock()
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	if b.closed || op.closing || op.ctx.Err() != nil {
		b.mu.Unlock()
		return nil, ErrBrokerClosed
	}
	if b.terminalErr != nil {
		err := b.terminalErr
		b.mu.Unlock()
		return nil, err
	}
	usable := b.cached != nil && b.cached.validFor(b, at) == nil
	renewalDue := !usable || b.cached.expiresAt.Sub(at) <= 5*time.Minute
	renewalAllowed := b.lastAccepted.IsZero() || at.Sub(b.lastAccepted) >= 30*time.Minute && at.UTC().Sub(b.lastAccepted.UTC()) >= 30*time.Minute
	if usable && (!renewalDue || b.issuing || !renewalAllowed) {
		lease := &installationLease{owner: b, operation: op, grant: b.cached}
		op.lease = lease
		b.mu.Unlock()
		return lease, nil
	}
	if b.issuing || !renewalAllowed {
		b.mu.Unlock()
		return nil, ErrBrokerUnavailable
	}
	if b.sequence >= 256 {
		b.terminalErr, b.cached = ErrIssuanceFenced, nil
		b.mu.Unlock()
		return nil, ErrIssuanceFenced
	}
	b.issuing = true
	b.mu.Unlock()
	grant, err := b.issue(op.Context(), at)
	b.mu.Lock()
	b.issuing = false
	if b.closed || op.closing || op.ctx.Err() != nil {
		grant = nil
		if err == nil {
			err = ErrIssuanceFenced
		}
	}
	if err != nil {
		if err != ErrBrokerUnavailable {
			b.terminalErr, b.cached = err, nil
		}
		b.mu.Unlock()
		return nil, err
	}
	if grant == nil || grant.validFor(b, b.lastClock) != nil {
		b.terminalErr, b.cached = ErrBrokerMismatch, nil
		b.mu.Unlock()
		return nil, ErrBrokerMismatch
	}
	b.cached, b.lastAccepted = grant, grant.acceptedAt
	lease := &installationLease{owner: b, operation: op, grant: grant}
	op.lease = lease
	b.mu.Unlock()
	return lease, nil
}

type installationGrant struct {
	owner                                       *InstallationTokenBroker
	token                                       Token
	authority, lane                             string
	attempt                                     IssuanceAttempt
	installationID, repositoryID                uint64
	repositoryFullName                          string
	permissions                                 map[string]string
	receivedAt, acceptedAt, expiresAt, useUntil time.Time
	native, accepted                            bool
}

func (g *installationGrant) validFor(b *InstallationTokenBroker, at time.Time) error {
	if g == nil || b == nil || !g.native || !g.accepted || g.owner != b || g.token.Validate() != nil || g.authority != b.AuthorityIdentity() || g.lane != b.IssuanceAuthorityIdentity() || g.attempt.Validate() != nil || g.attempt.AuthorityIdentity() != g.lane ||
		g.installationID != b.authority.config.InstallationID || g.repositoryID != b.authority.config.GitHubRepositoryID || g.repositoryFullName != b.authority.config.RepositoryFullName || !exactBrokerPermissions(g.permissions) ||
		g.receivedAt.IsZero() || g.receivedAt.Sub(g.attempt.StartedAt()) < 0 || g.receivedAt.Sub(g.attempt.StartedAt()) > 30*time.Second || g.receivedAt.UTC().Sub(g.attempt.StartedAt().UTC()) < 0 || g.receivedAt.UTC().Sub(g.attempt.StartedAt().UTC()) > 30*time.Second || !g.expiresAt.After(g.receivedAt.Add(5*time.Minute)) || g.expiresAt.After(g.attempt.StartedAt().Add(time.Hour+time.Minute)) || !g.useUntil.Equal(g.receivedAt.Add(g.expiresAt.Sub(g.receivedAt)-30*time.Second)) ||
		g.acceptedAt.Before(g.receivedAt) || g.acceptedAt.UTC().Before(g.receivedAt.UTC()) || g.acceptedAt.Sub(g.attempt.StartedAt()) > 30*time.Second || g.acceptedAt.UTC().Sub(g.attempt.StartedAt().UTC()) > 30*time.Second ||
		at.IsZero() || at.Before(g.acceptedAt) || at.UTC().Before(g.acceptedAt.UTC()) || at.Before(g.receivedAt) || at.UTC().Before(g.receivedAt.UTC()) || !at.Before(g.expiresAt) || !at.Before(g.useUntil) || !at.UTC().Before(g.useUntil.UTC()) {
		return ErrBrokerMismatch
	}
	return nil
}

type installationLease struct {
	owner           *InstallationTokenBroker
	operation       *brokerOperation
	grant           *installationGrant
	released, bound bool
	cancel          context.CancelFunc
}

func (l *installationLease) validate(at time.Time) error {
	if l == nil || l.owner == nil || l.operation == nil {
		return ErrBrokerMismatch
	}
	b := l.owner
	b.mu.Lock()
	defer b.mu.Unlock()
	return l.validateLocked(at)
}
func (l *installationLease) validateLocked(at time.Time) error {
	b, op := l.owner, l.operation
	if l.released || op.owner != b || op.lease != l || op.closing {
		return ErrBrokerMismatch
	}
	if _, active := b.operations[op]; !active {
		return ErrBrokerMismatch
	}
	if b.closed || b.lifetime.Err() != nil {
		return ErrBrokerClosed
	}
	if op.ctx.Err() != nil {
		return ErrBrokerUnavailable
	}
	if b.terminalErr != nil && !l.bound {
		return b.terminalErr
	}
	return l.grant.validFor(b, at)
}
func (l *installationLease) release() {
	if l == nil || l.owner == nil || l.operation == nil {
		return
	}
	b := l.owner
	b.mu.Lock()
	if l.released {
		b.mu.Unlock()
		return
	}
	l.released = true
	cancel := l.cancel
	l.cancel = nil
	op := l.operation
	if op.lease == l {
		op.lease = nil
	}
	if op.closing && !op.borrowing && op.lease == nil {
		delete(b.operations, op)
	}
	l.grant = nil
	b.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	b.finalize()
}
func (l *installationLease) bindSourceRequest(request *http.Request) (*http.Request, func(), error) {
	if l == nil || l.owner == nil || l.operation == nil || request == nil || l.operation.purpose != IssuancePurposeRuntime {
		return nil, nil, ErrBrokerMismatch
	}
	b := l.owner
	if err := validateBrokerSourceRequest(b.authority, request); err != nil {
		return nil, nil, err
	}
	op, err := operationFromContext(request.Context(), b)
	if err != nil || op != l.operation {
		return nil, nil, ErrBrokerMismatch
	}
	at, err := b.sampleClock()
	if err != nil {
		return nil, nil, err
	}
	b.mu.Lock()
	if err := l.validateLocked(at); err != nil {
		b.mu.Unlock()
		return nil, nil, err
	}
	if l.bound {
		b.mu.Unlock()
		return nil, nil, ErrBrokerMismatch
	}
	l.bound = true
	grant := l.grant
	b.mu.Unlock()
	deadline := time.Now().Add(defaultRequestTimeout)
	if grant.useUntil.Before(deadline) {
		deadline = grant.useUntil
	}
	if grant.expiresAt.Add(-30 * time.Second).Before(deadline) {
		deadline = grant.expiresAt.Add(-30 * time.Second)
	}
	ctx, cancel := context.WithDeadline(request.Context(), deadline)
	if ctx.Err() != nil {
		cancel()
		l.release()
		return nil, nil, ErrBrokerUnavailable
	}
	bound := request.Clone(ctx)
	bound.Header.Set("Authorization", "Bearer "+grant.token.value)
	b.mu.Lock()
	err = l.validateLocked(at)
	if err == nil && b.terminalErr != nil {
		err = b.terminalErr
	}
	if err == nil {
		l.cancel = cancel
	}
	b.mu.Unlock()
	if err != nil {
		cancel()
		l.release()
		return nil, nil, err
	}
	return bound, func() {
		l.release()
		cancel()
	}, nil
}
func (l *installationLease) permissionObservation(permissionAuthority string) (PermissionObservation, error) {
	if l == nil || l.owner == nil || l.operation == nil || l.operation.purpose != IssuancePurposeSetup {
		return PermissionObservation{}, ErrBrokerMismatch
	}
	at, err := l.owner.sampleClock()
	if err != nil {
		return PermissionObservation{}, err
	}
	l.owner.mu.Lock()
	defer l.owner.mu.Unlock()
	if err := l.validateLocked(at); err != nil {
		return PermissionObservation{}, err
	}
	if !validDigest(permissionAuthority) || permissionAuthority != l.operation.permissionAuthority || l.bound {
		return PermissionObservation{}, ErrBrokerMismatch
	}
	g := l.grant
	observation := PermissionObservation{authorityIdentity: permissionAuthority, installationID: g.installationID, repositoryID: g.repositoryID,
		brokerAuthority: g.authority, issuanceAuthority: g.lane, attemptIdentity: g.attempt.Identity(), expiresAt: g.expiresAt, verified: true}
	observation.identity = derivePermissionObservationIdentity(observation)
	if observation.Validate() != nil {
		return PermissionObservation{}, ErrBrokerMismatch
	}
	return observation, nil
}

func validateBrokerSourceRequest(authority InstallationBrokerAuthority, r *http.Request) error {
	if authority.Validate() != nil || r == nil || r.URL == nil || r.Method != http.MethodGet || r.Body != nil && r.Body != http.NoBody || r.GetBody != nil || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || r.RequestURI != "" || r.Host != "" && r.Host != r.URL.Host {
		return ErrBrokerMismatch
	}
	endpoint, err := url.Parse(authority.config.APIEndpoint)
	if err != nil || r.URL.Scheme != endpoint.Scheme || r.URL.Host != endpoint.Host || r.URL.User != nil || r.URL.Opaque != "" || r.URL.RawPath != "" || r.URL.Fragment != "" || r.URL.RawFragment != "" || r.URL.ForceQuery {
		return ErrBrokerMismatch
	}
	for key, values := range r.Header {
		switch http.CanonicalHeaderKey(key) {
		case "X-Github-Api-Version":
			if key != http.CanonicalHeaderKey(key) || len(values) != 1 || values[0] != authority.config.APIVersion {
				return ErrBrokerMismatch
			}
		case "Accept":
			if key != "Accept" || len(values) != 1 || values[0] != permissionAccept {
				return ErrBrokerMismatch
			}
		default:
			return ErrBrokerMismatch
		}
	}
	if r.Header.Get("X-GitHub-Api-Version") != authority.config.APIVersion {
		return ErrBrokerMismatch
	}
	prefix := endpoint.Path + "/repos/" + authority.config.RepositoryFullName + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return ErrBrokerMismatch
	}
	suffix := strings.TrimPrefix(r.URL.Path, prefix)
	tree := false
	var digest string
	switch {
	case strings.HasPrefix(suffix, "git/commits/"):
		digest = strings.TrimPrefix(suffix, "git/commits/")
	case strings.HasPrefix(suffix, "git/trees/"):
		digest = strings.TrimPrefix(suffix, "git/trees/")
		tree = true
	case strings.HasPrefix(suffix, "tarball/"):
		digest = strings.TrimPrefix(suffix, "tarball/")
	default:
		return ErrBrokerMismatch
	}
	if (len(digest) != 40 && len(digest) != 64) || !validObjectID(digest, len(digest)) {
		return ErrBrokerMismatch
	}
	if tree {
		if r.URL.RawQuery != "recursive=1" {
			return ErrBrokerMismatch
		}
	} else if r.URL.RawQuery != "" {
		return ErrBrokerMismatch
	}
	return nil
}

func (b *InstallationTokenBroker) issue(ctx context.Context, startedAt time.Time) (*installationGrant, error) {
	if _, err := operationFromContext(ctx, b); err != nil {
		return nil, err
	}
	b.mu.Lock()
	admitted := b.issuing && !b.closed && b.terminalErr == nil
	signer := b.signer
	sequence := b.sequence + 1
	b.mu.Unlock()
	if !admitted || signer == nil {
		return nil, ErrBrokerClosed
	}
	cycle, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	jwt, err := signer.sign(cycle, startedAt)
	if err != nil {
		return nil, err
	}
	defer func() { jwt = Token{} }()
	if err := b.getInstallation(cycle, jwt); err != nil {
		return nil, err
	}
	attempt, err := newIssuanceAttempt(b.lane, sequence, startedAt)
	if err != nil {
		return nil, err
	}
	return b.postInstallationToken(cycle, jwt, attempt)
}

func (b *InstallationTokenBroker) issuerRequest(ctx context.Context, method, suffix string, jwt Token, body []byte) (*http.Request, error) {
	if nilInterface(ctx) || ctx.Err() != nil {
		return nil, ErrBrokerUnavailable
	}
	if jwt.Validate() != nil {
		return nil, ErrBrokerDenied
	}
	endpoint, err := url.Parse(b.authority.config.APIEndpoint)
	if err != nil {
		return nil, ErrBrokerMismatch
	}
	endpoint.Path += "/app/installations/" + strconv.FormatUint(b.authority.config.InstallationID, 10) + suffix
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrBrokerMismatch
	}
	request.GetBody = nil
	request.Header.Set("Authorization", "Bearer "+jwt.value)
	request.Header.Set("Accept", permissionAccept)
	request.Header.Set("X-GitHub-Api-Version", b.authority.config.APIVersion)
	request.Header.Set("User-Agent", "open-trestle/github-installation-broker")
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

func (b *InstallationTokenBroker) getInstallation(ctx context.Context, jwt Token) error {
	request, err := b.issuerRequest(ctx, http.MethodGet, "", jwt, nil)
	if err != nil {
		return err
	}
	response, err := b.issuerClient.Do(request)
	if err != nil || response == nil {
		if response != nil {
			drainAndClose(response.Body)
		}
		return ErrBrokerUnavailable
	}
	if response.StatusCode != http.StatusOK {
		drainAndClose(response.Body)
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 || response.StatusCode == http.StatusForbidden && (response.Header.Get("Retry-After") != "" || response.Header.Get("X-RateLimit-Remaining") == "0") {
			return ErrBrokerUnavailable
		}
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return ErrBrokerDenied
		}
		return ErrBrokerMismatch
	}
	if !isPermissionJSONResponse(response) {
		drainAndClose(response.Body)
		return ErrBrokerMismatch
	}
	content, ok := readBounded(response, maxPermissionResponseBytes)
	if !ok {
		return ErrBrokerMismatch
	}
	defer clear(content)
	fields, err := decodeSelectedObject(content, map[string]bool{"id": true, "app_id": true, "account": true, "repository_selection": true, "permissions": true, "events": true, "suspended_at": true})
	if err != nil {
		return ErrBrokerMismatch
	}
	id, idOK := decodeUint(fields["id"])
	appID, appOK := decodeUint(fields["app_id"])
	if !idOK || !appOK || id != b.authority.config.InstallationID || appID != b.authority.config.AppID {
		return ErrBrokerMismatch
	}
	account, err := decodeSelectedObject(fields["account"], map[string]bool{"login": true})
	if err != nil {
		return ErrBrokerMismatch
	}
	var login, selection string
	var events []string
	permissions, err := decodeStringMap(fields["permissions"])
	if err != nil || json.Unmarshal(account["login"], &login) != nil || json.Unmarshal(fields["repository_selection"], &selection) != nil || json.Unmarshal(fields["events"], &events) != nil {
		return ErrBrokerMismatch
	}
	observed := permissionInstallation{id: id, accountLogin: login, repositorySelection: selection, permissions: permissions, events: events,
		suspended: !bytes.Equal(bytes.TrimSpace(fields["suspended_at"]), []byte("null")), suspensionPresent: true}
	if !observed.valid(b.authority.config.InstallationID, b.authority.config.RepositoryFullName) {
		return ErrBrokerMismatch
	}
	if ctx.Err() != nil {
		return ErrBrokerUnavailable
	}
	return nil
}

func (b *InstallationTokenBroker) postInstallationToken(ctx context.Context, jwt Token, attempt IssuanceAttempt) (*installationGrant, error) {
	if attempt.Validate() != nil || attempt.AuthorityIdentity() != b.IssuanceAuthorityIdentity() {
		return nil, ErrBrokerMismatch
	}
	body, err := json.Marshal(struct {
		RepositoryIDs []uint64          `json:"repository_ids"`
		Permissions   map[string]string `json:"permissions"`
	}{[]uint64{b.authority.config.GitHubRepositoryID}, requiredGitHubPermissions()})
	if err != nil {
		return nil, ErrBrokerMismatch
	}
	request, err := b.issuerRequest(ctx, http.MethodPost, "/access_tokens", jwt, body)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	if b.closed || !b.issuing || b.terminalErr != nil || b.sequence >= 256 || attempt.Sequence() != b.sequence+1 {
		b.mu.Unlock()
		return nil, ErrIssuanceFenced
	}
	b.sequence = attempt.Sequence()
	guard := b.guard
	b.mu.Unlock()
	reserved, err := guard.Reserve(ctx, attempt)
	if err != nil || !reserved {
		return nil, ErrIssuanceFenced
	}
	if ctx.Err() != nil {
		b.completeUncertain(ctx, guard, attempt)
		return nil, ErrIssuanceFenced
	}
	response, err := b.issuerClient.Do(request)
	if err != nil || response == nil {
		if response != nil {
			drainAndClose(response.Body)
		}
		b.completeUncertain(ctx, guard, attempt)
		return nil, ErrIssuanceFenced
	}
	if response.StatusCode != http.StatusCreated {
		status := response.StatusCode
		drainAndClose(response.Body)
		if status >= 400 && status < 500 && status != http.StatusRequestTimeout && status != http.StatusTooManyRequests {
			if guard.Complete(ctx, attempt, IssuanceRejected, time.Time{}) != nil {
				return nil, ErrIssuanceFenced
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				return nil, ErrBrokerDenied
			}
			return nil, ErrBrokerMismatch
		}
		b.completeUncertain(ctx, guard, attempt)
		return nil, ErrIssuanceFenced
	}
	if !isPermissionJSONResponse(response) {
		drainAndClose(response.Body)
		b.completeUncertain(ctx, guard, attempt)
		return nil, ErrIssuanceFenced
	}
	content, ok := readBounded(response, maxPermissionResponseBytes)
	if !ok {
		b.completeUncertain(ctx, guard, attempt)
		return nil, ErrIssuanceFenced
	}
	defer clear(content)
	receivedAt, err := b.sampleClock()
	if err != nil {
		b.completeUncertain(ctx, guard, attempt)
		return nil, ErrIssuanceFenced
	}
	grant, err := b.parseInstallationGrant(content, attempt, receivedAt)
	if err != nil || ctx.Err() != nil || samePermissionToken(jwt, grant.token) {
		b.completeUncertain(ctx, guard, attempt)
		return nil, ErrIssuanceFenced
	}
	if guard.Complete(ctx, attempt, IssuanceAccepted, grant.expiresAt) != nil {
		return nil, ErrIssuanceFenced
	}
	acceptedAt, err := b.sampleClock()
	if err != nil || ctx.Err() != nil || acceptedAt.Sub(attempt.StartedAt()) > 30*time.Second || acceptedAt.UTC().Sub(attempt.StartedAt().UTC()) > 30*time.Second {
		return nil, ErrIssuanceFenced
	}
	b.mu.Lock()
	closed := b.closed || b.terminalErr != nil
	b.mu.Unlock()
	if closed {
		return nil, ErrIssuanceFenced
	}
	grant.acceptedAt, grant.accepted = acceptedAt, true
	return grant, nil
}

func (b *InstallationTokenBroker) completeUncertain(ctx context.Context, guard IssuanceAttemptGuard, attempt IssuanceAttempt) {
	deadline := time.Now().Add(5 * time.Second)
	b.mu.Lock()
	if !b.closeDeadline.IsZero() && b.closeDeadline.Before(deadline) {
		deadline = b.closeDeadline
	}
	b.mu.Unlock()
	cleanup, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	defer cancel()
	_ = guard.Complete(cleanup, attempt, IssuanceUnknown, time.Time{})
}

func (b *InstallationTokenBroker) parseInstallationGrant(body []byte, attempt IssuanceAttempt, receivedAt time.Time) (*installationGrant, error) {
	if len(body) == 0 || len(body) > maxPermissionResponseBytes || attempt.Validate() != nil || attempt.AuthorityIdentity() != b.IssuanceAuthorityIdentity() || receivedAt.IsZero() {
		return nil, ErrBrokerMismatch
	}
	elapsed := receivedAt.Sub(attempt.StartedAt())
	wallElapsed := receivedAt.UTC().Sub(attempt.StartedAt().UTC())
	if elapsed < 0 || elapsed > 30*time.Second || wallElapsed < 0 || wallElapsed > 30*time.Second {
		return nil, ErrBrokerMismatch
	}
	fields, err := decodeSelectedObject(body, nil)
	if err != nil {
		return nil, ErrBrokerMismatch
	}
	var rawToken, rawExpiry string
	if json.Unmarshal(fields["token"], &rawToken) != nil || json.Unmarshal(fields["expires_at"], &rawExpiry) != nil {
		return nil, ErrBrokerMismatch
	}
	ownedToken := []byte(rawToken)
	rawToken = ""
	token, err := NewToken(ownedToken)
	clear(ownedToken)
	if err != nil {
		return nil, ErrBrokerMismatch
	}
	expiresAt, err := time.Parse(time.RFC3339, rawExpiry)
	if err != nil || !expiresAt.After(receivedAt.Add(5*time.Minute)) || expiresAt.After(attempt.StartedAt().Add(time.Hour+time.Minute)) {
		return nil, ErrBrokerMismatch
	}
	permissions, err := decodeStringMap(fields["permissions"])
	if err != nil || !exactBrokerPermissions(permissions) {
		return nil, ErrBrokerMismatch
	}
	if selection, present := fields["repository_selection"]; present {
		var value string
		if json.Unmarshal(selection, &value) != nil || value != "selected" {
			return nil, ErrBrokerMismatch
		}
	}
	var repositories []json.RawMessage
	if json.Unmarshal(fields["repositories"], &repositories) != nil || len(repositories) != 1 {
		return nil, ErrBrokerMismatch
	}
	repository, err := decodeSelectedObject(repositories[0], map[string]bool{"id": true, "full_name": true})
	if err != nil {
		return nil, ErrBrokerMismatch
	}
	repositoryID, ok := decodeUint(repository["id"])
	var fullName string
	if !ok || repositoryID != b.authority.config.GitHubRepositoryID || json.Unmarshal(repository["full_name"], &fullName) != nil || fullName != b.authority.config.RepositoryFullName || !validRepositoryFullName(fullName) {
		return nil, ErrBrokerMismatch
	}
	return &installationGrant{owner: b, token: token, authority: b.AuthorityIdentity(), lane: b.IssuanceAuthorityIdentity(), attempt: attempt,
		installationID: b.authority.config.InstallationID, repositoryID: repositoryID, repositoryFullName: fullName, permissions: permissions,
		receivedAt: receivedAt, expiresAt: expiresAt, useUntil: receivedAt.Add(expiresAt.Sub(receivedAt) - 30*time.Second), native: true}, nil
}

func exactBrokerPermissions(permissions map[string]string) bool {
	return len(permissions) == 3 && permissions["contents"] == "read" && permissions["metadata"] == "read" && permissions["pull_requests"] == "read"
}

func (g installationGrant) String() string   { return "GitHub installation grant" }
func (g installationGrant) GoString() string { return "github.installationGrant{<redacted>}" }
func (g installationGrant) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, g.String(), g.GoString())
}

type brokerClientKind uint8

const (
	brokerSourceClient brokerClientKind = iota + 1
	brokerIssuerClient
)

func newBrokerClient(kind brokerClientKind) (*http.Client, *http.Transport) {
	transport := newPermissionTransport()
	timeout := defaultRequestTimeout
	if kind == brokerIssuerClient {
		timeout = 30 * time.Second
	}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport
}

func (v InstallationBrokerAuthority) String() string { return "GitHub InstallationBrokerAuthority" }
func (v InstallationBrokerAuthority) GoString() string {
	return "github.InstallationBrokerAuthority{<redacted>}"
}
func (v InstallationBrokerAuthority) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, v.String(), v.GoString())
}

func (v IssuanceAuthority) String() string   { return "GitHub IssuanceAuthority" }
func (v IssuanceAuthority) GoString() string { return "github.IssuanceAuthority{<redacted>}" }
func (v IssuanceAuthority) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, v.String(), v.GoString())
}

func (v IssuanceAttempt) String() string   { return "GitHub IssuanceAttempt" }
func (v IssuanceAttempt) GoString() string { return "github.IssuanceAttempt{<redacted>}" }
func (v IssuanceAttempt) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, v.String(), v.GoString())
}

func (v InstallationTokenBroker) String() string { return "GitHub InstallationTokenBroker" }
func (v InstallationTokenBroker) GoString() string {
	return "github.InstallationTokenBroker{<redacted>}"
}
func (v InstallationTokenBroker) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, v.String(), v.GoString())
}

func (v brokerOperation) String() string   { return "GitHub brokerOperation" }
func (v brokerOperation) GoString() string { return "github.brokerOperation{<redacted>}" }
func (v brokerOperation) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, v.String(), v.GoString())
}

func (v installationLease) String() string   { return "GitHub installationLease" }
func (v installationLease) GoString() string { return "github.installationLease{<redacted>}" }
func (v installationLease) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, v.String(), v.GoString())
}

func (s installationBrokerState) String() string { return "GitHub installationBrokerState" }
func (s installationBrokerState) GoString() string {
	return "github.installationBrokerState{<redacted>}"
}
func (s installationBrokerState) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, s.String(), s.GoString())
}
