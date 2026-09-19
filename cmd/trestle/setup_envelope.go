package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	awskms "github.com/georgejieh/open-trestle/adapters/keys/awskms"
	s3store "github.com/georgejieh/open-trestle/adapters/storage/s3"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

type setupEnvelopeExecution struct {
	configuration                                                   setupEnvelopeConfiguration
	rootIdentity, repositoryID                                      string
	createdAt                                                       time.Time
	s3Access, s3Secret, s3Session, kmsAccess, kmsSecret, kmsSession string
}

func (e *setupEnvelopeExecution) clear() {
	if e == nil {
		return
	}
	e.s3Access = ""
	e.s3Secret = ""
	e.s3Session = ""
	e.kmsAccess = ""
	e.kmsSecret = ""
	e.kmsSession = ""
}
func (e setupEnvelopeExecution) String() string   { return "setup envelope storage execution" }
func (e setupEnvelopeExecution) GoString() string { return "main.setupEnvelopeExecution{<redacted>}" }
func (e setupEnvelopeExecution) Format(state fmt.State, verb rune) {
	writeSetupEnvelopeFormat(state, verb, e.String(), e.GoString())
}

type setupEnvelopeExecutor func(context.Context, setupEnvelopeExecution) (string, error)
type setupEnvelopeStorageProbe struct {
	environment            func(string) string
	planRoot, repositoryID string
	createdAt              time.Time
	configuration          setupEnvelopeConfiguration
	authorityIdentity      string
	execute                setupEnvelopeExecutor
}

func newSetupEnvelopeStorageProbe(environment func(string) string, plan setupcore.Plan, configuration setupEnvelopeConfiguration, execute setupEnvelopeExecutor) (*setupEnvelopeStorageProbe, string, error) {
	if environment == nil || execute == nil || plan.Validate() != nil || configuration.tenantID != plan.TenantID() {
		return nil, "", errors.New("invalid envelope storage setup probe")
	}
	authority, _, _, err := deriveSetupEnvelopeAuthority(configuration)
	if err != nil {
		return nil, "", err
	}
	probe := &setupEnvelopeStorageProbe{environment, plan.RootIdentity(), plan.RepositoryID(), plan.CreatedAt(), configuration, authority, execute}
	if probe.ConfigurationIdentity() == "" {
		return nil, "", errors.New("invalid envelope storage setup probe")
	}
	return probe, authority, nil
}
func (p *setupEnvelopeStorageProbe) AuthorityIdentity() string {
	if p == nil {
		return ""
	}
	authority, _, _, err := deriveSetupEnvelopeAuthority(p.configuration)
	if err != nil || authority != p.authorityIdentity {
		return ""
	}
	return authority
}
func (p *setupEnvelopeStorageProbe) ConfigurationIdentity() string {
	if p == nil || p.planRoot == "" || p.repositoryID == "" || p.createdAt.IsZero() {
		return ""
	}
	authority := p.AuthorityIdentity()
	if authority == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("open-trestle/setup-envelope-storage-probe/v1\x00" + authority + "\x00" + p.planRoot + "\x00" + p.repositoryID + "\x00" + p.createdAt.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(sum[:])
}
func (p *setupEnvelopeStorageProbe) Probe(ctx context.Context) setupcore.EnvelopeStorageProbeResult {
	if p == nil || p.environment == nil || p.execute == nil || ctx == nil || ctx.Err() != nil || p.ConfigurationIdentity() == "" {
		return setupcore.NewInvalidEnvelopeStorageProbeResult()
	}
	execution := setupEnvelopeExecution{configuration: p.configuration, rootIdentity: p.planRoot, repositoryID: p.repositoryID, createdAt: p.createdAt}
	defer execution.clear()
	execution.s3Access = p.environment("OPEN_TRESTLE_S3_ACCESS_KEY_ID")
	execution.s3Secret = p.environment("OPEN_TRESTLE_S3_SECRET_ACCESS_KEY")
	execution.s3Session = p.environment("OPEN_TRESTLE_S3_SESSION_TOKEN")
	execution.kmsAccess = p.environment("OPEN_TRESTLE_AWS_ACCESS_KEY_ID")
	execution.kmsSecret = p.environment("OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY")
	execution.kmsSession = p.environment("OPEN_TRESTLE_AWS_SESSION_TOKEN")
	if ctx.Err() != nil {
		return setupcore.NewUnavailableEnvelopeStorageProbeResult()
	}
	if execution.s3Access == execution.kmsAccess || !validSetupAWSCredential(execution.s3Access, 8, 128) || !validSetupAWSCredential(execution.s3Secret, 32, 512) || execution.s3Session != "" && !validSetupAWSCredential(execution.s3Session, 16, 4096) || !validSetupAWSCredential(execution.kmsAccess, 8, 128) || !validSetupAWSCredential(execution.kmsSecret, 32, 512) || execution.kmsSession != "" && !validSetupAWSCredential(execution.kmsSession, 16, 4096) {
		return setupcore.NewInvalidEnvelopeStorageProbeResult()
	}
	conformance, err := p.execute(ctx, execution)
	if ctx.Err() != nil {
		return setupcore.NewUnavailableEnvelopeStorageProbeResult()
	}
	if err == nil {
		if !validAdminDigest(conformance) {
			return setupcore.NewInvalidEnvelopeStorageProbeResult()
		}
		return setupcore.NewVerifiedEnvelopeStorageProbeResult(p.authorityIdentity, conformance)
	}
	if errors.Is(err, s3store.ErrS3Request) || errors.Is(err, artifact.ErrRemoteStorePersistence) || errors.Is(err, artifact.ErrEnvelopeKeyUnavailable) || errors.Is(err, awskms.ErrKMSUnavailable) {
		return setupcore.NewUnavailableEnvelopeStorageProbeResult()
	}
	return setupcore.NewInvalidEnvelopeStorageProbeResult()
}
func (p *setupEnvelopeStorageProbe) String() string { return "setup envelope storage probe" }
func (p *setupEnvelopeStorageProbe) GoString() string {
	return "main.setupEnvelopeStorageProbe{<redacted>}"
}
func (p *setupEnvelopeStorageProbe) Format(state fmt.State, verb rune) {
	writeSetupEnvelopeFormat(state, verb, p.String(), p.GoString())
}
func writeSetupEnvelopeFormat(state fmt.State, verb rune, plain, syntax string) {
	value := plain
	if verb == 'q' {
		value = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		value = syntax
	}
	_, _ = state.Write([]byte(value))
}
func executeSetupEnvelopeStorage(ctx context.Context, value setupEnvelopeExecution) (string, error) {
	if ctx == nil || ctx.Err() != nil {
		return "", artifact.ErrRemoteStorePersistence
	}
	authority, s3Authority, kmsAuthority, err := deriveSetupEnvelopeAuthority(value.configuration)
	if err != nil {
		return "", err
	}
	s3Credentials, err := s3store.NewCredentials(value.s3Access, value.s3Secret, value.s3Session)
	if err != nil {
		return "", err
	}
	s3Provider, err := s3store.NewStaticCredentialsProvider(s3Credentials)
	if err != nil {
		return "", err
	}
	s3Transport := newSetupDirectTransport()
	defer s3Transport.CloseIdleConnections()
	s3Client := &http.Client{Transport: s3Transport, Timeout: 30 * time.Second}
	backend, err := s3store.New(s3store.Config{Endpoint: value.configuration.s3Endpoint, Region: value.configuration.s3Region, Bucket: value.configuration.s3Bucket, Credentials: s3Provider, HTTPClient: s3Client})
	if err != nil {
		return "", err
	}
	if backend.ConfigurationIdentity() != s3Authority || backend.Validate() != nil {
		return "", s3store.ErrInvalidConfig
	}
	keyProvider, kmsTransport, err := newSetupKMSProvider(value.configuration.tenantID, value.configuration.kmsRegion, value.configuration.kmsKeyARN, value.configuration.kmsEndpoint, value.kmsAccess, value.kmsSecret, value.kmsSession)
	if err != nil {
		return "", err
	}
	if keyProvider.ConfigurationIdentity() != kmsAuthority || keyProvider.Validate() != nil {
		kmsTransport.CloseIdleConnections()
		return "", awskms.ErrInvalidKMSProvider
	}
	defer kmsTransport.CloseIdleConnections()
	store, err := artifact.NewEnvelopeStore(value.configuration.s3Prefix, backend, keyProvider)
	if err != nil {
		return "", err
	}
	scope, err := audit.NewReviewScope(value.configuration.tenantID, value.repositoryID, value.rootIdentity)
	if err != nil {
		return "", err
	}
	receipt, err := artifact.VerifyEnvelopeStorageConformance(ctx, store, scope, authority, value.createdAt)
	if err != nil {
		return "", err
	}
	return receipt.Identity(), nil
}
