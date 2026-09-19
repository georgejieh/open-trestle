package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskmsclient "github.com/aws/aws-sdk-go-v2/service/kms"
	awskms "github.com/georgejieh/open-trestle/adapters/keys/awskms"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/provider"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

type setupKMSExecutor func(context.Context, string, string, string, string, string, string, string) error
type setupKMSProbe struct {
	environment                                           func(string) string
	tenantID, region, keyARN, endpoint, authorityIdentity string
	execute                                               setupKMSExecutor
}

func newSetupKMSProbe(environment func(string) string, tenantID, region, keyARN, endpoint string, execute setupKMSExecutor) (*setupKMSProbe, string, error) {
	if environment == nil || execute == nil {
		return nil, "", errors.New("invalid KMS setup probe")
	}
	authority, err := awskms.ConfigurationIdentity(region, []awskms.TenantKey{{TenantID: tenantID, KeyARN: keyARN}})
	if err != nil {
		return nil, "", err
	}
	normalized := ""
	if endpoint != "" {
		parsed, parseErr := provider.ParseServiceEndpoint(endpoint)
		if parseErr != nil {
			return nil, "", parseErr
		}
		if _, classifyErr := provider.ClassifyServiceEndpoint(endpoint); classifyErr != nil {
			return nil, "", classifyErr
		}
		normalized = parsed.String()
	}
	return &setupKMSProbe{environment, tenantID, region, keyARN, normalized, authority, execute}, authority, nil
}
func (p *setupKMSProbe) ConfigurationIdentity() string {
	if p == nil {
		return ""
	}
	authority := p.AuthorityIdentity()
	if authority == "" {
		return ""
	}
	normalized := ""
	if p.endpoint != "" {
		parsed, err := provider.ParseServiceEndpoint(p.endpoint)
		if err != nil || parsed.String() != p.endpoint {
			return ""
		}
		if _, classifyErr := provider.ClassifyServiceEndpoint(p.endpoint); classifyErr != nil {
			return ""
		}
		normalized = parsed.String()
	}
	return deriveSetupKMSProbeIdentity(authority, normalized)
}
func (p *setupKMSProbe) AuthorityIdentity() string {
	if p == nil {
		return ""
	}
	authority, err := awskms.ConfigurationIdentity(p.region, []awskms.TenantKey{{TenantID: p.tenantID, KeyARN: p.keyARN}})
	if err != nil || authority != p.authorityIdentity {
		return ""
	}
	return authority
}
func deriveSetupKMSProbeIdentity(authority, endpoint string) string {
	sum := sha256.Sum256([]byte("open-trestle/setup-kms-probe/v1\x00" + authority + "\x00" + endpoint + "\x00OPEN_TRESTLE_AWS_ACCESS_KEY_ID\x00OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY\x00OPEN_TRESTLE_AWS_SESSION_TOKEN"))
	return hex.EncodeToString(sum[:])
}
func (p *setupKMSProbe) Probe(ctx context.Context) setupcore.SecretBackendProbeResult {
	if p == nil || p.environment == nil || p.execute == nil || ctx == nil || ctx.Err() != nil {
		return setupcore.NewInvalidSecretBackendProbeResult()
	}
	access := p.environment("OPEN_TRESTLE_AWS_ACCESS_KEY_ID")
	secret := p.environment("OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY")
	session := p.environment("OPEN_TRESTLE_AWS_SESSION_TOKEN")
	if ctx.Err() != nil {
		return setupcore.NewUnavailableSecretBackendProbeResult()
	}
	if !validSetupAWSCredential(access, 8, 128) || !validSetupAWSCredential(secret, 32, 512) || session != "" && !validSetupAWSCredential(session, 16, 4096) {
		return setupcore.NewInvalidSecretBackendProbeResult()
	}
	err := p.execute(ctx, p.tenantID, p.region, p.keyARN, p.endpoint, access, secret, session)
	if ctx.Err() != nil {
		return setupcore.NewUnavailableSecretBackendProbeResult()
	}
	if err == nil {
		return setupcore.NewVerifiedSecretBackendProbeResult(p.authorityIdentity)
	}
	if errors.Is(err, awskms.ErrKMSUnavailable) {
		return setupcore.NewUnavailableSecretBackendProbeResult()
	}
	return setupcore.NewInvalidSecretBackendProbeResult()
}
func (p *setupKMSProbe) String() string   { return "setup KMS secret backend probe" }
func (p *setupKMSProbe) GoString() string { return "main.setupKMSProbe{<redacted>}" }
func (p *setupKMSProbe) Format(state fmt.State, verb rune) {
	value := p.String()
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = p.GoString()
	}
	_, _ = state.Write([]byte(value))
}

func validSetupAWSCredential(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, candidate := range value {
		if candidate < 0x21 || candidate == 0x7f {
			return false
		}
	}
	return true
}

func newSetupDirectTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.ForceAttemptHTTP2 = false
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	transport.Protocols = protocols
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.MaxResponseHeaderBytes = 1 << 20
	return transport
}
func newSetupKMSProvider(tenantID, region, keyARN, endpoint, access, secret, session string) (*awskms.Provider, *http.Transport, error) {
	transport := newSetupDirectTransport()
	client := &http.Client{Transport: setupKMSBoundedTransport{transport, 1 << 20}, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return awskms.ErrKMSUnavailable }}
	credentials := aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: access, SecretAccessKey: secret, SessionToken: session, Source: "open-trestle-setup"}, nil
	}))
	configuration := aws.Config{Region: region, Credentials: credentials, HTTPClient: client, RetryMaxAttempts: 3, RetryMode: aws.RetryModeStandard}
	kmsClient := awskmsclient.NewFromConfig(configuration, func(options *awskmsclient.Options) {
		if endpoint != "" {
			options.BaseEndpoint = aws.String(endpoint)
		}
	})
	keyProvider, err := awskms.New(kmsClient, region, []awskms.TenantKey{{TenantID: tenantID, KeyARN: keyARN}})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, err
	}
	return keyProvider, transport, nil
}
func executeSetupKMS(ctx context.Context, tenantID, region, keyARN, endpoint, access, secret, session string) error {
	if ctx == nil || ctx.Err() != nil {
		return awskms.ErrKMSUnavailable
	}
	keyProvider, transport, err := newSetupKMSProvider(tenantID, region, keyARN, endpoint, access, secret, session)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	return artifact.VerifyEnvelopeKeyProvider(ctx, tenantID, keyProvider)
}

type setupKMSBoundedTransport struct {
	inner   http.RoundTripper
	maximum int64
}

func (t setupKMSBoundedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.inner == nil || t.maximum <= 0 {
		return nil, awskms.ErrKMSUnavailable
	}
	response, err := t.inner.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response == nil || response.Body == nil || response.ContentLength > t.maximum {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, awskms.ErrKMSUnavailable
	}
	response.Body = &setupKMSBoundedBody{response.Body, t.maximum}
	return response, nil
}

type setupKMSBoundedBody struct {
	inner     io.ReadCloser
	remaining int64
}

func (b *setupKMSBoundedBody) Read(buffer []byte) (int, error) {
	if b == nil || b.inner == nil {
		return 0, awskms.ErrKMSUnavailable
	}
	if b.remaining == 0 {
		var probe [1]byte
		count, err := b.inner.Read(probe[:])
		if count != 0 {
			return 0, awskms.ErrKMSUnavailable
		}
		return 0, err
	}
	if int64(len(buffer)) > b.remaining {
		buffer = buffer[:b.remaining]
	}
	count, err := b.inner.Read(buffer)
	b.remaining -= int64(count)
	return count, err
}
func (b *setupKMSBoundedBody) Close() error {
	if b == nil || b.inner == nil {
		return awskms.ErrKMSUnavailable
	}
	return b.inner.Close()
}
