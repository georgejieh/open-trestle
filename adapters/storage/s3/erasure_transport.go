package s3

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

// This profile is source-pinned to Go1.24.13. Fresh H1 connections and no
// replayable body exclude transport replay of application requests. It does
// not bound packets, address attempts, or provider execution.
func newOwnedErasureTransport(ctx context.Context, roots *x509.CertPool, hostname string) (*http.Transport, error) {
	deadline, ok := ctx.Deadline()
	remaining := time.Until(deadline)
	if !ok || remaining <= 0 || roots == nil || hostname == "" {
		return nil, ErrInvalidRequest
	}
	phase := min(5*time.Second, remaining)
	// getConn uses WithoutCancel in the pinned source. The dialer's explicit
	// deadline still bounds its owned work independently of that context.
	dialer := &net.Dialer{Timeout: phase, Deadline: minErasureDeadline(time.Now().Add(phase), deadline), KeepAlive: -1}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(false)
	protocols.SetUnencryptedHTTP2(false)
	return &http.Transport{
		Protocols:   protocols,
		Proxy:       nil,
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			RootCAs: roots.Clone(), ServerName: hostname, MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"}, InsecureSkipVerify: false,
		},
		TLSNextProto:      make(map[string]func(string, *tls.Conn) http.RoundTripper),
		ForceAttemptHTTP2: false,
		DisableKeepAlives: true, DisableCompression: true,
		TLSHandshakeTimeout: phase, ResponseHeaderTimeout: phase,
		MaxResponseHeaderBytes: 16384,
	}, nil
}
func minErasureDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func validErasureContext(ctx context.Context) bool {
	return ctx != nil && ctx.Err() == nil && httptrace.ContextClientTrace(ctx) == nil
}

// erasureExchange owns the only RoundTrip call in the typed path. Responses
// are consumed under their application-body ceiling and closed, never drained.
func (b *ErasureBackend) erasureExchange(request *http.Request, maximum uint32) (*http.Response, []byte, error) {
	if request == nil || !validErasureContext(request.Context()) {
		return nil, nil, ErrInvalidRequest
	}
	ctx, cancel := context.WithTimeout(request.Context(), 30*time.Second)
	defer cancel()
	request = request.Clone(ctx)
	request.GetBody = nil
	request.Close = true
	transport, err := newOwnedErasureTransport(ctx, b.roots, b.base.endpoint.Hostname())
	if err != nil {
		return nil, nil, ErrInvalidRequest
	}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, nil, ErrS3Request
	}
	content, err := readErasureResponse(response, maximum)
	if err != nil {
		return nil, nil, err
	}
	if ctx.Err() != nil {
		clear(content)
		return nil, nil, ErrS3Request
	}
	return response, content, nil
}

// Only the private ordinary compatibility client uses this adapter. Its
// fixed CheckRedirect is also required: Client.Do otherwise dispatches again.
type ownedOneShotRoundTripper struct {
	roots    *x509.CertPool
	hostname string
}

func (t *ownedOneShotRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || !validErasureContext(request.Context()) {
		return nil, ErrInvalidRequest
	}
	ctx, cancel := context.WithTimeout(request.Context(), 30*time.Second)
	owned := request.Clone(ctx)
	owned.GetBody = nil
	owned.Close = true
	transport, err := newOwnedErasureTransport(ctx, t.roots, t.hostname)
	if err != nil {
		cancel()
		return nil, ErrInvalidRequest
	}
	response, err := transport.RoundTrip(owned)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		cancel()
		transport.CloseIdleConnections()
		return nil, ErrS3Request
	}
	response.Body = &ownedErasureResponseBody{body: response.Body, cancel: cancel, transport: transport}
	return response, nil
}

type ownedErasureResponseBody struct {
	body      io.ReadCloser
	cancel    context.CancelFunc
	transport *http.Transport
	once      sync.Once
	closeErr  error
}

func (b *ownedErasureResponseBody) Read(p []byte) (int, error) { return b.body.Read(p) }
func (b *ownedErasureResponseBody) Close() error {
	b.once.Do(func() { b.closeErr = b.body.Close(); b.cancel(); b.transport.CloseIdleConnections() })
	return b.closeErr
}
