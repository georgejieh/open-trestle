package s3

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

const (
	erasureTestOwner   = "123456789012"
	erasureTestBucket  = "owned-erasure-test"
	erasureTestRegion  = "us-east-1"
	erasureTestAccess  = "SYNTHETICACCESSKEY"
	erasureTestSecret  = "synthetic-not-a-real-secret-key-000000000000"
	erasureTestSession = "synthetic-session-token-not-real"
	erasureTestKey     = "objects/fixture.data"
	erasureTestVersion = "opaque+/=%2F.token"
)

func erasureTestDigest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func erasureTestExactKey(t *testing.T) artifact.ExactObjectKey {
	t.Helper()
	v, err := artifact.NewExactObjectKey(strings.Repeat("a", 64), erasureTestKey)
	if err != nil {
		t.Fatalf("exact-key positive fixture: %v", err)
	}
	return v
}

func erasureTestObjectVersion(t *testing.T, kind artifact.ObjectVersionKind, id string) artifact.ObjectVersion {
	t.Helper()
	v, err := artifact.NewObjectVersion(strings.Repeat("a", 64), erasureTestKey, kind, id)
	if err != nil {
		t.Fatalf("version positive fixture: %v", err)
	}
	return v
}

func erasureTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

type erasureTestPKI struct {
	pem  []byte
	cert tls.Certificate
}

func erasureTestCertificates(t *testing.T, wrongSAN bool) erasureTestPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic local erasure CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("127.0.0.1")
	if wrongSAN {
		ip = net.ParseIP("127.0.0.2")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{ip}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return erasureTestPKI{pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert: tls.Certificate{Certificate: [][]byte{leafDER, der}, PrivateKey: leafKey}}
}

type erasureTestRequest struct {
	method, uri, host, proto string
	headers                  http.Header
	body                     []byte
	close                    bool
	connection               int
}

type erasureTestReply struct {
	wire  string
	close bool
	reset bool
}

// Only the local server accepts scripts. The backend always owns its actual transport.
type erasureTestTLS struct {
	listener    *net.TCPListener
	pki         erasureTestPKI
	deadline    time.Time
	done        chan struct{}
	once        sync.Once
	mu          sync.Mutex
	connections map[net.Conn]int
	accepted    int
	requests    []erasureTestRequest
	alpn        []string
	hello       [][]string
	faults      []string
	script      func(erasureTestRequest, int) erasureTestReply
}

func erasureTestServer(t *testing.T, pki erasureTestPKI, script func(erasureTestRequest, int) erasureTestReply) *erasureTestTLS {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	if err := ln.SetDeadline(deadline); err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	s := &erasureTestTLS{listener: ln, pki: pki, deadline: deadline, done: make(chan struct{}), connections: make(map[net.Conn]int), script: script}
	go s.serve()
	t.Cleanup(func() { s.stop(t) })
	return s
}

func (s *erasureTestTLS) serve() {
	var workers sync.WaitGroup
	defer func() { workers.Wait(); close(s.done) }()
	for i := 0; i < 16; i++ {
		raw, err := s.listener.AcceptTCP()
		if err != nil {
			return
		}
		_ = raw.SetDeadline(s.deadline)
		s.mu.Lock()
		s.accepted++
		id := s.accepted
		s.connections[raw] = id
		s.mu.Unlock()
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer raw.Close()
			config := &tls.Config{Certificates: []tls.Certificate{s.pki.cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
			config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				s.mu.Lock()
				s.hello = append(s.hello, append([]string(nil), hello.SupportedProtos...))
				s.mu.Unlock()
				return nil, nil
			}
			conn := tls.Server(raw, config)
			ctx, cancel := context.WithDeadline(context.Background(), s.deadline)
			defer cancel()
			if err := conn.HandshakeContext(ctx); err != nil {
				return
			}
			s.mu.Lock()
			s.alpn = append(s.alpn, conn.ConnectionState().NegotiatedProtocol)
			s.mu.Unlock()
			reader := bufio.NewReader(io.LimitReader(conn, 256<<10))
			for j := 0; j < 16; j++ {
				r, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				body, readErr := io.ReadAll(io.LimitReader(r.Body, (16<<10)+1))
				closeErr := r.Body.Close()
				if readErr != nil || closeErr != nil || len(body) > 16<<10 {
					s.mu.Lock()
					s.faults = append(s.faults, "invalid or oversized request body")
					s.mu.Unlock()
					return
				}
				got := erasureTestRequest{r.Method, r.RequestURI, r.Host, r.Proto, r.Header.Clone(), append([]byte(nil), body...), r.Close, id}
				s.mu.Lock()
				s.requests = append(s.requests, got)
				index := len(s.requests) - 1
				s.mu.Unlock()
				reply := s.script(got, index)
				if reply.reset {
					_ = raw.SetLinger(0)
					return
				}
				if reply.wire != "" {
					if _, err := io.WriteString(conn, reply.wire); err != nil {
						return
					}
				}
				if reply.close {
					_ = conn.Close()
					return
				}
			}
		}()
	}
	s.mu.Lock()
	s.faults = append(s.faults, "fixture connection budget exhausted")
	s.mu.Unlock()
}

func (s *erasureTestTLS) stop(t *testing.T) {
	t.Helper()
	s.once.Do(func() {
		_ = s.listener.Close()
		s.mu.Lock()
		for conn := range s.connections {
			_ = conn.Close()
		}
		s.mu.Unlock()
	})
	timer := time.NewTimer(9 * time.Second)
	defer timer.Stop()
	select {
	case <-s.done:
	case <-timer.C:
		t.Fatal("local TLS fixture did not join within finite deadline")
	}
}

func (s *erasureTestTLS) endpoint() string { return "https://" + s.listener.Addr().String() }

func (s *erasureTestTLS) config(t *testing.T) ErasureConfig {
	t.Helper()
	creds, err := NewCredentials(erasureTestAccess, erasureTestSecret, erasureTestSession)
	if err != nil {
		t.Fatal(err)
	}
	return ErasureConfig{Endpoint: s.endpoint(), Region: erasureTestRegion, Bucket: erasureTestBucket, Credentials: creds, TrustedCAPEM: append([]byte(nil), s.pki.pem...)}
}

func (s *erasureTestTLS) backend(t *testing.T) *ErasureBackend {
	t.Helper()
	b, err := NewErasureBackend(s.config(t))
	if err != nil || b == nil {
		t.Fatalf("owned constructor positive control: %v", err)
	}
	if err := b.ValidateErasure(); err != nil {
		t.Fatalf("owned validation positive control: %v", err)
	}
	return b
}

func (s *erasureTestTLS) assertTraffic(t *testing.T, count int) []erasureTestRequest {
	t.Helper()
	s.stop(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.faults) != 0 {
		t.Fatalf("fixture faults: %v", s.faults)
	}
	if len(s.requests) != count || s.accepted != count {
		t.Fatalf("accepted HTTP=%d TCP=%d, want %d each in this local case", len(s.requests), s.accepted, count)
	}
	for _, p := range s.alpn {
		if p != "http/1.1" {
			t.Fatalf("negotiated ALPN %q, server offered h2 first", p)
		}
	}
	for _, p := range s.hello {
		if !reflect.DeepEqual(p, []string{"http/1.1"}) {
			t.Fatalf("client ALPN offer %v", p)
		}
	}
	seen := map[int]bool{}
	for _, r := range s.requests {
		if r.host != s.listener.Addr().String() {
			t.Fatalf("unexpected signed host %q", r.host)
		}
		if seen[r.connection] {
			t.Fatal("connection reused for an application request")
		}
		seen[r.connection] = true
		if r.proto != "HTTP/1.1" || !r.close {
			t.Fatalf("unexpected request profile: %s close=%t", r.proto, r.close)
		}
	}
	return append([]erasureTestRequest(nil), s.requests...)
}

func erasureTestWire(status int, headers, body string) string {
	return fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\n%s\r\n%s", status, http.StatusText(status), len(body), headers, body)
}

func erasureTestPresentWire() string {
	return erasureTestWire(200, "x-amz-version-id: "+erasureTestVersion+"\r\n", "complete-body")
}

func erasureTestPresent(t *testing.T, b *ErasureBackend) artifact.ErasureObjectRead {
	t.Helper()
	got, err := b.ReadErasureObject(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, 4096)
	if err != nil || got.Kind != artifact.ErasureReadPresent || string(got.Object.Content) != "complete-body" || got.Object.Version != "version:"+erasureTestVersion || got.Object.Digest != erasureTestDigest([]byte("complete-body")) || !reflect.DeepEqual(got.Marker, artifact.ObjectVersion{}) {
		t.Fatalf("actual TLS present positive control failed: kind=%v err=%v", got.Kind, err)
	}
	return got
}

func erasureTestFixedError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, fixed := range []error{ErrInvalidConfig, ErrInvalidRequest, ErrS3Request, artifact.ErrErasureBackendUnsupported, artifact.ErrErasureBlocked, artifact.ErrRemoteObjectConflict, artifact.ErrRemoteObjectIntegrity, artifact.ErrRemoteObjectTooLarge} {
		if err.Error() == fixed.Error() {
			return
		}
	}
	t.Fatal("adapter returned non-fixed error text")
}

func erasureTestZeroRead(t *testing.T, got artifact.ErasureObjectRead, err error) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(got, artifact.ErasureObjectRead{}) {
		t.Fatalf("refusal must return zero observation, err=%v kind=%v", err, got.Kind)
	}
	erasureTestFixedError(t, err)
}

func erasureTestZeroPage(t *testing.T, got artifact.VersionPage, err error) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(got, artifact.VersionPage{}) {
		t.Fatalf("refusal must return zero page, err=%v entries=%d", err, len(got.Entries))
	}
	erasureTestFixedError(t, err)
}

// SigV4 oracle does not call product canonicalization or signing helpers.
func erasureTestSigned(t *testing.T, r erasureTestRequest, method, path string, query url.Values, owner bool) {
	t.Helper()
	if r.method != method {
		t.Fatalf("method %q want %q", r.method, method)
	}
	if method != "PUT" && len(r.body) != 0 {
		t.Fatal("body on non-create request")
	}
	u, err := url.ParseRequestURI(r.uri)
	if err != nil {
		t.Fatal(err)
	}
	wantQuery := strings.ReplaceAll(query.Encode(), "+", "%20")
	if u.EscapedPath() != path || u.RawQuery != wantQuery {
		t.Fatalf("request URI %q want %q query=%q", r.uri, path, wantQuery)
	}
	for _, h := range []string{"Range", "Expect", "Upgrade", "Idempotency-Key", "X-Idempotency-Key", "Cookie", "Trailer", "X-Amz-Bypass-Governance-Retention", "X-Amz-Mfa", "X-Amz-Request-Payer"} {
		if _, ok := r.headers[http.CanonicalHeaderKey(h)]; ok {
			t.Fatalf("forbidden request header %s", h)
		}
	}
	if a := r.headers.Get("Accept-Encoding"); a != "" && a != "identity" {
		t.Fatalf("encoding %q", a)
	}
	if owner && r.headers.Get("X-Amz-Expected-Bucket-Owner") != erasureTestOwner {
		t.Fatal("missing expected owner")
	}
	if r.headers.Get("X-Amz-Security-Token") != erasureTestSession {
		t.Fatal("static synthetic session not used")
	}
	if r.headers.Get("X-Amz-Content-Sha256") != erasureTestDigest(r.body) {
		t.Fatal("signed payload digest is not actual body digest")
	}
	at, err := time.Parse("20060102T150405Z", r.headers.Get("X-Amz-Date"))
	if err != nil || time.Since(at) > time.Minute || time.Until(at) > time.Minute {
		t.Fatal("signing time incompatible with current wall clock")
	}
	auth := r.headers.Get("Authorization")
	date := at.Format("20060102")
	scope := date + "/" + erasureTestRegion + "/s3/aws4_request"
	prefix := "AWS4-HMAC-SHA256 Credential=" + erasureTestAccess + "/" + scope + ", SignedHeaders="
	if !strings.HasPrefix(auth, prefix) {
		t.Fatal("wrong SigV4 credential scope")
	}
	parts := strings.Split(strings.TrimPrefix(auth, prefix), ", Signature=")
	if len(parts) != 2 {
		t.Fatal("invalid SigV4 fields")
	}
	names := strings.Split(parts[0], ";")
	if !sort.StringsAreSorted(names) {
		t.Fatal("unsorted signed headers")
	}
	required := []string{"host", "x-amz-content-sha256", "x-amz-date", "x-amz-security-token"}
	if owner {
		required = append(required, "x-amz-expected-bucket-owner")
	}
	if owner && method == "GET" && query.Get("max-keys") == "" {
		required = append(required, "x-amz-checksum-mode")
	}
	if method == "PUT" {
		required = append(required, "if-none-match", "content-type", "x-amz-checksum-sha256")
	}
	for _, name := range required {
		found := false
		for _, n := range names {
			found = found || n == name
		}
		if !found {
			t.Fatalf("unsigned required header %s", name)
		}
	}
	var canonical strings.Builder
	seen := map[string]bool{}
	for _, name := range names {
		if name != strings.ToLower(name) || seen[name] {
			t.Fatal("noncanonical signed header name")
		}
		seen[name] = true
		values := r.headers.Values(name)
		if name == "host" {
			values = []string{r.host}
		}
		if len(values) != 1 {
			t.Fatalf("signed header %s must occur once", name)
		}
		for i := range values {
			values[i] = strings.Join(strings.Fields(values[i]), " ")
		}
		canonical.WriteString(name + ":" + strings.Join(values, ",") + "\n")
	}
	canonicalRequest := strings.Join([]string{method, path, wantQuery, canonical.String(), parts[0], erasureTestDigest(r.body)}, "\n")
	toSign := "AWS4-HMAC-SHA256\n" + r.headers.Get("X-Amz-Date") + "\n" + scope + "\n" + erasureTestDigest([]byte(canonicalRequest))
	mac := func(key []byte, text string) []byte {
		m := hmac.New(sha256.New, key)
		_, _ = m.Write([]byte(text))
		return m.Sum(nil)
	}
	key := mac([]byte("AWS4"+erasureTestSecret), date)
	key = mac(key, erasureTestRegion)
	key = mac(key, "s3")
	key = mac(key, "aws4_request")
	if parts[1] != hex.EncodeToString(mac(key, toSign)) {
		t.Fatal("SigV4 signature mismatch")
	}
	if method == "PUT" && r.headers.Get("Content-Length") != strconv.Itoa(len(r.body)) {
		t.Fatal("PUT content length not exact")
	}
}

func erasureTestReadCase(t *testing.T, wire string, maximum uint32, check func(artifact.ErasureObjectRead, error)) {
	t.Helper()
	s := erasureTestServer(t, erasureTestCertificates(t, false), func(_ erasureTestRequest, index int) erasureTestReply {
		if index == 0 {
			return erasureTestReply{wire: erasureTestPresentWire()}
		}
		return erasureTestReply{wire: wire, close: true}
	})
	b := s.backend(t)
	erasureTestPresent(t, b)
	got, err := b.ReadErasureObject(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, maximum)
	check(got, err)
	for _, r := range s.assertTraffic(t, 2) {
		erasureTestSigned(t, r, "GET", "/"+erasureTestBucket+"/"+erasureTestKey, nil, true)
		if r.headers.Get("X-Amz-Checksum-Mode") != "ENABLED" {
			t.Fatal("checksum-mode missing")
		}
	}
}

func erasureTestXMLText(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
