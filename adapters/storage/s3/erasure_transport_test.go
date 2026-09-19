package s3

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http/httptrace"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

func TestErasureConstructorStrictExplicitTrust(t *testing.T) {
	pki := erasureTestCertificates(t, false)
	s := erasureTestServer(t, pki, func(_ erasureTestRequest, _ int) erasureTestReply {
		return erasureTestReply{wire: erasureTestPresentWire()}
	})
	cfg := s.config(t)
	b, err := NewErasureBackend(cfg)
	if err != nil || b == nil {
		t.Fatalf("positive constructor: %v", err)
	}
	identity, identityErr := ConfigurationIdentity(cfg.Endpoint, cfg.Region, cfg.Bucket)
	if identityErr != nil || b.ConfigurationIdentity() != identity {
		t.Fatal("existing configuration identity changed")
	}
	s.mu.Lock()
	n := s.accepted
	s.mu.Unlock()
	if n != 0 {
		t.Fatal("constructor performed local endpoint I/O")
	}
	clear(cfg.TrustedCAPEM)
	erasureTestPresent(t, b)
	for _, count := range []int{1, 64} {
		c := s.config(t)
		c.TrustedCAPEM = bytes.Repeat(pki.pem, count)
		owned, err := NewErasureBackend(c)
		if err != nil || owned == nil {
			t.Fatalf("%d explicit certificates refused: %v", count, err)
		}
		if owned.ConfigurationIdentity() != b.ConfigurationIdentity() {
			t.Fatal("CA data changed existing configuration identity")
		}
	}
	capConfig := s.config(t)
	capConfig.TrustedCAPEM = append(append([]byte(nil), pki.pem...), bytes.Repeat([]byte(" "), 262144-len(pki.pem))...)
	if value, err := NewErasureBackend(capConfig); err != nil || value == nil {
		t.Fatalf("exact CA byte cap positive: %v", err)
	}
	block, _ := pem.Decode(pki.pem)
	cases := []struct {
		name   string
		change func(*ErasureConfig)
	}{
		{"empty-ca", func(c *ErasureConfig) { c.TrustedCAPEM = nil }},
		{"whitespace-ca", func(c *ErasureConfig) { c.TrustedCAPEM = []byte(" \n\t") }},
		{"prefix-junk", func(c *ErasureConfig) { c.TrustedCAPEM = append([]byte("junk"), pki.pem...) }},
		{"suffix-junk", func(c *ErasureConfig) { c.TrustedCAPEM = append(append([]byte(nil), pki.pem...), []byte("junk")...) }},
		{"wrong-pem-type", func(c *ErasureConfig) {
			c.TrustedCAPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block.Bytes})
		}},
		{"invalid-certificate", func(c *ErasureConfig) {
			c.TrustedCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")})
		}},
		{"certificate-65", func(c *ErasureConfig) { c.TrustedCAPEM = bytes.Repeat(pki.pem, 65) }},
		{"ca-over-byte-cap", func(c *ErasureConfig) {
			c.TrustedCAPEM = append(append([]byte(nil), pki.pem...), bytes.Repeat([]byte(" "), 262145-len(pki.pem))...)
		}},
		{"http-even-loopback", func(c *ErasureConfig) { c.Endpoint = strings.Replace(c.Endpoint, "https:", "http:", 1) }},
		{"endpoint-path", func(c *ErasureConfig) { c.Endpoint += "/objects" }},
		{"endpoint-query", func(c *ErasureConfig) { c.Endpoint += "?secret=synthetic" }},
		{"endpoint-userinfo", func(c *ErasureConfig) { c.Endpoint = strings.Replace(c.Endpoint, "https://", "https://synthetic@", 1) }},
		{"bucket", func(c *ErasureConfig) { c.Bucket = "Invalid" }},
		{"region", func(c *ErasureConfig) { c.Region = "Invalid" }},
		{"credentials", func(c *ErasureConfig) { c.Credentials = Credentials{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := s.config(t)
			tc.change(&c)
			got, err := NewErasureBackend(c)
			if got != nil || !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("invalid constructor returned backend=%t err=%v", got != nil, err)
			}
		})
	}
	if !errors.Is((new(ErasureBackend)).ValidateErasure(), ErrInvalidConfig) || !errors.Is((new(ErasureBackend)).Validate(), ErrInvalidConfig) {
		t.Fatal("zero backend admitted")
	}
	var nilBackend *ErasureBackend
	if !errors.Is(nilBackend.ValidateErasure(), ErrInvalidConfig) || !errors.Is(nilBackend.Validate(), ErrInvalidConfig) {
		t.Fatal("nil backend admitted")
	}
	s.assertTraffic(t, 1)
}

func TestErasurePublicSurfaceHasNoMutableAuthority(t *testing.T) {
	typ := reflect.TypeOf(ErasureConfig{})
	want := map[string]reflect.Type{"Endpoint": reflect.TypeOf(""), "Region": reflect.TypeOf(""), "Bucket": reflect.TypeOf(""), "Credentials": reflect.TypeOf(Credentials{}), "TrustedCAPEM": reflect.TypeOf([]byte(nil))}
	if typ.NumField() != len(want) {
		t.Fatal("ErasureConfig gained an unreviewed field")
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Anonymous || f.PkgPath != "" || want[f.Name] != f.Type {
			t.Fatalf("unexpected config field %s", f.Name)
		}
	}
	owned := reflect.TypeOf(ErasureBackend{})
	for i := 0; i < owned.NumField(); i++ {
		f := owned.Field(i)
		if f.PkgPath == "" {
			t.Fatalf("exported backend state %s", f.Name)
		}
	}
	methods := map[string]bool{"Validate": true, "ValidateErasure": true, "ConfigurationIdentity": true, "Create": true, "Read": true, "Delete": true, "ReadErasureObject": true, "CreateErasureObject": true, "ListObjectVersions": true, "DeleteObjectVersion": true, "String": true, "GoString": true, "Format": true}
	pointer := reflect.TypeOf((*ErasureBackend)(nil))
	for i := 0; i < pointer.NumMethod(); i++ {
		if !methods[pointer.Method(i).Name] {
			t.Fatalf("unreviewed exported method %s", pointer.Method(i).Name)
		}
	}
	var _ artifact.ErasureObjectBackend = (*ErasureBackend)(nil)
	var _ artifact.ConfiguredObjectBackend = (*ErasureBackend)(nil)
}

func TestErasureTrustAndHostnameVerificationRemainEnabled(t *testing.T) {
	for _, wrongSAN := range []bool{false, true} {
		t.Run(map[bool]string{false: "untrusted-root", true: "wrong-ip-san"}[wrongSAN], func(t *testing.T) {
			control := erasureTestServer(t, erasureTestCertificates(t, false), func(_ erasureTestRequest, _ int) erasureTestReply {
				return erasureTestReply{wire: erasureTestPresentWire()}
			})
			erasureTestPresent(t, control.backend(t))
			control.assertTraffic(t, 1)
			s := erasureTestServer(t, erasureTestCertificates(t, wrongSAN), func(_ erasureTestRequest, _ int) erasureTestReply {
				return erasureTestReply{wire: erasureTestPresentWire()}
			})
			cfg := s.config(t)
			if !wrongSAN {
				cfg.TrustedCAPEM = erasureTestCertificates(t, false).pem
			}
			b, err := NewErasureBackend(cfg)
			if err != nil {
				t.Fatalf("syntactically valid trust config refused before handshake: %v", err)
			}
			got, err := b.ReadErasureObject(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, 4096)
			erasureTestZeroRead(t, got, err)
			if !errors.Is(err, ErrS3Request) {
				t.Fatalf("TLS error mapping: %v", err)
			}
			s.stop(t)
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.accepted != 1 || len(s.requests) != 0 {
				t.Fatalf("untrusted TLS yielded HTTP=%d TCP=%d", len(s.requests), s.accepted)
			}
		})
	}
}

func TestErasureOrdinaryCompatibilityUsesOwnedH1WithoutCookies(t *testing.T) {
	// These are synthetic future-test values. No credential or environment input is read by the author.
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, "http://127.0.0.1:1")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-env-not-the-config")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-env-secret-not-used")
	t.Setenv("SSL_CERT_FILE", "/nonexistent-synthetic-erasure-ca")
	t.Setenv("SSL_CERT_DIR", "/nonexistent-synthetic-erasure-ca-dir")
	s := erasureTestServer(t, erasureTestCertificates(t, false), func(r erasureTestRequest, _ int) erasureTestReply {
		if r.method == "PUT" {
			return erasureTestReply{wire: erasureTestWire(200, "Set-Cookie: synthetic=must-not-return\r\n", "")}
		}
		return erasureTestReply{wire: erasureTestPresentWire()}
	})
	b := s.backend(t)
	body := []byte("ordinary-content")
	ok, err := b.Create(erasureTestContext(t), erasureTestKey, body, erasureTestDigest(body))
	if err != nil || !ok {
		t.Fatalf("ordinary Create positive control: %v", err)
	}
	got, err := b.Read(erasureTestContext(t), erasureTestKey, 4096)
	if err != nil || string(got.Content) != "complete-body" {
		t.Fatalf("ordinary Read positive control: %v", err)
	}
	for _, ctx := range []context.Context{erasureTestContext(t), nil} {
		ok, err := b.Delete(ctx, erasureTestKey, "version:"+erasureTestVersion)
		if ok || !errors.Is(err, artifact.ErrErasureBackendUnsupported) {
			t.Fatalf("generic Delete must refuse before I/O: %v", err)
		}
	}
	requests := s.assertTraffic(t, 2)
	erasureTestSigned(t, requests[0], "PUT", "/"+erasureTestBucket+"/"+erasureTestKey, nil, false)
	erasureTestSigned(t, requests[1], "GET", "/"+erasureTestBucket+"/"+erasureTestKey, nil, false)
}

func erasureTestOperation(t *testing.T, b *ErasureBackend, name string, success bool) error {
	t.Helper()
	ctx := erasureTestContext(t)
	key := erasureTestExactKey(t)
	body := []byte("complete-body")
	switch name {
	case "read":
		got, err := b.ReadErasureObject(ctx, key, erasureTestOwner, 4096)
		if success {
			if err != nil || got.Kind != artifact.ErasureReadPresent {
				t.Fatalf("read positive: %v", err)
			}
		} else {
			erasureTestZeroRead(t, got, err)
		}
		return err
	case "create":
		ok, err := b.CreateErasureObject(ctx, key, erasureTestOwner, body, erasureTestDigest(body))
		if success {
			if err != nil || !ok {
				t.Fatalf("create positive: %v", err)
			}
		} else if err == nil || ok {
			t.Fatal("create error has output")
		}
		return err
	case "list":
		page, err := b.ListObjectVersions(ctx, key, erasureTestOwner, artifact.VersionCursor{}, 2, 4096)
		if success {
			if err != nil || len(page.Entries) != 1 {
				t.Fatalf("list positive: %v", err)
			}
		} else {
			erasureTestZeroPage(t, page, err)
		}
		return err
	case "delete":
		got, err := b.DeleteObjectVersion(ctx, key, erasureTestOwner, erasureTestObjectVersion(t, artifact.ObjectVersionData, erasureTestVersion))
		if success {
			if err != nil || got != artifact.VersionDeleteDeleted {
				t.Fatalf("delete positive: %v", err)
			}
		} else if err == nil || got != 0 {
			t.Fatal("delete error has output")
		}
		return err
	case "ordinary-read":
		got, err := b.Read(ctx, erasureTestKey, 4096)
		if success {
			if err != nil || string(got.Content) != "complete-body" {
				t.Fatalf("ordinary read positive: %v", err)
			}
		} else if err == nil || !reflect.DeepEqual(got, artifact.RemoteObject{}) {
			t.Fatal("ordinary read error has output")
		}
		return err
	case "ordinary-create":
		ok, err := b.Create(ctx, erasureTestKey, body, erasureTestDigest(body))
		if success {
			if err != nil || !ok {
				t.Fatalf("ordinary create positive: %v", err)
			}
		} else if err == nil || ok {
			t.Fatal("ordinary create error has output")
		}
		return err
	default:
		t.Fatal("unknown fixture operation")
		return nil
	}
}

func erasureTestOperationWire(name string) string {
	if name == "list" {
		return erasureTestWire(200, "", erasureTestListXML(2, "", "", false, "", erasureTestVersionXML(erasureTestKey, erasureTestVersion, true, "")))
	}
	if name == "create" || name == "ordinary-create" || name == "delete" {
		return erasureTestWire(200, "", "")
	}
	return erasureTestPresentWire()
}

func TestErasureRedirectsNeverProduceAnotherApplicationRequest(t *testing.T) {
	for _, operation := range []string{"read", "create", "list", "delete", "ordinary-read", "ordinary-create"} {
		for _, status := range []int{301, 302, 303, 307, 308} {
			t.Run(operation+"-"+strconv.Itoa(status), func(t *testing.T) {
				s := erasureTestServer(t, erasureTestCertificates(t, false), func(_ erasureTestRequest, index int) erasureTestReply {
					if index == 0 {
						return erasureTestReply{wire: erasureTestOperationWire(operation)}
					}
					return erasureTestReply{wire: erasureTestWire(status, "Location: /redirect-target\r\nSet-Cookie: synthetic=redirect\r\n", ""), close: true}
				})
				b := s.backend(t)
				erasureTestOperation(t, b, operation, true)
				erasureTestOperation(t, b, operation, false)
				for _, r := range s.assertTraffic(t, 2) {
					if strings.Contains(r.uri, "redirect-target") {
						t.Fatal("redirect followed")
					}
				}
			})
		}
	}
}

func TestErasureNetworkFaultsDoNotReplay(t *testing.T) {
	faults := []struct {
		name  string
		reply erasureTestReply
	}{
		{"close-before-response", erasureTestReply{close: true}},
		{"reset-after-request", erasureTestReply{reset: true}},
		{"short-body", erasureTestReply{wire: "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nx-amz-version-id: token\r\n\r\nshort", close: true}},
		{"invalid-chunk", erasureTestReply{wire: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nx-amz-version-id: token\r\n\r\nX\r\n", close: true}},
		{"server-503", erasureTestReply{wire: erasureTestWire(503, "", ""), close: true}},
	}
	for _, operation := range []string{"read", "create", "list", "delete"} {
		for _, fault := range faults {
			t.Run(operation+"/"+fault.name, func(t *testing.T) {
				s := erasureTestServer(t, erasureTestCertificates(t, false), func(_ erasureTestRequest, index int) erasureTestReply {
					if index == 0 {
						return erasureTestReply{wire: erasureTestOperationWire(operation)}
					}
					return fault.reply
				})
				b := s.backend(t)
				erasureTestOperation(t, b, operation, true)
				err := erasureTestOperation(t, b, operation, false)
				if !errors.Is(err, ErrS3Request) {
					t.Fatalf("network failure mapping: %v", err)
				}
				s.assertTraffic(t, 2)
			})
		}
	}
}

func TestErasureTraceAndCanceledInputsRefuseBeforeDispatch(t *testing.T) {
	s := erasureTestServer(t, erasureTestCertificates(t, false), func(r erasureTestRequest, _ int) erasureTestReply {
		operation := "read"
		if r.method == "PUT" {
			operation = "create"
		}
		if r.method == "DELETE" {
			operation = "delete"
		}
		if r.method == "GET" && strings.Contains(r.uri, "versions=") {
			operation = "list"
		}
		return erasureTestReply{wire: erasureTestOperationWire(operation)}
	})
	b := s.backend(t)
	erasureTestPresent(t, b)
	for _, operation := range []string{"create", "list", "delete"} {
		erasureTestOperation(t, b, operation, true)
	}
	var callbacks atomic.Int32
	trace := httptrace.WithClientTrace(erasureTestContext(t), &httptrace.ClientTrace{GetConn: func(string) { callbacks.Add(1) }, GotFirstResponseByte: func() { callbacks.Add(1) }})
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	for _, ctx := range []context.Context{nil, canceled, expired, trace} {
		got, err := b.ReadErasureObject(ctx, erasureTestExactKey(t), erasureTestOwner, 4096)
		erasureTestZeroRead(t, got, err)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("read preflight: %v", err)
		}
		page, err := b.ListObjectVersions(ctx, erasureTestExactKey(t), erasureTestOwner, artifact.VersionCursor{}, 2, 4096)
		erasureTestZeroPage(t, page, err)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("list preflight: %v", err)
		}
		ok, err := b.CreateErasureObject(ctx, erasureTestExactKey(t), erasureTestOwner, []byte("x"), erasureTestDigest([]byte("x")))
		if ok || !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("create preflight: %v", err)
		}
		deleted, err := b.DeleteObjectVersion(ctx, erasureTestExactKey(t), erasureTestOwner, erasureTestObjectVersion(t, artifact.ObjectVersionData, erasureTestVersion))
		if deleted != 0 || !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("delete preflight: %v", err)
		}
	}
	for _, maximum := range []uint32{0, (32 << 20) + 1} {
		got, err := b.ReadErasureObject(erasureTestContext(t), erasureTestExactKey(t), erasureTestOwner, maximum)
		erasureTestZeroRead(t, got, err)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("read maximum preflight: %v", err)
		}
	}
	for _, owner := range []string{"", "000000000000", "12345678901x"} {
		got, err := b.ReadErasureObject(erasureTestContext(t), erasureTestExactKey(t), owner, 4096)
		erasureTestZeroRead(t, got, err)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("read owner preflight: %v", err)
		}
		page, err := b.ListObjectVersions(erasureTestContext(t), erasureTestExactKey(t), owner, artifact.VersionCursor{}, 2, 4096)
		erasureTestZeroPage(t, page, err)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("list owner preflight: %v", err)
		}
		outcome, err := b.DeleteObjectVersion(erasureTestContext(t), erasureTestExactKey(t), owner, erasureTestObjectVersion(t, artifact.ObjectVersionData, erasureTestVersion))
		if outcome != 0 || !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("delete owner preflight: %v", err)
		}
	}
	if callbacks.Load() != 0 {
		t.Fatal("untrusted httptrace callback invoked")
	}
	s.assertTraffic(t, 4)
}

func TestErasureCancellationAfterAcceptedRequestReturnsNoObservation(t *testing.T) {
	for _, operation := range []string{"read", "create", "list", "delete"} {
		t.Run(operation, func(t *testing.T) {
			accepted := make(chan struct{}, 1)
			release := make(chan struct{})
			released := false
			defer func() {
				if !released {
					close(release)
				}
			}()
			s := erasureTestServer(t, erasureTestCertificates(t, false), func(_ erasureTestRequest, index int) erasureTestReply {
				if index == 0 {
					return erasureTestReply{wire: erasureTestOperationWire(operation)}
				}
				select {
				case accepted <- struct{}{}:
				default:
				}
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				select {
				case <-release:
				case <-timer.C:
				}
				return erasureTestReply{close: true}
			})
			b := s.backend(t)
			erasureTestOperation(t, b, operation, true)
			ctx, cancel := context.WithCancel(erasureTestContext(t))
			defer cancel()
			key := erasureTestExactKey(t)
			version := erasureTestObjectVersion(t, artifact.ObjectVersionData, erasureTestVersion)
			type result struct {
				err  error
				zero bool
			}
			done := make(chan result, 1)
			joined := make(chan struct{})
			t.Cleanup(func() {
				cancel()
				timer := time.NewTimer(9 * time.Second)
				defer timer.Stop()
				select {
				case <-joined:
				case <-timer.C:
					t.Error("backend call goroutine did not join")
				}
			})
			go func() {
				defer close(joined)
				switch operation {
				case "read":
					v, err := b.ReadErasureObject(ctx, key, erasureTestOwner, 4096)
					done <- result{err, reflect.DeepEqual(v, artifact.ErasureObjectRead{})}
				case "list":
					v, err := b.ListObjectVersions(ctx, key, erasureTestOwner, artifact.VersionCursor{}, 2, 4096)
					done <- result{err, reflect.DeepEqual(v, artifact.VersionPage{})}
				case "create":
					v, err := b.CreateErasureObject(ctx, key, erasureTestOwner, []byte("x"), erasureTestDigest([]byte("x")))
					done <- result{err, !v}
				case "delete":
					v, err := b.DeleteObjectVersion(ctx, key, erasureTestOwner, version)
					done <- result{err, v == 0}
				}
			}()
			timer := time.NewTimer(6 * time.Second)
			defer timer.Stop()
			select {
			case <-accepted:
			case <-timer.C:
				t.Fatal("operation never reached local HTTP boundary")
			}
			cancel()
			select {
			case got := <-done:
				if !got.zero || !errors.Is(got.err, ErrS3Request) {
					t.Fatalf("post-dispatch cancellation produced usable evidence: zero=%t err=%v", got.zero, got.err)
				}
			case <-timer.C:
				t.Fatal("canceled operation did not join within its finite request deadline")
			}
			close(release)
			released = true
			s.assertTraffic(t, 2)
		})
	}
}
