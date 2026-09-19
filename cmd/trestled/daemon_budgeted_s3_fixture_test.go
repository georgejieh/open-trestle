package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	daemonBudgetedS3MaxRawRequests    = 16
	daemonBudgetedS3MaxBodyBytes      = 1 << 20
	daemonBudgetedS3MaxAggregateBytes = 4 << 20
	daemonBudgetedS3MaxFailures       = 16
)

type daemonBudgetedS3Profile struct {
	MaxRawRequests    int
	MaxBodyBytes      int64
	MaxAggregateBytes int64
}

func daemonBudgetedDefaultS3Profile() daemonBudgetedS3Profile {
	return daemonBudgetedS3Profile{MaxRawRequests: daemonBudgetedS3MaxRawRequests, MaxBodyBytes: daemonBudgetedS3MaxBodyBytes, MaxAggregateBytes: daemonBudgetedS3MaxAggregateBytes}
}

func daemonBudgetedS3ProfileOrDefault(profile daemonBudgetedS3Profile) daemonBudgetedS3Profile {
	if profile.MaxRawRequests == 0 && profile.MaxBodyBytes == 0 && profile.MaxAggregateBytes == 0 {
		return daemonBudgetedDefaultS3Profile()
	}
	return profile
}

type daemonBudgetedS3Fixture struct {
	mu       sync.Mutex
	server   *httptest.Server
	profile  daemonBudgetedS3Profile
	bucket   string
	region   string
	access   string
	secret   string
	session  string
	objects  map[string]daemonBudgetedS3Object
	requests []daemonBudgetedS3Request
	rawCount int
	rawBytes int64
	failures []string
}

type daemonBudgetedS3Object struct {
	body    []byte
	version string
}

type daemonBudgetedS3Request struct {
	Method string
	Key    string
	Digest string
	Bytes  int
}

func newDaemonBudgetedS3Fixture(t *testing.T, bucket, region, access, secret, session string) *daemonBudgetedS3Fixture {
	t.Helper()
	return newDaemonBudgetedS3FixtureWithProfile(t, bucket, region, access, secret, session, daemonBudgetedDefaultS3Profile())
}

func newDaemonBudgetedS3FixtureWithProfile(t *testing.T, bucket, region, access, secret, session string, profile daemonBudgetedS3Profile) *daemonBudgetedS3Fixture {
	t.Helper()
	profile = daemonBudgetedS3ProfileOrDefault(profile)
	if profile.MaxRawRequests <= 0 || profile.MaxRawRequests > 512 || profile.MaxBodyBytes <= 0 || profile.MaxBodyBytes > daemonBudgetedS3MaxBodyBytes || profile.MaxAggregateBytes <= 0 || profile.MaxAggregateBytes > 16<<20 {
		t.Fatal("invalid bounded S3 fixture profile")
	}
	f := &daemonBudgetedS3Fixture{profile: profile, bucket: bucket, region: region, access: access, secret: secret, session: session, objects: map[string]daemonBudgetedS3Object{}}
	server := httptest.NewUnstartedServer(http.HandlerFunc(f.handle))
	server.EnableHTTP2 = false
	server.Config.ReadHeaderTimeout = 2 * time.Second
	server.Config.ReadTimeout = 5 * time.Second
	server.Config.WriteTimeout = 5 * time.Second
	server.Config.MaxHeaderBytes = 16 << 10
	server.StartTLS()
	f.server = server
	t.Cleanup(f.Close)
	return f
}

func (f *daemonBudgetedS3Fixture) Endpoint() string { return f.server.URL }
func (f *daemonBudgetedS3Fixture) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})
}
func (f *daemonBudgetedS3Fixture) Close() {
	if f.server != nil {
		f.server.Close()
	}
}
func (f *daemonBudgetedS3Fixture) Requests() []daemonBudgetedS3Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]daemonBudgetedS3Request, len(f.requests))
	copy(out, f.requests)
	return out
}
func (f *daemonBudgetedS3Fixture) RawRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rawCount
}
func (f *daemonBudgetedS3Fixture) Failures() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.failures...)
}
func (f *daemonBudgetedS3Fixture) recordRaw() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rawCount >= f.profile.MaxRawRequests {
		f.failLocked("s3 raw request limit exceeded")
		return false
	}
	f.rawCount++
	return true
}
func (f *daemonBudgetedS3Fixture) recordBody(size int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if size < 0 || int64(size) > f.profile.MaxBodyBytes || f.rawBytes+int64(size) > f.profile.MaxAggregateBytes {
		f.failLocked("s3 body budget exceeded")
		return false
	}
	f.rawBytes += int64(size)
	return true
}
func (f *daemonBudgetedS3Fixture) reject(w http.ResponseWriter, message string, status int) {
	f.mu.Lock()
	f.failLocked(message)
	f.mu.Unlock()
	http.Error(w, message, status)
}
func (f *daemonBudgetedS3Fixture) failLocked(message string) {
	if len(f.failures) < daemonBudgetedS3MaxFailures {
		f.failures = append(f.failures, message)
	}
}

func (f *daemonBudgetedS3Fixture) handle(w http.ResponseWriter, r *http.Request) {
	if !f.recordRaw() {
		http.Error(w, "s3 raw request limit exceeded", http.StatusTooManyRequests)
		return
	}
	if r.ProtoMajor != 1 || r.URL.RawQuery != "" {
		f.reject(w, "bad request", http.StatusBadRequest)
		return
	}
	prefix := "/" + f.bucket + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		f.reject(w, "wrong bucket", http.StatusNotFound)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, prefix)
	body, err := io.ReadAll(io.LimitReader(r.Body, f.profile.MaxBodyBytes+1))
	_ = r.Body.Close()
	if err != nil || int64(len(body)) > f.profile.MaxBodyBytes || !f.recordBody(len(body)) || key == "" || strings.Contains(key, "//") {
		f.reject(w, "bounded request failed", http.StatusBadRequest)
		return
	}
	if err := f.checkSignature(r, body); err != nil {
		f.reject(w, "signature refused", http.StatusForbidden)
		return
	}
	digest := daemonBudgetedHex(body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) >= f.profile.MaxRawRequests {
		f.failLocked("s3 valid request limit exceeded")
		http.Error(w, "s3 valid request limit exceeded", http.StatusTooManyRequests)
		return
	}
	f.requests = append(f.requests, daemonBudgetedS3Request{Method: r.Method, Key: key, Digest: digest, Bytes: len(body)})
	switch r.Method {
	case http.MethodGet:
		object, ok := f.objects[key]
		if !ok {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<Error><Code>NoSuchKey</Code></Error>`))
			return
		}
		w.Header().Set("x-amz-version-id", object.version)
		w.Header().Set("x-amz-checksum-sha256", base64.StdEncoding.EncodeToString(daemonBudgetedDigest(object.body)))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(append([]byte(nil), object.body...))
	case http.MethodPut:
		if r.Header.Get("If-None-Match") != "*" || r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("x-amz-content-sha256") != digest {
			f.failLocked("bad create")
			http.Error(w, "bad create", http.StatusBadRequest)
			return
		}
		checksum, err := base64.StdEncoding.DecodeString(r.Header.Get("x-amz-checksum-sha256"))
		if err != nil || !hmac.Equal(checksum, daemonBudgetedDigest(body)) {
			f.failLocked("bad checksum")
			http.Error(w, "bad checksum", http.StatusBadRequest)
			return
		}
		if _, exists := f.objects[key]; exists {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		f.objects[key] = daemonBudgetedS3Object{body: append([]byte(nil), body...), version: fmt.Sprintf("v%06d", len(f.requests))}
		w.Header().Set("x-amz-version-id", f.objects[key].version)
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		f.failLocked("delete is outside this startup smoke")
		http.Error(w, "delete is outside this startup smoke", http.StatusBadRequest)
	default:
		f.failLocked("method refused")
		http.Error(w, "method refused", http.StatusMethodNotAllowed)
	}
}

func (f *daemonBudgetedS3Fixture) checkSignature(r *http.Request, body []byte) error {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") || !strings.Contains(auth, "Credential="+f.access+"/") || !strings.Contains(auth, "/s3/aws4_request") || !strings.Contains(auth, "Signature=") {
		return fmt.Errorf("missing sigv4")
	}
	if f.session != "" && r.Header.Get("x-amz-security-token") != f.session {
		return fmt.Errorf("missing session token")
	}
	if r.Header.Get("x-amz-date") == "" || r.Header.Get("x-amz-content-sha256") != daemonBudgetedHex(body) {
		return fmt.Errorf("missing signing headers")
	}
	return daemonBudgetedVerifySigV4(r, f.secret, "s3", f.region, body)
}

func daemonBudgetedVerifySigV4(r *http.Request, secret, service, region string, body []byte) error {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return fmt.Errorf("bad algorithm")
	}
	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ",") {
		part = strings.TrimSpace(part)
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			return fmt.Errorf("bad authorization field")
		}
		fields[name] = value
	}
	credential := strings.Split(fields["Credential"], "/")
	if len(credential) != 5 || credential[2] != region || credential[3] != service || credential[4] != "aws4_request" || fields["SignedHeaders"] == "" || fields["Signature"] == "" {
		return fmt.Errorf("bad credential scope")
	}
	amzDate := r.Header.Get("x-amz-date")
	if amzDate == "" {
		amzDate = r.Header.Get("X-Amz-Date")
	}
	if amzDate == "" || !strings.HasPrefix(amzDate, credential[1]) {
		return fmt.Errorf("bad signing date")
	}
	payloadHash := r.Header.Get("x-amz-content-sha256")
	if payloadHash == "" {
		payloadHash = r.Header.Get("X-Amz-Content-Sha256")
	}
	if payloadHash == "" {
		payloadHash = daemonBudgetedHex(body)
	}
	if payloadHash != daemonBudgetedHex(body) {
		return fmt.Errorf("bad payload hash")
	}
	var canonical strings.Builder
	signedHeaders := strings.Split(fields["SignedHeaders"], ";")
	for _, name := range signedHeaders {
		if name == "" || strings.ToLower(name) != name {
			return fmt.Errorf("bad signed header")
		}
		value := ""
		if name == "host" {
			value = r.Host
		} else {
			value = r.Header.Get(name)
		}
		if value == "" {
			return fmt.Errorf("missing signed header")
		}
		canonical.WriteString(name)
		canonical.WriteByte(':')
		canonical.WriteString(strings.Join(strings.Fields(value), " "))
		canonical.WriteByte('\n')
	}
	query := strings.ReplaceAll(r.URL.Query().Encode(), "+", "%20")
	request := strings.Join([]string{r.Method, r.URL.EscapedPath(), query, canonical.String(), fields["SignedHeaders"], payloadHash}, "\n")
	scope := strings.Join(credential[1:], "/")
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + daemonBudgetedHex([]byte(request))
	dateKey := daemonBudgetedHMACSHA256([]byte("AWS4"+secret), credential[1])
	regionKey := daemonBudgetedHMACSHA256(dateKey, credential[2])
	serviceKey := daemonBudgetedHMACSHA256(regionKey, service)
	signingKey := daemonBudgetedHMACSHA256(serviceKey, "aws4_request")
	want := hex.EncodeToString(daemonBudgetedHMACSHA256(signingKey, stringToSign))
	if !hmac.Equal([]byte(want), []byte(fields["Signature"])) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func daemonBudgetedHMACSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}
func daemonBudgetedDigest(body []byte) []byte { sum := sha256.Sum256(body); return sum[:] }
func daemonBudgetedHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func daemonBudgetedS3SawMethod(requests []daemonBudgetedS3Request, method string) bool {
	for _, r := range requests {
		if r.Method == method {
			return true
		}
	}
	return false
}
func daemonBudgetedS3SawArtifactWrite(requests []daemonBudgetedS3Request) bool {
	for _, r := range requests {
		if r.Method == http.MethodPut && strings.Contains(r.Key, "/artifacts/") {
			return true
		}
	}
	return false
}
func daemonBudgetedBytesEqual(a, b []byte) bool { return bytes.Equal(a, b) }
