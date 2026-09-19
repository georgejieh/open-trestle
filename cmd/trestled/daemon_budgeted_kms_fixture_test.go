package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	daemonBudgetedKMSMaxRawRequests    = 16
	daemonBudgetedKMSMaxBodyBytes      = 1 << 20
	daemonBudgetedKMSMaxAggregateBytes = 4 << 20
	daemonBudgetedKMSMaxFailures       = 16
)

type daemonBudgetedKMSProfile struct {
	MaxRawRequests    int
	MaxBodyBytes      int64
	MaxAggregateBytes int64
}

func daemonBudgetedDefaultKMSProfile() daemonBudgetedKMSProfile {
	return daemonBudgetedKMSProfile{MaxRawRequests: daemonBudgetedKMSMaxRawRequests, MaxBodyBytes: daemonBudgetedKMSMaxBodyBytes, MaxAggregateBytes: daemonBudgetedKMSMaxAggregateBytes}
}

func daemonBudgetedKMSProfileOrDefault(profile daemonBudgetedKMSProfile) daemonBudgetedKMSProfile {
	if profile.MaxRawRequests == 0 && profile.MaxBodyBytes == 0 && profile.MaxAggregateBytes == 0 {
		return daemonBudgetedDefaultKMSProfile()
	}
	return profile
}

type daemonBudgetedKMSFixture struct {
	mu       sync.Mutex
	server   *httptest.Server
	profile  daemonBudgetedKMSProfile
	region   string
	keyARN   string
	access   string
	secret   string
	session  string
	wrapped  map[string][]byte
	requests []daemonBudgetedKMSRequest
	rawCount int
	rawBytes int64
	failures []string
}

type daemonBudgetedKMSRequest struct {
	Target string
	KeyID  string
	Bytes  int
}

func newDaemonBudgetedKMSFixture(t *testing.T, region, keyARN, access, secret, session string) *daemonBudgetedKMSFixture {
	t.Helper()
	return newDaemonBudgetedKMSFixtureWithProfile(t, region, keyARN, access, secret, session, daemonBudgetedDefaultKMSProfile())
}

func newDaemonBudgetedKMSFixtureWithProfile(t *testing.T, region, keyARN, access, secret, session string, profile daemonBudgetedKMSProfile) *daemonBudgetedKMSFixture {
	t.Helper()
	profile = daemonBudgetedKMSProfileOrDefault(profile)
	if profile.MaxRawRequests <= 0 || profile.MaxRawRequests > 256 || profile.MaxBodyBytes <= 0 || profile.MaxBodyBytes > daemonBudgetedKMSMaxBodyBytes || profile.MaxAggregateBytes <= 0 || profile.MaxAggregateBytes > 16<<20 {
		t.Fatal("invalid bounded KMS fixture profile")
	}
	f := &daemonBudgetedKMSFixture{profile: profile, region: region, keyARN: keyARN, access: access, secret: secret, session: session, wrapped: map[string][]byte{}}
	server := httptest.NewUnstartedServer(http.HandlerFunc(f.handle))
	server.Config.ReadHeaderTimeout = 2 * time.Second
	server.Config.ReadTimeout = 5 * time.Second
	server.Config.WriteTimeout = 5 * time.Second
	server.Config.MaxHeaderBytes = 16 << 10
	server.Start()
	f.server = server
	t.Cleanup(f.Close)
	return f
}
func (f *daemonBudgetedKMSFixture) Endpoint() string { return f.server.URL }
func (f *daemonBudgetedKMSFixture) Close() {
	if f.server != nil {
		f.server.Close()
	}
}
func (f *daemonBudgetedKMSFixture) Requests() []daemonBudgetedKMSRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]daemonBudgetedKMSRequest, len(f.requests))
	copy(out, f.requests)
	return out
}
func (f *daemonBudgetedKMSFixture) RawRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rawCount
}
func (f *daemonBudgetedKMSFixture) Failures() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.failures...)
}
func (f *daemonBudgetedKMSFixture) recordRaw() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rawCount >= f.profile.MaxRawRequests {
		f.failLocked("kms raw request limit exceeded")
		return false
	}
	f.rawCount++
	return true
}
func (f *daemonBudgetedKMSFixture) recordBody(size int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if size <= 0 || int64(size) > f.profile.MaxBodyBytes || f.rawBytes+int64(size) > f.profile.MaxAggregateBytes {
		f.failLocked("kms body budget exceeded")
		return false
	}
	f.rawBytes += int64(size)
	return true
}
func (f *daemonBudgetedKMSFixture) reject(w http.ResponseWriter, message string, status int) {
	f.mu.Lock()
	f.failLocked(message)
	f.mu.Unlock()
	http.Error(w, message, status)
}
func (f *daemonBudgetedKMSFixture) failLocked(message string) {
	if len(f.failures) < daemonBudgetedKMSMaxFailures {
		f.failures = append(f.failures, message)
	}
}

func (f *daemonBudgetedKMSFixture) handle(w http.ResponseWriter, r *http.Request) {
	if !f.recordRaw() {
		http.Error(w, "kms raw request limit exceeded", http.StatusTooManyRequests)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/" || r.URL.RawQuery != "" {
		f.reject(w, "bad kms request", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, f.profile.MaxBodyBytes+1))
	_ = r.Body.Close()
	if err != nil || len(body) == 0 || int64(len(body)) > f.profile.MaxBodyBytes || !f.recordBody(len(body)) {
		f.reject(w, "bad kms body", http.StatusBadRequest)
		return
	}
	if err := f.checkSignature(r, body); err != nil {
		f.reject(w, "signature refused", http.StatusForbidden)
		return
	}
	target := r.Header.Get("X-Amz-Target")
	switch target {
	case "TrentService.GenerateDataKey":
		var req struct {
			KeyID             string            `json:"KeyId"`
			KeySpec           string            `json:"KeySpec"`
			EncryptionContext map[string]string `json:"EncryptionContext"`
		}
		if json.Unmarshal(body, &req) != nil || req.KeyID != f.keyARN || req.KeySpec != "AES_256" || !daemonBudgetedValidKMSContext(req.EncryptionContext) {
			f.reject(w, "bad generate", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		if len(f.requests) >= f.profile.MaxRawRequests {
			f.failLocked("kms valid request limit exceeded")
			f.mu.Unlock()
			http.Error(w, "kms valid request limit exceeded", http.StatusTooManyRequests)
			return
		}
		plain := daemonBudgetedKMSPlaintext(req.KeyID, len(f.requests)+1)
		wrapped := append([]byte("wrapped:"), daemonBudgetedDigest(plain)...)
		wrappedKey := base64.StdEncoding.EncodeToString(wrapped)
		f.requests = append(f.requests, daemonBudgetedKMSRequest{Target: target, KeyID: req.KeyID, Bytes: len(body)})
		f.wrapped[wrappedKey] = append([]byte(nil), plain...)
		f.mu.Unlock()
		f.writeJSON(w, map[string]any{"KeyId": f.keyARN, "Plaintext": base64.StdEncoding.EncodeToString(plain), "CiphertextBlob": wrappedKey})
	case "TrentService.Decrypt":
		var req struct {
			KeyID               string            `json:"KeyId"`
			CiphertextBlob      string            `json:"CiphertextBlob"`
			EncryptionAlgorithm string            `json:"EncryptionAlgorithm"`
			EncryptionContext   map[string]string `json:"EncryptionContext"`
		}
		if json.Unmarshal(body, &req) != nil || req.KeyID != f.keyARN || req.EncryptionAlgorithm != "SYMMETRIC_DEFAULT" || !daemonBudgetedValidKMSContext(req.EncryptionContext) {
			f.reject(w, "bad decrypt", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		if len(f.requests) >= f.profile.MaxRawRequests {
			f.failLocked("kms valid request limit exceeded")
			f.mu.Unlock()
			http.Error(w, "kms valid request limit exceeded", http.StatusTooManyRequests)
			return
		}
		plain, ok := f.wrapped[req.CiphertextBlob]
		if ok {
			plain = append([]byte(nil), plain...)
		}
		f.requests = append(f.requests, daemonBudgetedKMSRequest{Target: target, KeyID: req.KeyID, Bytes: len(body)})
		f.mu.Unlock()
		if !ok {
			f.reject(w, "unknown ciphertext", http.StatusBadRequest)
			return
		}
		f.writeJSON(w, map[string]any{"KeyId": f.keyARN, "Plaintext": base64.StdEncoding.EncodeToString(plain), "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"})
	default:
		f.reject(w, "target refused", http.StatusBadRequest)
	}
}

func (f *daemonBudgetedKMSFixture) checkSignature(r *http.Request, body []byte) error {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") || !strings.Contains(auth, "Credential="+f.access+"/") || !strings.Contains(auth, "/"+f.region+"/kms/aws4_request") || strings.Contains(auth, "Credential=s3-") {
		return fmt.Errorf("missing kms signature")
	}
	if f.session != "" && r.Header.Get("X-Amz-Security-Token") != f.session {
		return fmt.Errorf("missing session")
	}
	if r.Header.Get("X-Amz-Date") == "" || r.Header.Get("Content-Type") == "" {
		return fmt.Errorf("missing headers")
	}
	return daemonBudgetedVerifySigV4(r, f.secret, "kms", f.region, body)
}

func (f *daemonBudgetedKMSFixture) writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(value)
}

func daemonBudgetedKMSPlaintext(key string, counter int) []byte {
	seed := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", key, counter)))
	out := append([]byte(nil), seed[:]...)
	if len(out) != 32 || daemonBudgetedAllZero(out) {
		panic("bad kms fixture plaintext")
	}
	return out
}
func daemonBudgetedValidKMSContext(ctx map[string]string) bool {
	value := ctx["open_trestle_tenant_binding"]
	expected := sha256.Sum256([]byte("open-trestle/aws-kms-tenant/v1:" + daemonBudgetedTenant))
	decoded, err := hex.DecodeString(value)
	return len(ctx) == 1 && value == hex.EncodeToString(expected[:]) && err == nil && len(decoded) == sha256.Size
}
func daemonBudgetedAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
func daemonBudgetedKMSTargetCount(requests []daemonBudgetedKMSRequest, target string) int {
	count := 0
	for _, r := range requests {
		if r.Target == target {
			count++
		}
	}
	return count
}
