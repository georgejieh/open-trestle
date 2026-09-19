package s3

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }
func TestBackendImplementsConditionalVersionedObjectOperations(t *testing.T) {
	body := []byte("encrypted artifact bytes")
	digest := digestHex(body)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") {
			t.Errorf("authorization=%q", request.Header.Get("Authorization"))
		}
		if request.Header.Get("X-Amz-Date") != "20260902T120000Z" {
			t.Errorf("date=%q", request.Header.Get("X-Amz-Date"))
		}
		switch requests {
		case 1:
			if request.Method != http.MethodPut || request.URL.Path != "/artifacts/reviews/artifacts/abc" || request.Header.Get("If-None-Match") != "*" || request.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(mustDigestBytes(t, digest)) {
				t.Errorf("create request=%s %s %#v", request.Method, request.URL.String(), request.Header)
			}
			received := new(bytes.Buffer)
			_, _ = received.ReadFrom(request.Body)
			if !bytes.Equal(received.Bytes(), body) {
				t.Errorf("body=%q", received.Bytes())
			}
			writer.Header().Set("x-amz-version-id", "v1")
			writer.WriteHeader(http.StatusOK)
		case 2:
			if request.Method != http.MethodGet {
				t.Errorf("read method=%s", request.Method)
			}
			writer.Header().Set("x-amz-version-id", "v1")
			writer.Header().Set("x-amz-checksum-sha256", base64.StdEncoding.EncodeToString(mustDigestBytes(t, digest)))
			writer.Header().Set("Content-Length", "24")
			_, _ = writer.Write(body)
		case 3:
			if request.Method != http.MethodDelete || request.URL.Query().Get("versionId") != "v1" {
				t.Errorf("delete=%s %s", request.Method, request.URL.String())
			}
			writer.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	backend := backendFixture(t, server.URL)
	created, err := backend.Create(context.Background(), "reviews/artifacts/abc", body, digest)
	if err != nil || !created {
		t.Fatalf("create=(%v,%v)", created, err)
	}
	object, err := backend.Read(context.Background(), "reviews/artifacts/abc", 1024)
	if err != nil || !bytes.Equal(object.Content, body) || object.Version != "version:v1" || object.Digest != digest {
		t.Fatalf("read=(%#v,%v)", object, err)
	}
	deleted, err := backend.Delete(context.Background(), "reviews/artifacts/abc", object.Version)
	if err != nil || !deleted {
		t.Fatalf("delete=(%v,%v)", deleted, err)
	}
	if requests != 3 {
		t.Fatalf("requests=%d", requests)
	}
}
func TestBackendMapsConditionalAndBoundedResponses(t *testing.T) {
	statuses := []int{http.StatusPreconditionFailed, http.StatusConflict, http.StatusNotFound, http.StatusOK}
	request := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		status := statuses[request]
		request++
		if status == http.StatusOK {
			writer.Header().Set("x-amz-version-id", "v2")
			writer.Header().Set("Content-Length", "100")
			writer.WriteHeader(status)
			_, _ = writer.Write(bytes.Repeat([]byte{'x'}, 100))
			return
		}
		writer.WriteHeader(status)
		if status == http.StatusNotFound {
			_, _ = writer.Write([]byte("<Error><Code>NoSuchKey</Code></Error>"))
		}
	}))
	defer server.Close()
	backend := backendFixture(t, server.URL)
	created, err := backend.Create(context.Background(), "objects/key", []byte("x"), digestHex([]byte("x")))
	if err != nil || created {
		t.Fatalf("precondition=(%v,%v)", created, err)
	}
	if _, err := backend.Create(context.Background(), "objects/key", []byte("x"), digestHex([]byte("x"))); err != artifact.ErrRemoteObjectConflict {
		t.Fatalf("conflict=%v", err)
	}
	if _, err := backend.Read(context.Background(), "objects/key", 10); err != artifact.ErrRemoteObjectNotFound {
		t.Fatalf("not found=%v", err)
	}
	if _, err := backend.Read(context.Background(), "objects/key", 10); err != artifact.ErrRemoteObjectTooLarge {
		t.Fatalf("large=%v", err)
	}
}
func TestBackendRejectsRedirectAndMissingVersioning(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("redirect followed") }))
	defer target.Close()
	responses := 0
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		responses++
		if responses == 1 {
			writer.Header().Set("Location", target.URL)
			writer.WriteHeader(http.StatusFound)
			return
		}
		_, _ = writer.Write([]byte("x"))
	}))
	defer source.Close()
	backend := backendFixture(t, source.URL)
	if _, err := backend.Read(context.Background(), "objects/key", 10); err != ErrS3Request {
		t.Fatalf("redirect=%v", err)
	}
	if _, err := backend.Read(context.Background(), "objects/key", 10); err != artifact.ErrRemoteObjectConflict {
		t.Fatalf("missing version=%v", err)
	}
}
func TestCredentialsAndBackendFormattingRedactsSecrets(t *testing.T) {
	credentials, _ := NewCredentials("AKIDEXAMPLE", "very-secret-value-very-secret-value-1234", "")
	if strings.Contains(strings.Join([]string{credentials.String(), credentials.GoString(), formatValue(credentials)}, " "), "very-secret") {
		t.Fatal("credential formatting leaked secret")
	}
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	backend := backendFixture(t, server.URL)
	if strings.Contains(formatValue(backend), "AKIDEXAMPLE") || strings.Contains(formatValue(backend), server.URL) {
		t.Fatal("backend formatting leaked configuration")
	}
}
func backendFixture(t *testing.T, endpoint string) *Backend {
	t.Helper()
	credentials, err := NewCredentials("AKIDEXAMPLE", "very-secret-value-very-secret-value-1234", "")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewStaticCredentialsProvider(credentials)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := New(Config{Endpoint: endpoint, Region: "us-east-1", Bucket: "artifacts", Credentials: provider, Clock: fixedClock{at: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	return backend
}
func mustDigestBytes(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
func formatValue(value any) string { return fmt.Sprintf("%v %#v", value, value) }

func TestSignatureV4CanonicalRequestMatchesIndependentVector(t *testing.T) {
	credentials, _ := NewCredentials("AKIDEXAMPLE", "very-secret-value-very-secret-value-1234", "")
	provider, _ := NewStaticCredentialsProvider(credentials)
	backend, err := New(Config{Endpoint: "https://s3.example.test", Region: "us-east-1", Bucket: "artifacts", Credentials: provider, Clock: fixedClock{at: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("encrypted artifact bytes")
	digest := digestHex(body)
	checksum, _ := hex.DecodeString(digest)
	request, err := backend.newRequest(context.Background(), http.MethodPut, "reviews/artifacts/abc", nil, http.Header{"Content-Type": []string{"application/octet-stream"}, "If-None-Match": []string{"*"}, "X-Amz-Checksum-Sha256": []string{base64.StdEncoding.EncodeToString(checksum)}}, body, digest)
	if err != nil {
		t.Fatal(err)
	}
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260902/us-east-1/s3/aws4_request, SignedHeaders=content-type;host;if-none-match;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date, Signature=0458d383d790940ad053fcad8767a05bba3ce244d0944295d3af0d4f250f18f4"
	if request.Header.Get("Authorization") != want {
		t.Fatalf("authorization=%s", request.Header.Get("Authorization"))
	}
}

func TestConfigurationIdentityBindsCanonicalS3Authority(t *testing.T) {
	first, err := ConfigurationIdentity("https://s3.example.test", "us-east-1", "artifacts")
	if err != nil {
		t.Fatal(err)
	}
	same, err := ConfigurationIdentity("https://s3.example.test/", "us-east-1", "artifacts")
	if err != nil || same != first {
		t.Fatalf("same=%s err=%v", same, err)
	}
	for _, configuration := range [][3]string{{"https://other.example.test", "us-east-1", "artifacts"}, {"https://s3.example.test", "us-west-2", "artifacts"}, {"https://s3.example.test", "us-east-1", "other-artifacts"}} {
		changed, changeErr := ConfigurationIdentity(configuration[0], configuration[1], configuration[2])
		if changeErr != nil || changed == first {
			t.Fatalf("changed=%s err=%v", changed, changeErr)
		}
	}
	for _, endpoint := range []string{"https://169.254.169.254", "HTTPS://s3.example.test", "https://user@s3.example.test"} {
		if identity, invalidErr := ConfigurationIdentity(endpoint, "us-east-1", "artifacts"); invalidErr == nil || identity != "" {
			t.Fatalf("endpoint=%s identity=%s err=%v", endpoint, identity, invalidErr)
		}
	}
	credentials, _ := NewCredentials("ACCESSKEY", strings.Repeat("s", 32), "")
	provider, _ := NewStaticCredentialsProvider(credentials)
	backend, err := New(Config{Endpoint: "https://s3.example.test", Region: "us-east-1", Bucket: "artifacts", Credentials: provider})
	if err != nil || backend.ConfigurationIdentity() != first || backend.Validate() != nil {
		t.Fatalf("backend=%#v err=%v", backend, err)
	}
	formatted := fmt.Sprintf("%#v", backend)
	if strings.Contains(formatted, "s3.example") || strings.Contains(formatted, "artifacts") {
		t.Fatal("backend formatter leaked authority")
	}
	backend.region = "us-west-2"
	if backend.Validate() == nil {
		t.Fatal("changed backend validated")
	}
}

func TestBackendDoesNotTreatMissingBucketAsObjectAbsence(t *testing.T) {
	for _, body := range []string{"<Error><Code>NoSuchBucket</Code></Error>", "not found", "<Error><Code>NoSuchKey</Code><Code>NoSuchKey</Code></Error>", "<Other><Code>NoSuchKey</Code></Other>", "<Error><Code>NoSuchKey</Code></Error>trailing", strings.Repeat("x", maximumErrorBodyBytes+1)} {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusNotFound)
			_, _ = writer.Write([]byte(body))
		}))
		backend := backendFixture(t, server.URL)
		if _, err := backend.Read(context.Background(), "objects/key", 10); err != ErrS3Request {
			server.Close()
			t.Fatalf("body=%q err=%v", body, err)
		}
		server.Close()
	}
}
