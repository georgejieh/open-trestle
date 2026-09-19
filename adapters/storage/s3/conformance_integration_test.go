package s3_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	s3store "github.com/georgejieh/open-trestle/adapters/storage/s3"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

type conformanceKeyProvider struct{ key [32]byte }

func (p conformanceKeyProvider) GenerateDataKey(context.Context, string) (artifact.EnvelopeDataKey, error) {
	wrapped := make([]byte, 32)
	for index := range wrapped {
		wrapped[index] = p.key[index] ^ 0x5a
	}
	return artifact.NewEnvelopeDataKey(p.key, "kms:test:key", wrapped)
}
func (p conformanceKeyProvider) UnwrapDataKey(_ context.Context, _ string, _ string, wrapped []byte) ([32]byte, error) {
	var key [32]byte
	if len(wrapped) != 32 {
		return key, errors.New("invalid wrapped key")
	}
	for index := range wrapped {
		key[index] = wrapped[index] ^ 0x5a
	}
	return key, nil
}
func TestConformanceDoesNotAcceptMissingBucketAsFinalAbsence(t *testing.T) {
	var mu sync.Mutex
	var object []byte
	deleted := false
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		switch request.Method {
		case http.MethodGet:
			if len(object) == 0 {
				writer.WriteHeader(http.StatusNotFound)
				_, _ = writer.Write([]byte("<Error><Code>NoSuchKey</Code></Error>"))
				return
			}
			if deleted {
				writer.WriteHeader(http.StatusNotFound)
				_, _ = writer.Write([]byte("<Error><Code>NoSuchBucket</Code></Error>"))
				return
			}
			sum := sha256.Sum256(object)
			writer.Header().Set("x-amz-version-id", "v1")
			writer.Header().Set("x-amz-checksum-sha256", base64.StdEncoding.EncodeToString(sum[:]))
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(object)
		case http.MethodPut:
			content, _ := io.ReadAll(request.Body)
			object = append([]byte(nil), content...)
			writer.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			if request.URL.Query().Get("versionId") != "v1" {
				writer.WriteHeader(http.StatusConflict)
				return
			}
			deleted = true
			writer.WriteHeader(http.StatusNoContent)
		default:
			writer.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	credentials, _ := s3store.NewCredentials("ACCESSKEY", "ssssssssssssssssssssssssssssssss", "")
	provider, _ := s3store.NewStaticCredentialsProvider(credentials)
	backend, err := s3store.New(s3store.Config{Endpoint: server.URL, Region: "us-east-1", Bucket: "artifacts", Credentials: provider, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	copy(key[:], []byte("0123456789abcdef0123456789abcdef"))
	store, err := artifact.NewEnvelopeStore("reviews", backend, conformanceKeyProvider{key})
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "setup-root-a")
	authority := sha256.Sum256([]byte("authority"))
	receipt, err := artifact.VerifyEnvelopeStorageConformance(context.Background(), store, scope, hex.EncodeToString(authority[:]), time.UnixMilli(100).UTC())
	if receipt.Identity() != "" || !errors.Is(err, artifact.ErrRemoteStorePersistence) || requests != 8 {
		t.Fatalf("receipt=%#v err=%v requests=%d", receipt, err, requests)
	}
}
