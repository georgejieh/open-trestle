package github

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/georgejieh/open-trestle/webhook"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fixedWebhookClock struct{ at time.Time }

func (c fixedWebhookClock) Now() time.Time { return c.at }
func webhookHandlerFixture(t *testing.T) (*HTTPHandler, *webhook.MemoryStore, []byte) {
	t.Helper()
	secret := []byte("01234567890123456789012345678901")
	verifier, err := NewVerifier(secret, strings.Repeat("a", 64), map[string][]string{"pull_request": {"opened"}})
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	policy, _ := webhook.NewAdmissionPolicy([]webhook.VerifierAuthority{{Scope: scope, Source: webhook.SourceGitHub, VerifierIdentity: verifier.Identity()}})
	store := webhook.NewMemoryStore()
	inbox, _ := webhook.NewInbox(store, policy)
	handler, err := NewHTTPHandler(scope, verifier, inbox, fixedWebhookClock{at: time.UnixMilli(1000)}, 8)
	if err != nil {
		t.Fatal(err)
	}
	return handler, store, secret
}
func githubRequest(payload, secret []byte) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://trestle.test/webhooks/github", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Delivery", "delivery-1")
	request.Header.Set("X-GitHub-Event", "pull_request")
	request.Header.Set("X-Hub-Signature-256", signatureForTest(secret, payload))
	return request
}
func TestHTTPHandlerDurablyAcknowledgesAndDeduplicates(t *testing.T) {
	handler, store, secret := webhookHandlerFixture(t)
	payload := []byte(`{"action":"opened","number":1}`)
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, githubRequest(payload, secret))
	if first.Code != http.StatusAccepted {
		t.Fatalf("first=%d %s", first.Code, first.Body.String())
	}
	var firstResponse webhookResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstResponse); err != nil || firstResponse.AcceptanceIdentity == "" || firstResponse.Duplicate {
		t.Fatalf("first response=(%#v,%v)", firstResponse, err)
	}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, githubRequest(payload, secret))
	if second.Code != http.StatusOK {
		t.Fatalf("second=%d %s", second.Code, second.Body.String())
	}
	var secondResponse webhookResponse
	_ = json.Unmarshal(second.Body.Bytes(), &secondResponse)
	if !secondResponse.Duplicate || secondResponse.AcceptanceIdentity != firstResponse.AcceptanceIdentity {
		t.Fatalf("second response=%#v", secondResponse)
	}
	scope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	entries, err := store.List(context.Background(), scope, webhook.SourceGitHub, "", 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=(%#v,%v)", entries, err)
	}
}
func TestHTTPHandlerRejectsUnauthenticatedMalformedAndOversizedRequests(t *testing.T) {
	handler, _, secret := webhookHandlerFixture(t)
	payload := []byte(`{"action":"opened"}`)
	badSignature := githubRequest(payload, secret)
	badSignature.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64))
	oversized := githubRequest(bytes.Repeat([]byte("x"), maxHTTPWebhookBodyBytes+1), secret)
	tests := []struct {
		name    string
		request *http.Request
		status  int
	}{{"signature", badSignature, http.StatusUnauthorized}, {"method", httptest.NewRequest(http.MethodGet, "https://trestle.test/webhooks/github", nil), http.StatusMethodNotAllowed}, {"oversized", oversized, http.StatusRequestEntityTooLarge}, {"media", func() *http.Request {
		r := githubRequest(payload, secret)
		r.Header.Set("Content-Type", "text/plain")
		return r
	}(), http.StatusUnsupportedMediaType}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, test.request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), string(secret)) {
				t.Fatal("response leaked secret")
			}
		})
	}
}
func TestHTTPHandlerAcknowledgesFilteredAuthenticActionWithoutStoring(t *testing.T) {
	handler, store, secret := webhookHandlerFixture(t)
	payload := []byte(`{"action":"closed"}`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, githubRequest(payload, secret))
	if response.Code != http.StatusAccepted {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
	scope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	entries, _ := store.List(context.Background(), scope, webhook.SourceGitHub, "", 10)
	if len(entries) != 0 {
		t.Fatalf("entries=%#v", entries)
	}
}

type captureNotifier struct{ notices []webhook.DeliveryNotice }

func (n *captureNotifier) Notify(notice webhook.DeliveryNotice) bool {
	n.notices = append(n.notices, notice)
	return true
}
func TestHTTPHandlerNotifiesAfterDurableAcceptance(t *testing.T) {
	base, _, secret := webhookHandlerFixture(t)
	notifier := &captureNotifier{}
	handler, err := NewHTTPHandlerWithNotifier(base.scope, base.verifier, base.inbox, notifier, base.clock, 8)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, githubRequest([]byte(`{"action":"opened","number":1}`), secret))
	if response.Code != http.StatusAccepted || len(notifier.notices) != 1 || notifier.notices[0].Validate() != nil {
		t.Fatalf("response=%d notices=%#v", response.Code, notifier.notices)
	}
}
