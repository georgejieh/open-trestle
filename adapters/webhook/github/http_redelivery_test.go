package github

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/webhook"
)

type advancingWebhookClock struct{ at time.Time }

func (c *advancingWebhookClock) Now() time.Time {
	at := c.at
	c.at = c.at.Add(time.Millisecond)
	return at
}

func TestHTTPHandlerSignedRedeliveryWithAdvancingClock(t *testing.T) {
	base, store, secret := webhookHandlerFixture(t)
	clock := &advancingWebhookClock{at: time.UnixMilli(1000)}
	notifier := &captureNotifier{}
	handler, err := NewHTTPHandlerWithNotifier(base.scope, base.verifier, base.inbox, notifier, clock, 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = base.verifier.Close() })
	payload := []byte(`{"action":"opened","number":1}`)
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, githubRequest(payload, secret))
	var accepted webhookResponse
	if err := json.Unmarshal(first.Body.Bytes(), &accepted); err != nil || first.Code != http.StatusAccepted || accepted.AcceptanceIdentity == "" || accepted.Duplicate {
		t.Fatalf("first=%d response=%#v err=%v", first.Code, accepted, err)
	}
	entries, err := store.List(context.Background(), base.scope, webhook.SourceGitHub, "", 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=(%d,%v)", len(entries), err)
	}
	original := entries[0]
	if !original.Delivery().ReceivedAt().Equal(time.UnixMilli(1000)) || !original.Receipt().AcceptedAt().Equal(time.UnixMilli(1000)) || original.Receipt().Identity() != accepted.AcceptanceIdentity {
		t.Fatal("initial response did not bind the stored observation")
	}
	before, err := webhook.EncodeStoredDelivery(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		payload   []byte
		badHMAC   bool
		status    int
		errorCode string
	}{
		{"later-identical", payload, false, http.StatusOK, ""},
		{"unauthenticated-retry", payload, true, http.StatusUnauthorized, "unauthenticated"},
		{"signed-changed-body", []byte(`{"action":"opened","number":2}`), false, http.StatusConflict, "delivery_conflict"},
		{"original-after-conflict", payload, false, http.StatusOK, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := githubRequest(test.payload, secret)
			if test.badHMAC {
				request.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64))
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			var body webhookResponse
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.status || body.Error != test.errorCode {
				t.Fatalf("status=%d response=%#v", response.Code, body)
			}
			if test.status == http.StatusOK {
				if !body.Duplicate || body.AcceptanceIdentity != accepted.AcceptanceIdentity {
					t.Fatalf("duplicate response=%#v", body)
				}
			} else if body.Duplicate || body.AcceptanceIdentity != "" {
				t.Fatalf("rejected request acknowledged: %#v", body)
			}
		})
	}
	entries, err = store.List(context.Background(), base.scope, webhook.SourceGitHub, "", 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=(%d,%v)", len(entries), err)
	}
	after, err := webhook.EncodeStoredDelivery(entries[0])
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("retry or conflict rewrote stored observation: %v", err)
	}
	if len(notifier.notices) != 3 {
		t.Fatalf("successful deliveries must wake reconciliation: notices=%d", len(notifier.notices))
	}
	for _, notice := range notifier.notices {
		if notice.Validate() != nil || notice.Scope.Identity() != original.Delivery().Scope().Identity() || notice.Source != original.Delivery().Source() || notice.DeduplicationKey != original.Delivery().DeduplicationKey() {
			t.Fatal("notification changed scope")
		}
	}
}

type expiredAcceptanceStore struct{ webhook.Store }

func (expiredAcceptanceStore) Put(context.Context, webhook.VerifiedDelivery, time.Time) (webhook.StoredDelivery, bool, error) {
	return webhook.StoredDelivery{}, false, webhook.ErrDeliveryExpired
}

func TestHTTPHandlerDoesNotAcknowledgeExpiredDelivery(t *testing.T) {
	base, store, secret := webhookHandlerFixture(t)
	defer base.verifier.Close()
	policy, err := webhook.NewAdmissionPolicy([]webhook.VerifierAuthority{{Scope: base.scope, Source: webhook.SourceGitHub, VerifierIdentity: base.verifier.Identity()}})
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := webhook.NewInbox(expiredAcceptanceStore{Store: store}, policy)
	if err != nil {
		t.Fatal(err)
	}
	notifier := &captureNotifier{}
	handler, err := NewHTTPHandlerWithNotifier(base.scope, base.verifier, inbox, notifier, fixedWebhookClock{at: time.UnixMilli(1000)}, 8)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, githubRequest([]byte(`{"action":"opened","number":1}`), secret))
	var body webhookResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusGone || body.Error != "delivery_expired" || body.AcceptanceIdentity != "" || len(notifier.notices) != 0 {
		t.Fatalf("expired delivery acknowledged: status=%d body=%#v", response.Code, body)
	}
}
