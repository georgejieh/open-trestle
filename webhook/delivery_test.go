package webhook

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNewVerifiedDeliveryBindsExactPayloadAndScope(t *testing.T) {
	scope, err := NewRepositoryScope("tenant-a", "repo-a")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"action":"synchronize"}`)
	delivery, err := NewVerifiedDelivery(scope, SourceGitHub, "delivery-1", "pull_request", "synchronize", strings.Repeat("a", 64), payload, time.UnixMilli(1000))
	if err != nil || delivery.Validate() != nil || delivery.Identity() == "" || delivery.DeduplicationKey() == "" || delivery.BodyDigest() == "" {
		t.Fatalf("delivery=(%#v,%v)", delivery, err)
	}
	copied := delivery.Payload()
	copied[0] = 'x'
	if bytes.Equal(copied, delivery.Payload()) {
		t.Fatal("payload was mutable")
	}
	other, _ := NewVerifiedDelivery(scope, SourceGitHub, "delivery-1", "pull_request", "synchronize", strings.Repeat("a", 64), []byte(`{"action":"opened"}`), time.UnixMilli(1000))
	if other.DeduplicationKey() != delivery.DeduplicationKey() || other.Identity() == delivery.Identity() {
		t.Fatal("deduplication or content identity did not bind expected fields")
	}
	if fmt.Sprintf("%#v", delivery) != "webhook.VerifiedDelivery{<redacted>}" || strings.Contains(fmt.Sprint(delivery), "synchronize") {
		t.Fatal("formatting leaked delivery")
	}
}
func TestNewVerifiedDeliveryRejectsUnsafeFields(t *testing.T) {
	scope, _ := NewRepositoryScope("tenant-a", "repo-a")
	valid := []byte(`{}`)
	tests := []struct {
		name                              string
		scope                             RepositoryScope
		source                            Source
		delivery, event, action, verifier string
		payload                           []byte
		at                                time.Time
		want                              error
	}{{"scope", RepositoryScope{}, SourceGitHub, "delivery-1", "push", "", strings.Repeat("a", 64), valid, time.UnixMilli(1), ErrInvalidRepositoryScope}, {"source", scope, 99, "delivery-1", "push", "", strings.Repeat("a", 64), valid, time.UnixMilli(1), ErrInvalidVerifiedDelivery}, {"delivery", scope, SourceGitHub, "bad delivery", "push", "", strings.Repeat("a", 64), valid, time.UnixMilli(1), ErrInvalidVerifiedDelivery}, {"event", scope, SourceGitHub, "delivery-1", "bad event", "", strings.Repeat("a", 64), valid, time.UnixMilli(1), ErrInvalidVerifiedDelivery}, {"payload", scope, SourceGitHub, "delivery-1", "push", "", strings.Repeat("a", 64), nil, time.UnixMilli(1), ErrInvalidVerifiedDelivery}, {"time", scope, SourceGitHub, "delivery-1", "push", "", strings.Repeat("a", 64), valid, time.Time{}, ErrInvalidVerifiedDelivery}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NewVerifiedDelivery(test.scope, test.source, test.delivery, test.event, test.action, test.verifier, test.payload, test.at)
			if !errors.Is(err, test.want) || got.Identity() != "" {
				t.Fatalf("delivery=(%#v,%v)", got, err)
			}
		})
	}
}

func TestNewVerifiedDeliveryRejectsUppercaseDigest(t *testing.T) {
	scope, _ := NewRepositoryScope("tenant-a", "repo-a")
	if _, err := NewVerifiedDelivery(scope, SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("A", 64), []byte(`{}`), time.UnixMilli(1)); err == nil {
		t.Fatal("expected uppercase digest rejection")
	}
}

func TestVerifiedDeliveryEncodingRoundTripsPayload(t *testing.T) {
	scope, _ := NewRepositoryScope("tenant-a", "repo-a")
	delivery, _ := NewVerifiedDelivery(scope, SourceGitHub, "delivery-1", "push", "", strings.Repeat("a", 64), []byte(`{"ref":"main"}`), time.UnixMilli(1000))
	encoded, err := EncodeVerifiedDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseVerifiedDelivery(encoded)
	if err != nil || parsed.Identity() != delivery.Identity() || !bytes.Equal(parsed.Payload(), delivery.Payload()) || !bytes.Equal(encoded, mustEncodeDelivery(t, parsed)) {
		t.Fatalf("parsed=(%#v,%v)", parsed, err)
	}
	unknown := bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":1,"extra":true`), 1)
	if got, err := ParseVerifiedDelivery(unknown); err == nil || got.Identity() != "" {
		t.Fatalf("unknown=(%#v,%v)", got, err)
	}
}
func mustEncodeDelivery(t *testing.T, delivery VerifiedDelivery) []byte {
	t.Helper()
	encoded, err := EncodeVerifiedDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
