package review

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPublisherCatalogResolvesExactAuthorizedPublisher(t *testing.T) {
	scope, authorization, claim, attempt, gate, at := claimedPublicationFixture(t)
	raw, _ := NewSuccessfulPublicationResult("external")
	publisher := &recordingPublisher{publisherID: "github", result: raw}
	catalog, err := NewPublisherCatalog([]Publisher{publisher})
	if err != nil {
		t.Fatal(err)
	}
	result, err := DispatchClaimedPublicationFromCatalog(context.Background(), catalog, scope, authorization, claim, attempt, gate, at)
	if err != nil || result.Status() != PublicationSucceeded || publisher.calls != 1 || catalog.Len() != 1 || catalog.Validate() != nil {
		t.Fatalf("catalog dispatch=(%#v,%v),calls=%d", result, err, publisher.calls)
	}
}

func TestPublisherCatalogRejectsInvalidDuplicateAndMissingPublisher(t *testing.T) {
	valid := &recordingPublisher{publisherID: "github"}
	for _, test := range []struct {
		name       string
		publishers []Publisher
		want       error
	}{
		{"empty", nil, ErrInvalidPublisherCatalog}, {"nil", []Publisher{nil}, ErrInvalidPublisher},
		{"invalid", []Publisher{&recordingPublisher{publisherID: "Bad"}}, ErrInvalidPublisherID},
		{"zero configuration", []Publisher{&recordingPublisher{publisherID: "github", configurationIdentity: strings.Repeat("0", 64)}}, ErrInvalidPublisher},
		{"idempotency", []Publisher{&recordingPublisher{publisherID: "github", guarantee: 2}}, ErrPublicationIdempotencyNotGuaranteed},
		{"duplicate", []Publisher{valid, valid}, ErrDuplicatePublisher},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog, err := NewPublisherCatalog(test.publishers)
			if !errors.Is(err, test.want) || catalog.Len() != 0 {
				t.Fatalf("NewPublisherCatalog()=(%#v,%v),want %v", catalog, err, test.want)
			}
		})
	}
	scope, authorization, claim, attempt, gate, at := claimedPublicationFixture(t)
	catalog, _ := NewPublisherCatalog([]Publisher{&recordingPublisher{publisherID: "gitlab"}})
	if result, err := DispatchClaimedPublicationFromCatalog(context.Background(), catalog, scope, authorization, claim, attempt, gate, at); !errors.Is(err, ErrPublisherNotRegistered) || result.Identity() != "" {
		t.Fatalf("missing publisher=(%#v,%v)", result, err)
	}
}

func TestPublisherCatalogIdentityBindsConfiguration(t *testing.T) {
	first, _ := NewPublisherCatalog([]Publisher{&recordingPublisher{publisherID: "github", configurationIdentity: strings.Repeat("a", 64)}})
	second, _ := NewPublisherCatalog([]Publisher{&recordingPublisher{publisherID: "github", configurationIdentity: strings.Repeat("b", 64)}})
	if first.Identity() == second.Identity() {
		t.Fatal("publisher configuration omitted from catalog identity")
	}
}
