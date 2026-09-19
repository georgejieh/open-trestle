package review

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestHeadResolverCatalogResolvesExactAuthorizedImplementation(t *testing.T) {
	scope, authorization, claim, attempt, at := publicationClaimStateFixture(t)
	raw, _ := NewResolvedPublicationHeadObservation(authorization.Plan().Target().HeadRevision())
	resolver := &recordingHeadResolver{resolverID: "github", observation: raw}
	catalog, err := NewHeadResolverCatalog([]HeadResolver{resolver})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ResolvePublicationHeadFromCatalog(context.Background(), catalog, scope, authorization, claim, attempt, at)
	if err != nil || observation.Status() != PublicationHeadResolved || resolver.calls != 1 || catalog.Len() != 1 || catalog.Validate() != nil {
		t.Fatalf("catalog resolution=(%#v,%v),calls=%d", observation, err, resolver.calls)
	}
}
func TestHeadResolverCatalogRejectsInvalidDuplicateAndMissing(t *testing.T) {
	valid := &recordingHeadResolver{resolverID: "github"}
	for _, test := range []struct {
		name      string
		resolvers []HeadResolver
		want      error
	}{{"empty", nil, ErrInvalidHeadResolverCatalog}, {"nil", []HeadResolver{nil}, ErrInvalidHeadResolver}, {"invalid", []HeadResolver{&recordingHeadResolver{resolverID: "Bad"}}, ErrInvalidPublisherID}, {"zero configuration", []HeadResolver{&recordingHeadResolver{resolverID: "github", configurationIdentity: strings.Repeat("0", 64)}}, ErrInvalidHeadResolver}, {"duplicate", []HeadResolver{valid, valid}, ErrDuplicateHeadResolver}} {
		t.Run(test.name, func(t *testing.T) {
			catalog, err := NewHeadResolverCatalog(test.resolvers)
			if !errors.Is(err, test.want) || catalog.Len() != 0 {
				t.Fatalf("catalog=(%#v,%v),want %v", catalog, err, test.want)
			}
		})
	}
	scope, authorization, claim, attempt, at := publicationClaimStateFixture(t)
	catalog, _ := NewHeadResolverCatalog([]HeadResolver{&recordingHeadResolver{resolverID: "gitlab"}})
	if observation, err := ResolvePublicationHeadFromCatalog(context.Background(), catalog, scope, authorization, claim, attempt, at); !errors.Is(err, ErrHeadResolverNotRegistered) || observation.Identity() != "" {
		t.Fatalf("missing resolver=(%#v,%v)", observation, err)
	}
}

func TestHeadResolverCatalogIdentityBindsConfiguration(t *testing.T) {
	first, _ := NewHeadResolverCatalog([]HeadResolver{&recordingHeadResolver{resolverID: "github", configurationIdentity: strings.Repeat("a", 64)}})
	second, _ := NewHeadResolverCatalog([]HeadResolver{&recordingHeadResolver{resolverID: "github", configurationIdentity: strings.Repeat("b", 64)}})
	if first.Identity() == second.Identity() {
		t.Fatal("resolver configuration omitted from catalog identity")
	}
}
