package fake

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
)

func TestNewPublisherValidatesClosedResult(t *testing.T) {
	result, _ := review.NewSuccessfulPublicationResult("external-1")
	publisher, err := NewPublisher("github", result)
	if err != nil || publisher.PublisherID() != "github" || publisher.PublishedCount() != 0 || publisher.Validate() != nil {
		t.Fatalf("publisher = (%#v, %v)", publisher, err)
	}
	if fmt.Sprint(publisher) != "fake source-control publisher" {
		t.Fatalf("publisher formatting = %v", publisher)
	}
}

func TestNewPublisherRejectsInvalidValues(t *testing.T) {
	result, _ := review.NewSuccessfulPublicationResult("external-1")
	if publisher, err := NewPublisher("Bad", result); !errors.Is(err, review.ErrInvalidPublisherID) || publisher != nil {
		t.Fatalf("invalid ID = (%#v, %v)", publisher, err)
	}
	if publisher, err := NewPublisher("github", review.PublicationResult{}); err == nil || publisher != nil {
		t.Fatalf("invalid result = (%#v, %v)", publisher, err)
	}
}

func TestPublisherFailsClosedForInvalidAndCanceledRequest(t *testing.T) {
	result, _ := review.NewSuccessfulPublicationResult("external-1")
	publisher, _ := NewPublisher("github", result)
	invalid := publisher.Publish(context.Background(), review.PublicationDispatchRequest{})
	if invalid.Status() != review.PublicationFailed || invalid.Failure() != review.PublicationFailureValidation || invalid.Validate() != nil {
		t.Fatalf("invalid request = %#v", invalid)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := publisher.Publish(ctx, review.PublicationDispatchRequest{})
	if canceled.Status() != review.PublicationFailed || canceled.Failure() != review.PublicationFailureCancelled || canceled.Validate() != nil {
		t.Fatalf("canceled request = %#v", canceled)
	}
}

func TestNewAdapterBindsPublisherAndHeadResolver(t *testing.T) {
	result, _ := review.NewSuccessfulPublicationResult("external-1")
	head, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	adapter, err := NewAdapter("github", head, result)
	if err != nil || adapter.PublisherID() != adapter.ResolverID() || adapter.Validate() != nil {
		t.Fatalf("adapter=(%#v,%v)", adapter, err)
	}
	other, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err := adapter.SetCurrentHead(other); err != nil || adapter.Validate() != nil {
		t.Fatalf("set head: %v", err)
	}
}

var _ review.Publisher = (*Publisher)(nil)
var _ review.HeadResolver = (*Publisher)(nil)

func TestPublisherDeduplicatesExactIdempotencyKey(t *testing.T) {
	result, _ := review.NewSuccessfulPublicationResult("external-1")
	publisher, _ := NewPublisher("github", result)
	first := publisher.recordPublication("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	second := publisher.recordPublication("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if first.Identity() != second.Identity() || publisher.PublishedCount() != 1 {
		t.Fatalf("idempotent results = (%#v, %#v), count=%d", first, second, publisher.PublishedCount())
	}
}
