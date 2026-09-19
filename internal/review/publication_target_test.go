package review

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func publicationTargetFixture(t *testing.T) PublicationTarget {
	t.Helper()
	repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	if err != nil {
		t.Fatal(err)
	}
	target, err := NewPublicationTarget("github", repository, "pull-42", revision)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestNewPublicationTargetBindsExactRepositoryChangeAndHead(t *testing.T) {
	target := publicationTargetFixture(t)
	if target.Identity() == "" || target.PublisherID() != "github" || target.RepositoryIdentity().Identity() == "" || target.ChangeID() != "pull-42" || target.HeadRevision().Digest() != strings.Repeat("a", 40) || target.Validate() != nil {
		t.Fatalf("target did not round trip: %#v", target)
	}
	if fmt.Sprint(target) != "source-control publication target" || strings.Contains(fmt.Sprintf("%v", target), "pull-42") {
		t.Fatalf("target formatting leaked: %v", target)
	}
}

func TestNewPublicationTargetRejectsInvalidFields(t *testing.T) {
	valid := publicationTargetFixture(t)
	for _, test := range []struct {
		name, publisher, change string
		repository              evidence.RepositoryIdentity
		revision                evidence.RevisionIdentity
		want                    error
	}{
		{"publisher", "Bad", "pull-1", valid.RepositoryIdentity(), valid.HeadRevision(), ErrInvalidPublisherID},
		{"repository", "github", "pull-1", evidence.RepositoryIdentity{}, valid.HeadRevision(), ErrInvalidPublicationRepository},
		{"change", "github", "../pull", valid.RepositoryIdentity(), valid.HeadRevision(), ErrInvalidPublicationChangeID},
		{"revision", "github", "pull-1", valid.RepositoryIdentity(), evidence.RevisionIdentity{}, ErrInvalidPublicationRevision},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, err := NewPublicationTarget(test.publisher, test.repository, test.change, test.revision)
			if !errors.Is(err, test.want) || target.Identity() != "" {
				t.Fatalf("NewPublicationTarget() = (%#v, %v), want %v", target, err, test.want)
			}
		})
	}
}

func TestPublicationTargetRejectsTampering(t *testing.T) {
	target := publicationTargetFixture(t)
	forged := target
	forged.identity = strings.Repeat("f", 64)
	if !errors.Is(forged.Validate(), ErrInvalidPublicationTargetIdentity) {
		t.Fatal("forged publication target accepted")
	}
}
