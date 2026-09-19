//go:build unix

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	githubsource "github.com/georgejieh/open-trestle/adapters/scm/github"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	reviewcore "github.com/georgejieh/open-trestle/internal/review"
)

func publicationBrokerBoundaryCheckConfiguredProvider(t *testing.T, environment *plannerBrokerBoundaryEnvironment, owner *githubSourceRuntime, repository evidence.RepositoryIdentity, revision evidence.RevisionIdentity) {
	t.Helper()
	t.Run("publication-provider-isolation", func(t *testing.T) {
		broker := owner.credentials.Broker()
		if broker == nil || broker.Validate() != nil || broker.Purpose() != githubsource.IssuancePurposeRuntime {
			t.Fatal("publication isolation control requires the real daemon-owned source broker")
		}
		provider := repositoryPublicationTokenProvider{tenantID: "tenant-a", repositoryID: "repo-a", repositoryFullName: "owner/repo", publisherID: "tenant-github-review", environment: "OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN", forbiddenCredentialDigest: sha256.Sum256([]byte(daemonFixtureWebhook)), getenv: environment.getenv}
		if provider.ConfigurationIdentity() != "92320fb9ff9a31843e5ba4a7938c42552e3c2ca1b78631b9b1f7f9f3bd02b1c1" {
			t.Fatal("configured publication provider identity changed")
		}
		scope, err := audit.NewReviewScope("tenant-a", "repo-a", "publication-boundary")
		if err != nil {
			t.Fatal(err)
		}
		target, err := reviewcore.NewPublicationTarget("tenant-github-review", repository, "pull-42", revision)
		if err != nil {
			t.Fatal(err)
		}
		before := environment.snapshot()
		for _, publisher := range []string{broker.AuthorityIdentity(), broker.IssuanceAuthorityIdentity()} {
			crossed, err := reviewcore.NewPublicationTarget(publisher, repository, "pull-42", revision)
			if err != nil || crossed.Validate() != nil {
				t.Fatal("source-authority publication control is not structurally valid")
			}
			token, err := provider.RetrievePublicationToken(context.Background(), scope, crossed)
			if !errors.Is(err, githubsource.ErrPublicationCredentialsUnavailable) || token.Validate() == nil {
				t.Fatal("source common or issuance-lane identity replaced the configured publisher")
			}
		}
		if !reflect.DeepEqual(before, environment.snapshot()) {
			t.Fatal("crossed source authority reached publication credential retrieval")
		}
		expectedToken, err := githubsource.NewToken([]byte(daemonFixturePublication))
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{"", daemonFixturePublication, daemonFixtureWebhook, daemonFixturePublication} {
			environment.mu.Lock()
			environment.values["OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN"] = value
			environment.mu.Unlock()
			before := environment.snapshot()
			token, err := provider.RetrievePublicationToken(context.Background(), scope, target)
			if value == daemonFixturePublication {
				if err != nil || token.Validate() != nil || !reflect.DeepEqual(token, expectedToken) {
					t.Fatal("configured publication provider did not return its exact request-time credential")
				}
			} else if !errors.Is(err, githubsource.ErrPublicationCredentialsUnavailable) || token.Validate() == nil {
				t.Fatal("live source broker bypassed missing publication credential or webhook equality fence")
			}
			after := environment.snapshot()
			before["OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN"]++
			if !reflect.DeepEqual(before, after) {
				t.Fatal("publication provider read a source or unrelated environment credential")
			}
			if provider.ConfigurationIdentity() != "92320fb9ff9a31843e5ba4a7938c42552e3c2ca1b78631b9b1f7f9f3bd02b1c1" {
				t.Fatal("credential rotation changed the publication provider configuration identity")
			}
		}
	})
}
