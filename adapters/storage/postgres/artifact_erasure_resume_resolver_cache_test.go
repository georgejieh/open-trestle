package postgres

import (
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
)

func TestResumeResolverParsesEachResponseOncePerAttempt(t *testing.T) {
	g := newResumeJournalFixture(t)
	_, operation, _ := g.Prepared()
	allowance, _, _ := resumeAllowance(
		t, g.policy, operation, g.clock.Value(), "response-cache", resumeMaximum(),
	)
	request := resumeCurrentRequest(t, g, operation, allowance, "response-cache")
	attempt, err := artifact.NewErasureAttempt(request, 1, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{
		Attempt: attempt, ObservedAt: g.clock.Value(), Code: artifact.AttemptResponseAbsent,
	})
	if err != nil {
		t.Fatal(err)
	}
	parses := 0
	resolver := &resumeResolver{
		responses: map[string]artifact.AttemptResponseOptions{},
		parseResponseEvidence: func(e artifact.ErasureEvidence, a artifact.ErasureAttempt) (artifact.AttemptResponseOptions, error) {
			parses++
			return artifact.ParseAttemptResponseEvidence(e, a)
		},
	}
	parsed, err := resolver.parseResponse(evidence, attempt)
	if err != nil || parsed.Attempt.Identity() != attempt.Identity() || len(resolver.responses) != 1 || parses != 1 {
		t.Fatal("initial response parse was not retained", err)
	}
	for range 2 {
		cached, err := resolver.parseResponse(evidence, attempt)
		if err != nil || cached.Attempt.Identity() != attempt.Identity() {
			t.Fatal("validated response was not cached", err)
		}
	}
	if len(resolver.responses) != 1 || parses != 1 {
		t.Fatal("cached response changed or was parsed again")
	}
	other, err := artifact.NewErasureAttempt(request, 2, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resolver.response(evidence.Identity(), other.Identity()); ok {
		t.Fatal("response cache accepted a different attempt")
	}
}
