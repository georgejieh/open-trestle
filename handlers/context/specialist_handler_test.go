package context

import (
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/review"
)

func TestSpecialistHandlerBindsProfileIntoIdentityOnly(t *testing.T) {
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 16)
	if err != nil {
		t.Fatal(err)
	}
	clock := contextTestClock{time.UnixMilli(230)}
	calls, requestIdentity := 0, ""
	authorizer := contextTestAuthorizer{identity: strings.Repeat("5", 64), calls: &calls, requestIdentity: &requestIdentity}
	sanitizer := contextTestSanitizer{}
	plain, err := NewHandler(store, clock, authorizer, sanitizer)
	if err != nil {
		t.Fatal(err)
	}
	if plain.HandlerIdentity() != deriveHandlerIdentity(authorizer.Identity(), sanitizer.Identity(), review.ContextSpecialist{}, "", "", review.ContextBudget{}) {
		t.Fatal("plain handler identity changed")
	}
	bugHunter, err := review.NewContextSpecialist("bug_hunter")
	if err != nil {
		t.Fatal(err)
	}
	backend, err := review.NewContextSpecialist("backend")
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewSpecialistHandler(store, clock, authorizer, sanitizer, bugHunter)
	if err != nil || first.Validate() != nil {
		t.Fatal("specialist handler rejected a packaged profile")
	}
	second, err := NewSpecialistHandler(store, clock, authorizer, sanitizer, backend)
	if err != nil {
		t.Fatal(err)
	}
	if first.HandlerIdentity() == plain.HandlerIdentity() || first.HandlerIdentity() == second.HandlerIdentity() || !validDigest(first.HandlerIdentity()) {
		t.Fatal("handler identity does not bind the selected specialist")
	}
	if _, err := NewSpecialistHandler(store, clock, authorizer, sanitizer, review.ContextSpecialist{}); err == nil {
		t.Fatal("specialist handler accepted no specialist")
	}
	relabeled := *first
	relabeled.specialist = backend
	if relabeled.Validate() == nil {
		t.Fatal("handler accepted a specialist that differs from its identity")
	}
	if calls != 0 {
		t.Fatal("constructing handlers authorized a request")
	}
}
