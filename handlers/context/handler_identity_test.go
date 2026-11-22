package context

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/review"
)

func contextAssemblyIdentityPreimage(t *testing.T, version int, authorizer, sanitizer string) string {
	t.Helper()
	encoded, err := json.Marshal(struct {
		Contract   string `json:"contract"`
		Version    int    `json:"version"`
		Authorizer string `json:"authorizer"`
		Sanitizer  string `json:"sanitizer,omitempty"`
	}{"open-trestle/context-assembly-handler", version, authorizer, sanitizer})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// The version 11 context (the optional check_runs object and its contract
// sentence) alters the packet bytes this handler builds, so its identity moves
// to version 10, as the version 10 context moved it to version 9 and the
// earlier context changes moved it through versions 8, 7 and 6. A plan that
// recorded an earlier identity is not served by this handler.
func TestContextAssemblyHandlerIdentityIsVersionTen(t *testing.T) {
	authorizer, sanitizer := strings.Repeat("5", 64), contextTestSanitizer{}.Identity()
	current := deriveHandlerIdentity(authorizer, sanitizer, review.ContextSpecialist{}, "", "", review.ContextBudget{}, "")
	if current != contextAssemblyIdentityPreimage(t, 10, authorizer, sanitizer) {
		t.Fatal("route-granting context handler identity is not the version 10 preimage")
	}
	for _, earlier := range []int{5, 6, 7, 8, 9} {
		if current == contextAssemblyIdentityPreimage(t, earlier, authorizer, sanitizer) {
			t.Fatalf("context handler identity did not change with its packet bytes (version %d)", earlier)
		}
	}
	specialist, err := review.NewContextSpecialist("bug_hunter")
	if err != nil {
		t.Fatal(err)
	}
	if bound := deriveHandlerIdentity(authorizer, sanitizer, specialist, "", "", review.ContextBudget{}, ""); bound == current || bound == contextAssemblyIdentityPreimage(t, 5, authorizer, sanitizer) {
		t.Fatal("specialist handler identity collides with an unbound identity")
	}
	intent := strings.Repeat("6", 64)
	withIntent := deriveHandlerIdentity(authorizer, sanitizer, review.ContextSpecialist{}, intent, "", review.ContextBudget{}, "")
	if withIntent == current || withIntent == deriveHandlerIdentity(authorizer, sanitizer, specialist, intent, "", review.ContextBudget{}, "") || withIntent == deriveHandlerIdentity(authorizer, sanitizer, review.ContextSpecialist{}, strings.Repeat("7", 64), "", review.ContextBudget{}, "") {
		t.Fatal("the change intent source is not bound into the handler identity")
	}
	runs := strings.Repeat("8", 64)
	withRuns := deriveHandlerIdentity(authorizer, sanitizer, review.ContextSpecialist{}, intent, "", review.ContextBudget{}, runs)
	if withRuns == withIntent || withRuns == deriveHandlerIdentity(authorizer, sanitizer, review.ContextSpecialist{}, intent, "", review.ContextBudget{}, strings.Repeat("9", 64)) || withRuns == deriveHandlerIdentity(authorizer, sanitizer, review.ContextSpecialist{}, "", runs, review.ContextBudget{}, intent) {
		t.Fatal("the check runs are not bound into the handler identity")
	}
}

// The index source and the budget each change the packets a handler builds, so
// each is bound into the identity, and so is every field of the budget.
func TestContextAssemblyHandlerIdentityBindsIndexSourceAndBudget(t *testing.T) {
	authorizer, sanitizer := strings.Repeat("5", 64), contextTestSanitizer{}.Identity()
	derive := func(index string, budget review.ContextBudget) string {
		return deriveHandlerIdentity(authorizer, sanitizer, review.ContextSpecialist{}, "", index, budget, "")
	}
	unbound := derive("", review.ContextBudget{})
	budget := review.RouteContextBudget(64000, 4096)
	seen := map[string]string{"unbound": unbound}
	for name, identity := range map[string]string{
		"index source":       derive(strings.Repeat("8", 64), review.ContextBudget{}),
		"other index source": derive(strings.Repeat("9", 64), review.ContextBudget{}),
		"budget":             derive("", budget),
		"default budget":     derive("", review.DefaultContextBudget()),
		"source and budget":  derive(strings.Repeat("8", 64), budget),
		"other window":       derive("", review.RouteContextBudget(128000, 4096)),
		"other output":       derive("", review.RouteContextBudget(64000, 8192)),
	} {
		if previous, duplicate := seen[identity]; duplicate {
			t.Fatalf("%s handler identity equals the %s identity", name, previous)
		}
		seen[identity] = name
	}
}
