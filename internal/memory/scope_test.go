package memory

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func testScope(t *testing.T) Scope {
	t.Helper()
	scope, err := NewScope("tenant-1", "repo-1", "actor-1", RefVisibilityExact, strings.Repeat("a", 64), []string{"internal/review", "cmd"})
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func TestNewScopeCanonicalizesHardPartition(t *testing.T) {
	scope := testScope(t)
	if scope.Identity() == "" || scope.TenantID() != "tenant-1" || scope.RepositoryID() != "repo-1" || scope.ActorID() != "actor-1" || scope.RefVisibility() != RefVisibilityExact || scope.RefSetIdentity() != strings.Repeat("a", 64) || !reflect.DeepEqual(scope.PathPrefixes(), []string{"cmd", "internal/review"}) || scope.Validate() != nil {
		t.Fatalf("scope did not round trip: %#v", scope)
	}
	prefixes := scope.PathPrefixes()
	prefixes[0] = "changed"
	if scope.PathPrefixes()[0] != "cmd" {
		t.Fatal("scope exposed mutable prefixes")
	}
	if !scope.AllowsPath("cmd/trestle/main.go") || !scope.AllowsPath("internal/review") || scope.AllowsPath("internal/reviewer/file.go") || scope.AllowsPath("docs/readme.md") {
		t.Fatal("scope path boundary was not enforced")
	}
	reversed, _ := NewScope("tenant-1", "repo-1", "actor-1", RefVisibilityExact, strings.Repeat("a", 64), []string{"cmd", "internal/review"})
	if reversed.Identity() != scope.Identity() || !reflect.DeepEqual(reversed.PathPrefixes(), scope.PathPrefixes()) {
		t.Fatal("equivalent prefix sets were not canonical")
	}
	otherActor, _ := NewScope("tenant-1", "repo-1", "actor-2", RefVisibilityExact, strings.Repeat("a", 64), []string{"cmd", "internal/review"})
	otherRef, _ := NewScope("tenant-1", "repo-1", "actor-1", RefVisibilityExact, strings.Repeat("b", 64), []string{"cmd", "internal/review"})
	if otherActor.Identity() == scope.Identity() || otherRef.Identity() == scope.Identity() {
		t.Fatal("scope identity ignored actor or ref visibility")
	}
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v"} {
		formatted := fmt.Sprintf(format, scope)
		if strings.Contains(formatted, "tenant-1") || strings.Contains(formatted, "internal/review") {
			t.Fatalf("scope formatting leaked: %q", formatted)
		}
	}
}

func TestScopeSupportsExplicitRepositoryWidePrefix(t *testing.T) {
	scope, err := NewScope("tenant", "repo", "actor", RefVisibilityReachable, strings.Repeat("a", 64), []string{"."})
	if err != nil || !scope.AllowsPath("any/path.go") || !scope.AllowsPath("root.go") || scope.AllowsPath("../outside") {
		t.Fatalf("repository scope = (%#v, %v)", scope, err)
	}
}

func TestNewScopeRejectsInvalidFields(t *testing.T) {
	validDigest := strings.Repeat("a", 64)
	for _, test := range []struct {
		name, tenant, repository, actor, ref string
		visibility                           RefVisibility
		prefixes                             []string
		want                                 error
	}{
		{"tenant", "Tenant", "repo", "actor", validDigest, RefVisibilityExact, []string{"."}, ErrInvalidScopeIdentifier},
		{"repository", "tenant", "../repo", "actor", validDigest, RefVisibilityExact, []string{"."}, ErrInvalidScopeIdentifier},
		{"actor", "tenant", "repo", "actor space", validDigest, RefVisibilityExact, []string{"."}, ErrInvalidScopeIdentifier},
		{"visibility", "tenant", "repo", "actor", validDigest, 0, []string{"."}, ErrInvalidRefVisibility},
		{"ref", "tenant", "repo", "actor", "bad", RefVisibilityExact, []string{"."}, ErrInvalidRefSetIdentity},
		{"zero ref", "tenant", "repo", "actor", strings.Repeat("0", 64), RefVisibilityExact, []string{"."}, ErrInvalidRefSetIdentity},
		{"empty paths", "tenant", "repo", "actor", validDigest, RefVisibilityExact, nil, ErrInvalidScopePathPrefix},
		{"traversal", "tenant", "repo", "actor", validDigest, RefVisibilityExact, []string{"../secret"}, ErrInvalidScopePathPrefix},
		{"absolute", "tenant", "repo", "actor", validDigest, RefVisibilityExact, []string{"/secret"}, ErrInvalidScopePathPrefix},
		{"duplicate", "tenant", "repo", "actor", validDigest, RefVisibilityExact, []string{"cmd", "cmd"}, ErrDuplicateScopePathPrefix},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope, err := NewScope(test.tenant, test.repository, test.actor, test.visibility, test.ref, test.prefixes)
			if !errors.Is(err, test.want) || scope.Identity() != "" {
				t.Fatalf("NewScope() = (%#v, %v), want %v", scope, err, test.want)
			}
		})
	}
}

func TestRefVisibilityRoundTrips(t *testing.T) {
	for _, value := range []string{"exact", "reachable"} {
		visibility, err := ParseRefVisibility(value)
		if err != nil || visibility.String() != value || visibility.Validate() != nil {
			t.Fatalf("ParseRefVisibility(%q) = (%v, %v)", value, visibility, err)
		}
	}
	if visibility, err := ParseRefVisibility("all"); !errors.Is(err, ErrInvalidRefVisibility) || visibility != 0 {
		t.Fatalf("invalid visibility = (%v, %v)", visibility, err)
	}
}
