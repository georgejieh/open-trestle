package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestNewRepositoryIdentityAcceptsCanonicalScope(t *testing.T) {
	namespace := []string{"team", "platform"}
	repository, err := NewRepositoryIdentity("git.example.com", namespace, "open-trestle")
	if err != nil {
		t.Fatalf("NewRepositoryIdentity() error = %v", err)
	}
	if len(repository.Identity()) != 64 || repository.Authority() != "git.example.com" || repository.Name() != "open-trestle" {
		t.Fatalf("repository = (%q, %q, %q)", repository.Identity(), repository.Authority(), repository.Name())
	}
	if got := repository.Namespace(); len(got) != 2 || got[0] != "team" || got[1] != "platform" {
		t.Fatalf("Namespace() = %v", got)
	}
	repeated, err := NewRepositoryIdentity("git.example.com", []string{"team", "platform"}, "open-trestle")
	if err != nil || repeated.Identity() != repository.Identity() {
		t.Fatalf("repeated = (%#v, %v), want identity %q", repeated, err, repository.Identity())
	}
}

func TestRepositoryIdentityUsesCanonicalPreimage(t *testing.T) {
	repository, err := NewRepositoryIdentity("git.example.com", []string{"team", "platform"}, "open-trestle")
	if err != nil {
		t.Fatalf("NewRepositoryIdentity() error = %v", err)
	}
	preimage := `{"contract":"open-trestle/repository-identity","schema_version":1,"authority":"git.example.com","namespace":["team","platform"],"name":"open-trestle"}`
	digest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(digest[:]); repository.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", repository.Identity(), preimage)
	}
}

func TestRepositoryIdentityPreservesScopeSyntax(t *testing.T) {
	testCases := []struct {
		name      string
		namespace []string
		repoName  string
	}{
		{name: "namespace case", namespace: []string{"Team", "platform"}, repoName: "repo"},
		{name: "name case", namespace: []string{"team", "platform"}, repoName: "Repo"},
		{name: "namespace order", namespace: []string{"platform", "team"}, repoName: "repo"},
		{name: "namespace count", namespace: []string{"team.platform"}, repoName: "repo"},
		{name: "single space", namespace: []string{"team", "platform"}, repoName: "Data Science"},
		{name: "double space", namespace: []string{"team", "platform"}, repoName: "Data  Science"},
		{name: "dot git", namespace: []string{"team", "platform"}, repoName: "repo.git"},
	}
	identities := make(map[string]string, len(testCases))
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			repository, err := NewRepositoryIdentity("git.example.com", testCase.namespace, testCase.repoName)
			if err != nil {
				t.Fatalf("NewRepositoryIdentity() error = %v", err)
			}
			if prior, ok := identities[repository.Identity()]; ok {
				t.Fatalf("%s and %s produced identity %q", testCase.name, prior, repository.Identity())
			}
			identities[repository.Identity()] = testCase.name
		})
	}
}

func TestRepositoryIdentityChangesWithAuthority(t *testing.T) {
	first, err := NewRepositoryIdentity("git.example.com", []string{"team"}, "repo")
	if err != nil {
		t.Fatalf("NewRepositoryIdentity(first) error = %v", err)
	}
	second, err := NewRepositoryIdentity("code.example.com", []string{"team"}, "repo")
	if err != nil {
		t.Fatalf("NewRepositoryIdentity(second) error = %v", err)
	}
	if first.Identity() == second.Identity() {
		t.Fatalf("different authorities produced identity %q", first.Identity())
	}
}

func TestNewRepositoryIdentityAcceptsScopeAllowlist(t *testing.T) {
	values := []string{
		"Team",
		"platform-core",
		"my_repo",
		"repo.v2",
		"Data Science",
		"Data  Science",
		".github",
		"repo.",
		"_repo",
		"repo_",
		"-repo",
		"repo-",
	}
	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			if _, err := NewRepositoryIdentity("git.example.com", []string{value}, value); err != nil {
				t.Fatalf("NewRepositoryIdentity(%q) error = %v", value, err)
			}
		})
	}
}

func TestNewRepositoryIdentityRejectsScopePunctuation(t *testing.T) {
	const rejectedPunctuation = `!"#$%&'()*+,/:;<=>?@[\]^` + "`" + `{|}~`
	for i := 0; i < len(rejectedPunctuation); i++ {
		value := "a" + string(rejectedPunctuation[i]) + "b"
		t.Run(fmt.Sprintf("%02x", rejectedPunctuation[i]), func(t *testing.T) {
			if repository, err := NewRepositoryIdentity("git.example.com", []string{value}, "repo"); err == nil || repository.Identity() != "" {
				t.Fatalf("NewRepositoryIdentity(namespace %q) = (%#v, %v), want zero error result", value, repository, err)
			}
			if repository, err := NewRepositoryIdentity("git.example.com", []string{"team"}, value); err == nil || repository.Identity() != "" {
				t.Fatalf("NewRepositoryIdentity(name %q) = (%#v, %v), want zero error result", value, repository, err)
			}
		})
	}
}

func TestNewRepositoryIdentityRejectsInvalidScopeValues(t *testing.T) {
	testCases := []struct {
		name      string
		namespace []string
		repoName  string
	}{
		{name: "nil namespace", repoName: "repo"},
		{name: "empty namespace", namespace: []string{}, repoName: "repo"},
		{name: "empty segment", namespace: []string{"team", ""}, repoName: "repo"},
		{name: "dot segment", namespace: []string{"."}, repoName: "repo"},
		{name: "dot dot segment", namespace: []string{".."}, repoName: "repo"},
		{name: "punctuation segment", namespace: []string{"---"}, repoName: "repo"},
		{name: "underscore segment", namespace: []string{"___"}, repoName: "repo"},
		{name: "spaces segment", namespace: []string{"   "}, repoName: "repo"},
		{name: "leading space", namespace: []string{" team"}, repoName: "repo"},
		{name: "trailing space", namespace: []string{"team "}, repoName: "repo"},
		{name: "tab", namespace: []string{"te\tam"}, repoName: "repo"},
		{name: "newline", namespace: []string{"te\nam"}, repoName: "repo"},
		{name: "non-breaking space", namespace: []string{"te\u00a0am"}, repoName: "repo"},
		{name: "Unicode", namespace: []string{"例"}, repoName: "repo"},
		{name: "empty name", namespace: []string{"team"}},
		{name: "punctuation name", namespace: []string{"team"}, repoName: "..."},
		{name: "leading name space", namespace: []string{"team"}, repoName: " repo"},
		{name: "trailing name space", namespace: []string{"team"}, repoName: "repo "},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			repository, err := NewRepositoryIdentity("git.example.com", testCase.namespace, testCase.repoName)
			if err == nil || repository.Identity() != "" {
				t.Fatalf("NewRepositoryIdentity() = (%#v, %v), want zero error result", repository, err)
			}
		})
	}
}

func TestNewRepositoryIdentityEnforcesScopeBounds(t *testing.T) {
	segments32 := make([]string, 32)
	for i := range segments32 {
		segments32[i] = fmt.Sprintf("s%d", i)
	}
	if _, err := NewRepositoryIdentity("git.example.com", segments32, "repo"); err != nil {
		t.Fatalf("NewRepositoryIdentity(32 segments) error = %v", err)
	}
	segments33 := append(append([]string{}, segments32...), "extra")
	if repository, err := NewRepositoryIdentity("git.example.com", segments33, "repo"); err == nil || repository.Identity() != "" {
		t.Fatalf("NewRepositoryIdentity(33 segments) = (%#v, %v), want zero error result", repository, err)
	}
	if _, err := NewRepositoryIdentity("git.example.com", []string{strings.Repeat("a", 255)}, strings.Repeat("b", 255)); err != nil {
		t.Fatalf("NewRepositoryIdentity(255-byte values) error = %v", err)
	}
	for name, namespace := range map[string][]string{
		"256-byte segment": {strings.Repeat("a", 256)},
	} {
		t.Run(name, func(t *testing.T) {
			if repository, err := NewRepositoryIdentity("git.example.com", namespace, "repo"); err == nil || repository.Identity() != "" {
				t.Fatalf("NewRepositoryIdentity() = (%#v, %v), want zero error result", repository, err)
			}
		})
	}
	if repository, err := NewRepositoryIdentity("git.example.com", []string{"team"}, strings.Repeat("a", 256)); err == nil || repository.Identity() != "" {
		t.Fatalf("NewRepositoryIdentity(256-byte name) = (%#v, %v), want zero error result", repository, err)
	}
	exactScope := make([]string, 16)
	for i := range exactScope {
		exactScope[i] = strings.Repeat("a", 240)
	}
	if _, err := NewRepositoryIdentity("git.example.com", exactScope, strings.Repeat("b", 240)); err != nil {
		t.Fatalf("NewRepositoryIdentity(4096-byte scope) error = %v", err)
	}
	if repository, err := NewRepositoryIdentity("git.example.com", exactScope, strings.Repeat("b", 241)); err == nil || repository.Identity() != "" {
		t.Fatalf("NewRepositoryIdentity(4097-byte scope) = (%#v, %v), want zero error result", repository, err)
	}
}

func TestNewRepositoryIdentityAcceptsCanonicalAuthorities(t *testing.T) {
	authorities := []string{
		"gitlab",
		"localhost",
		"git.example.com",
		"1.2.git.4",
		"0.0.0.0",
		"1.2.3.4",
		"9.10.99.100",
		"255.255.255.255",
	}
	for _, authority := range authorities {
		t.Run(authority, func(t *testing.T) {
			repository, err := NewRepositoryIdentity(authority, []string{"team"}, "repo")
			if err != nil || repository.Authority() != authority {
				t.Fatalf("NewRepositoryIdentity() = (%#v, %v)", repository, err)
			}
		})
	}
}

func TestNewRepositoryIdentityRejectsInvalidAuthorities(t *testing.T) {
	authorities := []string{
		"",
		"Git.Example.com",
		"git.example.com.",
		"https://git.example.com",
		"user@git.example.com",
		"git.example.com:443",
		"git.example.com/team",
		"git.example.com?x=1",
		"git.example.com#fragment",
		" git.example.com",
		"git.example.com ",
		"git\\example.com",
		"git%2eexample.com",
		"例.example.com",
		"-git.example.com",
		"git-.example.com",
		"git..example.com",
		"-",
		"01.2.3.4",
		"1.02.3.4",
		"1.2.003.4",
		"256.1.1.1",
		"1.2.3.999",
	}
	for _, authority := range authorities {
		t.Run(authority, func(t *testing.T) {
			repository, err := NewRepositoryIdentity(authority, []string{"team"}, "repo")
			if err == nil || repository.Identity() != "" {
				t.Fatalf("NewRepositoryIdentity() = (%#v, %v), want zero error result", repository, err)
			}
		})
	}
}

func TestNewRepositoryIdentityEnforcesAuthorityBounds(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	if _, err := NewRepositoryIdentity(label63+".b", []string{"team"}, "repo"); err != nil {
		t.Fatalf("NewRepositoryIdentity(63-byte label) error = %v", err)
	}
	if repository, err := NewRepositoryIdentity(strings.Repeat("a", 64)+".b", []string{"team"}, "repo"); err == nil || repository.Identity() != "" {
		t.Fatalf("NewRepositoryIdentity(64-byte label) = (%#v, %v), want zero error result", repository, err)
	}
	authority253 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("b", 61)
	if len(authority253) != 253 {
		t.Fatalf("authority length = %d, want 253", len(authority253))
	}
	if _, err := NewRepositoryIdentity(authority253, []string{"team"}, "repo"); err != nil {
		t.Fatalf("NewRepositoryIdentity(253-byte authority) error = %v", err)
	}
	authority254 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("b", 62)
	if repository, err := NewRepositoryIdentity(authority254, []string{"team"}, "repo"); err == nil || repository.Identity() != "" {
		t.Fatalf("NewRepositoryIdentity(254-byte authority) = (%#v, %v), want zero error result", repository, err)
	}
}

func TestRepositoryIdentityDefensivelyCopiesNamespace(t *testing.T) {
	namespace := []string{"team", "platform"}
	repository, err := NewRepositoryIdentity("git.example.com", namespace, "repo")
	if err != nil {
		t.Fatalf("NewRepositoryIdentity() error = %v", err)
	}
	identity := repository.Identity()
	namespace[0] = "changed"
	returned := repository.Namespace()
	returned[1] = "changed"
	if repository.Identity() != identity || repository.Namespace()[0] != "team" || repository.Namespace()[1] != "platform" {
		t.Fatal("namespace mutation changed RepositoryIdentity")
	}
}

func TestRepositoryIdentityZeroValueIsEmpty(t *testing.T) {
	var repository RepositoryIdentity
	if repository.Identity() != "" || repository.Authority() != "" || repository.Name() != "" || len(repository.Namespace()) != 0 {
		t.Fatalf("zero RepositoryIdentity = %#v", repository)
	}
}
