package github

import (
	"net/http"
	"strings"
	"testing"
)

// The brokered source transport admits the merge-base compare read only in
// its exact shape: two full object IDs of one length, three dots, one page.
func TestBrokerSourceRequestAdmitsOnlyTheExactCompareRead(t *testing.T) {
	authority := brokerAuthorityFixture(t, "https://api.github.example/api/v3", strings.Repeat("e", 64))
	base, head := strings.Repeat("a", 40), strings.Repeat("b", 40)
	request := func(path, query string) *http.Request {
		t.Helper()
		target := "https://api.github.example/api/v3/repos/owner/repo/" + path
		if query != "" {
			target += "?" + query
		}
		value, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		value.Header.Set("Accept", permissionAccept)
		value.Header.Set("X-GitHub-Api-Version", "2026-03-10")
		return value
	}
	if err := validateBrokerSourceRequest(authority, request("compare/"+base+"..."+head, "per_page=1")); err != nil {
		t.Fatalf("exact compare read refused: %v", err)
	}
	sha256Base, sha256Head := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := validateBrokerSourceRequest(authority, request("compare/"+sha256Base+"..."+sha256Head, "per_page=1")); err != nil {
		t.Fatalf("exact SHA-256 compare read refused: %v", err)
	}
	for _, refused := range []struct{ path, query string }{
		{"compare/" + base + "..." + head, ""},
		{"compare/" + base + "..." + head, "per_page=2"},
		{"compare/" + base + "..." + head, "per_page=1&page=2"},
		{"compare/" + base + ".." + head, "per_page=1"},
		{"compare/" + base + "...." + head, "per_page=1"},
		{"compare/" + base + "..." + sha256Head, "per_page=1"},
		{"compare/" + strings.ToUpper(base) + "..." + head, "per_page=1"},
		{"compare/" + strings.Repeat("0", 40) + "..." + head, "per_page=1"},
		{"compare/main..." + head, "per_page=1"},
		{"compare/" + base + "..." + head + "/files", "per_page=1"},
		{"compare/" + base, "per_page=1"},
	} {
		if err := validateBrokerSourceRequest(authority, request(refused.path, refused.query)); err == nil {
			t.Fatalf("broker admitted %s?%s", refused.path, refused.query)
		}
	}
}
