package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func permissionConfigFixture(server *httptest.Server, provider TokenProvider) PermissionConfig {
	runtimeToken, _ := NewToken([]byte("runtime-token"))
	return PermissionConfig{APIEndpoint: server.URL, APIVersion: "2026-03-10", InstallationID: 42, RepositoryFullName: "owner/repo", UserCredentialIdentity: strings.Repeat("a", 64), RuntimeCredentialIdentity: strings.Repeat("c", 64), UserCredentials: provider, RuntimeCredentials: &tokenProvider{token: runtimeToken}, Timeout: 5 * time.Second}
}
func TestPermissionInspectorAcceptsExactReadOnlySelectedRepository(t *testing.T) {
	f := permissionBrokerNewFixture(t, permissionBrokerNewKey(t), permissionBrokerOptions{})
	observation, err := f.inspector.Inspect(context.Background())
	f.permissionBrokerAssertEffects(t, 1, true, true)
	if err != nil || observation.Validate() != nil || observation.AuthorityIdentity() != f.inspector.AuthorityIdentity() || observation.Identity() == "" {
		t.Fatalf("observation=%#v err=%v", observation, err)
	}
	formatted := fmt.Sprintf("%#v %#v", f.inspector, observation)
	if strings.Contains(formatted, f.server.URL) || strings.Contains(formatted, "owner/repo") {
		t.Fatal("formatter leaked authority")
	}
}

func TestPermissionInspectorRejectsWriteExtraRepositoryAndSuspension(t *testing.T) {
	key := permissionBrokerNewKey(t)
	tests := []struct {
		name, installation, repositories string
		wantRequests                     int
	}{{"write", `{"id":42,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"read","pull_requests":"write"},"events":["pull_request"],"suspended_at":null}`, `[{"id":99,"full_name":"owner/repo"}]`, 1}, {"duplicate permission", `{"id":42,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"write","contents":"read","pull_requests":"read"},"events":["pull_request"],"suspended_at":null}`, `[{"id":99,"full_name":"owner/repo"}]`, 1}, {"extra repository", `{"id":42,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"read","pull_requests":"read"},"events":["pull_request"],"suspended_at":null}`, `[{"id":99,"full_name":"owner/repo"},{"id":100,"full_name":"owner/other"}]`, 3}, {"all repositories", `{"id":42,"account":{"login":"owner"},"repository_selection":"all","permissions":{"metadata":"read","contents":"read","pull_requests":"read"},"events":["pull_request"],"suspended_at":null}`, `[{"id":99,"full_name":"owner/repo"}]`, 1}, {"extra permission", `{"id":42,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"read","pull_requests":"read","checks":"read"},"events":["pull_request"],"suspended_at":null}`, `[{"id":99,"full_name":"owner/repo"}]`, 1}, {"extra event", `{"id":42,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"read","pull_requests":"read"},"events":["pull_request","push"],"suspended_at":null}`, `[{"id":99,"full_name":"owner/repo"}]`, 1}, {"suspended", `{"id":42,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"read","pull_requests":"read"},"events":["pull_request"],"suspended_at":"2026-01-01T00:00:00Z"}`, `[{"id":99,"full_name":"owner/repo"}]`, 1}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := permissionBrokerNewFixture(t, key, permissionBrokerOptions{installation: test.installation, repositories: test.repositories})
			observation, err := f.inspector.Inspect(context.Background())
			f.permissionBrokerAssertEffects(t, 1, test.wantRequests == 3, false)
			if observation.Identity() != "" || !errors.Is(err, ErrPermissionMismatch) {
				t.Fatalf("observation=%#v err=%v", observation, err)
			}
		})
	}
}

func TestPermissionInspectorSeparatesDeniedAndUnavailable(t *testing.T) {
	key := permissionBrokerNewKey(t)
	for _, test := range []struct {
		status int
		want   error
	}{{http.StatusUnauthorized, ErrPermissionDenied}, {http.StatusForbidden, ErrPermissionDenied}, {http.StatusTooManyRequests, ErrPermissionUnavailable}, {http.StatusInternalServerError, ErrPermissionUnavailable}} {
		t.Run(fmt.Sprint(test.status), func(t *testing.T) {
			f := permissionBrokerNewFixture(t, key, permissionBrokerOptions{status: test.status})
			observation, err := f.inspector.Inspect(context.Background())
			f.permissionBrokerAssertEffects(t, 1, false, false)
			if observation.Identity() != "" || !errors.Is(err, test.want) {
				t.Fatalf("status=%d observation=%#v err=%v", test.status, observation, err)
			}
		})
	}
}

func TestPermissionInspectorBoundsAndValidatesInstallationPagination(t *testing.T) {
	template := func(id uint64) map[string]any {
		return map[string]any{"id": id, "account": map[string]any{"login": "owner"}, "repository_selection": "selected", "permissions": map[string]any{"metadata": "read", "contents": "read", "pull_requests": "read"}, "events": []string{"pull_request"}, "suspended_at": nil}
	}
	pageOne := make([]map[string]any, 100)
	for index := range pageOne {
		pageOne[index] = template(uint64(1000 + index))
	}
	first, err := json.Marshal(map[string]any{"total_count": 101, "installations": pageOne})
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(map[string]any{"total_count": 101, "installations": []map[string]any{template(42)}})
	if err != nil {
		t.Fatal(err)
	}
	key := permissionBrokerNewKey(t)
	t.Run("two pages", func(t *testing.T) {
		f := permissionBrokerNewFixture(t, key, permissionBrokerOptions{pages: []string{string(first), string(second)}})
		observation, err := f.inspector.Inspect(context.Background())
		f.permissionBrokerAssertEffects(t, 2, true, true)
		if err != nil || observation.Validate() != nil {
			t.Fatalf("observation=%#v err=%v", observation, err)
		}
	})
	t.Run("large", func(t *testing.T) {
		f := permissionBrokerNewFixture(t, key, permissionBrokerOptions{pages: []string{`{"total_count":1001,"installations":[]}`}})
		observation, err := f.inspector.Inspect(context.Background())
		f.permissionBrokerAssertEffects(t, 1, false, false)
		if observation.Identity() != "" || !errors.Is(err, ErrPermissionUnavailable) {
			t.Fatalf("large observation=%#v err=%v", observation, err)
		}
	})
}

func TestPermissionInspectorPreservesEnterpriseAPIBasePath(t *testing.T) {
	f := permissionBrokerNewFixture(t, permissionBrokerNewKey(t), permissionBrokerOptions{basePath: "/api/v3"})
	observation, err := f.inspector.Inspect(context.Background())
	f.permissionBrokerAssertEffects(t, 1, true, true)
	if err != nil || observation.Validate() != nil {
		t.Fatalf("observation=%#v err=%v", observation, err)
	}
}

func TestPermissionInspectorRejectsRedirectAndDuplicateCriticalJSON(t *testing.T) {
	key := permissionBrokerNewKey(t)
	t.Run("redirect", func(t *testing.T) {
		var targetRequests atomic.Int64
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			targetRequests.Add(1)
			http.Error(w, "redirect must not be followed", http.StatusBadRequest)
		}))
		t.Cleanup(target.Close)
		f := permissionBrokerNewFixture(t, key, permissionBrokerOptions{status: http.StatusFound, headers: map[string]string{"Location": target.URL}})
		observation, err := f.inspector.Inspect(context.Background())
		f.permissionBrokerAssertEffects(t, 1, false, false)
		if observation.Identity() != "" || !errors.Is(err, ErrPermissionUnavailable) || targetRequests.Load() != 0 {
			t.Fatalf("redirect observation=%#v err=%v target requests=%d", observation, err, targetRequests.Load())
		}
	})
	t.Run("duplicate critical JSON", func(t *testing.T) {
		f := permissionBrokerNewFixture(t, key, permissionBrokerOptions{installation: `{"id":42,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"write","contents":"read","pull_requests":"read"},"events":["pull_request"],"suspended_at":null}`})
		observation, err := f.inspector.Inspect(context.Background())
		f.permissionBrokerAssertEffects(t, 1, false, false)
		if observation.Identity() != "" || !errors.Is(err, ErrPermissionMismatch) {
			t.Fatalf("duplicate observation=%#v err=%v", observation, err)
		}
	})
}

func TestPermissionInspectorRejectsSameUserAndRuntimeToken(t *testing.T) {
	f := permissionBrokerNewFixture(t, permissionBrokerNewKey(t), permissionBrokerOptions{issuedToken: "github-token"})
	observation, err := f.inspector.Inspect(context.Background())
	f.permissionBrokerAssertEffects(t, 1, true, true)
	if observation.Identity() != "" || !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("observation=%#v err=%v", observation, err)
	}
}

func TestPermissionInspectorTreatsRateLimitedForbiddenAsUnavailable(t *testing.T) {
	f := permissionBrokerNewFixture(t, permissionBrokerNewKey(t), permissionBrokerOptions{status: http.StatusForbidden, headers: map[string]string{"X-RateLimit-Remaining": "0"}})
	observation, err := f.inspector.Inspect(context.Background())
	f.permissionBrokerAssertEffects(t, 1, false, false)
	if observation.Identity() != "" || !errors.Is(err, ErrPermissionUnavailable) {
		t.Fatalf("observation=%#v err=%v", observation, err)
	}
}

func TestPermissionAuthorityBindsBothCredentialReferencesAndLimits(t *testing.T) {
	first, err := PermissionAuthorityIdentity("https://api.github.com", "2026-03-10", 42, "owner/repo", strings.Repeat("a", 64), strings.Repeat("c", 64), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if identity, err := PermissionAuthorityIdentity("https://api.github.com", "2026-03-10", 42, "owner/.github", strings.Repeat("a", 64), strings.Repeat("c", 64), 30*time.Second); err != nil || identity == "" {
		t.Fatalf("dot repository=%s %v", identity, err)
	}
	same, _ := PermissionAuthorityIdentity("https://api.github.com/", "2026-03-10", 42, "owner/repo", strings.Repeat("a", 64), strings.Repeat("c", 64), 30*time.Second)
	changed, _ := PermissionAuthorityIdentity("https://api.github.com", "2026-03-10", 42, "owner/repo", strings.Repeat("a", 64), strings.Repeat("d", 64), 30*time.Second)
	if first != "15e63a31ee3f71e831be841246d5c4bca725de4466b8e92414dac70a88770467" || same != first || changed == first {
		t.Fatalf("identities=%s/%s/%s", first, same, changed)
	}
}

func TestPermissionInspectorPrivatelyOwnsTransportConfiguration(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	inspector, err := NewPermissionInspector(permissionConfigFixture(server, &tokenProvider{token: testToken(t)}))
	if err != nil || !validPermissionTransport(inspector.transport) {
		t.Fatalf("inspector=%#v err=%v", inspector, err)
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	inspector.transport.Protocols = protocols
	if inspector.Validate() == nil {
		t.Fatal("mutated private transport validated")
	}
}

func TestPermissionTransportTemplateExcludesAlternateAuthority(t *testing.T) {
	transport := newPermissionTransport()
	if !validPermissionTransport(transport) || transport.Protocols == nil || !transport.Protocols.HTTP1() || transport.Protocols.HTTP2() || transport.Protocols.UnencryptedHTTP2() || len(transport.TLSNextProto) != 0 || len(transport.TLSClientConfig.NextProtos) != 0 || transport.TLSClientConfig.RootCAs != nil || transport.TLSClientConfig.ServerName != "" || transport.TLSClientConfig.KeyLogWriter != nil {
		t.Fatalf("transport=%#v", transport)
	}
}
