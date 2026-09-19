package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPermissionInspectorRefusesUnprovenRuntimeGrant(t *testing.T) {
	for _, name := range []string{"different-installation", "unverified-effective-permissions"} {
		t.Run(name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/user/installations":
					if r.Header.Get("Authorization") != "Bearer github-token" {
						t.Error("wrong setup credential")
					}
					_, _ = w.Write([]byte(`{"total_count":1,"installations":[{"id":42,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"read","pull_requests":"read"},"events":["pull_request"],"suspended_at":null}]}`))
				case "/installation/repositories":
					if r.Header.Get("Authorization") != "Bearer "+name {
						t.Error("wrong runtime credential")
					}
					// This endpoint proves repository membership, not the credential's
					// installation identity or its full effective permission grant.
					_, _ = w.Write([]byte(`{"total_count":1,"repositories":[{"id":99,"full_name":"owner/repo"}]}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			runtimeToken, err := NewToken([]byte(name))
			if err != nil {
				t.Fatal(err)
			}
			config := permissionConfigFixture(server, &tokenProvider{token: testToken(t)})
			config.RuntimeCredentials = &tokenProvider{token: runtimeToken}
			inspector, err := NewPermissionInspector(config)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := inspector.Inspect(context.Background())
			if err == nil || observed.Identity() != "" {
				t.Errorf("unproven runtime grant produced verified observation after %d requests", requests)
			}
		})
	}
}
