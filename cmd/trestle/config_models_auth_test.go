package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/modelcatalog"
)

func TestConfigModelsAuthenticatedRefreshApply(t *testing.T) {
	const reference = "OPEN_TRESTLE_PROVIDER_METADATA"
	const secret = "synthetic-metadata-key"
	t.Setenv(reference, secret)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != "GET" || r.URL.Path != "/v1/models" || r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("metadata request lost its explicit authentication authority")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"data":[{"id":"Provider/Exact:Tag"}]}`)
	}))
	defer server.Close()
	dir := t.TempDir()
	sources, current, proposal := filepath.Join(dir, "sources.json"), filepath.Join(dir, "catalog.json"), filepath.Join(dir, "proposal.json")
	manifest := fmt.Sprintf(`{"schema_version":2,"sources":[{"id":"authenticated","kind":"openai_models","url":%q,"credential_environment":%q}]}`, server.URL+"/v1/models", reference)
	if err := os.WriteFile(sources, []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := runConfig([]string{"models", "refresh", "--sources", sources, "--current", current, "--proposal", proposal}, &out, &stderr); code != 0 {
		t.Fatalf("authenticated refresh=%d: %s", code, stderr.String())
	}
	var review modelcatalog.Review
	if err := json.Unmarshal(out.Bytes(), &review); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || len(review.Failures) != 0 || len(review.Diff.Added) != 1 || review.Diff.Added[0].Selector != "Provider/Exact:Tag" {
		t.Fatal("authenticated metadata was not staged")
	}
	staged, err := os.ReadFile(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(staged), secret) || strings.Contains(out.String()+stderr.String(), secret) {
		t.Fatal("credential leaked")
	}
	t.Setenv(reference, "invalid key")
	out.Reset()
	stderr.Reset()
	if code := runConfig([]string{"models", "apply", "--sources", sources, "--current", current, "--proposal", proposal, "--expected-proposal", review.ProposalDigest, "--expected-current", review.CurrentDigest}, &out, &stderr); code != 0 {
		t.Fatalf("metadata apply unexpectedly requires credential: %s", stderr.String())
	}
	if requests != 1 {
		t.Fatal("apply made a request")
	}
	applied, err := os.ReadFile(current)
	if err != nil || bytes.Contains(applied, []byte(secret)) {
		t.Fatal("catalog missing or credential leaked")
	}
}
