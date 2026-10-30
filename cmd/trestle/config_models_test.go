package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/georgejieh/open-trestle/modelcatalog"
)

func TestConfigModelsRefreshApplyAcceptance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/models" {
			t.Error("non-metadata call")
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"Provider/Exact:Tag"}]}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	sources := filepath.Join(dir, "sources.json")
	current := filepath.Join(dir, "models.json")
	proposal := filepath.Join(dir, "proposal.json")
	data, _ := json.Marshal(modelcatalog.Manifest{SchemaVersion: 1, Sources: []modelcatalog.Source{{ID: "local", Kind: "openai_models", URL: server.URL + "/models"}}})
	if err := os.WriteFile(sources, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := runConfig([]string{"models", "refresh", "--sources", sources, "--current", current, "--proposal", proposal}, &out, &stderr); code != 0 {
		t.Fatalf("refresh=%d %s", code, stderr.String())
	}
	var review modelcatalog.Review
	if err := json.Unmarshal(out.Bytes(), &review); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(current); !os.IsNotExist(err) {
		t.Fatal("refresh activated catalog")
	}
	out.Reset()
	stderr.Reset()
	args := []string{"models", "apply", "--sources", sources, "--current", current, "--proposal", proposal, "--expected-proposal", review.ProposalDigest, "--expected-current", review.CurrentDigest}
	if code := runConfig(args, &out, &stderr); code != 0 {
		t.Fatalf("apply=%d %s", code, stderr.String())
	}
	if !bytes.Contains(out.Bytes(), []byte(`"status":"applied"`)) {
		t.Fatal(out.String())
	}
	if code := runConfig(args, &out, &stderr); code == 0 {
		t.Fatal("accepted stale apply")
	}
}
func TestConfigModelsRequiresExplicitArguments(t *testing.T) {
	for _, args := range [][]string{{"models"}, {"models", "refresh"}, {"models", "apply"}, {"models", "refresh", "--api-key", "secret"}} {
		var out, err bytes.Buffer
		if code := runConfig(args, &out, &err); code != 2 {
			t.Fatalf("%v: %d", args, code)
		}
	}
}
