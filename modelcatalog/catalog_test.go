package modelcatalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/filelock"
)

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func paths(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "sources.json"), filepath.Join(dir, "catalog.json"), filepath.Join(dir, "proposal.json")
}
func manifest(t *testing.T, path string, sources ...Source) {
	t.Helper()
	writeJSON(t, path, Manifest{SchemaVersion: 1, Sources: sources})
}
func TestRefreshApplyAndPartialFailure(t *testing.T) {
	body := `{"data":[{"id":"Exact/Moving:Selector","owned_by":"one"}]}`
	fail := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/models" || r.Header.Get("Authorization") != "" {
			t.Error("not an unauthenticated metadata GET")
		}
		if fail {
			http.Error(w, "secret provider error", 500)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	sources, current, proposal := paths(t)
	manifest(t, sources, Source{ID: "local", Kind: "openai_models", URL: server.URL + "/v1/models"})
	review, err := Refresh(context.Background(), sources, current, proposal, false)
	if err != nil {
		t.Fatal(err)
	}
	if review.CurrentDigest != "absent" || len(review.Diff.Added) != 1 || review.Diff.Added[0].Selector != "Exact/Moving:Selector" {
		t.Fatalf("bad review: %+v", review)
	}
	if _, err := os.Stat(current); !os.IsNotExist(err) {
		t.Fatal("refresh changed current")
	}
	if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, "absent"); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(current)
	if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, "absent"); err == nil {
		t.Fatal("stale apply accepted")
	}
	if err := os.Remove(proposal); err != nil {
		t.Fatal(err)
	}
	fail = true
	review, err = Refresh(context.Background(), sources, current, proposal, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Failures) != 1 || len(review.Diff.Removed) != 0 || strings.Contains(string(mustRead(t, proposal)), "secret provider error") {
		t.Fatal("failed source lost entries or leaked body")
	}
	if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, Digest(first)); err != nil {
		t.Fatal(err)
	}
	var got Catalog
	if err := json.Unmarshal(mustRead(t, current), &got); err != nil {
		t.Fatal(err)
	}
	if got.Sources[0].Models[0].Selector != "Exact/Moving:Selector" || len(got.Failures) != 1 {
		t.Fatal("last known good lost")
	}
}
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestChangedRemovedAddedAndTags(t *testing.T) {
	body := `{"models":[{"name":"model:exact","digest":"sha256:first","size":1},{"name":"removed"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer server.Close()
	sources, current, proposal := paths(t)
	manifest(t, sources, Source{ID: "tags", Kind: "ollama_tags", URL: server.URL + "/api/tags"})
	review, err := Refresh(context.Background(), sources, current, proposal, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, "absent"); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(proposal)
	body = `{"models":[{"name":"model:exact","digest":"sha256:second","size":1},{"name":"new"}]}`
	review, err = Refresh(context.Background(), sources, current, proposal, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Diff.Changed) != 1 || len(review.Diff.Removed) != 1 || len(review.Diff.Added) != 1 {
		t.Fatalf("bad diff: %+v", review.Diff)
	}
	if review.Diff.Changed[0].Before.Selector != "model:exact" || review.Diff.Changed[0].After.Selector != "model:exact" {
		t.Fatal("selector rewritten")
	}
}
func TestMetadataFailureBoundsAndNoRedirect(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; http.Redirect(w, r, "/load", 302) }))
	defer server.Close()
	sources, current, proposal := paths(t)
	manifest(t, sources, Source{ID: "s", Kind: "openai_models", URL: server.URL + "/models"})
	review, err := Refresh(context.Background(), sources, current, proposal, false)
	if err != nil {
		t.Fatal(err)
	}
	if hits != 1 || len(review.Failures) != 1 {
		t.Fatal("followed redirect")
	}
	for _, body := range []string{`{"data":[{"id":"a"},{"id":"a"}]}`, `{"data":[{"id":" a "}]}`, `{"models":[]}`, `{"data":null}`, `{"data":[]} {}`, strings.Repeat("x", MaxResponseBytes+1)} {
		if _, err := parseModels("openai_models", []byte(body)); err == nil {
			t.Fatal("accepted malformed, duplicate or oversized response")
		}
	}
}
func TestSourceNetworkAuthority(t *testing.T) {
	for _, source := range []Source{
		{ID: "x", Kind: "openai_models", URL: "https://example.com/models"},
		{ID: "x", Kind: "openai_models", URL: "http://localhost/models"},
		{ID: "x", Kind: "openai_models", URL: "http://192.168.1.2/models"},
		{ID: "x", Kind: "openai_models", URL: "file:///models"},
		{ID: "x", Kind: "openai_models", URL: "http://127.0.0.1/models?key=secret"},
		{ID: "x", Kind: "openai_models", URL: "http://user:secret@127.0.0.1/models"},
		{ID: "x", Kind: "openai_models", URL: "http://127.0.0.1/responses"},
	} {
		if validateSource(source, false) == nil {
			t.Fatalf("accepted source: %+v", source)
		}
	}
	if validateSource(Source{ID: "x", Kind: "openai_models", URL: "https://example.com/v1/models"}, true) != nil {
		t.Fatal("explicit remote rejected")
	}
	if validateSource(Source{ID: "x", Kind: "ollama_tags", URL: "http://[::1]:11434/api/tags"}, false) != nil {
		t.Fatal("numeric loopback rejected")
	}
}
func TestProtectedConflictAndExclusiveWriter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"data":[]}`)) }))
	defer server.Close()
	sources, current, proposal := paths(t)
	manifest(t, sources, Source{ID: "s", Kind: "openai_models", URL: server.URL + "/models"})
	review, err := Refresh(context.Background(), sources, current, proposal, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Refresh(context.Background(), sources, current, proposal, false); err == nil {
		t.Fatal("proposal overwrite accepted")
	}
	lock, err := filelock.Acquire(current + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if err = Apply(context.Background(), sources, current, proposal, review.ProposalDigest, "absent"); err == nil {
		t.Fatal("parallel writer accepted")
	}
	_ = lock.Close()
	if err = Apply(context.Background(), sources, current, proposal, strings.Repeat("0", 64), "absent"); err == nil {
		t.Fatal("proposal mismatch accepted")
	}
	original := mustRead(t, sources)
	_ = os.WriteFile(sources, append(original, ' '), 0600)
	if err = Apply(context.Background(), sources, current, proposal, review.ProposalDigest, "absent"); err == nil {
		t.Fatal("changed source authority accepted")
	}
	_ = os.WriteFile(sources, original, 0600)
	if err = os.Symlink(sources, current); err != nil {
		t.Fatal(err)
	}
	if err = Apply(context.Background(), sources, current, proposal, review.ProposalDigest, "absent"); err == nil {
		t.Fatal("symlink accepted")
	}
	if string(mustRead(t, sources)) != string(original) {
		t.Fatal("symlink target overwritten")
	}
}

func TestFailedSourceRetainedWhileSuccessfulSourceChanges(t *testing.T) {
	fail := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad/models" && fail {
			http.Error(w, "no", 503)
			return
		}
		if r.URL.Path == "/good/models" && fail {
			_, _ = w.Write([]byte(`{"data":[{"id":"new"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"old"}]}`))
	}))
	defer server.Close()
	sources, current, proposal := paths(t)
	manifest(t, sources, Source{ID: "bad", Kind: "openai_models", URL: server.URL + "/bad/models"}, Source{ID: "good", Kind: "openai_models", URL: server.URL + "/good/models"})
	first, err := Refresh(context.Background(), sources, current, proposal, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), sources, current, proposal, first.ProposalDigest, "absent"); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(proposal)
	fail = true
	review, err := Refresh(context.Background(), sources, current, proposal, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Failures) != 1 || review.Failures[0].SourceID != "bad" || len(review.Diff.Removed) != 1 || review.Diff.Removed[0].SourceID != "good" || len(review.Diff.Added) != 1 || review.Diff.Added[0].Selector != "new" {
		t.Fatalf("bad partial result: %+v", review)
	}
}
func TestMalformedManifestAndDuplicateKeysDoNotFetch(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; _, _ = w.Write([]byte(`{"data":[]}`)) }))
	defer server.Close()
	sources, current, proposal := paths(t)
	for _, value := range []string{
		`{"schema_version":1,"schema_version":1,"sources":[]}`,
		`{"schema_version":1,"sources":[{"id":"x","kind":"openai_models","url":"` + server.URL + `/models","auth":"secret"}]}`,
	} {
		if err := os.WriteFile(sources, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Refresh(context.Background(), sources, current, proposal, false); err == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
	if hits != 0 {
		t.Fatal("invalid manifest caused fetch")
	}
	if _, err := parseModels("openai_models", []byte(`{"data":[{"id":"a","id":"b"}]}`)); err == nil {
		t.Fatal("duplicate metadata keys accepted")
	}
}
func TestCurrentAndProposalTamperingPreservesCatalog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"data":[]}`)) }))
	defer server.Close()
	sources, current, proposal := paths(t)
	manifest(t, sources, Source{ID: "s", Kind: "openai_models", URL: server.URL + "/models"})
	review, err := Refresh(context.Background(), sources, current, proposal, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, "absent"); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(proposal)
	review, err = Refresh(context.Background(), sources, current, proposal, false)
	if err != nil {
		t.Fatal(err)
	}
	before := append(mustRead(t, current), ' ')
	if err := os.WriteFile(current, before, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, review.CurrentDigest); err == nil {
		t.Fatal("current digest mismatch accepted")
	}
	if string(mustRead(t, current)) != string(before) {
		t.Fatal("current changed after conflict")
	}
	if err := os.WriteFile(proposal, append(mustRead(t, proposal), ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, Digest(before)); err == nil {
		t.Fatal("proposal digest mismatch accepted")
	}
	if string(mustRead(t, current)) != string(before) {
		t.Fatal("current changed after proposal mismatch")
	}
}
func TestProtectedManifestModeAndAncestorSymlink(t *testing.T) {
	sources, current, proposal := paths(t)
	manifest(t, sources, Source{ID: "s", Kind: "openai_models", URL: "http://127.0.0.1:1/models"})
	if err := os.Chmod(sources, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(context.Background(), sources, current, proposal, false); err == nil {
		t.Fatal("writable manifest accepted")
	}
	_ = os.Chmod(sources, 0600)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(sources), alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(context.Background(), filepath.Join(alias, "sources.json"), current, proposal, false); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
}

func TestReviewDiffPreservesLargeIntegerChanges(t *testing.T) {
	before := Catalog{Sources: []Snapshot{{Source: Source{ID: "s"}, Models: []Model{{Selector: "exact", Metadata: json.RawMessage(`{"id":"exact","size":9007199254740992}`)}}}}}
	after := Catalog{Sources: []Snapshot{{Source: Source{ID: "s"}, Models: []Model{{Selector: "exact", Metadata: json.RawMessage(`{"id":"exact","size":9007199254740993}`)}}}}}
	diff := catalogDiff(before, after)
	if len(diff.Changed) != 1 {
		t.Fatalf("large integer change disappeared: %+v", diff)
	}
}

func TestRejectsInvalidUTF8Selectors(t *testing.T) {
	data := append([]byte(`{"data":[{"id":"`), 0xff)
	data = append(data, []byte(`"}]}`)...)
	if _, err := parseModels("openai_models", data); err == nil {
		t.Fatal("invalid UTF-8 silently changed selector")
	}
}
