package modelcatalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestNamedMetadataDocumentedSourceAuthority(t *testing.T) {
	for _, source := range []Source{
		{ID: "opencode-go", Kind: "openai_models", URL: "https://opencode.ai/inference/go/v1/models"},
		{ID: "ollama-cloud", Kind: "ollama_tags", URL: "https://ollama.com/api/tags"},
	} {
		t.Run(source.ID, func(t *testing.T) {
			declaration := Manifest{SchemaVersion: 1, Sources: []Source{source}}
			if err := validateManifest(declaration, false); err == nil {
				t.Fatal("remote metadata accepted without explicit opt-in")
			}
			if err := validateManifest(declaration, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNamedMetadataRefreshApplyAndLastKnownGood(t *testing.T) {
	for _, test := range []struct {
		name, kind, path, envelope, selector, fixture string
	}{
		{"opencode-go", "openai_models", "/inference/go/v1/models", "data", "glm-5.3-flash", "opencode_go.json"},
		{"ollama-cloud", "ollama_tags", "/api/tags", "models", "gemma4:31b", "ollama_cloud.json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := mustRead(t, filepath.Join("testdata", "named_metadata", test.fixture))
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(body, &envelope); err != nil {
				t.Fatal(err)
			}
			var rows []map[string]json.RawMessage
			if err := json.Unmarshal(envelope[test.envelope], &rows); err != nil || len(rows) != 1 {
				t.Fatalf("fixture must have one representative row: %v", err)
			}
			// Stored metadata is the rest of the model object; the selector is
			// stored once, beside it.
			rest := func(row map[string]json.RawMessage) json.RawMessage {
				t.Helper()
				fields := map[string]json.RawMessage{}
				for key, value := range row {
					fields[key] = value
				}
				delete(fields, map[string]string{"openai_models": "id", "ollama_tags": "name"}[test.kind])
				encoded, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				return encoded
			}
			originalMetadata := rest(rows[0])
			rows[0]["fixture_revision"] = json.RawMessage(`2`)
			changedMetadata := rest(rows[0])
			changedRows, err := json.Marshal(rows)
			if err != nil {
				t.Fatal(err)
			}
			envelope[test.envelope] = changedRows
			changedBody, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}

			var mu sync.Mutex
			status, response, hits := http.StatusOK, string(body), 0
			fixtureURL := ""
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				hits++
				code, payload, authority := status, response, fixtureURL
				mu.Unlock()
				if r.Method != http.MethodGet || "http://"+r.Host+r.URL.RequestURI() != authority || r.URL.RawQuery != "" || r.URL.Path != test.path {
					t.Error("request changed the owned fixture source authority")
				}
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.ContentLength > 0 {
					t.Error("metadata request carried credentials or a body")
				}
				if r.Header.Get("Accept") != "application/json" || r.Header.Get("User-Agent") != "open-trestle/modelcatalog" {
					t.Error("unexpected metadata request headers")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				_, _ = w.Write([]byte(payload))
			}))
			defer server.Close()
			mu.Lock()
			fixtureURL = server.URL + test.path
			mu.Unlock()
			parsed, err := url.Parse(fixtureURL)
			if err != nil || parsed.Hostname() != "127.0.0.1" {
				t.Fatal("fixture is not owned numeric loopback")
			}
			sources, current, proposal := paths(t)
			source := Source{ID: test.name, Kind: test.kind, URL: fixtureURL}
			manifest(t, sources, source)
			review, err := Refresh(context.Background(), sources, current, proposal, false)
			if err != nil {
				t.Fatal(err)
			}
			if review.CurrentDigest != "absent" || len(review.Failures) != 0 || len(review.Diff.Added) != 1 || len(review.Diff.Removed) != 0 || len(review.Diff.Changed) != 0 {
				t.Fatalf("unexpected initial review: %+v", review)
			}
			added := review.Diff.Added[0]
			if added.SourceID != source.ID || added.Selector != test.selector {
				t.Fatal("refresh rewrote source identity or exact model selector")
			}
			assertNamedMetadataJSON(t, added.Metadata, originalMetadata)
			if _, err := os.Stat(current); !os.IsNotExist(err) {
				t.Fatal("refresh changed the current catalog")
			}
			if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, "absent"); err != nil {
				t.Fatal(err)
			}
			var catalog Catalog
			if err := json.Unmarshal(mustRead(t, current), &catalog); err != nil {
				t.Fatal(err)
			}
			if len(catalog.Sources) != 1 || catalog.Sources[0].Source != source || catalog.Sources[0].ResponseDigest != Digest(body) || catalog.Sources[0].RetrievedAt == "" || len(catalog.Sources[0].Models) != 1 || catalog.Sources[0].Models[0].Selector != test.selector {
				t.Fatal("apply lost source, response digest or exact model identity")
			}
			assertNamedMetadataJSON(t, catalog.Sources[0].Models[0].Metadata, originalMetadata)
			before := mustRead(t, current)

			mu.Lock()
			response = string(changedBody)
			mu.Unlock()
			proposal = filepath.Join(filepath.Dir(proposal), "changed.json")
			review, err = Refresh(context.Background(), sources, current, proposal, false)
			if err != nil {
				t.Fatal(err)
			}
			if review.CurrentDigest != Digest(before) || len(review.Failures) != 0 || len(review.Diff.Changed) != 1 || len(review.Diff.Added) != 0 || len(review.Diff.Removed) != 0 {
				t.Fatalf("metadata revision was not an exact-ID change: %+v", review)
			}
			change := review.Diff.Changed[0]
			if change.Before.SourceID != source.ID || change.After.SourceID != source.ID || change.Before.Selector != test.selector || change.After.Selector != test.selector {
				t.Fatal("metadata diff rewrote model identity")
			}
			assertNamedMetadataJSON(t, change.Before.Metadata, originalMetadata)
			assertNamedMetadataJSON(t, change.After.Metadata, changedMetadata)
			if string(mustRead(t, current)) != string(before) {
				t.Fatal("changed refresh overwrote current before apply")
			}
			if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, review.CurrentDigest); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(mustRead(t, current), &catalog); err != nil {
				t.Fatal(err)
			}
			if len(catalog.Sources) != 1 || len(catalog.Sources[0].Models) != 1 || catalog.Sources[0].Models[0].Selector != test.selector || catalog.Sources[0].ResponseDigest != Digest(changedBody) {
				t.Fatal("changed apply lost exact model identity or response digest")
			}
			assertNamedMetadataJSON(t, catalog.Sources[0].Models[0].Metadata, changedMetadata)
			lastGood, err := json.Marshal(catalog.Sources[0])
			if err != nil {
				t.Fatal(err)
			}

			for _, failure := range []struct {
				name   string
				status int
				body   string
			}{
				{"forbidden", http.StatusForbidden, "private-provider-error-body"},
				{"malformed", http.StatusOK, `{"not_the_envelope":[]}`},
			} {
				before = mustRead(t, current)
				mu.Lock()
				status, response = failure.status, failure.body
				mu.Unlock()
				proposal = filepath.Join(filepath.Dir(proposal), failure.name+".json")
				review, err = Refresh(context.Background(), sources, current, proposal, false)
				if err != nil {
					t.Fatal(err)
				}
				if review.CurrentDigest != Digest(before) || len(review.Failures) != 1 || review.Failures[0] != (Failure{SourceID: source.ID, Code: "metadata_unavailable"}) || len(review.Diff.Added) != 0 || len(review.Diff.Removed) != 0 || len(review.Diff.Changed) != 0 {
					t.Fatalf("failed named source lost last-known-good models: %+v", review)
				}
				if strings.Contains(string(mustRead(t, proposal)), failure.body) || string(mustRead(t, current)) != string(before) {
					t.Fatal("failed refresh leaked response body or changed current")
				}
				if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, review.CurrentDigest); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(mustRead(t, current), &catalog); err != nil {
					t.Fatal(err)
				}
				if len(catalog.Sources) != 1 || !reflect.DeepEqual(catalog.Failures, review.Failures) {
					t.Fatal("failure apply did not preserve source count and failure status")
				}
				currentSnapshot, err := json.Marshal(catalog.Sources[0])
				if err != nil {
					t.Fatal(err)
				}
				assertNamedMetadataJSON(t, currentSnapshot, lastGood)
			}
			mu.Lock()
			requestCount := hits
			mu.Unlock()
			if requestCount != 4 {
				t.Fatalf("expected four metadata GETs and no apply fetch: %d", requestCount)
			}
		})
	}
}

func assertNamedMetadataJSON(t *testing.T, got, want json.RawMessage) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("model metadata changed: got %s; want %s", got, want)
	}
}
