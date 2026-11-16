package modelcatalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
)

// responseBodyOfSize returns a valid one-model openai_models body of exactly size bytes.
func responseBodyOfSize(t *testing.T, size int) []byte {
	t.Helper()
	prefix, suffix := `{"data":[{"id":"exact","padding":"`, `"}]}`
	padding := size - len(prefix) - len(suffix)
	if padding < 0 {
		t.Fatal("fixture size is below the body overhead")
	}
	return []byte(prefix + strings.Repeat("x", padding) + suffix)
}

func TestResponseBoundAdmitsFourMiBBodiesAndRefusesOneByteMore(t *testing.T) {
	if MaxResponseBytes != 4<<20 {
		t.Fatalf("MaxResponseBytes = %d, want 4 MiB", MaxResponseBytes)
	}
	for _, test := range []struct {
		name   string
		size   int
		reject bool
	}{
		// The size of OpenRouter's public list; the body is synthetic.
		{name: "measured_openrouter_size", size: 829400},
		{name: "former_1_mib_bound_plus_one", size: 1<<20 + 1},
		{name: "exact_bound", size: MaxResponseBytes},
		{name: "bound_plus_one", size: MaxResponseBytes + 1, reject: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := responseBodyOfSize(t, test.size)
			models, err := parseModels("openai_models", body)
			if test.reject != (err != nil) || !test.reject && (len(models) != 1 || models[0].Selector != "exact") {
				t.Fatalf("parse = (%d models, %v), want reject %t", len(models), err, test.reject)
			}
			// A declared Content-Length is refused before the read; a chunked body by the bounded read.
			for _, declared := range []bool{true, false} {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if declared {
						w.Header().Set("Content-Length", strconv.Itoa(len(body)))
					}
					_, _ = w.Write(body)
				}))
				models, err := List(context.Background(), Source{ID: "s", Kind: "openai_models", URL: server.URL + "/models"}, false, nil)
				server.Close()
				if test.reject != (err != nil) || !test.reject && (len(models) != 1 || models[0].Selector != "exact") {
					t.Fatalf("declared length %t: list = (%d models, %v), want reject %t", declared, len(models), err, test.reject)
				}
			}
		})
	}
}

func TestSelectorsRejectUnpairedSurrogatesAndPreserveUnicode(t *testing.T) {
	for _, kind := range []string{"openai_models", "ollama_tags"} {
		t.Run(kind, func(t *testing.T) {
			field, selector := "data", "id"
			if kind == "ollama_tags" {
				field, selector = "models", "name"
			}
			for _, test := range []struct {
				name, encoded, want string
				reject              bool
			}{
				{name: "unpaired_high", encoded: `"\ud800"`, reject: true},
				{name: "unpaired_low", encoded: `"\udfff"`, reject: true},
				{name: "paired", encoded: `"prefix-\ud83d\ude80:tag"`, want: "prefix-🚀:tag"},
				{name: "literal_replacement", encoded: `"prefix-�:tag"`, want: "prefix-�:tag"},
			} {
				t.Run(test.name, func(t *testing.T) {
					body := []byte(`{"` + field + `":[{"` + selector + `":` + test.encoded + `}]}`)
					models, err := parseModels(kind, body)
					if test.reject {
						if err == nil {
							t.Fatalf("accepted unpaired surrogate as %+v", models)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if len(models) != 1 || models[0].Selector != test.want {
						t.Fatalf("selector changed: %+v", models)
					}
					// The selector is stored once, as the model's selector,
					// and the stored encoding keeps it unescaped.
					var metadata map[string]string
					if err := json.Unmarshal(models[0].Metadata, &metadata); err != nil {
						t.Fatal(err)
					}
					if _, present := metadata[selector]; present || len(metadata) != 0 {
						t.Fatalf("metadata kept the selector: %s", models[0].Metadata)
					}
					stored, err := encodeDocument(models[0])
					if err != nil || !strings.Contains(string(stored), `"selector":"`+test.want+`"`) {
						t.Fatalf("stored selector changed: %s", stored)
					}
				})
			}
		})
	}
}

// A stored proposal nests each model object four levels deeper than its list,
// so the fetch admits only model objects that still fit the complete-document
// depth bound once stored. A deeper list is that source's failure: the other
// sources still refresh, and the proposal applies.
func TestRefreshDepthBoundIsPerSource(t *testing.T) {
	deep := func(depth int) []byte {
		return []byte(`{"data":[{"id":"exact","details":` + strings.Repeat("[", depth) + `0` + strings.Repeat("]", depth) + `}]}`)
	}
	healthy := []byte(`{"data":[{"id":"healthy"}]}`)
	for _, test := range []struct {
		name   string
		depth  int
		reject bool
	}{
		{name: "within_bound", depth: 16},
		{name: "deepest_stored", depth: 57},
		{name: "one_level_deeper", depth: 58, reject: true},
		{name: "list_bound", depth: 61, reject: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := deep(test.depth)
			if _, err := parseModels("openai_models", body); (err != nil) != test.reject {
				t.Fatalf("parseModels depth %d err=%v, want reject=%v", test.depth, err, test.reject)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/healthy/models" {
					_, _ = w.Write(healthy)
					return
				}
				_, _ = w.Write(body)
			}))
			defer server.Close()
			sources, current, proposal := paths(t)
			manifest(t, sources, Source{ID: "deep", Kind: "openai_models", URL: server.URL + "/models"}, Source{ID: "healthy", Kind: "openai_models", URL: server.URL + "/healthy/models"})
			review, err := Refresh(context.Background(), sources, current, proposal, false)
			if err != nil {
				t.Fatalf("one source blocked the refresh: %v", err)
			}
			wantFailures, wantAdded := 0, 2
			if test.reject {
				wantFailures, wantAdded = 1, 1
				if review.Failures[0].SourceID != "deep" {
					t.Fatalf("failure recorded for %+v", review.Failures)
				}
			}
			if len(review.Failures) != wantFailures || len(review.Diff.Added) != wantAdded {
				t.Fatalf("failures=%+v added=%d", review.Failures, len(review.Diff.Added))
			}
			if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, "absent"); err != nil {
				t.Fatalf("refreshed proposal did not apply: %v", err)
			}
		})
	}
}

func TestRefreshCompleteProposalExactByteBoundary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "unavailable", 503) }))
	defer server.Close()
	for _, test := range []struct {
		name       string
		finalBytes int
		reject     bool
	}{
		{name: "exact_limit", finalBytes: maxFileBytes},
		{name: "newline_exceeds_limit", finalBytes: maxFileBytes + 1, reject: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			sources, current, proposal := paths(t)
			sourceList := make([]Source, 9)
			catalog := Catalog{SchemaVersion: 1, Sources: []Snapshot{}, Failures: []Failure{}}
			for i := range sourceList {
				id := string(rune('a' + i))
				sourceList[i] = Source{ID: id, Kind: "openai_models", URL: server.URL + "/models"}
				padding := ""
				if i < 8 {
					padding = strings.Repeat("x", 930000)
				}
				metadata, _ := json.Marshal(map[string]string{"id": "exact", "padding": padding})
				catalog.Sources = append(catalog.Sources, Snapshot{Source: sourceList[i], RetrievedAt: "2026-10-30T00:00:00Z", ResponseDigest: strings.Repeat("a", 64), Models: []Model{{Selector: "exact", Metadata: metadata}}})
			}
			manifest(t, sources, sourceList...)
			failedCatalog := catalog
			failedCatalog.Failures = make([]Failure, 0, len(sourceList))
			for _, source := range sourceList {
				failedCatalog.Failures = append(failedCatalog.Failures, Failure{SourceID: source.ID, Code: "metadata_unavailable"})
			}
			candidate := Proposal{SchemaVersion: 1, ManifestDigest: Digest(mustRead(t, sources)), CurrentDigest: strings.Repeat("a", 64), Catalog: failedCatalog}
			encoded, err := encodeDocument(candidate)
			if err != nil {
				t.Fatal(err)
			}
			paddingBytes := test.finalBytes - len(encoded)
			if paddingBytes < 0 {
				t.Fatal("fixture overhead exceeds target")
			}
			metadata, err := json.Marshal(map[string]string{"id": "exact", "padding": strings.Repeat("x", paddingBytes)})
			if err != nil {
				t.Fatal(err)
			}
			if len(metadata) > MaxResponseBytes {
				t.Fatal("fixture metadata exceeds per-provider response bound")
			}
			catalog.Sources[8].Models[0].Metadata = metadata
			currentBytes, err := encodeDocument(catalog)
			if err != nil {
				t.Fatal(err)
			}
			if len(currentBytes) > maxFileBytes {
				t.Fatal("fixture current catalog exceeds read bound")
			}
			if err := os.WriteFile(current, currentBytes, 0600); err != nil {
				t.Fatal(err)
			}
			candidate.CurrentDigest = Digest(currentBytes)
			encoded, err = encodeDocument(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) != test.finalBytes {
				t.Fatalf("fixture boundary drift: got %d want %d", len(encoded), test.finalBytes)
			}
			review, err := Refresh(context.Background(), sources, current, proposal, false)
			if test.reject {
				if err == nil {
					t.Error("Refresh accepted proposal exceeding exact byte limit after newline")
				}
				if _, statErr := os.Lstat(proposal); !os.IsNotExist(statErr) {
					t.Errorf("oversized proposal persisted: %v", statErr)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if len(mustRead(t, proposal)) != test.finalBytes {
					t.Fatal("proposal did not reach exact boundary")
				}
				if len(review.Failures) != len(sourceList) {
					t.Fatal("fixture failures not retained")
				}
				if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, review.CurrentDigest); err != nil {
					t.Fatalf("exact-limit proposal not applicable: %v", err)
				}
			}
			if test.reject && string(mustRead(t, current)) != string(currentBytes) {
				t.Fatal("refusal changed current catalog")
			}
		})
	}
}
