package modelcatalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

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
					var metadata map[string]string
					if err := json.Unmarshal(models[0].Metadata, &metadata); err != nil {
						t.Fatal(err)
					}
					if metadata[selector] != test.want {
						t.Fatalf("metadata selector changed: %q", metadata[selector])
					}
				})
			}
		})
	}
}

func TestRefreshValidatesCompleteProposalDepthBeforeWriting(t *testing.T) {
	for _, test := range []struct {
		name   string
		depth  int
		reject bool
	}{
		{name: "within_bound", depth: 16},
		{name: "wrapped_proposal_exceeds_bound", depth: 59, reject: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(`{"data":[{"id":"exact","details":` + strings.Repeat("[", test.depth) + `0` + strings.Repeat("]", test.depth) + `}]}`)
			if _, err := parseModels("openai_models", body); err != nil {
				t.Fatalf("fixture must pass provider document bounds: %v", err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
			defer server.Close()
			sources, current, proposal := paths(t)
			manifest(t, sources, Source{ID: "s", Kind: "openai_models", URL: server.URL + "/models"})
			review, err := Refresh(context.Background(), sources, current, proposal, false)
			if test.reject {
				if err == nil {
					t.Error("Refresh accepted a proposal beyond complete-document depth bound")
				}
				if _, statErr := os.Lstat(proposal); !os.IsNotExist(statErr) {
					t.Errorf("proposal persisted before refusal: %v", statErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(review.Failures) != 0 || len(review.Diff.Added) != 1 {
				t.Fatalf("within-bound metadata not fetched: %+v", review)
			}
			if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, "absent"); err != nil {
				t.Fatalf("successful refresh must produce applicable proposal: %v", err)
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
			encoded, err := json.MarshalIndent(candidate, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			paddingBytes := test.finalBytes - 1 - len(encoded)
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
			currentBytes, err := json.MarshalIndent(catalog, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			currentBytes = append(currentBytes, '\n')
			if len(currentBytes) > maxFileBytes {
				t.Fatal("fixture current catalog exceeds read bound")
			}
			if err := os.WriteFile(current, currentBytes, 0600); err != nil {
				t.Fatal(err)
			}
			candidate.CurrentDigest = Digest(currentBytes)
			encoded, err = json.MarshalIndent(candidate, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded)+1 != test.finalBytes {
				t.Fatalf("fixture boundary drift: got %d want %d", len(encoded)+1, test.finalBytes)
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
