package modelcatalog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// boundaryList builds a model list body of exactly MaxResponseBytes from rows
// that row(i) renders, padding the last row through its pad member.
func boundaryList(t *testing.T, field string, row func(index int, pad string) string) []byte {
	t.Helper()
	prefix, suffix := `{"`+field+`":[`, `]}`
	rows := []string{}
	size := len(prefix) + len(suffix)
	for index := 0; index < maxModels; index++ {
		next := row(index, "")
		if size+len(next)+1 > MaxResponseBytes {
			break
		}
		rows = append(rows, next)
		size += len(next) + 1
	}
	size-- // n rows need n-1 separators
	// A non-empty pad of n bytes grows a row by n plus a fixed member overhead.
	last := len(rows) - 1
	overhead := len(row(last, "x")) - len(row(last, "")) - 1
	for MaxResponseBytes-size < overhead {
		size -= len(rows[last]) + 1
		rows, last = rows[:last], last-1
	}
	if short := MaxResponseBytes - size; short > 0 {
		rows[last] = row(last, strings.Repeat("x", short-overhead))
	}
	body := []byte(prefix + strings.Join(rows, ",") + suffix)
	if len(body) != MaxResponseBytes {
		t.Fatalf("fixture body is %d bytes, want %d", len(body), MaxResponseBytes)
	}
	return body
}

// Every list the fetch accepts must refresh into a proposal, and apply into a
// catalog, within the unchanged 8 MiB protected-file bound. Each list below is
// exactly at the 4 MiB fetch bound and stresses one way the stored encoding
// could outgrow the response: indentation of deep metadata, HTML and line
// separator escaping, the selector stored beside its own metadata, and per-model
// framing at the model count limit.
func TestRefreshOfAnyAcceptedListFitsTheProtectedFileBound(t *testing.T) {
	// A selector of width bytes; the closing letter keeps a whitespace fill
	// such as U+2028 from being trimmed.
	selector := func(index, width int, fill string) string {
		label := fmt.Sprintf("%05d-", index)
		return label + strings.Repeat(fill, (width-len(label)-1)/len(fill)) + "z"
	}
	pad := func(value string) string {
		if value == "" {
			return ""
		}
		return `,"pad":"` + value + `"`
	}
	nested := strings.Repeat("[", 50) + "0" + strings.Repeat("]", 50)
	lists := []struct {
		name, kind, field string
		row               func(index int, padding string) string
	}{
		{"longest selectors", "openai_models", "data", func(i int, p string) string {
			return `{"id":"` + selector(i, 1024, "a") + `"` + pad(p) + `}`
		}},
		{"line separator selectors", "openai_models", "data", func(i int, p string) string {
			return `{"id":"` + selector(i, 1024, " ") + `"` + pad(p) + `}`
		}},
		{"html characters", "openai_models", "data", func(i int, p string) string {
			return `{"id":"m` + fmt.Sprint(i) + `","description":"` + strings.Repeat("<&>", 300) + `"` + pad(p) + `}`
		}},
		{"deep metadata", "ollama_tags", "models", func(i int, p string) string {
			return `{"name":"m` + fmt.Sprint(i) + `:tag","details":{"a":` + nested + `,"b":` + nested + `}` + pad(p) + `}`
		}},
		{"most models", "openai_models", "data", func(i int, p string) string {
			return `{"id":"m` + fmt.Sprint(i) + `","pad":"` + strings.Repeat("x", 400) + p + `"}`
		}},
	}
	for index, list := range lists {
		t.Run(list.name, func(t *testing.T) {
			t.Parallel()
			body := boundaryList(t, list.field, list.row)
			models, err := parseModels(list.kind, body)
			if err != nil || len(models) == 0 {
				t.Fatalf("fetch refused the boundary list: %v", err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
			defer server.Close()
			url := server.URL + "/models"
			if list.kind == "ollama_tags" {
				url = server.URL + "/api/tags"
			}
			sources, current, proposal := paths(t)
			manifest(t, sources, Source{ID: "s", Kind: list.kind, URL: url})
			review, err := Refresh(context.Background(), sources, current, proposal, false)
			if err != nil {
				t.Fatalf("refresh of a %d-model list at the fetch bound failed: %v", len(models), err)
			}
			if len(review.Failures) != 0 || len(review.Diff.Added) != len(models) {
				t.Fatalf("refresh lost models: %d failures, %d added of %d", len(review.Failures), len(review.Diff.Added), len(models))
			}
			size := len(mustRead(t, proposal))
			if size > maxFileBytes {
				t.Fatalf("proposal is %d bytes, over the protected-file bound", size)
			}
			t.Logf("%d models in %d response bytes: %d proposal bytes", len(models), len(body), size)
			if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, "absent"); err != nil {
				t.Fatalf("apply failed: %v", err)
			}
			stored, digest, err := readCatalog(current)
			if err != nil || len(mustRead(t, current)) > maxFileBytes || len(stored.Sources) != 1 || len(stored.Sources[0].Models) != len(models) {
				t.Fatalf("applied catalog did not read back: %v", err)
			}
			if index != 0 {
				return
			}
			// One list also proves the applied catalog diffs as unchanged.
			again := proposal + ".again"
			second, err := Refresh(context.Background(), sources, current, again, false)
			if err != nil || second.CurrentDigest != digest || len(second.Diff.Added)+len(second.Diff.Removed)+len(second.Diff.Changed) != 0 {
				t.Fatalf("refresh against the applied catalog changed entries: %v", err)
			}
		})
	}
}

// Catalogs and proposals written before compact encoding were indented and
// stored each model's complete object, selector included, as metadata. They
// still read back, apply, and diff without reporting unchanged models.
func TestRefreshReadsIndentedCatalogsWithSelectorsInMetadata(t *testing.T) {
	body := `{"data":[{"id":"kept","owned_by":"one"},{"id":"changed","owned_by":"two"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer server.Close()
	sources, current, proposal := paths(t)
	source := Source{ID: "s", Kind: "openai_models", URL: server.URL + "/models"}
	manifest(t, sources, source)
	legacy := Catalog{SchemaVersion: 1, Failures: []Failure{}, Sources: []Snapshot{{Source: source, RetrievedAt: "2026-10-30T00:00:00Z", ResponseDigest: strings.Repeat("a", 64), Models: []Model{
		{Selector: "changed", Metadata: json.RawMessage(`{"id":"changed","owned_by":"one"}`)},
		{Selector: "kept", Metadata: json.RawMessage(`{"id":"kept","owned_by":"one"}`)},
	}}}}
	encoded, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(current, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	read, digest, err := readCatalog(current)
	if err != nil || digest != Digest(encoded) || len(read.Sources[0].Models) != 2 {
		t.Fatalf("indented catalog did not read back: %v", err)
	}
	review, err := Refresh(context.Background(), sources, current, proposal, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Diff.Added) != 0 || len(review.Diff.Removed) != 0 || len(review.Diff.Changed) != 1 || review.Diff.Changed[0].After.Selector != "changed" {
		t.Fatalf("diff against an indented catalog = %+v", review.Diff)
	}
	if err := Apply(context.Background(), sources, current, proposal, review.ProposalDigest, digest); err != nil {
		t.Fatal(err)
	}
	// A selector member that disagrees with its model is still refused.
	legacy.Sources[0].Models[1].Metadata = json.RawMessage(`{"id":"other","owned_by":"one"}`)
	if validateCatalog(legacy) == nil {
		t.Fatal("catalog accepted metadata naming another selector")
	}
	legacy.Sources[0].Models[1].Metadata = json.RawMessage(`null`)
	if validateCatalog(legacy) == nil {
		t.Fatal("catalog accepted non-object metadata")
	}
}
