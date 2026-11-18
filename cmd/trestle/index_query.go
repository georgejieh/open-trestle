package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/repoindex"
)

// writeIndexJSON prints a result as indented JSON in which every control,
// format and bidirectional character is escaped, so that repository names
// and paths cannot move a terminal's cursor, reorder or hide text. The
// escapes are JSON, so the data is unchanged.
func writeIndexJSON(stdout, stderr io.Writer, value any) int {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return indexFail(stderr, 1, "the result could not be written")
	}
	if _, err := stdout.Write(escapeHiddenCharacters(encoded.Bytes())); err != nil {
		return indexFail(stderr, 1, "the result could not be written")
	}
	return 0
}

// escapeHiddenCharacters rewrites the format characters (Unicode category
// Cf, which holds the bidirectional controls) and the C1 controls of JSON
// text as \u escapes. encoding/json escapes the C0 controls and U+2028 and
// U+2029 itself; outside strings JSON holds only ASCII.
func escapeHiddenCharacters(encoded []byte) []byte {
	out := make([]byte, 0, len(encoded))
	for len(encoded) > 0 {
		r, size := utf8.DecodeRune(encoded)
		if r >= 0x80 && (unicode.Is(unicode.Cf, r) || unicode.IsControl(r)) {
			out = appendJSONEscape(out, r)
		} else {
			out = append(out, encoded[:size]...)
		}
		encoded = encoded[size:]
	}
	return out
}

func appendJSONEscape(out []byte, r rune) []byte {
	units := []rune{r}
	if r > 0xffff {
		r -= 0x10000
		units = []rune{0xd800 + r>>10, 0xdc00 + r&0x3ff}
	}
	for _, u := range units {
		hex := strconv.FormatInt(int64(u), 16)
		out = append(out, `\u`...)
		for i := len(hex); i < 4; i++ {
			out = append(out, '0')
		}
		out = append(out, hex...)
	}
	return out
}

func runIndexQuery(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeIndexUsage(stderr)
		return 2
	}
	kind := args[0]
	f, positional, err := parseIndexFlags("query "+kind, args[1:], kind == "dependents")
	wantArgs := 1
	if kind == "dependents" {
		wantArgs = 0
	}
	if err != nil || len(positional) != wantArgs || kind == "dependents" && f.base == "" {
		writeIndexUsage(stderr)
		return 2
	}
	switch kind {
	case "definitions", "references", "tests", "imports", "dependents":
	default:
		fmt.Fprintf(stderr, "trestle index: unknown query %q\n", kind)
		writeIndexUsage(stderr)
		return 2
	}
	s, err := openIndexSession(ctx, f)
	if err != nil {
		return indexFail(stderr, 1, "%v", err)
	}
	defer s.close()
	revision, err := s.commit(ctx, f.commit)
	if err != nil {
		return indexFail(stderr, 2, "--commit: %v", err)
	}
	graph, err := s.ensureIndexed(ctx, revision, stderr)
	if err != nil {
		return indexFail(stderr, 1, "%v", err)
	}
	if kind == "dependents" {
		return runIndexDependents(ctx, s, f, graph, stdout, stderr)
	}
	return writeIndexJSON(stdout, stderr, indexQueryResult(graph, kind, positional[0]))
}

type symbolResult struct {
	Definition repoindex.Symbol `json:"definition"`
	References []repoindex.Use  `json:"references,omitempty"`
	Tests      []repoindex.Use  `json:"tests,omitempty"`
}

// indexQueryResult answers a query. Every answer carries the graph's
// coverage, since a file the index does not cover can hide a reference.
func indexQueryResult(graph *repoindex.Graph, kind, argument string) any {
	if kind == "imports" {
		imports, unresolved, found := graph.Imports(argument)
		importers, _ := graph.Importers(argument)
		return struct {
			Coverage   repoindex.GraphCoverage `json:"coverage"`
			Found      bool                    `json:"found"`
			Imports    []string                `json:"imports"`
			Unresolved int                     `json:"unresolved"`
			Importers  []string                `json:"importers"`
		}{graph.Coverage(), found, imports, unresolved, importers}
	}
	results := []symbolResult{}
	for _, d := range graph.Definitions(argument) {
		r := symbolResult{Definition: d}
		switch kind {
		case "references":
			r.References = graph.References(d.ID)
		case "tests":
			r.Tests = graph.TestReferences(d.ID)
		}
		results = append(results, r)
	}
	return struct {
		Coverage    repoindex.GraphCoverage `json:"coverage"`
		Definitions []symbolResult          `json:"definitions"`
	}{graph.Coverage(), results}
}
