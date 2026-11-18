package syntaxwasm

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

var (
	sharedOnce     sync.Once
	sharedAnalyzer *Analyzer
	sharedErr      error
)

// testAnalyzer returns one analyzer for the package's tests, so that each
// family module is compiled once per test binary.
func testAnalyzer(t testing.TB) *Analyzer {
	t.Helper()
	sharedOnce.Do(func() {
		sharedAnalyzer, sharedErr = New(context.Background(), Config{})
	})
	if sharedErr != nil {
		t.Fatal(sharedErr)
	}
	if !sharedAnalyzer.Available() {
		t.Skip("the wazero compiler does not run on this platform")
	}
	return sharedAnalyzer
}

func analyze(t testing.TB, a *Analyzer, path string, content []byte) syntaxanalysis.FileAnalysis {
	t.Helper()
	language, ok := syntaxanalysis.LanguageForPath(path)
	if !ok {
		t.Fatalf("no language for %s", path)
	}
	source, err := syntaxanalysis.NewSource(path, language, content)
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := a.Analyze(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	return analysis
}

func rangeText(r syntaxanalysis.Range) string {
	return fmt.Sprintf("%d:%d-%d:%d", r.Start.Line, r.Start.Column, r.End.Line, r.End.Column)
}

// renderGolden prints an analysis in the golden-file format: one record per
// line, repository text quoted with strconv.Quote so that it stays data.
func renderGolden(a syntaxanalysis.FileAnalysis) string {
	var b strings.Builder
	q := func(t syntaxanalysis.Text) string { return strconv.Quote(t.Untrusted()) }
	enclosing := func(i int) string {
		if i < 0 {
			return ""
		}
		return " in " + q(a.QualifiedName(i))
	}
	b.WriteString("# definitions\n")
	for i, d := range a.Definitions {
		depth := 0
		for p := d.Parent; p >= 0; p = a.Definitions[p].Parent {
			depth++
		}
		line := fmt.Sprintf("%s%s %s %s", strings.Repeat("  ", depth), rangeText(d.Range), d.Kind, q(a.QualifiedName(i)))
		if d.Exported {
			line += " exported"
		}
		if !d.Container.Empty() {
			line += " container=" + q(d.Container)
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("# references\n")
	for _, r := range a.References {
		line := fmt.Sprintf("%d:%d %s %s", r.Range.Start.Line, r.Range.Start.Column, r.Kind, q(r.Name))
		if !r.Qualifier.Empty() {
			line += " qualifier=" + q(r.Qualifier)
		}
		b.WriteString(line + enclosing(r.Enclosing) + "\n")
	}
	b.WriteString("# imports\n")
	for _, i := range a.Imports {
		line := fmt.Sprintf("%s source=%s", rangeText(i.Range), q(i.Source))
		if !i.Name.Empty() {
			line += " name=" + q(i.Name)
		}
		if !i.Alias.Empty() {
			line += " alias=" + q(i.Alias)
		}
		b.WriteString(line + enclosing(i.Enclosing) + "\n")
	}
	b.WriteString("# gaps\n")
	for _, g := range a.Gaps {
		line := string(g.Reason)
		if g.Limit != "" {
			line += " " + string(g.Limit)
		}
		if g.HasRange {
			line = rangeText(g.Range) + " " + line
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// TestGolden analyses every fixture under testdata/<language>/ and compares
// the result with the .golden file next to it. Run with -update to rewrite
// the golden files after a deliberate change, then review the diff.
func TestGolden(t *testing.T) {
	a := testAnalyzer(t)
	fixtures, err := filepath.Glob(filepath.Join("testdata", "*", "*"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, fixture := range fixtures {
		if strings.HasSuffix(fixture, ".golden") {
			continue
		}
		count++
		t.Run(filepath.ToSlash(fixture), func(t *testing.T) {
			content, err := os.ReadFile(fixture)
			if err != nil {
				t.Fatal(err)
			}
			analysis := analyze(t, a, filepath.ToSlash(fixture), content)
			encoded, err := syntaxanalysis.EncodeBinary(analysis)
			if err != nil {
				t.Fatal(err)
			}
			if decoded, err := syntaxanalysis.DecodeBinary(encoded, analysis.Path); err != nil || !reflect.DeepEqual(decoded, analysis) {
				t.Fatalf("the binary encoding does not round-trip: %v", err)
			}
			got := renderGolden(analysis)
			golden := fixture + ".golden"
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("missing golden file; run go test -run TestGolden -update: %v", err)
			}
			if got != string(want) {
				t.Fatalf("analysis differs from %s; run with -update and review the diff\n%s", golden, firstDifference(string(want), got))
			}
		})
	}
	if count == 0 {
		t.Fatal("no fixtures found")
	}
}

func firstDifference(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return fmt.Sprintf("line %d\nwant: %s\ngot:  %s", i+1, wl, gl)
		}
	}
	return ""
}
