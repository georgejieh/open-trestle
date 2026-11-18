package repoindex

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

func buildCommit(t *testing.T, store *Store, analyzer *countingAnalyzer, tree Tree) Snapshot {
	t.Helper()
	snapshot, err := Builder{Store: store, Analyzer: analyzer, Parallelism: 4}.Build(context.Background(), tree)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func loadGraph(t *testing.T, store *Store, s Snapshot) *Graph {
	t.Helper()
	g, err := store.Load(context.Background(), s.Algorithm, s.Commit)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func quote(s string) string { return strconv.Quote(s) }

// renderGraph prints the files and the answers of every query kind for the
// fixture, repository text quoted as data.
func renderGraph(g *Graph) string {
	var b strings.Builder
	b.WriteString("# files\n")
	for _, f := range g.Files() {
		fmt.Fprintf(&b, "%s role=%s status=%s language=%s\n", f.Path, f.Role, f.Status, f.Language)
	}
	for _, name := range []string{"Add", "Push", "helper", "format", "kv_get", "size", "Generated"} {
		fmt.Fprintf(&b, "# definitions %s\n", quote(name))
		for _, d := range g.Definitions(name) {
			fmt.Fprintf(&b, "%s:%d %s %s exported=%v\n", d.Path, d.Range.Start.Line, d.Kind, quote(d.QualifiedName.Untrusted()), d.Exported)
			for _, u := range g.References(d.ID) {
				fmt.Fprintf(&b, "  ref %s:%d:%d %s scope=%s in=%s\n", u.Path, u.Range.Start.Line, u.Range.Start.Column, u.Kind, u.Scope, quote(u.Enclosing.Untrusted()))
			}
			for _, u := range g.TestReferences(d.ID) {
				fmt.Fprintf(&b, "  test %s:%d\n", u.Path, u.Range.Start.Line)
			}
		}
	}
	b.WriteString("# imports\n")
	for _, f := range g.Files() {
		targets, unresolved, _ := g.Imports(f.Path)
		importers, _ := g.Importers(f.Path)
		if len(targets) == 0 && unresolved == 0 && len(importers) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s -> %v unresolved=%d <- %v\n", f.Path, targets, unresolved, importers)
	}
	return b.String()
}

func TestGoldenFixtureRepository(t *testing.T) {
	analyzer := realAnalyzer(t)
	repo := newGitRepository(t)
	repo.write(fixtureFiles)
	commit := repo.commit("fixture")
	store := newTestStore(t, DefaultStoreLimits())
	snapshot := buildCommit(t, store, analyzer, repo.tree(commit))
	if snapshot.Coverage.Reused != 0 || snapshot.Coverage.Analysed == 0 || snapshot.Coverage.TreeTruncated {
		t.Fatalf("coverage = %+v", snapshot.Coverage)
	}
	got := renderGraph(loadGraph(t, store, snapshot))
	golden := filepath.Join("testdata", "fixture.golden")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("missing golden file; run go test -run TestGoldenFixtureRepository -update: %v", err)
	}
	if got != string(want) {
		t.Fatalf("graph differs from %s; run with -update and review the diff\n%s", golden, firstDifference(string(want), got))
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

// TestIncrementalBuildAnalysesOnlyNewBlobs renames a file and edits
// another: the second build analyses only the edited blob, and building a
// commit again analyses nothing.
func TestIncrementalBuildAnalysesOnlyNewBlobs(t *testing.T) {
	analyzer := realAnalyzer(t)
	repo := newGitRepository(t)
	repo.write(fixtureFiles)
	first := repo.commit("first")
	store := newTestStore(t, DefaultStoreLimits())
	tree := repo.tree(first)
	// A small acquisition makes the reads span many acquisitions.
	tree.acquisitionBytes = 100
	a := buildCommit(t, store, analyzer, tree)
	analysedFirst := analyzer.calls.Load()

	repo.git("mv", "calc/calc.go", "calc/arith.go")
	repo.write(map[string]string{"cmd/app/main.go": strings.Replace(fixtureFiles["cmd/app/main.go"], "calc.Add(2, 3)", "calc.Add(2, 4)", 1)})
	second := repo.commit("rename and edit")
	b := buildCommit(t, store, analyzer, repo.tree(second))
	if got := analyzer.calls.Load() - analysedFirst; got != 1 || b.Coverage.Analysed != 1 {
		t.Fatalf("second build analysed %d blobs (coverage %d), want 1", got, b.Coverage.Analysed)
	}
	if b.Coverage.Reused != a.Coverage.Analysed+countStatus(a, StatusBinary)-1 {
		t.Fatalf("reused %d of %d", b.Coverage.Reused, a.Coverage.Analysed)
	}
	g := loadGraph(t, store, b)
	defs := g.Definitions("Add")
	if len(defs) == 0 || defs[0].Path != "calc/arith.go" {
		t.Fatalf("renamed definition = %v", defs)
	}
	before := analyzer.calls.Load()
	buildCommit(t, store, analyzer, repo.tree(first))
	if analyzer.calls.Load() != before {
		t.Fatal("rebuilding an indexed commit analysed blobs")
	}
}

func countStatus(s Snapshot, status Status) int {
	n := 0
	for _, f := range s.Files {
		if f.Status == status {
			n++
		}
	}
	return n
}
