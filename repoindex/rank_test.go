package repoindex

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"
)

func TestGoSelectorsAndBareNamesReachOnlyTheirKind(t *testing.T) {
	g := indexRepository(t, map[string]string{
		"go.mod": "module example.com/app\n",
		"a.go":   "package app\n\ntype Cmd struct{ Flags int }\n\nfunc (c *Cmd) Run() int { return walk() }\n\nfunc Run() int { return 0 }\n\nfunc walk() int { return 1 }\n\nfunc (c *Cmd) walk() int { return c.Run() }\n",
		"b.go":   "package app\n\nfunc use(c *Cmd) int { return c.Run() + Run() + walk() }\n",
	})
	if got := fmt.Sprint(referencePaths(g, "Run", "a.go")); got != "[a.go:11 file b.go:3 package b.go:3 package]" {
		t.Fatalf("Run candidates = %s", got)
	}
	cases := map[string]bool{}
	for _, d := range g.Definitions("Run") {
		for _, u := range g.References(d.ID) {
			cases[fmt.Sprintf("%s %s:%d qualified=%t", d.Kind, u.Path, u.Range.Start.Line, u.Qualifier.Untrusted() != "")] = true
		}
	}
	for key := range cases {
		switch key {
		case "method a.go:11 qualified=true", "method b.go:3 qualified=true", "function b.go:3 qualified=false":
		default:
			t.Errorf("unexpected candidate %s", key)
		}
	}
	for _, d := range g.Definitions("walk") {
		for _, u := range g.References(d.ID) {
			if u.Qualifier.Untrusted() != "" && d.Kind != "method" || u.Qualifier.Untrusted() == "" && d.Kind == "method" {
				t.Errorf("%s walk matched %s:%d", d.Kind, u.Path, u.Range.Start.Line)
			}
		}
	}
}

func TestRankLeavesTheImportAnswersUnchanged(t *testing.T) {
	g := indexRepository(t, map[string]string{
		"go.mod":      "module example.com/m\n",
		"app/main.go": "package main\n\nimport \"example.com/m/lib\"\n\nfunc main() { lib.Run() }\n",
		"lib/lib.go":  "package lib\n\nfunc Run() {}\n",
		"lib/more.go": "package lib\n\nfunc More() {}\n",
		"web/a.ts":    "import { b } from \"./b\";\nimport { c } from \"./c\";\n\nexport const a = b + c;\n",
		"web/b.ts":    "export const b = 1;\n",
		"web/c.ts":    "export const c = 2;\n",
	})
	answers := func() string {
		out := ""
		for _, f := range g.Files() {
			imports, unresolved, _ := g.Imports(f.Path)
			importers, _ := g.Importers(f.Path)
			out += fmt.Sprintf("%s %v %d %v\n", f.Path, imports, unresolved, importers)
		}
		return out
	}
	before := answers()
	if _, err := g.Rank(context.Background(), []string{"app/main.go", "web/a.ts"}, DefaultRankLimits()); err != nil {
		t.Fatal(err)
	}
	if after := answers(); after != before {
		t.Fatalf("ranking changed the import answers:\n%s\nbecame\n%s", before, after)
	}
}

func rank(t *testing.T, g *Graph, seeds []string, limits RankLimits) Ranking {
	t.Helper()
	r, err := g.Rank(context.Background(), seeds, limits)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// chainFiles is a chain of packages, each importing and calling the next.
var chainFiles = map[string]string{
	"go.mod":     "module example.com/m\n",
	"a/a.go":     "package a\n\nimport \"example.com/m/b\"\n\nfunc A() int { return b.B() + b.B() }\n",
	"b/b.go":     "package b\n\nimport \"example.com/m/c\"\n\nfunc B() int { return c.C() }\n",
	"c/c.go":     "package c\n\nimport \"example.com/m/d\"\n\nfunc C() int { return d.D() }\n",
	"d/d.go":     "package d\n\nfunc D() int { return 1 }\n",
	"far/far.go": "package far\n\nimport \"example.com/m/d\"\n\nfunc F() int { return d.D() }\n",
}

func TestRankStaysInTheSeedsNeighbourhood(t *testing.T) {
	g := indexRepository(t, chainFiles)
	r := rank(t, g, []string{"a/a.go"}, DefaultRankLimits())
	if !r.Complete {
		t.Fatal("an unbounded ranking is incomplete")
	}
	files := slices.Sorted(maps.Keys(r.Files))
	if fmt.Sprint(files) != "[a/a.go b/b.go c/c.go]" {
		t.Fatalf("files = %v", files)
	}
	names := []string{}
	for _, s := range r.Symbols {
		names = append(names, s.Name.Untrusted())
	}
	if fmt.Sprint(names) != "[B C]" {
		t.Fatalf("symbols = %v", names)
	}
}

func TestRankRecordsEachCut(t *testing.T) {
	g := indexRepository(t, chainFiles)
	for name, limits := range map[string]RankLimits{
		"candidates": {MaxCandidates: 1},
		"work":       {MaxWork: 1},
		"files":      {MaxFiles: 2},
		"edges":      {MaxEdges: 1},
	} {
		if r := rank(t, g, []string{"a/a.go"}, limits); r.Complete {
			t.Errorf("a %s cut left the ranking complete: %v", name, r.Files)
		}
	}
	if r := rank(t, g, []string{"a/a.go"}, RankLimits{MaxFiles: 2}); len(r.Files) > 2 {
		t.Fatalf("the file bound was passed: %v", r.Files)
	}
	wide := map[string]string{"go.mod": "module example.com/m\n", "app/main.go": "package main\n\nimport \"example.com/m/lib\"\n\nfunc main() { lib.F0() }\n"}
	for i := range 6 {
		wide[fmt.Sprintf("lib/f%d.go", i)] = fmt.Sprintf("package lib\n\nfunc F%d() {}\n", i)
	}
	if r := rank(t, indexRepository(t, wide), []string{"app/main.go"}, RankLimits{MaxEdges: 3}); r.Complete || len(r.Files) > 4 {
		t.Fatalf("a wide import passed the link bound: %v", r.Files)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.Rank(ctx, []string{"a/a.go"}, DefaultRankLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled ranking returned %v", err)
	}
}

func TestRankFollowsReferencesFromTheSeedFiles(t *testing.T) {
	g := indexRepository(t, map[string]string{
		"go.mod":         "module example.com/app\n",
		"core/core.go":   "package core\n\nfunc Parse() int { return 1 }\n\nfunc Unused() int { return 2 }\n",
		"util/util.go":   "package util\n\nfunc Pad() int { return 3 }\n",
		"cmd/main.go":    "package main\n\nimport \"example.com/app/core\"\n\nfunc main() { _ = core.Parse() }\n",
		"other/other.go": "package other\n\nimport \"example.com/app/util\"\n\nfunc Use() int { return util.Pad() }\n",
	})
	first := rank(t, g, []string{"cmd/main.go"}, DefaultRankLimits())
	second := rank(t, g, []string{"cmd/main.go"}, DefaultRankLimits())
	if fmt.Sprint(first.Symbols) != fmt.Sprint(second.Symbols) || !first.Complete {
		t.Fatalf("ranking is not stable or complete: %v %v", first.Symbols, second.Symbols)
	}
	if len(first.Symbols) == 0 || first.Symbols[0].Name.Untrusted() != "Parse" {
		t.Fatalf("symbols = %+v", first.Symbols)
	}
	if first.Files["core/core.go"] <= first.Files["util/util.go"] {
		t.Fatalf("files = %v", first.Files)
	}
	for _, s := range first.Symbols {
		if s.Name.Untrusted() == "Unused" {
			t.Fatalf("an unreferenced definition was ranked: %+v", s)
		}
	}
	if empty := rank(t, g, nil, DefaultRankLimits()); len(empty.Files) != 0 || len(empty.Symbols) != 0 || !empty.Complete {
		t.Fatalf("a ranking without seeds is not empty: %+v", empty)
	}
}
