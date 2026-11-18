package repoindex

import (
	"fmt"
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

func TestRankFollowsReferencesFromTheSeedFiles(t *testing.T) {
	g := indexRepository(t, map[string]string{
		"go.mod":         "module example.com/app\n",
		"core/core.go":   "package core\n\nfunc Parse() int { return 1 }\n\nfunc Unused() int { return 2 }\n",
		"util/util.go":   "package util\n\nfunc Pad() int { return 3 }\n",
		"cmd/main.go":    "package main\n\nimport \"example.com/app/core\"\n\nfunc main() { _ = core.Parse() }\n",
		"other/other.go": "package other\n\nimport \"example.com/app/util\"\n\nfunc Use() int { return util.Pad() }\n",
	})
	first := g.Rank([]string{"cmd/main.go"}, DefaultRankLimits())
	second := g.Rank([]string{"cmd/main.go"}, DefaultRankLimits())
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
	if uniform := g.Rank(nil, DefaultRankLimits()); len(uniform.Files) == 0 {
		t.Fatal("a ranking without seeds is empty")
	}
}
