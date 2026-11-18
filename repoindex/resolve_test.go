package repoindex

import (
	"fmt"
	"strings"
	"testing"
)

// indexFiles builds and loads a commit of a repository holding files.
func indexRepository(t *testing.T, files map[string]string) *Graph {
	t.Helper()
	analyzer := realAnalyzer(t)
	repo := newGitRepository(t)
	repo.write(files)
	commit := repo.commit("files")
	store := newTestStore(t, DefaultStoreLimits())
	return loadGraph(t, store, buildCommit(t, store, analyzer, repo.tree(commit)))
}

func referencePaths(g *Graph, name, inPath string) []string {
	out := []string{}
	for _, d := range g.Definitions(name) {
		if d.Path != inPath {
			continue
		}
		for _, u := range g.References(d.ID) {
			out = append(out, fmt.Sprintf("%s:%d %s", u.Path, u.Range.Start.Line, u.Scope))
		}
	}
	return out
}

func TestGoImportsResolveThroughModulesAndDeclaredPackageNames(t *testing.T) {
	g := indexRepository(t, map[string]string{
		"go.mod":        "module example.com/app\n",
		"errors/new.go": "package errors\n\nfunc New() int { return 1 }\n",
		"lib/api.go":    "package service\n\nfunc Run() int { return 1 }\n",
		"main.go":       "package main\n\nimport (\n\t\"errors\"\n\n\t\"example.com/app/lib\"\n)\n\nfunc main() {\n\t_ = errors.New(\"x\")\n\t_ = service.Run()\n}\n",
	})
	if got := referencePaths(g, "New", "errors/new.go"); len(got) != 0 {
		t.Fatalf("a standard library import matched a local package: %v", got)
	}
	if got := referencePaths(g, "Run", "lib/api.go"); fmt.Sprint(got) != "[main.go:11 import]" {
		t.Fatalf("the declared package name was not bound: %v", got)
	}
	if !g.Coverage().Complete {
		t.Fatalf("coverage = %+v", g.Coverage())
	}
}

func TestGoModulesLeftOutMakeCoverageIncomplete(t *testing.T) {
	g := indexRepository(t, map[string]string{"go.mod": "go 1.22\n", "a.go": "package a\n"})
	if c := g.Coverage(); c.Complete || c.Coverage.ModulesLeftOut != 1 {
		t.Fatalf("coverage = %+v", c)
	}
}

func TestJavaClassImportsTargetTheClassFile(t *testing.T) {
	g := indexRepository(t, map[string]string{
		"src/com/ex/Box.java":   "package com.ex;\n\npublic class Box {\n  public int size() { return 1; }\n}\n",
		"src/com/ex/Other.java": "package com.ex;\n\npublic class Other {\n  public int size() { return 2; }\n}\n",
		"src/com/app/App.java":  "package com.app;\n\nimport com.ex.Box;\n\npublic class App {\n  int run() { return new Box().size(); }\n}\n",
	})
	if got := referencePaths(g, "size", "src/com/ex/Other.java"); len(got) != 0 {
		t.Fatalf("a class import admitted candidates of another class: %v", got)
	}
	if got := referencePaths(g, "size", "src/com/ex/Box.java"); fmt.Sprint(got) != "[src/com/app/App.java:6 import]" {
		t.Fatalf("candidates of the imported class = %v", got)
	}
	imports, _, _ := g.Imports("src/com/app/App.java")
	if fmt.Sprint(imports) != "[src/com/ex/Box.java]" {
		t.Fatalf("imports = %v", imports)
	}
}

func TestDependentsFindFormerUsersOfRemovedAndHiddenDefinitions(t *testing.T) {
	analyzer := realAnalyzer(t)
	repo := newGitRepository(t)
	repo.write(map[string]string{
		"web/lib.ts":                  "export function run(): number {\n  return 1;\n}\n",
		"web/main.ts":                 "import { run } from \"./lib\";\n\nexport function go(): number {\n  return run();\n}\n",
		"src/com/ex/Foo.java":         "package com.ex;\n\nclass Foo {\n  static int run() { return 1; }\n}\n",
		"src/test/com/ex/UseFoo.java": "package com.ex;\n\nclass UseFoo {\n  int call() { return Foo.run(); }\n}\n",
	})
	baseCommit := repo.commit("base")
	repo.write(map[string]string{"web/lib.ts": "function run(): number {\n  return 1;\n}\n"})
	repo.git("rm", "-q", "src/com/ex/Foo.java")
	headCommit := repo.commit("head")
	store := newTestStore(t, DefaultStoreLimits())
	base := loadGraph(t, store, buildCommit(t, store, analyzer, repo.tree(baseCommit)))
	head := loadGraph(t, store, buildCommit(t, store, analyzer, repo.tree(headCommit)))
	result := Dependents(head, base, []Change{
		{Path: "web/lib.ts", BasePath: "web/lib.ts", HeadLines: []LineRange{{1, 1}}, BaseLines: []LineRange{{1, 1}}},
		{BasePath: "src/com/ex/Foo.java", BaseLines: WholeFile},
	}, DefaultDependentsLimits())
	got := []string{}
	for _, d := range result.Dependents {
		got = append(got, d.Path+" "+string(d.Scope))
	}
	if strings.Join(got, ",") != "web/main.ts import,src/test/com/ex/UseFoo.java package" {
		t.Fatalf("dependents = %v (changed %d)", got, len(result.Changed))
	}
}

func TestDependentsRecordTheWorkBudget(t *testing.T) {
	g := indexRepository(t, map[string]string{
		"a.go": "package a\n\nfunc Run() {}\n",
		"b.go": "package a\n\nfunc b() { Run(); Run(); Run() }\n",
	})
	result := Dependents(g, nil, []Change{{Path: "a.go", HeadLines: []LineRange{{3, 3}}}}, DependentsLimits{MaxWork: 1})
	if result.Cut.WorkCut != 1 || result.Coverage.Complete {
		t.Fatalf("cut = %+v, complete %v", result.Cut, result.Coverage.Complete)
	}
}
