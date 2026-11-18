package reviewcontext

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/internal/syntaxwasm"
	"github.com/georgejieh/open-trestle/repoindex"
	"github.com/georgejieh/open-trestle/semanticimpact"
	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

var update = flag.Bool("update", false, "rewrite the golden files")

var (
	wasmOnce     sync.Once
	wasmAnalyzer *syntaxwasm.Analyzer
	wasmErr      error
)

func analyzer(t *testing.T) syntaxanalysis.Analyzer {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fixture store needs an owner-only folder")
	}
	wasmOnce.Do(func() { wasmAnalyzer, wasmErr = syntaxwasm.New(context.Background(), syntaxwasm.Config{}) })
	if wasmErr != nil {
		t.Fatal(wasmErr)
	}
	if !wasmAnalyzer.Available() {
		t.Skip("the wazero compiler does not run on this platform")
	}
	goAnalyzer, err := semanticimpact.NewGoSyntaxAnalyzer(syntaxanalysis.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return syntaxanalysis.NewDispatcher(goAnalyzer, wasmAnalyzer)
}

// change is a fixture repository with a base and a head commit.
type change struct {
	t          *testing.T
	dir        string
	store      *repoindex.Store
	objects    *scm.LocalGitObjectStore
	base, head *repoindex.Graph
}

func (c *change) git(args ...string) string {
	c.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", c.dir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + c.dir, "GIT_CONFIG_NOSYSTEM=1"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		c.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (c *change) commit(files map[string]string) string {
	c.t.Helper()
	for name, content := range files {
		p := filepath.Join(c.dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			c.t.Fatal(err)
		}
		if content == "" {
			_ = os.Remove(p)
			continue
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			c.t.Fatal(err)
		}
	}
	c.git("add", "-A")
	c.git("commit", "-q", "-m", "change")
	return c.git("rev-parse", "HEAD")
}

func (c *change) tree(commit string) *repoindex.GitTree {
	c.t.Helper()
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, commit)
	if err != nil {
		c.t.Fatal(err)
	}
	tree, err := repoindex.NewGitTree(c.objects, revision)
	if err != nil {
		c.t.Fatal(err)
	}
	return tree
}

// newChange indexes a base commit of files and a head commit that applies
// edits, where an empty content deletes a file.
func newChange(t *testing.T, files, edits map[string]string) (*change, []repoindex.Change) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	a := analyzer(t)
	c := &change{t: t, dir: t.TempDir()}
	c.git("init", "-q", "-b", "main")
	baseCommit := c.commit(files)
	headCommit := c.commit(edits)
	c.git("repack", "-adq")
	root, err := os.OpenRoot(filepath.Join(c.dir, ".git", "objects"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	repository, _ := evidence.NewRepositoryIdentity("local", []string{"test"}, "fixture")
	c.objects, err = scm.NewLocalGitObjectStoreWithOptions(scm.LocalGitObjectStoreOptions{ObjectsRoot: root, Repository: repository, Profile: scm.LocalGitObjectStoreProfileLooseAndPackIndexV1, ObjectAlgorithm: evidence.RevisionAlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.objects.Close(context.Background()) })
	if c.store, err = repoindex.NewStore(filepath.Join(t.TempDir(), "index"), [32]byte{7}, repoindex.DefaultStoreLimits()); err != nil {
		t.Fatal(err)
	}
	load := func(commit string) *repoindex.Graph {
		g, _, err := repoindex.Builder{Store: c.store, Analyzer: a, Parallelism: 2}.Load(context.Background(), c.tree(commit))
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	c.base, c.head = load(baseCommit), load(headCommit)
	changes, pairs := repoindex.ChangedFiles(c.base.Files(), c.head.Files())
	if err := repoindex.DiffChanges(context.Background(), c.tree(headCommit), changes, pairs, 1<<20); err != nil {
		t.Fatal(err)
	}
	repoindex.SortChanges(changes)
	return c, changes
}

func render(plan review.ContextPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "state %s complete %t dependents %d\n", plan.State, plan.Complete, plan.Dependents)
	for _, item := range plan.Items {
		fmt.Fprintf(&b, "%s %d depth %d %s:%d-%d\n", item.Stage, item.Rank, item.Depth, item.Path, item.StartLine, item.EndLine)
	}
	for _, d := range plan.Changed {
		fmt.Fprintf(&b, "changed %s:%d-%d dependents %d tests %d\n", d.Path, d.StartLine, d.EndLine, d.Dependents, d.Tests)
	}
	stages := []string{}
	for stage, n := range plan.StageOmitted {
		stages = append(stages, fmt.Sprintf("stage limit %s %d\n", stage, n))
	}
	sort.Strings(stages)
	b.WriteString(strings.Join(stages, ""))
	return b.String()
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatalf("%s differs from the golden file:\n%s", name, got)
	}
}

var goFiles = map[string]string{
	"go.mod":            "module example.com/m\n\ngo 1.22\n",
	"calc/calc.go":      "package calc\n\n// Add adds.\nfunc Add(a, b int) int {\n\tsum := a + b\n\treturn sum\n}\n\nfunc Twice(a int) int { return Add(a, a) }\n\ntype Acc struct{ total int }\n\nfunc (a *Acc) Push(v int) { a.total = Add(a.total, v) }\n",
	"calc/calc_test.go": "package calc\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) {\n\tif Add(1, 2) != 3 {\n\t\tt.Fatal(\"sum\")\n\t}\n}\n",
	"cmd/app/main.go":   "package main\n\nimport \"example.com/m/calc\"\n\nfunc main() {\n\t_ = run()\n}\n\nfunc run() int {\n\treturn calc.Add(2, 3)\n}\n",
	"util/pad.go":       "package util\n\nfunc Pad(s string) string { return s + \" \" }\n",
}

func TestPlanGoChange(t *testing.T) {
	c, changes := newChange(t, goFiles, map[string]string{
		"calc/calc.go": strings.Replace(goFiles["calc/calc.go"], "\tsum := a + b\n", "\tsum := a + b + 0\n", 1),
	})
	plan := Plan(c.head, c.base, changes, DefaultLimits())
	checkGolden(t, "go", render(plan))
	if again := Plan(c.head, c.base, changes, DefaultLimits()); render(again) != render(plan) {
		t.Fatal("the plan is not stable")
	}
}

func TestPlanPythonChange(t *testing.T) {
	files := map[string]string{
		"pkg/__init__.py":    "",
		"pkg/util.py":        "def helper(x):\n    y = x + 1\n    return y\n\n\ndef other():\n    return 0\n",
		"pkg/app.py":         "from pkg.util import helper\n\n\ndef main():\n    return helper(2)\n",
		"tests/test_util.py": "from pkg.util import helper\n\n\ndef test_helper():\n    assert helper(1) == 2\n",
	}
	files["pkg/__init__.py"] = "\n"
	c, changes := newChange(t, files, map[string]string{"pkg/util.py": strings.Replace(files["pkg/util.py"], "y = x + 1", "y = x + 2", 1)})
	checkGolden(t, "python", render(Plan(c.head, c.base, changes, DefaultLimits())))
}

func TestPlanTypeScriptChange(t *testing.T) {
	files := map[string]string{
		"web/lib.ts":      "export function format(value: number): string {\n  const text = String(value);\n  return text;\n}\n",
		"web/main.ts":     "import { format } from \"./lib\";\n\nexport function show(): string {\n  return format(1);\n}\n",
		"web/lib.test.ts": "import { format } from \"./lib\";\n\ntest(\"format\", () => {\n  expect(format(2)).toBe(\"2\");\n});\n",
	}
	c, changes := newChange(t, files, map[string]string{"web/lib.ts": strings.Replace(files["web/lib.ts"], "String(value)", "String(value + 0)", 1)})
	checkGolden(t, "typescript", render(Plan(c.head, c.base, changes, DefaultLimits())))
}

func TestPlanLimitsCutEachStage(t *testing.T) {
	c, changes := newChange(t, goFiles, map[string]string{
		"calc/calc.go": strings.Replace(goFiles["calc/calc.go"], "\tsum := a + b\n", "\tsum := a + b + 0\n", 1),
	})
	limits := DefaultLimits()
	limits.Callers, limits.Tests, limits.Map, limits.EnclosingLines = 1, 0, 1, 2
	plan := Plan(c.head, c.base, changes, limits)
	checkGolden(t, "go_limits", render(plan))
	if plan.StageOmitted[review.ContextStageRelatedTest] == 0 || plan.StageOmitted[review.ContextStageDirectReference] == 0 {
		t.Fatalf("stage limits were not recorded: %v", plan.StageOmitted)
	}
}

func TestPlanMapsWhatTheChangedFilesUse(t *testing.T) {
	c, changes := newChange(t, goFiles, map[string]string{
		"cmd/app/main.go": "package main\n\nimport (\n\t\"example.com/m/calc\"\n\t\"example.com/m/util\"\n)\n\nfunc main() {\n\t_ = run()\n}\n\nfunc run() int {\n\t_ = util.Pad(\"x\")\n\treturn calc.Twice(3)\n}\n",
	})
	plan := Plan(c.head, c.base, changes, DefaultLimits())
	checkGolden(t, "go_map", render(plan))
	mapped := map[string]bool{}
	for _, item := range plan.Items {
		if item.Stage == review.ContextStageRepositoryMap {
			mapped[item.Path] = true
		}
	}
	if !mapped["calc/calc.go"] || !mapped["util/pad.go"] {
		t.Fatalf("the map does not list what the changed file uses: %v", plan.Items)
	}
}

func TestPlanShowsAFunctionThatOnlyLostLines(t *testing.T) {
	base := map[string]string{}
	for name, content := range goFiles {
		base[name] = content
	}
	base["calc/calc.go"] = strings.Replace(goFiles["calc/calc.go"], "\treturn sum\n", "\tif sum < 0 {\n\t\treturn 0\n\t}\n\treturn sum\n", 1)
	c, changes := newChange(t, base, map[string]string{"calc/calc.go": goFiles["calc/calc.go"]})
	plan := Plan(c.head, c.base, changes, DefaultLimits())
	checkGolden(t, "go_deletion", render(plan))
	if len(plan.Items) == 0 || plan.Items[0].Stage != review.ContextStageEnclosingSymbol || plan.Items[0].Path != "calc/calc.go" {
		t.Fatalf("the function that lost a line is not shown: %v", plan.Items)
	}
}
