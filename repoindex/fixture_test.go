package repoindex

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/internal/syntaxwasm"
	"github.com/georgejieh/open-trestle/semanticimpact"
	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

var testIdentity = [32]byte{1, 2, 3}

// countingAnalyzer counts the files it analyses.
type countingAnalyzer struct {
	syntaxanalysis.Analyzer
	calls atomic.Int64
}

func (c *countingAnalyzer) Analyze(ctx context.Context, s syntaxanalysis.Source) (syntaxanalysis.FileAnalysis, error) {
	c.calls.Add(1)
	return c.Analyzer.Analyze(ctx, s)
}

var (
	wasmOnce     sync.Once
	wasmAnalyzer *syntaxwasm.Analyzer
	wasmErr      error
)

// realAnalyzer analyses in process with the same analyzers the worker runs.
func realAnalyzer(t *testing.T) *countingAnalyzer {
	t.Helper()
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
	return &countingAnalyzer{Analyzer: syntaxanalysis.NewDispatcher(goAnalyzer, wasmAnalyzer)}
}

// gitRepository is a repository made with the git command in a test folder.
type gitRepository struct {
	t   *testing.T
	dir string
}

func newGitRepository(t *testing.T) *gitRepository {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	r := &gitRepository{t: t, dir: t.TempDir()}
	r.git("init", "-q", "-b", "main")
	return r
}

func (r *gitRepository) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.dir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + r.dir, "GIT_CONFIG_NOSYSTEM=1"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *gitRepository) write(files map[string]string) {
	r.t.Helper()
	for name, content := range files {
		p := filepath.Join(r.dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			r.t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
}

func (r *gitRepository) commit(message string) string {
	r.t.Helper()
	r.git("add", "-A")
	r.git("commit", "-q", "-m", message)
	return r.git("rev-parse", "HEAD")
}

// tree packs the repository's objects, as a clone has them, and returns a
// commit's tree from the packed object store.
func (r *gitRepository) tree(commit string) *GitTree {
	r.t.Helper()
	r.git("repack", "-adq")
	root, err := os.OpenRoot(filepath.Join(r.dir, ".git", "objects"))
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = root.Close() })
	repository, err := evidence.NewRepositoryIdentity("local", []string{"test"}, "fixture")
	if err != nil {
		r.t.Fatal(err)
	}
	store, err := scm.NewLocalGitObjectStoreWithOptions(scm.LocalGitObjectStoreOptions{ObjectsRoot: root, Repository: repository, Profile: scm.LocalGitObjectStoreProfileLooseAndPackIndexV1, ObjectAlgorithm: evidence.RevisionAlgorithmSHA1})
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = store.Close(context.Background()) })
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, commit)
	if err != nil {
		r.t.Fatal(err)
	}
	tree, err := NewGitTree(store, revision)
	if err != nil {
		r.t.Fatal(err)
	}
	return tree
}

func newTestStore(t *testing.T, limits StoreLimits) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "index"), testIdentity, limits)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// fixtureFiles is a small repository in several languages, with tests that
// reference source symbols, vendored, generated, binary and docs files.
var fixtureFiles = map[string]string{
	"go.mod":                            "module example.com/m\n\ngo 1.22\n",
	"README.md":                         "# Fixture\n",
	"calc/calc.go":                      "package calc\n\n// Add adds.\nfunc Add(a, b int) int { return a + b }\n\ntype Acc struct{ total int }\n\nfunc (a *Acc) Push(v int) { a.total = Add(a.total, v) }\n\nfunc unexported() int { return Add(1, 2) }\n",
	"calc/calc_test.go":                 "package calc\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) {\n\tif Add(1, 2) != 3 {\n\t\tt.Fatal(\"sum\")\n\t}\n\tvar a Acc\n\ta.Push(1)\n}\n",
	"cmd/app/main.go":                   "package main\n\nimport \"example.com/m/calc\"\n\nfunc main() {\n\trun()\n}\n\nfunc run() int {\n\treturn calc.Add(2, 3)\n}\n\nfunc Add() {}\n",
	"other/other.go":                    "package other\n\nfunc use() int { return Add() }\n\nfunc Add() int { return 0 }\n",
	"pkg/util.py":                       "def helper(x):\n    return x + 1\n\n\ndef _private():\n    return helper(1)\n",
	"pkg/app.py":                        "from pkg.util import helper\n\n\ndef main():\n    return helper(2)\n",
	"tests/test_util.py":                "from pkg import util\n\n\ndef test_helper():\n    assert util.helper(1) == 2\n",
	"web/lib.ts":                        "export function format(value: number): string {\n  return String(value);\n}\n",
	"web/main.ts":                       "import { format } from \"./lib\";\n\nexport function show(): string {\n  return format(1);\n}\n",
	"web/lib.test.ts":                   "import { format } from \"./lib\";\n\ntest(\"format\", () => {\n  expect(format(2)).toBe(\"2\");\n});\n",
	"native/kv.h":                       "#ifndef KV_H\n#define KV_H\nint kv_get(int key);\n#endif\n",
	"native/kv.c":                       "#include \"kv.h\"\n\nint kv_get(int key) {\n  return key * 2;\n}\n",
	"native/main.c":                     "#include \"kv.h\"\n\nint main(void) {\n  return kv_get(1);\n}\n",
	"src/main/java/com/ex/Box.java":     "package com.ex;\n\npublic class Box {\n  public int size() {\n    return 1;\n  }\n}\n",
	"src/main/java/com/ex/app/App.java": "package com.ex.app;\n\nimport com.ex.Box;\n\npublic class App {\n  public int run() {\n    return new Box().size();\n  }\n}\n",
	"src/test/java/com/ex/BoxTest.java": "package com.ex;\n\npublic class BoxTest {\n  public void sizeIsOne() {\n    new Box().size();\n  }\n}\n",
	"vendor/dep/dep.go":                 "package dep\n\nfunc Add() {}\n",
	"gen/api.pb.go":                     "package gen\n\nfunc Marshal() {}\n",
	"gen/zz.go":                         "// Code generated by tool. DO NOT EDIT.\n\npackage gen\n\nfunc Generated() {}\n",
	"assets/blob.js":                    "var x = 1;\x00\x01\x02",
}
