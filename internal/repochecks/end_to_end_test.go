package repochecks

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/checksandbox"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

// endToEnd runs the real checks on base and head in the real sandbox. It
// skips only when the sandbox or the toolchain is missing here, never when
// a check runs and disagrees.
func endToEnd(t *testing.T, base, head map[string]string, changed []string) Result {
	t.Helper()
	limits := checksandbox.DefaultLimits()
	limits.Time = 5 * time.Minute
	report, err := Run(context.Background(), Input{
		BaseTree: writeTree(t, base), HeadTree: writeTree(t, head), Scope: Scope{Changed: changed},
		Limits: limits, Budget: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) == 0 {
		t.Fatal("no check was detected")
	}
	first := report.Results[0]
	if !first.Ran && (strings.Contains(first.Reason, "not installed on this machine") || strings.Contains(first.Reason, "user namespaces") ||
		strings.Contains(first.Reason, "NUL device") || strings.Contains(first.Reason, "read access") || strings.Contains(first.Reason, "AppContainer")) {
		t.Skipf("the check could not run here: %s", first.Reason)
	}
	t.Log(report.Summary())
	return first
}

func TestEndToEndGoRegression(t *testing.T) {
	files := map[string]string{
		"go.mod":         "module example.com/calc\n\ngo 1.22\n",
		"calc/calc.go":   "package calc\n\nfunc Add(a, b int) int { return a + b }\n\nfunc Sub(a, b int) int { return a - b }\n",
		"calc/c_test.go": "package calc\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) {\n\tif Add(2, 3) != 5 {\n\t\tt.Fatal(Add(2, 3))\n\t}\n}\n\nfunc TestSub(t *testing.T) {\n\tif Sub(3, 2) != 1 {\n\t\tt.Fatal(Sub(3, 2))\n\t}\n}\n",
		"other/other.go": "package other\n\nfunc Broken() int { return \"not compiled: out of scope\" }\n",
	}
	head := map[string]string{}
	for name, content := range files {
		head[name] = content
	}
	head["calc/calc.go"] = strings.Replace(files["calc/calc.go"], "return a + b", "return a - b", 1)
	result := endToEnd(t, files, head, []string{"calc/calc.go"})
	if !result.Ran || !slices.Equal(result.Regressions, []string{"example.com/calc/calc.TestAdd"}) || result.Flaky != 0 || result.Tests != 2 {
		t.Fatalf("result %+v", result)
	}
}

func TestEndToEndPythonRegression(t *testing.T) {
	files := map[string]string{
		"shop/__init__.py":        "",
		"shop/price.py":           "def total(prices):\n    return sum(prices)\n",
		"tests/__init__.py":       "",
		"tests/test_price.py":     "import unittest\n\nfrom shop.price import total\n\n\nclass Total(unittest.TestCase):\n    def test_sum(self):\n        self.assertEqual(total([1, 2]), 3)\n\n    def test_empty(self):\n        self.assertEqual(total([]), 0)\n",
		"tests/test_untouched.py": "import unittest\n\n\nclass Untouched(unittest.TestCase):\n    def test_ok(self):\n        pass\n",
	}
	head := map[string]string{}
	for name, content := range files {
		head[name] = content
	}
	head["shop/price.py"] = "def total(prices):\n    return sum(prices) + (1 if prices else 0)\n"
	result := endToEnd(t, files, head, []string{"shop/price.py"})
	if !result.Ran || !slices.Equal(result.Regressions, []string{"tests.test_price.Total.test_sum"}) || result.Tests != 3 {
		t.Fatalf("result %+v", result)
	}
}

func TestEndToEndNodeRegression(t *testing.T) {
	files := map[string]string{
		"package.json":   `{"type": "module", "scripts": {"test": "node --test"}}`,
		"lib/greet.js":   "export const greet = (name) => `hello ${name}`;\n",
		"greet.test.mjs": "import test from 'node:test';\nimport assert from 'node:assert';\nimport { greet } from './lib/greet.js';\ntest('greets', () => assert.equal(greet('a'), 'hello a'));\ntest('stable', () => {});\n",
	}
	head := map[string]string{}
	for name, content := range files {
		head[name] = content
	}
	head["lib/greet.js"] = "export const greet = (name) => `hi ${name}`;\n"
	result := endToEnd(t, files, head, []string{"lib/greet.js"})
	if !result.Ran || !slices.Equal(result.Regressions, []string{"greets"}) || result.Tests != 2 {
		t.Fatalf("result %+v", result)
	}
}

func TestMaterializeWritesTheCommitTree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repository := t.TempDir()
	git := func(args ...string) string {
		command := exec.Command("git", append([]string{"-C", repository, "-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + repository, "GIT_CONFIG_NOSYSTEM=1", "SYSTEMROOT=" + os.Getenv("SYSTEMROOT")}
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "-b", "main")
	writeFile := func(name, content string, mode os.FileMode) {
		path := filepath.Join(repository, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("a/b.txt", "content", 0o644)
	writeFile("run.sh", "#!/bin/sh\n", 0o755)
	git("add", ".")
	git("update-index", "--chmod=+x", "run.sh")
	git("commit", "-q", "-m", "c")
	digest := git("rev-parse", "HEAD")

	objects, err := os.OpenRoot(filepath.Join(repository, ".git", "objects"))
	if err != nil {
		t.Fatal(err)
	}
	defer objects.Close()
	identity, _ := evidence.NewRepositoryIdentity("local", []string{"checkout"}, "repository")
	store, err := scm.NewLocalGitObjectStoreWithOptions(scm.LocalGitObjectStoreOptions{ObjectsRoot: objects, Repository: identity, Profile: scm.LocalGitObjectStoreProfileLooseAndPackIndexV1, ObjectAlgorithm: evidence.RevisionAlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close(context.Background())
	commit, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, digest)
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := Materialize(context.Background(), store, commit, target, 1<<20); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(target, "a", "b.txt")); err != nil || string(data) != "content" {
		t.Fatalf("a/b.txt: %q, %v", data, err)
	}
	if info, err := os.Stat(filepath.Join(target, "run.sh")); err != nil || runtime.GOOS != "windows" && info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("run.sh: %v, %v", info, err)
	}
	if err := Materialize(context.Background(), store, commit, t.TempDir(), 3); err == nil {
		t.Fatal("a tree past the limit was written")
	}

	writeFile("a/b.txt", "changed", 0o644)
	writeFile("c.txt", "new", 0o644)
	git("add", ".")
	git("commit", "-q", "-m", "d")
	next, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, git("rev-parse", "HEAD"))
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ChangedPaths(context.Background(), store, commit, next)
	if err != nil || !slices.Equal(changed, []string{"a/b.txt", "c.txt"}) {
		t.Fatalf("changed %v, %v", changed, err)
	}
}
