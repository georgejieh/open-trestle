package repochecks

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func names(checks []Check) []string {
	var out []string
	for _, check := range checks {
		out = append(out, check.Name)
	}
	return out
}

func TestDetectGoRestrictsToChangedPackagesAndDependents(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": "module m\n", "a/a.go": "package a", "b/b.go": "package b", "c/c.go": "package c", "root.go": "package m",
		"tools/go.mod": "module m/tools\n", "tools/x/x.go": "package x",
		"vendor/v/v.go": "package v", "README.md": "",
	})
	checks, err := Detect(root, Scope{Changed: []string{"a/a.go", "tools/x/x.go", "README.md", "gone/gone.go"}, Dependents: []string{"b/b.go", "root.go"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"go test ./x (in tools)", "go vet ./x (in tools)", "go test . ./a ./b", "go vet . ./a ./b"}
	if got := names(checks); !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if checks[0].Dir != "tools" || !slices.Equal(checks[2].Args, []string{"test", "-json", "-count=1"}) || !slices.Equal(checks[2].Packages, []string{".", "./a", "./b"}) || checks[2].Vendored {
		t.Fatalf("checks %+v", checks)
	}
}

func TestDetectGoVendoredModule(t *testing.T) {
	root := writeTree(t, map[string]string{"go.mod": "module m\n", "a/a.go": "package a", "vendor/modules.txt": "# example.com/x v1.0.0\n"})
	checks, _ := Detect(root, Scope{Changed: []string{"a/a.go"}})
	if len(checks) != 2 || !checks[0].Vendored {
		t.Fatalf("checks %+v", checks)
	}
	machine := host{home: t.TempDir(), getenv: func(string) string { return "" }, lookPath: func(string) (string, error) { return filepath.Join(root, "go"), nil }}
	for _, vendored := range []bool{true, false} {
		_, chain, err := machine.resolve(Check{Tool: "go", Stack: "go", Vendored: vendored})
		if err != nil || slices.Contains(chain.env, "GOFLAGS=-mod=mod") == vendored {
			t.Fatalf("vendored %v: env %v, %v", vendored, chain.env, err)
		}
	}
}

func TestDetectNothingWithoutChanges(t *testing.T) {
	root := writeTree(t, map[string]string{"go.mod": "module m\n", "a/a.go": "package a", "package.json": `{"scripts":{"test":"node --test"}}`})
	if checks, err := Detect(root, Scope{}); err != nil || len(checks) != 0 {
		t.Fatalf("got %q, %v", names(checks), err)
	}
}

func TestDetectNode(t *testing.T) {
	for _, test := range []struct {
		name    string
		files   map[string]string
		want    Check
		noCheck bool
	}{
		{name: "node test runner", files: map[string]string{"package.json": `{"scripts":{"test":"node --test test/"}}`},
			want: Check{Name: "node --test test/", Tool: "node", Format: FormatTAP}},
		{name: "other script through pnpm", files: map[string]string{"package.json": `{"scripts":{"test":"node --test && eslint ."}}`, "pnpm-lock.yaml": ""},
			want: Check{Name: "pnpm test", Tool: "pnpm", Format: FormatExit}},
		// Declared dependencies are not installed, but the tests may not
		// need them: the run says when one is missing.
		{name: "declared dependencies", files: map[string]string{"package.json": `{"scripts":{"test":"node --test"},"devDependencies":{"prettier":"^3"}}`, "package-lock.json": "{}"},
			want: Check{Name: "node --test", Tool: "node", Format: FormatTAP}},
		{name: "npm placeholder", files: map[string]string{"package.json": `{"scripts":{"test":"echo \"Error: no test specified\" && exit 1"}}`}, noCheck: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			checks, err := Detect(writeTree(t, test.files), Scope{Changed: []string{"package.json"}})
			if err != nil {
				t.Fatal(err)
			}
			if test.noCheck {
				if len(checks) != 0 {
					t.Fatalf("got %+v", checks)
				}
				return
			}
			if len(checks) != 1 {
				t.Fatalf("got %+v", checks)
			}
			got := checks[0]
			if got.Name != test.want.Name || got.Tool != test.want.Tool || got.Format != test.want.Format || got.Missing != test.want.Missing {
				t.Fatalf("got %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestDetectNodeAddsTAPReporterBeforeTestPaths(t *testing.T) {
	checks, _ := Detect(writeTree(t, map[string]string{"package.json": `{"scripts":{"test":"node --test test/ lib/a.test.js"}}`}), Scope{Changed: []string{"lib/a.js"}})
	if len(checks) != 1 || !slices.Equal(checks[0].Args, []string{"--test", "--test-reporter=tap", "--test-reporter-destination=stdout", "test/", "lib/a.test.js"}) {
		t.Fatalf("got %+v", checks)
	}
}

func TestDetectGoRunsTheModuleWhenItsDependenciesChange(t *testing.T) {
	root := writeTree(t, map[string]string{"go.mod": "module m\n", "go.sum": "", "a/a.go": "package a"})
	checks, _ := Detect(root, Scope{Changed: []string{"go.sum", "a/a.go"}})
	if !slices.Equal(names(checks), []string{"go test ./...", "go vet ./..."}) {
		t.Fatalf("got %q", names(checks))
	}
}

func TestDetectPython(t *testing.T) {
	unittest, _ := Detect(writeTree(t, map[string]string{"pkg/mod.py": "", "tests/test_mod.py": ""}), Scope{Changed: []string{"pkg/mod.py"}})
	if !slices.Equal(names(unittest), []string{"python -m unittest"}) || unittest[0].Format != FormatUnittest {
		t.Fatalf("got %+v", unittest)
	}
	tree := writeTree(t, map[string]string{"pyproject.toml": "[tool.pytest.ini_options]\n", "pkg/mod.py": "", "tests/test_mod.py": "", "tests/test_other.py": ""})
	scoped, _ := Detect(tree, Scope{Changed: []string{"pkg/mod.py"}, Dependents: []string{"tests/test_mod.py"}})
	if !slices.Equal(names(scoped), []string{"pytest"}) || scoped[0].Format != FormatJUnit || scoped[0].Report != "pytest-report.xml" {
		t.Fatalf("got %+v", scoped)
	}
	untouched, _ := Detect(tree, Scope{Changed: []string{"README.md"}})
	if len(untouched) != 0 {
		t.Fatalf("an unrelated change ran %+v", untouched)
	}
}

func TestDetectRust(t *testing.T) {
	checks, _ := Detect(writeTree(t, map[string]string{"Cargo.toml": "[package]\n", "src/lib.rs": ""}), Scope{Changed: []string{"src/lib.rs"}})
	if !slices.Equal(names(checks), []string{"cargo test"}) || !slices.Equal(checks[0].Args, []string{"test", "--offline"}) {
		t.Fatalf("got %+v", checks)
	}
}

// Linters run only when the repository's own files use them.
func TestDetectLintersOnlyWhenTheRepositoryUsesThem(t *testing.T) {
	goFiles := map[string]string{"go.mod": "module m\n", "a/a.go": "package a"}
	plain, _ := Detect(writeTree(t, goFiles), Scope{Changed: []string{"a/a.go"}})
	if !slices.Equal(names(plain), []string{"go test ./a", "go vet ./a"}) || plain[1].Format != FormatDiagnostics {
		t.Fatalf("got %+v", plain)
	}
	goFiles[".golangci.yml"] = "version: \"2\"\n"
	goFiles[".github/workflows/ci.yml"] = "on: [pull_request]\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: staticcheck ./...\n"
	linted, _ := Detect(writeTree(t, goFiles), Scope{Changed: []string{"a/a.go"}})
	if !slices.Equal(names(linted), []string{"go test ./a", "go vet ./a", "staticcheck ./a", "golangci-lint run ./a"}) || linted[3].Tool != "golangci-lint" || linted[3].Format != FormatDiagnostics {
		t.Fatalf("got %+v", linted)
	}

	pyFiles := map[string]string{"pkg/a.py": "", "pyproject.toml": "[tool.ruff]\n\n[tool.mypy]\n", "Makefile": "lint:\n\tflake8 .\n"}
	python, _ := Detect(writeTree(t, pyFiles), Scope{Changed: []string{"pkg/a.py"}})
	if !slices.Equal(names(python), []string{"ruff check", "flake8", "mypy"}) || python[2].Stack != "python" {
		t.Fatalf("got %+v", python)
	}
	if untouched, _ := Detect(writeTree(t, pyFiles), Scope{Changed: []string{"README.md"}}); len(untouched) != 0 {
		t.Fatalf("an unrelated change ran %+v", untouched)
	}

	rust, _ := Detect(writeTree(t, map[string]string{"Cargo.toml": "[package]\n", "clippy.toml": "", "src/lib.rs": ""}), Scope{Changed: []string{"src/lib.rs"}})
	if !slices.Equal(names(rust), []string{"cargo test", "cargo clippy"}) || !slices.Equal(rust[1].Args, []string{"clippy", "--offline", "--message-format=short"}) {
		t.Fatalf("got %+v", rust)
	}
}

// A Go linter runs with the go command first on its path.
func TestResolvePutsTheGoCommandBeforeAGoLinter(t *testing.T) {
	root := t.TempDir()
	programs := map[string]string{"go": filepath.Join(root, "sdk", "go", "bin", "go"), "staticcheck": filepath.Join(root, "tools", "bin", "staticcheck")}
	for _, program := range programs {
		os.MkdirAll(filepath.Dir(program), 0o755)
		os.WriteFile(program, nil, 0o755)
	}
	machine := host{home: t.TempDir(), getenv: func(string) string { return "" }, lookPath: func(name string) (string, error) { return programs[name], nil }}
	program, chain, err := machine.resolve(Check{Tool: "staticcheck", Stack: "go"})
	if err != nil || program != "staticcheck" || !slices.Equal(chain.path, []string{filepath.Dir(programs["go"]), filepath.Dir(programs["staticcheck"])}) ||
		!slices.Equal(chain.readOnly, []string{filepath.Join(root, "sdk", "go"), filepath.Join(root, "tools")}) {
		t.Fatalf("program %s, path %v, read-only %v, %v", program, chain.path, chain.readOnly, err)
	}
}

func TestResolveRunsALinkedLauncherFromItsOwnFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need a privilege on Windows")
	}
	root := t.TempDir()
	target := filepath.Join(root, "node", "lib", "node_modules", "npm", "bin", "npm-cli.js")
	launcher := filepath.Join(root, "node", "bin", "npm")
	for _, folder := range []string{filepath.Dir(target), filepath.Dir(launcher)} {
		if err := os.MkdirAll(folder, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(target, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../lib/node_modules/npm/bin/npm-cli.js", launcher); err != nil {
		t.Fatal(err)
	}
	machine := host{home: t.TempDir(), getenv: func(string) string { return "" }, lookPath: func(string) (string, error) { return launcher, nil }}
	program, chain, err := machine.resolve(Check{Tool: "npm", Stack: "node"})
	if err != nil {
		t.Fatal(err)
	}
	resolvedRoot, _ := filepath.EvalSymlinks(filepath.Join(root, "node", "lib", "node_modules", "npm"))
	if program != "npm" || !slices.Equal(chain.path, []string{filepath.Dir(launcher)}) || !slices.Equal(chain.readOnly, []string{filepath.Join(root, "node"), resolvedRoot}) {
		t.Fatalf("program %s, path %v, read-only %v", program, chain.path, chain.readOnly)
	}
}

func TestResolveNeverShowsTheHomeFolder(t *testing.T) {
	home := t.TempDir()
	for _, located := range []string{filepath.Join(home, ".local", "bin", "node"), filepath.Join(home, "bin", "node")} {
		if err := os.MkdirAll(filepath.Dir(located), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(located, nil, 0o755); err != nil {
			t.Fatal(err)
		}
		machine := host{home: home, getenv: func(string) string { return "" }, lookPath: func(string) (string, error) { return located, nil }}
		_, chain, err := machine.resolve(Check{Tool: "node", Stack: "node"})
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Dir(located); !slices.Equal(chain.readOnly, []string{want}) {
			t.Fatalf("read-only %v, want only %s", chain.readOnly, want)
		}
	}
	deep := filepath.Join(home, "sdk", "go1.26", "bin", "go")
	os.MkdirAll(filepath.Dir(deep), 0o755)
	os.WriteFile(deep, nil, 0o755)
	machine := host{home: home, getenv: func(string) string { return "" }, lookPath: func(string) (string, error) { return deep, nil }}
	if _, chain, _ := machine.resolve(Check{Tool: "go", Stack: "go"}); !slices.Equal(chain.readOnly, []string{filepath.Join(home, "sdk", "go1.26")}) {
		t.Fatalf("read-only %v", chain.readOnly)
	}
}
