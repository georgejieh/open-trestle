package repochecks

import (
	"os"
	"path/filepath"
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
	want := []string{"go test ./x", "go vet ./x", "go test . ./a ./b", "go vet . ./a ./b"}
	if got := names(checks); !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if checks[0].Dir != "tools" || !slices.Equal(checks[2].Args, []string{"test", "-json", "-count=1", ".", "./a", "./b"}) {
		t.Fatalf("checks %+v", checks)
	}
}

func TestDetectWholeRepository(t *testing.T) {
	root := writeTree(t, map[string]string{"go.mod": "module m\n", "a/a.go": "package a"})
	checks, err := Detect(root, Scope{})
	if err != nil || !slices.Equal(names(checks), []string{"go test ./...", "go vet ./..."}) {
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
		{name: "dependencies are missing", files: map[string]string{"package.json": `{"scripts":{"test":"jest"},"devDependencies":{"jest":"^29"}}`, "package-lock.json": "{}"},
			want: Check{Name: "npm test", Tool: "npm", Format: FormatExit, Missing: "missing dependency: the package's dependencies are not installed, and checks run offline and never install packages"}},
		{name: "npm placeholder", files: map[string]string{"package.json": `{"scripts":{"test":"echo \"Error: no test specified\" && exit 1"}}`}, noCheck: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			checks, err := Detect(writeTree(t, test.files), Scope{})
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

func TestDetectNodeAddsTAPReporter(t *testing.T) {
	checks, _ := Detect(writeTree(t, map[string]string{"package.json": `{"scripts":{"test":"node --test"}}`}), Scope{})
	if len(checks) != 1 || !slices.Equal(checks[0].Args, []string{"--test", "--test-reporter=tap", "--test-reporter-destination=stdout"}) {
		t.Fatalf("got %+v", checks)
	}
}

func TestDetectPython(t *testing.T) {
	unittest, _ := Detect(writeTree(t, map[string]string{"pkg/mod.py": "", "tests/test_mod.py": ""}), Scope{})
	if !slices.Equal(names(unittest), []string{"python -m unittest"}) || unittest[0].Format != FormatUnittest {
		t.Fatalf("got %+v", unittest)
	}
	tree := writeTree(t, map[string]string{"pyproject.toml": "[tool.pytest.ini_options]\n", "pkg/mod.py": "", "tests/test_mod.py": "", "tests/test_other.py": ""})
	scoped, _ := Detect(tree, Scope{Changed: []string{"pkg/mod.py"}, Dependents: []string{"tests/test_mod.py"}})
	if !slices.Equal(names(scoped), []string{"pytest tests/test_mod.py"}) || scoped[0].Format != FormatJUnit || scoped[0].Report != "pytest-report.xml" {
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
