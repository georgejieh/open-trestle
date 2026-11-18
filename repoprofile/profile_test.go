package repoprofile

import (
	"bytes"
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/repoindex"
	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func entry(path string, role repoindex.Role, language syntaxanalysis.Language) repoindex.FileEntry {
	status := repoindex.StatusNotAnalysed
	if language != "" {
		status = repoindex.StatusIndexed
	}
	return repoindex.FileEntry{Path: path, Object: "0a", Role: role, Language: language, Status: status}
}

// fixture loads the files of a testdata directory as snapshot entries and
// their contents.
func fixture(t *testing.T, name string) ([]repoindex.FileEntry, map[string][]byte) {
	t.Helper()
	root := filepath.Join("testdata", name)
	var files []repoindex.FileEntry
	contents := map[string][]byte{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		files = append(files, entry(rel, repoindex.RoleConfig, ""))
		data, err := os.ReadFile(p)
		contents[rel] = data
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files, contents
}

func TestDetectChecksGolden(t *testing.T) {
	for _, name := range []string{"go", "python", "js"} {
		t.Run(name, func(t *testing.T) {
			files, contents := fixture(t, name)
			read := map[string][]byte{}
			for _, p := range ConfigPaths(files) {
				read[p] = contents[p]
			}
			got, err := json.MarshalIndent(Detect(files, nil, read).Checks, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			golden := filepath.Join("testdata", name+".golden.json")
			if *update {
				if err := os.WriteFile(golden, append(got, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil || !bytes.Equal(append(got, '\n'), want) {
				t.Fatalf("checks differ from %s (run with -update to rewrite):\n%s", golden, got)
			}
		})
	}
}

func TestEveryRuleToolIsKnown(t *testing.T) {
	for _, r := range commandRules {
		if _, ok := toolClass[r.tool]; !ok {
			t.Errorf("rule tool %q has no class", r.tool)
		}
	}
	for _, tool := range hookTools {
		if _, ok := toolClass[tool]; !ok {
			t.Errorf("hook tool %q has no class", tool)
		}
	}
	for _, tool := range configTools {
		if _, ok := toolClass[tool]; !ok {
			t.Errorf("config tool %q has no class", tool)
		}
	}
}

func TestCommandRules(t *testing.T) {
	tests := []struct {
		line string
		want []string
	}{
		{"go test -race ./...", []string{"go-test", "go-test-race"}},
		{"go test -fuzz FuzzX -fuzztime 5s", []string{"go-fuzz", "go-test"}},
		{"go test -fuzztime=5s ./...", []string{"go-test"}},
		{"gofmt -w .", nil},
		{"if [ -n \"$(gofmt -l .)\" ]; then exit 1; fi", []string{"gofmt"}},
		{"cargo fmt --check && cargo clippy -- -D warnings", []string{"clippy", "rustfmt"}},
		{"cargo fmt", nil},
		{"black --check src", []string{"black"}},
		{"black src", nil},
		{"npm install eslint prettier", nil},
		{"pip install ruff && ruff check .", []string{"ruff"}},
		{"./node_modules/.bin/eslint .", []string{"eslint"}},
		{"./mvnw -B verify", []string{"junit"}},
		{"# eslint .", nil},
		{"uses: github/codeql-action/init@v3", []string{"codeql"}},
		{"uses: gitleaks/gitleaks-action@v2", []string{"gitleaks"}},
		{"coverage report --fail-under=90", []string{"coverage-py"}},
		{"prettier --write . # --check", nil},
	}
	for _, tc := range tests {
		got := []string{}
		scanCommands(tc.line, SourceCI, func(_, tool string) { got = append(got, tool) })
		slices.Sort(got)
		if !reflect.DeepEqual(got, orEmpty(tc.want)) {
			t.Errorf("%q: got %v, want %v", tc.line, got, tc.want)
		}
	}
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func TestLanguagesAndTests(t *testing.T) {
	files := []repoindex.FileEntry{
		entry("a.go", repoindex.RoleSource, syntaxanalysis.LanguageGo),
		entry("b.go", repoindex.RoleSource, syntaxanalysis.LanguageGo),
		entry("b_test.go", repoindex.RoleTest, syntaxanalysis.LanguageGo),
		entry("web/app.ts", repoindex.RoleSource, syntaxanalysis.LanguageTypeScript),
		entry("web/__tests__/app.test.ts", repoindex.RoleTest, syntaxanalysis.LanguageTypeScript),
		entry("tools/x.py", repoindex.RoleSource, syntaxanalysis.LanguagePython),
		entry("tools/y.py", repoindex.RoleSource, syntaxanalysis.LanguagePython),
		entry("README.md", repoindex.RoleDocs, ""),
		entry("vendor/v.go", repoindex.RoleVendored, syntaxanalysis.LanguageGo),
	}
	imports := func(p string) []string {
		switch p {
		case "b_test.go":
			return []string{"testing", "github.com/stretchr/testify/require"}
		case "web/__tests__/app.test.ts":
			return []string{"vitest"}
		}
		return nil
	}
	got := Detect(files, imports, nil)
	wantLanguages := []LanguageShare{{"go", 3, 42}, {"python", 2, 28}, {"typescript", 2, 28}}
	if !reflect.DeepEqual(got.Languages, wantLanguages) {
		t.Errorf("languages = %v", got.Languages)
	}
	wantTests := Tests{Frameworks: []string{"go_testing", "testify", "vitest"}, Layouts: []string{"colocated", "test_directory"}, Files: 2}
	if !reflect.DeepEqual(got.Tests, wantTests) {
		t.Errorf("tests = %+v", got.Tests)
	}
	if got.Checks == nil || len(got.Checks) != 0 {
		t.Errorf("checks = %#v", got.Checks)
	}
}

func TestClasses(t *testing.T) {
	p := Profile{Checks: []Check{{Class: "lint"}, {Class: "formatting"}, {Class: "lint"}}}
	if got := p.Classes(); !reflect.DeepEqual(got, []string{"formatting", "lint"}) {
		t.Errorf("classes = %v", got)
	}
}

func TestConfigPathsSelectsRootAndWorkflowFilesOnly(t *testing.T) {
	var files []repoindex.FileEntry
	for _, p := range []string{
		"Makefile", "sub/Makefile", ".github/workflows/ci.yml", ".github/workflows/nested/x.yml", ".github/workflows/notes.md",
		".husky/pre-commit", ".husky/_/husky.sh", ".golangci.toml", "sub/.golangci.yml", "package.json", "docs/package.json",
		".eslintrc.json", "eslint.config.mjs", ".prettierrc", ".circleci/config.yml", "main.go",
	} {
		files = append(files, entry(p, repoindex.RoleConfig, ""))
	}
	files = append(files, repoindex.FileEntry{Path: "justfile", Object: "0a", Status: repoindex.StatusSymlink})
	want := []string{".circleci/config.yml", ".eslintrc.json", ".github/workflows/ci.yml", ".golangci.toml", ".husky/pre-commit", ".prettierrc", "Makefile", "eslint.config.mjs", "package.json"}
	if got := ConfigPaths(files); !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v", got)
	}
}

func TestBounds(t *testing.T) {
	var files []repoindex.FileEntry
	for i := range 200 {
		files = append(files, entry(".github/workflows/w"+string(rune('a'+i/26))+string(rune('a'+i%26))+".yml", repoindex.RoleConfig, ""))
	}
	paths := ConfigPaths(files)
	if len(paths) != 64 || !slices.IsSorted(paths) {
		t.Errorf("ConfigPaths returned %d paths", len(paths))
	}

	contents := map[string][]byte{
		"Makefile":                  []byte(strings.Repeat("# x\n", 10) + "\tgo vet ./...\n"),
		".github/workflows/big.yml": append([]byte(strings.Repeat(" ", MaxFileBytes)), "run: go vet ./...\n"...),
		".github/workflows/bin.yml": append([]byte("run: go vet ./...\n"), 0, 1),
		"tox.ini":                   []byte(strings.Repeat("\n", maxLines) + "pytest\n"),
	}
	got := Detect(nil, nil, contents).Checks
	if len(got) != 1 || got[0].Tool != "go-vet" || got[0].Path != "Makefile" {
		t.Errorf("checks = %v", got)
	}

	long := "run: " + strings.Repeat("a ", maxLineBytes) + "go vet ./...\n"
	if got := Detect(nil, nil, map[string][]byte{"Makefile": []byte(long)}).Checks; len(got) != 0 {
		t.Errorf("a line past the bound was read: %v", got)
	}
}
