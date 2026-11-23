package repochecks

import (
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/georgejieh/open-trestle/repoindex"
	"github.com/georgejieh/open-trestle/repoprofile"
)

// Check is one command detected from a repository's tree.
type Check struct {
	// Name is what the walkthrough shows, for example "go test ./a ./b".
	Name  string
	Stack string
	// Tool is the program, found on the host's PATH and shown read-only.
	Tool string
	// Dir is the working directory, slash-separated and relative to the
	// tree root.
	Dir  string
	Args []string
	// Packages are the Go package patterns, which follow Args. Each tree
	// runs only those it has, so a package added on head is new there.
	Packages []string
	// Vendored is set for a Go module with a vendor/modules.txt file, whose
	// dependencies come from its vendor folder.
	Vendored bool
	Format   Format
	// Report is the report file, relative to the sandbox's temporary
	// folder, that Args ask the runner to write.
	Report string
	// Missing, when set, says why the check cannot run before it is tried.
	Missing string
}

// Scope restricts checks to the changed area.
type Scope struct {
	// Changed are the files the change adds, removes or modifies,
	// slash-separated.
	Changed []string
	// Dependents are files that depend on the changed ones, from the
	// repository index, slash-separated.
	Dependents []string
}

func (scope Scope) paths() []string {
	return append(append([]string{}, scope.Changed...), scope.Dependents...)
}

// skippedFolders never hold the repository's own checks.
var skippedFolders = map[string]bool{".git": true, "node_modules": true, "vendor": true, "testdata": true, ".venv": true, "venv": true, "target": true, "__pycache__": true}

// Detect lists the checks for the tree at root, restricted to scope.
func Detect(root string, scope Scope) ([]Check, error) {
	files, err := listFiles(root)
	if err != nil {
		return nil, err
	}
	read := func(name string) []byte {
		data, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		return data
	}
	exists := func(name string) bool { return isFile(filepath.Join(root, filepath.FromSlash(name))) }
	used := usedTools(root, files)
	var checks []Check
	checks = append(checks, detectGo(files, exists, used, scope)...)
	checks = append(checks, detectNode(files, read, scope)...)
	checks = append(checks, detectPython(files, read, used, scope)...)
	checks = append(checks, detectRust(files, used, scope)...)
	return checks, nil
}

// usedTools are the tools that the repository's CI, task runners, hooks or
// configuration files use, as repoprofile reads them.
func usedTools(root string, files []string) map[string]bool {
	entries := make([]repoindex.FileEntry, len(files))
	for index, file := range files {
		// ConfigPaths reads only entries with content, which every listed
		// file has.
		entries[index] = repoindex.FileEntry{Path: file, Object: "file"}
	}
	contents := map[string][]byte{}
	for _, name := range repoprofile.ConfigPaths(entries) {
		if data, err := readBounded(filepath.Join(root, filepath.FromSlash(name)), repoprofile.MaxFileBytes); err == nil {
			contents[name] = data
		}
	}
	used := map[string]bool{}
	for _, check := range repoprofile.Detect(nil, nil, contents).Checks {
		used[check.Tool] = true
	}
	return used
}

// readBounded reads at most limit bytes and one more of a file, so a larger
// file is seen to be too large without being held.
func readBounded(name string, limit int64) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, limit+1))
}

// linter is a linter or type checker that runs when the repository uses
// tool, with arguments that keep it offline, leave the tree unchanged,
// keep its caches in the sandbox and print one line per diagnostic.
type linter struct {
	tool, name, program string
	args                []string
}

var goLinters = []linter{
	{tool: "staticcheck", name: "staticcheck", program: "staticcheck"},
	{tool: "golangci-lint", name: "golangci-lint run", program: "golangci-lint", args: []string{"run", "--fix=false", "--new=false", "--path-mode=abs", "--max-issues-per-linter=0", "--max-same-issues=0",
		"--output.text.path=stdout", "--output.text.print-issued-lines=false", "--output.text.colors=false", "--show-stats=false"}},
}

var pythonLinters = []linter{
	{tool: "ruff", name: "ruff check", program: "ruff", args: []string{"check", "--no-cache", "--no-fix", "--output-format=concise", "--quiet", "."}},
	{tool: "flake8", name: "flake8", program: "flake8", args: []string{"."}},
	{tool: "mypy", name: "mypy", program: "mypy", args: []string{"--cache-dir=$TMPDIR/mypy-cache", "--no-error-summary", "--no-pretty", "--no-color-output", "."}},
}

// listFiles returns the tree's files, slash-separated and sorted.
func listFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && name != root && skippedFolders[entry.Name()] {
			return filepath.SkipDir
		}
		if entry.Type().IsRegular() {
			relative, err := filepath.Rel(root, name)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(relative))
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func detectGo(files []string, exists func(string) bool, used map[string]bool, scope Scope) []Check {
	var modules []string
	packages := map[string]bool{}
	for _, file := range files {
		if path.Base(file) == "go.mod" {
			modules = append(modules, path.Dir(file))
		}
		if strings.HasSuffix(file, ".go") {
			packages[path.Dir(file)] = true
		}
	}
	// Deepest module first, so each file belongs to its nearest module.
	sort.Slice(modules, func(i, j int) bool { return len(modules[i]) > len(modules[j]) })
	targets := map[string][]string{}
	for _, file := range scope.paths() {
		if base := path.Base(file); base == "go.mod" || base == "go.sum" || base == "go.work" || base == "go.work.sum" {
			if slices.Contains(modules, path.Dir(file)) {
				targets[path.Dir(file)] = append(targets[path.Dir(file)], "./...")
			}
			continue
		}
		if !strings.HasSuffix(file, ".go") || !packages[path.Dir(file)] {
			continue
		}
		if module, ok := nearest(modules, file); ok {
			targets[module] = append(targets[module], packagePattern(module, path.Dir(file)))
		}
	}
	var checks []Check
	for _, module := range modules {
		patterns := targets[module]
		if len(patterns) == 0 {
			continue
		}
		sort.Strings(patterns)
		patterns = slices.Compact(patterns)
		if slices.Contains(patterns, "./...") {
			patterns = []string{"./..."}
		}
		vendored := exists(path.Join(module, "vendor", "modules.txt"))
		listed := strings.Join(patterns, " ")
		checks = append(checks,
			Check{Name: "go test " + listed, Stack: "go", Tool: "go", Dir: module, Args: []string{"test", "-json", "-count=1"}, Packages: patterns, Vendored: vendored, Format: FormatGoJSON},
			Check{Name: "go vet " + listed, Stack: "go", Tool: "go", Dir: module, Args: []string{"vet"}, Packages: patterns, Vendored: vendored, Format: FormatDiagnostics},
		)
		for _, linter := range goLinters {
			if used[linter.tool] {
				checks = append(checks, Check{Name: linter.name + " " + listed, Stack: "go", Tool: linter.program, Dir: module, Args: linter.args, Packages: patterns, Vendored: vendored, Format: FormatDiagnostics})
			}
		}
	}
	return checks
}

// lintChecks are the checks of the linters the repository uses, run in the
// tree root.
func lintChecks(linters []linter, stack string, used map[string]bool) []Check {
	var checks []Check
	for _, linter := range linters {
		if used[linter.tool] {
			checks = append(checks, Check{Name: linter.name, Stack: stack, Tool: linter.program, Dir: ".", Args: linter.args, Format: FormatDiagnostics})
		}
	}
	return checks
}

// packagePattern names the package in folder for the go command run in
// module.
func packagePattern(module, folder string) string {
	relative := folder
	if module != "." {
		relative = strings.TrimPrefix(strings.TrimPrefix(folder, module), "/")
	}
	if relative == "" || relative == "." {
		return "."
	}
	return "./" + relative
}

// nearest returns the deepest folder of folders that holds file.
func nearest(folders []string, file string) (string, bool) {
	for _, folder := range folders {
		if folder == "." || strings.HasPrefix(file, folder+"/") {
			return folder, true
		}
	}
	return "", false
}

type packageJSON struct {
	Scripts map[string]string
}

const npmPlaceholderTest = `echo "Error: no test specified" && exit 1`

var shellSyntax = regexp.MustCompile("[|&;<>()$`\\\\\"'*?\\[\\]#~=%]")

// detectNode runs the root package's test script. A script that is a
// plain "node --test" call runs node directly with a TAP reporter, so each
// test has a result; any other script runs through the package manager and
// gives one result for the whole script. Declared dependencies are not
// installed in the sandbox; a run that needs one reports it missing.
func detectNode(files []string, read func(string) []byte, scope Scope) []Check {
	if !slices.Contains(files, "package.json") || !touches(scope, ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", "package.json") {
		return nil
	}
	var manifest packageJSON
	if json.Unmarshal(read("package.json"), &manifest) != nil {
		return []Check{{Name: "npm test", Stack: "node", Tool: "npm", Dir: ".", Missing: "package.json cannot be parsed"}}
	}
	script := strings.TrimSpace(manifest.Scripts["test"])
	if script == "" || script == npmPlaceholderTest {
		return nil
	}
	manager := "npm"
	switch {
	case slices.Contains(files, "pnpm-lock.yaml"):
		manager = "pnpm"
	case slices.Contains(files, "yarn.lock"):
		manager = "yarn"
	}
	check := Check{Name: manager + " test", Stack: "node", Tool: manager, Dir: ".", Args: []string{"test"}, Format: FormatExit}
	if fields := strings.Fields(script); len(fields) >= 2 && fields[0] == "node" && fields[1] == "--test" && !shellSyntax.MatchString(script) {
		args := append([]string{"--test", "--test-reporter=tap", "--test-reporter-destination=stdout"}, fields[2:]...)
		check = Check{Name: script, Stack: "node", Tool: "node", Dir: ".", Args: args, Format: FormatTAP}
	}
	return []Check{check}
}

// detectPython runs pytest when the repository configures it, and
// unittest discovery otherwise, when the tree has Python tests and a Python
// file changed. Either runs the whole suite: which tests cover a changed
// module is not known here. The linters the repository uses run after them.
func detectPython(files []string, read func(string) []byte, used map[string]bool, scope Scope) []Check {
	if !touches(scope, ".py", "pyproject.toml", "setup.cfg", "pytest.ini", "tox.ini", "ruff.toml", "mypy.ini", ".flake8") {
		return nil
	}
	return append(pythonTests(files, read, scope), lintChecks(pythonLinters, "python", used)...)
}

func pythonTests(files []string, read func(string) []byte, scope Scope) []Check {
	var tests []string
	pytest := false
	for _, file := range files {
		base := path.Base(file)
		if isPythonTest(file) {
			tests = append(tests, file)
		}
		switch {
		case base == "conftest.py" || file == "pytest.ini":
			pytest = true
		case file == "pyproject.toml" && strings.Contains(string(read(file)), "[tool.pytest"),
			file == "setup.cfg" && strings.Contains(string(read(file)), "[tool:pytest]"),
			file == "tox.ini" && strings.Contains(string(read(file)), "[pytest]"):
			pytest = true
		}
	}
	if len(tests) == 0 || !touches(scope, ".py", "pyproject.toml", "setup.cfg", "pytest.ini", "tox.ini") {
		return nil
	}
	if !pytest {
		return []Check{{Name: "python -m unittest", Stack: "python", Tool: "python", Dir: ".", Args: []string{"-m", "unittest", "discover", "-v", "-b"}, Format: FormatUnittest}}
	}
	args := []string{"-m", "pytest", "-p", "no:cacheprovider", "-q", "--junitxml=$TMPDIR/pytest-report.xml"}
	return []Check{{Name: "pytest", Stack: "python", Tool: "python", Dir: ".", Args: args, Format: FormatJUnit, Report: "pytest-report.xml"}}
}

func isPythonTest(file string) bool {
	base := path.Base(file)
	return strings.HasSuffix(base, ".py") && (strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py"))
}

func detectRust(files []string, used map[string]bool, scope Scope) []Check {
	if !slices.Contains(files, "Cargo.toml") || !touches(scope, ".rs", "Cargo.toml", "Cargo.lock", "clippy.toml") {
		return nil
	}
	checks := []Check{{Name: "cargo test", Stack: "rust", Tool: "cargo", Dir: ".", Args: []string{"test", "--offline"}, Format: FormatLibtest}}
	if used["clippy"] {
		checks = append(checks, Check{Name: "cargo clippy", Stack: "rust", Tool: "cargo", Dir: ".", Args: []string{"clippy", "--offline", "--message-format=short"}, Format: FormatDiagnostics})
	}
	return checks
}

// touches reports whether a changed or dependent file has one of the
// suffixes.
func touches(scope Scope, suffixes ...string) bool {
	for _, file := range scope.paths() {
		for _, suffix := range suffixes {
			if strings.HasSuffix(file, suffix) {
				return true
			}
		}
	}
	return false
}
