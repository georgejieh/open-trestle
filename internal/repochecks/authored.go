package repochecks

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/checksandbox"
)

// Model-written checks are test files a verifier wrote for its verified
// findings. Each runs alone, twice on base and twice on head, in the same
// sandbox as the repository's checks, and is kept only when it shows a
// regression.

// Kept statuses of a model-written check.
const (
	// AuthoredRegression passed in both base runs and failed in both head runs.
	AuthoredRegression = "regression"
	// AuthoredFailsOnHead did not build on base and failed in both head runs.
	AuthoredFailsOnHead = "fails_on_head"
)

// AuthoredBudget bounds all model-written checks of one review.
const AuthoredBudget = 5 * time.Minute

const maxAuthoredBytes = 12 << 10

// testFrameworks names the test framework of each format whose tests a
// model-written check can add to.
var testFrameworks = map[Format]string{FormatGoJSON: "go_test", FormatJUnit: "pytest", FormatUnittest: "unittest"}

// Authored is one model-written test file: its framework, the
// slash-separated folder of the finding it demonstrates, and its text.
type Authored struct {
	Framework, Dir, Content string
}

// AuthoredResult is one model-written check's outcome. Status is
// AuthoredRegression, AuthoredFailsOnHead, or "" when the check was
// discarded, with Reason saying why. Tests are the test IDs that failed on
// head.
type AuthoredResult struct {
	Status, Path, Reason string
	Tests                []string
}

// AuthoredInput is the checks of one review and the trees to run them on.
// The trees are written to: each check adds its own file to both.
type AuthoredInput struct {
	BaseTree, HeadTree string
	Checks             []Authored
	Limits             checksandbox.Limits
	Budget             time.Duration
	Runner             Runner
}

// AuthoredReport holds one result per check, in order, and the scratch
// folders that runs could not remove.
type AuthoredReport struct {
	Results   []AuthoredResult
	Leftovers []string
}

// RunAuthored validates, writes and runs each model-written check.
func RunAuthored(ctx context.Context, input AuthoredInput) AuthoredReport {
	return runAuthoredWith(ctx, input, realHost())
}

func runAuthoredWith(ctx context.Context, input AuthoredInput, machine host) AuthoredReport {
	if input.Runner == nil {
		input.Runner = checksandbox.Run
	}
	if input.Budget <= 0 {
		input.Budget = AuthoredBudget
	}
	ctx, cancel := context.WithTimeout(ctx, input.Budget)
	defer cancel()
	report := AuthoredReport{}
	run := collectLeftovers(input.Runner, &report.Leftovers)
	trees := newTrees(input.BaseTree, input.HeadTree)
	seeds := &goSeeds{homes: map[string]string{}}
	defer seeds.close()
	for index, authored := range input.Checks {
		result := AuthoredResult{}
		check, name, err := authoredCheck(trees.head, index+1, authored)
		if err == nil {
			result.Path = name
			err = errors.Join(writeAuthored(trees.base, name, authored.Content), writeAuthored(trees.head, name, authored.Content))
		}
		if err != nil {
			result.Reason = err.Error()
			report.Results = append(report.Results, result)
			continue
		}
		spec, reason := sandboxSpec(ctx, machine, input.Limits, check, trees, seeds)
		if reason != "" {
			result.Reason = reason
			report.Results = append(report.Results, result)
			continue
		}
		base, _, baseProblem := runSide(ctx, run, spec, check, trees, trees.base)
		head, _, headProblem := runSide(ctx, run, spec, check, trees, trees.head)
		if result.Status, result.Tests = classifyAuthored(base, head, baseProblem, headProblem); result.Status == "" {
			result.Reason = "it did not show a regression"
		}
		report.Results = append(report.Results, result)
	}
	return report
}

// classifyAuthored keeps a check whose head runs both failed the same tests:
// a regression when every result passed in both base runs, and fails on
// head when base could not build it. Anything else, flaky runs included,
// is discarded.
func classifyAuthored(base, head [2]map[string]Outcome, baseProblem, headProblem *problem) (string, []string) {
	if headProblem != nil {
		return "", nil
	}
	after, flaky := stable(head)
	var failed []string
	for id, outcome := range after {
		if outcome == Fail && !strings.HasSuffix(id, exitStatusSuffix) {
			failed = append(failed, id)
		}
	}
	slices.Sort(failed)
	if len(flaky) > 0 || len(failed) == 0 {
		return "", nil
	}
	if baseProblem != nil {
		if baseProblem.noResults {
			return AuthoredFailsOnHead, failed
		}
		return "", nil
	}
	before, flaky := stable(base)
	if len(flaky) > 0 || len(before) == 0 {
		return "", nil
	}
	passed, built := true, false
	for id, outcome := range before {
		passed = passed && outcome == Pass
		built = built || outcome == Pass || after[id] != ""
	}
	switch {
	case passed && !slices.ContainsFunc(failed, func(id string) bool { return before[id] != Pass }):
		return AuthoredRegression, failed
	case !built:
		// Base reported only failures of its own, such as a package that
		// does not build.
		return AuthoredFailsOnHead, failed
	}
	return "", nil
}

// authoredCheck validates a check and returns the command that runs only
// its tests and the path the host picked for it, the n-th of the review.
func authoredCheck(head string, n int, authored Authored) (Check, string, error) {
	dir := path.Clean(authored.Dir)
	if !filepath.IsLocal(filepath.FromSlash(dir)) && dir != "." || len(authored.Content) > maxAuthoredBytes || !utf8.ValidString(authored.Content) || strings.ContainsRune(authored.Content, 0) {
		return Check{}, "", errors.New("it is too large, not UTF-8 text, or outside the tree")
	}
	switch authored.Framework {
	case "go_test":
		name := path.Join(dir, fmt.Sprintf("trestle_check_%d_test.go", n))
		module, found := goModuleFolder(head, dir)
		if !found {
			return Check{}, "", errors.New("its folder is in no Go module")
		}
		tests, err := validateGoCheck(authored.Content, goPackageName(filepath.Join(head, filepath.FromSlash(dir))))
		if err != nil {
			return Check{}, "", err
		}
		pattern := packagePattern(module, dir)
		args := []string{"test", "-json", "-count=1", "-run", "^(" + strings.Join(tests, "|") + ")$"}
		vendored := isFile(filepath.Join(head, filepath.FromSlash(module), "vendor", "modules.txt"))
		return Check{Name: "go test " + pattern, Stack: "go", Tool: "go", Dir: module, Args: args, Packages: []string{pattern}, Vendored: vendored, Format: FormatGoJSON}, name, nil
	case "pytest", "unittest":
		name := path.Join(dir, fmt.Sprintf("test_trestle_check_%d.py", n))
		if word := deniedPython.FindString(authored.Content); word != "" {
			return Check{}, "", fmt.Errorf("it uses %s", word)
		}
		if authored.Framework == "unittest" {
			return Check{Name: "python -m unittest " + name, Stack: "python", Tool: "python", Dir: ".", Args: []string{"-m", "unittest", "discover", "-v", "-b", "-s", dir, "-p", path.Base(name)}, Format: FormatUnittest}, name, nil
		}
		args := []string{"-m", "pytest", "-p", "no:cacheprovider", "-q", "--junitxml=$TMPDIR/pytest-report.xml", "./" + name}
		return Check{Name: "pytest " + name, Stack: "python", Tool: "python", Dir: ".", Args: args, Format: FormatJUnit, Report: "pytest-report.xml"}, name, nil
	}
	return Check{}, "", errors.New("its framework is not one whose tests ran")
}

// The sandbox already keeps a check from the network and the host; these
// lists keep it honest instead. A test that reads the source tree, starts
// processes or writes its own output could report a regression it did not
// show, so a check that reaches for those is refused before it runs.
var (
	deniedGoImports      = []string{"os", "os/exec", "io/ioutil", "io/fs", "path/filepath", "text/template", "html/template", "embed", "unsafe", "plugin", "C"}
	deniedGoImportTrees  = []string{"go", "runtime", "syscall", "net", "debug"}
	deniedGoDirectives   = []string{"//go:build", "// +build", "//go:embed", "//go:linkname"}
	deniedGoFunctions    = []string{"init", "TestMain"}
	deniedPython         = regexp.MustCompile(`\b(open|__file__|__import__|inspect|subprocess|os|socket|importlib|pathlib|pytest_plugins|conftest)\b`)
	errGoCheckUnreadable = errors.New("it does not parse as Go")
)

// validateGoCheck checks a Go test file against the folder's package name
// and returns its test functions.
func validateGoCheck(content, pkg string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "check_test.go", content, parser.ParseComments)
	if err != nil {
		return nil, errGoCheckUnreadable
	}
	if pkg == "" || file.Name.Name != pkg && file.Name.Name != pkg+"_test" {
		return nil, errors.New("its package is not the folder's")
	}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			if slices.ContainsFunc(deniedGoDirectives, func(directive string) bool { return strings.HasPrefix(comment.Text, directive) }) {
				return nil, errors.New("it has a build constraint or a go:embed or go:linkname directive")
			}
		}
	}
	for _, spec := range file.Imports {
		imported, _ := strconv.Unquote(spec.Path.Value)
		if slices.Contains(deniedGoImports, imported) || slices.ContainsFunc(deniedGoImportTrees, func(tree string) bool { return imported == tree || strings.HasPrefix(imported, tree+"/") }) {
			return nil, fmt.Errorf("it imports %s", imported)
		}
	}
	var tests []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Recv != nil {
			continue
		}
		name := function.Name.Name
		if slices.Contains(deniedGoFunctions, name) {
			return nil, fmt.Errorf("it declares %s", name)
		}
		if rest, ok := strings.CutPrefix(name, "Test"); ok {
			if first, _ := utf8.DecodeRuneInString(rest); rest == "" || !unicode.IsLower(first) {
				tests = append(tests, name)
			}
		}
	}
	if len(tests) == 0 {
		return nil, errors.New("it has no test function")
	}
	return tests, nil
}

// goPackageName is the package of the non-test Go files in folder, or "".
func goPackageName(folder string) string {
	entries, err := os.ReadDir(folder)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		if file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(folder, entry.Name()), nil, parser.PackageClauseOnly); err == nil {
			return file.Name.Name
		}
	}
	return ""
}

// goModuleFolder is the nearest folder at or above dir in tree with a
// go.mod file.
func goModuleFolder(tree, dir string) (string, bool) {
	for folder := dir; ; folder = path.Dir(folder) {
		if isFile(filepath.Join(tree, filepath.FromSlash(folder), "go.mod")) {
			return folder, true
		}
		if folder == "." {
			return "", false
		}
	}
}

// writeAuthored creates the file name in tree, through an os.Root, and
// fails when it already exists.
func writeAuthored(tree, name, content string) error {
	root, err := os.OpenRoot(tree)
	if err != nil {
		return err
	}
	defer root.Close()
	local := filepath.FromSlash(name)
	if err := root.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		return err
	}
	file, err := root.OpenFile(local, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return errors.New("its file cannot be created in the tree")
	}
	_, err = file.WriteString(content)
	return errors.Join(err, file.Close())
}
