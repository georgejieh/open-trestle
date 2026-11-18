package repoprofile

import (
	"bytes"
	"cmp"
	"path"
	"slices"
	"sort"
	"strings"
)

const (
	// MaxFileBytes bounds a configuration file that is read; a larger one is
	// ignored.
	MaxFileBytes = 256 << 10
	maxLines     = 5000
	maxLineBytes = 1000

	// maxCommands bounds the commands examined in one profile, and maxDepth
	// how far a CI command is followed into task runners: a CI step may run
	// a target that runs one more target.
	maxCommands = 20000
	maxDepth    = 2
)

// Check is one check the repository's own files describe.
type Check struct {
	Class    string `json:"class"`    // one of the Class constants
	Tool     string `json:"tool"`     // a tool of the closed table
	Source   string `json:"source"`   // one of the Source constants
	Path     string `json:"path"`     // the file it was read from (repository text)
	Enforced bool   `json:"enforced"` // a CI job runs it on pushes or pull requests
}

type file struct{ path, text string }

// scanner collects the checks of a repository's files. A check found in a
// command or action that CI runs on changes is enforced; every other check
// is recorded as information.
type scanner struct {
	found   map[Check]bool // the check without Enforced, and whether it is enforced
	runners map[string]*runnerFile
	hooks   []hook
	hookRef string // the file the hooks were read from
	seen    map[string]bool
	budget  int
}

// detectChecks reads the configuration files and returns their checks,
// sorted by class, tool, source and path.
func detectChecks(contents map[string][]byte) []Check {
	files := readable(contents)
	s := &scanner{found: map[Check]bool{}, runners: map[string]*runnerFile{}, seen: map[string]bool{}, budget: maxCommands}
	for _, f := range files {
		s.load(f)
	}
	for _, f := range files {
		s.scan(f)
	}
	checks := make([]Check, 0, len(s.found))
	for c, enforced := range s.found {
		c.Enforced = enforced
		checks = append(checks, c)
	}
	slices.SortFunc(checks, func(a, b Check) int {
		return cmp.Or(strings.Compare(a.Class, b.Class), strings.Compare(a.Tool, b.Tool), strings.Compare(a.Source, b.Source), strings.Compare(a.Path, b.Path))
	})
	return checks
}

// readable returns, in path order, the files that Detect reads and that are
// text within the size bound.
func readable(contents map[string][]byte) []file {
	paths := make([]string, 0, len(contents))
	for p := range contents {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	paths = paths[:min(len(paths), maxConfigPaths)]
	var files []file
	for _, p := range paths {
		data := contents[p]
		if sourceOf(p) != "" && len(data) <= MaxFileBytes && bytes.IndexByte(data, 0) < 0 {
			files = append(files, file{p, string(data)})
		}
	}
	return files
}

func (s *scanner) add(source, path, tool string, enforced bool) {
	class, ok := toolClass[tool]
	if !ok {
		return
	}
	key := Check{Class: class, Tool: tool, Source: source, Path: path}
	s.found[key] = s.found[key] || enforced
}

// load parses the files that CI commands can run.
func (s *scanner) load(f file) {
	base := path.Base(f.path)
	switch {
	case f.path == ".pre-commit-config.yaml":
		s.hooks, s.hookRef = parsePreCommit(f.text), f.path
	case sourceOf(f.path) == SourceTaskRunner:
		if r := parseRunner(f.path, base, f.text); r != nil {
			s.runners[f.path] = r
		}
	}
}

// scan records the checks of one file.
func (s *scanner) scan(f file) {
	switch source := sourceOf(f.path); {
	case source == SourceCI:
		s.workflow(f.path, f.text)
	case source == SourceCIOther:
		s.otherCI(f.path, f.text)
	case source == SourceConfig:
		s.config(f.path, f.text)
	case source == SourceTaskRunner:
		if r := s.runners[f.path]; r != nil {
			s.runnerInformation(r)
		}
	case f.path == ".pre-commit-config.yaml":
		for _, h := range s.hooks {
			s.addHook(h, false)
		}
	case path.Base(f.path) == "lefthook.yml":
		for _, run := range yamlRuns(parseYAML(f.text), 0) {
			s.script(run, f.path, SourcePreCommit, maxDepth, false)
		}
	default:
		s.script(f.text, f.path, SourcePreCommit, maxDepth, false)
	}
}

// script records the tools that the commands of a script run. Only when
// enforced, the task-runner targets and hooks its commands invoke are
// followed and recorded as enforced too.
func (s *scanner) script(script, path, source string, depth int, enforced bool) {
	for _, words := range shellCommands(script) {
		if s.budget--; s.budget < 0 {
			return
		}
		if words = commandWords(words); len(words) == 0 {
			continue
		}
		for _, tool := range commandTools(words) {
			s.add(source, path, tool, enforced)
		}
		if enforced && depth < maxDepth {
			s.invoke(words, depth+1)
		}
	}
}

// action records the tool of a GitHub Actions step.
func (s *scanner) action(uses, path string, enforced bool) {
	name, _, _ := strings.Cut(strings.ToLower(uses), "@")
	if name == "pre-commit/action" {
		if enforced {
			s.runPreCommit([]string{"run", "--all-files"})
		}
		return
	}
	for _, rule := range actionRules {
		if name == rule.prefix || strings.HasPrefix(name, rule.prefix+"/") {
			s.add(SourceCI, path, rule.tool, enforced)
		}
	}
}

var ciCommandKeys = []string{"run:", "script:", "command:", "bash:", "pwsh:", "powershell:", "sh ", "bat "}

// otherCI records the commands found in the file of a CI system other than
// GitHub Actions, as information.
func (s *scanner) otherCI(path, text string) {
	scanLines(text, func(line string) {
		line = strings.TrimSpace(line)
		for strings.HasPrefix(line, "- ") {
			line = strings.TrimSpace(line[2:])
		}
		for _, key := range ciCommandKeys {
			if rest, ok := strings.CutPrefix(line, key); ok {
				line = strings.Trim(strings.TrimSpace(rest), "\"'|>")
				break
			}
		}
		s.script(line, path, SourceCIOther, maxDepth, false)
	})
}

// scanLines calls visit with each line of text, up to the bounds.
func scanLines(text string, visit func(line string)) {
	for n := 0; n < maxLines && text != ""; n++ {
		line, rest, _ := strings.Cut(text, "\n")
		text = rest
		visit(line[:min(len(line), maxLineBytes)])
	}
}
