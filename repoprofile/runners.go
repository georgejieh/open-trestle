package repoprofile

import (
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// runnerFile is a task-runner file: the named targets a command can run.
type runnerFile struct {
	path     string
	targets  map[string]*target
	defaults []string // what running the tool without a target runs
}

type target struct {
	script string   // the shell commands of the target
	deps   []string // targets of the same file that run with it
}

func newRunnerFile(path string) *runnerFile {
	return &runnerFile{path: path, targets: map[string]*target{}}
}

func (f *runnerFile) target(name string) *target {
	t := f.targets[name]
	if t == nil {
		t = &target{}
		f.targets[name] = t
	}
	return t
}

// parseRunner reads a task-runner file, or returns nil for a file that
// holds no targets.
func parseRunner(p, base, text string) *runnerFile {
	switch base {
	case "Makefile", "makefile", "GNUmakefile":
		return parseMakefile(p, text)
	case "justfile", "Justfile":
		return parseJustfile(p, text)
	case "Taskfile.yml", "Taskfile.yaml":
		return parseTaskfile(p, text)
	case "package.json":
		return parsePackageJSON(p, text)
	case "tox.ini":
		return parseTox(p, text)
	case "noxfile.py":
		return parseNoxfile(p, text)
	}
	return nil
}

// runnerInformation records the tools of every target of a runner file as
// information.
func (s *scanner) runnerInformation(f *runnerFile) {
	names := make([]string, 0, len(f.targets))
	for name := range f.targets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s.script(f.targets[name].script, f.path, SourceTaskRunner, maxDepth, false)
	}
}

func (s *scanner) runner(names ...string) *runnerFile {
	for _, name := range names {
		if f := s.runners[name]; f != nil {
			return f
		}
	}
	return nil
}

// invoke follows a command that runs a task-runner target or the hooks of a
// pre-commit configuration, and records what they run as enforced.
func (s *scanner) invoke(words []string, depth int) {
	args := words[1:]
	switch tool := path.Base(words[0]); tool {
	case "make", "gmake":
		if names, ok := targetArgs(args, "-C", "--directory", "-f", "--file", "-I", "--include-dir"); ok {
			s.runNames(s.runner("Makefile", "makefile", "GNUmakefile"), names, depth)
		}
	case "just":
		if names, ok := targetArgs(args, "-f", "--justfile", "-d", "--working-directory"); ok {
			s.runNames(s.runner("justfile", "Justfile"), names, depth)
		}
	case "task":
		if names, ok := targetArgs(args, "-t", "--taskfile", "-d", "--dir"); ok {
			s.runNames(s.runner("Taskfile.yml", "Taskfile.yaml"), names, depth)
		}
	case "npm", "pnpm", "yarn", "bun":
		s.runNames(s.runner("package.json"), scriptNames(tool, args), depth)
	case "tox":
		s.runTox(args, depth)
	case "nox":
		s.runNames(s.runner("noxfile.py"), sessionArgs(args), depth)
	case "pre-commit":
		s.runPreCommit(args)
	}
}

func (s *scanner) runNames(f *runnerFile, names []string, depth int) {
	if f == nil {
		return
	}
	if len(names) == 0 {
		names = f.defaults
	}
	for _, name := range names {
		s.runTarget(f, name, depth)
	}
}

// runTarget records the commands of a target and of the targets it depends
// on, and follows the commands that run other targets.
func (s *scanner) runTarget(f *runnerFile, name string, depth int) {
	t := f.targets[name]
	key := f.path + "\x00" + name + "\x00" + strconv.Itoa(depth)
	if t == nil || s.seen[key] {
		return
	}
	s.seen[key] = true
	s.script(t.script, f.path, SourceTaskRunner, depth, true)
	for _, dep := range t.deps {
		s.runTarget(f, dep, depth)
	}
}

func (s *scanner) runTox(args []string, depth int) {
	f := s.runner("tox.ini")
	if f == nil {
		return
	}
	names := toxEnvs(args)
	if len(names) == 0 {
		names = f.defaults
	}
	for _, name := range names {
		if f.targets[name] == nil {
			name = "testenv"
		}
		s.runTarget(f, name, depth)
	}
}

// targetArgs returns the target names among the arguments of make, just or
// task. It reports false when a flag selects another file or directory.
func targetArgs(args []string, blocked ...string) ([]string, bool) {
	var names []string
	for _, a := range args {
		switch {
		case a == "--":
			return names, true
		case slices.ContainsFunc(blocked, func(b string) bool {
			return a == b || strings.HasPrefix(a, b+"=") || len(b) == 2 && strings.HasPrefix(a, b)
		}):
			return nil, false
		case strings.HasPrefix(a, "-") || strings.Contains(a, "="):
		default:
			if _, err := strconv.Atoi(a); err != nil {
				names = append(names, a)
			}
		}
	}
	return names, true
}

var packageManagerCommands = map[string]bool{"install": true, "i": true, "add": true, "remove": true, "exec": true, "dlx": true, "ci": true, "audit": true, "publish": true, "pack": true, "init": true, "link": true}

// scriptNames returns the package.json script that an npm, pnpm, yarn or bun
// command runs.
func scriptNames(manager string, args []string) []string {
	var words []string
	for _, a := range args {
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") {
			words = append(words, a)
		}
	}
	if i := slices.IndexFunc(words, func(w string) bool { return w == "run" || w == "run-script" }); i >= 0 {
		return words[i+1 : min(len(words), i+2)]
	}
	switch {
	case len(words) == 0 || manager == "bun":
		return nil
	case manager == "npm" && (words[0] == "test" || words[0] == "t" || words[0] == "tst"):
		return []string{"test"}
	case manager == "npm" || packageManagerCommands[words[0]]:
		return nil
	}
	return words[:1]
}

// toxEnvs returns the environments of a tox command's -e option.
func toxEnvs(args []string) []string {
	var list string
	for i, a := range args {
		switch {
		case (a == "-e" || a == "--env") && i+1 < len(args):
			list = args[i+1]
		case strings.HasPrefix(a, "--env="):
			list = a[len("--env="):]
		case strings.HasPrefix(a, "-e") && !strings.HasPrefix(a, "--"):
			list = strings.TrimPrefix(a[2:], "=")
		}
	}
	return splitList(list)
}

// sessionArgs returns the sessions of a nox command's -s option.
func sessionArgs(args []string) []string {
	var names []string
	selecting := false
	for _, a := range args {
		switch {
		case a == "-s" || a == "--session" || a == "--sessions":
			selecting = true
		case strings.HasPrefix(a, "--session=") || strings.HasPrefix(a, "--sessions="):
			_, list, _ := strings.Cut(a, "=")
			names = append(names, splitList(list)...)
		case strings.HasPrefix(a, "-"):
			selecting = false
		case selecting:
			names = append(names, a)
		}
	}
	return names
}

func splitList(list string) []string {
	return strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' })
}
