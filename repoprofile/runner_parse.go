package repoprofile

import (
	"encoding/json"
	"strings"
)

var makeVariables = strings.NewReplacer("$(MAKE)", "make", "${MAKE}", "make", "$$", "$")

// recipeLine returns a recipe line as a shell command: without the make and
// just prefixes @ and +, and empty for a "-" line, whose failure the tool
// ignores.
func recipeLine(line string) string {
	line = strings.TrimLeft(line, "@+ \t")
	if strings.HasPrefix(line, "-") {
		return ""
	}
	return makeVariables.Replace(line) + "\n"
}

func parseMakefile(path, text string) *runnerFile {
	f := newRunnerFile(path)
	var current []string
	scanLines(text, func(line string) {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "\t"):
			for _, name := range current {
				f.target(name).script += recipeLine(line)
			}
		case trimmed == "" || trimmed[0] == '#':
		default:
			current = nil
			names, deps, inline := makeRule(line)
			for _, name := range names {
				t := f.target(name)
				t.deps = append(t.deps, deps...)
				t.script += recipeLine(inline)
			}
			current = names
			if len(f.defaults) == 0 && len(names) > 0 {
				f.defaults = names[:1]
			}
		}
	})
	return f
}

// makeRule splits a Makefile rule line into its targets, prerequisites and
// inline recipe. It returns no targets for assignments, special targets and
// pattern rules.
func makeRule(line string) (names, deps []string, inline string) {
	head, rest, ok := strings.Cut(line, ":")
	if !ok || strings.ContainsAny(head, "=$%") || strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, ":=") {
		return nil, nil, ""
	}
	names = strings.Fields(head)
	if len(names) == 0 || names[0][0] == '.' {
		return nil, nil, ""
	}
	rest = strings.TrimPrefix(rest, ":")
	rest, inline, _ = strings.Cut(rest, ";")
	rest, _, _ = strings.Cut(rest, "#")
	for _, dep := range strings.Fields(rest) {
		if dep != "|" && !strings.ContainsAny(dep, "=$%") {
			deps = append(deps, dep)
		}
	}
	return names, deps, strings.TrimSpace(inline)
}

func parseJustfile(path, text string) *runnerFile {
	f := newRunnerFile(path)
	var current *target
	scanLines(text, func(line string) {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "" || trimmed[0] == '#':
		case line[0] == ' ' || line[0] == '\t':
			if current != nil {
				current.script += recipeLine(trimmed)
			}
		default:
			current = nil
			head, rest, ok := strings.Cut(trimmed, ":")
			names := strings.Fields(head)
			if !ok || len(names) == 0 || strings.HasPrefix(rest, "=") {
				return
			}
			name := strings.TrimLeft(names[0], "@")
			current = f.target(name)
			rest, _, _ = strings.Cut(rest, "#")
			for _, dep := range strings.Fields(rest) {
				if dep != "&&" && !strings.ContainsAny(dep, "()") {
					current.deps = append(current.deps, dep)
				}
			}
			if len(f.defaults) == 0 {
				f.defaults = []string{name}
			}
		}
	})
	return f
}

func parseTaskfile(path, text string) *runnerFile {
	f := newRunnerFile(path)
	f.defaults = []string{"default"}
	tasks := parseYAML(text).get("tasks")
	if tasks == nil || tasks.kind != yamlMapping {
		return f
	}
	for i, name := range tasks.keys {
		t := f.target(name)
		switch def := tasks.items[i]; def.kind {
		case yamlScalar:
			t.script = def.value
		case yamlSequence:
			t.addCommands(def.items)
		case yamlMapping:
			t.addCommands(def.get("cmds").seq())
			for _, dep := range def.get("deps").seq() {
				t.deps = append(t.deps, taskName(dep))
			}
		}
	}
	return f
}

// addCommands adds the commands of a Taskfile cmds list: command strings,
// "cmd" entries and "task" entries that run another task.
func (t *target) addCommands(items []*yamlNode) {
	for _, item := range items {
		switch {
		case item.str() != "":
			t.script += item.str() + "\n"
		case item.get("cmd") != nil:
			t.script += item.get("cmd").str() + "\n"
		case item.get("task") != nil:
			t.deps = append(t.deps, item.get("task").str())
		}
	}
}

func taskName(dep *yamlNode) string {
	if name := dep.str(); name != "" {
		return name
	}
	return dep.get("task").str()
}

func parsePackageJSON(path, text string) *runnerFile {
	f := newRunnerFile(path)
	var manifest struct {
		Scripts map[string]any `json:"scripts"`
	}
	if json.Unmarshal([]byte(text), &manifest) == nil {
		for name, script := range manifest.Scripts {
			if command, ok := script.(string); ok {
				f.target(name).script = command
			}
		}
	}
	return f
}

// parseTox reads the commands of each tox environment. An environment
// without commands of its own runs those of [testenv].
func parseTox(path, text string) *runnerFile {
	f := newRunnerFile(path)
	sections := parseINI(text)
	base := toxCommands(sections["testenv"], nil)
	f.target("testenv").script = base
	for name, section := range sections {
		if env, ok := strings.CutPrefix(name, "testenv:"); ok {
			f.target(env).script = toxCommands(section, &base)
		}
	}
	f.defaults = splitList(sections["tox"]["envlist"])
	if len(f.defaults) == 0 {
		f.defaults = []string{"testenv"}
	}
	return f
}

var toxVariables = strings.NewReplacer("{envpython}", "python", "{envbindir}/", "", "{posargs}", "")

func toxCommands(section map[string]string, fallback *string) string {
	if _, ok := section["commands"]; !ok && fallback != nil {
		return *fallback
	}
	var script strings.Builder
	for _, key := range []string{"commands_pre", "commands", "commands_post"} {
		for _, line := range strings.Split(section[key], "\n") {
			line = strings.TrimLeft(strings.TrimSpace(line), "!")
			if line != "" && !strings.HasPrefix(line, "-") {
				script.WriteString(toxVariables.Replace(line) + "\n")
			}
		}
	}
	return script.String()
}

// parseINI returns the keys of each section of an INI file; an indented
// line continues the value of the line before it.
func parseINI(text string) map[string]map[string]string {
	sections := map[string]map[string]string{}
	var section map[string]string
	key := ""
	scanLines(text, func(line string) {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "" || trimmed[0] == '#' || trimmed[0] == ';':
		case trimmed[0] == '[' && line[0] != ' ' && line[0] != '\t':
			name := strings.Trim(trimmed, "[] ")
			if sections[name] == nil {
				sections[name] = map[string]string{}
			}
			section, key = sections[name], ""
		case section == nil:
		case (line[0] == ' ' || line[0] == '\t') && key != "":
			section[key] += "\n" + trimmed
		default:
			name, value, ok := strings.Cut(trimmed, "=")
			if ok {
				key = strings.TrimSpace(name)
				section[key] = strings.TrimSpace(value)
			}
		}
	})
	return sections
}

// parseNoxfile reads the session names of a noxfile. A nox session is
// matched by its name only: a session named for a tool runs that tool.
func parseNoxfile(path, text string) *runnerFile {
	f := newRunnerFile(path)
	scanLines(text, func(line string) {
		if def, ok := strings.CutPrefix(line, "def "); ok {
			if name, params, ok := strings.Cut(def, "("); ok && strings.HasPrefix(params, "session") {
				f.target(name).script = name
				f.defaults = append(f.defaults, name)
			}
		}
	})
	return f
}
