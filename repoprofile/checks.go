package repoprofile

import (
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	// MaxFileBytes bounds a configuration file that is read; a larger one is
	// ignored.
	MaxFileBytes = 256 << 10
	maxLines     = 5000
	maxLineBytes = 1000
)

// Check is one thing the repository's own configuration enforces.
type Check struct {
	Class  string `json:"class"`  // one of the Class constants
	Tool   string `json:"tool"`   // a tool of the closed table
	Source string `json:"source"` // one of the Source constants
	Path   string `json:"path"`   // the file it was read from (repository text)
}

var (
	hookID     = regexp.MustCompile(`^\s*-?\s*id:\s*([\w.-]+)`)
	strictTrue = regexp.MustCompile(`"strict"\s*:\s*true`)
	wordsOnly  = regexp.MustCompile(`[a-z0-9]+`)
)

// detectChecks reads the configuration files and returns their checks,
// sorted by class, tool, source and path.
func detectChecks(contents map[string][]byte) []Check {
	found := map[Check]bool{}
	paths := make([]string, 0, len(contents))
	for p := range contents {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	paths = paths[:min(len(paths), maxConfigPaths)]
	for _, p := range paths {
		source := sourceOf(p)
		data := contents[p]
		if source == "" || len(data) > MaxFileBytes || bytes.IndexByte(data, 0) >= 0 {
			continue
		}
		add := func(source, tool string) {
			if class, ok := toolClass[tool]; ok {
				found[Check{Class: class, Tool: tool, Source: source, Path: p}] = true
			}
		}
		scanFile(p, source, string(data), add)
	}
	checks := make([]Check, 0, len(found))
	for c := range found {
		checks = append(checks, c)
	}
	sort.Slice(checks, func(i, j int) bool {
		a, b := checks[i], checks[j]
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Path < b.Path
	})
	return checks
}

func scanFile(p, source, text string, add func(source, tool string)) {
	base := path.Base(p)
	switch {
	case source == SourceConfig && base == "tsconfig.json":
		if strictTrue.MatchString(text) {
			add(SourceConfig, "tsc")
		}
	case source == SourceConfig:
		add(SourceConfig, configTool(base))
		if strings.HasPrefix(base, ".golangci.") {
			for _, linter := range enabledLinters(text) {
				add(SourceConfig, "golangci-lint:"+linter)
			}
		}
	case base == "package.json":
		var manifest struct {
			Scripts map[string]string `json:"scripts"`
		}
		if json.Unmarshal([]byte(text), &manifest) == nil {
			for _, script := range manifest.Scripts {
				scanCommands(script, source, add)
			}
		}
	default:
		scanCommands(text, source, add)
		scanLines(text, func(line string) {
			if source == SourcePreCommit {
				if m := hookID.FindStringSubmatch(line); m != nil {
					add(source, hookTools[m[1]])
				}
			}
			if base == "pyproject.toml" {
				scanPyproject(line, add)
			}
		})
	}
}

func scanPyproject(line string, add func(source, tool string)) {
	line = strings.TrimSpace(line)
	for prefix, tool := range pyprojectSections {
		if strings.HasPrefix(line, prefix) {
			add(SourceConfig, tool)
		}
	}
	if strings.HasPrefix(line, "fail_under") {
		add(SourceConfig, "coverage-py")
	}
}

// scanLines calls visit with each line of text, up to the bounds.
func scanLines(text string, visit func(line string)) {
	for n := 0; n < maxLines && text != ""; n++ {
		line, rest, _ := strings.Cut(text, "\n")
		text = rest
		visit(line[:min(len(line), maxLineBytes)])
	}
}

// scanCommands finds the commands of text, a shell script, task runner or
// workflow, and adds the tools they run.
func scanCommands(text, source string, add func(source, tool string)) {
	scanLines(text, func(line string) {
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
		for _, skip := range []string{"#", "name:", "description:", "echo "} {
			if strings.HasPrefix(trimmed, skip) {
				return
			}
		}
		if i := strings.Index(trimmed, " #"); i >= 0 {
			trimmed = trimmed[:i]
		}
		for _, command := range splitCommands(trimmed) {
			if isInstall(command) {
				continue
			}
			for _, rule := range commandRules {
				if rule.matches(command) {
					add(source, rule.tool)
				}
			}
		}
	})
}

var commandBreaks = strings.NewReplacer("&", ";", "|", ";", "(", " ", ")", " ", "$", " ", "`", " ", `"`, " ", "'", " ")

// splitCommands returns the tokens of each command of a line.
func splitCommands(line string) [][]string {
	var commands [][]string
	for _, part := range strings.Split(commandBreaks.Replace(line), ";") {
		if tokens := strings.Fields(part); len(tokens) > 0 {
			commands = append(commands, tokens)
		}
	}
	return commands
}

var installers = map[string]bool{"npm": true, "yarn": true, "pnpm": true, "pip": true, "pip3": true, "pipx": true, "cargo": true, "go": true, "gem": true, "apt": true, "apt-get": true, "brew": true}

// isInstall reports whether a command installs a tool instead of running it.
func isInstall(tokens []string) bool {
	for len(tokens) > 1 && (tokens[0] == "sudo" || tokens[0] == "run:") {
		tokens = tokens[1:]
	}
	if len(tokens) < 2 || !installers[tokens[0]] {
		return false
	}
	return tokens[1] == "install" || tokens[1] == "add" || tokens[1] == "i"
}

func (r commandRule) matches(tokens []string) bool {
	next := 0
	for _, t := range tokens {
		if next < len(r.words) && wordMatches(t, r.words[next]) {
			next++
		}
	}
	if next < len(r.words) {
		return false
	}
	if len(r.flags) == 0 {
		return true
	}
	for _, t := range tokens {
		for _, flag := range r.flags {
			if t == flag || strings.HasPrefix(t, flag+"=") {
				return true
			}
		}
	}
	return false
}

func wordMatches(token, word string) bool {
	if strings.Contains(word, "/") {
		return token == word || strings.HasPrefix(token, word+"/") || strings.HasPrefix(token, word+"@")
	}
	if i := strings.LastIndexByte(token, '/'); i >= 0 {
		token = token[i+1:]
	}
	return token == word || token == word+"w" && (word == "mvn" || word == "gradle")
}

// enabledLinters returns the linter names listed under an "enable" key of a
// golangci-lint configuration, YAML or TOML.
func enabledLinters(text string) []string {
	var linters []string
	enabled := false
	scanLines(text, func(line string) {
		trimmed := strings.TrimSpace(line)
		if key, rest, ok := strings.Cut(trimmed, ":"); ok && !strings.HasPrefix(trimmed, "-") && !strings.ContainsAny(key, " \t\"") {
			enabled, trimmed = key == "enable", rest
		} else if key, rest, ok := strings.Cut(trimmed, "="); ok && !strings.ContainsAny(strings.TrimSpace(key), " \t\"") {
			enabled, trimmed = strings.TrimSpace(key) == "enable", rest
		}
		if enabled {
			for _, word := range wordsOnly.FindAllString(strings.ToLower(trimmed), -1) {
				if _, ok := toolClass["golangci-lint:"+word]; ok {
					linters = append(linters, word)
				}
			}
		}
	})
	return linters
}
