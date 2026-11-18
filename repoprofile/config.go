package repoprofile

import (
	"path"
	"regexp"
	"strings"
)

var (
	strictTrue = regexp.MustCompile(`"strict"\s*:\s*true`)
	wordsOnly  = regexp.MustCompile(`[a-z0-9]+`)
)

// config records the facts of a linter, formatter or type-checker
// configuration file. They are information: a configuration enforces nothing
// until a CI command runs the tool.
func (s *scanner) config(p, text string) {
	add := func(tool string) { s.add(SourceConfig, p, tool, false) }
	base := path.Base(p)
	switch {
	case base == "tsconfig.json":
		if strictTrue.MatchString(text) {
			add("tsc")
		}
	case base == "pyproject.toml":
		pyproject(text, add)
	default:
		add(configTool(base))
		if strings.HasPrefix(base, ".golangci.") {
			for _, linter := range enabledLinters(text) {
				add("golangci-lint:" + linter)
			}
		}
	}
}

func configTool(base string) string {
	for prefix, tool := range configTools {
		if strings.HasPrefix(base, prefix) {
			return tool
		}
	}
	return ""
}

// pyproject reads only the tool tables of a pyproject.toml, never its
// dependency lists.
func pyproject(text string, add func(tool string)) {
	table := ""
	scanLines(text, func(line string) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			table = strings.Trim(line, "[] ")
			for prefix, tool := range pyprojectTables {
				if table == prefix || strings.HasPrefix(table, prefix+".") {
					add(tool)
				}
			}
			return
		}
		key, _, _ := strings.Cut(line, "=")
		switch key = strings.TrimSpace(key); {
		case key == "fail_under" && strings.HasPrefix(table, "tool.coverage"):
			add("coverage-py")
		case key == "addopts" && strings.HasPrefix(table, "tool.pytest") && strings.Contains(line, "--cov-fail-under"):
			add("pytest-cov")
		}
	})
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
