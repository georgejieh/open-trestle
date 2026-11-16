// Package kv parses key=value settings.
package kv

import (
	"fmt"
	"strings"
)

// Parse reads newline-separated key=value pairs. Blank lines and lines
// starting with # are ignored. A later key replaces an earlier one.
func Parse(text string) (map[string]string, error) {
	settings := make(map[string]string)
	for number, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, err := parseKV(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", number+1, err)
		}
		settings[k] = v
	}
	return settings, nil
}

// ParseLine parses one key=value pair.
func ParseLine(line string) (string, string, error) {
	return parseKV(strings.TrimSpace(line))
}

func parseKV(line string) (string, string, error) {
	k, v, found := strings.Cut(line, "=")
	if !found {
		return "", "", fmt.Errorf("missing '=' in %q", line)
	}
	k = strings.TrimSpace(k)
	if k == "" {
		return "", "", fmt.Errorf("empty key in %q", line)
	}
	return k, strings.TrimSpace(v), nil
}
