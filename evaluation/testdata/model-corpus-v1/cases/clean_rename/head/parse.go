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
	for index, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, err := splitPair(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", index+1, err)
		}
		settings[key] = value
	}
	return settings, nil
}

// ParseLine parses one key=value pair.
func ParseLine(line string) (string, string, error) {
	return splitPair(strings.TrimSpace(line))
}

func splitPair(line string) (string, string, error) {
	key, value, found := strings.Cut(line, "=")
	if !found {
		return "", "", fmt.Errorf("missing '=' in %q", line)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return "", "", fmt.Errorf("empty key in %q", line)
	}
	return key, strings.TrimSpace(value), nil
}
