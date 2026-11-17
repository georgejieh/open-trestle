// Package pinnedpatterns derives the host's pinned pattern table from the
// pinned Betterleaks ruleset.
package pinnedpatterns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/regexp/filterpatterns"
)

// recorder sees every pattern Betterleaks creates. It embeds the standard
// library engine only to satisfy the interface; nothing is compiled.
type recorder struct {
	blregexp.Stdlib
	seen map[string]struct{}
}

func (r *recorder) RecordPattern(pattern string) { r.seen[pattern] = struct{}{} }

// Collect loads the default ruleset the way the scanner does and returns,
// sorted, every pattern it registers plus the joined filter patterns. It
// replaces the process's Betterleaks engine while it runs and restores the
// standard library engine afterwards.
func Collect() ([]string, error) {
	engine := &recorder{seen: map[string]struct{}{}}
	blregexp.SetEngine(engine)
	defer blregexp.SetEngine(blregexp.Stdlib{})

	cfg, err := config.Default()
	if err != nil {
		return nil, err
	}
	if detect.NewDetectorContext(context.Background(), cfg, detect.ValidationOptions{Enabled: false}) == nil {
		return nil, errors.New("detector construction failed")
	}
	filters, err := filterpatterns.Collect(cfg)
	if err != nil {
		return nil, err
	}
	for _, pattern := range filters {
		engine.seen[pattern] = struct{}{}
	}
	patterns := make([]string, 0, len(engine.seen))
	for pattern := range engine.seen {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	return patterns, nil
}

// Encode returns the canonical file form of the table: a JSON array with one
// pattern per line and a final newline.
func Encode(patterns []string) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(patterns); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
