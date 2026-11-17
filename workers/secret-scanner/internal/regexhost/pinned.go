package regexhost

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
)

// pinnedPatternsJSON lists every pattern a scan with the pinned Betterleaks
// ruleset can compile: the patterns registered while the ruleset loads and
// the joined patterns of matchesAny and findMatch calls in its filter
// expressions. The guest module's tests regenerate it from the ruleset and
// fail when it differs.
//
//go:embed pinned-patterns.json
var pinnedPatternsJSON []byte

// PinnedPatternsSHA256 is the digest of pinned-patterns.json. A change to the
// table must change this value in the same commit.
const PinnedPatternsSHA256 = "608a0a519dbc8e536a122d9164daea5e73a5d26ffd896e397f08a3c0293b7b66"

// PinnedTable returns the table of the pinned ruleset after checking the
// embedded file against PinnedPatternsSHA256.
func PinnedTable() (*Table, error) {
	patterns, err := decodePinnedPatterns(pinnedPatternsJSON)
	if err != nil {
		return nil, err
	}
	return NewTable(patterns)
}

func decodePinnedPatterns(encoded []byte) ([]string, error) {
	digest := sha256.Sum256(encoded)
	if hex.EncodeToString(digest[:]) != PinnedPatternsSHA256 {
		return nil, errInvalidTable
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	var patterns []string
	if err := decoder.Decode(&patterns); err != nil {
		return nil, errInvalidTable
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errInvalidTable
	}
	if !sort.StringsAreSorted(patterns) {
		return nil, errInvalidTable
	}
	return patterns, nil
}
