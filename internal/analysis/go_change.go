package analysis

import (
	"fmt"
	"path"
	"sort"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// ResolveGoChangeSymbols resolves changed Symbols across every Go file in a Change.
func ResolveGoChangeSymbols(change evidence.Change, headContents map[string][]byte) ([]Symbol, error) {
	if change.Identity() == "" {
		return nil, fmt.Errorf("change is required")
	}
	fileChanges := change.FileChanges()
	goFiles := make([]evidence.FileChange, 0, len(fileChanges))
	expectedPaths := make(map[string]struct{}, len(fileChanges))
	for _, fileChange := range fileChanges {
		if path.Ext(fileChange.Path()) != ".go" {
			continue
		}
		goFiles = append(goFiles, fileChange)
		expectedPaths[fileChange.Path()] = struct{}{}
	}

	providedPaths := make([]string, 0, len(headContents))
	for providedPath := range headContents {
		providedPaths = append(providedPaths, providedPath)
	}
	sort.Strings(providedPaths)
	for _, providedPath := range providedPaths {
		if _, ok := expectedPaths[providedPath]; !ok {
			return nil, fmt.Errorf("unexpected head content path %q", providedPath)
		}
	}
	for _, fileChange := range goFiles {
		if _, ok := headContents[fileChange.Path()]; !ok {
			return nil, fmt.Errorf("missing Go content for %q", fileChange.Path())
		}
	}

	symbols := make([]Symbol, 0)
	for _, fileChange := range goFiles {
		resolved, err := ResolveGoChangedSymbols(change, fileChange.Path(), headContents[fileChange.Path()])
		if err != nil {
			return nil, fmt.Errorf("resolve changed Go symbols for %q: %w", fileChange.Path(), err)
		}
		symbols = append(symbols, resolved...)
	}
	return symbols, nil
}
