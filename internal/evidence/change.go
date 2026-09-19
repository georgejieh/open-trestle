package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Bounds one repository change while allowing large reviewed change sets.
const maxChangeFiles = 1024

// Change is a canonical set of text-file change evidence.
type Change struct {
	identity    string
	fileChanges []FileChange
	lineMaps    []LineMap
}

type changePair struct {
	fileChange FileChange
	lineMap    LineMap
}

// NewChange creates a canonical multi-file change aggregate.
func NewChange(fileChanges []FileChange, lineMaps []LineMap) (Change, error) {
	if len(fileChanges) == 0 {
		return Change{}, fmt.Errorf("at least one file change is required")
	}
	if len(fileChanges) > maxChangeFiles {
		return Change{}, fmt.Errorf("change exceeds %d files", maxChangeFiles)
	}
	if len(fileChanges) != len(lineMaps) {
		return Change{}, fmt.Errorf("file change and line map counts must match")
	}

	filesByIdentity := make(map[string]FileChange, len(fileChanges))
	seenPaths := make(map[string]struct{}, len(fileChanges))
	for i, fileChange := range fileChanges {
		canonical, err := canonicalFileChange(fileChange)
		if err != nil {
			return Change{}, fmt.Errorf("file change %d: %w", i, err)
		}
		fileChange = canonical
		if _, exists := filesByIdentity[fileChange.Identity()]; exists {
			return Change{}, fmt.Errorf("duplicate file change identity at index %d", i)
		}
		if _, exists := seenPaths[fileChange.Path()]; exists {
			return Change{}, fmt.Errorf("duplicate file path %q", fileChange.Path())
		}
		filesByIdentity[fileChange.Identity()] = fileChange
		seenPaths[fileChange.Path()] = struct{}{}
	}

	pairs := make([]changePair, 0, len(lineMaps))
	seenMapIdentities := make(map[string]struct{}, len(lineMaps))
	pairedFiles := make(map[string]struct{}, len(lineMaps))
	for i, lineMap := range lineMaps {
		if lineMap.Identity() == "" {
			return Change{}, fmt.Errorf("line map %d is required", i)
		}
		if _, exists := seenMapIdentities[lineMap.Identity()]; exists {
			return Change{}, fmt.Errorf("duplicate line map identity at index %d", i)
		}
		fileChange, exists := filesByIdentity[lineMap.FileChangeIdentity()]
		if !exists {
			return Change{}, fmt.Errorf("line map %d has no matching file change", i)
		}
		if lineMap.Path() != fileChange.Path() {
			return Change{}, fmt.Errorf("line map %d path does not match its file change", i)
		}
		if _, exists := pairedFiles[fileChange.Identity()]; exists {
			return Change{}, fmt.Errorf("file change %q has multiple line maps", fileChange.Path())
		}
		canonical, err := NewLineMap(fileChange, lineMap.BaseLineCount(), lineMap.HeadLineCount(), lineMap.Hunks())
		if err != nil || canonical.Identity() != lineMap.Identity() {
			return Change{}, fmt.Errorf("line map %d is not canonical for its file change", i)
		}
		seenMapIdentities[lineMap.Identity()] = struct{}{}
		pairedFiles[fileChange.Identity()] = struct{}{}
		pairs = append(pairs, changePair{fileChange: fileChange, lineMap: canonical})
	}
	if len(pairedFiles) != len(fileChanges) {
		return Change{}, fmt.Errorf("every file change requires exactly one line map")
	}

	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].fileChange.Path() < pairs[j].fileChange.Path()
	})
	canonical := struct {
		Contract      string           `json:"contract"`
		SchemaVersion int              `json:"schema_version"`
		Files         []changeFileWire `json:"files"`
	}{
		Contract:      "open-trestle/change",
		SchemaVersion: 1,
		Files:         make([]changeFileWire, len(pairs)),
	}
	canonicalFiles := make([]FileChange, len(pairs))
	canonicalMaps := make([]LineMap, len(pairs))
	for i, pair := range pairs {
		canonical.Files[i] = changeFileWire{
			Path:               pair.fileChange.Path(),
			FileChangeIdentity: pair.fileChange.Identity(),
			LineMapIdentity:    pair.lineMap.Identity(),
		}
		canonicalFiles[i] = pair.fileChange
		canonicalMaps[i] = pair.lineMap
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return Change{}, fmt.Errorf("encode change identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return Change{
		identity:    hex.EncodeToString(digest[:]),
		fileChanges: canonicalFiles,
		lineMaps:    canonicalMaps,
	}, nil
}

type changeFileWire struct {
	Path               string `json:"path"`
	FileChangeIdentity string `json:"file_change_identity"`
	LineMapIdentity    string `json:"line_map_identity"`
}

func canonicalFileChange(fileChange FileChange) (FileChange, error) {
	if fileChange.Identity() == "" {
		return FileChange{}, fmt.Errorf("file change is required")
	}
	canonical, err := NewFileChange(fileChange.Path(), fileChange.BaseDigest(), fileChange.HeadDigest(), fileChange.ChangedRanges())
	if err != nil || canonical.Identity() != fileChange.Identity() {
		return FileChange{}, fmt.Errorf("file change is not canonical")
	}
	return canonical, nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (c Change) Identity() string {
	return c.identity
}

// FileChanges returns canonical file evidence in path order.
func (c Change) FileChanges() []FileChange {
	result := make([]FileChange, len(c.fileChanges))
	for i, fileChange := range c.fileChanges {
		result[i] = cloneFileChange(fileChange)
	}
	return result
}

// LineMaps returns canonical line maps in path order.
func (c Change) LineMaps() []LineMap {
	result := make([]LineMap, len(c.lineMaps))
	for i, lineMap := range c.lineMaps {
		result[i] = cloneLineMap(lineMap)
	}
	return result
}

// FileChangeForPath returns file evidence for an exact path.
func (c Change) FileChangeForPath(path string) (FileChange, bool) {
	index, ok := c.pathIndex(path)
	if !ok {
		return FileChange{}, false
	}
	return cloneFileChange(c.fileChanges[index]), true
}

// LineMapForPath returns the line map for an exact path.
func (c Change) LineMapForPath(path string) (LineMap, bool) {
	index, ok := c.pathIndex(path)
	if !ok {
		return LineMap{}, false
	}
	return cloneLineMap(c.lineMaps[index]), true
}

func cloneFileChange(fileChange FileChange) FileChange {
	fileChange.ranges = append([]SourceRange(nil), fileChange.ranges...)
	return fileChange
}

func cloneLineMap(lineMap LineMap) LineMap {
	lineMap.hunks = append([]Hunk(nil), lineMap.hunks...)
	return lineMap
}

func (c Change) pathIndex(path string) (int, bool) {
	if err := validateSourcePath(path); err != nil {
		return 0, false
	}
	index := sort.Search(len(c.fileChanges), func(i int) bool {
		return c.fileChanges[i].Path() >= path
	})
	return index, index < len(c.fileChanges) && c.fileChanges[index].Path() == path
}
