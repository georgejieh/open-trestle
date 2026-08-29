package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

const maxRepositoryManifestDeltaFiles = maxRepositoryManifestFiles * 2

// RepositoryFileDeltaKind identifies a path-level manifest difference.
type RepositoryFileDeltaKind string

const (
	RepositoryFileDeltaAdded    RepositoryFileDeltaKind = "added"
	RepositoryFileDeltaModified RepositoryFileDeltaKind = "modified"
	RepositoryFileDeltaRemoved  RepositoryFileDeltaKind = "removed"
)

// RepositoryFileDelta records one exact path difference without inferring a rename.
type RepositoryFileDelta struct {
	identity string
	kind     RepositoryFileDeltaKind
	path     string
	baseFile RepositoryFile
	headFile RepositoryFile
}

// RepositoryManifestDelta records the canonical path differences between two manifests.
type RepositoryManifestDelta struct {
	identity             string
	baseManifestIdentity string
	headManifestIdentity string
	entries              []RepositoryFileDelta
	addedFileCount       int
	modifiedFileCount    int
	removedFileCount     int
	unchangedFileCount   int
}

// NewRepositoryManifestDelta compares two canonical manifests by path and file identity.
func NewRepositoryManifestDelta(base, head RepositoryManifest) (RepositoryManifestDelta, error) {
	canonicalBase, err := NewRepositoryManifest(base.Files())
	if err != nil || !repositoryManifestValuesEqual(base, canonicalBase) {
		return RepositoryManifestDelta{}, fmt.Errorf("base repository manifest is not canonical")
	}
	canonicalHead, err := NewRepositoryManifest(head.Files())
	if err != nil || !repositoryManifestValuesEqual(head, canonicalHead) {
		return RepositoryManifestDelta{}, fmt.Errorf("head repository manifest is not canonical")
	}
	baseFiles := canonicalBase.Files()
	headFiles := canonicalHead.Files()
	if len(baseFiles) > maxRepositoryManifestDeltaFiles-len(headFiles) {
		return RepositoryManifestDelta{}, fmt.Errorf("repository manifest delta exceeds %d files", maxRepositoryManifestDeltaFiles)
	}
	entries := make([]RepositoryFileDelta, 0, len(baseFiles)+len(headFiles))
	added, modified, removed, unchanged := 0, 0, 0, 0
	for baseIndex, headIndex := 0, 0; baseIndex < len(baseFiles) || headIndex < len(headFiles); {
		switch {
		case baseIndex == len(baseFiles):
			entry, err := newRepositoryFileDelta(RepositoryFileDeltaAdded, RepositoryFile{}, headFiles[headIndex])
			if err != nil {
				return RepositoryManifestDelta{}, err
			}
			entries = append(entries, entry)
			added++
			headIndex++
		case headIndex == len(headFiles):
			entry, err := newRepositoryFileDelta(RepositoryFileDeltaRemoved, baseFiles[baseIndex], RepositoryFile{})
			if err != nil {
				return RepositoryManifestDelta{}, err
			}
			entries = append(entries, entry)
			removed++
			baseIndex++
		case baseFiles[baseIndex].Path() < headFiles[headIndex].Path():
			entry, err := newRepositoryFileDelta(RepositoryFileDeltaRemoved, baseFiles[baseIndex], RepositoryFile{})
			if err != nil {
				return RepositoryManifestDelta{}, err
			}
			entries = append(entries, entry)
			removed++
			baseIndex++
		case headFiles[headIndex].Path() < baseFiles[baseIndex].Path():
			entry, err := newRepositoryFileDelta(RepositoryFileDeltaAdded, RepositoryFile{}, headFiles[headIndex])
			if err != nil {
				return RepositoryManifestDelta{}, err
			}
			entries = append(entries, entry)
			added++
			headIndex++
		default:
			if baseFiles[baseIndex] == headFiles[headIndex] {
				unchanged++
			} else {
				entry, err := newRepositoryFileDelta(RepositoryFileDeltaModified, baseFiles[baseIndex], headFiles[headIndex])
				if err != nil {
					return RepositoryManifestDelta{}, err
				}
				entries = append(entries, entry)
				modified++
			}
			baseIndex++
			headIndex++
		}
	}
	type entryWire struct {
		Path                        string                  `json:"path"`
		Kind                        RepositoryFileDeltaKind `json:"kind"`
		RepositoryFileDeltaIdentity string                  `json:"repository_file_delta_identity"`
	}
	preimage := struct {
		Contract             string      `json:"contract"`
		SchemaVersion        int         `json:"schema_version"`
		BaseManifestIdentity string      `json:"base_manifest_identity"`
		HeadManifestIdentity string      `json:"head_manifest_identity"`
		Entries              []entryWire `json:"entries"`
	}{
		Contract:             "open-trestle/repository-manifest-delta",
		SchemaVersion:        1,
		BaseManifestIdentity: canonicalBase.Identity(),
		HeadManifestIdentity: canonicalHead.Identity(),
		Entries:              make([]entryWire, len(entries)),
	}
	for i, entry := range entries {
		preimage.Entries[i] = entryWire{entry.Path(), entry.Kind(), entry.Identity()}
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RepositoryManifestDelta{}, fmt.Errorf("encode repository manifest delta identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return RepositoryManifestDelta{
		identity:             hex.EncodeToString(digest[:]),
		baseManifestIdentity: canonicalBase.Identity(),
		headManifestIdentity: canonicalHead.Identity(),
		entries:              entries,
		addedFileCount:       added,
		modifiedFileCount:    modified,
		removedFileCount:     removed,
		unchangedFileCount:   unchanged,
	}, nil
}

func newRepositoryFileDelta(kind RepositoryFileDeltaKind, base, head RepositoryFile) (RepositoryFileDelta, error) {
	var path string
	switch kind {
	case RepositoryFileDeltaAdded:
		canonicalHead, err := canonicalRepositoryFile(head)
		if err != nil || base != (RepositoryFile{}) {
			return RepositoryFileDelta{}, fmt.Errorf("added repository file delta is invalid")
		}
		head = canonicalHead
		path = head.Path()
	case RepositoryFileDeltaModified:
		canonicalBase, baseErr := canonicalRepositoryFile(base)
		canonicalHead, headErr := canonicalRepositoryFile(head)
		if baseErr != nil || headErr != nil || canonicalBase.Path() != canonicalHead.Path() || canonicalBase == canonicalHead {
			return RepositoryFileDelta{}, fmt.Errorf("modified repository file delta is invalid")
		}
		base, head = canonicalBase, canonicalHead
		path = base.Path()
	case RepositoryFileDeltaRemoved:
		canonicalBase, err := canonicalRepositoryFile(base)
		if err != nil || head != (RepositoryFile{}) {
			return RepositoryFileDelta{}, fmt.Errorf("removed repository file delta is invalid")
		}
		base = canonicalBase
		path = base.Path()
	default:
		return RepositoryFileDelta{}, fmt.Errorf("unsupported repository file delta kind %q", kind)
	}
	preimage := struct {
		Contract                   string                  `json:"contract"`
		SchemaVersion              int                     `json:"schema_version"`
		Kind                       RepositoryFileDeltaKind `json:"kind"`
		Path                       string                  `json:"path"`
		BaseRepositoryFileIdentity string                  `json:"base_repository_file_identity"`
		HeadRepositoryFileIdentity string                  `json:"head_repository_file_identity"`
	}{
		Contract:                   "open-trestle/repository-file-delta",
		SchemaVersion:              1,
		Kind:                       kind,
		Path:                       path,
		BaseRepositoryFileIdentity: base.Identity(),
		HeadRepositoryFileIdentity: head.Identity(),
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RepositoryFileDelta{}, fmt.Errorf("encode repository file delta identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return RepositoryFileDelta{
		identity: hex.EncodeToString(digest[:]),
		kind:     kind,
		path:     path,
		baseFile: base,
		headFile: head,
	}, nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (d RepositoryManifestDelta) Identity() string { return d.identity }

// BaseManifestIdentity returns the ordered base manifest identity.
func (d RepositoryManifestDelta) BaseManifestIdentity() string { return d.baseManifestIdentity }

// HeadManifestIdentity returns the ordered head manifest identity.
func (d RepositoryManifestDelta) HeadManifestIdentity() string { return d.headManifestIdentity }

// Entries returns changed paths in lexical order.
func (d RepositoryManifestDelta) Entries() []RepositoryFileDelta {
	return append([]RepositoryFileDelta(nil), d.entries...)
}

// Entry returns the delta for an exact path.
func (d RepositoryManifestDelta) Entry(path string) (RepositoryFileDelta, bool) {
	if validateSourcePath(path) != nil {
		return RepositoryFileDelta{}, false
	}
	index := sort.Search(len(d.entries), func(i int) bool { return d.entries[i].Path() >= path })
	if index == len(d.entries) || d.entries[index].Path() != path {
		return RepositoryFileDelta{}, false
	}
	return d.entries[index], true
}

// ChangedFileCount returns the number of added, modified, and removed paths.
func (d RepositoryManifestDelta) ChangedFileCount() int { return len(d.entries) }

// AddedFileCount returns the number of head-only paths.
func (d RepositoryManifestDelta) AddedFileCount() int { return d.addedFileCount }

// ModifiedFileCount returns the number of changed same-path files.
func (d RepositoryManifestDelta) ModifiedFileCount() int { return d.modifiedFileCount }

// RemovedFileCount returns the number of base-only paths.
func (d RepositoryManifestDelta) RemovedFileCount() int { return d.removedFileCount }

// UnchangedFileCount returns the number of identical same-path files.
func (d RepositoryManifestDelta) UnchangedFileCount() int { return d.unchangedFileCount }

// Identity returns the versioned canonical SHA-256 identity.
func (d RepositoryFileDelta) Identity() string { return d.identity }

// Kind returns the path-level change kind.
func (d RepositoryFileDelta) Kind() RepositoryFileDeltaKind { return d.kind }

// Path returns the exact workspace-relative path.
func (d RepositoryFileDelta) Path() string { return d.path }

// BaseFile returns the exact base metadata when present.
func (d RepositoryFileDelta) BaseFile() (RepositoryFile, bool) {
	return d.baseFile, d.baseFile.Identity() != ""
}

// HeadFile returns the exact head metadata when present.
func (d RepositoryFileDelta) HeadFile() (RepositoryFile, bool) {
	return d.headFile, d.headFile.Identity() != ""
}
