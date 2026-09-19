package scm

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// These limits mirror the accepted Git graph and acquisition contracts.
const (
	maxLocalGitRevisionDepth          = 128
	maxLocalGitRevisionEntries        = 65_536
	maxLocalGitRevisionUniqueTrees    = 65_536
	maxLocalGitRevisionUniqueBlobs    = 65_536
	maxLocalGitRevisionPathBytes      = 4 << 10
	maxLocalGitRevisionTotalPathBytes = 64 << 20
	maxLocalGitRevisionObjectBytes    = 256 << 20
	maxLocalGitRevisionResultBytes    = 256 << 20
	maxLocalGitTreeNameBytes          = 4 << 10
)

// LocalGitRevisionError identifies a stable revision-read failure category.
type LocalGitRevisionError string

const (
	LocalGitRevisionObjectUnavailable  LocalGitRevisionError = "object_unavailable"
	LocalGitRevisionUnsupportedSymlink LocalGitRevisionError = "unsupported_symlink"
	LocalGitRevisionUnsupportedGitlink LocalGitRevisionError = "unsupported_gitlink"
	LocalGitRevisionInvalidGraph       LocalGitRevisionError = "invalid_git_graph"
	LocalGitRevisionResourceLimit      LocalGitRevisionError = "resource_limit"
)

// Error returns the stable failure category.
func (e LocalGitRevisionError) Error() string {
	return string(e)
}

// LocalGitRevisionResult records a complete supported loose-object revision read.
type LocalGitRevisionResult struct {
	revisionIdentity       string
	repositoryIdentity     string
	manifest               evidence.RepositoryManifest
	contents               map[string][]byte
	gitCommitIdentity      string
	gitTreeGraphIdentity   string
	correspondenceIdentity string
	totalContentBytes      int64
}

type localGitEvidenceInputs struct {
	revision             evidence.RevisionIdentity
	commitVerification   evidence.GitCommitObjectVerification
	commitContent        []byte
	commit               evidence.GitCommit
	rootTreeVerification evidence.GitTreeObjectVerification
	rootTreeContent      []byte
	rootTree             evidence.GitTree
	childTreeContents    map[string][]byte
	blobContents         map[string][]byte
	graph                evidence.GitTreeGraph
	correspondence       evidence.GitManifestCorrespondence
}

// ReadLocalGitRevision constructs complete regular-file evidence from local Git objects.
// It does not establish root origin, ref reachability, or snapshot authority.
func ReadLocalGitRevision(ctx context.Context, store *LocalGitObjectStore, revision evidence.RevisionIdentity) (LocalGitRevisionResult, error) {
	if store == nil {
		return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
	}
	return store.readLocalGitRevision(ctx, revision, standardLocalGitRevisionLimits())
}

// RevisionIdentity returns the canonical requested revision identity.
func (r LocalGitRevisionResult) RevisionIdentity() string { return r.revisionIdentity }

// RepositoryIdentity returns the object store's repository scope label.
func (r LocalGitRevisionResult) RepositoryIdentity() string { return r.repositoryIdentity }

// Manifest returns the complete canonical regular-file manifest.
func (r LocalGitRevisionResult) Manifest() evidence.RepositoryManifest { return r.manifest }

// Contents returns independent copies of all path-addressed file bytes.
func (r LocalGitRevisionResult) Contents() map[string][]byte {
	return cloneLocalGitContents(r.contents)
}

// GitCommitIdentity returns the parsed verified commit identity.
func (r LocalGitRevisionResult) GitCommitIdentity() string { return r.gitCommitIdentity }

// GitTreeGraphIdentity returns the verified recursive graph identity.
func (r LocalGitRevisionResult) GitTreeGraphIdentity() string { return r.gitTreeGraphIdentity }

// CorrespondenceIdentity returns the exact graph-to-manifest correspondence identity.
func (r LocalGitRevisionResult) CorrespondenceIdentity() string { return r.correspondenceIdentity }

// FileCount returns the number of regular and executable files.
func (r LocalGitRevisionResult) FileCount() int { return r.manifest.FileCount() }

// TotalContentBytes returns the checked path-addressed content size.
func (r LocalGitRevisionResult) TotalContentBytes() int64 { return r.totalContentBytes }

type localGitObjectReader interface {
	RepositoryIdentity() string
	ReadCommit(context.Context, evidence.RevisionIdentity) ([]byte, error)
	ReadTree(context.Context, evidence.RevisionAlgorithm, string) ([]byte, error)
	ReadBlob(context.Context, evidence.RevisionAlgorithm, string) ([]byte, error)
}

type localGitRevisionLimits struct {
	maxDepth          int
	maxEntries        int
	maxUniqueTrees    int
	maxUniqueBlobs    int
	maxPathBytes      int
	maxTotalPathBytes int64
	maxObjectBytes    int64
	maxResultBytes    int64
	maxRetainedBytes  int64
}

func standardLocalGitRevisionLimits() localGitRevisionLimits {
	return localGitRevisionLimits{
		maxDepth:          maxLocalGitRevisionDepth,
		maxEntries:        maxLocalGitRevisionEntries,
		maxUniqueTrees:    maxLocalGitRevisionUniqueTrees,
		maxUniqueBlobs:    maxLocalGitRevisionUniqueBlobs,
		maxPathBytes:      maxLocalGitRevisionPathBytes,
		maxTotalPathBytes: maxLocalGitRevisionTotalPathBytes,
		maxObjectBytes:    maxLocalGitRevisionObjectBytes,
		maxResultBytes:    maxLocalGitRevisionResultBytes,
		maxRetainedBytes:  maxGitCommitPayloadBytes + maxLocalGitRevisionObjectBytes + maxLocalGitRevisionResultBytes,
	}
}

func (s *LocalGitObjectStore) readLocalGitRevision(ctx context.Context, revision evidence.RevisionIdentity, limits localGitRevisionLimits) (LocalGitRevisionResult, error) {
	var result LocalGitRevisionResult
	err := s.withScopedObjectReader(ctx, func(reader localGitObjectReader) error {
		var readErr error
		result, readErr = readLocalGitRevisionCapturing(ctx, reader, revision, limits, nil)
		return readErr
	})
	if err != nil {
		return LocalGitRevisionResult{}, err
	}
	return result, nil
}

func readLocalGitRevision(ctx context.Context, reader localGitObjectReader, revision evidence.RevisionIdentity, limits localGitRevisionLimits) (LocalGitRevisionResult, error) {
	if store, ok := reader.(*LocalGitObjectStore); ok {
		return store.readLocalGitRevision(ctx, revision, limits)
	}
	return readLocalGitRevisionCapturing(ctx, reader, revision, limits, nil)
}

// readLocalGitRevisionWithInputs takes ownership of successful reader payloads.
func readLocalGitRevisionWithInputs(ctx context.Context, reader localGitObjectReader, revision evidence.RevisionIdentity, limits localGitRevisionLimits) (LocalGitRevisionResult, localGitEvidenceInputs, error) {
	if store, ok := reader.(*LocalGitObjectStore); ok {
		if store.Profile() == LocalGitObjectStoreProfileLooseOnly {
			var inputs localGitEvidenceInputs
			result, err := readLocalGitRevisionCapturing(ctx, store, revision, limits, &inputs)
			if err != nil {
				return LocalGitRevisionResult{}, localGitEvidenceInputs{}, err
			}
			return result, inputs, nil
		}
		var result LocalGitRevisionResult
		var inputs localGitEvidenceInputs
		err := store.withScopedObjectReader(ctx, func(scoped localGitObjectReader) error {
			var readErr error
			result, inputs, readErr = readLocalGitRevisionWithInputs(ctx, scoped, revision, limits)
			return readErr
		})
		if err != nil {
			return LocalGitRevisionResult{}, localGitEvidenceInputs{}, err
		}
		return result, inputs, nil
	}
	var inputs localGitEvidenceInputs
	result, err := readLocalGitRevisionCapturing(ctx, reader, revision, limits, &inputs)
	if err != nil {
		return LocalGitRevisionResult{}, localGitEvidenceInputs{}, err
	}
	return result, inputs, nil
}

func readLocalGitRevisionCapturing(ctx context.Context, reader localGitObjectReader, revision evidence.RevisionIdentity, limits localGitRevisionLimits, inputs *localGitEvidenceInputs) (LocalGitRevisionResult, error) {
	if inputs != nil {
		*inputs = localGitEvidenceInputs{}
	}
	if isNilInterface(ctx) {
		return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
	}
	if err := ctx.Err(); err != nil {
		return LocalGitRevisionResult{}, err
	}
	if isNilInterface(reader) || !validLocalGitRevisionLimits(limits) {
		return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
	}
	canonicalRevision, err := evidence.NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	if err != nil || !revisionIdentityValuesEqual(revision, canonicalRevision) {
		return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
	}
	commitContent, err := reader.ReadCommit(ctx, canonicalRevision)
	if err != nil {
		return LocalGitRevisionResult{}, classifyLocalGitObjectRead(err)
	}
	if err := ctx.Err(); err != nil {
		return LocalGitRevisionResult{}, err
	}
	commitVerification, err := evidence.VerifyGitCommitObject(canonicalRevision, commitContent)
	if err != nil {
		return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
	}
	commit, err := evidence.ParseVerifiedGitCommit(canonicalRevision, commitVerification, commitContent)
	if err != nil || commit.TreeAlgorithm() != canonicalRevision.Algorithm() {
		return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
	}
	if err := ctx.Err(); err != nil {
		return LocalGitRevisionResult{}, err
	}
	rootTreeContent, err := reader.ReadTree(ctx, commit.TreeAlgorithm(), commit.TreeDigest())
	if err != nil {
		return LocalGitRevisionResult{}, classifyLocalGitObjectRead(err)
	}
	if err := ctx.Err(); err != nil {
		return LocalGitRevisionResult{}, err
	}
	rootTreeVerification, err := evidence.VerifyGitTreeObject(canonicalRevision, commitVerification, commitContent, commit, rootTreeContent)
	if err != nil {
		return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
	}
	rootTree, err := evidence.ParseVerifiedGitTree(canonicalRevision, commitVerification, commitContent, commit, rootTreeVerification, rootTreeContent)
	if err != nil {
		return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
	}
	if err := ctx.Err(); err != nil {
		return LocalGitRevisionResult{}, err
	}
	walker := localGitRevisionWalker{
		ctx:                    ctx,
		reader:                 reader,
		algorithm:              canonicalRevision.Algorithm(),
		limits:                 limits,
		trees:                  map[string][]localGitTreeEntry{rootTree.TreeDigest(): localEntriesFromVerifiedTree(rootTree)},
		childTreeContents:      make(map[string][]byte),
		blobContents:           make(map[string][]byte),
		activeTrees:            make(map[string]struct{}),
		seenPaths:              make(map[string]struct{}),
		retainedBaseBytes:      int64(len(commitContent)),
		transferObjectContents: inputs != nil,
	}
	if err := walker.addObjectBytes(len(rootTreeContent)); err != nil {
		return LocalGitRevisionResult{}, err
	}
	if err := walker.walkTree(rootTree.TreeDigest(), nil, 0); err != nil {
		return LocalGitRevisionResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return LocalGitRevisionResult{}, err
	}
	graph, err := evidence.VerifyGitTreeGraph(canonicalRevision, commitVerification, commitContent, commit, rootTreeVerification, rootTreeContent, rootTree, walker.childTreeContents, walker.blobContents)
	if err != nil {
		return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
	}
	if err := ctx.Err(); err != nil {
		return LocalGitRevisionResult{}, err
	}
	files := make([]evidence.RepositoryFile, 0, graph.UniqueBlobObjectCount())
	contents := make(map[string][]byte, graph.UniqueBlobObjectCount())
	var totalContentBytes int64
	for _, entry := range graph.Entries() {
		if err := ctx.Err(); err != nil {
			return LocalGitRevisionResult{}, err
		}
		switch entry.Mode() {
		case evidence.GitTreeModeDirectory:
			continue
		case evidence.GitTreeModeSymlink:
			return LocalGitRevisionResult{}, LocalGitRevisionUnsupportedSymlink
		case evidence.GitTreeModeGitlink:
			return LocalGitRevisionResult{}, LocalGitRevisionUnsupportedGitlink
		case evidence.GitTreeModeRegular, evidence.GitTreeModeExecutable:
		default:
			return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
		}
		pathBytes := entry.Path()
		if !utf8.Valid(pathBytes) {
			return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
		}
		path := string(pathBytes)
		content, exists := walker.blobContents[entry.ObjectDigest()]
		if !exists {
			return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
		}
		nextContentBytes, err := checkedLocalGitRevisionAdd(totalContentBytes, int64(len(content)), limits.maxResultBytes)
		if err != nil {
			return LocalGitRevisionResult{}, LocalGitRevisionResourceLimit
		}
		if err := walker.validateRetainedResultBytes(nextContentBytes); err != nil {
			return LocalGitRevisionResult{}, err
		}
		totalContentBytes = nextContentBytes
		file, err := evidence.NewRepositoryFile(path, content)
		if err != nil {
			return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
		}
		files = append(files, file)
		contents[path] = append([]byte{}, content...)
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	if err != nil || manifest.TotalSizeBytes() != totalContentBytes {
		return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
	}
	if err := ctx.Err(); err != nil {
		return LocalGitRevisionResult{}, err
	}
	correspondence, err := evidence.VerifyGitManifestCorrespondence(canonicalRevision, commitVerification, commitContent, commit, rootTreeVerification, rootTreeContent, rootTree, walker.childTreeContents, walker.blobContents, graph, manifest)
	if err != nil || correspondence.FileCount() != manifest.FileCount() || correspondence.TotalSizeBytes() != totalContentBytes {
		return LocalGitRevisionResult{}, LocalGitRevisionInvalidGraph
	}
	if err := ctx.Err(); err != nil {
		return LocalGitRevisionResult{}, err
	}
	if inputs != nil {
		*inputs = localGitEvidenceInputs{
			revision:             canonicalRevision,
			commitVerification:   commitVerification,
			commitContent:        commitContent,
			commit:               commit,
			rootTreeVerification: rootTreeVerification,
			rootTreeContent:      rootTreeContent,
			rootTree:             rootTree,
			childTreeContents:    walker.childTreeContents,
			blobContents:         walker.blobContents,
			graph:                graph,
			correspondence:       correspondence,
		}
	}
	return LocalGitRevisionResult{
		revisionIdentity:       canonicalRevision.Identity(),
		repositoryIdentity:     reader.RepositoryIdentity(),
		manifest:               manifest,
		contents:               contents,
		gitCommitIdentity:      commit.Identity(),
		gitTreeGraphIdentity:   graph.Identity(),
		correspondenceIdentity: correspondence.Identity(),
		totalContentBytes:      totalContentBytes,
	}, nil
}

type localGitRevisionWalker struct {
	ctx                    context.Context
	reader                 localGitObjectReader
	algorithm              evidence.RevisionAlgorithm
	limits                 localGitRevisionLimits
	trees                  map[string][]localGitTreeEntry
	childTreeContents      map[string][]byte
	blobContents           map[string][]byte
	activeTrees            map[string]struct{}
	seenPaths              map[string]struct{}
	entries                int
	pathBytes              int64
	objectBytes            int64
	retainedBaseBytes      int64
	transferObjectContents bool
}

type localGitTreeEntry struct {
	mode   evidence.GitTreeMode
	name   []byte
	digest string
}

func (w *localGitRevisionWalker) addObjectBytes(size int) error {
	objectBytes, err := checkedLocalGitRevisionAdd(w.objectBytes, int64(size), w.limits.maxObjectBytes)
	if err != nil {
		return LocalGitRevisionResourceLimit
	}
	if _, err := checkedLocalGitRevisionAdd(w.retainedBaseBytes, objectBytes, w.limits.maxRetainedBytes); err != nil {
		return LocalGitRevisionResourceLimit
	}
	w.objectBytes = objectBytes
	return nil
}

func (w *localGitRevisionWalker) validateRetainedResultBytes(resultBytes int64) error {
	retainedBytes, err := checkedLocalGitRevisionAdd(w.retainedBaseBytes, w.objectBytes, w.limits.maxRetainedBytes)
	if err != nil {
		return LocalGitRevisionResourceLimit
	}
	if _, err := checkedLocalGitRevisionAdd(retainedBytes, resultBytes, w.limits.maxRetainedBytes); err != nil {
		return LocalGitRevisionResourceLimit
	}
	return nil
}

func (w *localGitRevisionWalker) walkTree(digest string, prefix []byte, depth int) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if _, active := w.activeTrees[digest]; active {
		return LocalGitRevisionInvalidGraph
	}
	entries, exists := w.trees[digest]
	if !exists {
		if len(w.trees) >= w.limits.maxUniqueTrees {
			return LocalGitRevisionResourceLimit
		}
		content, err := w.reader.ReadTree(w.ctx, w.algorithm, digest)
		if err != nil {
			return classifyLocalGitObjectRead(err)
		}
		if err := w.ctx.Err(); err != nil {
			return err
		}
		if err := w.addObjectBytes(len(content)); err != nil {
			return err
		}
		entries, err = parseLocalGitTreeEntries(w.ctx, content, w.algorithm, w.limits.maxEntries-w.entries)
		if err != nil {
			return err
		}
		w.trees[digest] = entries
		if w.transferObjectContents {
			w.childTreeContents[digest] = content
		} else {
			w.childTreeContents[digest] = append([]byte{}, content...)
		}
	}
	w.activeTrees[digest] = struct{}{}
	defer delete(w.activeTrees, digest)
	for _, entry := range entries {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		entryDepth := depth + 1
		if entryDepth > w.limits.maxDepth || w.entries >= w.limits.maxEntries {
			return LocalGitRevisionResourceLimit
		}
		path := append([]byte{}, prefix...)
		if len(path) != 0 {
			path = append(path, '/')
		}
		path = append(path, entry.name...)
		if len(path) > w.limits.maxPathBytes {
			return LocalGitRevisionResourceLimit
		}
		var err error
		w.pathBytes, err = checkedLocalGitRevisionAdd(w.pathBytes, int64(len(path)), w.limits.maxTotalPathBytes)
		if err != nil {
			return LocalGitRevisionResourceLimit
		}
		if _, duplicate := w.seenPaths[string(path)]; duplicate {
			return LocalGitRevisionInvalidGraph
		}
		w.seenPaths[string(path)] = struct{}{}
		w.entries++
		switch entry.mode {
		case evidence.GitTreeModeDirectory:
			if err := w.walkTree(entry.digest, path, entryDepth); err != nil {
				return err
			}
		case evidence.GitTreeModeRegular, evidence.GitTreeModeExecutable:
			if _, exists := w.blobContents[entry.digest]; !exists {
				if len(w.blobContents) >= w.limits.maxUniqueBlobs {
					return LocalGitRevisionResourceLimit
				}
				content, err := w.reader.ReadBlob(w.ctx, w.algorithm, entry.digest)
				if err != nil {
					return classifyLocalGitObjectRead(err)
				}
				if err := w.ctx.Err(); err != nil {
					return err
				}
				if err := w.addObjectBytes(len(content)); err != nil {
					return err
				}
				if w.transferObjectContents {
					w.blobContents[entry.digest] = content
				} else {
					w.blobContents[entry.digest] = append([]byte{}, content...)
				}
			}
		case evidence.GitTreeModeSymlink:
			return LocalGitRevisionUnsupportedSymlink
		case evidence.GitTreeModeGitlink:
			return LocalGitRevisionUnsupportedGitlink
		default:
			return LocalGitRevisionInvalidGraph
		}
	}
	return nil
}

func parseLocalGitTreeEntries(ctx context.Context, content []byte, algorithm evidence.RevisionAlgorithm, maxEntries int) ([]localGitTreeEntry, error) {
	objectIDBytes := sha1.Size
	if algorithm == evidence.RevisionAlgorithmSHA256 {
		objectIDBytes = sha256.Size
	} else if algorithm != evidence.RevisionAlgorithmSHA1 {
		return nil, LocalGitRevisionInvalidGraph
	}
	entries := make([]localGitTreeEntry, 0)
	seenNames := make(map[string]struct{})
	cursor := 0
	for cursor < len(content) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(entries) >= maxEntries {
			return nil, LocalGitRevisionResourceLimit
		}
		modeEnd := bytes.IndexByte(content[cursor:], ' ')
		if modeEnd < 0 {
			return nil, LocalGitRevisionInvalidGraph
		}
		mode, ok := parseLocalGitTreeMode(content[cursor : cursor+modeEnd])
		if !ok {
			return nil, LocalGitRevisionInvalidGraph
		}
		cursor += modeEnd + 1
		nameEnd := bytes.IndexByte(content[cursor:], 0)
		if nameEnd < 0 {
			return nil, LocalGitRevisionInvalidGraph
		}
		name := content[cursor : cursor+nameEnd]
		if len(name) == 0 || len(name) > maxLocalGitTreeNameBytes || bytes.IndexByte(name, '/') >= 0 || bytes.Equal(name, []byte(".")) || bytes.Equal(name, []byte("..")) {
			return nil, LocalGitRevisionInvalidGraph
		}
		if _, duplicate := seenNames[string(name)]; duplicate {
			return nil, LocalGitRevisionInvalidGraph
		}
		cursor += nameEnd + 1
		if len(content)-cursor < objectIDBytes {
			return nil, LocalGitRevisionInvalidGraph
		}
		entry := localGitTreeEntry{mode: mode, name: append([]byte{}, name...), digest: hex.EncodeToString(content[cursor : cursor+objectIDBytes])}
		cursor += objectIDBytes
		if len(entries) != 0 {
			previous := entries[len(entries)-1]
			if compareLocalGitTreeNames(previous.name, previous.mode == evidence.GitTreeModeDirectory, entry.name, entry.mode == evidence.GitTreeModeDirectory) >= 0 {
				return nil, LocalGitRevisionInvalidGraph
			}
		}
		seenNames[string(name)] = struct{}{}
		entries = append(entries, entry)
	}
	return entries, nil
}

func parseLocalGitTreeMode(mode []byte) (evidence.GitTreeMode, bool) {
	switch string(mode) {
	case string(evidence.GitTreeModeRegular):
		return evidence.GitTreeModeRegular, true
	case string(evidence.GitTreeModeExecutable):
		return evidence.GitTreeModeExecutable, true
	case string(evidence.GitTreeModeSymlink):
		return evidence.GitTreeModeSymlink, true
	case string(evidence.GitTreeModeDirectory):
		return evidence.GitTreeModeDirectory, true
	case string(evidence.GitTreeModeGitlink):
		return evidence.GitTreeModeGitlink, true
	default:
		return "", false
	}
}

func compareLocalGitTreeNames(first []byte, firstDirectory bool, second []byte, secondDirectory bool) int {
	common := len(first)
	if len(second) < common {
		common = len(second)
	}
	if compared := bytes.Compare(first[:common], second[:common]); compared != 0 {
		return compared
	}
	firstNext, secondNext := byte(0), byte(0)
	if len(first) > common {
		firstNext = first[common]
	} else if firstDirectory {
		firstNext = '/'
	}
	if len(second) > common {
		secondNext = second[common]
	} else if secondDirectory {
		secondNext = '/'
	}
	return int(firstNext) - int(secondNext)
}

func localEntriesFromVerifiedTree(tree evidence.GitTree) []localGitTreeEntry {
	entries := tree.Entries()
	result := make([]localGitTreeEntry, len(entries))
	for i, entry := range entries {
		result[i] = localGitTreeEntry{mode: entry.Mode(), name: entry.Name(), digest: entry.ObjectDigest()}
	}
	return result
}

func validLocalGitRevisionLimits(limits localGitRevisionLimits) bool {
	return limits.maxDepth >= 0 && limits.maxEntries >= 0 && limits.maxUniqueTrees >= 1 && limits.maxUniqueBlobs >= 0 && limits.maxPathBytes >= 0 && limits.maxTotalPathBytes >= 0 && limits.maxObjectBytes >= 0 && limits.maxResultBytes >= 0 && limits.maxRetainedBytes >= 0
}

func checkedLocalGitRevisionAdd(current, added, limit int64) (int64, error) {
	if current < 0 || added < 0 || limit < 0 || current > limit || added > limit-current {
		return current, LocalGitRevisionResourceLimit
	}
	return current + added, nil
}

func classifyLocalGitObjectRead(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var revErr LocalGitRevisionError
	if errors.As(err, &revErr) {
		return revErr
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		return LocalGitRevisionObjectUnavailable
	}
	return LocalGitRevisionInvalidGraph
}

func cloneLocalGitContents(contents map[string][]byte) map[string][]byte {
	if contents == nil {
		return nil
	}
	cloned := make(map[string][]byte, len(contents))
	for path, content := range contents {
		cloned[path] = append([]byte{}, content...)
	}
	return cloned
}
