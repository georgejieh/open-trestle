package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// This is a bounded pre-constructor shape, not a decoded owner or admission.
// The caller must strictly read and compare the owner under both writer leases.
const (
	recordedStateEntryLimit    = 1024
	recordedArtifactEntryLimit = 20001
)

var errLocalSourceOwnerRecordedSnapshot = errors.New("local source owner recorded snapshot refused")

type localSourceOwnerRecordedSnapshot struct {
	StatePath       string
	StateRoot       *os.Root
	ArtifactRoot    *os.Root
	StateInfo       os.FileInfo
	ArtifactInfo    os.FileInfo
	OwnerInfo       os.FileInfo
	StateEntries    map[string]os.FileInfo
	ArtifactEntries map[string]os.FileInfo
	statePin        *fileauthority.DirectoryPin
	artifactPin     *fileauthority.DirectoryPin
}

func (s *localSourceOwnerRecordedSnapshot) Close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.ArtifactRoot != nil {
		err = errors.Join(err, s.ArtifactRoot.Close())
	}
	if s.StateRoot != nil {
		err = errors.Join(err, s.StateRoot.Close())
	}
	s.ArtifactRoot, s.StateRoot = nil, nil
	return err
}

// inspectLocalSourceOwnerRecordedSnapshot never opens payload/owner bytes or repairs files.
func inspectLocalSourceOwnerRecordedSnapshot(ctx context.Context, stateDir string) (result *localSourceOwnerRecordedSnapshot, err error) {
	if ctx == nil || ctx.Err() != nil || stateDir == "" {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	return inspectLocalSourceOwnerRecordedSnapshotWithOpen(ctx, stateDir, localExistingRoot)
}

// The per-call opener lets tests replace a path immediately after an opened root
// is returned, without process-wide hooks or any production mutation path.
func inspectLocalSourceOwnerRecordedSnapshotWithOpen(ctx context.Context, stateDir string, openRoot func(string) (*os.Root, error)) (result *localSourceOwnerRecordedSnapshot, err error) {
	if ctx == nil || ctx.Err() != nil || stateDir == "" || openRoot == nil {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	statePath, pathErr := filepath.Abs(stateDir)
	if pathErr != nil || !validLocalOwnerPath(statePath) {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	statePin, pinErr := fileauthority.PinDirectory(statePath)
	if pinErr != nil {
		// Preserve the missing-owner classification for a genuinely absent state.
		if _, statErr := os.Lstat(statePath); errors.Is(statErr, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %w", errLocalSourceOwnerRecordedSnapshot, ErrLocalSourceOwnerMissing)
		}
		return nil, fmt.Errorf("%w: state ancestry: %v", errLocalSourceOwnerRecordedSnapshot, pinErr)
	}
	stateBefore, beforeErr := os.Lstat(statePath)
	if beforeErr != nil || statePin.Recheck() != nil {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	root, openErr := openRoot(statePath)
	if openErr != nil || root == nil {
		return nil, fmt.Errorf("%w: state path: %v", errLocalSourceOwnerRecordedSnapshot, openErr)
	}
	snap := &localSourceOwnerRecordedSnapshot{StatePath: statePath, StateRoot: root, statePin: statePin}
	defer func() {
		if err != nil {
			err = errors.Join(err, snap.Close())
			result = nil
		}
	}()
	snap.StateInfo, err = root.Stat(".")
	stateAfter, afterErr := os.Lstat(statePath)
	if err != nil || afterErr != nil || !ownerDirectoryInfo(snap.StateInfo) || !recordedEqual(stateBefore, snap.StateInfo) || !recordedEqual(stateAfter, snap.StateInfo) || statePin.Recheck() != nil {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	snap.StateEntries, err = scanRecordedEntries(ctx, root, false)
	if err != nil {
		return nil, err
	}
	snap.OwnerInfo = snap.StateEntries[localSourceOwnerLeaf]
	if snap.OwnerInfo == nil {
		return nil, fmt.Errorf("%w: %w", errLocalSourceOwnerRecordedSnapshot, ErrLocalSourceOwnerMissing)
	}
	if snap.StateEntries["artifacts"] == nil || snap.StateEntries[".run-writer.lock"] == nil {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	artifactPath := filepath.Join(statePath, "artifacts")
	snap.artifactPin, err = fileauthority.PinDirectory(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("%w: artifact ancestry: %v", errLocalSourceOwnerRecordedSnapshot, err)
	}
	artifactBefore, beforeErr := os.Lstat(artifactPath)
	if beforeErr != nil || snap.artifactPin.Recheck() != nil || !recordedEqual(snap.StateEntries["artifacts"], artifactBefore) {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	snap.ArtifactRoot, err = openRoot(artifactPath)
	if err != nil || snap.ArtifactRoot == nil {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	snap.ArtifactInfo, err = snap.ArtifactRoot.Stat(".")
	artifactOpenedAfter, afterErr := os.Lstat(artifactPath)
	if err != nil || afterErr != nil || !ownerDirectoryInfo(snap.ArtifactInfo) || !recordedEqual(snap.StateEntries["artifacts"], snap.ArtifactInfo) || !recordedEqual(artifactBefore, snap.ArtifactInfo) || !recordedEqual(artifactOpenedAfter, snap.ArtifactInfo) || snap.artifactPin.Recheck() != nil {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	snap.ArtifactEntries, err = scanRecordedEntries(ctx, snap.ArtifactRoot, true)
	if err != nil {
		return nil, err
	}
	if snap.ArtifactEntries[".artifact-writer.lock"] == nil {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	// Bracket enumeration with rooted child and opened-root identity observations.
	childAfter, childErr := root.Lstat("artifacts")
	artifactAfter, artifactErr := snap.ArtifactRoot.Stat(".")
	stateAfter, stateErr := root.Stat(".")
	if childErr != nil || artifactErr != nil || stateErr != nil || !recordedEqual(childAfter, snap.ArtifactInfo) || !recordedEqual(childAfter, snap.StateEntries["artifacts"]) || !recordedEqual(artifactAfter, snap.ArtifactInfo) || !recordedEqual(stateAfter, snap.StateInfo) || snap.statePin.Recheck() != nil || snap.artifactPin.Recheck() != nil || ctx.Err() != nil {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	if recheckLocalSourceOwnerRecordedSnapshot(ctx, snap, snap.StateRoot, snap.ArtifactRoot) != nil {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	if ctx.Err() != nil {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	return snap, nil
}

// recheckLocalSourceOwnerRecordedSnapshot compares saved opened roots and *all*
// direct entries against constructor-borrowed roots. It grants no owner authority.
func recheckLocalSourceOwnerRecordedSnapshot(ctx context.Context, s *localSourceOwnerRecordedSnapshot, stateRoot, artifactRoot *os.Root) error {
	if ctx == nil || ctx.Err() != nil || s == nil || s.StateRoot == nil || s.ArtifactRoot == nil || stateRoot == nil || artifactRoot == nil || s.statePin == nil || s.artifactPin == nil || s.OwnerInfo == nil || s.StateEntries == nil || s.ArtifactEntries == nil {
		return errLocalSourceOwnerRecordedSnapshot
	}
	if s.statePin.Recheck() != nil || s.artifactPin.Recheck() != nil {
		return errLocalSourceOwnerRecordedSnapshot
	}
	originalState, stateErr := s.StateRoot.Stat(".")
	borrowedState, borrowErr := stateRoot.Stat(".")
	if stateErr != nil || borrowErr != nil || !ownerDirectoryInfo(originalState) || !recordedEqual(s.StateInfo, originalState) || !recordedEqual(s.StateInfo, borrowedState) {
		return errLocalSourceOwnerRecordedSnapshot
	}
	childBefore, childErr := stateRoot.Lstat("artifacts")
	originalChild, originalChildErr := s.StateRoot.Lstat("artifacts")
	originalArtifact, artifactErr := s.ArtifactRoot.Stat(".")
	borrowedArtifact, borrowArtifactErr := artifactRoot.Stat(".")
	if childErr != nil || originalChildErr != nil || artifactErr != nil || borrowArtifactErr != nil || !ownerDirectoryInfo(childBefore) || !recordedEqual(s.StateEntries["artifacts"], childBefore) || !recordedEqual(s.ArtifactInfo, originalChild) || !recordedEqual(s.ArtifactInfo, originalArtifact) || !recordedEqual(s.ArtifactInfo, borrowedArtifact) {
		return errLocalSourceOwnerRecordedSnapshot
	}
	for _, root := range []*os.Root{s.StateRoot, stateRoot} {
		entries, err := scanRecordedEntries(ctx, root, false)
		if err != nil || !recordedEntriesEqual(s.StateEntries, entries) || !recordedEqual(s.OwnerInfo, entries[localSourceOwnerLeaf]) {
			return errLocalSourceOwnerRecordedSnapshot
		}
	}
	for _, root := range []*os.Root{s.ArtifactRoot, artifactRoot} {
		entries, err := scanRecordedEntries(ctx, root, true)
		if err != nil || !recordedEntriesEqual(s.ArtifactEntries, entries) {
			return errLocalSourceOwnerRecordedSnapshot
		}
	}
	childAfter, childErr := stateRoot.Lstat("artifacts")
	originalAfter, originalErr := s.StateRoot.Lstat("artifacts")
	artifactAfter, artifactErr := artifactRoot.Stat(".")
	originalArtifactAfter, oldErr := s.ArtifactRoot.Stat(".")
	stateAfter, stateErr := stateRoot.Stat(".")
	if childErr != nil || originalErr != nil || artifactErr != nil || oldErr != nil || stateErr != nil || !recordedEqual(s.ArtifactInfo, childAfter) || !recordedEqual(s.ArtifactInfo, originalAfter) || !recordedEqual(s.ArtifactInfo, artifactAfter) || !recordedEqual(s.ArtifactInfo, originalArtifactAfter) || !recordedEqual(s.StateInfo, stateAfter) || s.statePin.Recheck() != nil || s.artifactPin.Recheck() != nil || ctx.Err() != nil {
		return errLocalSourceOwnerRecordedSnapshot
	}
	return nil
}

// Artifact names exceed the first-use helper's 128-byte name bound.
func recordedBoundedEntries(root *os.Root, limit int, artifact bool) ([]os.DirEntry, error) {
	file, err := root.Open(".")
	if err != nil {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	entries, readErr := file.ReadDir(limit + 1)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > limit {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	maxName := 128
	if artifact {
		maxName = 160
	}
	for _, entry := range entries {
		if len(entry.Name()) == 0 || len(entry.Name()) > maxName {
			return nil, errLocalSourceOwnerRecordedSnapshot
		}
	}
	return entries, nil
}

func recordedEntriesEqual(saved, current map[string]os.FileInfo) bool {
	if len(saved) != len(current) {
		return false
	}
	for name, info := range saved {
		if !recordedEqual(info, current[name]) {
			return false
		}
	}
	return true
}
func recordedEqual(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size()
}

func scanRecordedEntries(ctx context.Context, root *os.Root, artifact bool) (map[string]os.FileInfo, error) {
	limit := recordedStateEntryLimit
	if artifact {
		limit = recordedArtifactEntryLimit
	}
	entries, err := recordedBoundedEntries(root, limit, artifact)
	if err != nil {
		return nil, errLocalSourceOwnerRecordedSnapshot
	}
	observed := make(map[string]os.FileInfo, len(entries))
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, errLocalSourceOwnerRecordedSnapshot
		}
		name := entry.Name()
		info, err := root.Lstat(name)
		if err != nil || !recordedEntryValid(name, info, artifact) {
			return nil, errLocalSourceOwnerRecordedSnapshot
		}
		observed[name] = info
	}
	return observed, nil
}
func recordedEntryValid(name string, info os.FileInfo, artifact bool) bool {
	if info == nil || !fileauthority.TrustedOwner(info) {
		return false
	}
	if artifact {
		if name == ".artifact-writer.lock" {
			return recordedPrivateSingleLink(info)
		}
		suffix := ".artifact.json"
		if strings.HasSuffix(name, ".artifact-deleted.json") {
			suffix = ".artifact-deleted.json"
		}
		prefix, ok := strings.CutSuffix(name, suffix)
		if !ok || len(prefix) != 129 || prefix[64] != '-' || !recordedDigest(prefix[:64]) || !recordedDigest(prefix[65:]) {
			return false
		}
		return info.Mode() == 0600 && info.Size() >= 0
	}
	switch name {
	case localSourceOwnerLeaf:
		return recordedPrivateSingleLink(info) && info.Size() > 0 && info.Size() <= maxLocalSourceOwnerRecordBytes
	case ".run-writer.lock":
		return recordedPrivateSingleLink(info)
	case "artifacts", "audit", "diagnostics", "webhook-inbox", "setup":
		return ownerDirectoryInfo(info)
	}
	suffix := ".run-plan.json"
	if strings.HasSuffix(name, ".run.jsonl") {
		suffix = ".run.jsonl"
	}
	prefix, ok := strings.CutSuffix(name, suffix)
	return ok && recordedDigest(prefix) && info.Mode().IsRegular() && info.Mode().Perm()&0077 == 0 && info.Size() > 0 && info.Size() <= 256<<20
}
func recordedDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' && value[i] < 'a' || value[i] > 'f' {
			return false
		}
	}
	return true
}
func recordedPrivateSingleLink(info os.FileInfo) bool {
	return runtime.GOOS == "linux" && ownerConstructorLockInfo(info)
}
