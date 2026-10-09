package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/setup"
)

// This observation is not a constructor-held inode, historical owner proof,
// migration approval, or authority to create a Store. A later startup gate must
// recheck it under both leases before making any ownership decision.
type localSourceOwnerSnapshotKind uint8

const (
	localSourceOwnerRefused localSourceOwnerSnapshotKind = iota
	localSourceOwnerMissing
	localSourceOwnerEmpty
	localSourceOwnerSetupOnly
)

var errLocalSourceOwnerSnapshot = errors.New("local source owner bootstrap snapshot refused")

type localSourceOwnerSnapshot struct {
	Kind        localSourceOwnerSnapshotKind
	StatePath   string
	StateRoot   *os.Root
	SetupRoot   *os.Root
	ReceiptRoot *os.Root
	// Entries are read-only, momentary observations for a future under-lock recheck.
	Entries map[string]os.FileInfo
	// SetupBytes fingerprints only the original setup leaves, never runtime state.
	SetupBytes map[string][sha256.Size]byte
}

func (s *localSourceOwnerSnapshot) Close() error {
	if s == nil {
		return nil
	}
	var result error
	for _, root := range []*os.Root{s.ReceiptRoot, s.SetupRoot, s.StateRoot} {
		if root != nil {
			result = errors.Join(result, root.Close())
		}
	}
	s.ReceiptRoot, s.SetupRoot, s.StateRoot = nil, nil, nil
	return result
}

// inspectLocalSourceOwnerSnapshot only observes pre-constructor first-use shapes.
// expected must be a separately approved setup plan for the setup-only shape;
// metadata and local Git source identities are NOT authenticated here.
func inspectLocalSourceOwnerSnapshot(ctx context.Context, stateDir, configuredSetupPath string, expected *setup.Plan) (*localSourceOwnerSnapshot, error) {
	return inspectLocalSourceOwnerSnapshotWithInspector(ctx, stateDir, configuredSetupPath, expected, setup.InspectStateFile)
}

// The per-call inspector seam keeps the byte bracket test local to this call.
func inspectLocalSourceOwnerSnapshotWithInspector(ctx context.Context, stateDir, configuredSetupPath string, expected *setup.Plan, inspector func(context.Context, string) (setup.Plan, error)) (result *localSourceOwnerSnapshot, err error) {
	if ctx == nil || ctx.Err() != nil || stateDir == "" {
		return nil, errLocalSourceOwnerSnapshot
	}
	statePath, err := filepath.Abs(stateDir)
	if err != nil {
		return nil, errLocalSourceOwnerSnapshot
	}
	root, err := localExistingRoot(statePath)
	if err != nil {
		return nil, fmt.Errorf("%w: state path", errLocalSourceOwnerSnapshot)
	}
	if root == nil {
		return &localSourceOwnerSnapshot{Kind: localSourceOwnerMissing, StatePath: statePath}, nil
	}
	snap := &localSourceOwnerSnapshot{Kind: localSourceOwnerRefused, StatePath: statePath, StateRoot: root, Entries: make(map[string]os.FileInfo)}
	defer func() {
		if err != nil {
			err = errors.Join(err, snap.Close())
			result = &localSourceOwnerSnapshot{Kind: localSourceOwnerRefused, StatePath: statePath}
		}
	}()
	info, statErr := root.Stat(".")
	if statErr != nil || info.Mode() != os.ModeDir|0700 || !fileauthority.TrustedOwner(info) {
		return nil, errLocalSourceOwnerSnapshot
	}
	snap.Entries["."] = info
	entries, err := boundedOwnerEntries(root, 2)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		snap.Kind = localSourceOwnerEmpty
		return snap, nil
	}
	if len(entries) != 1 || entries[0].Name() != "setup" {
		return nil, errLocalSourceOwnerSnapshot
	}
	if configuredSetupPath != filepath.Join(statePath, "setup", "plan.json") || expected == nil || expected.Validate() != nil {
		return nil, errLocalSourceOwnerSnapshot
	}
	setupRoot, setupInfo, err := ownerChildRoot(root, "setup")
	if err != nil {
		return nil, err
	}
	snap.SetupRoot = setupRoot
	snap.Entries["setup"] = setupInfo
	if err = scanOwnerSetup(snap); err != nil {
		return nil, err
	}
	snap.Kind = localSourceOwnerSetupOnly
	if err = recheckOwnerEntries(snap); err != nil {
		return nil, err
	}
	if err = recheckOriginalSetupSubtree(snap); err != nil {
		return nil, err
	}
	if snap.SetupBytes, err = hashOriginalSetupEntries(ctx, snap); err != nil {
		return nil, err
	}
	if err = recheckOriginalSetupSubtree(snap); err != nil || recheckOwnerEntries(snap) != nil {
		return nil, errLocalSourceOwnerSnapshot
	}
	plan, err := inspector(ctx, configuredSetupPath)
	if err != nil {
		return nil, fmt.Errorf("%w: setup plan or ledger: %v", errLocalSourceOwnerSnapshot, err)
	}
	if plan.Validate() != nil || plan.RootIdentity() != expected.RootIdentity() || plan.TenantID() != expected.TenantID() || plan.RepositoryID() != expected.RepositoryID() || plan.Profile() != expected.Profile() || plan.Posture() != expected.Posture() {
		return nil, errLocalSourceOwnerSnapshot
	}
	if ctx.Err() != nil || recheckOriginalSetupSubtree(snap) != nil || recheckOwnerEntries(snap) != nil {
		return nil, errLocalSourceOwnerSnapshot
	}
	observed, err := hashOriginalSetupEntries(ctx, snap)
	if err != nil || !equalOriginalSetupBytes(snap.SetupBytes, observed) || ctx.Err() != nil ||
		recheckOriginalSetupSubtree(snap) != nil || recheckOwnerEntries(snap) != nil {
		return nil, errLocalSourceOwnerSnapshot
	}
	return snap, nil
}

// File.ReadDir(n) stops at n entries. Never materialize an unbounded directory
// and then check its length. Names and file sizes are bounded before inspection.
func boundedOwnerEntries(root *os.Root, limit int) ([]os.DirEntry, error) {
	file, err := root.Open(".")
	if err != nil {
		return nil, errLocalSourceOwnerSnapshot
	}
	entries, readErr := file.ReadDir(limit + 1)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > limit {
		return nil, errLocalSourceOwnerSnapshot
	}
	for _, e := range entries {
		if len(e.Name()) == 0 || len(e.Name()) > 128 {
			return nil, errLocalSourceOwnerSnapshot
		}
	}
	return entries, nil
}

func ownerChildRoot(parent *os.Root, name string) (*os.Root, os.FileInfo, error) {
	before, err := parent.Lstat(name)
	if err != nil || before.Mode() != os.ModeDir|0700 || !fileauthority.TrustedOwner(before) {
		return nil, nil, errLocalSourceOwnerSnapshot
	}
	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, nil, errLocalSourceOwnerSnapshot
	}
	after, err := child.Stat(".")
	again, againErr := parent.Lstat(name)
	if err != nil || againErr != nil || !os.SameFile(before, after) || !os.SameFile(before, again) || after.Mode() != before.Mode() || again.Mode() != before.Mode() {
		_ = child.Close()
		return nil, nil, errLocalSourceOwnerSnapshot
	}
	return child, before, nil
}

var ownerReceiptName = regexp.MustCompile(`^[0-9]{20}-[0-9a-f]{64}\.receipt\.json(\.next)?$`)

func scanOwnerSetup(s *localSourceOwnerSnapshot) error {
	entries, err := boundedOwnerEntries(s.SetupRoot, 3)
	if err != nil || len(entries) != 3 {
		return errLocalSourceOwnerSnapshot
	}
	found := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		// A protected plan.json.next can be reclaimed by the setup writer,
		// but conservative first-use bootstrap refuses it until offline
		// resolution. This is policy, not a claim that the plan is corrupt.
		if name != "plan.json" && name != "plan.json.lock" && name != "plan.json.receipts" {
			return errLocalSourceOwnerSnapshot
		}
		found[name] = true
		if name == "plan.json.receipts" {
			root, info, err := ownerChildRoot(s.SetupRoot, name)
			if err != nil {
				return err
			}
			s.ReceiptRoot = root
			s.Entries["setup/"+name] = info
		} else if err := ownerPrivateFile(s.SetupRoot, name, 1<<20, s.Entries, "setup/"+name); err != nil {
			return err
		}
	}
	if len(found) != 3 || s.ReceiptRoot == nil {
		return errLocalSourceOwnerSnapshot
	}
	receipts, err := boundedOwnerEntries(s.ReceiptRoot, 257)
	if err != nil {
		return err
	}
	staging := 0
	for _, entry := range receipts {
		name := entry.Name()
		if !ownerReceiptName.MatchString(name) {
			return errLocalSourceOwnerSnapshot
		}
		if strings.HasSuffix(name, ".next") {
			staging++
			if staging > 1 {
				return errLocalSourceOwnerSnapshot
			}
		}
		if err := ownerPrivateFile(s.ReceiptRoot, name, 1<<20, s.Entries, "setup/plan.json.receipts/"+name); err != nil {
			return err
		}
	}
	return nil
}

func ownerPrivateFile(root *os.Root, name string, maxBytes int64, entries map[string]os.FileInfo, key string) error {
	info, err := root.Lstat(name)
	if err != nil || info.Mode() != 0600 || info.Size() < 0 || info.Size() > maxBytes || !fileauthority.TrustedOwner(info) {
		return errLocalSourceOwnerSnapshot
	}
	entries[key] = info
	return nil
}

// A metadata recheck cannot attest in-place, same-size bytes. The later gate
// must independently reread setup under both leases before granting authority.
func recheckOwnerEntries(s *localSourceOwnerSnapshot) error {
	if s == nil || s.StateRoot == nil || s.Entries == nil {
		return errLocalSourceOwnerSnapshot
	}
	if s.Kind != localSourceOwnerEmpty && s.Kind != localSourceOwnerSetupOnly {
		return errLocalSourceOwnerSnapshot
	}
	if s.Kind == localSourceOwnerSetupOnly && (s.SetupRoot == nil || s.ReceiptRoot == nil) {
		return errLocalSourceOwnerSnapshot
	}
	if s.Kind == localSourceOwnerEmpty && (s.SetupRoot != nil || s.ReceiptRoot != nil) {
		return errLocalSourceOwnerSnapshot
	}
	before, ok := s.Entries["."]
	after, err := s.StateRoot.Stat(".")
	if !ok || err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || after.Mode() != os.ModeDir|0700 || !fileauthority.TrustedOwner(after) {
		return errLocalSourceOwnerSnapshot
	}
	dirs := []struct {
		root   *os.Root
		prefix string
		limit  int
	}{{s.StateRoot, "", 2}}
	if s.Kind == localSourceOwnerSetupOnly {
		dirs = append(dirs, struct {
			root   *os.Root
			prefix string
			limit  int
		}{s.SetupRoot, "setup/", 3}, struct {
			root   *os.Root
			prefix string
			limit  int
		}{s.ReceiptRoot, "setup/plan.json.receipts/", 257})
	}
	for _, dir := range dirs {
		if err := recheckOwnerSnapshotDirectory(s, dir.root, dir.prefix, dir.limit); err != nil {
			return err
		}
	}
	return nil
}

// Compare one original directory without accepting changes to saved entry inodes.
func recheckOwnerSnapshotDirectory(s *localSourceOwnerSnapshot, root *os.Root, prefix string, limit int) error {
	entries, err := boundedOwnerEntries(root, limit)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		key := prefix + entry.Name()
		before, ok := s.Entries[key]
		after, statErr := root.Lstat(entry.Name())
		if !ok || before == nil || statErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !fileauthority.TrustedOwner(after) {
			return errLocalSourceOwnerSnapshot
		}
	}
	expected := 0
	for key := range s.Entries {
		if strings.HasPrefix(key, prefix) && key != "." && !strings.Contains(strings.TrimPrefix(key, prefix), "/") {
			expected++
		}
	}
	if len(entries) != expected {
		return errLocalSourceOwnerSnapshot
	}
	return nil
}

// recheckLocalSourceOwnerPostConstructor is a read-only shape comparison under
// both constructor-held leases. The caller supplies the scoped borrowed roots;
// this does not authenticate their origin, missing-root ancestry, setup bytes,
// or any historical owner, and never grants enrollment or activation.
func recheckLocalSourceOwnerPostConstructor(s *localSourceOwnerSnapshot, stateRoot, artifactRoot *os.Root) error {
	if s == nil || stateRoot == nil || artifactRoot == nil ||
		(s.Kind != localSourceOwnerMissing && s.Entries == nil) ||
		(s.Kind != localSourceOwnerMissing && s.Kind != localSourceOwnerEmpty && s.Kind != localSourceOwnerSetupOnly) {
		return errLocalSourceOwnerSnapshot
	}
	if s.Kind == localSourceOwnerMissing {
		if s.StateRoot != nil || s.SetupRoot != nil || s.ReceiptRoot != nil || len(s.Entries) != 0 {
			return errLocalSourceOwnerSnapshot
		}
	} else {
		if s.StateRoot == nil || (s.Kind == localSourceOwnerSetupOnly && (s.SetupRoot == nil || s.ReceiptRoot == nil)) ||
			(s.Kind == localSourceOwnerEmpty && (s.SetupRoot != nil || s.ReceiptRoot != nil)) {
			return errLocalSourceOwnerSnapshot
		}
	}
	stateBefore, err := stateRoot.Stat(".")
	if err != nil || !ownerDirectoryInfo(stateBefore) {
		return errLocalSourceOwnerSnapshot
	}
	if s.StateRoot != nil {
		original, originalErr := s.StateRoot.Stat(".")
		saved, ok := s.Entries["."]
		if originalErr != nil || !ok || saved == nil || !ownerDirectoryInfo(original) || !os.SameFile(saved, original) ||
			!os.SameFile(original, stateBefore) || saved.Mode() != original.Mode() {
			return errLocalSourceOwnerSnapshot
		}
	}
	// The artifact parent observations bracket the child enumeration. No payload
	// or owner bytes are opened here; constructor capture/whole-chain pinning
	// remains the responsibility of the two outer callback APIs.
	childBefore, err := stateRoot.Lstat("artifacts")
	if err != nil || !ownerDirectoryInfo(childBefore) {
		return errLocalSourceOwnerSnapshot
	}
	artifactBefore, err := artifactRoot.Stat(".")
	if err != nil || !ownerDirectoryInfo(artifactBefore) || !os.SameFile(childBefore, artifactBefore) {
		return errLocalSourceOwnerSnapshot
	}
	required := map[string]bool{".run-writer.lock": false, "artifacts": false}
	if s.Kind == localSourceOwnerSetupOnly {
		required["setup"] = false
	}
	entries, err := boundedOwnerEntries(stateRoot, len(required))
	if err != nil || len(entries) != len(required) {
		return errLocalSourceOwnerSnapshot
	}
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := required[name]; !ok || required[name] {
			return errLocalSourceOwnerSnapshot
		}
		required[name] = true
		info, statErr := stateRoot.Lstat(name)
		if statErr != nil {
			return errLocalSourceOwnerSnapshot
		}
		switch name {
		case ".run-writer.lock":
			if !ownerConstructorLockInfo(info) {
				return errLocalSourceOwnerSnapshot
			}
		case "artifacts":
			if !ownerDirectoryInfo(info) || !os.SameFile(info, artifactBefore) {
				return errLocalSourceOwnerSnapshot
			}
		case "setup":
			saved := s.Entries["setup"]
			original, originalErr := s.SetupRoot.Stat(".")
			if originalErr != nil || !ownerDirectoryInfo(info) || !ownerDirectoryInfo(original) ||
				saved == nil || !os.SameFile(saved, info) || !os.SameFile(info, original) ||
				saved.Mode() != info.Mode() {
				return errLocalSourceOwnerSnapshot
			}
		}
	}
	if s.Kind == localSourceOwnerSetupOnly {
		receiptBefore, err := s.SetupRoot.Lstat("plan.json.receipts")
		originalReceipt, originalErr := s.ReceiptRoot.Stat(".")
		if s.Entries["setup/plan.json.receipts"] == nil || err != nil || originalErr != nil || !ownerDirectoryInfo(receiptBefore) ||
			!ownerDirectoryInfo(originalReceipt) || !os.SameFile(receiptBefore, originalReceipt) ||
			!os.SameFile(receiptBefore, s.Entries["setup/plan.json.receipts"]) {
			return errLocalSourceOwnerSnapshot
		}
		if err := recheckOwnerSnapshotDirectory(s, s.SetupRoot, "setup/", 3); err != nil {
			return err
		}
		if err := recheckOwnerSnapshotDirectory(s, s.ReceiptRoot, "setup/plan.json.receipts/", 257); err != nil {
			return err
		}
		setupAfter, err := stateRoot.Lstat("setup")
		receiptAfter, receiptErr := s.SetupRoot.Lstat("plan.json.receipts")
		if s.Entries["setup"] == nil || err != nil || receiptErr != nil || !ownerDirectoryInfo(setupAfter) || !ownerDirectoryInfo(receiptAfter) ||
			!os.SameFile(setupAfter, s.Entries["setup"]) || !os.SameFile(receiptBefore, receiptAfter) {
			return errLocalSourceOwnerSnapshot
		}
	}
	artifactEntries, err := boundedOwnerEntries(artifactRoot, 1)
	if err != nil || len(artifactEntries) != 1 || artifactEntries[0].Name() != ".artifact-writer.lock" {
		return errLocalSourceOwnerSnapshot
	}
	artifactLock, err := artifactRoot.Lstat(".artifact-writer.lock")
	if err != nil || !ownerConstructorLockInfo(artifactLock) {
		return errLocalSourceOwnerSnapshot
	}
	stateLock, err := stateRoot.Lstat(".run-writer.lock")
	if err != nil || !ownerConstructorLockInfo(stateLock) {
		return errLocalSourceOwnerSnapshot
	}
	childAfter, err := stateRoot.Lstat("artifacts")
	artifactAfter, artifactErr := artifactRoot.Stat(".")
	stateAfter, stateErr := stateRoot.Stat(".")
	if err != nil || artifactErr != nil || stateErr != nil || !ownerDirectoryInfo(childAfter) ||
		!ownerDirectoryInfo(artifactAfter) || !ownerDirectoryInfo(stateAfter) ||
		!os.SameFile(childBefore, childAfter) || !os.SameFile(childAfter, artifactAfter) ||
		!os.SameFile(stateBefore, stateAfter) {
		return errLocalSourceOwnerSnapshot
	}
	return nil
}

// recheckOriginalSetupSubtree pins each saved parent-child edge and the exact
// original directory shape. It is not a pathname-based plan validator.
func recheckOriginalSetupSubtree(s *localSourceOwnerSnapshot) error {
	if s == nil || s.Kind != localSourceOwnerSetupOnly || s.StateRoot == nil || s.SetupRoot == nil || s.ReceiptRoot == nil || s.Entries == nil {
		return errLocalSourceOwnerSnapshot
	}
	if err := recheckOwnerSnapshotDirectory(s, s.SetupRoot, "setup/", 3); err != nil {
		return err
	}
	if err := recheckOwnerSnapshotDirectory(s, s.ReceiptRoot, "setup/plan.json.receipts/", 257); err != nil {
		return err
	}
	for _, edge := range []struct {
		parent, child *os.Root
		name, key     string
	}{
		{s.StateRoot, s.SetupRoot, "setup", "setup"},
		{s.SetupRoot, s.ReceiptRoot, "plan.json.receipts", "setup/plan.json.receipts"},
	} {
		saved := s.Entries[edge.key]
		observed, err := edge.parent.Lstat(edge.name)
		if err != nil || saved == nil || !ownerDirectoryInfo(observed) || !os.SameFile(saved, observed) || saved.Mode() != observed.Mode() {
			return errLocalSourceOwnerSnapshot
		}
		opened, err := edge.child.Stat(".")
		if err != nil || !ownerDirectoryInfo(opened) || !os.SameFile(saved, opened) || saved.Mode() != opened.Mode() {
			return errLocalSourceOwnerSnapshot
		}
	}
	return nil
}

// hashOriginalSetupEntries never enumerates a new digest target. The snapshot
// directory check separately rejects additions, removals and changed ancestry.
func hashOriginalSetupEntries(ctx context.Context, s *localSourceOwnerSnapshot) (map[string][sha256.Size]byte, error) {
	if ctx == nil || ctx.Err() != nil || s == nil || s.Kind != localSourceOwnerSetupOnly || s.SetupRoot == nil || s.ReceiptRoot == nil || s.Entries == nil {
		return nil, errLocalSourceOwnerSnapshot
	}
	const prefix = "setup/plan.json.receipts/"
	names := make([]string, 0, 259)
	for key, info := range s.Entries {
		if key == "setup/plan.json" || key == "setup/plan.json.lock" || strings.HasPrefix(key, prefix) {
			if info == nil || info.Mode() != 0600 || info.Size() < 0 || info.Size() > 1<<20 || !fileauthority.TrustedOwner(info) {
				return nil, errLocalSourceOwnerSnapshot
			}
			if strings.HasPrefix(key, prefix) && (!ownerReceiptName.MatchString(strings.TrimPrefix(key, prefix)) || strings.Contains(strings.TrimPrefix(key, prefix), "/")) {
				return nil, errLocalSourceOwnerSnapshot
			}
			names = append(names, key)
		}
	}
	if len(names) < 2 || len(names) > 259 || s.Entries["setup/plan.json"] == nil || s.Entries["setup/plan.json.lock"] == nil {
		return nil, errLocalSourceOwnerSnapshot
	}
	sort.Strings(names)
	digests := make(map[string][sha256.Size]byte, len(names))
	var total int64
	for _, key := range names {
		saved := s.Entries[key]
		if total+saved.Size() > 259<<20 {
			return nil, errLocalSourceOwnerSnapshot
		}
		total += saved.Size()
		root, name := s.SetupRoot, strings.TrimPrefix(key, "setup/")
		if strings.HasPrefix(key, prefix) {
			root, name = s.ReceiptRoot, strings.TrimPrefix(key, prefix)
		}
		digest, err := hashOriginalSetupLeaf(ctx, root, name, saved)
		if err != nil {
			return nil, err
		}
		digests[key] = digest
	}
	if ctx.Err() != nil {
		return nil, errLocalSourceOwnerSnapshot
	}
	return digests, nil
}

func hashOriginalSetupLeaf(ctx context.Context, root *os.Root, name string, saved os.FileInfo) (digest [sha256.Size]byte, err error) {
	return hashOriginalSetupLeafWithReader(ctx, root, name, saved, nil)
}

// makeReader is a per-call fault seam after descriptor Stat; nil reads the opened file.
func hashOriginalSetupLeafWithReader(ctx context.Context, root *os.Root, name string, saved os.FileInfo, makeReader func(*os.File) io.ReadCloser) (digest [sha256.Size]byte, err error) {
	if ctx == nil || ctx.Err() != nil || root == nil || saved == nil || saved.Mode() != 0600 || saved.Size() < 0 || saved.Size() > 1<<20 || !fileauthority.TrustedOwner(saved) {
		return digest, errLocalSourceOwnerSnapshot
	}
	before, statErr := root.Lstat(name)
	if statErr != nil || !sameOriginalSetupFile(saved, before) {
		return digest, errLocalSourceOwnerSnapshot
	}
	file, openErr := root.Open(name)
	if openErr != nil {
		return digest, errLocalSourceOwnerSnapshot
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("%w: close setup leaf: %v", errLocalSourceOwnerSnapshot, closeErr))
		}
	}()
	opened, statErr := file.Stat()
	if statErr != nil || !sameOriginalSetupFile(saved, opened) || !os.SameFile(before, opened) {
		return digest, errLocalSourceOwnerSnapshot
	}
	var reader io.Reader = file
	if makeReader != nil {
		injected := makeReader(file)
		if injected == nil {
			return digest, errLocalSourceOwnerSnapshot
		}
		reader = injected
		defer func() {
			if closeErr := injected.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("%w: close setup reader: %v", errLocalSourceOwnerSnapshot, closeErr))
			}
		}()
	}
	hash := sha256.New()
	var buffer [32 * 1024]byte
	remaining := saved.Size()
	for remaining > 0 {
		if ctx.Err() != nil {
			return digest, errLocalSourceOwnerSnapshot
		}
		count := int64(len(buffer))
		if remaining < count {
			count = remaining
		}
		n, readErr := reader.Read(buffer[:int(count)])
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			remaining -= int64(n)
		}
		if readErr != nil || n == 0 {
			return digest, errLocalSourceOwnerSnapshot
		}
	}
	if ctx.Err() != nil {
		return digest, errLocalSourceOwnerSnapshot
	}
	var probe [1]byte
	n, readErr := reader.Read(probe[:])
	if n != 0 || !errors.Is(readErr, io.EOF) {
		return digest, errLocalSourceOwnerSnapshot
	}
	after, statErr := root.Lstat(name)
	if statErr != nil || !sameOriginalSetupFile(saved, after) || !os.SameFile(before, after) || ctx.Err() != nil {
		return digest, errLocalSourceOwnerSnapshot
	}
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func sameOriginalSetupFile(saved, observed os.FileInfo) bool {
	return saved != nil && observed != nil && observed.Mode() == 0600 && saved.Mode() == observed.Mode() &&
		observed.Size() >= 0 && observed.Size() <= 1<<20 && saved.Size() == observed.Size() &&
		fileauthority.TrustedOwner(observed) && os.SameFile(saved, observed)
}

func equalOriginalSetupBytes(expected, observed map[string][sha256.Size]byte) bool {
	if expected == nil || len(expected) != len(observed) {
		return false
	}
	for key, digest := range observed {
		if previous, ok := expected[key]; !ok || previous != digest {
			return false
		}
	}
	return true
}

// recheckLocalSourceOwnerSetupBytes is private setup-only continuity evidence.
// The caller must hold both constructor leases. This does not validate the
// plan or grant ownership; the atomic caller must invoke this check both before
// and after its independent setup.InspectStateFile semantic inspection.
func recheckLocalSourceOwnerSetupBytes(ctx context.Context, s *localSourceOwnerSnapshot, stateRoot, artifactRoot *os.Root) error {
	if ctx == nil || ctx.Err() != nil || s == nil || s.Kind != localSourceOwnerSetupOnly || s.SetupBytes == nil {
		return errLocalSourceOwnerSnapshot
	}
	if recheckLocalSourceOwnerPostConstructor(s, stateRoot, artifactRoot) != nil || recheckOriginalSetupSubtree(s) != nil {
		return errLocalSourceOwnerSnapshot
	}
	observed, err := hashOriginalSetupEntries(ctx, s)
	if err != nil || !equalOriginalSetupBytes(s.SetupBytes, observed) || ctx.Err() != nil {
		return errLocalSourceOwnerSnapshot
	}
	if recheckOriginalSetupSubtree(s) != nil || recheckLocalSourceOwnerPostConstructor(s, stateRoot, artifactRoot) != nil || ctx.Err() != nil {
		return errLocalSourceOwnerSnapshot
	}
	return nil
}
