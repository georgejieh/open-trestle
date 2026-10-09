package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
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
func inspectLocalSourceOwnerSnapshot(ctx context.Context, stateDir, configuredSetupPath string, expected *setup.Plan) (result *localSourceOwnerSnapshot, err error) {
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
	plan, err := setup.InspectStateFile(ctx, configuredSetupPath)
	if err != nil {
		return nil, fmt.Errorf("%w: setup plan or ledger: %v", errLocalSourceOwnerSnapshot, err)
	}
	if plan.Validate() != nil || plan.RootIdentity() != expected.RootIdentity() || plan.TenantID() != expected.TenantID() || plan.RepositoryID() != expected.RepositoryID() || plan.Profile() != expected.Profile() || plan.Posture() != expected.Posture() {
		return nil, errLocalSourceOwnerSnapshot
	}
	snap.Kind = localSourceOwnerSetupOnly
	if ctx.Err() != nil || recheckOwnerEntries(snap) != nil {
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
		entries, err := boundedOwnerEntries(dir.root, dir.limit)
		if err != nil {
			return err
		}
		count := 0
		for _, entry := range entries {
			key := dir.prefix + entry.Name()
			before, ok := s.Entries[key]
			after, statErr := dir.root.Lstat(entry.Name())
			if !ok || statErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
				return errLocalSourceOwnerSnapshot
			}
			count++
		}
		expected := 0
		for key := range s.Entries {
			if strings.HasPrefix(key, dir.prefix) && key != "." && !strings.Contains(strings.TrimPrefix(key, dir.prefix), "/") {
				expected++
			}
		}
		if count != expected {
			return errLocalSourceOwnerSnapshot
		}
	}
	return nil
}
