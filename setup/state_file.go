package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/filelock"
)

var (
	ErrInvalidStatePath = errors.New("invalid setup state path")
	ErrStateLocked      = errors.New("setup state locked")
	ErrStateNotFound    = errors.New("setup state not found")
	ErrStateConflict    = errors.New("setup state conflict")
	ErrCorruptState     = errors.New("corrupt setup state")
	ErrStatePersistence = errors.New("setup state persistence failure")
)

// StateFile owns an exclusive crash-safe setup-state writer.
type StateFile struct {
	mu                          sync.Mutex
	path, parent, receiptRoot   string
	parentInfo, receiptRootInfo os.FileInfo
	lock                        *filelock.Lock
	closed                      bool
}

// OpenStateFile opens one protected path with an exclusive writer lock.
func OpenStateFile(path string) (*StateFile, error) {
	if path == "" || !fileOwnershipSupported() {
		return nil, ErrInvalidStatePath
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrInvalidStatePath
	}
	parent := filepath.Dir(absolute)
	if fileauthority.CheckDirectory(parent) != nil {
		return nil, ErrInvalidStatePath
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, ErrInvalidStatePath
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return nil, ErrInvalidStatePath
	}
	if err = validateStatePath(absolute, true); err != nil {
		return nil, err
	}
	_, stateErr := os.Lstat(absolute)
	stateMissing := errors.Is(stateErr, os.ErrNotExist)
	if stateErr != nil && !stateMissing {
		return nil, ErrInvalidStatePath
	}
	if !stateMissing {
		receiptInfo, receiptErr := os.Lstat(absolute + ".receipts")
		if receiptErr != nil || !receiptInfo.IsDir() || receiptInfo.Mode()&os.ModeSymlink != 0 || receiptInfo.Mode().Perm()&0o077 != 0 || !fileOwnedByCurrentProcess(receiptInfo) {
			return nil, ErrInvalidStatePath
		}
	}
	if err := validateStatePath(absolute+".lock", true); err != nil {
		return nil, err
	}
	lock, err := filelock.Acquire(absolute + ".lock")
	if err != nil {
		if errors.Is(err, filelock.ErrLocked) {
			return nil, ErrStateLocked
		}
		return nil, ErrStatePersistence
	}
	store := &StateFile{path: absolute, parent: parent, receiptRoot: absolute + ".receipts", parentInfo: info, lock: lock}
	if err = store.openReceiptRoot(stateMissing); err != nil {
		_ = lock.Close()
		return nil, err
	}
	if err = store.validateRoot(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	if err = validateStatePath(absolute, true); err != nil {
		_ = lock.Close()
		return nil, err
	}
	if err = store.reclaimTemporary(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return store, nil
}

// InspectStateFile reads a stable protected plan and receipt ledger without filesystem mutation.
func InspectStateFile(ctx context.Context, path string) (Plan, error) {
	if ctx == nil || ctx.Err() != nil || path == "" || !fileOwnershipSupported() {
		return Plan{}, ErrInvalidStatePath
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Plan{}, ErrInvalidStatePath
	}
	parent := filepath.Dir(absolute)
	if fileauthority.CheckDirectory(parent) != nil {
		return Plan{}, ErrInvalidStatePath
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o022 != 0 {
		return Plan{}, ErrInvalidStatePath
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return Plan{}, ErrInvalidStatePath
	}
	if _, err = os.Lstat(absolute); errors.Is(err, os.ErrNotExist) {
		return Plan{}, ErrStateNotFound
	}
	if err != nil {
		return Plan{}, ErrInvalidStatePath
	}
	if err = validateStatePath(absolute, false); err != nil {
		return Plan{}, err
	}
	receiptRoot := absolute + ".receipts"
	receiptInfo, err := os.Lstat(receiptRoot)
	if err != nil || !receiptInfo.IsDir() || receiptInfo.Mode()&os.ModeSymlink != 0 || receiptInfo.Mode().Perm()&0o077 != 0 || !fileOwnedByCurrentProcess(receiptInfo) {
		return Plan{}, ErrInvalidStatePath
	}
	reader := &StateFile{path: absolute, parent: parent, receiptRoot: receiptRoot, parentInfo: parentInfo, receiptRootInfo: receiptInfo}
	first, err := reader.readCurrent()
	if err != nil {
		return Plan{}, err
	}
	if ctx.Err() != nil {
		return Plan{}, ErrStatePersistence
	}
	second, err := reader.readCurrent()
	if err != nil {
		return Plan{}, err
	}
	if first.Identity() != second.Identity() {
		return Plan{}, ErrStateConflict
	}
	return second, nil
}

// Initialize durably creates the first plan without overwriting state.
func (s *StateFile) Initialize(ctx context.Context, plan Plan) error {
	if s == nil {
		return ErrInvalidStatePath
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateOperation(ctx); err != nil {
		return err
	}
	if plan.Validate() != nil || plan.revision != 1 || plan.previousIdentity != "" {
		return ErrInvalidPlan
	}
	if err := validateStatePath(s.path, true); err != nil {
		return err
	}
	if _, err := os.Lstat(s.path); err == nil {
		return ErrStateConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrStatePersistence
	}
	entries, err := os.ReadDir(s.receiptRoot)
	if err != nil {
		return ErrStatePersistence
	}
	if len(entries) != 0 {
		return ErrStateConflict
	}
	encoded, err := EncodePlan(plan)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrStatePersistence
	}
	return s.writeExclusive(encoded)
}

// Current reads and reconstructs the current plan revision.
func (s *StateFile) Current(ctx context.Context) (Plan, error) {
	if s == nil {
		return Plan{}, ErrInvalidStatePath
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateOperation(ctx); err != nil {
		return Plan{}, err
	}
	return s.readCurrent()
}

// PendingReceipt returns one durable receipt whose plan replacement was interrupted.
func (s *StateFile) PendingReceipt(ctx context.Context) (CheckReceipt, bool, error) {
	if s == nil {
		return CheckReceipt{}, false, ErrInvalidStatePath
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateOperation(ctx); err != nil {
		return CheckReceipt{}, false, err
	}
	current, err := s.readCurrent()
	if err != nil {
		return CheckReceipt{}, false, err
	}
	orphan, err := s.verifyReceiptLedger(current)
	if err != nil {
		return CheckReceipt{}, false, err
	}
	if orphan == nil {
		return CheckReceipt{}, false, nil
	}
	return *orphan, true, nil
}

// Apply verifies and atomically persists one approved setup-check transition.
func (s *StateFile) applyReceipt(ctx context.Context, receipt CheckReceipt, catalog CheckerCatalog) (Plan, error) {
	if s == nil {
		return Plan{}, ErrInvalidStatePath
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateOperation(ctx); err != nil {
		return Plan{}, err
	}
	current, err := s.readCurrent()
	if err != nil {
		return Plan{}, err
	}
	orphan, err := s.verifyReceiptLedger(current)
	if err != nil {
		return Plan{}, err
	}
	if orphan != nil && orphan.Identity() != receipt.Identity() {
		return Plan{}, ErrStateConflict
	}
	next, err := applyCheckReceipt(current, receipt, catalog)
	if err != nil {
		return Plan{}, err
	}
	encoded, err := EncodePlan(next)
	if err != nil {
		return Plan{}, err
	}
	if err = s.persistReceipt(next.revision, receipt); err != nil {
		return Plan{}, err
	}
	temporaryPath := s.path + ".next"
	temporary, err := os.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Plan{}, ErrStatePersistence
	}
	renamed := false
	defer func() {
		_ = temporary.Close()
		if !renamed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(0o600); err != nil {
		return Plan{}, ErrStatePersistence
	}
	if _, err = temporary.Write(encoded); err != nil {
		return Plan{}, ErrStatePersistence
	}
	if err = temporary.Sync(); err != nil {
		return Plan{}, ErrStatePersistence
	}
	if err = temporary.Close(); err != nil {
		return Plan{}, ErrStatePersistence
	}
	if ctx.Err() != nil {
		return Plan{}, ErrStatePersistence
	}
	if err = s.validateRoot(); err != nil {
		return Plan{}, err
	}
	currentAgain, err := s.readCurrent()
	if err != nil || currentAgain.identity != current.identity {
		return Plan{}, ErrStateConflict
	}
	if err = os.Rename(temporaryPath, s.path); err != nil {
		return Plan{}, ErrStatePersistence
	}
	renamed = true
	if err = syncSetupDirectory(s.parent); err != nil {
		return Plan{}, err
	}
	if err = validateStatePath(s.path, false); err != nil {
		return Plan{}, err
	}
	return next, nil
}

// Close releases the exclusive writer lock.
func (s *StateFile) Close() error {
	if s == nil {
		return ErrInvalidStatePath
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.lock == nil {
		return ErrInvalidStatePath
	}
	if err := s.lock.Close(); err != nil {
		return ErrStatePersistence
	}
	return nil
}
func (s *StateFile) readCurrent() (Plan, error) {
	plan, err := s.readPlan()
	if err != nil {
		return Plan{}, err
	}
	if _, err = s.verifyReceiptLedger(plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}
func (s *StateFile) readPlan() (Plan, error) {
	if err := s.validateRoot(); err != nil {
		return Plan{}, err
	}
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Plan{}, ErrStateNotFound
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !fileOwnedByCurrentProcess(info) {
		return Plan{}, ErrInvalidStatePath
	}
	file, err := os.Open(s.path)
	if err != nil {
		return Plan{}, ErrStatePersistence
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return Plan{}, ErrInvalidStatePath
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxSetupStateBytes+1))
	if err != nil {
		return Plan{}, ErrStatePersistence
	}
	if len(encoded) == 0 || len(encoded) >= maxSetupStateBytes {
		return Plan{}, ErrCorruptState
	}
	plan, err := DecodePlan(encoded)
	if err != nil {
		return Plan{}, ErrCorruptState
	}
	return plan, nil
}
func (s *StateFile) writeExclusive(encoded []byte) error {
	if err := s.validateRoot(); err != nil {
		return err
	}
	staging := s.path + ".next"
	file, err := os.OpenFile(staging, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrStateConflict
		}
		return ErrStatePersistence
	}
	defer file.Close()
	opened, err := file.Stat()
	pathInfo, pathErr := os.Lstat(staging)
	if err != nil || pathErr != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 || !fileOwnedByCurrentProcess(opened) || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, pathInfo) {
		return ErrInvalidStatePath
	}
	written, err := file.Write(encoded)
	if err != nil || written != len(encoded) {
		return ErrStatePersistence
	}
	if err = file.Sync(); err != nil {
		return ErrStatePersistence
	}
	if err = file.Close(); err != nil {
		return ErrStatePersistence
	}
	if err = s.validateRoot(); err != nil {
		return err
	}
	again, err := os.Lstat(staging)
	if err != nil || !again.Mode().IsRegular() || again.Mode().Perm()&0o077 != 0 || !fileOwnedByCurrentProcess(again) || !os.SameFile(opened, again) {
		return ErrInvalidStatePath
	}
	if err = os.Link(staging, s.path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrStateConflict
		}
		return ErrStatePersistence
	}
	if err = syncSetupDirectory(s.parent); err != nil {
		return err
	}
	return s.reclaimPlanTemporary()
}

func (s *StateFile) openReceiptRoot(allowCreate bool) error {
	info, err := os.Lstat(s.receiptRoot)
	if errors.Is(err, os.ErrNotExist) {
		if !allowCreate {
			return ErrInvalidStatePath
		}
		if err = os.Mkdir(s.receiptRoot, 0o700); err != nil {
			return ErrStatePersistence
		}
		if err = syncSetupDirectory(s.parent); err != nil {
			return err
		}
		info, err = os.Lstat(s.receiptRoot)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !fileOwnedByCurrentProcess(info) {
		return ErrInvalidStatePath
	}
	s.receiptRootInfo = info
	return nil
}
func receiptRecordName(revision uint64, identity string) string {
	return fmt.Sprintf("%020d-%s.receipt.json", revision, identity)
}
func (s *StateFile) persistReceipt(revision uint64, receipt CheckReceipt) error {
	if s == nil || s.closed || s.lock == nil {
		return ErrInvalidStatePath
	}
	if err := s.validateRoot(); err != nil {
		return err
	}
	encoded, err := EncodeCheckReceipt(receipt)
	if err != nil {
		return err
	}
	if revision < 2 {
		return ErrStateConflict
	}
	path := filepath.Join(s.receiptRoot, receiptRecordName(revision, receipt.Identity()))
	if _, err = os.Lstat(path); err == nil {
		existing, readErr := s.readReceipt(path)
		if readErr != nil || existing.Identity() != receipt.Identity() {
			return ErrStateConflict
		}
		return syncSetupDirectory(s.receiptRoot)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrStatePersistence
	}
	staging := path + ".next"
	file, err := os.OpenFile(staging, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrStatePersistence
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return ErrStatePersistence
	}
	// Failed writes remain staging, never committed evidence.
	if n, writeErr := file.Write(encoded); writeErr != nil || n != len(encoded) {
		return ErrStatePersistence
	}
	if err = file.Sync(); err != nil {
		return ErrStatePersistence
	}
	if err = file.Close(); err != nil {
		return ErrStatePersistence
	}
	if err = s.validateRoot(); err != nil {
		return err
	}
	stagedInfo, err := protectedReceiptStaging(staging)
	if err != nil || !os.SameFile(opened, stagedInfo) {
		return ErrInvalidStatePath
	}
	// A hard link installs the complete inode without replacing an existing name.
	if err = os.Link(staging, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return ErrStatePersistence
		}
		existing, readErr := s.readReceipt(path)
		if readErr != nil || existing.Identity() != receipt.Identity() {
			return ErrStateConflict
		}
	}
	if err = syncSetupDirectory(s.receiptRoot); err != nil {
		return err
	}
	if err = s.removeReceiptStaging(staging, stagedInfo); err != nil {
		return err
	}
	return syncSetupDirectory(s.receiptRoot)
}
func (s *StateFile) readReceipt(path string) (CheckReceipt, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !fileOwnedByCurrentProcess(info) {
		return CheckReceipt{}, ErrCorruptState
	}
	file, err := os.Open(path)
	if err != nil {
		return CheckReceipt{}, ErrStatePersistence
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return CheckReceipt{}, ErrCorruptState
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxSetupStateBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) >= maxSetupStateBytes {
		return CheckReceipt{}, ErrCorruptState
	}
	receipt, err := DecodeCheckReceipt(encoded)
	if err != nil {
		return CheckReceipt{}, ErrCorruptState
	}
	return receipt, nil
}
func (s *StateFile) verifyReceiptLedger(plan Plan) (*CheckReceipt, error) {
	entries, err := os.ReadDir(s.receiptRoot)
	if err != nil {
		return nil, ErrStatePersistence
	}
	staging, err := s.receiptStagingFiles(&plan)
	if err != nil {
		return nil, err
	}
	if len(entries)-len(staging) > len(plan.receipts)+1 {
		return nil, ErrCorruptState
	}
	expected := make(map[string]CheckReceipt, len(plan.receipts))
	for index, receipt := range plan.receipts {
		expected[receiptRecordName(uint64(index)+2, receipt.Identity())] = receipt
	}
	var orphan *CheckReceipt
	for _, entry := range entries {
		if _, temporary := staging[entry.Name()]; temporary {
			continue
		}
		if entry.IsDir() {
			return nil, ErrCorruptState
		}
		if want, ok := expected[entry.Name()]; ok {
			got, readErr := s.readReceipt(filepath.Join(s.receiptRoot, entry.Name()))
			if readErr != nil || got.Identity() != want.Identity() {
				return nil, ErrCorruptState
			}
			delete(expected, entry.Name())
			continue
		}
		got, readErr := s.readReceipt(filepath.Join(s.receiptRoot, entry.Name()))
		if readErr != nil || entry.Name() != receiptRecordName(plan.revision+1, got.Identity()) || got.PlanIdentity() != plan.Identity() || !got.CheckedAt().After(plan.UpdatedAt()) {
			return nil, ErrCorruptState
		}
		approved, ok := plan.checkerCatalog.Resolve(got.Key())
		if !ok || approved != got.CheckerIdentity() || orphan != nil {
			return nil, ErrCorruptState
		}
		copy := got
		orphan = &copy
	}
	if len(expected) != 0 {
		return nil, ErrCorruptState
	}
	return orphan, nil
}

func parseReceiptRecordName(name string) (uint64, string, bool) {
	if len(name) != 20+1+64+len(".receipt.json") || name[20] != '-' || !strings.HasSuffix(name, ".receipt.json") {
		return 0, "", false
	}
	revision, err := strconv.ParseUint(name[:20], 10, 64)
	identity := name[21:85]
	if err != nil || revision < 2 || !nonzeroSetupDigest(identity) || strings.ToLower(identity) != identity || receiptRecordName(revision, identity) != name {
		return 0, "", false
	}
	return revision, identity, true
}

func protectedReceiptStaging(path string) (os.FileInfo, error) {
	if err := validateStatePath(path, false); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, ErrInvalidStatePath
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalidStatePath
	}
	opened, statErr := file.Stat()
	closeErr := file.Close()
	again, pathErr := os.Lstat(path)
	if statErr != nil || closeErr != nil || pathErr != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 || !fileOwnedByCurrentProcess(opened) || !os.SameFile(info, opened) || !os.SameFile(opened, again) || again.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidStatePath
	}
	return opened, nil
}

func (s *StateFile) receiptStagingFiles(plan *Plan) (map[string]os.FileInfo, error) {
	entries, err := os.ReadDir(s.receiptRoot)
	if err != nil {
		return nil, ErrStatePersistence
	}
	staging := make(map[string]os.FileInfo)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".next") {
			continue
		}
		if _, _, ok := parseReceiptRecordName(strings.TrimSuffix(entry.Name(), ".next")); !ok {
			return nil, ErrCorruptState
		}
		info, err := protectedReceiptStaging(filepath.Join(s.receiptRoot, entry.Name()))
		if err != nil {
			return nil, err
		}
		staging[entry.Name()] = info
	}
	if len(staging) == 0 {
		return staging, nil
	}
	if len(staging) != 1 {
		return nil, ErrCorruptState
	}
	expected := make(map[string]CheckReceipt)
	pendingRevision := uint64(2)
	if plan != nil {
		pendingRevision = plan.revision + 1
		for index, receipt := range plan.receipts {
			expected[receiptRecordName(uint64(index)+2, receipt.Identity())] = receipt
		}
	} else {
		// Before a restored plan exists, only a contiguous installed prefix is known.
		for _, entry := range entries {
			if _, temporary := staging[entry.Name()]; temporary {
				continue
			}
			revision, identity, ok := parseReceiptRecordName(entry.Name())
			if !ok || revision != pendingRevision {
				return nil, ErrCorruptState
			}
			receipt, err := s.readReceipt(filepath.Join(s.receiptRoot, entry.Name()))
			if err != nil || receipt.Identity() != identity {
				return nil, ErrCorruptState
			}
			expected[entry.Name()] = receipt
			pendingRevision++
		}
	}
	for name := range staging {
		finalName := strings.TrimSuffix(name, ".next")
		revision, identity, _ := parseReceiptRecordName(finalName)
		if want, installed := expected[finalName]; installed {
			got, err := s.readReceipt(filepath.Join(s.receiptRoot, finalName))
			if err != nil || got.Identity() != want.Identity() {
				return nil, ErrCorruptState
			}
			continue
		}
		if revision != pendingRevision {
			return nil, ErrCorruptState
		}
		finalPath := filepath.Join(s.receiptRoot, finalName)
		if _, err := os.Lstat(finalPath); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, ErrCorruptState
		}
		got, err := s.readReceipt(finalPath)
		if err != nil || got.Identity() != identity || plan == nil || got.PlanIdentity() != plan.Identity() || !got.CheckedAt().After(plan.UpdatedAt()) {
			return nil, ErrCorruptState
		}
		approved, ok := plan.checkerCatalog.Resolve(got.Key())
		if !ok || approved != got.CheckerIdentity() {
			return nil, ErrCorruptState
		}
	}
	return staging, nil
}

func (s *StateFile) removeReceiptStaging(path string, expected os.FileInfo) error {
	if s.closed || s.lock == nil {
		return ErrInvalidStatePath
	}
	if err := s.validateRoot(); err != nil {
		return err
	}
	info, err := protectedReceiptStaging(path)
	if err != nil || !os.SameFile(expected, info) {
		return ErrInvalidStatePath
	}
	if err = os.Remove(path); err != nil {
		return ErrStatePersistence
	}
	return nil
}

func (s *StateFile) reclaimTemporary() error {
	if err := s.reclaimPlanTemporary(); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.receiptRoot)
	if err != nil {
		return ErrStatePersistence
	}
	hasStaging := false
	for _, entry := range entries {
		hasStaging = hasStaging || strings.HasSuffix(entry.Name(), ".next")
	}
	if !hasStaging {
		return nil
	}
	var current *Plan
	plan, err := s.readPlan()
	if err == nil {
		current = &plan
		if _, err = s.verifyReceiptLedger(plan); err != nil {
			return err
		}
	} else if !errors.Is(err, ErrStateNotFound) {
		return err
	}
	staging, err := s.receiptStagingFiles(current)
	if err != nil {
		return err
	}
	for name, info := range staging {
		if err = s.removeReceiptStaging(filepath.Join(s.receiptRoot, name), info); err != nil {
			return err
		}
	}
	return syncSetupDirectory(s.receiptRoot)
}

func (s *StateFile) reclaimPlanTemporary() error {
	path := s.path + ".next"
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !fileOwnedByCurrentProcess(info) {
		return ErrInvalidStatePath
	}
	if err = os.Remove(path); err != nil {
		return ErrStatePersistence
	}
	return syncSetupDirectory(s.parent)
}

func (s *StateFile) validateOperation(ctx context.Context) error {
	if s == nil || s.closed || s.lock == nil {
		return ErrInvalidStatePath
	}
	if ctx == nil || ctx.Err() != nil {
		return ErrStatePersistence
	}
	return s.validateRoot()
}
func (s *StateFile) validateRoot() error {
	if fileauthority.CheckDirectory(s.parent) != nil {
		return ErrInvalidStatePath
	}
	info, err := os.Lstat(s.parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || !os.SameFile(info, s.parentInfo) {
		return ErrInvalidStatePath
	}
	receipts, err := os.Lstat(s.receiptRoot)
	if err != nil || !receipts.IsDir() || receipts.Mode()&os.ModeSymlink != 0 || receipts.Mode().Perm()&0o077 != 0 || s.receiptRootInfo == nil || !os.SameFile(receipts, s.receiptRootInfo) || !fileOwnedByCurrentProcess(receipts) {
		return ErrInvalidStatePath
	}
	return nil
}
func validateStatePath(path string, allowMissing bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !fileOwnedByCurrentProcess(info) {
		return ErrInvalidStatePath
	}
	return nil
}
func syncSetupDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return ErrStatePersistence
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return ErrStatePersistence
	}
	return nil
}
func (s *StateFile) String() string   { return "setup state file" }
func (s *StateFile) GoString() string { return "setup.StateFile{<redacted>}" }
func (s *StateFile) Format(state fmt.State, verb rune) {
	value := s.String()
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = s.GoString()
	}
	_, _ = state.Write([]byte(value))
}
