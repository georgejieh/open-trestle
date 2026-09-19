package audit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/georgejieh/open-trestle/internal/filelock"
)

const (
	auditStreamFileSuffix = ".audit.jsonl"
	auditWriterLockName   = ".writer.lock"
	maxAuditStreamBytes   = 64 << 20
	maxAuditStreamEvents  = 10_000
)

var (
	// ErrInvalidAuditLedgerRoot identifies an empty, non-directory, symlinked, or broadly accessible ledger directory.
	ErrInvalidAuditLedgerRoot = errors.New("invalid audit ledger root")
	// ErrAuditLedgerLocked identifies a directory already owned by a writer or left locked after an unclean stop.
	ErrAuditLedgerLocked = errors.New("audit ledger locked")
	// ErrAuditLedgerClosed identifies use after the writer lease was released.
	ErrAuditLedgerClosed = errors.New("audit ledger closed")
	// ErrCorruptAuditStream identifies a malformed, noncanonical, cross-scoped, or broken event chain.
	ErrCorruptAuditStream = errors.New("corrupt audit stream")
	// ErrAuditStreamTooLarge identifies a review stream beyond the local file-ledger bound.
	ErrAuditStreamTooLarge = errors.New("audit stream too large")
	// ErrAuditPersistence identifies a failed durable filesystem operation.
	ErrAuditPersistence = errors.New("audit persistence failure")
)

// FileLedger is a durable local ledger with one exclusive writer lease per root.
// The process-owned lease is reclaimed after a confirmed owner exit.
type FileLedger struct {
	mu     sync.Mutex
	root   string
	lock   *filelock.Lock
	closed bool
}

// NewFileLedger opens or creates a private ledger directory and acquires its writer lease.
func NewFileLedger(root string) (*FileLedger, error) {
	if root == "" {
		return nil, ErrInvalidAuditLedgerRoot
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAuditLedgerRoot, err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	information, err := os.Lstat(absolute)
	if err != nil || !information.IsDir() || information.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidAuditLedgerRoot
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	lock, err := filelock.Acquire(filepath.Join(absolute, auditWriterLockName))
	if errors.Is(err, filelock.ErrLocked) {
		return nil, ErrAuditLedgerLocked
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	ledger := &FileLedger{root: absolute, lock: lock}
	if err := ledger.syncRoot(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return ledger, nil
}

// Close releases the writer lease. It is safe to call more than once.
func (l *FileLedger) Close() error {
	if l == nil {
		return ErrInvalidAuditLedger
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	if l.lock != nil {
		if err := l.lock.Close(); err != nil {
			return fmt.Errorf("%w: %v", ErrAuditPersistence, err)
		}
		l.lock = nil
	}
	l.closed = true
	return l.syncRoot()
}

// Append atomically rewrites one verified scope stream with exactly the next event.
func (l *FileLedger) Append(ctx context.Context, expectedHead string, event Event) error {
	if l == nil {
		return ErrInvalidAuditLedger
	}
	if err := validateAuditContext(ctx); err != nil {
		return err
	}
	if expectedHead != "" && !validAuditIdentity(expectedHead) {
		return ErrInvalidAuditExpectedHead
	}
	if err := event.Validate(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrAuditLedgerClosed
	}
	if err := auditContextDone(ctx); err != nil {
		return err
	}
	stream, err := l.loadStream(event.Scope())
	if err != nil {
		return err
	}
	currentHead := ""
	if len(stream) != 0 {
		currentHead = stream[len(stream)-1].Identity()
	}
	if expectedHead != currentHead {
		return ErrAuditHeadConflict
	}
	if event.Sequence() != uint64(len(stream))+1 || event.PreviousIdentity() != currentHead {
		return ErrAuditChainMismatch
	}
	if len(stream) >= maxAuditStreamEvents {
		return ErrAuditStreamTooLarge
	}
	return l.replaceStream(ctx, event.Scope(), append(stream, cloneEvent(event)))
}

// Head returns the last durably stored event for one exact scope.
func (l *FileLedger) Head(ctx context.Context, scope ReviewScope) (Event, bool, error) {
	if l == nil {
		return Event{}, false, ErrInvalidAuditLedger
	}
	if err := validateAuditContext(ctx); err != nil {
		return Event{}, false, err
	}
	if err := scope.Validate(); err != nil {
		return Event{}, false, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return Event{}, false, ErrAuditLedgerClosed
	}
	stream, err := l.loadStream(scope)
	if err != nil {
		return Event{}, false, err
	}
	if len(stream) == 0 {
		return Event{}, false, nil
	}
	return cloneEvent(stream[len(stream)-1]), true, nil
}

// Read returns a verified bounded page after the supplied sequence.
func (l *FileLedger) Read(ctx context.Context, scope ReviewScope, afterSequence uint64, limit uint16) ([]Event, error) {
	if l == nil {
		return nil, ErrInvalidAuditLedger
	}
	if err := validateAuditContext(ctx); err != nil {
		return nil, err
	}
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if limit == 0 || limit > maxAuditReadEvents {
		return nil, ErrInvalidAuditReadLimit
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, ErrAuditLedgerClosed
	}
	stream, err := l.loadStream(scope)
	if err != nil {
		return nil, err
	}
	if afterSequence >= uint64(len(stream)) {
		return nil, nil
	}
	start := int(afterSequence)
	end := start + int(limit)
	if end > len(stream) {
		end = len(stream)
	}
	result := make([]Event, end-start)
	for index := range result {
		result[index] = cloneEvent(stream[start+index])
	}
	return result, nil
}

func (l *FileLedger) streamPath(scope ReviewScope) string {
	return filepath.Join(l.root, scope.Identity()+auditStreamFileSuffix)
}

func (l *FileLedger) loadStream(scope ReviewScope) ([]Event, error) {
	path := l.streamPath(scope)
	pathInformation, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	if pathInformation.Mode()&os.ModeSymlink != 0 || !pathInformation.Mode().IsRegular() {
		return nil, ErrCorruptAuditStream
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	defer file.Close()
	information, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	if !information.Mode().IsRegular() || information.Mode().Perm()&0o077 != 0 {
		return nil, ErrCorruptAuditStream
	}
	if information.Size() <= 0 || information.Size() > maxAuditStreamBytes {
		return nil, ErrAuditStreamTooLarge
	}
	if _, err := file.Seek(-1, io.SeekEnd); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptAuditStream, err)
	}
	last := []byte{0}
	if _, err := io.ReadFull(file, last); err != nil || last[0] != '\n' {
		return nil, ErrCorruptAuditStream
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4<<10), maxEncodedAuditEventBytes+1)
	events := make([]Event, 0, 64)
	previous := ""
	for scanner.Scan() {
		if len(events) >= maxAuditStreamEvents {
			return nil, ErrAuditStreamTooLarge
		}
		event, err := ParseEvent(scanner.Bytes())
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCorruptAuditStream, err)
		}
		if event.Scope() != scope || event.Sequence() != uint64(len(events))+1 || event.PreviousIdentity() != previous {
			return nil, ErrCorruptAuditStream
		}
		events = append(events, cloneEvent(event))
		previous = event.Identity()
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptAuditStream, err)
	}
	return events, nil
}

func (l *FileLedger) replaceStream(ctx context.Context, scope ReviewScope, events []Event) error {
	encodedEvents := make([][]byte, len(events))
	totalBytes := 0
	for index, event := range events {
		encoded, err := EncodeEvent(event)
		if err != nil {
			return err
		}
		totalBytes += len(encoded) + 1
		if totalBytes > maxAuditStreamBytes {
			return ErrAuditStreamTooLarge
		}
		encodedEvents[index] = encoded
	}
	temporary, err := os.CreateTemp(l.root, ".audit-write-*")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	temporaryPath := temporary.Name()
	cleaned := false
	defer func() {
		_ = temporary.Close()
		if !cleaned {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	writer := bufio.NewWriter(temporary)
	for _, encoded := range encodedEvents {
		if err := auditContextDone(ctx); err != nil {
			return err
		}
		if _, err := writer.Write(encoded); err != nil {
			return fmt.Errorf("%w: %v", ErrAuditPersistence, err)
		}
		if err := writer.WriteByte('\n'); err != nil {
			return fmt.Errorf("%w: %v", ErrAuditPersistence, err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	if err := os.Rename(temporaryPath, l.streamPath(scope)); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	cleaned = true
	return l.syncRoot()
}

func (l *FileLedger) syncRoot() error {
	directory, err := os.Open(l.root)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditPersistence, err)
	}
	return nil
}
