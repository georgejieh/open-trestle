package controlplane

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/filelock"
)

const (
	runJournalStreamSuffix    = ".run.jsonl"
	runJournalPlanSuffix      = ".run-plan.json"
	runJournalWriterLockName  = ".run-writer.lock"
	maxRunJournalStreamBytes  = 64 << 20
	maxRunJournalStreamEvents = 10_000
)

var (
	// ErrInvalidRunJournalRoot identifies an empty, non-directory, or symlinked root.
	ErrInvalidRunJournalRoot = errors.New("invalid run journal root")
	// ErrRunJournalLocked identifies a root already owned by a writer.
	ErrRunJournalLocked = errors.New("run journal locked")
	// ErrRunJournalClosed identifies use after releasing the writer lease.
	ErrRunJournalClosed = errors.New("run journal closed")
	// ErrInvalidRunJournalEffectSection identifies a missing effect callback.
	ErrInvalidRunJournalEffectSection = errors.New("invalid run journal effect section")
	// ErrCorruptRunJournalStream identifies a malformed or broken event stream.
	ErrCorruptRunJournalStream = errors.New("corrupt run journal stream")
	// ErrRunJournalStreamTooLarge identifies a stream beyond local bounds.
	ErrRunJournalStreamTooLarge = errors.New("run journal stream too large")
	// ErrRunJournalPersistence identifies a failed durable filesystem operation.
	ErrRunJournalPersistence = errors.New("run journal persistence failure")
)

// FileRunJournal is a durable local journal with one exclusive writer per root.
type FileRunJournal struct {
	mu             sync.Mutex
	gateMu         sync.Mutex
	gate           chan struct{}
	closingSignal  chan struct{}
	closing        bool
	root, lockPath string
	lockFile       *filelock.Lock
	// Optional fault-injection seams; production uses syncRoot and lockFile.Close.
	syncOnClose         func() error
	closeLock           func(*filelock.Lock) error
	onContendedGateWait func() // test observer, set before concurrent use only
	closed              bool
}

// NewFileRunJournal creates a private root and acquires its exclusive writer lease.
func NewFileRunJournal(root string) (*FileRunJournal, error) {
	if root == "" {
		return nil, ErrInvalidRunJournalRoot
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRunJournalRoot, err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	information, err := os.Lstat(absolute)
	if err != nil || !information.IsDir() || information.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidRunJournalRoot
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	lockPath := filepath.Join(absolute, runJournalWriterLockName)
	lockFile, err := filelock.Acquire(lockPath)
	if errors.Is(err, filelock.ErrLocked) {
		return nil, ErrRunJournalLocked
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	journal := &FileRunJournal{
		root: absolute, lockPath: lockPath, lockFile: lockFile,
		gate: make(chan struct{}, 1), closingSignal: make(chan struct{}),
	}
	journal.gate <- struct{}{}
	if err := journal.syncRoot(); err != nil {
		_ = lockFile.Close()
		return nil, err
	}
	return journal, nil
}
func (j *FileRunJournal) Close() error {
	if j == nil || j.gate == nil || j.closingSignal == nil {
		return ErrInvalidRunJournal
	}
	j.gateMu.Lock()
	if !j.closing {
		j.closing = true
		close(j.closingSignal)
	}
	j.gateMu.Unlock()
	<-j.gate
	defer func() { j.gate <- struct{}{} }()
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	// Retire the old owner before any fallible filesystem operation or lease release.
	j.closed = true
	// Sync while the writer lease is still held, even when sync fails.
	syncRoot := j.syncOnClose
	if syncRoot == nil {
		syncRoot = j.syncRoot
	}
	syncErr := syncRoot()
	if j.lockFile == nil {
		return syncErr
	}
	closeLock := j.closeLock
	if closeLock == nil {
		closeLock = (*filelock.Lock).Close
	}
	closeErr := closeLock(j.lockFile)
	j.lockFile = nil
	if closeErr != nil {
		closeErr = fmt.Errorf("%w: %v", ErrRunJournalPersistence, closeErr)
	}
	return errors.Join(syncErr, closeErr)
}

// WithEffectSection serializes a local synchronous effect with cancellation appends.
// The section is non-reentrant: the callback must not call Close, append a
// cancellation, or nest another WithEffectSection on this journal.
func (j *FileRunJournal) WithEffectSection(ctx context.Context, effect func() error) error {
	if j == nil || j.gate == nil || j.closingSignal == nil {
		return ErrInvalidRunJournal
	}
	if effect == nil {
		return ErrInvalidRunJournalEffectSection
	}
	if err := validateFileRunContext(ctx); err != nil {
		return err
	}
	return j.withEffectSection(ctx, effect)
}

func (j *FileRunJournal) withEffectSection(ctx context.Context, effect func() error) error {
	// An unbounded caller context must not leave a gate waiter stuck forever.
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// A test observer only acknowledges a real contended acquisition. It must
	// not block or change the gate, and must be installed before concurrent use.
	select {
	case <-j.gate:
	default:
		if j.onContendedGateWait != nil {
			j.onContendedGateWait()
		}
		select {
		case <-waitCtx.Done():
			return ErrRunJournalContextDone
		case <-j.closingSignal:
			return ErrRunJournalClosed
		case <-j.gate:
		}
	}
	defer func() { j.gate <- struct{}{} }()
	j.gateMu.Lock()
	closing := j.closing
	j.gateMu.Unlock()
	if closing {
		return ErrRunJournalClosed
	}
	if err := fileRunContextDone(waitCtx); err != nil {
		return err
	}
	return effect()
}

func (j *FileRunJournal) SavePlan(ctx context.Context, plan ReviewRunPlan) error {
	if j == nil {
		return ErrInvalidRunJournal
	}
	if err := validateFileRunContext(ctx); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrRunJournalClosed
	}
	existing, found, err := j.loadPlan(plan.Scope())
	if err != nil {
		return err
	}
	if found {
		if existing.Identity() == plan.Identity() {
			return nil
		}
		return ErrRunPlanConflict
	}
	stream, err := j.loadStream(plan.Scope())
	if err != nil {
		return err
	}
	if len(stream) != 0 && stream[0].PlanIdentity() != plan.Identity() {
		return ErrRunPlanConflict
	}
	return j.replacePlan(ctx, plan)
}
func (j *FileRunJournal) LoadPlan(ctx context.Context, scope audit.ReviewScope) (ReviewRunPlan, bool, error) {
	if j == nil {
		return ReviewRunPlan{}, false, ErrInvalidRunJournal
	}
	if err := validateFileRunContext(ctx); err != nil {
		return ReviewRunPlan{}, false, err
	}
	if err := scope.Validate(); err != nil {
		return ReviewRunPlan{}, false, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ReviewRunPlan{}, false, ErrRunJournalClosed
	}
	return j.loadPlan(scope)
}
func (j *FileRunJournal) planPath(scope audit.ReviewScope) string {
	return filepath.Join(j.root, scope.Identity()+runJournalPlanSuffix)
}
func (j *FileRunJournal) loadPlan(scope audit.ReviewScope) (ReviewRunPlan, bool, error) {
	path := j.planPath(scope)
	information, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ReviewRunPlan{}, false, nil
	}
	if err != nil {
		return ReviewRunPlan{}, false, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	if information.Mode()&os.ModeSymlink != 0 || !information.Mode().IsRegular() || information.Mode().Perm()&0o077 != 0 || information.Size() <= 0 || information.Size() > maxEncodedReviewRunPlanBytes {
		return ReviewRunPlan{}, false, ErrInvalidReviewRunPlanEncoding
	}
	file, err := os.Open(path)
	if err != nil {
		return ReviewRunPlan{}, false, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxEncodedReviewRunPlanBytes+1))
	if err != nil || len(content) > maxEncodedReviewRunPlanBytes {
		return ReviewRunPlan{}, false, ErrInvalidReviewRunPlanEncoding
	}
	plan, err := ParseReviewRunPlan(content)
	if err != nil || plan.Scope().Identity() != scope.Identity() {
		return ReviewRunPlan{}, false, ErrInvalidReviewRunPlanEncoding
	}
	return plan, true, nil
}
func (j *FileRunJournal) replacePlan(ctx context.Context, plan ReviewRunPlan) error {
	encoded, err := EncodeReviewRunPlan(plan)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(j.root, ".plan-write-*")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
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
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	if err := fileRunContextDone(ctx); err != nil {
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	if err := os.Rename(temporaryPath, j.planPath(plan.Scope())); err != nil {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	cleaned = true
	return j.syncRoot()
}

func (j *FileRunJournal) ListPlans(ctx context.Context, tenantID, repositoryID, afterRunID string, limit int) ([]ReviewRunPlan, error) {
	if j == nil {
		return nil, ErrInvalidRunJournal
	}
	if err := validateFileRunContext(ctx); err != nil {
		return nil, err
	}
	if !validRunPlanQuery(tenantID) || !validRunPlanQuery(repositoryID) || afterRunID != "" && !validRunPlanQuery(afterRunID) || limit <= 0 || limit > maxRunJournalReadLimit {
		return nil, ErrInvalidRunPlanQuery
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil, ErrRunJournalClosed
	}
	entries, err := os.ReadDir(j.root)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	if len(entries) > maxRunJournalStreamEvents*2+1 {
		return nil, ErrRunJournalStreamTooLarge
	}
	plans := make([]ReviewRunPlan, 0)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), runJournalPlanSuffix) {
			continue
		}
		path := filepath.Join(j.root, entry.Name())
		information, err := entry.Info()
		if err != nil || entry.Type()&os.ModeSymlink != 0 || !information.Mode().IsRegular() || information.Mode().Perm()&0o077 != 0 {
			return nil, ErrInvalidReviewRunPlanEncoding
		}
		content, err := os.ReadFile(path)
		if err != nil || len(content) > maxEncodedReviewRunPlanBytes {
			return nil, ErrInvalidReviewRunPlanEncoding
		}
		plan, err := ParseReviewRunPlan(content)
		if err != nil {
			return nil, err
		}
		if plan.Scope().TenantID() == tenantID && plan.Scope().RepositoryID() == repositoryID && plan.Scope().ReviewRunID() > afterRunID {
			plans = append(plans, plan)
		}
	}
	sort.Slice(plans, func(i, j int) bool { return plans[i].Scope().ReviewRunID() < plans[j].Scope().ReviewRunID() })
	if len(plans) > limit {
		plans = plans[:limit]
	}
	return plans, nil
}

func (j *FileRunJournal) Append(ctx context.Context, expectedHead string, event RunEvent) error {
	if j == nil || j.gate == nil || j.closingSignal == nil {
		return ErrInvalidRunJournal
	}
	if err := validateFileRunContext(ctx); err != nil {
		return err
	}
	if expectedHead != "" && !validControlPlaneDigest(expectedHead) {
		return ErrRunJournalHeadConflict
	}
	if err := event.Validate(); err != nil {
		return err
	}
	if event.Kind() == RunEventCanceled {
		return j.withEffectSection(ctx, func() error { return j.appendValidated(ctx, expectedHead, event) })
	}
	return j.appendValidated(ctx, expectedHead, event)
}

func (j *FileRunJournal) appendValidated(ctx context.Context, expectedHead string, event RunEvent) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrRunJournalClosed
	}
	if err := fileRunContextDone(ctx); err != nil {
		return err
	}
	stream, err := j.loadStream(event.Scope())
	if err != nil {
		return err
	}
	plan, planFound, err := j.loadPlan(event.Scope())
	if err != nil {
		return err
	}
	if planFound && plan.Identity() != event.PlanIdentity() {
		return ErrRunPlanConflict
	}
	if len(stream) > 0 && stream[0].PlanIdentity() != event.PlanIdentity() {
		return ErrRunPlanConflict
	}
	if len(stream) > 0 && stream[len(stream)-1].Identity() == event.Identity() {
		return nil
	}
	currentHead := ""
	if len(stream) > 0 {
		currentHead = stream[len(stream)-1].Identity()
	}
	if expectedHead != currentHead {
		return ErrRunJournalHeadConflict
	}
	if event.Sequence() != uint64(len(stream)+1) {
		return ErrRunJournalSequenceMismatch
	}
	if event.PreviousIdentity() != currentHead {
		return ErrRunJournalChainMismatch
	}
	if len(stream) >= maxRunJournalStreamEvents {
		return ErrRunJournalStreamTooLarge
	}
	return j.replaceStream(ctx, event.Scope(), append(stream, event))
}
func (j *FileRunJournal) Head(ctx context.Context, scope audit.ReviewScope) (RunEvent, bool, error) {
	if j == nil {
		return RunEvent{}, false, ErrInvalidRunJournal
	}
	if err := validateFileRunContext(ctx); err != nil {
		return RunEvent{}, false, err
	}
	if err := scope.Validate(); err != nil {
		return RunEvent{}, false, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return RunEvent{}, false, ErrRunJournalClosed
	}
	stream, err := j.loadStream(scope)
	if err != nil {
		return RunEvent{}, false, err
	}
	if len(stream) == 0 {
		return RunEvent{}, false, nil
	}
	return stream[len(stream)-1], true, nil
}
func (j *FileRunJournal) Read(ctx context.Context, scope audit.ReviewScope, after uint64, limit int) ([]RunEvent, error) {
	if j == nil {
		return nil, ErrInvalidRunJournal
	}
	if err := validateFileRunContext(ctx); err != nil {
		return nil, err
	}
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > maxRunJournalReadLimit {
		return nil, ErrInvalidRunJournalReadLimit
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil, ErrRunJournalClosed
	}
	stream, err := j.loadStream(scope)
	if err != nil {
		return nil, err
	}
	if after >= uint64(len(stream)) {
		return []RunEvent{}, nil
	}
	start := int(after)
	end := min(start+limit, len(stream))
	return append([]RunEvent(nil), stream[start:end]...), nil
}
func (j *FileRunJournal) streamPath(scope audit.ReviewScope) string {
	return filepath.Join(j.root, scope.Identity()+runJournalStreamSuffix)
}
func (j *FileRunJournal) loadStream(scope audit.ReviewScope) ([]RunEvent, error) {
	path := j.streamPath(scope)
	information, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	if information.Mode()&os.ModeSymlink != 0 || !information.Mode().IsRegular() {
		return nil, ErrCorruptRunJournalStream
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	defer file.Close()
	information, err = file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	if !information.Mode().IsRegular() || information.Mode().Perm()&0o077 != 0 {
		return nil, ErrCorruptRunJournalStream
	}
	if information.Size() <= 0 || information.Size() > maxRunJournalStreamBytes {
		return nil, ErrRunJournalStreamTooLarge
	}
	if _, err := file.Seek(-1, io.SeekEnd); err != nil {
		return nil, ErrCorruptRunJournalStream
	}
	last := []byte{0}
	if _, err := io.ReadFull(file, last); err != nil || last[0] != '\n' {
		return nil, ErrCorruptRunJournalStream
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4<<10), maxEncodedRunEventV3Bytes+1)
	events := make([]RunEvent, 0, 64)
	previous, planIdentity := "", ""
	var occurredAt int64
	for scanner.Scan() {
		if len(events) >= maxRunJournalStreamEvents {
			return nil, ErrRunJournalStreamTooLarge
		}
		event, err := ParseRunEvent(scanner.Bytes())
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCorruptRunJournalStream, err)
		}
		if len(events) == 0 {
			planIdentity = event.PlanIdentity()
		}
		matchingScope := event.Scope().Identity() == scope.Identity()
		matchingPlan := event.PlanIdentity() == planIdentity
		matchingSequence := event.Sequence() == uint64(len(events)+1)
		matchingPrevious := event.PreviousIdentity() == previous
		monotonicTime := event.occurredAtMillis >= occurredAt
		if !matchingScope || !matchingPlan || !matchingSequence || !matchingPrevious || !monotonicTime {
			return nil, ErrCorruptRunJournalStream
		}
		events = append(events, event)
		previous = event.Identity()
		occurredAt = event.occurredAtMillis
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptRunJournalStream, err)
	}
	return events, nil
}
func (j *FileRunJournal) replaceStream(ctx context.Context, scope audit.ReviewScope, events []RunEvent) error {
	encodedEvents := make([][]byte, len(events))
	total := 0
	for index, event := range events {
		encoded, err := EncodeRunEvent(event)
		if err != nil {
			return err
		}
		total += len(encoded) + 1
		if total > maxRunJournalStreamBytes {
			return ErrRunJournalStreamTooLarge
		}
		encodedEvents[index] = encoded
	}
	temporary, err := os.CreateTemp(j.root, ".run-write-*")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
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
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	writer := bufio.NewWriter(temporary)
	for _, encoded := range encodedEvents {
		if err := fileRunContextDone(ctx); err != nil {
			return err
		}
		if _, err := writer.Write(encoded); err != nil {
			return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
		}
		if err := writer.WriteByte('\n'); err != nil {
			return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	if err := os.Rename(temporaryPath, j.streamPath(scope)); err != nil {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	cleaned = true
	return j.syncRoot()
}
func (j *FileRunJournal) syncRoot() error {
	directory, err := os.Open(j.root)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	return nil
}
func validateFileRunContext(ctx context.Context) error {
	if isNilRunJournalContext(ctx) {
		return ErrInvalidRunJournalContext
	}
	return fileRunContextDone(ctx)
}
func fileRunContextDone(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return ErrRunJournalContextDone
	}
	return nil
}

var _ RunJournal = (*FileRunJournal)(nil)
