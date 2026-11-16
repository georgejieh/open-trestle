// Rooted historical packet inspection is diagnostic only. It grants no startup authority.
package controlplane

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// HistoricalPacketScan can be called once, synchronously during its owner's callback.
// Its facts are provisional until the callback returns and the second witness passes.
type HistoricalPacketScan func(context.Context, func([]HistoricalContextPacketFact) error) error

var errHistoricalScannerUnavailable = errors.New("historical packet scanner unavailable")
var errHistoricalScannerEscaped = errors.New("historical packet scan escaped callback")
var errHistoricalScannerCallback = errors.New("invalid historical packet scanner callback")

type historicalScannerState uint8

const (
	historicalAvailable historicalScannerState = iota
	historicalRunning
	historicalSpent
)

// WithOwnedHistoricalPacketFacts lends the actual journal root and a one-use
// diagnostic scanner. The borrowed root and scanner must not outlive use.
func (j *FileRunJournal) WithOwnedHistoricalPacketFacts(ctx context.Context, use func(*os.Root, HistoricalPacketScan) error) error {
	if use == nil {
		return ErrInvalidRunJournalEffectSection
	}
	if j == nil {
		return ErrInvalidRunJournal
	}
	return j.WithOwnedRoot(ctx, func(opened *os.Root) (result error) {
		var lifeMu sync.Mutex
		state, active := historicalAvailable, true
		var done chan struct{}
		scan := func(scanCtx context.Context, after func([]HistoricalContextPacketFact) error) (err error) {
			lifeMu.Lock()
			if !active || state != historicalAvailable {
				lifeMu.Unlock()
				return errHistoricalScannerUnavailable
			}
			state, done = historicalRunning, make(chan struct{})
			lifeMu.Unlock()
			defer func() {
				lifeMu.Lock()
				state = historicalSpent
				close(done)
				lifeMu.Unlock()
			}()
			if after == nil {
				return errHistoricalScannerCallback
			}
			if err := validateFileRunContext(scanCtx); err != nil {
				return err
			}
			return j.scanOwnedHistoricalFacts(scanCtx, opened, after)
		}
		defer func() {
			panicValue := recover()
			lifeMu.Lock()
			active = false
			wasRunning, wait := state == historicalRunning, done
			lifeMu.Unlock()
			if wasRunning {
				<-wait
				result = errors.Join(result, errHistoricalScannerEscaped)
			}
			if panicValue != nil {
				panic(panicValue)
			}
		}()
		return use(opened, scan)
	})
}

type rootedEntry struct {
	name string
	info os.FileInfo
}
type rootedLeaf struct {
	entry  rootedEntry
	digest [sha256.Size]byte
}

func rootedSame(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() &&
		fileauthority.TrustedOwner(a) && fileauthority.TrustedOwner(b) &&
		(!a.Mode().IsRegular() || rootedSingleLink(a) && rootedSingleLink(b))
}
func rootedEntryValid(name string, info os.FileInfo) error {
	if info == nil || !fileauthority.TrustedOwner(info) || info.Mode().Perm()&0o077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidStartupInventoryEntry
	}
	mode, size := info.Mode(), info.Size()
	switch name {
	case ".local-source-owner.json":
		if mode != 0o600 || size <= 0 || size > 16<<10 {
			return ErrInvalidStartupInventoryEntry
		}
	case runJournalWriterLockName:
		if mode != 0o600 {
			return ErrInvalidStartupInventoryEntry
		}
	case "artifacts", "audit", "diagnostics", "webhook-inbox", "setup":
		if mode != os.ModeDir|0o700 {
			return ErrInvalidStartupInventoryEntry
		}
		return nil
	default:
		switch {
		case strings.HasSuffix(name, runJournalPlanSuffix):
			if !inventoryDigest(strings.TrimSuffix(name, runJournalPlanSuffix)) || !mode.IsRegular() || mode != 0o600 || size <= 0 {
				return ErrInvalidStartupInventoryEntry
			}
			if size > maxEncodedReviewRunPlanBytes {
				return ErrStartupInventoryLimit
			}
		case strings.HasSuffix(name, runJournalStreamSuffix):
			if !inventoryDigest(strings.TrimSuffix(name, runJournalStreamSuffix)) || !mode.IsRegular() || mode != 0o600 || size <= 0 {
				return ErrInvalidStartupInventoryEntry
			}
			if size > maxRunJournalStreamBytes {
				return ErrStartupInventoryLimit
			}
		case strings.HasSuffix(name, scopeIntentSuffix):
			if !inventoryDigest(strings.TrimSuffix(name, scopeIntentSuffix)) || !mode.IsRegular() || mode != 0o600 || size <= 0 || size > 1024 {
				return ErrInvalidStartupInventoryEntry
			}
		default:
			return ErrInvalidStartupInventoryEntry
		}
	}
	if mode.IsRegular() && !rootedSingleLink(info) {
		return ErrInvalidStartupInventoryEntry
	}
	return nil
}

// enumerateRooted checks every direct entry (not just packet leaves), including
// the directory handle's checked close. No pathname-based read is used here.
func enumerateRooted(root *os.Root) (found map[string]rootedEntry, err error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	defer func() {
		err = errors.Join(err, dir.Close())
		if err != nil {
			found = nil
		}
	}()
	list, err := dir.ReadDir(maxStartupInventoryEntries + 1)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	if len(list) > maxStartupInventoryEntries {
		return nil, ErrStartupInventoryLimit
	}
	found = make(map[string]rootedEntry, len(list))
	for _, entry := range list {
		name := entry.Name()
		enumerated, e := entry.Info()
		if e != nil {
			return nil, fmt.Errorf("%w: %v", ErrRunJournalPersistence, e)
		}
		observed, e := root.Lstat(name)
		if e != nil {
			return nil, fmt.Errorf("%w: %v", ErrRunJournalPersistence, e)
		}
		if e = rootedEntryValid(name, observed); e != nil {
			return nil, e
		}
		if !rootedSame(enumerated, observed) {
			return nil, ErrInvalidStartupInventoryEntry
		}
		found[name] = rootedEntry{name, observed}
	}
	return found, nil
}

func compareRootedEntries(before, after map[string]rootedEntry) error {
	if len(before) != len(after) {
		return ErrInvalidStartupInventoryEntry
	}
	for name, entry := range before {
		other, ok := after[name]
		if !ok || !rootedSame(entry.info, other.info) {
			return ErrInvalidStartupInventoryEntry
		}
	}
	return nil
}

// readRootedLeaf opens through the borrowed root only after Lstat, then checks
// both sides of the handle and its close. The reader must consume bounded bytes
// through EOF on success and reports an exact-byte SHA-256 witness.
func readRootedLeaf(root *os.Root, entry rootedEntry, limit int64, consume func(*os.File, io.Reader) error) (digest [sha256.Size]byte, size int64, err error) {
	before, e := root.Lstat(entry.name)
	if e != nil {
		return digest, 0, fmt.Errorf("%w: %v", ErrRunJournalPersistence, e)
	}
	if !rootedSame(entry.info, before) {
		return digest, 0, ErrInvalidStartupInventoryEntry
	}
	file, e := root.Open(entry.name)
	if e != nil {
		return digest, 0, fmt.Errorf("%w: %v", ErrRunJournalPersistence, e)
	}
	defer func() {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	opened, e := file.Stat()
	if e != nil {
		return digest, 0, fmt.Errorf("%w: %v", ErrRunJournalPersistence, e)
	}
	if !rootedSame(before, opened) || !opened.Mode().IsRegular() || opened.Size() <= 0 || opened.Size() > limit {
		return digest, 0, ErrInvalidStartupInventoryEntry
	}
	hash := sha256.New()
	counted := &rootedCountReader{reader: io.LimitReader(file, limit+1), hash: hash}
	err = consume(file, counted)
	if err == nil {
		_, err = io.Copy(io.Discard, counted) // includes scanner read-ahead and any tail
	}
	if err == nil {
		size = counted.count
		if size != opened.Size() || size > limit {
			err = ErrInvalidStartupInventoryEntry
		}
	}
	post, e := file.Stat()
	if e != nil {
		err = errors.Join(err, fmt.Errorf("%w: %v", ErrRunJournalPersistence, e))
	} else if !rootedSame(opened, post) {
		err = errors.Join(err, ErrInvalidStartupInventoryEntry)
	}
	// Check close before the final pathname sample; early returns use the defer.
	closeErr := file.Close()
	file = nil
	err = errors.Join(err, closeErr)
	leaf, e := root.Lstat(entry.name)
	if e != nil {
		err = errors.Join(err, fmt.Errorf("%w: %v", ErrRunJournalPersistence, e))
	} else if !rootedSame(opened, leaf) {
		err = errors.Join(err, ErrInvalidStartupInventoryEntry)
	}
	if err == nil {
		copy(digest[:], hash.Sum(nil))
	}
	return
}

type rootedCountReader struct {
	reader io.Reader
	hash   io.Writer
	count  int64
}

func (r *rootedCountReader) Read(p []byte) (int, error) {
	n, e := r.reader.Read(p)
	if n > 0 {
		r.count += int64(n)
		_, _ = r.hash.Write(p[:n])
	}
	return n, e
}

func (j *FileRunJournal) rootedJournalValid(opened *os.Root) error {
	inRoot, e := opened.Stat(".")
	if e != nil {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, e)
	}
	leaf, e := os.Lstat(j.root)
	if e != nil {
		return fmt.Errorf("%w: %v", ErrRunJournalPersistence, e)
	}
	return checkOwnedJournalInfo(j.rootInfo, inRoot, leaf)
}
func (j *FileRunJournal) rootedScanStatus(ctx context.Context) error {
	select {
	case <-j.closingSignal:
		return ErrRunJournalClosed
	default:
	}
	if j.closed {
		return ErrRunJournalClosed
	}
	return fileRunContextDone(ctx)
}
func cloneHistoricalFacts(facts []HistoricalContextPacketFact) []HistoricalContextPacketFact {
	out := make([]HistoricalContextPacketFact, len(facts))
	for i, f := range facts {
		out[i] = f
		if f.plan != nil {
			plan := cloneHistoricalPlan(*f.plan)
			out[i].plan = &plan
		}
		out[i].prepared = cloneHistoricalEvent(f.prepared)
		out[i].linked = cloneHistoricalEvent(f.linked)
		out[i].settlement = cloneHistoricalEvent(f.settlement)
		out[i].terminal = cloneHistoricalEvent(f.terminal)
		out[i].upstream = make([]RunEvent, len(f.upstream))
		for k, e := range f.upstream {
			out[i].upstream[k] = cloneHistoricalEvent(e)
		}
	}
	return out
}

func (j *FileRunJournal) scanOwnedHistoricalFacts(ctx context.Context, root *os.Root, after func([]HistoricalContextPacketFact) error) error {
	j.mu.Lock()
	facts, entries, witnesses, initial := j.rootedInitial(ctx, root)
	j.mu.Unlock()
	if initial != nil {
		return initial
	}
	callbackErr := after(cloneHistoricalFacts(facts))
	if errors.Is(callbackErr, ErrPreparedContextPacketAtStartup) {
		callbackErr = errHistoricalScannerCallback
	}
	j.mu.Lock()
	verifyErr := j.rootedFinal(ctx, root, entries, witnesses)
	j.mu.Unlock()
	return errors.Join(callbackErr, verifyErr)
}
func (j *FileRunJournal) rootedInitial(ctx context.Context, root *os.Root) ([]HistoricalContextPacketFact, map[string]rootedEntry, map[string]rootedLeaf, error) {
	if e := j.rootedScanStatus(ctx); e != nil {
		return nil, nil, nil, e
	}
	if !rootedScannerSupported() {
		return nil, nil, nil, ErrInvalidStartupInventoryEntry
	}
	if e := j.rootedJournalValid(root); e != nil {
		return nil, nil, nil, e
	}
	result, entries, witnesses, e := readRootedInventory(ctx, root, false)
	if e == nil {
		e = j.rootedScanStatus(ctx)
	}
	return result.facts, entries, witnesses, e
}

func readRootedInventory(ctx context.Context, root *os.Root, collectReceipts bool) (startupInventoryWalkResult, map[string]rootedEntry, map[string]rootedLeaf, error) {
	entries, e := enumerateRooted(root)
	if e != nil {
		return startupInventoryWalkResult{}, nil, nil, e
	}
	plans, streams := make(map[string]struct{}), make(map[string]struct{})
	var advertised int64
	for name, entry := range entries {
		if strings.HasSuffix(name, runJournalPlanSuffix) {
			plans[strings.TrimSuffix(name, runJournalPlanSuffix)] = struct{}{}
		} else if strings.HasSuffix(name, runJournalStreamSuffix) {
			streams[strings.TrimSuffix(name, runJournalStreamSuffix)] = struct{}{}
		} else {
			continue
		}
		advertised += entry.info.Size()
		if advertised > maxStartupInventoryEncodedBytes {
			return startupInventoryWalkResult{}, nil, nil, ErrStartupInventoryLimit
		}
	}
	if len(plans) > maxStartupInventoryPlans {
		return startupInventoryWalkResult{}, nil, nil, ErrStartupInventoryLimit
	}
	witnesses := make(map[string]rootedLeaf, len(plans)+len(streams))
	var actual int64
	readPlan := func(base string) (ReviewRunPlan, error) {
		name := base + runJournalPlanSuffix
		entry := entries[name]
		var content []byte
		hash, size, err := readRootedLeaf(root, entry, maxEncodedReviewRunPlanBytes, func(_ *os.File, reader io.Reader) error {
			var e error
			content, e = io.ReadAll(reader)
			return e
		})
		if err != nil {
			return ReviewRunPlan{}, err
		}
		actual += size
		if actual > maxStartupInventoryEncodedBytes {
			return ReviewRunPlan{}, ErrStartupInventoryLimit
		}
		witnesses[name] = rootedLeaf{entry, hash}
		return parseInventoryPlanBytes(base, content)
	}
	load := func(plan ReviewRunPlan) ([]RunEvent, error) {
		name := plan.Scope().Identity() + runJournalStreamSuffix
		entry, ok := entries[name]
		if !ok {
			return nil, ErrInvalidStartupInventoryEntry
		}
		var events []RunEvent
		hash, size, err := readRootedLeaf(root, entry, maxRunJournalStreamBytes, func(file *os.File, reader io.Reader) error {
			if e := probeRunJournalStreamNewline(file); e != nil {
				return e
			}
			var e error
			events, e = parseRunJournalStream(plan.Scope(), reader)
			return e
		})
		if err != nil {
			return nil, err
		}
		actual += size
		if actual > maxStartupInventoryEncodedBytes {
			return nil, ErrStartupInventoryLimit
		}
		witnesses[name] = rootedLeaf{entry, hash}
		return events, nil
	}
	result, e := walkInventoryPlansWithReceipts(ctx, !collectReceipts, collectReceipts, plans, streams, readPlan, load)
	if e == nil && result.overflow {
		e = ErrStartupInventoryLimit
	}
	if e != nil {
		return startupInventoryWalkResult{}, nil, nil, e
	}
	return result, entries, witnesses, nil
}
func (j *FileRunJournal) rootedFinal(ctx context.Context, root *os.Root, entries map[string]rootedEntry, witnesses map[string]rootedLeaf) error {
	if e := j.rootedScanStatus(ctx); e != nil {
		return e
	}
	var result error
	names := make([]string, 0, len(witnesses))
	for name := range witnesses {
		names = append(names, name)
	}
	sort.Strings(names)
	var actual int64
	for _, name := range names {
		witness := witnesses[name]
		limit := int64(maxRunJournalStreamBytes)
		if strings.HasSuffix(name, runJournalPlanSuffix) {
			limit = maxEncodedReviewRunPlanBytes
		}
		hash, size, e := readRootedLeaf(root, witness.entry, limit, func(_ *os.File, reader io.Reader) error { _, e := io.Copy(io.Discard, reader); return e })
		if e != nil {
			result = errors.Join(result, e)
		} else if hash != witness.digest {
			result = errors.Join(result, ErrInvalidStartupInventoryEntry)
		}
		actual += size
		if actual > maxStartupInventoryEncodedBytes {
			result = errors.Join(result, ErrStartupInventoryLimit)
			break
		}
		if e := fileRunContextDone(ctx); e != nil {
			result = errors.Join(result, e)
			break
		}
	}
	final, e := enumerateRooted(root)
	result = errors.Join(result, e)
	if e == nil {
		result = errors.Join(result, compareRootedEntries(entries, final))
	}
	result = errors.Join(result, j.rootedJournalValid(root), j.rootedScanStatus(ctx))
	return result
}
