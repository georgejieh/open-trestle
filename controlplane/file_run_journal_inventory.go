// Startup inventory is an API-only, fail-closed inspection of journal-root entries.
// It does not attest the owner, inspect sibling contents, or run before constructors.
package controlplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// Fixed local compatibility policy. Older larger journals require offline review;
// exceeding a bound is not evidence of corrupt bytes or of v4 absence.
const (
	maxStartupInventoryEntries            = 1024 // includes lock and sibling directories
	maxStartupInventoryPlans              = 500
	maxStartupInventoryEncodedBytes int64 = 256 << 20 // plans plus streams
)

var (
	ErrPreparedContextPacketAtStartup   = errors.New("prepared context packet in historical journal at startup")
	ErrIncompleteStartupInventoryPrefix = errors.New("incomplete startup inventory plan-only prefix")
	ErrInvalidStartupInventoryEntry     = errors.New("invalid startup inventory entry")
	ErrStartupInventoryLimit            = errors.New("startup inventory limit exceeded")
)

// StartupInventory contains only counts from an exhaustive successful inspection.
// An error always returns zero counters, including for a valid replayed v4 event.
type StartupInventory struct{ Plans, Streams, Events int }

// InspectStartupInventory checks every direct journal-root entry and every event
// in every paired stream. This method is not daemon startup wiring or packet safety.
type startupInventoryWalkResult struct {
	inventory StartupInventory
	facts     []HistoricalContextPacketFact
	hasPacket bool
	overflow  bool
}

// InspectStartupInventory preserves its blanket v4 refusal and zero-on-error
// counts. Both public APIs use the same exhaustive old-error-ordered walk.
func (j *FileRunJournal) InspectStartupInventory(ctx context.Context) (StartupInventory, error) {
	result, err := j.inspectStartupInventory(ctx, false)
	if err != nil {
		return StartupInventory{}, err
	}
	if result.hasPacket {
		return StartupInventory{}, ErrPreparedContextPacketAtStartup
	}
	return result.inventory, nil
}

// InspectHistoricalContextPackets is all-scope diagnostic metadata only. It
// grants no startup, owner-scoped, artifact, or dispatch authority.
func (j *FileRunJournal) InspectHistoricalContextPackets(ctx context.Context) ([]HistoricalContextPacketFact, error) {
	result, err := j.inspectStartupInventory(ctx, true)
	if err != nil {
		return nil, err
	}
	if result.overflow {
		return nil, ErrStartupInventoryLimit
	}
	return append([]HistoricalContextPacketFact{}, result.facts...), nil
}

func (j *FileRunJournal) inspectStartupInventory(ctx context.Context, historical bool) (startupInventoryWalkResult, error) {
	zero := startupInventoryWalkResult{}
	if j == nil {
		return zero, ErrInvalidRunJournal
	}
	if err := validateFileRunContext(ctx); err != nil {
		return zero, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	select {
	case <-j.closingSignal:
		return zero, ErrRunJournalClosed
	default:
	}
	if j.closed {
		return zero, ErrRunJournalClosed
	}
	rootInfo, err := os.Lstat(j.root)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode().Perm()&0o077 != 0 {
		return zero, ErrInvalidStartupInventoryEntry
	}
	directory, err := os.Open(j.root)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	defer directory.Close()
	// Positive n reads no more than n entries; never enumerate the unbounded root.
	entries, err := directory.ReadDir(maxStartupInventoryEntries + 1)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	if len(entries) > maxStartupInventoryEntries {
		return zero, ErrStartupInventoryLimit
	}
	plans := make(map[string]struct{})
	streams := make(map[string]struct{})
	var total int64
	for _, entry := range entries {
		if err := fileRunContextDone(ctx); err != nil {
			return zero, err
		}
		name := entry.Name()
		info, err := entry.Info()
		if err != nil {
			return zero, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
		}
		mode := info.Mode()
		if mode.Perm()&0o077 != 0 || mode&os.ModeSymlink != 0 {
			return zero, ErrInvalidStartupInventoryEntry
		}
		switch name {
		case ".local-source-owner.json":
			if mode != 0o600 || !mode.IsRegular() || !fileauthority.TrustedOwner(info) || info.Size() <= 0 || info.Size() > 16<<10 {
				return zero, ErrInvalidStartupInventoryEntry
			}
			continue
		case runJournalWriterLockName:
			if !mode.IsRegular() {
				return zero, ErrInvalidStartupInventoryEntry
			}
			continue
		case "artifacts", "audit", "diagnostics", "webhook-inbox", "setup":
			if !mode.IsDir() {
				return zero, ErrInvalidStartupInventoryEntry
			}
			continue
		}
		var base string
		var isPlan bool
		switch {
		case strings.HasSuffix(name, runJournalPlanSuffix):
			base = strings.TrimSuffix(name, runJournalPlanSuffix)
			isPlan = true
		case strings.HasSuffix(name, runJournalStreamSuffix):
			base = strings.TrimSuffix(name, runJournalStreamSuffix)
		default:
			return zero, ErrInvalidStartupInventoryEntry
		}
		if !inventoryDigest(base) || !mode.IsRegular() {
			return zero, ErrInvalidStartupInventoryEntry
		}
		size := info.Size()
		if size <= 0 {
			return zero, ErrInvalidStartupInventoryEntry
		}
		if isPlan {
			if size > maxEncodedReviewRunPlanBytes {
				return zero, ErrStartupInventoryLimit
			}
			plans[base] = struct{}{}
			if len(plans) > maxStartupInventoryPlans {
				return zero, ErrStartupInventoryLimit
			}
		} else {
			if size > maxRunJournalStreamBytes {
				return zero, ErrStartupInventoryLimit
			}
			streams[base] = struct{}{}
		}
		if size > maxStartupInventoryEncodedBytes-total {
			return zero, ErrStartupInventoryLimit
		}
		total += size
	}
	for base := range streams {
		if _, ok := plans[base]; !ok {
			return zero, ErrInvalidStartupInventoryEntry
		}
	}
	bases := make([]string, 0, len(plans))
	for base := range plans {
		bases = append(bases, base)
	}
	sort.Strings(bases)
	incomplete := false
	for _, base := range bases {
		if _, ok := streams[base]; ok {
			continue
		}
		if err := fileRunContextDone(ctx); err != nil {
			return zero, err
		}
		if _, err := j.readInventoryPlan(base); err != nil {
			return zero, err
		}
		incomplete = true
	}
	if incomplete {
		return zero, ErrIncompleteStartupInventoryPrefix
	}
	result := StartupInventory{}
	hasPacket := false
	// Every planned scope is recovered from bounded canonical plan bytes. The digest
	// cannot be inverted; exact filename identity is checked before loading stream.
	for _, base := range bases {
		if err := fileRunContextDone(ctx); err != nil {
			return zero, err
		}
		plan, err := j.readInventoryPlan(base)
		if err != nil {
			return zero, err
		}
		events, err := j.loadStream(plan.Scope())
		if err != nil {
			return zero, err
		}
		if len(events) == 0 {
			return zero, ErrInvalidStartupInventoryEntry
		}
		state, err := ReplayReviewRun(plan, events)
		if err != nil {
			return zero, fmt.Errorf("%w: %v", ErrInvalidStartupInventoryEntry, err)
		}
		for _, event := range events {
			if event.Kind() == RunEventContextPacketPrepared {
				hasPacket = true
			}
		}
		if historical && !zero.overflow {
			streamFacts, overflow, err := historicalFactsForStream(plan, events, state, maxStartupHistoricalPacketFacts-len(zero.facts))
			if err != nil {
				return startupInventoryWalkResult{}, err
			}
			zero.facts = append(zero.facts, streamFacts...)
			zero.overflow = overflow
		}
		result.Plans++
		result.Streams++
		result.Events += len(events)
	}
	if err := fileRunContextDone(ctx); err != nil {
		return zero, err
	}
	zero.inventory = result
	zero.hasPacket = hasPacket
	return zero, nil
}

func (j *FileRunJournal) readInventoryPlan(base string) (ReviewRunPlan, error) {
	path := filepath.Join(j.root, base+runJournalPlanSuffix)
	file, err := os.Open(path)
	if err != nil {
		return ReviewRunPlan{}, fmt.Errorf("%w: %v", ErrRunJournalPersistence, err)
	}
	info, statErr := file.Stat()
	if statErr != nil {
		file.Close()
		return ReviewRunPlan{}, fmt.Errorf("%w: %v", ErrRunJournalPersistence, statErr)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maxEncodedReviewRunPlanBytes {
		file.Close()
		return ReviewRunPlan{}, ErrInvalidReviewRunPlanEncoding
	}
	// Bound the read even if the file changes after directory classification.
	content, readErr := io.ReadAll(io.LimitReader(file, maxEncodedReviewRunPlanBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return ReviewRunPlan{}, fmt.Errorf("%w: %v", ErrRunJournalPersistence, errors.Join(readErr, closeErr))
	}
	if len(content) == 0 || len(content) > maxEncodedReviewRunPlanBytes || int64(len(content)) != info.Size() {
		return ReviewRunPlan{}, ErrInvalidReviewRunPlanEncoding
	}
	plan, err := ParseReviewRunPlan(content)
	if err != nil {
		return ReviewRunPlan{}, err
	}
	if plan.Scope().Identity() != base {
		return ReviewRunPlan{}, ErrInvalidReviewRunPlanEncoding
	}
	return plan, nil
}
func inventoryDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, ch := range []byte(value) {
		if ch < '0' || ch > '9' && ch < 'a' || ch > 'f' {
			return false
		}
	}
	return true
}
