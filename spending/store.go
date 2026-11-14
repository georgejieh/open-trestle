package spending

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/filelock"
)

const (
	// MaxLedgerFileBytes bounds one month's ledger file. At about 600 bytes an
	// entry that is some 14,000 review runs; past it, entries are refused.
	MaxLedgerFileBytes = 8 << 20
	ledgerLock         = "ledger.lock"
	limitsLock         = "limits.lock"
	lockWait           = 10 * time.Second
)

var (
	// ErrUnavailable is a usage folder that is not private, not owned by this
	// account, or whose files are not protected 0600 regular files.
	ErrUnavailable = errors.New("usage folder unavailable")
	// ErrLedgerUnreadable is a ledger file with a line that is not a valid
	// entry.
	ErrLedgerUnreadable = errors.New("usage ledger unreadable")
	// ErrLedgerFull is a month's ledger file that reached MaxLedgerFileBytes.
	ErrLedgerFull = errors.New("usage ledger full for this month")
)

var (
	limitFileName  = regexp.MustCompile(`^limit-[0-9a-f]{64}\.json$`)
	ledgerFileName = regexp.MustCompile(`^ledger-[0-9]{4}-[0-9]{2}\.jsonl$`)
)

// DefaultDirectory is $XDG_STATE_HOME/open-trestle/usage when XDG_STATE_HOME
// is an absolute path, and otherwise ~/.local/state/open-trestle/usage.
func DefaultDirectory(getenv func(string) string) (string, error) {
	if state := getenv("XDG_STATE_HOME"); state != "" && filepath.IsAbs(state) {
		return filepath.Join(filepath.Clean(state), "open-trestle", "usage"), nil
	}
	home := getenv("HOME")
	if home == "" {
		var err error
		if home, err = os.UserHomeDir(); err != nil {
			return "", ErrUnavailable
		}
	}
	if !filepath.IsAbs(home) {
		return "", ErrUnavailable
	}
	return filepath.Join(filepath.Clean(home), ".local", "state", "open-trestle", "usage"), nil
}

// Store is the usage folder: one limit record per key and one ledger file per
// UTC month. The folder is 0700 and every file 0600, owned by this account.
type Store struct {
	dir string
}

// NewStore names a usage folder by its absolute path. It touches nothing.
func NewStore(dir string) (*Store, error) {
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || len(dir) > 4096 {
		return nil, ErrUnavailable
	}
	return &Store{dir: dir}, nil
}

// Directory is the usage folder's path.
func (s *Store) Directory() string { return s.dir }

// prepare checks the folder and, with create, makes it. It reports false when
// the folder does not exist and create is not set.
func (s *Store) prepare(create bool) (*fileauthority.DirectoryPin, bool, error) {
	if create {
		if err := os.MkdirAll(s.dir, 0o700); err != nil {
			return nil, false, fmt.Errorf("%w: cannot create %s", ErrUnavailable, s.dir)
		}
	}
	info, err := os.Lstat(s.dir)
	if errors.Is(err, os.ErrNotExist) && !create {
		return nil, false, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("%w: %s is not a folder", ErrUnavailable, s.dir)
	}
	if info.Mode().Perm() != 0o700 {
		return nil, false, fmt.Errorf("%w: %s must be private (mode 0700, not %04o)", ErrUnavailable, s.dir, info.Mode().Perm())
	}
	pin, err := fileauthority.PinDirectory(s.dir)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %s or a parent folder is not owned by this account or is writable by others", ErrUnavailable, s.dir)
	}
	return pin, true, nil
}

// lock takes one of the folder's advisory locks, waiting up to lockWait for a
// concurrent writer.
func (s *Store) lock(ctx context.Context, pin *fileauthority.DirectoryPin, name string) (*filelock.Lock, error) {
	deadline := time.Now().Add(lockWait)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if pin.Recheck() != nil {
			return nil, ErrUnavailable
		}
		lock, err := filelock.Acquire(filepath.Join(s.dir, name))
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, filelock.ErrLocked) || time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: cannot lock %s", ErrUnavailable, name)
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// read returns a protected file's bytes, or found false when it does not
// exist. The file must be a 0600 regular file owned by this account under the
// pinned folder, and must not change while it is read.
func (s *Store) read(pin *fileauthority.DirectoryPin, name string, limit int) ([]byte, bool, error) {
	path := filepath.Join(s.dir, name)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	file, err := fileauthority.OpenReadOnly(path)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %s is not a protected file", ErrUnavailable, name)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || before.Mode().Perm() != 0o600 || before.Size() > int64(limit) {
		return nil, false, fmt.Errorf("%w: %s is not a protected file within its size bound", ErrUnavailable, name)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || len(data) > limit || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || pin.Recheck() != nil {
		return nil, false, fmt.Errorf("%w: %s changed or could not be read", ErrUnavailable, name)
	}
	return data, true, nil
}

func limitName(scope Scope) string { return "limit-" + scope.key() + ".json" }

// Limit returns the scope's limit, or found false when none is set.
func (s *Store) Limit(scope Scope) (Limit, bool, error) {
	if !scope.valid() {
		return Limit{}, false, ErrInvalidScope
	}
	pin, exists, err := s.prepare(false)
	if err != nil || !exists {
		return Limit{}, false, err
	}
	data, found, err := s.read(pin, limitName(scope), maxLimitBytes)
	if err != nil || !found {
		return Limit{}, false, err
	}
	limit, err := ParseLimit(data)
	if err != nil || limit.Scope != scope {
		return Limit{}, false, fmt.Errorf("%w: %s", ErrInvalidRecord, limitName(scope))
	}
	return limit, true, nil
}

// Limits returns every limit, sorted by key variable and provider.
func (s *Store) Limits() ([]Limit, error) {
	pin, exists, err := s.prepare(false)
	if err != nil || !exists {
		return nil, err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, ErrUnavailable
	}
	limits := []Limit{}
	for _, entry := range entries {
		if !limitFileName.MatchString(entry.Name()) {
			continue
		}
		data, found, err := s.read(pin, entry.Name(), maxLimitBytes)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		limit, err := ParseLimit(data)
		if err != nil || limitName(limit.Scope) != entry.Name() {
			return nil, fmt.Errorf("%w: %s", ErrInvalidRecord, entry.Name())
		}
		limits = append(limits, limit)
	}
	slices.SortFunc(limits, func(a, b Limit) int { return compareScopes(a.Scope, b.Scope) })
	return limits, nil
}

// SetLimit writes the scope's limit, replacing any earlier one atomically.
func (s *Store) SetLimit(ctx context.Context, limit Limit) error {
	encoded, err := EncodeLimit(limit)
	if err != nil {
		return err
	}
	pin, _, err := s.prepare(true)
	if err != nil {
		return err
	}
	lock, err := s.lock(ctx, pin, limitsLock)
	if err != nil {
		return err
	}
	defer lock.Close()
	return s.replace(ctx, pin, limitName(limit.Scope), encoded)
}

// replace installs content as name through a protected temporary file and a
// rename, then syncs the folder.
func (s *Store) replace(ctx context.Context, pin *fileauthority.DirectoryPin, name string, content []byte) error {
	target := filepath.Join(s.dir, name)
	if info, err := os.Lstat(target); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !fileauthority.TrustedOwner(info)) {
		return fmt.Errorf("%w: %s is not a protected file", ErrUnavailable, name)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrUnavailable
	}
	temp, err := os.CreateTemp(s.dir, ".limit-*")
	if err != nil {
		return fmt.Errorf("%w: cannot write in %s", ErrUnavailable, s.dir)
	}
	temporary := temp.Name()
	defer func() { _ = temp.Close(); _ = os.Remove(temporary) }()
	opened, err := temp.Stat()
	if err != nil || temp.Chmod(0o600) != nil {
		return ErrUnavailable
	}
	if n, err := temp.Write(content); err != nil || n != len(content) || temp.Sync() != nil || temp.Close() != nil {
		return fmt.Errorf("%w: cannot write in %s", ErrUnavailable, s.dir)
	}
	staged, err := os.Lstat(temporary)
	if err != nil || !os.SameFile(opened, staged) || !staged.Mode().IsRegular() || staged.Mode().Perm() != 0o600 || ctx.Err() != nil || pin.Recheck() != nil {
		return ErrUnavailable
	}
	if err := os.Rename(temporary, target); err != nil {
		return fmt.Errorf("%w: cannot replace %s", ErrUnavailable, name)
	}
	return syncDirectory(s.dir)
}

// ClearLimit removes the scope's limit. It reports false when none was set.
func (s *Store) ClearLimit(ctx context.Context, scope Scope) (bool, error) {
	if !scope.valid() {
		return false, ErrInvalidScope
	}
	pin, exists, err := s.prepare(false)
	if err != nil || !exists {
		return false, err
	}
	lock, err := s.lock(ctx, pin, limitsLock)
	if err != nil {
		return false, err
	}
	defer lock.Close()
	path := filepath.Join(s.dir, limitName(scope))
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	err = fileauthority.RemoveValidatedProtectedFile(ctx, path, maxLimitBytes, func(data []byte) error {
		limit, err := ParseLimit(data)
		if err != nil || limit.Scope != scope {
			return ErrInvalidRecord
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("%w: cannot remove %s", ErrUnavailable, limitName(scope))
	}
	return true, nil
}

func ledgerName(at time.Time) string {
	return "ledger-" + at.UTC().Format("2006-01") + ".jsonl"
}

// Append adds one entry to its month's ledger file under the ledger lock. A
// final line left without a newline by an interrupted write is closed first,
// so the new entry starts on its own line; readers ignore such a torn line.
func (s *Store) Append(ctx context.Context, entry Entry) error {
	line, err := EncodeEntry(entry)
	if err != nil {
		return err
	}
	entry, _ = NewEntry(entry)
	pin, _, err := s.prepare(true)
	if err != nil {
		return err
	}
	lock, err := s.lock(ctx, pin, ledgerLock)
	if err != nil {
		return err
	}
	defer lock.Close()
	name := ledgerName(entry.RecordedAt)
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return ErrUnavailable
	}
	defer root.Close()
	_, statErr := root.Lstat(name)
	created := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !created {
		return ErrUnavailable
	}
	file, err := root.OpenFile(name, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("%w: cannot open %s", ErrUnavailable, name)
	}
	defer file.Close()
	opened, err := file.Stat()
	linked, linkErr := root.Lstat(name)
	if err != nil || linkErr != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 || !fileauthority.TrustedOwner(opened) || !os.SameFile(opened, linked) || pin.Recheck() != nil {
		return fmt.Errorf("%w: %s is not a protected file", ErrUnavailable, name)
	}
	size := opened.Size()
	if size > 0 {
		last := make([]byte, 1)
		if _, err := file.ReadAt(last, size-1); err != nil {
			return ErrUnavailable
		}
		if last[0] != '\n' {
			line = append([]byte{'\n'}, line...)
		}
	}
	if size+int64(len(line)) > MaxLedgerFileBytes {
		return ErrLedgerFull
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if n, err := file.Write(line); err != nil || n != len(line) {
		return fmt.Errorf("%w: cannot write %s", ErrUnavailable, name)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("%w: cannot sync %s", ErrUnavailable, name)
	}
	if created {
		return syncDirectory(s.dir)
	}
	return nil
}

// Entries returns every entry recorded in [start, end), in file order.
func (s *Store) Entries(start, end time.Time) ([]Entry, error) {
	pin, exists, err := s.prepare(false)
	if err != nil || !exists || !end.After(start) {
		return nil, err
	}
	entries := []Entry{}
	month := time.Date(start.UTC().Year(), start.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	for ; month.Before(end); month = month.AddDate(0, 1, 0) {
		name := ledgerName(month)
		data, found, err := s.read(pin, name, MaxLedgerFileBytes)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		lines := bytes.SplitAfter(data, []byte{'\n'})
		for index, line := range lines {
			if len(line) == 0 {
				continue
			}
			if line[len(line)-1] != '\n' {
				// A torn final line from an interrupted write is not an entry.
				if index == len(lines)-1 {
					continue
				}
				return nil, fmt.Errorf("%w: %s", ErrLedgerUnreadable, name)
			}
			entry, err := ParseEntry(line)
			if err != nil || ledgerName(entry.RecordedAt) != name {
				return nil, fmt.Errorf("%w: %s line %d", ErrLedgerUnreadable, name, index+1)
			}
			if !entry.RecordedAt.Before(start) && entry.RecordedAt.Before(end) {
				entries = append(entries, entry)
			}
		}
	}
	return entries, nil
}

// Spend is what the ledger records against one key in a period.
type Spend struct {
	MicroUSD uint64
	// Entries counts the review runs charged; UpperBound counts those whose
	// usage was not known, so they count at the reservation upper bound.
	Entries, UpperBound int
}

// Spent sums the entries charged to scope in [start, end).
func (s *Store) Spent(scope Scope, start, end time.Time) (Spend, error) {
	entries, err := s.Entries(start, end)
	if err != nil {
		return Spend{}, err
	}
	return SumSpend(entries, scope), nil
}

// SumSpend sums the entries charged to scope.
func SumSpend(entries []Entry, scope Scope) Spend {
	var spend Spend
	for _, entry := range entries {
		if !entry.Charges(scope) {
			continue
		}
		spend.Entries++
		if !entry.UsageKnown {
			spend.UpperBound++
		}
		if spend.MicroUSD > ^uint64(0)-entry.CostMicroUSD {
			spend.MicroUSD = ^uint64(0)
			continue
		}
		spend.MicroUSD += entry.CostMicroUSD
	}
	return spend
}

func syncDirectory(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return ErrUnavailable
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("%w: cannot sync %s", ErrUnavailable, dir)
	}
	return nil
}

// Scopes returns the distinct keys charged by entries, sorted.
func Scopes(entries []Entry) []Scope {
	scopes := []Scope{}
	for _, entry := range entries {
		for _, scope := range entry.Scopes {
			if !slices.Contains(scopes, scope) {
				scopes = append(scopes, scope)
			}
		}
	}
	slices.SortFunc(scopes, compareScopes)
	return scopes
}

// DisplayDirectory shortens the home folder to ~ for messages.
func DisplayDirectory(dir string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" && strings.HasPrefix(dir, home+string(os.PathSeparator)) {
		return "~" + strings.TrimPrefix(dir, home)
	}
	return dir
}
