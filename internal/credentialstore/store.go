// Package credentialstore keeps provider API keys that the operator typed into
// `trestle init` or `trestle keys set`, so later reviews find them without the
// key being exported in every shell.
//
// Threat model. Each key is a plaintext file protected only by file
// permissions, like other command-line credential files: the folder is 0700,
// each file 0600, and both must be owned by this account. On Windows the owner
// and access-control list say the same: only this account and the system's
// own accounts (SYSTEM, Administrators and TrustedInstaller) may have
// access, and the folder and files are created that way rather than
// tightened afterwards. That keeps the key from other local accounts, but
// not from anything that runs as this account, from the administrator, or
// from a backup or disk image that copies the folder. The store refuses a
// folder or file with broader permissions, another owner, or a symbolic link
// instead of using it, and replaces a key through a protected temporary file
// and a rename, so a reader sees the old key or the new one, never part of
// either. An operating-system keyring is a possible later backend; it is not
// used.
//
// Only the variable name (OPEN_TRESTLE_PROVIDER_...) names a key. The value is
// never part of an error, a file name, or anything the package prints.
package credentialstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// MaxKeyBytes bounds one stored key, the bound the model adapter accepts.
const MaxKeyBytes = 4096

var (
	// ErrUnavailable is a credential folder or file that is not private, not
	// owned by this account, a symbolic link, or not readable.
	ErrUnavailable = errors.New("credential folder unavailable")
	// ErrInvalidName is a variable name outside OPEN_TRESTLE_PROVIDER_[A-Z0-9_]+.
	ErrInvalidName = errors.New("not an OPEN_TRESTLE_PROVIDER_ variable name")
	// ErrInvalidKey is a value the model adapter would not send: empty, longer
	// than MaxKeyBytes, or with a space, control or non-ASCII character.
	ErrInvalidKey = errors.New("not a usable API key")
)

// DefaultDirectory is $XDG_CONFIG_HOME/open-trestle/credentials when
// XDG_CONFIG_HOME is an absolute path, and otherwise
// ~/.config/open-trestle/credentials.
func DefaultDirectory(getenv func(string) string) (string, error) {
	if config := getenv("XDG_CONFIG_HOME"); config != "" && filepath.IsAbs(config) {
		return filepath.Join(filepath.Clean(config), "open-trestle", "credentials"), nil
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
	return filepath.Join(filepath.Clean(home), ".config", "open-trestle", "credentials"), nil
}

// ValidName reports whether name is a provider key variable name.
func ValidName(name string) bool { return runtimeconfig.ValidCredentialEnvironment(name) }

// ValidKey reports whether value is a key the model adapter would send.
func ValidKey(value string) error {
	if _, err := openai.NewAPIKey([]byte(value)); err != nil {
		return ErrInvalidKey
	}
	return nil
}

// Store is the credential folder: one file per variable name, holding exactly
// the key's bytes.
type Store struct {
	dir string
}

// NewStore names a credential folder by its absolute path. It touches nothing.
func NewStore(dir string) (*Store, error) {
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || len(dir) > 4096 {
		return nil, ErrUnavailable
	}
	return &Store{dir: dir}, nil
}

// Directory is the credential folder's path.
func (s *Store) Directory() string { return s.dir }

// prepare checks the folder and, with create, makes it. It reports false when
// the folder does not exist and create is not set.
func (s *Store) prepare(create bool) (*fileauthority.DirectoryPin, bool, error) {
	if create {
		if err := fileauthority.MkdirAllPrivate(s.dir); err != nil {
			return nil, false, fmt.Errorf("%w: cannot create %s", ErrUnavailable, s.dir)
		}
	}
	info, err := os.Lstat(s.dir)
	if errors.Is(err, os.ErrNotExist) && !create {
		return nil, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, false, fmt.Errorf("%w: %s is not a folder", ErrUnavailable, s.dir)
	}
	if !fileauthority.PrivateDirectory(s.dir, info) {
		return nil, false, fmt.Errorf("%w: %s must be private (%s)", ErrUnavailable, s.dir, fileauthority.PrivateDirectoryRequirement(info))
	}
	pin, err := fileauthority.PinDirectory(s.dir)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %s or a parent folder is not owned by this account or is writable by others", ErrUnavailable, s.dir)
	}
	return pin, true, nil
}

// checkTarget refuses an existing entry that is not a protected regular file:
// a symbolic link, a folder, broader permissions or another owner.
func checkTarget(path, name string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: %s cannot be read", ErrUnavailable, name)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%w: %s is a symbolic link", ErrUnavailable, name)
	}
	if !fileauthority.PrivateFile(path, info) {
		return false, fmt.Errorf("%w: %s must be %s", ErrUnavailable, name, fileauthority.PrivateFileRequirement())
	}
	return true, nil
}

// Get returns the key saved for name, or found false when none is saved.
func (s *Store) Get(name string) (string, bool, error) {
	if !ValidName(name) {
		return "", false, ErrInvalidName
	}
	pin, exists, err := s.prepare(false)
	if err != nil || !exists {
		return "", false, err
	}
	path := filepath.Join(s.dir, name)
	if found, err := checkTarget(path, name); err != nil || !found {
		return "", false, err
	}
	file, err := fileauthority.OpenReadOnly(path)
	if err != nil {
		return "", false, fmt.Errorf("%w: %s is not a protected file", ErrUnavailable, name)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !fileauthority.PrivateOpenFile(file, before) || before.Size() > MaxKeyBytes {
		return "", false, fmt.Errorf("%w: %s is not a protected file within its size bound", ErrUnavailable, name)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxKeyBytes+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || len(data) > MaxKeyBytes || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || pin.Recheck() != nil {
		return "", false, fmt.Errorf("%w: %s changed or could not be read", ErrUnavailable, name)
	}
	if ValidKey(string(data)) != nil {
		return "", false, fmt.Errorf("%w: %s does not hold a usable key", ErrUnavailable, name)
	}
	return string(data), true, nil
}

// Set saves key for name, replacing any earlier key atomically: the key is
// written to a new protected temporary file in the folder and renamed over
// the old one, and the folder is synced.
func (s *Store) Set(ctx context.Context, name, key string) error {
	if !ValidName(name) {
		return ErrInvalidName
	}
	if ValidKey(key) != nil {
		return ErrInvalidKey
	}
	pin, _, err := s.prepare(true)
	if err != nil {
		return err
	}
	target := filepath.Join(s.dir, name)
	if _, err := checkTarget(target, name); err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return ErrUnavailable
	}
	temporary := filepath.Join(s.dir, "."+name+"."+hex.EncodeToString(suffix)+".tmp")
	if err := fileauthority.WriteNewProtectedFile(ctx, temporary, []byte(key), MaxKeyBytes); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("%w: cannot write in %s", ErrUnavailable, s.dir)
	}
	defer func() { _ = os.Remove(temporary) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := checkTarget(target, name); err != nil || pin.Recheck() != nil {
		return fmt.Errorf("%w: %s changed while it was replaced", ErrUnavailable, name)
	}
	if err := os.Rename(temporary, target); err != nil {
		return fmt.Errorf("%w: cannot replace %s", ErrUnavailable, name)
	}
	return syncDirectory(s.dir)
}

// Remove deletes the key saved for name. It reports false when none was saved.
func (s *Store) Remove(ctx context.Context, name string) (bool, error) {
	if !ValidName(name) {
		return false, ErrInvalidName
	}
	_, exists, err := s.prepare(false)
	if err != nil || !exists {
		return false, err
	}
	path := filepath.Join(s.dir, name)
	if found, err := checkTarget(path, name); err != nil || !found {
		return false, err
	}
	err = fileauthority.RemoveValidatedProtectedFile(ctx, path, MaxKeyBytes, func(data []byte) error { return ValidKey(string(data)) })
	if err != nil {
		return false, fmt.Errorf("%w: cannot remove %s", ErrUnavailable, name)
	}
	return true, nil
}

// Names lists the variable names that have a saved key, sorted. Entries that
// are not variable names, such as an interrupted write's temporary file, are
// skipped.
func (s *Store) Names() ([]string, error) {
	_, exists, err := s.prepare(false)
	if err != nil || !exists {
		return nil, err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, ErrUnavailable
	}
	names := []string{}
	for _, entry := range entries {
		if ValidName(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)
	return names, nil
}

func syncDirectory(dir string) error {
	if err := fileauthority.SyncDirectory(dir); err != nil {
		return fmt.Errorf("%w: cannot sync %s", ErrUnavailable, dir)
	}
	return nil
}
