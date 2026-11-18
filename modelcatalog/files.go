package modelcatalog

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/filelock"
)

func distinctPaths(sources, current, proposal string) error {
	paths := []string{sources, current, proposal, current + ".lock", proposal + ".lock"}
	seen := map[string]bool{}
	var infos []os.FileInfo
	for _, path := range paths {
		if path == "" {
			return ErrProtected
		}
		absolute, err := filepath.Abs(path)
		if err != nil || seen[absolute] {
			return ErrProtected
		}
		seen[absolute] = true
		info, err := os.Lstat(absolute)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return ErrProtected
		}
		for _, previous := range infos {
			if os.SameFile(previous, info) {
				return ErrProtected
			}
		}
		infos = append(infos, info)
	}
	return nil
}
func stableInfo(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
func readProtected(path string, allowAbsent bool) ([]byte, error) {
	pin, err := fileauthority.PinDirectory(filepath.Dir(path))
	if err != nil {
		return nil, ErrProtected
	}
	var original os.FileInfo
	var first []byte
	for pass := 0; pass < 2; pass++ {
		if pin.Recheck() != nil {
			return nil, ErrProtected
		}
		_, err := os.Lstat(path)
		if allowAbsent && errors.Is(err, os.ErrNotExist) {
			if pass == 0 {
				return nil, nil
			}
			return nil, ErrProtected
		}
		if err != nil {
			return nil, ErrProtected
		}
		file, err := fileauthority.OpenReadOnly(path)
		if err != nil {
			return nil, ErrProtected
		}
		before, statErr := file.Stat()
		if statErr != nil || before.Size() > maxFileBytes {
			_ = file.Close()
			return nil, ErrProtected
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
		after, afterErr := file.Stat()
		closeErr := file.Close()
		again, pathErr := os.Lstat(path)
		if readErr != nil || afterErr != nil || closeErr != nil || pathErr != nil || len(data) > maxFileBytes || !stableInfo(before, after) || !stableInfo(before, again) || pin.Recheck() != nil {
			return nil, ErrProtected
		}
		if pass == 0 {
			original = before
			first = data
		} else if !stableInfo(original, before) || !bytes.Equal(first, data) {
			return nil, ErrProtected
		}
	}
	return first, nil
}
func readCatalog(path string) (Catalog, string, error) {
	data, err := readProtected(path, true)
	if err != nil {
		return Catalog{}, "", err
	}
	if data == nil {
		return Catalog{SchemaVersion: 1, Sources: []Snapshot{}, Failures: []Failure{}}, "absent", nil
	}
	var catalog Catalog
	if decode(data, &catalog, true) != nil || validateCatalog(catalog) != nil {
		return Catalog{}, "", ErrInvalid
	}
	return catalog, Digest(data), nil
}
func currentDigest(path string) (string, error) {
	data, err := readProtected(path, true)
	if err != nil {
		return "", err
	}
	if data == nil {
		return "absent", nil
	}
	return Digest(data), nil
}
func checkLockPath(path string, allowAbsent bool) error {
	if _, err := os.Lstat(path); allowAbsent && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	file, err := fileauthority.OpenReadOnly(path)
	if err != nil {
		return ErrProtected
	}
	return file.Close()
}
func writeAtomic(ctx context.Context, path string, data []byte, expected string, recheck func() error) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ErrProtected
	}
	parent := filepath.Dir(absolute)
	pin, err := fileauthority.PinDirectory(parent)
	if err != nil {
		return ErrProtected
	}
	if err = checkLockPath(absolute+".lock", true); err != nil {
		return err
	}
	lock, err := filelock.Acquire(absolute + ".lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	verify := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if pin.Recheck() != nil || checkLockPath(absolute+".lock", false) != nil {
			return ErrProtected
		}
		info, err := os.Lstat(absolute + ".lock")
		if err != nil || !lock.SameFile(info) {
			return ErrProtected
		}
		digest, err := currentDigest(absolute)
		if err != nil {
			return err
		}
		if digest != expected {
			return ErrConflict
		}
		return recheck()
	}
	if err = verify(); err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return ErrPersistence
	}
	temporary := filepath.Join(parent, ".modelcatalog-"+hex.EncodeToString(suffix))
	temp, err := fileauthority.CreatePrivateFile(temporary)
	if err != nil {
		return ErrPersistence
	}
	defer func() { _ = temp.Close(); _ = os.Remove(temporary) }()
	if err = temp.Chmod(0600); err != nil {
		return ErrPersistence
	}
	opened, err := temp.Stat()
	if err != nil {
		return ErrPersistence
	}
	if n, err := temp.Write(data); err != nil || n != len(data) {
		return ErrPersistence
	}
	if err = temp.Sync(); err != nil {
		return ErrPersistence
	}
	if err = temp.Close(); err != nil {
		return ErrPersistence
	}
	staged, err := os.Lstat(temporary)
	if err != nil || !os.SameFile(opened, staged) || !fileauthority.PrivateFile(temporary, staged) {
		return ErrProtected
	}
	if err = verify(); err != nil {
		return err
	}
	if expected == "absent" {
		// Linking installs a complete inode without clobbering an unexpected new file.
		if err = os.Link(temporary, absolute); err != nil {
			return ErrConflict
		}
		if err = os.Remove(temporary); err != nil {
			return ErrDurability
		}
	} else if err = os.Rename(temporary, absolute); err != nil {
		return ErrPersistence
	}
	if err := fileauthority.SyncDirectory(parent); err != nil {
		return ErrDurability
	}
	return nil
}
