package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

var errRecoveryInventoryLimit = errors.New("local recovery inventory limit exceeded")

var errRestoreObservationMismatch = errors.New("restored observation does not match recovery point")

// Inventory is bounded independently of available memory and reads bytes only.
const localRecoveryInventoryBytes int64 = 256 << 20
const localRecoveryInventoryDepth = 8

func inventoryRestoredTree(ctx context.Context, root *os.Root) ([]localRecoveryEntry, error) {
	return inventoryRecoveryTree(ctx, root, false)
}
func inventoryRecoveryTree(ctx context.Context, root *os.Root, git bool) ([]localRecoveryEntry, error) {
	if ctx == nil || root == nil {
		return nil, errRestoreObservationMismatch
	}
	var entries []localRecoveryEntry
	var total int64
	var walk func(*os.Root, string, int) error
	walk = func(directory *os.Root, prefix string, depth int) error {
		if depth > localRecoveryInventoryDepth {
			return errRecoveryInventoryLimit
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		handle, err := directory.Open(".")
		if err != nil {
			return err
		}
		names, readErr := handle.ReadDir(maxLocalRecoveryPointEntries - len(entries) + 1)
		closeErr := handle.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		if len(names)+len(entries) > maxLocalRecoveryPointEntries {
			return errRecoveryInventoryLimit
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(entries) >= maxLocalRecoveryPointEntries {
				return errRecoveryInventoryLimit
			}
			leaf := name.Name()
			before, err := directory.Lstat(leaf)
			if err != nil {
				return err
			}
			relative := filepath.Join(prefix, leaf)
			if !fileauthority.TrustedOwner(before) {
				return errRestoreObservationMismatch
			}
			if before.Mode() == os.ModeDir|0o700 || git && before.Mode()&os.ModeType == os.ModeDir && before.Mode().Perm()&0o022 == 0 {
				entries = append(entries, localRecoveryEntry{Path: relative, Mode: uint32(before.Mode().Perm())})
				child, err := directory.OpenRoot(leaf)
				if err != nil {
					return err
				}
				opened, statErr := child.Stat(".")
				if statErr != nil || !recordedEqual(before, opened) {
					child.Close()
					return errRestoreObservationMismatch
				}
				walkErr := walk(child, relative, depth+1)
				closeErr := child.Close()
				after, statErr := directory.Lstat(leaf)
				if walkErr != nil || closeErr != nil || statErr != nil {
					return errors.Join(walkErr, closeErr, statErr)
				}
				if !recordedEqual(before, after) {
					return errRestoreObservationMismatch
				}
				continue
			}
			if !(before.Mode() == 0o600 && recordedPrivateSingleLink(before) || git && before.Mode().IsRegular() && before.Mode().Perm()&0o022 == 0) || before.Size() < 0 {
				return errRestoreObservationMismatch
			}
			if before.Size() > localRecoveryInventoryBytes-total {
				return errRecoveryInventoryLimit
			}
			file, err := directory.Open(leaf)
			if err != nil {
				return err
			}
			opened, statErr := file.Stat()
			if statErr != nil || !recordedEqual(before, opened) {
				file.Close()
				return errRestoreObservationMismatch
			}
			hash := sha256.New()
			n, readErr := io.Copy(hash, io.LimitReader(file, before.Size()+1))
			end, statErr := file.Stat()
			closeErr := file.Close()
			linked, linkErr := directory.Lstat(leaf)
			if readErr != nil || statErr != nil || closeErr != nil || linkErr != nil {
				return errors.Join(readErr, statErr, closeErr, linkErr)
			}
			if n != before.Size() || !recordedEqual(before, end) || !recordedEqual(before, linked) {
				return errRestoreObservationMismatch
			}
			total += n
			entries = append(entries, localRecoveryEntry{Path: relative, Mode: uint32(before.Mode().Perm()), Size: n, SHA256: hex.EncodeToString(hash.Sum(nil))})
		}
		return nil
	}
	if err := walk(root, "", 0); err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}
