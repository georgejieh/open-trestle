package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

var errLocalSourceOwnerConflict = errors.New("local source owner record already exists")

// The hook is scoped to one call. It may arrange a filesystem change or fail a
// stage, but cannot supply final bytes or replace the strict rooted reader.
type localSourceOwnerPublishHook struct {
	Stage func(stage string, root *os.Root, temp string, file *os.File) error
	Write func(file *os.File, encoded []byte) (int, error)
}

func (hook *localSourceOwnerPublishHook) fail(stage string, root *os.Root, temp string, file *os.File) error {
	if hook == nil || hook.Stage == nil {
		return nil
	}
	return hook.Stage(stage, root, temp, file)
}

func ownerPublishIO(stage string, err error) error {
	if err == nil {
		return nil
	}
	return ownerPersistence(stage, err)
}

func ownerPublishCapability(stage string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOSYS) {
		return fmt.Errorf("%w: %s: %w", errLocalSourceOwnerUnsupported, stage, err)
	}
	return ownerPersistence(stage, err)
}

func ownerPublishTempInfo(info os.FileInfo, opened os.FileInfo, size int64) error {
	if info == nil || info.Mode() != 0600 || !info.Mode().IsRegular() || !ownerTrustedFile(info) || info.Size() != size {
		return ownerPersistence("temporary leaf metadata changed", nil)
	}
	if !os.SameFile(info, opened) {
		return ownerPersistence("temporary leaf inode changed", nil)
	}
	return nil
}

func ownerTrustedFile(info os.FileInfo) bool {
	return info != nil && fileauthority.TrustedOwner(info)
}

func ownerPublishDirectorySync(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return ownerPublishCapability("open parent for sync", err)
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	return errors.Join(ownerPublishCapability("parent sync", syncErr), ownerPublishIO("close parent", closeErr))
}

// publishLocalSourceOwnerRecord is unwired. Eligibility and observed record
// identity are the caller's responsibility; the opened root is mandatory.
func publishLocalSourceOwnerRecord(root *os.Root, statePath string, record localSourceOwnerRecord, hook *localSourceOwnerPublishHook) error {
	if _, err := observeLocalSourceDirectory(statePath, root); err != nil {
		return err
	}
	encoded, err := encodeLocalSourceOwnerRecord(record)
	if err != nil {
		return err
	}
	if len(encoded) == 0 || len(encoded) > maxLocalSourceOwnerRecordBytes {
		return ErrLocalSourceOwnerMalformed
	}
	_, err = root.Lstat(localSourceOwnerLeaf)
	if err == nil {
		return fmt.Errorf("%w: %w", errLocalSourceOwnerConflict, os.ErrExist)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ownerPersistence("final precheck", err)
	}
	if _, err := observeLocalSourceDirectory(statePath, root); err != nil {
		return err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return ownerPublishIO("temporary name randomness", err)
	}
	temp := ".local-source-owner-" + hex.EncodeToString(random) + ".tmp"
	file, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ownerPublishIO("exclusive temporary create", err)
	}
	opened, statErr := file.Stat()
	if statErr != nil || opened == nil || opened.Mode() != 0600 || !opened.Mode().IsRegular() || !ownerTrustedFile(opened) || opened.Size() != 0 {
		return errors.Join(ownerPublishIO("opened temporary capture", statErr), ownerPersistence("opened temporary metadata invalid", nil), ownerPublishIO("close uncaptured temporary file", file.Close()))
	}
	closed := false
	cleanup := func(primary error) error {
		if !closed {
			primary = errors.Join(primary, ownerPublishIO("temporary close", file.Close()))
			closed = true
		}
		info, lookupErr := root.Lstat(temp)
		if lookupErr != nil {
			return errors.Join(primary, ownerPersistence("temporary cleanup lookup", lookupErr))
		}
		if err := ownerPublishTempInfo(info, opened, info.Size()); err != nil {
			return errors.Join(primary, err)
		}
		removeErr := hook.fail("cleanup-remove", root, temp, nil)
		if removeErr == nil {
			info, lookupErr = root.Lstat(temp)
			if lookupErr != nil {
				return errors.Join(primary, ownerPersistence("temporary cleanup recheck", lookupErr))
			}
			if identityErr := ownerPublishTempInfo(info, opened, info.Size()); identityErr != nil {
				return errors.Join(primary, identityErr)
			}
			removeErr = root.Remove(temp)
		}
		if removeErr != nil {
			return errors.Join(primary, ownerPublishIO("temporary cleanup removal", removeErr))
		}
		syncErr := hook.fail("cleanup-parent-sync", root, temp, nil)
		if syncErr == nil {
			syncErr = ownerPublishDirectorySync(root)
		}
		return errors.Join(primary, ownerPublishCapability("temporary cleanup parent sync", syncErr))
	}
	info, err := root.Lstat(temp)
	if err != nil {
		return cleanup(ownerPersistence("temporary capture lookup", err))
	}
	if err := ownerPublishTempInfo(info, opened, 0); err != nil {
		return cleanup(err)
	}
	if err := hook.fail("write", root, temp, file); err != nil {
		return cleanup(ownerPublishIO("temporary write", err))
	}
	var n int
	if hook != nil && hook.Write != nil {
		n, err = hook.Write(file, encoded)
	} else {
		n, err = file.Write(encoded)
	}
	if err != nil || n != len(encoded) {
		if n != len(encoded) {
			err = errors.Join(err, io.ErrShortWrite)
		}
		return cleanup(ownerPublishIO("temporary write", err))
	}
	if err := hook.fail("file-sync", root, temp, file); err != nil {
		return cleanup(ownerPublishIO("temporary file sync", err))
	}
	if err := file.Sync(); err != nil {
		return cleanup(ownerPublishIO("temporary file sync", err))
	}
	injectedClose := hook.fail("close", root, temp, file)
	realClose := file.Close()
	closed = true
	if injectedClose != nil || realClose != nil {
		return cleanup(errors.Join(ownerPublishIO("temporary close", injectedClose), ownerPublishIO("temporary close", realClose)))
	}
	if err := hook.fail("temp-recheck", root, temp, nil); err != nil {
		return cleanup(ownerPublishIO("temporary recheck", err))
	}
	info, err = root.Lstat(temp)
	if err != nil {
		return cleanup(ownerPersistence("temporary recheck lookup", err))
	}
	if err := ownerPublishTempInfo(info, opened, int64(len(encoded))); err != nil {
		return cleanup(err)
	}
	if _, err := observeLocalSourceDirectory(statePath, root); err != nil {
		return cleanup(err)
	}
	if err := hook.fail("link", root, temp, nil); err != nil {
		return cleanup(ownerPublishLinkError(err))
	}
	if err := root.Link(temp, localSourceOwnerLeaf); err != nil {
		return cleanup(ownerPublishLinkError(err))
	}
	if err := hook.fail("post-link-parent-sync", root, temp, nil); err != nil {
		return ownerPublishCapability("post-link parent sync", err)
	}
	if err := ownerPublishDirectorySync(root); err != nil {
		return err
	}
	if err := hook.fail("strict-read", root, temp, nil); err != nil {
		return ownerPublishIO("strict reread", err)
	}
	if err := ownerPublishVerifyFinal(root, statePath, record, encoded, opened); err != nil {
		return err
	}
	info, err = root.Lstat(temp)
	if err != nil {
		return ownerPersistence("post-link temporary lookup", err)
	}
	if err := ownerPublishTempInfo(info, opened, int64(len(encoded))); err != nil {
		return err
	}
	if err := hook.fail("post-link-remove", root, temp, nil); err != nil {
		return ownerPublishIO("post-link temporary removal", err)
	}
	// Recheck after the hook too: a hook may arrange a replacement before removal.
	info, err = root.Lstat(temp)
	if err != nil {
		return ownerPersistence("post-link temporary removal lookup", err)
	}
	if err := ownerPublishTempInfo(info, opened, int64(len(encoded))); err != nil {
		return err
	}
	if err := root.Remove(temp); err != nil {
		return ownerPublishIO("post-link temporary removal", err)
	}
	if err := hook.fail("final-parent-sync", root, temp, nil); err != nil {
		return ownerPublishCapability("final parent sync", err)
	}
	if err := ownerPublishDirectorySync(root); err != nil {
		return err
	}
	return ownerPublishVerifyFinal(root, statePath, record, encoded, opened)
}

// Reobserve the live pathname after each post-link stage that can change it.
// These checks detect stage-boundary changes, not same-UID concurrent tampering.
func ownerPublishVerifyFinal(root *os.Root, statePath string, record localSourceOwnerRecord, encoded []byte, opened os.FileInfo) error {
	if _, err := observeLocalSourceDirectory(statePath, root); err != nil {
		return err
	}
	reread, raw, finalOpened, err := readLocalSourceOwnerRecordDetails(root, statePath)
	if err != nil {
		return ownerPersistence("published leaf strict reread", err)
	}
	finalNamed, err := root.Lstat(localSourceOwnerLeaf)
	if err != nil {
		return ownerPersistence("published leaf lookup", err)
	}
	if !os.SameFile(finalOpened, opened) || !os.SameFile(finalNamed, opened) || !bytes.Equal(raw, encoded) || reread != record {
		return ownerPersistence("published leaf bytes or inode changed", nil)
	}
	return nil
}

func ownerPublishLinkError(err error) error {
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%w: link: %w", errLocalSourceOwnerConflict, err)
	}
	return ownerPublishCapability("no-replace link", err)
}
