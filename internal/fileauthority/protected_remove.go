package fileauthority

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
)

var (
	ErrProtectedRemoveRefused    = errors.New("protected removal refused")
	ErrProtectedRemoveIncomplete = errors.New("protected removal incomplete")
)

// RemoveValidatedProtectedFile removes one sampled, validated entry under its
// pinned parent. It does not isolate against hostile code running as this user.
func RemoveValidatedProtectedFile(ctx context.Context, path string, limit int, validate func([]byte) error) error {
	if ctx == nil || ctx.Err() != nil || limit <= 0 || limit > 65536 || validate == nil {
		return ErrProtectedRemoveRefused
	}
	parent, base, err := protectedWriteTarget(path)
	if err != nil {
		return ErrProtectedRemoveRefused
	}
	chain, err := pinChain(parent, true)
	if err != nil {
		return ErrProtectedRemoveRefused
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return ErrProtectedRemoveRefused
	}
	removed := false
	finish := func(result error) error {
		if err := root.Close(); err != nil && removed {
			return ErrProtectedRemoveIncomplete
		}
		return result
	}
	rootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(rootInfo, chain[0].info) || rootInfo.Mode() != chain[0].info.Mode() || recheckChain(chain) != nil {
		return finish(ErrProtectedRemoveRefused)
	}
	before, err := root.Lstat(base)
	if err != nil || !trustedCreatedProtectedFile(before) || before.Size() <= 0 || before.Size() > int64(limit) {
		return finish(ErrProtectedRemoveRefused)
	}
	file, err := root.Open(base)
	if err != nil {
		return finish(ErrProtectedRemoveRefused)
	}
	opened, err := file.Stat()
	if err != nil || !sameProtectedRemovalInfo(before, opened) {
		_ = file.Close()
		return finish(ErrProtectedRemoveRefused)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || !sameProtectedRemovalInfo(before, after) || len(encoded) > limit || ctx.Err() != nil || validate(append([]byte(nil), encoded...)) != nil {
		_ = file.Close()
		return finish(ErrProtectedRemoveRefused)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return finish(ErrProtectedRemoveRefused)
	}
	again, readErr := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	final, statErr := file.Stat()
	closeErr := file.Close()
	linked, linkErr := root.Lstat(base)
	if readErr != nil || statErr != nil || closeErr != nil || linkErr != nil || !bytes.Equal(encoded, again) || !sameProtectedRemovalInfo(before, final) || !sameProtectedRemovalInfo(before, linked) || recheckChain(chain) != nil || ctx.Err() != nil {
		return finish(ErrProtectedRemoveRefused)
	}
	if err := root.Remove(base); err != nil {
		return finish(ErrProtectedRemoveIncomplete)
	}
	removed = true
	directory, err := root.Open(".")
	if err != nil {
		return finish(ErrProtectedRemoveIncomplete)
	}
	syncErr := directory.Sync()
	closeErr = directory.Close()
	_, absentErr := root.Lstat(base)
	if syncErr != nil || closeErr != nil || !os.IsNotExist(absentErr) || recheckChain(chain) != nil || ctx.Err() != nil {
		return finish(ErrProtectedRemoveIncomplete)
	}
	return finish(nil)
}

func sameProtectedRemovalInfo(a, b os.FileInfo) bool {
	return a != nil && b != nil && trustedCreatedProtectedFile(a) && trustedCreatedProtectedFile(b) && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
