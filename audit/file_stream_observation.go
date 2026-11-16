package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// ObserveFileStream reads one exact stream through a borrowed private root.
// It neither acquires a writer nor changes files. The caller must retain and
// recheck root ownership; this observation does not authorize later effects.
func ObserveFileStream(ctx context.Context, root *os.Root, scope ReviewScope) ([]Event, error) {
	return observeFileStream(ctx, root, scope, nil, (*os.File).Close)
}

func observeFileStream(ctx context.Context, root *os.Root, scope ReviewScope, afterRead func() error, closeFile func(*os.File) error) ([]Event, error) {
	if err := validateAuditContext(ctx); err != nil {
		return nil, err
	}
	if root == nil || closeFile == nil {
		return nil, ErrInvalidAuditLedgerRoot
	}
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	before, err := root.Stat(".")
	if err != nil || !privateAuditRoot(before) {
		return nil, ErrInvalidAuditLedgerRoot
	}
	name := scope.Identity() + auditStreamFileSuffix
	first, firstInfo, present, err := readObservedAuditFile(ctx, root, name, closeFile)
	if err != nil {
		return nil, err
	}
	var events []Event
	if present {
		if len(first) == 0 || first[len(first)-1] != '\n' {
			return nil, ErrCorruptAuditStream
		}
		events, err = parseFileAuditStream(bytes.NewReader(first), scope)
		if err != nil {
			return nil, err
		}
	}
	if afterRead != nil {
		if err := afterRead(); err != nil {
			return nil, err
		}
	}
	second, secondInfo, stillPresent, err := readObservedAuditFile(ctx, root, name, closeFile)
	if err != nil {
		return nil, err
	}
	if present != stillPresent || present && (!sameObservedAuditFile(firstInfo, secondInfo) || !bytes.Equal(first, second)) {
		return nil, ErrCorruptAuditStream
	}
	after, err := root.Stat(".")
	if err != nil || !privateAuditRoot(after) || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return nil, ErrInvalidAuditLedgerRoot
	}
	if err := auditContextDone(ctx); err != nil {
		return nil, err
	}
	return events, nil
}

func privateAuditRoot(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode().Perm() == 0700 && fileauthority.TrustedOwner(info)
}

func privateObservedAuditFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && fileauthority.TrustedOwner(info)
}

func sameObservedAuditFile(a, b os.FileInfo) bool {
	return privateObservedAuditFile(a) && privateObservedAuditFile(b) && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func readObservedAuditFile(ctx context.Context, root *os.Root, name string, closeFile func(*os.File) error) ([]byte, os.FileInfo, bool, error) {
	if err := auditContextDone(ctx); err != nil {
		return nil, nil, false, err
	}
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, errors.Join(ErrAuditPersistence, err)
	}
	if !privateObservedAuditFile(before) {
		return nil, nil, false, ErrCorruptAuditStream
	}
	if before.Size() <= 0 || before.Size() > maxAuditStreamBytes {
		return nil, nil, false, ErrAuditStreamTooLarge
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, false, errors.Join(ErrAuditPersistence, err)
	}
	opened, statErr := file.Stat()
	if statErr != nil || !sameObservedAuditFile(before, opened) {
		return nil, nil, false, errors.Join(ErrCorruptAuditStream, statErr, closeFile(file))
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, before.Size()+1))
	after, statErr := file.Stat()
	closeErr := closeFile(file)
	linked, linkErr := root.Lstat(name)
	if readErr != nil || statErr != nil || closeErr != nil || linkErr != nil {
		return nil, nil, false, errors.Join(ErrAuditPersistence, readErr, statErr, closeErr, linkErr)
	}
	if int64(len(raw)) != before.Size() || !sameObservedAuditFile(before, after) || !sameObservedAuditFile(before, linked) {
		return nil, nil, false, ErrCorruptAuditStream
	}
	if err := auditContextDone(ctx); err != nil {
		return nil, nil, false, err
	}
	return raw, linked, true, nil
}
