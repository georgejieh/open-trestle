package fileauthority

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
)

var (
	ErrProtectedWriteRefused    = errors.New("protected write refused")
	ErrProtectedWriteIncomplete = errors.New("protected write incomplete")
)

// WriteNewProtectedFile creates path with descriptor-relative exclusive create
// beneath an already trusted parent and writes content durably. It never removes
// an output file after create; on ErrProtectedWriteIncomplete a partial or
// complete file may remain.
func WriteNewProtectedFile(ctx context.Context, path string, content []byte, limit int) error {
	if ctx == nil {
		return ErrProtectedWriteRefused
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if limit <= 0 || limit > 65536 || len(content) == 0 || len(content) > limit {
		return ErrProtectedWriteRefused
	}
	parent, base, err := protectedWriteTarget(path)
	if err != nil {
		return ErrProtectedWriteRefused
	}
	chain, err := pinChain(parent, true)
	if err != nil {
		return ErrProtectedWriteRefused
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := os.OpenRoot(parent)
	if err != nil || root == nil {
		return ErrProtectedWriteRefused
	}
	created := false
	closeRoot := func(current error) error {
		if closeErr := root.Close(); closeErr != nil && created {
			return ErrProtectedWriteIncomplete
		}
		return current
	}
	if info, err := root.Stat("."); err != nil || !os.SameFile(info, chain[0].info) || info.Mode() != chain[0].info.Mode() || !componentTrusted(pinnedPath{path: chain[0].path, info: info, role: roleDirectory}, nil) || recheckChain(chain) != nil {
		return closeRoot(ErrProtectedWriteRefused)
	}
	if err := ctx.Err(); err != nil {
		return closeRoot(err)
	}
	target := filepath.Join(chain[0].path, base)
	file, err := createProtected(root, chain[0].path, base)
	if err != nil || file == nil {
		return closeRoot(ErrProtectedWriteRefused)
	}
	created = true
	createdInfo, err := file.Stat()
	if err != nil || !PrivateOpenFile(file, createdInfo) {
		_ = file.Close()
		return closeRoot(ErrProtectedWriteIncomplete)
	}
	linkedInfo, err := root.Lstat(base)
	if err != nil || !os.SameFile(createdInfo, linkedInfo) || linkedInfo.Mode() != createdInfo.Mode() || !PrivateFile(target, linkedInfo) {
		_ = file.Close()
		return closeRoot(ErrProtectedWriteIncomplete)
	}
	if err := ctx.Err(); err != nil {
		_ = file.Close()
		return closeRoot(ErrProtectedWriteIncomplete)
	}
	if err := writeAllProtected(file, content); err != nil {
		_ = file.Close()
		return closeRoot(ErrProtectedWriteIncomplete)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return closeRoot(ErrProtectedWriteIncomplete)
	}
	if err := file.Close(); err != nil {
		return closeRoot(ErrProtectedWriteIncomplete)
	}
	if err := syncRoot(root, chain[0].path); err != nil {
		return closeRoot(ErrProtectedWriteIncomplete)
	}
	currentInfo, err := root.Lstat(base)
	if err != nil || !os.SameFile(createdInfo, currentInfo) || currentInfo.Mode() != createdInfo.Mode() || currentInfo.Size() != int64(len(content)) || !PrivateFile(target, currentInfo) || recheckChain(chain) != nil {
		return closeRoot(ErrProtectedWriteIncomplete)
	}
	if err := ctx.Err(); err != nil {
		return closeRoot(ErrProtectedWriteIncomplete)
	}
	return closeRoot(nil)
}

func protectedWriteTarget(name string) (string, string, error) {
	if name == "" || filepath.Clean(name) != name {
		return "", "", ErrProtectedWriteRefused
	}
	base := filepath.Base(name)
	if base == "." || base == ".." || base == string(os.PathSeparator) || base == "" {
		return "", "", ErrProtectedWriteRefused
	}
	parent := filepath.Dir(name)
	if parent == "" {
		return "", "", ErrProtectedWriteRefused
	}
	return parent, base, nil
}

func writeAllProtected(file *os.File, content []byte) error {
	for len(content) > 0 {
		written, err := file.Write(content)
		if written > 0 {
			content = content[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
