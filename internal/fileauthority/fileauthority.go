// Package fileauthority validates local file ownership and replacement authority.
package fileauthority

import (
	"errors"
	"os"
	"path/filepath"
)

var ErrUntrustedPath = errors.New("untrusted file authority")

type pinnedPath struct {
	path string
	info os.FileInfo
}

func trustedParent(parent, child os.FileInfo) bool {
	return parent.IsDir() && parent.Mode()&os.ModeSymlink == 0 && TrustedOwner(parent) &&
		(parent.Mode().Perm()&0022 == 0 || parent.Mode()&os.ModeSticky != 0 && TrustedOwner(child))
}

func pinChain(path string, directory bool) ([]pinnedPath, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || path == "" {
		return nil, ErrUntrustedPath
	}
	chain := []pinnedPath{}
	for current := absolute; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !TrustedOwner(info) {
			return nil, ErrUntrustedPath
		}
		if len(chain) == 0 {
			if directory {
				if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
					return nil, ErrUntrustedPath
				}
			} else if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
				return nil, ErrUntrustedPath
			}
		} else if !trustedParent(info, chain[len(chain)-1].info) {
			return nil, ErrUntrustedPath
		}
		chain = append(chain, pinnedPath{current, info})
		if filepath.Dir(current) == current {
			break
		}
	}
	return chain, nil
}

func recheckChain(chain []pinnedPath) error {
	for index, pin := range chain {
		info, err := os.Lstat(pin.path)
		if err != nil || !os.SameFile(info, pin.info) || info.Mode() != pin.info.Mode() || !TrustedOwner(info) {
			return ErrUntrustedPath
		}
		if index > 0 && !trustedParent(info, chain[index-1].info) {
			return ErrUntrustedPath
		}
	}
	return nil
}

// CheckDirectory refuses directories controlled by another local principal.
func CheckDirectory(path string) error {
	chain, err := pinChain(path, true)
	if err != nil {
		return err
	}
	return recheckChain(chain)
}

// OpenReadOnly pins a regular configuration file beneath trusted ancestors.
// Callers must separately bound and validate its content before using it as authority.
func OpenReadOnly(path string) (*os.File, error) {
	chain, err := pinChain(path, false)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(chain[0].path)
	if err != nil {
		return nil, ErrUntrustedPath
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(opened, chain[0].info) || opened.Mode() != chain[0].info.Mode() || !TrustedOwner(opened) || recheckChain(chain) != nil {
		_ = file.Close()
		return nil, ErrUntrustedPath
	}
	return file, nil
}
