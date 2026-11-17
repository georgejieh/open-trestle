// Package fileauthority validates local file ownership and replacement authority.
//
// On Unix it reads owners and mode bits. On Windows, where mode bits say
// nothing about access, it reads the owner and DACL of each object through a
// handle; see package ownersonly for the rules.
package fileauthority

import (
	"errors"
	"os"
	"path/filepath"
)

var ErrUntrustedPath = errors.New("untrusted file authority")

// componentRole is what a path component must be: the final directory, the
// final regular file, or a directory above them.
type componentRole uint8

const (
	roleAncestor componentRole = iota
	roleDirectory
	roleFile
)

type pinnedPath struct {
	path string
	info os.FileInfo
	role componentRole
}

// DirectoryPin is a sampled, checked directory path chain, not an authorization token.
// Its saved component identities are private and cannot be changed by callers.
type DirectoryPin struct {
	chain []pinnedPath
}

// PinDirectory captures a trusted non-symlink directory and all of its ancestors.
func PinDirectory(path string) (*DirectoryPin, error) {
	chain, err := pinChain(path, true)
	if err != nil {
		return nil, err
	}
	if err := recheckChain(chain); err != nil {
		return nil, err
	}
	return &DirectoryPin{chain: chain}, nil
}

// Recheck compares the path chain against the same saved component identities.
func (p *DirectoryPin) Recheck() error {
	if p == nil || len(p.chain) == 0 {
		return ErrUntrustedPath
	}
	return recheckChain(p.chain)
}

// pinChain samples path and every directory above it. Each component must be
// trusted in its role: owned by this account or the administrator, and
// writable by no one else, except that a directory above another may let
// others add entries the way a sticky directory does.
func pinChain(path string, directory bool) ([]pinnedPath, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || path == "" {
		return nil, ErrUntrustedPath
	}
	chain := []pinnedPath{}
	for current := absolute; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUntrustedPath
		}
		component := pinnedPath{path: current, info: info, role: roleAncestor}
		var child *pinnedPath
		if len(chain) == 0 {
			component.role = roleFile
			if directory {
				component.role = roleDirectory
			}
		} else {
			child = &chain[len(chain)-1]
		}
		if !componentTrusted(component, child) {
			return nil, ErrUntrustedPath
		}
		chain = append(chain, component)
		if filepath.Dir(current) == current {
			break
		}
	}
	return chain, nil
}

func recheckChain(chain []pinnedPath) error {
	for index, pin := range chain {
		info, err := os.Lstat(pin.path)
		if err != nil || !os.SameFile(info, pin.info) || info.Mode() != pin.info.Mode() {
			return ErrUntrustedPath
		}
		var child *pinnedPath
		if index > 0 {
			child = &chain[index-1]
		}
		if !componentTrusted(pinnedPath{path: pin.path, info: info, role: pin.role}, child) {
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
	if err != nil || !os.SameFile(opened, chain[0].info) || opened.Mode() != chain[0].info.Mode() || !openedFileTrusted(file, opened) || recheckChain(chain) != nil {
		_ = file.Close()
		return nil, ErrUntrustedPath
	}
	return file, nil
}
