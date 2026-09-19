package runtimeconfig

import (
	"bytes"
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"io"
	"os"
	"path/filepath"
)

var ErrProtectedConfiguration = errors.New("protected runtime configuration unavailable or unstable")

type protectedConfigurationFile interface {
	Read([]byte) (int, error)
	Stat() (os.FileInfo, error)
	Close() error
}

// LoadProtectedConfiguration reads explicit protected execution authority. No
// credential lookup, environment fallback, or remote access occurs here.
func LoadProtectedConfiguration(ctx context.Context, inventoryPath, policyPath string) (RouteInventory, RuntimePolicy, error) {
	fail := func() (RouteInventory, RuntimePolicy, error) {
		return RouteInventory{}, RuntimePolicy{}, ErrProtectedConfiguration
	}
	if ctx == nil || ctx.Err() != nil || inventoryPath == "" || policyPath == "" {
		return fail()
	}
	first, e1 := filepath.Abs(inventoryPath)
	second, e2 := filepath.Abs(policyPath)
	if e1 != nil || e2 != nil || first == second {
		return fail()
	}
	opener := func(path string) (protectedConfigurationFile, error) { return fileauthority.OpenReadOnly(path) }
	inventoryBytes, err := readProtectedConfiguration(ctx, inventoryPath, 8<<20, opener)
	if err != nil {
		return fail()
	}
	policyBytes, err := readProtectedConfiguration(ctx, policyPath, 1<<20, opener)
	if err != nil {
		return fail()
	}
	inventory, err := DecodeRouteInventory(ctx, bytes.NewReader(inventoryBytes))
	if err != nil {
		return fail()
	}
	policy, err := DecodeRuntimePolicy(ctx, bytes.NewReader(policyBytes), inventory)
	if err != nil || policy.ValidateAgainstInventory(inventory) != nil || ctx.Err() != nil {
		return fail()
	}
	// Recheck both after decoding and cross-file binding. There is no persistent
	// pathname authority: returned values are immutable content-bound snapshots.
	inventoryAgain, err := readProtectedConfiguration(ctx, inventoryPath, 8<<20, opener)
	if err != nil || !bytes.Equal(inventoryAgain, inventoryBytes) {
		return fail()
	}
	policyAgain, err := readProtectedConfiguration(ctx, policyPath, 1<<20, opener)
	if err != nil || !bytes.Equal(policyAgain, policyBytes) || ctx.Err() != nil {
		return fail()
	}
	return inventory, policy, nil
}
func readProtectedConfiguration(ctx context.Context, path string, limit int, opener func(string) (protectedConfigurationFile, error)) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || limit <= 0 || limit > 8<<20 || opener == nil {
		return nil, ErrProtectedConfiguration
	}
	var first []byte
	var original os.FileInfo
	for pass := 0; pass < 2; pass++ {
		if ctx.Err() != nil {
			return nil, ErrProtectedConfiguration
		}
		file, err := opener(path)
		if err != nil || file == nil {
			return nil, ErrProtectedConfiguration
		}
		before, statErr := file.Stat()
		var value []byte
		if statErr == nil && before.Mode().IsRegular() && before.Size() <= int64(limit) {
			value, err = io.ReadAll(io.LimitReader(protectedContextReader{ctx, file}, int64(limit)+1))
		} else {
			err = ErrProtectedConfiguration
		}
		after, afterErr := file.Stat()
		closeErr := file.Close()
		if err != nil || statErr != nil || afterErr != nil || closeErr != nil || ctx.Err() != nil || len(value) > limit || !stableProtectedInfo(before, after) {
			return nil, ErrProtectedConfiguration
		}
		if pass == 0 {
			first = value
			original = before
		} else if !stableProtectedInfo(original, before) || !bytes.Equal(first, value) {
			return nil, ErrProtectedConfiguration
		}
	}
	return first, nil
}
func stableProtectedInfo(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

type protectedContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r protectedContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p)
	if canceled := r.ctx.Err(); canceled != nil {
		return n, canceled
	}
	return n, err
}
