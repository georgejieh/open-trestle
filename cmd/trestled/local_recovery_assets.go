package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type localRecoveryAsset struct {
	Role   string `json:"role"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// observeRecoveryAssets pins operator-retained runtime inputs without executing
// a scanner, loading credentials, or contacting a model route.
func observeRecoveryAssets(ctx context.Context, assets []localRecoveryAsset) ([]localRecoveryAsset, error) {
	roles := []string{"binary", "scanner", "scanner-worker", "route-inventory", "runtime-policy"}
	if len(assets) != len(roles) {
		return nil, errInvalidRecoveryPoint
	}
	observed := make([]localRecoveryAsset, len(assets))
	var total int64
	for i, asset := range assets {
		if ctx == nil || ctx.Err() != nil || asset.Role != roles[i] || !validLocalOwnerPath(asset.Path) {
			return nil, errInvalidRecoveryPoint
		}
		file, err := fileauthority.OpenReadOnly(asset.Path)
		if err != nil {
			return nil, err
		}
		before, statErr := file.Stat()
		if statErr != nil || before.Size() <= 0 || before.Size() > localRecoveryInventoryBytes-total {
			file.Close()
			return nil, errInvalidRecoveryPoint
		}
		hash := sha256.New()
		size, readErr := io.Copy(hash, io.LimitReader(file, before.Size()+1))
		after, statErr := file.Stat()
		closeErr := file.Close()
		linked, linkErr := os.Lstat(asset.Path)
		if readErr != nil || statErr != nil || closeErr != nil || linkErr != nil {
			return nil, errors.Join(readErr, statErr, closeErr, linkErr)
		}
		if size != before.Size() || !recordedEqual(before, after) || !recordedEqual(before, linked) {
			return nil, errRestoreObservationMismatch
		}
		total += size
		observed[i] = localRecoveryAsset{Role: asset.Role, Path: asset.Path, SHA256: hex.EncodeToString(hash.Sum(nil))}
	}
	// Decode the pinned operator configuration with canonical policy/inventory codecs.
	if _, _, err := runtimeconfig.LoadProtectedConfiguration(ctx, assets[3].Path, assets[4].Path); err != nil {
		return nil, err
	}
	return observed, nil
}
