//go:build linux

package scm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestLocalGitPackedFailedCatalogBuildDoesNotAccumulatePackIndexFDs(t *testing.T) {
	objectRoot, revision, _, files := packedSimpleRevisionFixture(t, evidence.RevisionAlgorithmSHA1, func(f *packedTestFiles) {
		f.idx[len(f.idx)-1] ^= 0x55
	})
	store, root := packedOpenStore(t, objectRoot, evidence.RevisionAlgorithmSHA1)
	beforePack, beforeIndex := ownedPackIndexFDCounts(t, files.packPath, files.idxPath)
	for i := 0; i < 8; i++ {
		ctx, cancel := packedRegressionContext(t)
		result, err := ReadLocalGitRevision(ctx, store, revision)
		cancel()
		if err == nil || result.RevisionIdentity() != "" || !strings.Contains(err.Error(), "Git pack index checksum mismatch") {
			t.Fatalf("ReadLocalGitRevision(corrupt index checksum) iteration %d = (%#v, %v), want checksum failure and no result", i, result, err)
		}
		gotPack, gotIndex := ownedPackIndexFDCounts(t, files.packPath, files.idxPath)
		if gotPack != beforePack || gotIndex != beforeIndex {
			t.Fatalf("owned pack/index fds after failing acquisition %d = (%d, %d), before (%d, %d)", i+1, gotPack, gotIndex, beforePack, beforeIndex)
		}
	}
	if _, err := root.Stat("."); err != nil {
		t.Fatalf("caller object root is not usable after failed acquisitions: %v", err)
	}
	ctx, cancel := packedRegressionContext(t)
	if err := store.Close(ctx); err != nil {
		cancel()
		t.Fatalf("Close() after failed acquisitions error = %v", err)
	}
	cancel()
}

func ownedPackIndexFDCounts(t *testing.T, packPath, indexPath string) (int, int) {
	t.Helper()
	packPath = filepath.Clean(packPath)
	indexPath = filepath.Clean(indexPath)
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("ReadDir(/proc/self/fd) error = %v", err)
	}
	var packs int
	var indexes int
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil {
			continue
		}
		target = filepath.Clean(strings.TrimSuffix(target, " (deleted)"))
		switch target {
		case packPath:
			packs++
		case indexPath:
			indexes++
		}
	}
	return packs, indexes
}
