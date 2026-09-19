package scm

import (
	"context"
	"os"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestLocalGitPackIndexCatalogBuildEnforcesCumulativePhysicalReadLimit(t *testing.T) {
	algorithm := evidence.RevisionAlgorithmSHA1
	objectRoot, _, _, files := packedSimpleRevisionFixture(t, algorithm, nil)

	indexPhaseReads := packedCatalogIndexPhaseReadBytes(t, files, algorithm)
	packPhaseReads := int64(len(files.pack) + localGitPackHeaderBytes)
	rejectLimit := indexPhaseReads + localGitPackHeaderBytes
	if rejectLimit <= indexPhaseReads || rejectLimit >= indexPhaseReads+packPhaseReads {
		t.Fatalf("reject limit %d is not between index phase %d and index+pack phase %d", rejectLimit, indexPhaseReads, indexPhaseReads+packPhaseReads)
	}

	catalog, err := packedOpenCatalogWithPhysicalReadLimit(t, objectRoot, algorithm, rejectLimit)
	if err != LocalGitRevisionResourceLimit {
		t.Fatalf("newLocalGitPackIndexCatalog(limit %d) error = %v, catalog = %#v, want %v", rejectLimit, err, catalog, LocalGitRevisionResourceLimit)
	}

	controlLimit := indexPhaseReads + packPhaseReads + int64(len(files.entries))*(int64(packedHashSize(t, algorithm))+localGitPackHeaderBytes) + 4096
	catalog, err = packedOpenCatalogWithPhysicalReadLimit(t, objectRoot, algorithm, controlLimit)
	if err != nil {
		t.Fatalf("newLocalGitPackIndexCatalog(control limit %d) error = %v", controlLimit, err)
	}
	if catalog.catalogPhysicalBytes <= rejectLimit {
		t.Fatalf("catalogPhysicalBytes = %d, want more than rejecting cumulative limit %d", catalog.catalogPhysicalBytes, rejectLimit)
	}
}

func packedOpenCatalogWithPhysicalReadLimit(t *testing.T, objectRoot string, algorithm evidence.RevisionAlgorithm, limit int64) (*localGitPackIndexCatalog, error) {
	t.Helper()
	root, err := os.OpenRoot(objectRoot)
	if err != nil {
		t.Fatal(err)
	}
	limits := standardLocalGitPackLimits()
	limits.maxPhysicalReadBytes = limit
	catalog, err := newLocalGitPackIndexCatalog(context.Background(), root, algorithm, limits)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	t.Cleanup(func() {
		_ = catalog.close()
		_ = root.Close()
	})
	return catalog, nil
}

func packedCatalogIndexPhaseReadBytes(t *testing.T, files packedTestFiles, algorithm evidence.RevisionAlgorithm) int64 {
	t.Helper()
	hashLen := packedHashSize(t, algorithm)
	objectCount := len(files.entries)
	_, _, _, _, packChecksumOffset := packedIdxLayout(t, algorithm, objectCount)
	if packChecksumOffset != len(files.idx)-2*hashLen {
		t.Fatalf("unexpected fixture index layout: pack checksum offset = %d, want %d", packChecksumOffset, len(files.idx)-2*hashLen)
	}
	for _, entry := range files.entries {
		if entry.offset > 0x7fffffff {
			t.Fatalf("fixture unexpectedly requires a large-offset index row at offset %d", entry.offset)
		}
	}
	return int64(8+256*4) + int64(len(files.idx)-hashLen) + int64(hashLen) + int64(hashLen) + int64(objectCount*hashLen) + int64(objectCount*8)
}
