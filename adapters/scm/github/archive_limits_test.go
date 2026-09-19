package github

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func skippedEntryArchive(t *testing.T, rootFile bool, directories int) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	tw := tar.NewWriter(gz)
	root := &tar.Header{Name: "repo/", Typeflag: tar.TypeDir, Mode: 0700}
	if rootFile {
		root.Name = "repo"
		root.Typeflag = tar.TypeReg
		root.Size = 1
	}
	if err := tw.WriteHeader(root); err != nil {
		t.Fatal(err)
	}
	if rootFile {
		if _, err := tw.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < directories; i++ {
		if err := tw.WriteHeader(&tar.Header{Name: "repo/dir/", Typeflag: tar.TypeDir, Mode: 0700}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: "repo/a.go", Typeflag: tar.TypeReg, Size: 1, Mode: 0600}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func TestArchiveRejectsNonDirectoryRootAndExcessSkippedEntries(t *testing.T) {
	files := map[string]treeFile{"a.go": {mode: "100644", size: 1, sha: gitObjectSHA1("blob", []byte("a"))}}
	for _, test := range []struct {
		name        string
		rootFile    bool
		directories int
	}{
		{"root regular file", true, 0},
		{"excess skipped directory entries", false, maximumTreeEntries + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded := skippedEntryArchive(t, test.rootFile, test.directories)
			response := &http.Response{Body: io.NopCloser(bytes.NewReader(encoded)), ContentLength: int64(len(encoded))}
			contents, failure := extractArchive(context.Background(), response, evidence.RevisionAlgorithmSHA1, files)
			if failure == nil || len(contents) != 0 {
				t.Fatalf("skipped archive input accepted: files=%d failure=%v", len(contents), failure)
			}
		})
	}
}

func TestArchiveChargesHeadersAndTrailingInflatedBytes(t *testing.T) {
	files := map[string]treeFile{"a.go": {mode: "100644", size: 1, sha: gitObjectSHA1("blob", []byte("a"))}}
	encoded := skippedEntryArchive(t, false, 2)
	// This budget is below the tar headers alone, despite a one-byte payload.
	response := &http.Response{Body: io.NopCloser(bytes.NewReader(encoded)), ContentLength: int64(len(encoded))}
	contents, failure := extractArchiveWithinLimits(context.Background(), response, evidence.RevisionAlgorithmSHA1, files, 1024, 10)
	if failure == nil || failure.reason != evidence.AcquisitionReasonResourceLimit || len(contents) != 0 {
		t.Fatalf("header bytes escaped budget: failure=%v", failure)
	}

	original := skippedEntryArchive(t, false, 0)
	var combined bytes.Buffer
	combined.Write(original)
	extra := gzip.NewWriter(&combined)
	if _, err := extra.Write(bytes.Repeat([]byte{'x'}, 8192)); err != nil {
		t.Fatal(err)
	}
	if err := extra.Close(); err != nil {
		t.Fatal(err)
	}
	response = &http.Response{Body: io.NopCloser(bytes.NewReader(combined.Bytes())), ContentLength: int64(combined.Len())}
	contents, failure = extractArchiveWithinLimits(context.Background(), response, evidence.RevisionAlgorithmSHA1, files, 4096, 10)
	if failure == nil || failure.reason != evidence.AcquisitionReasonResourceLimit || len(contents) != 0 {
		t.Fatalf("trailing inflated bytes escaped budget: failure=%v", failure)
	}
}

func TestArchiveCancellationFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	encoded := skippedEntryArchive(t, false, 0)
	response := &http.Response{Body: io.NopCloser(bytes.NewReader(encoded)), ContentLength: int64(len(encoded))}
	contents, failure := extractArchive(ctx, response, evidence.RevisionAlgorithmSHA1, nil)
	if failure == nil || failure.reason != evidence.AcquisitionReasonAdapterUnavailable || len(contents) != 0 {
		t.Fatalf("canceled extraction accepted: failure=%v", failure)
	}
}
