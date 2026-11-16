package testsupport

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"strings"
)

// UpdateArchive returns a small stand-in for the packaged Linux archive: the
// pyz shebang followed by a stored zip with __main__.py and a manifest.json
// naming version and target, laid out as tools/linux_distribution.py lays out
// the real one. It is not a working lifecycle; tests fake its verify-archive.
func UpdateArchive(version, target string) []byte {
	manifest, err := json.Marshal(map[string]any{
		"created":        "2026-11-15T00:00:00Z",
		"files":          []any{},
		"name":           "open-trestle",
		"revision":       strings.Repeat("a", 40),
		"schema_version": 2,
		"target":         target,
		"version":        version,
	})
	if err != nil {
		panic(err)
	}
	return UpdateArchiveWith(map[string][]byte{
		"__main__.py":   []byte("raise SystemExit('test archive')\n"),
		"manifest.json": manifest,
	})
}

// UpdateArchiveWith returns the shebang followed by a stored zip of members.
func UpdateArchiveWith(members map[string][]byte) []byte {
	shebang := []byte("#!/usr/bin/env python3\n")
	var archive bytes.Buffer
	archive.Write(shebang)
	writer := zip.NewWriter(&archive)
	writer.SetOffset(int64(len(shebang)))
	for _, name := range slices.Sorted(maps.Keys(members)) {
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			panic(err)
		}
		if _, err := entry.Write(members[name]); err != nil {
			panic(err)
		}
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return archive.Bytes()
}

// UpdateSidecar is the SHA-256 sidecar the packager writes beside archive
// when it is named name.
func UpdateSidecar(archive []byte, name string) []byte {
	sum := sha256.Sum256(archive)
	return []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
}
