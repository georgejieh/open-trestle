package update

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

// ErrArchiveInvalid is an archive that is not a packaged Open Trestle
// archive for this target.
var ErrArchiveInvalid = errors.New("not a packaged Open Trestle archive")

const maxManifestBytes = 1 << 20

var revisionPattern = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})?$`)

// Manifest is what a packaged archive says about itself in manifest.json.
// Only the fields an update shows or checks are read; the archive's own
// lifecycle validates the rest.
type Manifest struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Target   string `json:"target"`
	Revision string `json:"revision"`
	Created  string `json:"created"`
}

// ReadManifest reads manifest.json from a packaged archive (a zip after the
// pyz shebang) and checks that it is Open Trestle for this target with a
// SemVer version. It reads the zip directory and that one member only.
func ReadManifest(archive io.ReaderAt, size int64) (Manifest, Version, error) {
	reader, err := zip.NewReader(archive, size)
	if err != nil {
		return Manifest{}, Version{}, fmt.Errorf("%w: not a zip archive", ErrArchiveInvalid)
	}
	var entry *zip.File
	for _, file := range reader.File {
		if file.Name != "manifest.json" {
			continue
		}
		if entry != nil {
			return Manifest{}, Version{}, fmt.Errorf("%w: more than one manifest", ErrArchiveInvalid)
		}
		entry = file
	}
	if entry == nil || entry.Method != zip.Store || entry.UncompressedSize64 > maxManifestBytes {
		return Manifest{}, Version{}, fmt.Errorf("%w: no stored manifest within %d bytes", ErrArchiveInvalid, maxManifestBytes)
	}
	source, err := entry.Open()
	if err != nil {
		return Manifest{}, Version{}, fmt.Errorf("%w: the manifest cannot be read", ErrArchiveInvalid)
	}
	raw, err := io.ReadAll(io.LimitReader(source, maxManifestBytes+1))
	closeErr := source.Close()
	if err != nil || closeErr != nil || len(raw) > maxManifestBytes {
		return Manifest{}, Version{}, fmt.Errorf("%w: the manifest cannot be read", ErrArchiveInvalid)
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(&fields) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || fields == nil {
		return Manifest{}, Version{}, fmt.Errorf("%w: the manifest is not one JSON object", ErrArchiveInvalid)
	}
	var manifest Manifest
	if json.Unmarshal(raw, &manifest) != nil {
		return Manifest{}, Version{}, fmt.Errorf("%w: the manifest fields have the wrong types", ErrArchiveInvalid)
	}
	if manifest.Name != "open-trestle" || manifest.Target != Target {
		return Manifest{}, Version{}, fmt.Errorf("%w: the manifest is not Open Trestle for %s", ErrArchiveInvalid, Target)
	}
	version, err := ParseVersion(manifest.Version)
	if err != nil {
		return Manifest{}, Version{}, fmt.Errorf("%w: the manifest version is not SemVer", ErrArchiveInvalid)
	}
	if !revisionPattern.MatchString(manifest.Revision) {
		return Manifest{}, Version{}, fmt.Errorf("%w: the manifest revision is not a commit ID", ErrArchiveInvalid)
	}
	return manifest, version, nil
}
