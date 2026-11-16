package update

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/testsupport"
)

func TestReadManifestFromAShebangArchive(t *testing.T) {
	archive := testsupport.UpdateArchive("0.2.0", Target)
	manifest, version, err := ReadManifest(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	if version.String() != "0.2.0" || manifest.Name != "open-trestle" || manifest.Target != Target || manifest.Revision != strings.Repeat("a", 40) {
		t.Fatalf("manifest=%+v version=%s", manifest, version)
	}
}

func TestReadManifestRefusals(t *testing.T) {
	encode := func(value map[string]any) []byte {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	good := map[string]any{"name": "open-trestle", "version": "0.2.0", "target": Target, "revision": strings.Repeat("a", 40), "created": "x", "files": []any{}, "schema_version": 2}
	with := func(key string, value any) []byte {
		changed := map[string]any{}
		for k, v := range good {
			changed[k] = v
		}
		if value == nil {
			delete(changed, key)
		} else {
			changed[key] = value
		}
		return encode(changed)
	}
	for name, archive := range map[string][]byte{
		"not a zip":        []byte("#!/usr/bin/env python3\nnot a zip"),
		"no manifest":      testsupport.UpdateArchiveWith(map[string][]byte{"__main__.py": []byte("x")}),
		"other target":     testsupport.UpdateArchive("0.2.0", "linux-arm64"),
		"bad version":      testsupport.UpdateArchive("0.2", Target),
		"other name":       testsupport.UpdateArchiveWith(map[string][]byte{"manifest.json": with("name", "other")}),
		"no version":       testsupport.UpdateArchiveWith(map[string][]byte{"manifest.json": with("version", nil)}),
		"bad revision":     testsupport.UpdateArchiveWith(map[string][]byte{"manifest.json": with("revision", "HEAD")}),
		"not an object":    testsupport.UpdateArchiveWith(map[string][]byte{"manifest.json": []byte(`["open-trestle"]`)}),
		"trailing data":    testsupport.UpdateArchiveWith(map[string][]byte{"manifest.json": append(encode(good), []byte(" {}")...)}),
		"oversized":        testsupport.UpdateArchiveWith(map[string][]byte{"manifest.json": append(encode(good), bytes.Repeat([]byte(" "), maxManifestBytes)...)}),
		"version not text": testsupport.UpdateArchiveWith(map[string][]byte{"manifest.json": with("version", 2)}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ReadManifest(bytes.NewReader(archive), int64(len(archive))); !errors.Is(err, ErrArchiveInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
