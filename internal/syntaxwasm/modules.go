package syntaxwasm

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

//go:embed modules/manifest.json modules/*.wasm.gz
var moduleFiles embed.FS

var errModule = errors.New("syntax module does not match its manifest")

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// moduleManifest is the part of modules/manifest.json the host relies on.
// tools/build_syntax_modules.py writes the file and records every build
// input in it as well.
type moduleManifest struct {
	SchemaVersion int              `json:"schema_version"`
	Families      []familyManifest `json:"families"`
}

type familyManifest struct {
	Name       string   `json:"name"`
	Languages  []string `json:"languages"`
	Module     string   `json:"module"`
	WasmSHA256 string   `json:"wasm_sha256"`
	WasmSize   int      `json:"wasm_size"`
	GzipSHA256 string   `json:"gzip_sha256"`
	GzipSize   int      `json:"gzip_size"`
}

// maxModuleBytes bounds the decompressed size of one module. The largest
// family module is well below it.
const maxModuleBytes = 64 << 20

func readManifest() (moduleManifest, error) {
	data, err := moduleFiles.ReadFile("modules/manifest.json")
	if err != nil {
		return moduleManifest{}, err
	}
	var manifest moduleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return moduleManifest{}, err
	}
	if manifest.SchemaVersion != 1 || len(manifest.Families) == 0 {
		return moduleManifest{}, errModule
	}
	seen := map[string]bool{}
	for _, f := range manifest.Families {
		if f.Name == "" || seen[f.Name] || len(f.Languages) == 0 || f.Module != f.Name+".wasm.gz" ||
			!hex64.MatchString(f.WasmSHA256) || !hex64.MatchString(f.GzipSHA256) ||
			f.WasmSize <= 0 || f.WasmSize > maxModuleBytes || f.GzipSize <= 0 {
			return moduleManifest{}, errModule
		}
		seen[f.Name] = true
	}
	return manifest, nil
}

// loadModule returns the decompressed module after checking the compressed
// and decompressed bytes against the manifest digests.
func loadModule(f familyManifest) ([]byte, error) {
	compressed, err := moduleFiles.ReadFile("modules/" + f.Module)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(compressed)
	if len(compressed) != f.GzipSize || hex.EncodeToString(sum[:]) != f.GzipSHA256 {
		return nil, errModule
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, errModule
	}
	data, err := io.ReadAll(io.LimitReader(reader, int64(f.WasmSize)+1))
	if err != nil || reader.Close() != nil {
		return nil, errModule
	}
	sum = sha256.Sum256(data)
	if len(data) != f.WasmSize || hex.EncodeToString(sum[:]) != f.WasmSHA256 {
		return nil, errModule
	}
	return data, nil
}
