package update

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

const (
	// ReceiptPath is the packaged install's receipt, which the lifecycle
	// writes root-owned and mode 0444 on every install, upgrade and version
	// rollback.
	ReceiptPath     = "/usr/local/share/open-trestle/distribution/receipt.json"
	maxReceiptBytes = 1 << 20
)

var (
	// ErrNotInstalled is a machine without the packaged install's receipt.
	ErrNotInstalled = errors.New("Open Trestle is not installed as a package on this machine")
	// ErrReceiptUnusable is a receipt that exists but cannot be trusted or
	// read.
	ErrReceiptUnusable = errors.New("the package receipt cannot be used")
)

// Installed is what the receipt says is installed.
type Installed struct {
	Version       Version
	ArchiveSHA256 string
}

type receiptFields struct {
	SchemaVersion *int    `json:"schema_version"`
	Target        *string `json:"target"`
	Version       *string `json:"version"`
	ArchiveSHA256 *string `json:"archive_sha256"`
}

// ReadReceipt reads the installed version from the receipt at path, which
// must be a regular mode-0444 file owned by owner (root, 0, outside tests)
// beneath folders no other account can change. Only the fields an update
// needs are read; the lifecycle verifies the rest itself.
func ReadReceipt(path string, owner uint32) (Installed, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Installed{}, fmt.Errorf("%w (no %s)", ErrNotInstalled, path)
	}
	if err != nil {
		return Installed{}, fmt.Errorf("%w: %s cannot be read", ErrReceiptUnusable, path)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 {
		return Installed{}, fmt.Errorf("%w: %s is not a regular mode-0444 file", ErrReceiptUnusable, path)
	}
	if uid, ok := fileOwner(info); !ok || uid != owner {
		return Installed{}, fmt.Errorf("%w: %s is not owned by root", ErrReceiptUnusable, path)
	}
	file, err := fileauthority.OpenReadOnly(path)
	if err != nil {
		return Installed{}, fmt.Errorf("%w: %s is in a folder another account can change", ErrReceiptUnusable, path)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() > maxReceiptBytes {
		return Installed{}, fmt.Errorf("%w: %s changed or is larger than %d bytes", ErrReceiptUnusable, path, maxReceiptBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxReceiptBytes+1))
	if err != nil || len(raw) > maxReceiptBytes {
		return Installed{}, fmt.Errorf("%w: %s cannot be read", ErrReceiptUnusable, path)
	}
	var fields receiptFields
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(&fields) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		return Installed{}, fmt.Errorf("%w: %s is not one JSON object", ErrReceiptUnusable, path)
	}
	if fields.SchemaVersion == nil || *fields.SchemaVersion < 1 || fields.Target == nil || *fields.Target != Target || fields.Version == nil || fields.ArchiveSHA256 == nil || !sha256Pattern.MatchString(*fields.ArchiveSHA256) {
		return Installed{}, fmt.Errorf("%w: %s does not describe a %s install", ErrReceiptUnusable, path, Target)
	}
	version, err := ParseVersion(*fields.Version)
	if err != nil {
		return Installed{}, fmt.Errorf("%w: %s names no SemVer version", ErrReceiptUnusable, path)
	}
	return Installed{Version: version, ArchiveSHA256: *fields.ArchiveSHA256}, nil
}
