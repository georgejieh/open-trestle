package update

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

// TrestlePath is where the packaged install puts trestle.
const TrestlePath = "/usr/local/bin/trestle"

// Installed is what the receipt says is installed.
type Installed struct {
	Version       Version
	ArchiveSHA256 string
	// Trestle is the receipt's SHA-256 and size of TrestlePath, or a zero
	// value when the receipt lists none.
	Trestle InstalledFile
}

// InstalledFile is one file the receipt binds.
type InstalledFile struct {
	SHA256 string
	Size   int64
}

type receiptFields struct {
	SchemaVersion *int    `json:"schema_version"`
	Target        *string `json:"target"`
	Version       *string `json:"version"`
	ArchiveSHA256 *string `json:"archive_sha256"`
	Files         []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"files"`
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
	installed := Installed{Version: version, ArchiveSHA256: *fields.ArchiveSHA256}
	for _, file := range fields.Files {
		if "/"+file.Path == TrestlePath && sha256Pattern.MatchString(file.SHA256) && file.Size > 0 {
			installed.Trestle = InstalledFile{SHA256: file.SHA256, Size: file.Size}
		}
	}
	return installed, nil
}

// CheckRootFile refuses path unless it is a regular file, not a symbolic
// link, owned by owner (root, 0, outside tests), not writable by group or
// others, beneath folders no other account can change. When want is not
// zero, its SHA-256 and size must match too.
func CheckRootFile(path string, owner uint32, want InstalledFile) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is not a regular file that only root can change", path)
	}
	if uid, ok := fileOwner(info); !ok || uid != owner {
		return fmt.Errorf("%s is not owned by root", path)
	}
	file, err := fileauthority.OpenReadOnly(path)
	if err != nil {
		return fmt.Errorf("%s is in a folder another account can change", path)
	}
	defer file.Close()
	if want == (InstalledFile{}) {
		return nil
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, want.Size+1))
	if err != nil || size != want.Size || hex.EncodeToString(hash.Sum(nil)) != want.SHA256 {
		return fmt.Errorf("%s is not the file the receipt names", path)
	}
	return nil
}
