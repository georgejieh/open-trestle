package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// A candidate is copied into a fresh private folder first and verified
// there, so the bytes checked are the bytes the lifecycle later runs as root.
// Between that check and the install, the copy is protected only by the
// folder's 0700 mode: a program running as this account could still change
// it, as it could change anything else this account runs.

// ErrCandidateRefused is a candidate copy that failed verification.
var ErrCandidateRefused = errors.New("the update was refused")

const shebang = "#!/usr/bin/env python3\n"

// afterCopy runs between copying a candidate and verifying the copy. Tests
// set it to change the copy or its source.
var afterCopy = func(string) {}

// Workspace is a fresh private folder for one candidate.
type Workspace struct {
	dir string
	pin *fileauthority.DirectoryPin
}

// NewWorkspace creates a mode-0700 folder under the temporary folder.
func NewWorkspace() (*Workspace, error) {
	dir, err := os.MkdirTemp("", "open-trestle-update-")
	if err != nil {
		return nil, fmt.Errorf("a private temporary folder cannot be created: %w", err)
	}
	workspace := &Workspace{dir: dir}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = workspace.Remove()
		return nil, fmt.Errorf("%s cannot be made private", dir)
	}
	info, err := os.Lstat(dir)
	if err == nil && info.IsDir() && info.Mode().Perm() == 0o700 {
		workspace.pin, err = fileauthority.PinDirectory(dir)
	}
	if err != nil || workspace.pin == nil {
		_ = workspace.Remove()
		return nil, fmt.Errorf("%s or a parent folder is not private to this account", dir)
	}
	return workspace, nil
}

// Recheck confirms, just before the copy runs, that the folder is the same
// private folder and the copy still has the verified bytes.
func (w *Workspace) Recheck(copied Copy) error {
	refused := fmt.Errorf("%w: the verified copy changed before it ran", ErrCandidateRefused)
	if w.pin == nil || w.pin.Recheck() != nil || filepath.Dir(copied.Archive) != w.dir {
		return refused
	}
	if info, err := os.Lstat(w.dir); err != nil || info.Mode().Perm() != 0o700 {
		return refused
	}
	file, info, err := openRegular(copied.Archive)
	if err != nil {
		return refused
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, MaxArchiveBytes+1))
	if err != nil || info.Mode().Perm() != 0o555 || size != copied.Size || hex.EncodeToString(hash.Sum(nil)) != copied.SHA256 {
		return refused
	}
	return nil
}

// Dir is the folder's path.
func (w *Workspace) Dir() string { return w.dir }

// Remove deletes the folder and everything in it.
func (w *Workspace) Remove() error { return os.RemoveAll(w.dir) }

// write creates name in the folder, never replacing a file, lets fill write
// it, and leaves it with mode.
func (w *Workspace) write(name string, mode os.FileMode, fill func(io.Writer) error) (string, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return "", fmt.Errorf("%q is not a file name", name)
	}
	path := filepath.Join(w.dir, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("%s cannot be created", path)
	}
	fillErr := fill(file)
	syncErr := file.Sync()
	if err := errors.Join(fillErr, syncErr, file.Close()); err != nil {
		return "", err
	}
	if err := os.Chmod(path, mode); err != nil {
		return "", fmt.Errorf("%s cannot be protected", path)
	}
	return path, nil
}

// copyFile copies a regular file of at most limit bytes into the folder.
func (w *Workspace) copyFile(source, name string, limit int64, mode os.FileMode) (string, error) {
	return w.write(name, mode, func(destination io.Writer) error {
		file, err := fileauthority.OpenReadOnly(source)
		if err != nil {
			return fmt.Errorf("%w: %s cannot be opened as a protected file", ErrLocalUnusable, source)
		}
		defer file.Close()
		written, err := io.Copy(destination, io.LimitReader(file, limit+1))
		if err != nil {
			return fmt.Errorf("%s could not be copied", source)
		}
		if written > limit {
			return fmt.Errorf("%w: %s is larger than %d bytes", ErrLocalUnusable, source, limit)
		}
		return nil
	})
}

// openRegular opens path only when it is a regular file, not a symbolic
// link, and the file opened is the one inspected.
func openRegular(path string) (*os.File, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: %s is not a regular file", ErrCandidateRefused, path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s cannot be opened", ErrCandidateRefused, path)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%w: %s changed while it was opened", ErrCandidateRefused, path)
	}
	return file, opened, nil
}

// Copy is a candidate archive in a workspace whose bytes were verified
// after they were copied there.
type Copy struct {
	Archive  string
	SHA256   string
	Size     int64
	Version  Version
	Manifest Manifest
}

// VerifyCopy checks an archive copy and its sidecar copy in place: modes
// 0555 and 0444 as the lifecycle requires, a sidecar that names the copy's
// SHA-256 and file name, the pyz shebang, and a manifest for this target.
func VerifyCopy(archive, sidecar string) (Copy, error) {
	file, before, err := openRegular(archive)
	if err != nil {
		return Copy{}, err
	}
	defer file.Close()
	if before.Mode().Perm() != 0o555 || before.Size() <= int64(len(shebang)) || before.Size() > MaxArchiveBytes {
		return Copy{}, fmt.Errorf("%w: the copy is not a mode-0555 archive of at most %d bytes", ErrCandidateRefused, MaxArchiveBytes)
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, MaxArchiveBytes+1))
	if err != nil || size != before.Size() {
		return Copy{}, fmt.Errorf("%w: the copy could not be read completely", ErrCandidateRefused)
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	sidecarFile, sidecarInfo, err := openRegular(sidecar)
	if err != nil {
		return Copy{}, err
	}
	defer sidecarFile.Close()
	raw, err := io.ReadAll(io.LimitReader(sidecarFile, MaxSidecarBytes+1))
	if err != nil || sidecarInfo.Mode().Perm() != 0o444 || !bytes.Equal(raw, []byte(digest+"  "+filepath.Base(archive)+"\n")) {
		return Copy{}, fmt.Errorf("%w: the SHA-256 sidecar does not match the archive", ErrCandidateRefused)
	}
	head := make([]byte, len(shebang))
	if _, err := file.ReadAt(head, 0); err != nil || string(head) != shebang {
		return Copy{}, fmt.Errorf("%w: the copy does not start with the pyz shebang", ErrCandidateRefused)
	}
	manifest, version, err := ReadManifest(file, size)
	if err != nil {
		return Copy{}, fmt.Errorf("%w: %w", ErrCandidateRefused, err)
	}
	after, err := file.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return Copy{}, fmt.Errorf("%w: the copy changed while it was verified", ErrCandidateRefused)
	}
	return Copy{Archive: archive, SHA256: digest, Size: size, Version: version, Manifest: manifest}, nil
}

// Matches checks a verified copy against a signed statement.
func (c Copy) Matches(statement Statement) error {
	if c.SHA256 != statement.ArchiveSHA256 || c.Size != statement.ArchiveSize {
		return fmt.Errorf("%w: the archive's SHA-256 or size is not the signed one", ErrCandidateRefused)
	}
	if c.Version.String() != statement.Version || c.Manifest.Target != statement.Target {
		return fmt.Errorf("%w: the archive's own version or target is not the signed one", ErrCandidateRefused)
	}
	return nil
}

// Prepared is a verified candidate copy ready for its lifecycle's upgrade.
type Prepared struct {
	Copy Copy
	// Signed reports a signature that verified with a pinned key.
	Signed    bool
	Statement Statement
	Key       PublicKey
	// SignatureUnchecked reports a .sig beside a local build that this
	// build could not check because it pins no key.
	SignatureUnchecked bool
}

// VerifyReleaseSignature downloads a release's signature and verifies it
// with ring as a statement for that release's tag and version.
func VerifyReleaseSignature(ctx context.Context, client Client, ring KeyRing, release Release) (Statement, PublicKey, error) {
	if len(ring) == 0 {
		return Statement{}, PublicKey{}, ErrNoPinnedKey
	}
	var raw bytes.Buffer
	if _, err := client.Download(ctx, release.Signature, MaxSignatureBytes, 30*time.Second, &raw); err != nil {
		return Statement{}, PublicKey{}, err
	}
	statement, key, err := ring.Verify(raw.Bytes())
	if err != nil {
		return Statement{}, PublicKey{}, fmt.Errorf("%w: %w", ErrCandidateRefused, err)
	}
	if statement.Tag != release.Tag || statement.Version != release.Version.String() {
		return Statement{}, PublicKey{}, fmt.Errorf("%w: the signature is for %s, not %s", ErrCandidateRefused, statement.Tag, release.Tag)
	}
	return statement, key, nil
}

// PrepareRelease verifies a release's signature, then downloads its sidecar
// and archive into workspace and verifies the copies against the signed
// statement. Nothing is downloaded past the signature unless it verifies.
func PrepareRelease(ctx context.Context, client Client, ring KeyRing, release Release, workspace *Workspace, timeout time.Duration) (Prepared, error) {
	statement, key, err := VerifyReleaseSignature(ctx, client, ring, release)
	if err != nil {
		return Prepared{}, err
	}
	sidecar, err := workspace.write(SidecarName, 0o444, func(destination io.Writer) error {
		_, err := client.Download(ctx, release.Sidecar, MaxSidecarBytes, 30*time.Second, destination)
		return err
	})
	if err != nil {
		return Prepared{}, err
	}
	archive, err := workspace.write(ArchiveName, 0o555, func(destination io.Writer) error {
		written, err := client.Download(ctx, release.Archive, statement.ArchiveSize, timeout, destination)
		if err == nil && written != statement.ArchiveSize {
			err = fmt.Errorf("%w: the archive is %d bytes, not the signed %d", ErrCandidateRefused, written, statement.ArchiveSize)
		}
		return err
	})
	if err != nil {
		return Prepared{}, err
	}
	afterCopy(workspace.dir)
	copied, err := VerifyCopy(archive, sidecar)
	if err != nil {
		return Prepared{}, err
	}
	if err := copied.Matches(statement); err != nil {
		return Prepared{}, err
	}
	return Prepared{Copy: copied, Signed: true, Statement: statement, Key: key}, nil
}

// PrepareLocal copies a local build and its sidecar into workspace and
// verifies the copies. When a .sig is beside the build and ring has a key,
// the signature must verify and match the copy; with no key it is reported
// as unchecked.
func PrepareLocal(build LocalBuild, ring KeyRing, workspace *Workspace) (Prepared, error) {
	name := filepath.Base(build.Archive)
	archive, err := workspace.copyFile(build.Archive, name, MaxArchiveBytes, 0o555)
	if err != nil {
		return Prepared{}, err
	}
	sidecar, err := workspace.copyFile(build.Sidecar, name+".sha256", MaxSidecarBytes, 0o444)
	if err != nil {
		return Prepared{}, err
	}
	var signature []byte
	if build.Signature != "" {
		file, err := fileauthority.OpenReadOnly(build.Signature)
		if err != nil {
			return Prepared{}, fmt.Errorf("%w: %s cannot be opened as a protected file", ErrLocalUnusable, build.Signature)
		}
		signature, err = io.ReadAll(io.LimitReader(file, MaxSignatureBytes+1))
		_ = file.Close()
		if err != nil {
			return Prepared{}, fmt.Errorf("%w: %s cannot be read", ErrLocalUnusable, build.Signature)
		}
	}
	afterCopy(workspace.dir)
	copied, err := VerifyCopy(archive, sidecar)
	if err != nil {
		return Prepared{}, err
	}
	prepared := Prepared{Copy: copied}
	switch {
	case build.Signature == "":
	case len(ring) == 0:
		prepared.SignatureUnchecked = true
	default:
		statement, key, err := ring.Verify(signature)
		if err != nil {
			return Prepared{}, fmt.Errorf("%w: %w", ErrCandidateRefused, err)
		}
		if err := copied.Matches(statement); err != nil {
			return Prepared{}, err
		}
		prepared.Signed, prepared.Statement, prepared.Key = true, statement, key
	}
	return prepared, nil
}
