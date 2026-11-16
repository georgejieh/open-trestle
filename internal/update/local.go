package update

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// ErrLocalUnusable is a local update folder or candidate file that is not
// private to this account, is a symbolic link, or is not a packaged archive.
var ErrLocalUnusable = errors.New("the local build cannot be used")

var candidateName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.pyz$`)

// LocalBuild is an unsigned archive on this machine and its SHA-256 sidecar.
type LocalBuild struct {
	Archive, Sidecar string
	// Signature is the archive's .sig beside it, or "" when there is none.
	Signature string
	Version   Version
	Manifest  Manifest
}

// LocalDirectory is $XDG_DATA_HOME/open-trestle/updates when XDG_DATA_HOME
// is an absolute path, and otherwise ~/.local/share/open-trestle/updates.
func LocalDirectory(getenv func(string) string) (string, error) {
	if data := getenv("XDG_DATA_HOME"); data != "" && filepath.IsAbs(data) {
		return filepath.Join(filepath.Clean(data), "open-trestle", "updates"), nil
	}
	home := getenv("HOME")
	if home == "" {
		var err error
		if home, err = os.UserHomeDir(); err != nil {
			return "", fmt.Errorf("%w: HOME is not set", ErrLocalUnusable)
		}
	}
	if !filepath.IsAbs(home) {
		return "", fmt.Errorf("%w: HOME is not an absolute path", ErrLocalUnusable)
	}
	return filepath.Join(filepath.Clean(home), ".local", "share", "open-trestle", "updates"), nil
}

// FindLocal looks in the local update folder for open-trestle-linux-amd64.pyz
// and its sidecar. found is false when the folder or the archive does not
// exist. The folder must be mode 0700 and, like its parents, owned by this
// account or root and not writable by others.
func FindLocal(dir string) (build LocalBuild, found bool, err error) {
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return LocalBuild{}, false, nil
	}
	switch {
	case err != nil:
		return LocalBuild{}, false, fmt.Errorf("%w: %s cannot be read", ErrLocalUnusable, dir)
	case info.Mode()&os.ModeSymlink != 0:
		return LocalBuild{}, false, fmt.Errorf("%w: %s is a symbolic link", ErrLocalUnusable, dir)
	case !info.IsDir():
		return LocalBuild{}, false, fmt.Errorf("%w: %s is not a folder", ErrLocalUnusable, dir)
	case info.Mode().Perm() != 0o700:
		return LocalBuild{}, false, fmt.Errorf("%w: %s must be private (mode 0700, not %04o)", ErrLocalUnusable, dir, info.Mode().Perm())
	}
	pin, err := fileauthority.PinDirectory(dir)
	if err != nil {
		return LocalBuild{}, false, fmt.Errorf("%w: %s or a parent folder is not owned by this account or is writable by others", ErrLocalUnusable, dir)
	}
	archive := filepath.Join(dir, ArchiveName)
	if _, err := os.Lstat(archive); errors.Is(err, fs.ErrNotExist) {
		return LocalBuild{}, false, nil
	}
	build, err = inspectCandidate(archive)
	if err != nil {
		return LocalBuild{}, false, err
	}
	if pin.Recheck() != nil {
		return LocalBuild{}, false, fmt.Errorf("%w: %s changed while it was read", ErrLocalUnusable, dir)
	}
	return build, true, nil
}

// FindFile inspects an archive the operator names, such as one downloaded by
// hand. Its sidecar must be beside it; a .sig beside it is reported too.
func FindFile(path string) (LocalBuild, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return LocalBuild{}, fmt.Errorf("%w: %s is not a usable path", ErrLocalUnusable, path)
	}
	if !candidateName.MatchString(filepath.Base(absolute)) {
		return LocalBuild{}, fmt.Errorf("%w: %s must be a .pyz file named with letters, digits, dots, dashes or underscores", ErrLocalUnusable, path)
	}
	return inspectCandidate(absolute)
}

// checkCandidateFile refuses anything but a regular file owned by this
// account or root that no other account can write.
func checkCandidateFile(path string, limit int64) (bool, error) {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("%w: %s cannot be read", ErrLocalUnusable, path)
	case info.Mode()&os.ModeSymlink != 0:
		return false, fmt.Errorf("%w: %s is a symbolic link", ErrLocalUnusable, path)
	case !info.Mode().IsRegular():
		return false, fmt.Errorf("%w: %s is not a regular file", ErrLocalUnusable, path)
	case info.Mode().Perm()&0o022 != 0 || !fileauthority.TrustedOwner(info):
		return false, fmt.Errorf("%w: %s must be owned by this account and not writable by others", ErrLocalUnusable, path)
	case info.Size() <= 0 || info.Size() > limit:
		return false, fmt.Errorf("%w: %s is empty or larger than %d bytes", ErrLocalUnusable, path, limit)
	}
	return true, nil
}

func inspectCandidate(archive string) (LocalBuild, error) {
	build := LocalBuild{Archive: archive, Sidecar: archive + ".sha256"}
	if found, err := checkCandidateFile(archive, MaxArchiveBytes); err != nil || !found {
		if err == nil {
			err = fmt.Errorf("%w: %s does not exist", ErrLocalUnusable, archive)
		}
		return LocalBuild{}, err
	}
	if found, err := checkCandidateFile(build.Sidecar, MaxSidecarBytes); err != nil || !found {
		if err == nil {
			err = fmt.Errorf("%w: %s has no %s beside it", ErrLocalUnusable, archive, filepath.Base(build.Sidecar))
		}
		return LocalBuild{}, err
	}
	signature := archive + ".sig"
	if found, err := checkCandidateFile(signature, MaxSignatureBytes); err != nil {
		return LocalBuild{}, err
	} else if found {
		build.Signature = signature
	}
	file, err := fileauthority.OpenReadOnly(archive)
	if err != nil {
		return LocalBuild{}, fmt.Errorf("%w: %s or a parent folder is not owned by this account or is writable by others", ErrLocalUnusable, archive)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return LocalBuild{}, fmt.Errorf("%w: %s cannot be read", ErrLocalUnusable, archive)
	}
	build.Manifest, build.Version, err = ReadManifest(file, info.Size())
	if err != nil {
		return LocalBuild{}, fmt.Errorf("%s: %w", archive, err)
	}
	return build, nil
}
