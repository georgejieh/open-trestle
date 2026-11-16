package localownerroot

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

type DirectoryIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

var ErrUnsafePath = errors.New("unsafe local owner path")

func unsafePath(policyErr error) error {
	if policyErr == nil {
		return ErrUnsafePath
	}
	return policyErr
}

func ValidPath(path string) bool {
	return path != "" && len(path) <= 4096 && utf8.ValidString(path) && strings.IndexByte(path, 0) == -1 && filepath.IsAbs(path) && filepath.Clean(path) == path && path[0] == '/'
}

// ExistingRoot checks each component from a rooted parent in order. It
// neither creates a missing component nor assumes an ENOENT masks other errors.
func ExistingRoot(absolute string, policyErr error) (*os.Root, error) {
	parent, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	defer func() {
		if parent != nil {
			_ = parent.Close()
		}
	}()
	path := string(filepath.Separator)
	components := strings.Split(strings.TrimPrefix(absolute, path), path)
	for _, component := range components {
		if component == "" {
			continue
		}
		path = filepath.Join(path, component)
		before, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			// The rooted lookup distinguishes a missing child from a changed or
			// inaccessible absolute pathname at this instant.
			if _, rootedErr := parent.Lstat(component); !errors.Is(rootedErr, os.ErrNotExist) {
				return nil, unsafePath(policyErr)
			}
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		rooted, err := parent.Lstat(component)
		if err != nil || !os.SameFile(before, rooted) || before.Mode() != rooted.Mode() || !before.IsDir() || before.Mode()&os.ModeType != os.ModeDir {
			return nil, unsafePath(policyErr)
		}
		child, err := parent.OpenRoot(component)
		if err != nil {
			return nil, err
		}
		opened, openErr := child.Stat(".")
		after, afterErr := os.Lstat(path)
		rootedAfter, rootedErr := parent.Lstat(component)
		if openErr != nil || afterErr != nil || rootedErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) || !os.SameFile(before, rootedAfter) || before.Mode() != opened.Mode() || before.Mode() != after.Mode() || before.Mode() != rootedAfter.Mode() {
			_ = child.Close()
			return nil, unsafePath(policyErr)
		}
		_ = parent.Close()
		parent = child
	}
	info, err := parent.Stat(".")
	if err != nil || info.Mode() != os.ModeDir|0o700 {
		return nil, unsafePath(policyErr)
	}
	// The caller holds the observed leaf through the following constructors.
	openedLeaf := parent
	parent = nil
	return openedLeaf, nil
}

var (
	ErrPersistence = errors.New("local source owner persistence or changed state")
	ErrUnsupported = errors.New("local source owner directory identity unsupported")
)

func Persistence(stage string, err error) error {
	if err == nil {
		return fmt.Errorf("%w: %s", ErrPersistence, stage)
	}
	return fmt.Errorf("%w: %s: %w", ErrPersistence, stage, err)
}

func DirectoryInfo(info os.FileInfo) bool {
	return info != nil && info.Mode() == os.ModeDir|0700 && fileauthority.TrustedOwner(info)
}

// The path observations check cooperative consistency with the caller's opened root.
// Each checked root validates every existing component without following symlinks.
func ObserveDirectory(path string, root *os.Root, policyErr error) (DirectoryIdentity, error) {
	if root == nil || !ValidPath(path) || filepath.Clean(path) != path {
		return DirectoryIdentity{}, Persistence("absent or invalid opened root", nil)
	}
	before, err := CheckedDirectoryInfo(path, policyErr)
	if err != nil {
		return DirectoryIdentity{}, Persistence("directory chain before", err)
	}
	opened, err := root.Stat(".")
	if err != nil {
		return DirectoryIdentity{}, Persistence("opened directory", err)
	}
	after, err := CheckedDirectoryInfo(path, policyErr)
	if err != nil {
		return DirectoryIdentity{}, Persistence("directory chain after", err)
	}
	if !DirectoryInfo(before) || !DirectoryInfo(opened) || !DirectoryInfo(after) || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return DirectoryIdentity{}, Persistence("directory identity or private mode changed", nil)
	}
	return IdentityFromInfo(opened)
}

func CheckedDirectoryInfo(path string, policyErr error) (os.FileInfo, error) {
	checked, err := ExistingRoot(path, policyErr)
	if err != nil {
		return nil, err
	}
	if checked == nil {
		return nil, os.ErrNotExist
	}
	info, statErr := checked.Stat(".")
	closeErr := checked.Close()
	return info, errors.Join(statErr, closeErr)
}

// An opened artifact root must also match the exact child of its opened state root.
func ObserveArtifactDirectory(stateRoot, artifactRoot *os.Root, statePath string, policyErr error) (DirectoryIdentity, error) {
	return ObserveArtifactDirectoryWithHook(stateRoot, artifactRoot, statePath, nil, policyErr)
}

// The per-call hook only arranges changes between child observations.
func ObserveArtifactDirectoryWithHook(stateRoot, artifactRoot *os.Root, statePath string, hook func(string), policyErr error) (DirectoryIdentity, error) {
	if stateRoot == nil || artifactRoot == nil {
		return DirectoryIdentity{}, Persistence("absent artifact root", nil)
	}
	if _, err := ObserveDirectory(statePath, stateRoot, policyErr); err != nil {
		return DirectoryIdentity{}, err
	}
	before, err := stateRoot.Lstat("artifacts")
	if err != nil {
		return DirectoryIdentity{}, Persistence("artifact child before", err)
	}
	if hook != nil {
		hook("after-child-before")
	}
	identity, err := ObserveDirectory(filepath.Join(statePath, "artifacts"), artifactRoot, policyErr)
	if err != nil {
		return DirectoryIdentity{}, err
	}
	opened, err := artifactRoot.Stat(".")
	if err != nil {
		return DirectoryIdentity{}, Persistence("artifact opened", err)
	}
	after, err := stateRoot.Lstat("artifacts")
	if err != nil {
		return DirectoryIdentity{}, Persistence("artifact child after", err)
	}
	if !DirectoryInfo(before) || !DirectoryInfo(after) || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return DirectoryIdentity{}, Persistence("artifact child changed", nil)
	}
	if _, err := ObserveDirectory(statePath, stateRoot, policyErr); err != nil {
		return DirectoryIdentity{}, err
	}
	return identity, nil
}
