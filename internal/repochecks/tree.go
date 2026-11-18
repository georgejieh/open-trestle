package repochecks

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

// maxTreeEntries bounds the files of one materialised tree.
const maxTreeEntries = 200_000

// Materialize writes the tree of commit, read from the verified object
// store, into the empty folder target: regular and executable files and,
// except on Windows, symbolic links. Submodules are left out. All writes go
// through an os.Root, so no path in the tree can reach outside target.
func Materialize(ctx context.Context, store *scm.LocalGitObjectStore, commit evidence.RevisionIdentity, target string, limit int64) error {
	var entries []scm.LocalGitTreeEntry
	walk, err := store.WalkTree(ctx, commit, maxTreeEntries, func(entry scm.LocalGitTreeEntry) error {
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return fmt.Errorf("the commit's tree cannot be read: %w", err)
	}
	if walk.Truncated {
		return errors.New("the commit's tree has too many files to check")
	}
	root, err := os.OpenRoot(target)
	if err != nil {
		return err
	}
	defer root.Close()
	var total int64
	for len(entries) > 0 {
		before := len(entries)
		err := store.WithObjectReader(ctx, func(reader scm.LocalGitObjectReader) error {
			for len(entries) > 0 {
				entry := entries[0]
				if !wanted(entry) {
					entries = entries[1:]
					continue
				}
				content, err := reader.ReadBlob(ctx, commit.Algorithm(), entry.Object)
				if err != nil {
					return err
				}
				if total += int64(len(content)); total > limit {
					return errors.New("the commit's tree is larger than the check's disk limit")
				}
				if err := writeEntry(root, entry, content); err != nil {
					return err
				}
				entries = entries[1:]
			}
			return nil
		})
		// An acquisition that runs out of work budget is continued in a new
		// one from the entry it stopped at.
		if err != nil && (!errors.Is(err, scm.LocalGitRevisionResourceLimit) || len(entries) == before) {
			return fmt.Errorf("the commit's files cannot be read: %w", err)
		}
	}
	return nil
}

// ChangedPaths lists the paths whose entry differs between the trees of
// base and head: added, removed, or changed in content or mode.
func ChangedPaths(ctx context.Context, store *scm.LocalGitObjectStore, base, head evidence.RevisionIdentity) ([]string, error) {
	entries := func(commit evidence.RevisionIdentity) (map[string]scm.LocalGitTreeEntry, error) {
		found := map[string]scm.LocalGitTreeEntry{}
		walk, err := store.WalkTree(ctx, commit, maxTreeEntries, func(entry scm.LocalGitTreeEntry) error {
			found[entry.Path] = entry
			return nil
		})
		if err == nil && walk.Truncated {
			err = errors.New("the commit's tree has too many files to check")
		}
		return found, err
	}
	before, err := entries(base)
	if err != nil {
		return nil, err
	}
	after, err := entries(head)
	if err != nil {
		return nil, err
	}
	changed := []string{}
	for name, entry := range after {
		if old, ok := before[name]; !ok || old != entry {
			changed = append(changed, name)
		}
	}
	for name := range before {
		if _, ok := after[name]; !ok {
			changed = append(changed, name)
		}
	}
	sort.Strings(changed)
	return changed, nil
}

func wanted(entry scm.LocalGitTreeEntry) bool {
	switch entry.Mode {
	case evidence.GitTreeModeRegular, evidence.GitTreeModeExecutable:
		return true
	case evidence.GitTreeModeSymlink:
		return runtime.GOOS != "windows"
	}
	return false
}

func writeEntry(root *os.Root, entry scm.LocalGitTreeEntry, content []byte) error {
	name := filepath.FromSlash(entry.Path)
	if !filepath.IsLocal(name) {
		return fmt.Errorf("the tree holds a path outside it: %q", entry.Path)
	}
	if dir := filepath.Dir(name); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if entry.Mode == evidence.GitTreeModeSymlink {
		return root.Symlink(string(content), name)
	}
	mode := fs.FileMode(0o644)
	if entry.Mode == evidence.GitTreeModeExecutable {
		mode = 0o755
	}
	return root.WriteFile(name, content, mode)
}

// copyFolder copies the regular files and folders of source into target.
func copyFolder(source, target string) error {
	if err := os.MkdirAll(target, 0o755); err != nil {
		return err
	}
	return filepath.WalkDir(source, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, name)
		if err != nil || relative == "." {
			return err
		}
		destination := filepath.Join(target, relative)
		switch {
		case entry.IsDir():
			return os.Mkdir(destination, 0o755)
		case entry.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(name)
			if err != nil {
				return err
			}
			return os.Symlink(link, destination)
		case entry.Type().IsRegular():
			data, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			return os.WriteFile(destination, data, info.Mode().Perm())
		}
		return nil
	})
}

// writeFiles adds files, by slash-separated relative path, under target.
func writeFiles(target string, files map[string][]byte) error {
	root, err := os.OpenRoot(target)
	if err != nil {
		return err
	}
	defer root.Close()
	for name, content := range files {
		local := filepath.FromSlash(path.Clean(name))
		if !filepath.IsLocal(local) {
			return fmt.Errorf("an extra file's path leaves the tree: %q", name)
		}
		if err := root.MkdirAll(filepath.Dir(local), 0o755); err != nil {
			return err
		}
		if err := root.WriteFile(local, content, 0o644); err != nil {
			return err
		}
	}
	return nil
}
