package repochecks

import (
	"context"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

// goSeedTime bounds the standard library build of one review.
const goSeedTime = 3 * time.Minute

// goSeedRoots are the standard library packages every test binary links.
var goSeedRoots = []string{"testing", "testing/internal/testdeps"}

// goSeeds holds one standard library seed per Go toolchain of a review.
type goSeeds struct {
	homes    map[string]string
	cleanups []func()
}

// home returns the seed for program, building it on first use.
func (s *goSeeds) home(ctx context.Context, program string, chain toolchain, trees []string) string {
	key := strings.Join(chain.path, string(os.PathListSeparator)) + "|" + program
	if home, ok := s.homes[key]; ok {
		return home
	}
	home, cleanup := buildGoSeed(ctx, program, chain, trees)
	s.homes[key] = home
	s.cleanups = append(s.cleanups, cleanup)
	return home
}

func (s *goSeeds) close() {
	for _, cleanup := range s.cleanups {
		cleanup()
	}
}

// buildGoSeed compiles, with the host's toolchain and the same environment
// the sandboxed runs use, the standard library packages that the trees'
// Go files import, into a build cache below the returned home folder. No
// repository code runs: the trees are only parsed for import paths. Each
// sandboxed run starts from a copy, so it compiles only the repository's
// own packages. It returns "" when nothing could be built; the runs then
// compile everything themselves.
func buildGoSeed(ctx context.Context, program string, chain toolchain, trees []string) (string, func()) {
	// The Windows sandbox cannot run the go command; see platformArgs.
	if runtime.GOOS == "windows" {
		return "", func() {}
	}
	goroot := ""
	for _, folder := range chain.readOnly {
		if isDir(filepath.Join(folder, "src", "runtime")) {
			goroot = folder
		}
	}
	if goroot == "" {
		return "", func() {}
	}
	packages := standardImports(goroot, trees)
	root, err := os.MkdirTemp("", "open-trestle-go-seed-")
	if err != nil {
		return "", func() {}
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	home, temporary := filepath.Join(root, "home"), filepath.Join(root, "tmp")
	if os.Mkdir(home, 0o700) != nil || os.Mkdir(temporary, 0o700) != nil {
		cleanup()
		return "", func() {}
	}
	ctx, cancel := context.WithTimeout(ctx, goSeedTime)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(chain.path[0], program), append([]string{"build"}, packages...)...)
	command.Dir = root
	command.Env = append([]string{"PATH=" + strings.Join(chain.path, string(os.PathListSeparator)), "HOME=" + home, "TMPDIR=" + temporary, "TEMP=" + temporary, "TMP=" + temporary},
		expandSeedEnv(chain.env, home, temporary)...)
	if command.Run() != nil {
		cleanup()
		return "", func() {}
	}
	return home, cleanup
}

// expandSeedEnv expands $HOME and $TMPDIR in the values of entries, as the
// sandbox does for its own folders.
func expandSeedEnv(entries []string, home, temporary string) []string {
	expanded := make([]string, 0, len(entries))
	for _, entry := range entries {
		key, value, _ := strings.Cut(entry, "=")
		expanded = append(expanded, key+"="+os.Expand(value, func(name string) string {
			switch name {
			case "HOME":
				return home
			case "TMPDIR":
				return temporary
			}
			return "$" + name
		}))
	}
	return expanded
}

// standardImports lists the standard library packages that the Go files of
// trees import, plus those every test binary links.
func standardImports(goroot string, trees []string) []string {
	packages := slices.Clone(goSeedRoots)
	files := token.NewFileSet()
	for _, tree := range trees {
		_ = filepath.WalkDir(tree, func(name string, entry fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() && name != tree && skippedFolders[entry.Name()] {
				return filepath.SkipDir
			}
			if !entry.Type().IsRegular() || !strings.HasSuffix(name, ".go") {
				return nil
			}
			parsed, err := parser.ParseFile(files, name, nil, parser.ImportsOnly)
			if err != nil {
				return nil
			}
			for _, spec := range parsed.Imports {
				if path, err := strconv.Unquote(spec.Path.Value); err == nil && isDir(filepath.Join(goroot, "src", filepath.FromSlash(path))) {
					packages = append(packages, path)
				}
			}
			return nil
		})
	}
	slices.Sort(packages)
	return slices.Compact(packages)
}
