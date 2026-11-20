package repochecks

import (
	"context"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/internal/checksandbox"
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
	packages := standardImports(ctx, goroot, trees)
	root, err := os.MkdirTemp("", checksandbox.GoSeedFolderPrefix)
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
	command := exec.CommandContext(ctx, filepath.Join(chain.path[0], program), append([]string{"build", "--"}, packages...)...)
	command.Dir = root
	command.Env = append([]string{"PATH=" + strings.Join(chain.path, string(os.PathListSeparator)), "HOME=" + home, "TMPDIR=" + temporary, "TEMP=" + temporary, "TMP=" + temporary},
		checksandbox.ExpandEnv(chain.env, home, temporary)...)
	// A package that fails to build leaves the others in the cache, which
	// is all a run needs from it.
	_ = command.Run()
	return home, cleanup
}

// Bounds on reading the trees for import paths.
const (
	maxSeedFileBytes = 1 << 20
	maxSeedPackages  = 1024
)

// standardPackage matches the import path of a standard library package
// that a repository may import: lowercase word segments, so nothing in it
// can read as a flag, a pattern or a path outside GOROOT.
var standardPackage = regexp.MustCompile(`^[a-z0-9_]+(/[a-z0-9_]+)*$`)

// standardImports lists the standard library packages that the Go files of
// trees import, plus those every test binary links. The import paths come
// from the repository, so each must be a canonical standard library name
// that exists in GOROOT, and the command, internal and vendored packages
// are left out.
func standardImports(ctx context.Context, goroot string, trees []string) []string {
	packages := slices.Clone(goSeedRoots)
	seen := map[string]bool{}
	files := token.NewFileSet()
	for _, tree := range trees {
		_ = filepath.WalkDir(tree, func(name string, entry fs.DirEntry, err error) error {
			if ctx.Err() != nil || len(packages) >= maxSeedPackages {
				return filepath.SkipAll
			}
			if err != nil {
				return nil
			}
			if entry.IsDir() && name != tree && skippedFolders[entry.Name()] {
				return filepath.SkipDir
			}
			if !entry.Type().IsRegular() || !strings.HasSuffix(name, ".go") {
				return nil
			}
			if info, err := entry.Info(); err != nil || info.Size() > maxSeedFileBytes {
				return nil
			}
			parsed, err := parser.ParseFile(files, name, nil, parser.ImportsOnly)
			if err != nil {
				return nil
			}
			for _, spec := range parsed.Imports {
				if path, err := strconv.Unquote(spec.Path.Value); err == nil && !seen[path] && seedable(goroot, path) {
					seen[path] = true
					packages = append(packages, path)
				}
			}
			return nil
		})
	}
	slices.Sort(packages)
	return slices.Compact(packages)
}

func seedable(goroot, path string) bool {
	top := strings.SplitN(path, "/", 2)[0]
	return standardPackage.MatchString(path) && top != "cmd" && top != "internal" && top != "vendor" &&
		!strings.Contains(path, "/internal/") && !strings.HasSuffix(path, "/internal") &&
		isDir(filepath.Join(goroot, "src", filepath.FromSlash(path)))
}
