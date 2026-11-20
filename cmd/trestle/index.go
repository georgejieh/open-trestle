package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/internal/syntaxworker"
	"github.com/georgejieh/open-trestle/repoindex"
)

// `trestle index` builds and queries the repository index of the checkout in
// the current directory. The index lives in the setup folder (the one
// `trestle review` uses) under index/. Files are read from the verified Git
// object store, never from the working tree.
//
//	trestle index status
//	trestle index build [--commit REF]
//	trestle index query definitions|references|tests NAME [--commit REF]
//	trestle index query imports PATH [--commit REF]
//	trestle index query dependents --base REF [--commit REF]
//
// `trestle index worker` is the syntax worker the build starts; it is not
// meant to be run by hand.

func writeIndexUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle index status|build [--commit REF] [--directory PATH]   (the repository index: every file's role, definitions, references and imports; see docs/repository-index.md)")
	fmt.Fprintln(w, "       trestle index query definitions|references|tests NAME | imports PATH | dependents --base REF [--commit REF] [--directory PATH]   (JSON)")
}

func indexFail(stderr io.Writer, code int, format string, values ...any) int {
	fmt.Fprintf(stderr, "trestle index: "+format+"\n", values...)
	return code
}

func runIndex(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		out, code := stdout, 0
		if len(args) == 0 {
			out, code = stderr, 2
		}
		writeIndexUsage(out)
		return code
	}
	switch args[0] {
	case "worker":
		return syntaxworker.Run(ctx, args[1:], os.Stdin, stdout)
	case "status":
		return runIndexStatus(ctx, args[1:], stdout, stderr)
	case "build":
		return runIndexBuild(ctx, args[1:], stdout, stderr)
	case "query":
		return runIndexQuery(ctx, args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "trestle index: unknown command %q\n", args[0])
	writeIndexUsage(stderr)
	return 2
}

type indexFlags struct {
	directory, commit, base string
}

// parseIndexFlags reads the flags and returns the positional arguments.
func parseIndexFlags(name string, args []string, base bool) (indexFlags, []string, error) {
	var f indexFlags
	flags := flag.NewFlagSet("trestle index "+name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&f.directory, "directory", "", "")
	flags.StringVar(&f.commit, "commit", "HEAD", "")
	if base {
		flags.StringVar(&f.base, "base", "", "")
	}
	positional := []string{}
	for len(args) > 0 {
		if err := flags.Parse(args); err != nil {
			return f, nil, err
		}
		if flags.NArg() == 0 {
			break
		}
		positional = append(positional, flags.Arg(0))
		args = flags.Args()[1:]
	}
	return f, positional, nil
}

// indexSession is a checkout, its object store and its index.
type indexSession struct {
	checkout  string
	algorithm string
	objects   *os.Root
	store     *scm.LocalGitObjectStore
	index     *repoindex.Store
}

func (s *indexSession) close() {
	_ = s.store.Close(context.Background())
	_ = s.objects.Close()
}

func openIndexSession(ctx context.Context, f indexFlags) (*indexSession, error) {
	checkout, err := findRepositoryCheckout(ctx)
	if err != nil {
		return nil, errors.New("this folder is not inside a Git checkout (or git is not installed)")
	}
	dir := ""
	if f.directory != "" {
		if dir, err = initValidateDirectory(f.directory); err != nil {
			return nil, fmt.Errorf("--directory: %w", err)
		}
	}
	return openIndexSessionAt(ctx, checkout, dir)
}

// openIndexSessionAt opens the index of a checkout in a setup folder, the
// checkout's own one when dir is empty.
func openIndexSessionAt(ctx context.Context, checkout, dir string) (*indexSession, error) {
	if dir == "" {
		dir = discoverSetupDirectory(ctx, checkout)
	}
	objectsPath, algorithm, err := resolveLocalCheckoutObjects(ctx, checkout)
	if err != nil {
		return nil, errors.New("the checkout's Git objects cannot be found")
	}
	s, err := openIndexSessionForObjects(objectsPath, algorithm, dir)
	if err != nil {
		return nil, err
	}
	s.checkout = checkout
	return s, nil
}

// openIndexSessionForObjects opens the index of a Git object store in a
// setup folder.
func openIndexSessionForObjects(objectsPath, algorithm, dir string) (*indexSession, error) {
	if dir == "" {
		return nil, errors.New("the setup folder cannot be found (set HOME)")
	}
	identity, err := executableIdentity()
	if err != nil {
		return nil, errors.New("this program's own file cannot be read to name the analyzer build")
	}
	index, err := repoindex.NewStore(filepath.Join(dir, "index"), identity, repoindex.DefaultStoreLimits())
	if err != nil {
		return nil, err
	}
	objects, err := os.OpenRoot(objectsPath)
	if err != nil {
		return nil, errors.New("the checkout's Git objects cannot be opened")
	}
	repository, _ := evidence.NewRepositoryIdentity("local", []string{"checkout"}, "repository")
	store, err := scm.NewLocalGitObjectStoreWithOptions(scm.LocalGitObjectStoreOptions{ObjectsRoot: objects, Repository: repository, Profile: scm.LocalGitObjectStoreProfileLooseAndPackIndexV1, ObjectAlgorithm: evidence.RevisionAlgorithm(algorithm)})
	if err != nil {
		_ = objects.Close()
		return nil, fmt.Errorf("the checkout's Git objects cannot be read: %v", err)
	}
	return &indexSession{algorithm: algorithm, objects: objects, store: store, index: index}, nil
}

// executableIdentity is the SHA-256 of this program's file. The analyzers
// and their grammars are compiled into it, so records made by any other
// build are never reused.
func executableIdentity() ([32]byte, error) {
	path, err := os.Executable()
	if err != nil {
		return [32]byte{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return [32]byte{}, err
	}
	return [32]byte(hash.Sum(nil)), nil
}

// commit resolves a branch, tag, ref, HEAD or commit ID to a commit.
func (s *indexSession) commit(ctx context.Context, ref string) (evidence.RevisionIdentity, error) {
	selection, err := initNormalizeSelection(ctx, s.checkout, ref)
	if err != nil {
		return evidence.RevisionIdentity{}, err
	}
	digest, _, err := initGit(ctx, s.checkout, "rev-parse", "--verify", "--quiet", "--end-of-options", selection+"^{commit}")
	if err != nil {
		return evidence.RevisionIdentity{}, errors.New("Git does not know that commit here")
	}
	return evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithm(s.algorithm), digest)
}

// builder returns a builder of a commit's tree with a pool of syntax
// workers, which the caller closes.
func (s *indexSession) builder(revision evidence.RevisionIdentity) (repoindex.Builder, *repoindex.GitTree, *syntaxworker.Pool, error) {
	tree, err := repoindex.NewGitTree(s.store, revision)
	if err != nil {
		return repoindex.Builder{}, nil, nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return repoindex.Builder{}, nil, nil, err
	}
	command := []string{executable, "index", "worker"}
	if cache, ok := s.compiledModuleFolder(); ok {
		command = append(command, "--cache-directory", cache)
	}
	pool, err := syntaxworker.NewPool(syntaxworker.Config{Command: command, Environment: workerEnvironment()})
	if err != nil {
		return repoindex.Builder{}, nil, nil, err
	}
	return repoindex.Builder{Store: s.index, Analyzer: pool, Parallelism: pool.Workers()}, tree, pool, nil
}

// compiledModuleFolder is the private folder for compiled grammar modules.
// The analyzer accepts one only where owner and mode bits prove it private.
func (s *indexSession) compiledModuleFolder() (string, bool) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return "", false
	}
	folder := filepath.Join(s.index.Directory(), "compiled")
	if err := fileauthority.MkdirAllPrivate(folder); err != nil {
		return "", false
	}
	return folder, true
}

// workerEnvironment is the whole environment of a syntax worker: a soft
// memory limit, and on Windows the system folder the runtime needs. No
// variable of the parent, and so no credential, reaches it.
func workerEnvironment() []string {
	environment := []string{"GOMEMLIMIT=512MiB"}
	if runtime.GOOS == "windows" {
		environment = append(environment, "SystemRoot="+os.Getenv("SystemRoot"))
	}
	return environment
}

// ensureIndexed loads a commit's graph, building the commit first when the
// index has no snapshot of it or its records are damaged.
func (s *indexSession) ensureIndexed(ctx context.Context, revision evidence.RevisionIdentity, stderr io.Writer) (*repoindex.Graph, error) {
	b, tree, pool, err := s.builder(revision)
	if err != nil {
		return nil, err
	}
	defer pool.Close()
	graph, built, err := b.Load(ctx, tree)
	if built && err == nil {
		fmt.Fprintf(stderr, "Indexed %s first.\n", shortCommit(revision.Digest()))
	}
	return graph, err
}

func shortCommit(digest string) string { return digest[:min(12, len(digest))] }

func runIndexBuild(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f, positional, err := parseIndexFlags("build", args, false)
	if err != nil || len(positional) != 0 {
		writeIndexUsage(stderr)
		return 2
	}
	s, err := openIndexSession(ctx, f)
	if err != nil {
		return indexFail(stderr, 1, "%v", err)
	}
	defer s.close()
	revision, err := s.commit(ctx, f.commit)
	if err != nil {
		return indexFail(stderr, 2, "--commit: %v", err)
	}
	b, tree, pool, err := s.builder(revision)
	if err != nil {
		return indexFail(stderr, 1, "the index could not be built: %v", err)
	}
	snapshot, err := b.Build(ctx, tree)
	pool.Close()
	if err != nil {
		return indexFail(stderr, 1, "the index could not be built: %v", err)
	}
	for _, line := range snapshotLines(snapshot) {
		fmt.Fprintln(stdout, line)
	}
	if stats := pool.Stats(); stats.Killed > 0 {
		fmt.Fprintf(stdout, "  Syntax workers replaced: %d (%d timed out, %d crashed, %d answered malformed output, %d left a guest call running, %d canceled).\n", stats.Killed, stats.TimedOut, stats.Crashed, stats.Malformed, stats.Abandoned, stats.Canceled)
	}
	return 0
}

// snapshotLines describes a snapshot without any repository path or name.
func snapshotLines(s repoindex.Snapshot) []string {
	c := s.Coverage
	counts := map[repoindex.Status]int{}
	for _, f := range s.Files {
		counts[f.Status]++
	}
	lines := []string{fmt.Sprintf("%s built %s in %s: %d files, %d analysed now (%d bytes), %d reused.", shortCommit(s.Commit), s.BuiltAt.Format(time.RFC3339), c.Duration.Round(time.Millisecond), len(s.Files), c.Analysed, c.AnalysedBytes, c.Reused)}
	statuses := make([]string, 0, len(counts))
	for status, n := range counts {
		statuses = append(statuses, fmt.Sprintf("%s %d", status, n))
	}
	sort.Strings(statuses)
	lines = append(lines, "  Files by status: "+strings.Join(statuses, ", ")+".")
	limited := counts[repoindex.StatusFileLimit] + counts[repoindex.StatusByteLimit] + counts[repoindex.StatusTimeLimit] + counts[repoindex.StatusStoreLimit] + counts[repoindex.StatusFailed]
	if limited > 0 {
		lines = append(lines, fmt.Sprintf("  %d files were left out by a limit or a failed analysis; build again to continue.", limited))
	}
	if c.TreeTruncated {
		lines = append(lines, fmt.Sprintf("  The tree was cut at %d entries; later entries are not indexed.", c.Limits.MaxEntries))
	}
	if c.InvalidPaths > 0 {
		lines = append(lines, fmt.Sprintf("  %d paths are not valid UTF-8 or are too long and are not indexed.", c.InvalidPaths))
	}
	return lines
}

func runIndexStatus(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f, positional, err := parseIndexFlags("status", args, false)
	if err != nil || len(positional) != 0 {
		writeIndexUsage(stderr)
		return 2
	}
	s, err := openIndexSession(ctx, f)
	if err != nil {
		return indexFail(stderr, 1, "%v", err)
	}
	defer s.close()
	revision, err := s.commit(ctx, f.commit)
	if err != nil {
		return indexFail(stderr, 2, "--commit: %v", err)
	}
	fmt.Fprintf(stdout, "Index folder: %s\n", initDisplayPath(s.index.Directory()))
	snapshot, err := s.index.Snapshot(ctx, s.algorithm, revision.Digest())
	if errors.Is(err, repoindex.ErrNotIndexed) {
		fmt.Fprintf(stdout, "%s is not indexed. Run trestle index build.\n", shortCommit(revision.Digest()))
		return 0
	}
	if err != nil {
		return indexFail(stderr, 1, "%v", err)
	}
	for _, line := range snapshotLines(snapshot) {
		fmt.Fprintln(stdout, line)
	}
	return 0
}
