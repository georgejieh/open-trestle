package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
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
	dir := discoverSetupDirectory(ctx, checkout)
	if f.directory != "" {
		if dir, err = initValidateDirectory(f.directory); err != nil {
			return nil, fmt.Errorf("--directory: %w", err)
		}
	}
	if dir == "" {
		return nil, errors.New("the setup folder cannot be found (set HOME)")
	}
	objectsPath, algorithm, err := resolveLocalCheckoutObjects(ctx, checkout)
	if err != nil {
		return nil, errors.New("the checkout's Git objects cannot be found")
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
	return &indexSession{checkout: checkout, algorithm: algorithm, objects: objects, store: store, index: index}, nil
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

// build indexes a commit with a pool of syntax workers.
func (s *indexSession) build(ctx context.Context, revision evidence.RevisionIdentity) (repoindex.Snapshot, error) {
	tree, err := repoindex.NewGitTree(s.store, revision)
	if err != nil {
		return repoindex.Snapshot{}, err
	}
	executable, err := os.Executable()
	if err != nil {
		return repoindex.Snapshot{}, err
	}
	command := []string{executable, "index", "worker"}
	if cache, ok := s.compiledModuleFolder(); ok {
		command = append(command, "--cache-directory", cache)
	}
	pool, err := syntaxworker.NewPool(syntaxworker.Config{Command: command, Environment: workerEnvironment()})
	if err != nil {
		return repoindex.Snapshot{}, err
	}
	defer pool.Close()
	return repoindex.Builder{Store: s.index, Analyzer: pool, Parallelism: pool.Workers()}.Build(ctx, tree)
}

// compiledModuleFolder is the private folder for compiled grammar modules.
// The analyzer accepts one only where owner and mode bits prove it private.
func (s *indexSession) compiledModuleFolder() (string, bool) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return "", false
	}
	folder := filepath.Join(s.index.Directory(), "compiled")
	if err := os.MkdirAll(folder, 0o700); err != nil {
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

// ensureIndexed builds a commit that the index has no complete snapshot of.
func (s *indexSession) ensureIndexed(ctx context.Context, revision evidence.RevisionIdentity, stderr io.Writer) (*repoindex.Graph, error) {
	graph, err := s.index.Load(ctx, s.algorithm, revision.Digest())
	if err == nil {
		return graph, nil
	}
	if !errors.Is(err, repoindex.ErrNotIndexed) {
		return nil, err
	}
	fmt.Fprintf(stderr, "Indexing %s first.\n", shortCommit(revision.Digest()))
	if _, err := s.build(ctx, revision); err != nil {
		return nil, err
	}
	return s.index.Load(ctx, s.algorithm, revision.Digest())
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
	snapshot, err := s.build(ctx, revision)
	if err != nil {
		return indexFail(stderr, 1, "the index could not be built: %v", err)
	}
	for _, line := range snapshotLines(snapshot) {
		fmt.Fprintln(stdout, line)
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

func writeIndexJSON(stdout, stderr io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return indexFail(stderr, 1, "the result could not be written")
	}
	return 0
}

func runIndexQuery(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeIndexUsage(stderr)
		return 2
	}
	kind := args[0]
	f, positional, err := parseIndexFlags("query "+kind, args[1:], kind == "dependents")
	wantArgs := 1
	if kind == "dependents" {
		wantArgs = 0
	}
	if err != nil || len(positional) != wantArgs || kind == "dependents" && f.base == "" {
		writeIndexUsage(stderr)
		return 2
	}
	switch kind {
	case "definitions", "references", "tests", "imports", "dependents":
	default:
		fmt.Fprintf(stderr, "trestle index: unknown query %q\n", kind)
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
	graph, err := s.ensureIndexed(ctx, revision, stderr)
	if err != nil {
		return indexFail(stderr, 1, "%v", err)
	}
	if kind == "dependents" {
		return runIndexDependents(ctx, s, f, graph, stdout, stderr)
	}
	return writeIndexJSON(stdout, stderr, indexQueryResult(graph, kind, positional[0]))
}

type symbolResult struct {
	Definition repoindex.Symbol `json:"definition"`
	References []repoindex.Use  `json:"references,omitempty"`
	Tests      []repoindex.Use  `json:"tests,omitempty"`
}

func indexQueryResult(graph *repoindex.Graph, kind, argument string) any {
	if kind == "imports" {
		imports, unresolved, found := graph.Imports(argument)
		importers, _ := graph.Importers(argument)
		return struct {
			Found      bool     `json:"found"`
			Imports    []string `json:"imports"`
			Unresolved int      `json:"unresolved"`
			Importers  []string `json:"importers"`
		}{found, imports, unresolved, importers}
	}
	results := []symbolResult{}
	for _, d := range graph.Definitions(argument) {
		r := symbolResult{Definition: d}
		switch kind {
		case "references":
			r.References = graph.References(d.ID)
		case "tests":
			r.Tests = graph.TestReferences(d.ID)
		}
		results = append(results, r)
	}
	return struct {
		Definitions []symbolResult `json:"definitions"`
	}{results}
}

// runIndexDependents computes the dependents of the change from --base to
// --commit: the changed lines come from a diff of each changed file's base
// and head blobs.
func runIndexDependents(ctx context.Context, s *indexSession, f indexFlags, head *repoindex.Graph, stdout, stderr io.Writer) int {
	baseRevision, err := s.commit(ctx, f.base)
	if err != nil {
		return indexFail(stderr, 2, "--base: %v", err)
	}
	base, err := s.ensureIndexed(ctx, baseRevision, stderr)
	if err != nil {
		return indexFail(stderr, 1, "%v", err)
	}
	changes, err := s.changes(ctx, base.Files(), head.Files())
	if err != nil {
		return indexFail(stderr, 1, "the change could not be read: %v", err)
	}
	return writeIndexJSON(stdout, stderr, repoindex.Dependents(head, base, changes, repoindex.DefaultDependentsLimits()))
}

// changes lists the files whose blob differs between two snapshots, with
// the changed lines of each modified file. A file the diff cannot represent
// counts as changed throughout.
func (s *indexSession) changes(ctx context.Context, base, head []repoindex.FileEntry) ([]repoindex.Change, error) {
	whole := []repoindex.LineRange{{Start: 1, End: math.MaxInt32}}
	baseObjects := map[string]string{}
	for _, f := range base {
		baseObjects[f.Path] = f.Object
	}
	changes := []repoindex.Change{}
	for _, f := range head {
		object, existed := baseObjects[f.Path]
		delete(baseObjects, f.Path)
		switch {
		case !existed:
			changes = append(changes, repoindex.Change{Path: f.Path, HeadLines: whole})
		case object != f.Object:
			change := repoindex.Change{Path: f.Path, BasePath: f.Path, HeadLines: whole, BaseLines: whole}
			if headLines, baseLines, ok := s.diff(ctx, f.Path, object, f.Object); ok {
				change.HeadLines, change.BaseLines = headLines, baseLines
			}
			changes = append(changes, change)
		}
	}
	for p := range baseObjects {
		changes = append(changes, repoindex.Change{BasePath: p, BaseLines: whole})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path+changes[i].BasePath < changes[j].Path+changes[j].BasePath })
	return changes, ctx.Err()
}

func (s *indexSession) diff(ctx context.Context, path, baseObject, headObject string) (head, base []repoindex.LineRange, ok bool) {
	algorithm := evidence.RevisionAlgorithm(s.algorithm)
	baseContent, err := s.store.ReadBlob(ctx, algorithm, baseObject)
	if err != nil {
		return nil, nil, false
	}
	headContent, err := s.store.ReadBlob(ctx, algorithm, headObject)
	if err != nil {
		return nil, nil, false
	}
	patch, err := evidence.GenerateUnifiedFileDiff(path, baseContent, headContent)
	if err != nil {
		return nil, nil, false
	}
	_, lineMap, err := evidence.ParseUnifiedFileDiff(path, baseContent, headContent, patch)
	if err != nil {
		return nil, nil, false
	}
	for _, hunk := range lineMap.Hunks() {
		if n := hunk.HeadLineCount(); n > 0 {
			head = append(head, repoindex.LineRange{Start: hunk.HeadStartLine(), End: hunk.HeadStartLine() + n - 1})
		}
		if n := hunk.BaseLineCount(); n > 0 {
			base = append(base, repoindex.LineRange{Start: hunk.BaseStartLine(), End: hunk.BaseStartLine() + n - 1})
		}
	}
	return head, base, true
}
