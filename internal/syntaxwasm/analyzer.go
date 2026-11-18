// Package syntaxwasm analyses source files with tree-sitter grammars
// compiled to WebAssembly and run under wazero.
//
// The tree-sitter runtime, the grammars of one language family and a small
// C shim are linked into one WASI reactor module per family (see
// modules/manifest.json and tools/build_syntax_modules.py). The parser is C
// code processing hostile repository text, so the guest is treated as
// untrusted: it runs in its own linear memory under a page cap, it has no
// file system, environment, clock or network capability, every pointer and
// length it returns is bounds-checked, and an instance is discarded after
// any trap, deadline or malformed result.
//
// The per-file deadline has two layers. The shim asks the host whether to
// stop every hundred parser operations, during query matching and during
// the error-region walk, and the host answers from the call's context; this
// costs almost nothing. wazero's own termination checks, which call into Go
// on every loop iteration, would make a parse several times slower. A guest
// that does not stop, which only a defect in tree-sitter or a grammar could
// cause, is caught by a watchdog at twice the deadline (at least one second
// more): the file gets a deadline gap at once, the call is abandoned so
// that its next stop check traps it, and the family switches for the rest
// of the process to code compiled with wazero's termination checks, which
// stops every later call at its deadline. A guest that loops without ever
// reaching a stop check keeps its goroutine, CPU and memory until the
// process exits; AbandonedCalls counts such calls, so that a host running
// analysis in a worker process can replace the worker.
//
// Compiling a query takes up to a few seconds inside the guest. The first
// instance of a family that compiles a query, before it sees any repository
// content, becomes the family's memory image, and later instances start
// from a copy of that memory with the query already compiled.
//
// Modules are compiled lazily, once per family and process, with wazero's
// compiler. Where the compiler does not run, every file gets an
// analysis_unavailable gap; the interpreter is never used.
package syntaxwasm

import (
	"context"
	"errors"
	"runtime"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// compilerAvailable is compilerSupported; tests replace it to exercise the
// unavailable path on platforms where the compiler runs.
var compilerAvailable = compilerSupported

// Identity names this analyzer in FileAnalysis.Analyzer.
const Identity = "open-trestle/syntax/tree-sitter-wasm/v1"

const (
	// DefaultMemoryLimitPages caps each instance at 256 MiB of linear
	// memory.
	DefaultMemoryLimitPages = 4096
	// recycleMemoryBytes is the instance memory size above which an
	// instance is closed after use instead of kept, so that one large file
	// does not keep its memory for the life of the process.
	recycleMemoryBytes = 64 << 20
)

var errUnavailable = errors.New("the wazero compiler did not start")

var (
	// ErrInvalidConfig reports a configuration value outside its range.
	ErrInvalidConfig = errors.New("invalid syntax analyzer configuration")
	// ErrCacheUntrusted reports a compilation cache directory that is not
	// private to the current user.
	ErrCacheUntrusted = errors.New("syntax module cache directory is not private to the current user")
)

// Config configures an Analyzer.
type Config struct {
	// CacheDirectory, when not empty, keeps compiled native code across
	// processes. Whoever can write it controls the code the analyzer runs,
	// so it must be an absolute path to a directory owned by the current
	// user with no group or other permission bits, on a path that only
	// root and the current user can change. It is refused on macOS and
	// Windows, where owner and mode bits do not prove that.
	CacheDirectory string
	// Limits bound the work per file. The zero value means
	// syntaxanalysis.DefaultLimits.
	Limits syntaxanalysis.Limits
	// MemoryLimitPages caps each instance's linear memory in 64 KiB pages.
	// Zero means DefaultMemoryLimitPages.
	MemoryLimitPages uint32
	// InstancesPerFamily bounds the concurrent analyses of one family.
	// Zero means min(4, GOMAXPROCS).
	InstancesPerFamily int
}

// Analyzer implements syntaxanalysis.Analyzer for every language that has a
// grammar in a family module. It is safe for concurrent use.
type Analyzer struct {
	limits      syntaxanalysis.Limits
	memoryPages uint32
	languages   map[syntaxanalysis.Language]languageEntry
	runtime     wazero.Runtime
	cache       wazero.CompilationCache
	// terminating is the runtime with wazero's termination checks, created
	// after a guest ignores the stop checks (guarded by mu).
	terminating wazero.Runtime
	// orphans counts guest calls still running after their watchdog fired
	// (guarded by mu). While one runs, the runtimes stay open: closing a
	// runtime unmaps the code a call is executing. Close leaves them to the
	// last orphan to end.
	orphans     int
	unavailable bool

	// calls is held for reading by every analysis and for writing by
	// Close, so that a runtime is never closed under running code.
	calls  sync.RWMutex
	mu     sync.Mutex
	closed bool
}

type languageEntry struct {
	family *family
	pack   *pack
}

// New returns an analyzer. It compiles nothing: each family module is
// compiled when a file of one of its languages is first analysed.
func New(ctx context.Context, config Config) (*Analyzer, error) {
	limits := config.Limits
	if limits == (syntaxanalysis.Limits{}) {
		limits = syntaxanalysis.DefaultLimits()
	}
	pages := config.MemoryLimitPages
	if pages == 0 {
		pages = DefaultMemoryLimitPages
	}
	instances := config.InstancesPerFamily
	if instances == 0 {
		instances = min(4, runtime.GOMAXPROCS(0))
	}
	if !limits.Valid() || pages > 65536 || instances < 1 || instances > 256 {
		return nil, ErrInvalidConfig
	}
	manifest, err := readManifest()
	if err != nil {
		return nil, err
	}
	packs, err := loadPacks()
	if err != nil {
		return nil, err
	}
	a := &Analyzer{limits: limits, memoryPages: pages, languages: map[syntaxanalysis.Language]languageEntry{}}
	for _, fm := range manifest.Families {
		f := newFamily(a, fm, instances)
		for _, name := range fm.Languages {
			language := syntaxanalysis.Language(name)
			if !language.Valid() || language == syntaxanalysis.LanguageGo {
				return nil, errModule
			}
			if _, dup := a.languages[language]; dup {
				return nil, errModule
			}
			entry := languageEntry{family: f}
			if p, ok := packs[language]; ok {
				entry.pack = &p
			}
			a.languages[language] = entry
		}
	}
	for language := range packs {
		if _, ok := a.languages[language]; !ok {
			return nil, errModule
		}
	}
	if !compilerAvailable() {
		if config.CacheDirectory != "" {
			if _, err := privateCacheDirectory(config.CacheDirectory); err != nil {
				return nil, err
			}
		}
		a.unavailable = true
		return a, nil
	}
	if config.CacheDirectory != "" {
		directory, err := privateCacheDirectory(config.CacheDirectory)
		if err != nil {
			return nil, err
		}
		cache, err := wazero.NewCompilationCacheWithDir(directory)
		if err != nil {
			return nil, ErrCacheUntrusted
		}
		a.cache = cache
	}
	if a.runtime, err = a.newRuntime(ctx, false); err != nil {
		// The compiler did not start here, for example because the
		// platform refuses executable memory.
		a.unavailable = true
	}
	return a, nil
}

// newWazeroRuntime creates a runtime; tests replace it to inject an engine
// failure.
var newWazeroRuntime = wazero.NewRuntimeWithConfig

// newRuntime returns a compiler runtime with the WASI and ot_host imports.
// With terminating set, compiled code checks for a closed module on every
// loop iteration, so a context deadline stops it.
func (a *Analyzer) newRuntime(ctx context.Context, terminating bool) (r wazero.Runtime, err error) {
	defer func() {
		if recover() != nil {
			r, err = nil, errUnavailable
		}
	}()
	config := wazero.NewRuntimeConfigCompiler().
		WithMemoryLimitPages(a.memoryPages).
		WithCloseOnContextDone(terminating)
	if a.cache != nil {
		config = config.WithCompilationCache(a.cache)
	}
	r = newWazeroRuntime(ctx, config)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		_ = r.Close(ctx)
		return nil, err
	}
	_, err = r.NewHostModuleBuilder("ot_host").
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context) uint32 {
			if callAbandoned(ctx) {
				// Unwinds the guest call; wazero returns the panic as
				// the call's error.
				panic(errAbandoned)
			}
			if stopRequested(ctx) {
				return 1
			}
			return 0
		}).
		Export("should_stop").
		Instantiate(ctx)
	if err != nil {
		_ = r.Close(ctx)
		return nil, err
	}
	return r, nil
}

// stopRequested answers the guest's stop checks. Tests replace it to model
// a guest that never stops.
var stopRequested = func(ctx context.Context) bool { return ctx.Err() != nil }

// terminatingRuntime returns the runtime with termination checks, creating
// it on first use.
func (a *Analyzer) terminatingRuntime(ctx context.Context) (wazero.Runtime, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, errInstance
	}
	if a.terminating == nil {
		r, err := a.newRuntime(ctx, true)
		if err != nil {
			return nil, err
		}
		a.terminating = r
	}
	return a.terminating, nil
}

// Available reports whether analysis can run on this platform. When it
// cannot, every supported file gets an analysis_unavailable gap.
func (a *Analyzer) Available() bool { return !a.unavailable }

// AbandonedCalls returns the number of guest calls that the watchdog gave
// up on and that are still running. Such a call holds a goroutine, CPU and
// memory until it returns, which a guest that never reaches a stop check
// does only when the process exits.
func (a *Analyzer) AbandonedCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.orphans
}

// Supports reports whether a family module has a grammar for the language.
// A supported language without a query pack yields a no_query_pack gap.
func (a *Analyzer) Supports(language syntaxanalysis.Language) bool {
	_, ok := a.languages[language]
	return ok
}

// HasQueryPack reports whether the language has a query pack.
func (a *Analyzer) HasQueryPack(language syntaxanalysis.Language) bool {
	entry, ok := a.languages[language]
	return ok && entry.pack != nil
}

// Close releases every instance and compiled module after the analyses in
// progress end. While a call abandoned by the watchdog still runs, the
// runtimes stay open; they are closed when the last such call ends.
func (a *Analyzer) Close(ctx context.Context) error {
	a.calls.Lock()
	defer a.calls.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	if a.orphans > 0 {
		return nil
	}
	return a.closeRuntimes(ctx)
}

// orphanEnded records the end of a call abandoned by the watchdog, and
// closes the runtimes if Close ran while it was still going.
func (a *Analyzer) orphanEnded() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.orphans--
	if a.closed && a.orphans == 0 {
		_ = a.closeRuntimes(context.Background())
	}
}

// closeRuntimes closes the runtimes and the cache. The caller holds mu.
func (a *Analyzer) closeRuntimes(ctx context.Context) error {
	var err error
	if a.runtime != nil {
		err = a.runtime.Close(ctx)
	}
	if a.terminating != nil {
		err = errors.Join(err, a.terminating.Close(ctx))
	}
	if a.cache != nil {
		err = errors.Join(err, a.cache.Close(ctx))
	}
	return err
}

func (a *Analyzer) isClosed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}
