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
// that stops asking, which only a defect in tree-sitter or a grammar could
// cause, is caught by a watchdog at twice the deadline (at least one second
// more): the file gets a deadline gap at once, the call is abandoned so
// that its next stop check traps it, the instance is closed when the call
// ends, and the family switches for the rest of the process to code
// compiled with wazero's termination checks, which stops every later call
// at its deadline. A guest that loops without ever reaching a stop check
// cannot be interrupted in fast code; its goroutine runs until the loop
// ends or the process exits.
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
	"time"

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
	orphans int
	// stalls counts the calls whose watchdog fired (guarded by mu).
	stalls      int
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
		_ = a.Close(ctx)
		return nil, err
	}
	return a, nil
}

// newRuntime returns a compiler runtime with the WASI and ot_host imports.
// With terminating set, compiled code checks for a closed module on every
// loop iteration, so a context deadline stops it.
func (a *Analyzer) newRuntime(ctx context.Context, terminating bool) (wazero.Runtime, error) {
	config := wazero.NewRuntimeConfigCompiler().
		WithMemoryLimitPages(a.memoryPages).
		WithCloseOnContextDone(terminating)
	if a.cache != nil {
		config = config.WithCompilationCache(a.cache)
	}
	r := wazero.NewRuntimeWithConfig(ctx, config)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		_ = r.Close(ctx)
		return nil, err
	}
	_, err := r.NewHostModuleBuilder("ot_host").
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

// Analyze implements syntaxanalysis.Analyzer. Every analysis failure is a
// coverage gap; the error result is only for an unsupported language and
// for cancellation of ctx.
func (a *Analyzer) Analyze(ctx context.Context, source syntaxanalysis.Source) (syntaxanalysis.FileAnalysis, error) {
	entry, ok := a.languages[source.Language()]
	if !ok || source.Path() == "" {
		return syntaxanalysis.FileAnalysis{}, syntaxanalysis.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return syntaxanalysis.FileAnalysis{}, err
	}
	gap := func(reason syntaxanalysis.GapReason, limit syntaxanalysis.Limit) (syntaxanalysis.FileAnalysis, error) {
		return syntaxanalysis.WholeFileGap(source, Identity, reason, limit), nil
	}
	switch {
	case entry.pack == nil:
		return gap(syntaxanalysis.GapNoQueryPack, "")
	case a.unavailable || a.isClosed():
		return gap(syntaxanalysis.GapAnalysisUnavailable, "")
	case source.Size() > a.limits.MaxFileBytes:
		return gap(syntaxanalysis.GapLimitExceeded, syntaxanalysis.LimitFileSize)
	}
	content := source.Content()
	if source.Language() == syntaxanalysis.LanguageC && headerLanguage(source.Path(), content) == syntaxanalysis.LanguageCPP {
		// A .h file is C by its name; one written in C++ is analysed and
		// reported as C++.
		cpp, err := syntaxanalysis.NewSource(source.Path(), syntaxanalysis.LanguageCPP, content)
		if cppEntry, ok := a.languages[syntaxanalysis.LanguageCPP]; err == nil && ok && cppEntry.pack != nil {
			source, entry = cpp, cppEntry
		}
	}
	started := time.Now()
	raw, embedded, failure := a.parse(ctx, entry, source.Language(), content, a.limits, syntaxanalysis.Span{})
	if failure != nil {
		if err := ctx.Err(); err != nil {
			return syntaxanalysis.FileAnalysis{}, err
		}
		return gap(failure.reason, failure.limit)
	}
	if entry.pack.filter != nil {
		entry.pack.filter(content, &raw)
	}
	for _, e := range embedded {
		if err := a.addEmbedded(ctx, content, e, &raw, started); err != nil {
			return syntaxanalysis.FileAnalysis{}, err
		}
	}
	analysis := syntaxanalysis.Assemble(source, Identity, raw, a.limits)
	if entry.pack.finish != nil && !hasGap(analysis, syntaxanalysis.GapAnalysisFailed) {
		entry.pack.finish(content, raw, &analysis)
	}
	return analysis, nil
}

// parse runs one guest analysis of content and turns its result into raw
// records. The gaps for the guest's limits cover scope, or the whole file
// when scope is empty.
func (a *Analyzer) parse(ctx context.Context, entry languageEntry, language syntaxanalysis.Language, content []byte, limits syntaxanalysis.Limits, scope syntaxanalysis.Span) (syntaxanalysis.RawFile, []embeddedCode, *failure) {
	a.calls.RLock()
	if a.isClosed() {
		a.calls.RUnlock()
		return syntaxanalysis.RawFile{}, nil, &failure{reason: syntaxanalysis.GapAnalysisUnavailable}
	}
	result, roles, fail := entry.family.analyze(ctx, language, entry.pack, content, limits)
	a.calls.RUnlock()
	if fail != nil {
		return syntaxanalysis.RawFile{}, nil, fail
	}
	raw, embedded, err := rawFile(content, result, roles)
	if err != nil {
		return syntaxanalysis.RawFile{}, nil, &failure{reason: syntaxanalysis.GapAnalysisFailed}
	}
	if result.flags&flagMatchLimit != 0 {
		raw.Gaps = append(raw.Gaps, syntaxanalysis.RawGap{Reason: syntaxanalysis.GapLimitExceeded, Limit: syntaxanalysis.LimitMatches, Span: scope})
	}
	if result.flags&flagResultLimit != 0 {
		raw.Gaps = append(raw.Gaps, syntaxanalysis.RawGap{Reason: syntaxanalysis.GapLimitExceeded, Limit: syntaxanalysis.LimitRecords, Span: tailSpan(result, len(content))})
	}
	if result.flags&flagErrorLimit != 0 {
		raw.Gaps = append(raw.Gaps, syntaxanalysis.RawGap{Reason: syntaxanalysis.GapLimitExceeded, Limit: syntaxanalysis.LimitErrorRegions, Span: scope})
	}
	if result.flags&flagTreeHasError != 0 && len(result.regions) == 0 && result.flags&flagErrorLimit == 0 {
		// The tree reports an error the region walk did not find; the
		// whole file is then not trustworthy.
		raw.Gaps = append(raw.Gaps, syntaxanalysis.RawGap{Reason: syntaxanalysis.GapParseError, Span: syntaxanalysis.Span{Start: 0, End: len(content)}})
	}
	return raw, embedded, nil
}

// addEmbedded analyses code embedded in a file, such as an inline HTML
// script, with the pack of its language, and adds its records to the
// file's at their offsets in the file. It shares the file's deadline. A
// failure becomes a gap over the embedded code; only cancellation of ctx
// is an error.
func (a *Analyzer) addEmbedded(ctx context.Context, content []byte, e embeddedCode, raw *syntaxanalysis.RawFile, started time.Time) error {
	language, ok := htmlScriptLanguage(content[e.tag.Start:e.tag.End])
	entry, known := a.languages[language]
	if !ok || !known || entry.pack == nil || e.code.Empty() {
		return nil
	}
	limits := a.limits
	limits.FileDeadline -= time.Since(started)
	if limits.FileDeadline <= 0 {
		raw.Gaps = append(raw.Gaps, syntaxanalysis.RawGap{Reason: syntaxanalysis.GapDeadlineExceeded, Span: e.code})
		return nil
	}
	code := content[e.code.Start:e.code.End]
	embedded, _, fail := a.parse(ctx, entry, language, code, limits, syntaxanalysis.Span{Start: 0, End: len(code)})
	if fail != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw.Gaps = append(raw.Gaps, syntaxanalysis.RawGap{Reason: fail.reason, Limit: fail.limit, Span: e.code})
		return nil
	}
	if entry.pack.filter != nil {
		entry.pack.filter(code, &embedded)
	}
	// The script's export list, if any, names its own bindings and not the
	// page's, so embedded.Exports is left out.
	at := e.code.Start
	shift := func(s syntaxanalysis.Span) syntaxanalysis.Span {
		if s.Empty() {
			return s
		}
		return syntaxanalysis.Span{Start: s.Start + at, End: s.End + at}
	}
	for _, d := range embedded.Definitions {
		d.Name, d.Node, d.Container = shift(d.Name), shift(d.Node), shift(d.Container)
		raw.Definitions = append(raw.Definitions, d)
	}
	for _, r := range embedded.References {
		r.Name, r.Qualifier = shift(r.Name), shift(r.Qualifier)
		raw.References = append(raw.References, r)
	}
	for _, i := range embedded.Imports {
		i.Source, i.Name, i.Alias, i.Node = shift(i.Source), shift(i.Name), shift(i.Alias), shift(i.Node)
		raw.Imports = append(raw.Imports, i)
	}
	for _, g := range embedded.Gaps {
		switch {
		case g.Reason == syntaxanalysis.GapParseError:
			// A missing token is a parse error of zero width.
			g.Span = syntaxanalysis.Span{Start: g.Span.Start + at, End: g.Span.End + at}
		case g.Span.Empty():
			g.Span = e.code
		default:
			g.Span = shift(g.Span)
		}
		raw.Gaps = append(raw.Gaps, g)
	}
	return nil
}

// tailSpan covers the source from the last returned match to the end, the
// part the match limit may have cut.
func tailSpan(result analysisResult, size int) syntaxanalysis.Span {
	start := 0
	if n := len(result.matches); n > 0 && len(result.matches[n-1].captures) > 0 {
		start = result.matches[n-1].captures[0].start
	}
	if start >= size {
		return syntaxanalysis.Span{}
	}
	return syntaxanalysis.Span{Start: start, End: size}
}

func hasGap(a syntaxanalysis.FileAnalysis, reason syntaxanalysis.GapReason) bool {
	for _, g := range a.Gaps {
		if g.Reason == reason {
			return true
		}
	}
	return false
}
