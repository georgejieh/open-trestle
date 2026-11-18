package syntaxwasm

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tetratelabs/wazero"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// setupDeadline bounds instantiation and query compilation, which process
// only the project's own module and queries.
const setupDeadline = 30 * time.Second

var (
	errInstance  = errors.New("syntax module instance is unusable")
	errStopped   = errors.New("syntax module stopped at the host's request")
	errStalled   = errors.New("syntax module ignored the stop checks")
	errAbandoned = errors.New("syntax module call was abandoned by the watchdog")
)

// abandonKey keys the flag that the watchdog sets on the context of a call
// it gave up on.
type abandonKey struct{}

// callAbandoned reports whether the watchdog gave up on the call that ctx
// belongs to; the host's next stop check then traps the guest.
func callAbandoned(ctx context.Context) bool {
	flag, ok := ctx.Value(abandonKey{}).(*atomic.Bool)
	return ok && flag.Load()
}

// watchdog is how long watch waits for a call: the deadline plus the
// deadline again, and at least one second more.
func watchdog(deadline time.Duration) time.Duration {
	return deadline + max(deadline, time.Second)
}

// watchdogFired is called each time the watchdog gives up on a call. Tests
// replace it to count those calls.
var watchdogFired = func() {}

// watch runs ot_analyze and waits at most until the watchdog. A call that
// outlives it is abandoned: its next stop check traps it, its instance is
// closed when it returns, and the family switches to terminating code.
func (f *family) watch(ctx context.Context, deadline time.Duration, inst *instance, params ...uint64) (uint32, error) {
	type outcome struct {
		value uint32
		err   error
	}
	abandoned := &atomic.Bool{}
	ctx = context.WithValue(ctx, abandonKey{}, abandoned)
	done := make(chan outcome, 1)
	go func() {
		value, err := inst.call(ctx, inst.analyze, params...)
		done <- outcome{value, err}
	}()
	timer := time.NewTimer(watchdog(deadline))
	defer timer.Stop()
	select {
	case o := <-done:
		return o.value, o.err
	case <-timer.C:
	}
	abandoned.Store(true)
	watchdogFired()
	a := f.analyzer
	a.mu.Lock()
	a.orphans++
	a.mu.Unlock()
	f.switchToTerminating()
	go func() {
		<-done
		inst.close()
		a.orphanEnded()
	}()
	return 0, errStalled
}

// failure is an analysis failure, reported as a whole-file gap.
type failure struct {
	reason syntaxanalysis.GapReason
	limit  syntaxanalysis.Limit
}

// family is one language family module: compiled once per mode,
// instantiated up to a fixed number of times, with idle instances kept for
// reuse.
type family struct {
	analyzer *Analyzer
	manifest familyManifest
	slots    chan struct{}
	// modules are indexed by mode: fast, then terminating.
	modules [2]compiledModule

	mu   sync.Mutex
	idle []*instance
	// terminating is set once a guest ignored the stop checks; new
	// instances then come from the terminating runtime.
	terminating bool
	// image is the memory of an instance that compiled queries and analysed
	// nothing; new instances start from it instead of compiling again.
	image *memoryImage
}

// compiledModule is a family module compiled for one runtime, once.
type compiledModule struct {
	once     sync.Once
	compiled wazero.CompiledModule
	err      error
}

const (
	modeFast        = 0
	modeTerminating = 1
)

func newFamily(a *Analyzer, manifest familyManifest, instances int) *family {
	return &family{analyzer: a, manifest: manifest, slots: make(chan struct{}, instances)}
}

// switchToTerminating makes every later instance use terminating code and
// closes the idle fast ones.
func (f *family) switchToTerminating() {
	f.mu.Lock()
	f.terminating = true
	idle := f.idle
	f.idle = nil
	f.mu.Unlock()
	for _, inst := range idle {
		inst.close()
	}
}

// compile compiles the module for a mode once, outside the family lock, so
// that a slow cold compile does not hold up the idle list.
func (f *family) compile(ctx context.Context, mode int) (wazero.CompiledModule, wazero.Runtime, error) {
	runtime := f.analyzer.runtime
	if mode == modeTerminating {
		r, err := f.analyzer.terminatingRuntime(ctx)
		if err != nil {
			return nil, nil, err
		}
		runtime = r
	}
	m := &f.modules[mode]
	m.once.Do(func() { m.compiled, m.err = compileModule(context.WithoutCancel(ctx), runtime, f.manifest) })
	if m.err != nil {
		return nil, nil, m.err
	}
	return m.compiled, runtime, nil
}

// compileModule compiles a family module. A panic inside wazero, as when
// the platform refuses executable memory, is a module failure.
func compileModule(ctx context.Context, runtime wazero.Runtime, manifest familyManifest) (compiled wazero.CompiledModule, err error) {
	defer func() {
		if recover() != nil {
			compiled, err = nil, errModule
		}
	}()
	data, err := loadModule(manifest)
	if err != nil {
		return nil, err
	}
	compiled, err = runtime.CompileModule(ctx, data)
	if err != nil {
		return nil, err
	}
	if _, ok := compiled.ExportedMemories()["memory"]; !ok {
		_ = compiled.Close(ctx)
		return nil, errModule
	}
	return compiled, nil
}

func (f *family) instantiate(ctx context.Context) (*instance, error) {
	f.mu.Lock()
	mode := modeFast
	if f.terminating {
		mode = modeTerminating
	}
	image := f.image
	f.mu.Unlock()
	compiled, runtime, err := f.compile(ctx, mode)
	if err != nil {
		return nil, err
	}
	inst, err := newInstance(ctx, runtime, compiled, mode, f.manifest.Languages)
	if err != nil {
		return nil, err
	}
	if image != nil && !inst.restore(image) {
		inst.close()
		return nil, errInstance
	}
	return inst, nil
}

// keepImage makes image the family's image when it has every query the
// current one has. Two instances that compiled different queries at the
// same time cannot be merged; the next pristine instance to compile a
// missing query produces an image with both.
func (f *family) keepImage(image *memoryImage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.image != nil {
		if len(image.queries) <= len(f.image.queries) {
			return
		}
		for index := range f.image.queries {
			if _, ok := image.queries[index]; !ok {
				return
			}
		}
	}
	f.image = image
}

// acquire waits for a free slot and returns an idle or new instance.
func (f *family) acquire(ctx context.Context) (*instance, *failure) {
	select {
	case f.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, &failure{reason: syntaxanalysis.GapAnalysisUnavailable}
	}
	f.mu.Lock()
	if n := len(f.idle); n > 0 {
		inst := f.idle[n-1]
		f.idle = f.idle[:n-1]
		f.mu.Unlock()
		return inst, nil
	}
	f.mu.Unlock()
	inst, err := f.fresh(ctx)
	if err != nil {
		<-f.slots
		return nil, &failure{reason: syntaxanalysis.GapAnalysisUnavailable}
	}
	return inst, nil
}

// fresh instantiates the module for a slot the caller holds.
func (f *family) fresh(ctx context.Context) (*instance, error) {
	setup, cancel := context.WithTimeout(ctx, setupDeadline)
	defer cancel()
	return f.instantiate(setup)
}

// release returns a healthy instance to the idle list and closes any other.
func (f *family) release(inst *instance, healthy bool) {
	closed := f.analyzer.isClosed()
	f.mu.Lock()
	healthy = healthy && !closed && !(f.terminating && inst.mode == modeFast)
	if healthy {
		f.idle = append(f.idle, inst)
	}
	f.mu.Unlock()
	if !healthy {
		inst.close()
	}
	<-f.slots
}

// prepare returns an instance that has the language's query. An instance
// that has analysed files and lacks the query is replaced by a fresh one,
// which starts from the family's image; a pristine instance that compiles
// the query becomes the new image.
func (f *family) prepare(ctx context.Context, inst *instance, index int, text string) (*instance, loadedQuery, error) {
	if q, ok := inst.queries[index]; ok {
		return inst, q, nil
	}
	if !inst.pristine {
		inst.close()
		next, err := f.fresh(ctx)
		if err != nil {
			return nil, loadedQuery{}, err
		}
		inst = next
		if q, ok := inst.queries[index]; ok {
			return inst, q, nil
		}
	}
	q, err := inst.ensureQuery(ctx, index, text)
	if err != nil {
		return inst, loadedQuery{}, err
	}
	if image, ok := inst.snapshot(); ok {
		f.keepImage(image)
	}
	return inst, q, nil
}

// analyze runs the language's query over content in one instance and turns
// the result into raw records before the instance is released, so that a
// malformed result also discards the instance. The gaps for the guest's own
// limits cover scope, or the whole file when scope is empty.
func (f *family) analyze(ctx context.Context, language syntaxanalysis.Language, p *pack, content []byte, limits syntaxanalysis.Limits, scope syntaxanalysis.Span) (parsed, *failure) {
	index := slices.Index(f.manifest.Languages, string(language))
	if index < 0 {
		return parsed{}, &failure{reason: syntaxanalysis.GapAnalysisFailed}
	}
	inst, fail := f.acquire(ctx)
	if fail != nil {
		return parsed{}, fail
	}
	inst, query, err := f.prepare(ctx, inst, index, p.query)
	if inst == nil {
		<-f.slots
		return parsed{}, &failure{reason: syntaxanalysis.GapAnalysisUnavailable}
	}
	if err != nil {
		fail := inst.classify(ctx, ctx, err)
		f.release(inst, false)
		return parsed{}, fail
	}
	inst.pristine = false
	run := f.run(ctx, inst, index, query, content, limits, scope)
	if run.orphaned {
		<-f.slots
	} else {
		f.release(inst, run.fail == nil && inst.memory.Size() <= recycleMemoryBytes)
	}
	return run.parsed, run.fail
}

// parsed is the raw records of one guest analysis, the code embedded in
// the file, and when the analysis began, which starts the file's deadline.
type parsed struct {
	raw      syntaxanalysis.RawFile
	embedded []embeddedCode
	started  time.Time
}

type runResult struct {
	parsed
	fail *failure
	// orphaned is set when the watchdog abandoned the call, which then owns
	// the instance.
	orphaned bool
}

func (f *family) run(ctx context.Context, inst *instance, index int, query loadedQuery, content []byte, limits syntaxanalysis.Limits, scope syntaxanalysis.Span) runResult {
	failed := func(fail *failure) runResult { return runResult{fail: fail} }
	started := time.Now()
	call, cancel := context.WithTimeout(ctx, limits.FileDeadline)
	defer cancel()
	source, err := inst.write(call, content)
	if err != nil {
		return failed(inst.classify(ctx, call, err))
	}
	maxMatches := uint64(min(2*limits.MaxRecords, 1<<21))
	maxRegions := uint64(min(4*limits.MaxErrorRegions, 1<<18))
	pointer, err := f.watch(call, limits.FileDeadline, inst, uint64(index), uint64(source), uint64(len(content)), maxMatches, maxRegions)
	if errors.Is(err, errStalled) {
		return runResult{fail: &failure{reason: syntaxanalysis.GapDeadlineExceeded}, orphaned: true}
	}
	if err != nil {
		return failed(inst.classify(ctx, call, err))
	}
	data, err := inst.result(pointer)
	if err != nil {
		return failed(inst.classify(ctx, call, err))
	}
	if _, err := inst.call(call, inst.free, uint64(source)); err != nil {
		return failed(inst.classify(ctx, call, err))
	}
	result, status, err := decodeAnalysis(data, query.info, len(content))
	if err == nil && status == statusStopped {
		return failed(inst.classify(ctx, call, errStopped))
	}
	if err != nil || status != statusOK {
		return failed(&failure{reason: syntaxanalysis.GapAnalysisFailed})
	}
	raw, embedded, err := rawFile(content, result, query.roles)
	if err != nil {
		return failed(&failure{reason: syntaxanalysis.GapAnalysisFailed})
	}
	raw.Gaps = append(raw.Gaps, limitGaps(result, len(content), scope)...)
	return runResult{parsed: parsed{raw: raw, embedded: embedded, started: started}}
}

// limitGaps reports the limits the guest reached, over scope or, when scope
// is empty, the whole file. Matches arrive in the order they complete, so
// the match limit can drop a record from anywhere in scope.
func limitGaps(result analysisResult, size int, scope syntaxanalysis.Span) []syntaxanalysis.RawGap {
	var gaps []syntaxanalysis.RawGap
	if result.flags&flagMatchLimit != 0 {
		gaps = append(gaps, syntaxanalysis.RawGap{Reason: syntaxanalysis.GapLimitExceeded, Limit: syntaxanalysis.LimitMatches, Span: scope})
	}
	if result.flags&flagResultLimit != 0 {
		gaps = append(gaps, syntaxanalysis.RawGap{Reason: syntaxanalysis.GapLimitExceeded, Limit: syntaxanalysis.LimitRecords, Span: scope})
	}
	if result.flags&flagErrorLimit != 0 {
		gaps = append(gaps, syntaxanalysis.RawGap{Reason: syntaxanalysis.GapLimitExceeded, Limit: syntaxanalysis.LimitErrorRegions, Span: scope})
	}
	if result.flags&flagTreeHasError != 0 && len(result.regions) == 0 && result.flags&flagErrorLimit == 0 {
		// The tree reports an error the region walk did not find, so none
		// of the file is trustworthy.
		gaps = append(gaps, syntaxanalysis.RawGap{Reason: syntaxanalysis.GapParseError, Span: syntaxanalysis.Span{Start: 0, End: size}})
	}
	return gaps
}
