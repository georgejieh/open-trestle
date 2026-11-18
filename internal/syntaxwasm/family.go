package syntaxwasm

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

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
// belongs to. The host's stop check then traps the guest, so a call that
// still asks ends at its next check instead of running on.
func callAbandoned(ctx context.Context) bool {
	flag, ok := ctx.Value(abandonKey{}).(*atomic.Bool)
	return ok && flag.Load()
}

// watchdog is how long watch waits for a call: the deadline plus the
// deadline again, and at least one second more.
func watchdog(deadline time.Duration) time.Duration {
	return deadline + max(deadline, time.Second)
}

// watch runs ot_analyze and waits at most until the watchdog. A call that
// outlives it ignored the stop checks. The call is then abandoned, so its
// next stop check traps it, and the family switches to terminating code. A
// guest that never reaches a stop check again keeps running on its own
// goroutine until it returns; that goroutine closes the instance.
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
	a := f.analyzer
	a.mu.Lock()
	a.orphans++
	a.stalls++
	a.mu.Unlock()
	f.mu.Lock()
	f.terminating = true
	f.mu.Unlock()
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

// family is one language family module: compiled once, instantiated up to
// a fixed number of times, with idle instances kept for reuse.
type family struct {
	analyzer *Analyzer
	manifest familyManifest
	slots    chan struct{}

	mu sync.Mutex
	// compiled and compileErr are indexed by mode: fast, then terminating.
	compiled   [2]wazero.CompiledModule
	compileErr [2]error
	idle       []*instance
	// terminating is set once a guest ignored the stop checks; new
	// instances then come from the terminating runtime.
	terminating bool
}

const (
	modeFast        = 0
	modeTerminating = 1
)

func newFamily(a *Analyzer, manifest familyManifest, instances int) *family {
	return &family{analyzer: a, manifest: manifest, slots: make(chan struct{}, instances)}
}

// instance is one module instance. It is used by one goroutine at a time.
type instance struct {
	module      api.Module
	memory      api.Memory
	alloc, free api.Function
	loadQuery   api.Function
	analyze     api.Function
	failureFlag uint32
	languages   []string
	queries     map[int]loadedQuery
	mode        int
}

type loadedQuery struct {
	info  queryInfo
	roles []role
}

func (f *family) compile(ctx context.Context, mode int) (wazero.CompiledModule, wazero.Runtime, error) {
	runtime := f.analyzer.runtime
	if mode == modeTerminating {
		r, err := f.analyzer.terminatingRuntime(ctx)
		if err != nil {
			return nil, nil, err
		}
		runtime = r
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.compiled[mode] != nil || f.compileErr[mode] != nil {
		return f.compiled[mode], runtime, f.compileErr[mode]
	}
	data, err := loadModule(f.manifest)
	if err != nil {
		f.compileErr[mode] = err
		return nil, nil, err
	}
	compiled, err := runtime.CompileModule(ctx, data)
	if err != nil {
		if ctx.Err() == nil {
			f.compileErr[mode] = err
		}
		return nil, nil, err
	}
	if _, ok := compiled.ExportedMemories()["memory"]; !ok {
		_ = compiled.Close(ctx)
		f.compileErr[mode] = errModule
		return nil, nil, errModule
	}
	f.compiled[mode] = compiled
	return compiled, runtime, nil
}

func (f *family) instantiate(ctx context.Context) (*instance, error) {
	f.mu.Lock()
	mode := modeFast
	if f.terminating {
		mode = modeTerminating
	}
	f.mu.Unlock()
	compiled, runtime, err := f.compile(ctx, mode)
	if err != nil {
		return nil, err
	}
	module, err := runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("").WithStartFunctions("_initialize"))
	if err != nil {
		return nil, err
	}
	inst := &instance{
		mode:   mode,
		module: module, memory: module.Memory(),
		alloc: module.ExportedFunction("ot_alloc"), free: module.ExportedFunction("ot_free"),
		loadQuery: module.ExportedFunction("ot_load_query"), analyze: module.ExportedFunction("ot_analyze"),
		queries: map[int]loadedQuery{},
	}
	abi, describe, flag := module.ExportedFunction("ot_abi_version"), module.ExportedFunction("ot_describe"), module.ExportedFunction("ot_failure_flag_address")
	if inst.memory == nil || inst.alloc == nil || inst.free == nil || inst.loadQuery == nil || inst.analyze == nil || abi == nil || describe == nil || flag == nil {
		inst.close()
		return nil, errModule
	}
	version, err := inst.call(ctx, abi)
	if err != nil || version != shimABIVersion {
		inst.close()
		return nil, errModule
	}
	if inst.failureFlag, err = inst.call(ctx, flag); err != nil || uint64(inst.failureFlag)+4 > uint64(inst.memory.Size()) {
		inst.close()
		return nil, errModule
	}
	pointer, err := inst.call(ctx, describe)
	if err != nil {
		inst.close()
		return nil, err
	}
	data, err := inst.result(pointer)
	if err != nil {
		inst.close()
		return nil, err
	}
	described, err := decodeDescribe(data)
	if err != nil {
		inst.close()
		return nil, err
	}
	for _, d := range described {
		inst.languages = append(inst.languages, d.name)
	}
	if !slices.Equal(inst.languages, f.manifest.Languages) {
		inst.close()
		return nil, errModule
	}
	return inst, nil
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
	setup, cancel := context.WithTimeout(ctx, setupDeadline)
	defer cancel()
	inst, err := f.instantiate(setup)
	if err != nil {
		<-f.slots
		return nil, &failure{reason: syntaxanalysis.GapAnalysisUnavailable}
	}
	return inst, nil
}

// release returns a healthy instance to the idle list and closes any other.
func (f *family) release(inst *instance, healthy bool) {
	if healthy && f.analyzer.isClosed() {
		healthy = false
	}
	f.mu.Lock()
	if f.terminating && inst.mode == modeFast {
		healthy = false
	}
	f.mu.Unlock()
	if healthy {
		f.mu.Lock()
		f.idle = append(f.idle, inst)
		f.mu.Unlock()
	} else {
		inst.close()
	}
	<-f.slots
}

func (f *family) analyze(ctx context.Context, language syntaxanalysis.Language, p *pack, content []byte, limits syntaxanalysis.Limits) (analysisResult, []role, *failure) {
	index := slices.Index(f.manifest.Languages, string(language))
	if index < 0 {
		return analysisResult{}, nil, &failure{reason: syntaxanalysis.GapAnalysisFailed}
	}
	inst, fail := f.acquire(ctx)
	if fail != nil {
		return analysisResult{}, nil, fail
	}
	healthy, orphaned := false, false
	defer func() {
		if orphaned {
			<-f.slots
			return
		}
		f.release(inst, healthy)
	}()

	query, err := inst.ensureQuery(ctx, index, p.query)
	if err != nil {
		return analysisResult{}, nil, inst.classify(ctx, ctx, err)
	}
	call, cancel := context.WithTimeout(ctx, limits.FileDeadline)
	defer cancel()
	source, err := inst.write(call, content)
	if err != nil {
		return analysisResult{}, nil, inst.classify(ctx, call, err)
	}
	maxMatches := uint64(min(2*limits.MaxRecords, 1<<21))
	maxRegions := uint64(min(4*limits.MaxErrorRegions, 1<<18))
	pointer, err := f.watch(call, limits.FileDeadline, inst, uint64(index), uint64(source), uint64(len(content)), maxMatches, maxRegions)
	if errors.Is(err, errStalled) {
		orphaned = true
		return analysisResult{}, nil, &failure{reason: syntaxanalysis.GapDeadlineExceeded}
	}
	if err != nil {
		return analysisResult{}, nil, inst.classify(ctx, call, err)
	}
	data, err := inst.result(pointer)
	if err != nil {
		return analysisResult{}, nil, inst.classify(ctx, call, err)
	}
	if _, err := inst.call(call, inst.free, uint64(source)); err != nil {
		return analysisResult{}, nil, inst.classify(ctx, call, err)
	}
	result, status, err := decodeAnalysis(data, query.info, len(content))
	if err == nil && status == statusStopped {
		return analysisResult{}, nil, inst.classify(ctx, call, errStopped)
	}
	if err != nil || status != statusOK {
		return analysisResult{}, nil, &failure{reason: syntaxanalysis.GapAnalysisFailed}
	}
	healthy = inst.memory.Size() <= recycleMemoryBytes
	return result, query.roles, nil
}

// classify maps a failed guest call to a gap. The instance is discarded
// either way, because the caller does not mark it healthy.
func (inst *instance) classify(parent, call context.Context, err error) *failure {
	switch {
	case parent.Err() != nil:
		return &failure{reason: syntaxanalysis.GapAnalysisFailed}
	case errors.Is(call.Err(), context.DeadlineExceeded):
		return &failure{reason: syntaxanalysis.GapDeadlineExceeded}
	case inst.outOfMemory():
		return &failure{reason: syntaxanalysis.GapLimitExceeded, limit: syntaxanalysis.LimitMemory}
	}
	return &failure{reason: syntaxanalysis.GapAnalysisFailed}
}

// outOfMemory reads the flag the shim sets before trapping on a failed
// allocation. It reads memory directly and never calls into the instance.
func (inst *instance) outOfMemory() bool {
	value, ok := inst.memory.ReadUint32Le(inst.failureFlag)
	return ok && value != 0
}

func (inst *instance) close() {
	_ = inst.module.Close(context.Background())
}

// call runs a guest function that returns one 32-bit value.
func (inst *instance) call(ctx context.Context, fn api.Function, params ...uint64) (uint32, error) {
	results, err := fn.Call(ctx, params...)
	if err != nil {
		return 0, err
	}
	if len(results) == 0 {
		return 0, nil
	}
	if len(results) != 1 || results[0] > 0xffffffff {
		return 0, errProtocol
	}
	return uint32(results[0]), nil
}

// write copies data into a fresh guest allocation and returns its address.
func (inst *instance) write(ctx context.Context, data []byte) (uint32, error) {
	pointer, err := inst.call(ctx, inst.alloc, uint64(len(data)))
	if err != nil {
		return 0, err
	}
	if pointer == 0 {
		return 0, errInstance
	}
	if uint64(pointer)+uint64(len(data)) > uint64(inst.memory.Size()) || !inst.memory.Write(pointer, data) {
		return 0, errProtocol
	}
	return pointer, nil
}

// result copies a result buffer out of guest memory after checking that its
// header and its whole declared length lie inside the memory.
func (inst *instance) result(pointer uint32) ([]byte, error) {
	size := uint64(inst.memory.Size())
	if pointer == 0 || uint64(pointer)+8 > size {
		return nil, errProtocol
	}
	header, ok := inst.memory.Read(pointer, 8)
	if !ok {
		return nil, errProtocol
	}
	length := uint64(header[4]) | uint64(header[5])<<8 | uint64(header[6])<<16 | uint64(header[7])<<24
	if length < 8 || length > maxResultBytes || uint64(pointer)+length > size {
		return nil, errProtocol
	}
	view, ok := inst.memory.Read(pointer, uint32(length))
	if !ok {
		return nil, errProtocol
	}
	return slices.Clone(view), nil
}

// ensureQuery compiles the language's query in this instance once.
func (inst *instance) ensureQuery(ctx context.Context, index int, text string) (loadedQuery, error) {
	if q, ok := inst.queries[index]; ok {
		return q, nil
	}
	setup, cancel := context.WithTimeout(ctx, setupDeadline)
	defer cancel()
	pointer, err := inst.write(setup, []byte(text))
	if err != nil {
		return loadedQuery{}, err
	}
	resultPointer, err := inst.call(setup, inst.loadQuery, uint64(index), uint64(pointer), uint64(len(text)))
	if err != nil {
		return loadedQuery{}, err
	}
	data, err := inst.result(resultPointer)
	if err != nil {
		return loadedQuery{}, err
	}
	if _, err := inst.call(setup, inst.free, uint64(pointer)); err != nil {
		return loadedQuery{}, err
	}
	info, err := decodeQueryInfo(data)
	if err != nil {
		return loadedQuery{}, err
	}
	roles, err := captureRoles(info.captures)
	if err != nil {
		return loadedQuery{}, err
	}
	q := loadedQuery{info: info, roles: roles}
	inst.queries[index] = q
	return q, nil
}
