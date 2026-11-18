package syntaxwasm

import (
	"context"
	"errors"
	"maps"
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
	// image is the memory of an instance that compiled queries and analysed
	// nothing; new instances start from it instead of compiling again.
	image *memoryImage
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
	// pristine is true until the instance first sees repository content;
	// only then may its memory become the family's image.
	pristine bool
}

type loadedQuery struct {
	info  queryInfo
	roles []role
}

// imagePageBytes is the unit in which memory images are stored; pages of
// zeros are left out.
const imagePageBytes = 64 << 10

// memoryImage is a copy of an instance's linear memory after it compiled
// the queries in queries. Compiled queries live in the guest heap, so an
// instance whose memory is replaced by the image has them too. The image
// holds only state derived from the module and the project's own queries,
// never repository content.
type memoryImage struct {
	size    uint32
	pages   map[uint32][]byte
	queries map[int]loadedQuery
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
	image := f.image
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
		queries:  map[int]loadedQuery{},
		pristine: true,
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
	if image != nil && !inst.restore(image) {
		inst.close()
		return nil, errInstance
	}
	return inst, nil
}

// restore replaces the memory of a fresh instance with the image. The
// stack pointer and the other mutable globals hold the same values in
// every instance between calls, so the memory is the whole state that
// differs.
func (inst *instance) restore(image *memoryImage) bool {
	size := inst.memory.Size()
	if size > image.size {
		return false
	}
	if size < image.size {
		if _, ok := inst.memory.Grow((image.size - size) / imagePageBytes); !ok || inst.memory.Size() != image.size {
			return false
		}
	}
	zero := make([]byte, imagePageBytes)
	for at := uint32(0); at < image.size; at += imagePageBytes {
		page, ok := image.pages[at]
		if !ok {
			current, ok := inst.memory.Read(at, imagePageBytes)
			if !ok {
				return false
			}
			if allZero(current) {
				continue
			}
			page = zero
		}
		if !inst.memory.Write(at, page) {
			return false
		}
	}
	inst.queries = maps.Clone(image.queries)
	return true
}

// snapshot copies the memory of a pristine instance into an image.
func (inst *instance) snapshot() (*memoryImage, bool) {
	size := inst.memory.Size()
	if !inst.pristine || size%imagePageBytes != 0 {
		return nil, false
	}
	image := &memoryImage{size: size, pages: map[uint32][]byte{}, queries: maps.Clone(inst.queries)}
	for at := uint32(0); at < size; at += imagePageBytes {
		view, ok := inst.memory.Read(at, imagePageBytes)
		if !ok {
			return nil, false
		}
		if !allZero(view) {
			image.pages[at] = slices.Clone(view)
		}
	}
	return image, true
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
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

func (f *family) imageHas(index int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.image == nil {
		return false
	}
	_, ok := f.image.queries[index]
	return ok
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
		switch {
		case orphaned:
			<-f.slots
		case inst == nil:
			<-f.slots
		default:
			f.release(inst, healthy)
		}
	}()

	inst, query, err := f.prepare(ctx, inst, index, p.query)
	if inst == nil {
		return analysisResult{}, nil, &failure{reason: syntaxanalysis.GapAnalysisUnavailable}
	}
	if err != nil {
		return analysisResult{}, nil, inst.classify(ctx, ctx, err)
	}
	inst.pristine = false
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
