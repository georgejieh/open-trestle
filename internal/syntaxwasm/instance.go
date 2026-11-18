package syntaxwasm

import (
	"context"
	"errors"
	"slices"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// instance is one module instance. It is used by one goroutine at a time.
type instance struct {
	module      api.Module
	memory      api.Memory
	alloc, free api.Function
	loadQuery   api.Function
	analyze     api.Function
	failureFlag uint32
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

// newInstance instantiates a compiled family module and checks its exports,
// its ABI version and the languages it describes.
func newInstance(ctx context.Context, runtime wazero.Runtime, compiled wazero.CompiledModule, mode int, languages []string) (*instance, error) {
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
	if err := inst.check(ctx, languages); err != nil {
		inst.close()
		return nil, err
	}
	return inst, nil
}

func (inst *instance) check(ctx context.Context, languages []string) error {
	m := inst.module
	abi, describe, flag := m.ExportedFunction("ot_abi_version"), m.ExportedFunction("ot_describe"), m.ExportedFunction("ot_failure_flag_address")
	if inst.memory == nil || inst.alloc == nil || inst.free == nil || inst.loadQuery == nil || inst.analyze == nil || abi == nil || describe == nil || flag == nil {
		return errModule
	}
	version, err := inst.call(ctx, abi)
	if err != nil || version != shimABIVersion {
		return errModule
	}
	if inst.failureFlag, err = inst.call(ctx, flag); err != nil || uint64(inst.failureFlag)+4 > uint64(inst.memory.Size()) {
		return errModule
	}
	pointer, err := inst.call(ctx, describe)
	if err != nil {
		return err
	}
	data, err := inst.result(pointer)
	if err != nil {
		return err
	}
	described, err := decodeDescribe(data)
	if err != nil {
		return err
	}
	if !slices.Equal(described, languages) {
		return errModule
	}
	return nil
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
