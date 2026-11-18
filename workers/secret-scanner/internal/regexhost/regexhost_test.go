package regexhost

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"strings"
	"testing"

	gore2 "github.com/betterleaks/go-re2"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/regexabi"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/wasmtest"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const (
	memoryPages = 32
	memoryBytes = memoryPages * 65536
	patternAt   = 0x100
	textAt      = 0x10000
	outputAt    = 0x100000
)

var testPatterns = []string{"a", "(a)(b)(c)", "x*", "secret-[0-9]+"}

const (
	handleA = iota
	handleGroups
	handleEmpty
	handleSecret
)

// probeModule imports every regexabi function and exports a wrapper with the
// same signature, so a test can call the host with any argument at all.
func probeModule() []byte {
	type function struct {
		name       string
		parameters int
	}
	functions := []function{
		{regexabi.FunctionCompile, 2},
		{regexabi.FunctionFindAll, 4},
		{regexabi.FunctionReadResult, 2},
		{regexabi.FunctionMatch, 3},
		{regexabi.FunctionSubmatch, 5},
	}
	module := wasmtest.Module{MemoryPages: memoryPages}
	for index, entry := range functions {
		module.Types = append(module.Types, wasmtest.FunctionType{
			Parameters: bytes.Repeat([]byte{wasmtest.I32}, entry.parameters),
			Results:    []byte{wasmtest.I32},
		})
		module.Imports = append(module.Imports, wasmtest.Import{Module: regexabi.ModuleName, Name: entry.name, Type: uint32(index)})
	}
	for index, entry := range functions {
		var body []byte
		for parameter := range entry.parameters {
			body = append(body, wasmtest.LocalGet(uint32(parameter))...)
		}
		body = append(body, wasmtest.Call(uint32(index))...)
		module.Functions = append(module.Functions, wasmtest.Function{Type: uint32(index), Body: body})
		module.Exports = append(module.Exports, wasmtest.Export{Name: entry.name, Kind: wasmtest.ExportFunction, Index: uint32(len(functions) + index)})
	}
	module.Exports = append(module.Exports, wasmtest.Export{Name: "memory", Kind: wasmtest.ExportMemory})
	return module.Encode()
}

type probe struct {
	t       *testing.T
	module  api.Module
	memory  api.Memory
	ctx     context.Context
	session *Session
}

func newProbe(t *testing.T, limits Limits) *probe {
	t.Helper()
	ctx := context.Background()
	table, err := NewTable(testPatterns)
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := NewBridge(table, limits)
	if err != nil {
		t.Fatal(err)
	}
	runtime := wazero.NewRuntime(ctx)
	t.Cleanup(func() { _ = runtime.Close(ctx) })
	if err := bridge.Instantiate(ctx, runtime); err != nil {
		t.Fatal(err)
	}
	sessionContext, session := bridge.NewSession(ctx)
	module, err := runtime.InstantiateWithConfig(sessionContext, probeModule(), wazero.NewModuleConfig().WithName(""))
	if err != nil {
		t.Fatal(err)
	}
	return &probe{t: t, module: module, memory: module.Memory(), ctx: sessionContext, session: session}
}

func (p *probe) call(name string, arguments ...uint64) int32 {
	p.t.Helper()
	results, err := p.module.ExportedFunction(name).Call(p.ctx, arguments...)
	if err != nil {
		p.t.Fatalf("%s: %v", name, err)
	}
	return api.DecodeI32(results[0])
}

func (p *probe) snapshot() []byte {
	content, ok := p.memory.Read(0, p.memory.Size())
	if !ok {
		p.t.Fatal("memory read failed")
	}
	return append([]byte(nil), content...)
}

// refused calls name and requires the result code and an unchanged guest
// memory.
func (p *probe) refused(want int32, name string, arguments ...uint64) {
	p.t.Helper()
	before := p.snapshot()
	refusedBefore := p.session.Refused()
	if got := p.call(name, arguments...); got != want {
		p.t.Fatalf("%s%v = %d, want %d", name, arguments, got, want)
	}
	if !bytes.Equal(before, p.snapshot()) {
		p.t.Fatalf("%s%v changed guest memory", name, arguments)
	}
	if p.session.Refused() != refusedBefore+1 {
		p.t.Fatalf("%s%v was not counted as refused", name, arguments)
	}
}

func (p *probe) write(offset uint32, content []byte) {
	p.t.Helper()
	if !p.memory.Write(offset, content) {
		p.t.Fatal("memory write failed")
	}
}

func u32(value uint32) uint64 { return api.EncodeU32(value) }
func i32(value int32) uint64  { return api.EncodeI32(value) }

func (p *probe) compile(pattern string) int32 {
	p.t.Helper()
	p.write(patternAt, []byte(pattern))
	return p.call(regexabi.FunctionCompile, u32(patternAt), u32(uint32(len(pattern))))
}

func (p *probe) text(content string) (uint64, uint64) {
	p.t.Helper()
	p.write(textAt, []byte(content))
	return u32(textAt), u32(uint32(len(content)))
}

func TestCompileRefusesUnpinnedAndOutOfBoundsPatterns(t *testing.T) {
	p := newProbe(t, DefaultLimits)
	p.write(patternAt, []byte("(a+)+$"))
	p.refused(regexabi.ErrUnknownPattern, regexabi.FunctionCompile, u32(patternAt), u32(6))
	for _, arguments := range [][2]uint32{
		{patternAt, 0},
		{patternAt, regexabi.MaxPatternBytes + 1},
		{patternAt, math.MaxUint32},
		{memoryBytes, 1},
		{memoryBytes - 1, 2},
		{math.MaxUint32 - 8, 32},
		{math.MaxUint32, math.MaxUint32},
	} {
		p.refused(regexabi.ErrArgument, regexabi.FunctionCompile, u32(arguments[0]), u32(arguments[1]))
	}
	for handle, pattern := range testPatterns {
		if got := p.compile(pattern); got != int32(handle) {
			t.Fatalf("compile(%q) = %d, want %d", pattern, got, handle)
		}
	}
	if p.session.Refused() != 8 {
		t.Fatalf("refused %d calls, want 8", p.session.Refused())
	}
}

func TestFindAllAndReadResultEnforceBoundsAndExactCapacity(t *testing.T) {
	p := newProbe(t, DefaultLimits)
	pointer, length := p.text("aaa")
	for _, handle := range []int32{-1, int32(len(testPatterns)), 1 << 30, math.MinInt32} {
		p.refused(regexabi.ErrArgument, regexabi.FunctionFindAll, i32(handle), pointer, length, i32(-1))
	}
	for _, span := range [][2]uint32{
		{memoryBytes, 1},
		{memoryBytes - 2, 3},
		{math.MaxUint32 - 1, 4},
		{textAt, regexabi.MaxTextBytes + 1},
		{textAt, math.MaxUint32},
	} {
		p.refused(regexabi.ErrArgument, regexabi.FunctionFindAll, i32(handleA), u32(span[0]), u32(span[1]), i32(-1))
	}
	for _, limit := range []int32{0, -2, -5, math.MinInt32, regexabi.MaxPairs + 1, 1 << 30} {
		p.refused(regexabi.ErrArgument, regexabi.FunctionFindAll, i32(handleA), pointer, length, i32(limit))
	}

	p.refused(regexabi.ErrArgument, regexabi.FunctionReadResult, u32(outputAt), u32(0))
	p.refused(regexabi.ErrArgument, regexabi.FunctionReadResult, u32(outputAt), u32(3))

	for _, wrong := range []uint32{0, 2, 4, regexabi.MaxPairs + 1, math.MaxUint32} {
		if got := p.call(regexabi.FunctionFindAll, i32(handleA), pointer, length, i32(-1)); got != 3 {
			t.Fatalf("find_all = %d, want 3", got)
		}
		p.refused(regexabi.ErrArgument, regexabi.FunctionReadResult, u32(outputAt), u32(wrong))
	}
	for _, destination := range []uint32{memoryBytes - 23, memoryBytes, math.MaxUint32 - 7} {
		if got := p.call(regexabi.FunctionFindAll, i32(handleA), pointer, length, i32(-1)); got != 3 {
			t.Fatalf("find_all = %d, want 3", got)
		}
		p.refused(regexabi.ErrArgument, regexabi.FunctionReadResult, u32(destination), u32(3))
	}

	if got := p.call(regexabi.FunctionFindAll, i32(handleA), pointer, length, i32(-1)); got != 3 {
		t.Fatalf("find_all = %d, want 3", got)
	}
	sentinel := bytes.Repeat([]byte{0xa5}, 64)
	p.write(outputAt-64, sentinel)
	p.write(outputAt+24, sentinel)
	if got := p.call(regexabi.FunctionReadResult, u32(outputAt), u32(3)); got != 3 {
		t.Fatalf("read_result = %d, want 3", got)
	}
	written, _ := p.memory.Read(outputAt-64, 64+24+64)
	want := append(append([]byte(nil), sentinel...), make([]byte, 24)...)
	for index, value := range []uint32{0, 1, 1, 2, 2, 3} {
		binary.LittleEndian.PutUint32(want[64+4*index:], value)
	}
	want = append(want, sentinel...)
	if !bytes.Equal(written, want) {
		t.Fatalf("read_result wrote %x, want %x", written, want)
	}
	p.refused(regexabi.ErrArgument, regexabi.FunctionReadResult, u32(outputAt), u32(3))

	if got := p.call(regexabi.FunctionFindAll, i32(handleA), pointer, length, i32(2)); got != 2 {
		t.Fatalf("find_all with limit 2 = %d", got)
	}
	if got := p.call(regexabi.FunctionFindAll, i32(handleSecret), pointer, length, i32(-1)); got != 0 {
		t.Fatalf("find_all without matches = %d", got)
	}
	if got := p.call(regexabi.FunctionFindAll, i32(handleA), u32(textAt), u32(0), i32(-1)); got != 0 {
		t.Fatalf("find_all over empty text = %d", got)
	}
	p.refused(regexabi.ErrArgument, regexabi.FunctionFindAll, i32(handleA), u32(math.MaxUint32), u32(0), i32(-1))
}

func TestFindAllRefusesTooManyMatchesAndDropsTheResult(t *testing.T) {
	p := newProbe(t, DefaultLimits)
	pointer, length := p.text(strings.Repeat("a", regexabi.MaxTextBytes))
	for _, handle := range []int32{handleA, handleEmpty} {
		if got := p.call(regexabi.FunctionFindAll, i32(handleSecret), pointer, length, i32(-1)); got != 0 {
			t.Fatalf("find_all = %d", got)
		}
		p.refused(regexabi.ErrTooManyMatches, regexabi.FunctionFindAll, i32(handle), pointer, length, i32(-1))
		p.refused(regexabi.ErrArgument, regexabi.FunctionReadResult, u32(outputAt), u32(0))
	}
	if got := p.call(regexabi.FunctionFindAll, i32(handleA), pointer, length, i32(regexabi.MaxPairs)); got != regexabi.MaxPairs {
		t.Fatalf("find_all at the bound = %d", got)
	}
}

func TestMatchAndSubmatchEnforceBoundsAndExactCapacity(t *testing.T) {
	p := newProbe(t, DefaultLimits)
	pointer, length := p.text("xxabcxx")
	for _, handle := range []int32{-1, int32(len(testPatterns)), 1 << 30} {
		p.refused(regexabi.ErrArgument, regexabi.FunctionMatch, i32(handle), pointer, length)
		p.refused(regexabi.ErrArgument, regexabi.FunctionSubmatch, i32(handle), pointer, length, u32(outputAt), u32(8))
	}
	for _, span := range [][2]uint32{{memoryBytes, 1}, {math.MaxUint32 - 1, 4}, {textAt, regexabi.MaxTextBytes + 1}} {
		p.refused(regexabi.ErrArgument, regexabi.FunctionMatch, i32(handleA), u32(span[0]), u32(span[1]))
		p.refused(regexabi.ErrArgument, regexabi.FunctionSubmatch, i32(handleGroups), u32(span[0]), u32(span[1]), u32(outputAt), u32(8))
	}
	for _, capacity := range []uint32{0, 7, 9, 2, math.MaxUint32} {
		p.refused(regexabi.ErrArgument, regexabi.FunctionSubmatch, i32(handleGroups), pointer, length, u32(outputAt), u32(capacity))
	}
	for _, destination := range []uint32{memoryBytes - 31, memoryBytes, math.MaxUint32 - 3} {
		p.refused(regexabi.ErrArgument, regexabi.FunctionSubmatch, i32(handleGroups), pointer, length, u32(destination), u32(8))
	}
	if got := p.call(regexabi.FunctionMatch, i32(handleA), pointer, length); got != 1 {
		t.Fatalf("match = %d", got)
	}
	if got := p.call(regexabi.FunctionMatch, i32(handleSecret), pointer, length); got != 0 {
		t.Fatalf("match without a match = %d", got)
	}

	sentinel := bytes.Repeat([]byte{0x5a}, 64)
	p.write(outputAt-64, sentinel)
	p.write(outputAt, make([]byte, 32))
	p.write(outputAt+32, sentinel)
	before := p.snapshot()
	nonePointer, noneLength := u32(textAt+2), u32(1)
	if got := p.call(regexabi.FunctionSubmatch, i32(handleGroups), nonePointer, noneLength, u32(outputAt), u32(8)); got != 0 {
		t.Fatalf("submatch without a match = %d", got)
	}
	if !bytes.Equal(before, p.snapshot()) {
		t.Fatal("submatch without a match wrote guest memory")
	}
	if got := p.call(regexabi.FunctionSubmatch, i32(handleGroups), pointer, length, u32(outputAt), u32(8)); got != 1 {
		t.Fatalf("submatch = %d", got)
	}
	written, _ := p.memory.Read(outputAt-64, 64+32+64)
	want := append(append([]byte(nil), sentinel...), make([]byte, 32)...)
	for index, value := range []int32{2, 5, 2, 3, 3, 4, 4, 5} {
		binary.LittleEndian.PutUint32(want[64+4*index:], uint32(value))
	}
	want = append(want, sentinel...)
	if !bytes.Equal(written, want) {
		t.Fatalf("submatch wrote %x, want %x", written, want)
	}
	if p.session.Refused() == 0 {
		t.Fatal("refusals were not counted")
	}
}

func TestCallAndByteBudgetsStopTheInstance(t *testing.T) {
	p := newProbe(t, Limits{MaxCalls: 5, MaxTextBytes: 1 << 20})
	pointer, length := p.text("a")
	for range 5 {
		if got := p.call(regexabi.FunctionMatch, i32(handleA), pointer, length); got != 1 {
			t.Fatalf("match within budget = %d", got)
		}
	}
	p.refused(regexabi.ErrBudget, regexabi.FunctionMatch, i32(handleA), pointer, length)
	p.refused(regexabi.ErrBudget, regexabi.FunctionCompile, u32(patternAt), u32(1))
	p.refused(regexabi.ErrBudget, regexabi.FunctionReadResult, u32(outputAt), u32(0))

	p = newProbe(t, Limits{MaxCalls: 100, MaxTextBytes: 10})
	pointer, length = p.text("aaaaaaaa")
	if got := p.call(regexabi.FunctionMatch, i32(handleA), pointer, length); got != 1 {
		t.Fatalf("match within byte budget = %d", got)
	}
	p.refused(regexabi.ErrBudget, regexabi.FunctionFindAll, i32(handleA), pointer, length, i32(-1))
	p.refused(regexabi.ErrBudget, regexabi.FunctionMatch, i32(handleA), pointer, u32(0))
}

func TestCallsWithoutSessionOrAfterCancellationAreRefused(t *testing.T) {
	p := newProbe(t, DefaultLimits)
	pointer, length := p.text("a")
	results, err := p.module.ExportedFunction(regexabi.FunctionMatch).Call(context.Background(), i32(handleA), pointer, length)
	if err != nil || api.DecodeI32(results[0]) != regexabi.ErrNoSession {
		t.Fatalf("call without session = %v, %v", results, err)
	}
	canceled, cancel := context.WithCancel(p.ctx)
	cancel()
	results, err = p.module.ExportedFunction(regexabi.FunctionMatch).Call(canceled, i32(handleA), pointer, length)
	if err != nil || api.DecodeI32(results[0]) != regexabi.ErrCanceled {
		t.Fatalf("call after cancellation = %v, %v", results, err)
	}
	if p.session.Refused() != 1 {
		t.Fatalf("refused %d, want 1", p.session.Refused())
	}
}

func TestSessionsAreIndependent(t *testing.T) {
	table, err := NewTable(testPatterns)
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := NewBridge(table, Limits{MaxCalls: 1, MaxTextBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, first := bridge.NewSession(context.Background())
	_, second := bridge.NewSession(context.Background())
	if !first.charge(1) || first.charge(0) || !second.charge(1) {
		t.Fatal("budgets are shared between sessions")
	}
}

func TestTableAndBridgeRejectInvalidConfiguration(t *testing.T) {
	for name, patterns := range map[string][]string{
		"empty table":       nil,
		"empty pattern":     {"a", ""},
		"duplicate pattern": {"a", "a"},
		"oversized pattern": {strings.Repeat("a", regexabi.MaxPatternBytes+1)},
	} {
		if _, err := NewTable(patterns); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	table, err := NewTable([]string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	for _, limits := range []Limits{{}, {MaxCalls: 1}, {MaxTextBytes: 1}, {MaxCalls: -1, MaxTextBytes: 1}} {
		if _, err := NewBridge(table, limits); err == nil {
			t.Errorf("limits %+v accepted", limits)
		}
	}
	if _, err := NewBridge(nil, DefaultLimits); err == nil {
		t.Error("nil table accepted")
	}
}

func TestPinnedTableIsTheVerifiedEmbeddedFile(t *testing.T) {
	table, err := PinnedTable()
	if err != nil {
		t.Fatal(err)
	}
	if table.Len() != 510 {
		t.Fatalf("pinned table has %d patterns, want 510", table.Len())
	}
	if _, pinned := table.index["(a+)+$"]; pinned {
		t.Fatal("pinned table holds a pattern outside the ruleset")
	}
	for _, tampered := range [][]byte{
		append(append([]byte(nil), pinnedPatternsJSON...), ' '),
		bytes.Replace(pinnedPatternsJSON, []byte(`"`), []byte(`'`), 1),
		[]byte(`["b","a"]`),
	} {
		if _, err := decodePinnedPatterns(tampered); err == nil {
			t.Fatal("tampered table accepted")
		}
	}
	for _, pattern := range table.Patterns() {
		compiled, err := gore2.Compile(pattern)
		if err != nil {
			t.Fatalf("pinned pattern does not compile with RE2: %v", err)
		}
		if compiled.NumSubexp() > regexabi.MaxGroups {
			t.Fatalf("pinned pattern has %d groups, more than submatch reports", compiled.NumSubexp())
		}
	}
}
