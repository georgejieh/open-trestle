// Package regexhost is the host side of the regexabi interface. It runs RE2
// (go-re2) over text in a guest's linear memory, for patterns from a pinned
// table only, and refuses every argument outside the interface bounds.
//
// go-re2 runs libre2 as a WebAssembly module whose standard output and error
// are the process's os.Stdout and os.Stderr at the time of the first compile.
// A process that uses this package must point both at the null device before
// the first guest call; the helper process does so at start.
package regexhost

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"sync"

	gore2 "github.com/betterleaks/go-re2"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/regexabi"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Limits are the per-guest-instance budgets. A call beyond either budget is
// refused, and so is every later call of the same instance.
type Limits struct {
	// MaxCalls is the number of host calls one instance may make.
	MaxCalls int64
	// MaxTextBytes is the total number of text and pattern bytes one
	// instance may pass to the host.
	MaxTextBytes int64
}

// DefaultLimits are the budgets the helper uses. A 2 MiB request makes a few
// thousand calls over a few tens of MiB of text; the budgets are three orders
// of magnitude above that and only stop a guest that loops.
var DefaultLimits = Limits{MaxCalls: 1 << 22, MaxTextBytes: 1 << 33}

var errInvalidTable = errors.New("invalid pinned pattern table")

// Table is an immutable set of pattern texts, each compiled on first use and
// shared by every instance that uses the table.
type Table struct {
	patterns []string
	index    map[string]int32
	entries  []tableEntry
}

type tableEntry struct {
	once     sync.Once
	compiled *gore2.Regexp
	err      error
}

// NewTable returns a table of the given patterns. Every pattern must be
// between 1 and regexabi.MaxPatternBytes long, and no pattern may repeat.
func NewTable(patterns []string) (*Table, error) {
	if len(patterns) == 0 || len(patterns) > math.MaxInt32 {
		return nil, errInvalidTable
	}
	table := &Table{
		patterns: append([]string(nil), patterns...),
		index:    make(map[string]int32, len(patterns)),
		entries:  make([]tableEntry, len(patterns)),
	}
	for handle, pattern := range table.patterns {
		if len(pattern) == 0 || len(pattern) > regexabi.MaxPatternBytes {
			return nil, errInvalidTable
		}
		if _, duplicate := table.index[pattern]; duplicate {
			return nil, errInvalidTable
		}
		table.index[pattern] = int32(handle)
	}
	return table, nil
}

// Len returns the number of patterns in the table.
func (t *Table) Len() int { return len(t.patterns) }

// Patterns returns a copy of the pattern texts in handle order.
func (t *Table) Patterns() []string { return append([]string(nil), t.patterns...) }

func (t *Table) compiled(handle int32) (*gore2.Regexp, bool) {
	if handle < 0 || int(handle) >= len(t.entries) {
		return nil, false
	}
	entry := &t.entries[handle]
	entry.once.Do(func() {
		entry.compiled, entry.err = gore2.Compile(t.patterns[handle])
	})
	return entry.compiled, entry.err == nil && entry.compiled != nil
}

// Bridge registers the host functions for one table and one set of limits.
type Bridge struct {
	table  *Table
	limits Limits
}

// NewBridge returns a bridge over table. Both limits must be positive.
func NewBridge(table *Table, limits Limits) (*Bridge, error) {
	if table == nil || limits.MaxCalls <= 0 || limits.MaxTextBytes <= 0 {
		return nil, errInvalidTable
	}
	return &Bridge{table: table, limits: limits}, nil
}

// Session is the state of one guest instance: its budgets, the result of its
// last find_all and whether any of its calls was refused.
type Session struct {
	limits  Limits
	calls   int64
	bytes   int64
	held    bool
	result  []uint32
	refused int64
}

type sessionKey struct{}

// NewSession returns a context that carries a fresh session for one guest
// instance. The guest must be instantiated with that context, because a host
// call finds its session through the context of the call.
func (b *Bridge) NewSession(ctx context.Context) (context.Context, *Session) {
	session := &Session{limits: b.limits}
	return context.WithValue(ctx, sessionKey{}, session), session
}

// Refused reports how many calls of the instance were refused. A guest that
// was refused anything must not be trusted, whatever it did next. It is read
// after the instance has stopped.
func (s *Session) Refused() int64 { return s.refused }

func sessionFrom(ctx context.Context) *Session {
	session, _ := ctx.Value(sessionKey{}).(*Session)
	return session
}

// charge counts one call and its bytes. Once a budget is exceeded the session
// stays exhausted.
func (s *Session) charge(byteCount int) bool {
	s.calls++
	s.bytes += int64(byteCount)
	return s.calls <= s.limits.MaxCalls && s.bytes <= s.limits.MaxTextBytes
}

// guestRange validates [pointer, pointer+length) against the memory using
// 64-bit arithmetic and returns a view of it. The view aliases guest memory
// and is valid only while the guest is blocked in the current call.
func guestRange(memory api.Memory, pointer, length, maximum uint32) ([]byte, bool) {
	if memory == nil || length > maximum {
		return nil, false
	}
	if uint64(pointer)+uint64(length) > uint64(memory.Size()) {
		return nil, false
	}
	if length == 0 {
		return []byte{}, true
	}
	return memory.Read(pointer, length)
}

// writeGuest writes content at pointer after the same range check.
func writeGuest(memory api.Memory, pointer uint32, content []byte) bool {
	if memory == nil || uint64(pointer)+uint64(len(content)) > uint64(memory.Size()) {
		return false
	}
	return memory.Write(pointer, content)
}

type hostCall func(memory api.Memory, session *Session, stack []uint64) int32

// Instantiate registers the regexabi module on runtime. Guests instantiated
// on the runtime afterwards can import it.
func (b *Bridge) Instantiate(ctx context.Context, runtime wazero.Runtime) error {
	i32 := api.ValueTypeI32
	builder := runtime.NewHostModuleBuilder(regexabi.ModuleName)
	export := func(name string, parameters int, call hostCall) {
		types := make([]api.ValueType, parameters)
		for index := range types {
			types[index] = i32
		}
		builder.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, module api.Module, stack []uint64) {
			stack[0] = api.EncodeI32(b.dispatch(ctx, module, stack, call))
		}), types, []api.ValueType{i32}).Export(name)
	}
	export(regexabi.FunctionCompile, 2, b.compile)
	export(regexabi.FunctionFindAll, 4, b.findAll)
	export(regexabi.FunctionReadResult, 2, b.readResult)
	export(regexabi.FunctionMatch, 3, b.match)
	export(regexabi.FunctionSubmatch, 5, b.submatch)
	_, err := builder.Instantiate(ctx)
	return err
}

func (b *Bridge) dispatch(ctx context.Context, module api.Module, stack []uint64, call hostCall) int32 {
	session := sessionFrom(ctx)
	if session == nil {
		return regexabi.ErrNoSession
	}
	result := regexabi.ErrCanceled
	if ctx.Err() == nil {
		result = call(module.Memory(), session, stack)
	}
	if result < 0 {
		session.refused++
		session.held = false
		session.result = session.result[:0]
	}
	return result
}

func (b *Bridge) compile(memory api.Memory, session *Session, stack []uint64) int32 {
	pattern, ok := guestRange(memory, api.DecodeU32(stack[0]), api.DecodeU32(stack[1]), regexabi.MaxPatternBytes)
	if !session.charge(len(pattern)) {
		return regexabi.ErrBudget
	}
	if !ok || len(pattern) == 0 {
		return regexabi.ErrArgument
	}
	handle, known := b.table.index[string(pattern)]
	if !known {
		return regexabi.ErrUnknownPattern
	}
	if _, ok := b.table.compiled(handle); !ok {
		return regexabi.ErrInternal
	}
	return handle
}

func (b *Bridge) findAll(memory api.Memory, session *Session, stack []uint64) int32 {
	text, ok := guestRange(memory, api.DecodeU32(stack[1]), api.DecodeU32(stack[2]), regexabi.MaxTextBytes)
	if !session.charge(len(text)) {
		return regexabi.ErrBudget
	}
	limit := api.DecodeI32(stack[3])
	if !ok || limit != regexabi.UnlimitedMatches && (limit < 1 || limit > regexabi.MaxPairs) {
		return regexabi.ErrArgument
	}
	compiled, ok := b.table.compiled(api.DecodeI32(stack[0]))
	if !ok {
		return regexabi.ErrArgument
	}
	// One more than the bound, so that a text with too many matches is
	// detected instead of silently truncated.
	count := regexabi.MaxPairs + 1
	if limit > 0 {
		count = int(limit)
	}
	found := compiled.FindAllIndex(text, count)
	if len(found) > regexabi.MaxPairs {
		return regexabi.ErrTooManyMatches
	}
	result := session.result[:0]
	for _, pair := range found {
		if len(pair) != 2 || pair[0] < 0 || pair[1] < pair[0] || pair[1] > len(text) {
			return regexabi.ErrInternal
		}
		result = append(result, uint32(pair[0]), uint32(pair[1]))
	}
	session.result = result
	session.held = true
	return int32(len(found))
}

func (b *Bridge) readResult(memory api.Memory, session *Session, stack []uint64) int32 {
	if !session.charge(0) {
		return regexabi.ErrBudget
	}
	pairs := api.DecodeU32(stack[1])
	if !session.held || pairs > regexabi.MaxPairs || uint64(pairs)*2 != uint64(len(session.result)) {
		return regexabi.ErrArgument
	}
	encoded := make([]byte, 4*len(session.result))
	for index, value := range session.result {
		binary.LittleEndian.PutUint32(encoded[4*index:], value)
	}
	if !writeGuest(memory, api.DecodeU32(stack[0]), encoded) {
		return regexabi.ErrArgument
	}
	session.held = false
	session.result = session.result[:0]
	return int32(pairs)
}

func (b *Bridge) match(memory api.Memory, session *Session, stack []uint64) int32 {
	text, ok := guestRange(memory, api.DecodeU32(stack[1]), api.DecodeU32(stack[2]), regexabi.MaxTextBytes)
	if !session.charge(len(text)) {
		return regexabi.ErrBudget
	}
	if !ok {
		return regexabi.ErrArgument
	}
	compiled, ok := b.table.compiled(api.DecodeI32(stack[0]))
	if !ok {
		return regexabi.ErrArgument
	}
	if compiled.Match(text) {
		return 1
	}
	return 0
}

func (b *Bridge) submatch(memory api.Memory, session *Session, stack []uint64) int32 {
	text, ok := guestRange(memory, api.DecodeU32(stack[1]), api.DecodeU32(stack[2]), regexabi.MaxTextBytes)
	if !session.charge(len(text)) {
		return regexabi.ErrBudget
	}
	if !ok {
		return regexabi.ErrArgument
	}
	compiled, ok := b.table.compiled(api.DecodeI32(stack[0]))
	if !ok {
		return regexabi.ErrArgument
	}
	groups := compiled.NumSubexp()
	if groups < 0 || groups > regexabi.MaxGroups || api.DecodeU32(stack[4]) != uint32(2*(groups+1)) {
		return regexabi.ErrArgument
	}
	offsets := compiled.FindSubmatchIndex(text)
	if offsets == nil {
		return 0
	}
	if len(offsets) != 2*(groups+1) {
		return regexabi.ErrInternal
	}
	encoded := make([]byte, 4*len(offsets))
	for index, offset := range offsets {
		if offset < -1 || offset > len(text) {
			return regexabi.ErrInternal
		}
		binary.LittleEndian.PutUint32(encoded[4*index:], uint32(int32(offset)))
	}
	if !writeGuest(memory, api.DecodeU32(stack[3]), encoded) {
		return regexabi.ErrArgument
	}
	return 1
}
