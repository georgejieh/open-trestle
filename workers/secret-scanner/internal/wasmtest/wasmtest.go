// Package wasmtest encodes small WebAssembly modules for tests that need a
// guest which does exactly what the test says, including things a correct
// guest never does.
package wasmtest

import "encoding/binary"

// I32 is the value type byte of i32.
const I32 = 0x7f

// Export kinds.
const (
	ExportFunction = 0x00
	ExportMemory   = 0x02
)

// FunctionType is a function signature as value type bytes.
type FunctionType struct {
	Parameters []byte
	Results    []byte
}

// Import is an imported function of type Type.
type Import struct {
	Module string
	Name   string
	Type   uint32
}

// Function is a defined function. Body is its instruction sequence without
// the final end, and it has no locals.
type Function struct {
	Type uint32
	Body []byte
}

// Export exports a function or the memory by index.
type Export struct {
	Name  string
	Kind  byte
	Index uint32
}

// Data is an active data segment of memory 0.
type Data struct {
	Offset uint32
	Bytes  []byte
}

// Module is a module with one defined memory. Function indices count
// imports first, then defined functions.
type Module struct {
	Types       []FunctionType
	Imports     []Import
	Functions   []Function
	MemoryPages uint32
	Exports     []Export
	Data        []Data
}

// Encode returns the binary form of the module.
func (m Module) Encode() []byte {
	encoded := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}

	var types []byte
	types = appendCount(types, len(m.Types))
	for _, signature := range m.Types {
		types = append(types, 0x60)
		types = appendCount(types, len(signature.Parameters))
		types = append(types, signature.Parameters...)
		types = appendCount(types, len(signature.Results))
		types = append(types, signature.Results...)
	}
	encoded = appendSection(encoded, 1, types)

	var imports []byte
	imports = appendCount(imports, len(m.Imports))
	for _, entry := range m.Imports {
		imports = appendName(imports, entry.Module)
		imports = appendName(imports, entry.Name)
		imports = append(imports, 0x00)
		imports = binary.AppendUvarint(imports, uint64(entry.Type))
	}
	encoded = appendSection(encoded, 2, imports)

	var functions []byte
	functions = appendCount(functions, len(m.Functions))
	for _, function := range m.Functions {
		functions = binary.AppendUvarint(functions, uint64(function.Type))
	}
	encoded = appendSection(encoded, 3, functions)

	memory := appendCount(nil, 1)
	memory = append(memory, 0x00)
	memory = binary.AppendUvarint(memory, uint64(m.MemoryPages))
	encoded = appendSection(encoded, 5, memory)

	var exports []byte
	exports = appendCount(exports, len(m.Exports))
	for _, export := range m.Exports {
		exports = appendName(exports, export.Name)
		exports = append(exports, export.Kind)
		exports = binary.AppendUvarint(exports, uint64(export.Index))
	}
	encoded = appendSection(encoded, 7, exports)

	var code []byte
	code = appendCount(code, len(m.Functions))
	for _, function := range m.Functions {
		body := append([]byte{0x00}, function.Body...)
		body = append(body, 0x0b)
		code = appendCount(code, len(body))
		code = append(code, body...)
	}
	encoded = appendSection(encoded, 10, code)

	var data []byte
	data = appendCount(data, len(m.Data))
	for _, segment := range m.Data {
		data = append(data, 0x00)
		data = append(data, I32Const(int32(segment.Offset))...)
		data = append(data, 0x0b)
		data = appendCount(data, len(segment.Bytes))
		data = append(data, segment.Bytes...)
	}
	return appendSection(encoded, 11, data)
}

// I32Const is the instruction i32.const value, whose immediate is signed
// LEB128.
func I32Const(value int32) []byte {
	encoded := []byte{0x41}
	remaining := int64(value)
	for {
		next := byte(remaining & 0x7f)
		remaining >>= 7
		if remaining == 0 && next&0x40 == 0 || remaining == -1 && next&0x40 != 0 {
			return append(encoded, next)
		}
		encoded = append(encoded, next|0x80)
	}
}

// Call is the instruction call index.
func Call(index uint32) []byte {
	return binary.AppendUvarint([]byte{0x10}, uint64(index))
}

// LocalGet is the instruction local.get index.
func LocalGet(index uint32) []byte {
	return binary.AppendUvarint([]byte{0x20}, uint64(index))
}

// Load8U is the instruction i32.load8_u with alignment 0 and offset.
func Load8U(offset uint32) []byte {
	return binary.AppendUvarint([]byte{0x2d, 0x00}, uint64(offset))
}

// Other instructions.
var (
	Drop        = []byte{0x1a}
	I32Equal    = []byte{0x46}
	IfEmpty     = []byte{0x04, 0x40}
	End         = []byte{0x0b}
	Unreachable = []byte{0x00}
)

// Concat joins instruction sequences.
func Concat(parts ...[]byte) []byte {
	var joined []byte
	for _, part := range parts {
		joined = append(joined, part...)
	}
	return joined
}

func appendSection(encoded []byte, id byte, content []byte) []byte {
	encoded = append(encoded, id)
	encoded = appendCount(encoded, len(content))
	return append(encoded, content...)
}

func appendCount(encoded []byte, count int) []byte {
	return binary.AppendUvarint(encoded, uint64(count))
}

func appendName(encoded []byte, name string) []byte {
	encoded = appendCount(encoded, len(name))
	return append(encoded, name...)
}
