//go:build wasip1

package hostre2

import "unsafe"

// The import module and function names are regexabi.ModuleName and the
// regexabi.Function constants; a directive cannot reference a constant.

//go:wasmimport ot_regex compile
func hostCompile(pattern unsafe.Pointer, length uint32) int32

//go:wasmimport ot_regex find_all
func hostFindAll(handle int32, text unsafe.Pointer, length uint32, limit int32) int32

//go:wasmimport ot_regex read_result
func hostReadResult(out unsafe.Pointer, pairs uint32) int32

//go:wasmimport ot_regex match
func hostMatch(handle int32, text unsafe.Pointer, length uint32) int32

//go:wasmimport ot_regex submatch
func hostSubmatch(handle int32, text unsafe.Pointer, length uint32, out unsafe.Pointer, capacity uint32) int32
