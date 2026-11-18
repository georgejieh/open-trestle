//go:build !wasip1

package hostre2

import (
	"unsafe"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/regexabi"
)

// Outside a WebAssembly guest there is no host to import from. Every call
// fails, so the engine ends the process; tests replace these functions.
var (
	hostCompile = func(unsafe.Pointer, uint32) int32 { return regexabi.ErrInternal }

	hostFindAll = func(int32, unsafe.Pointer, uint32, int32) int32 { return regexabi.ErrInternal }

	hostReadResult = func(unsafe.Pointer, uint32) int32 { return regexabi.ErrInternal }

	hostMatch = func(int32, unsafe.Pointer, uint32) int32 { return regexabi.ErrInternal }

	hostSubmatch = func(int32, unsafe.Pointer, uint32, unsafe.Pointer, uint32) int32 { return regexabi.ErrInternal }
)
