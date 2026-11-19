//go:build !wasip1

package adapter

import "github.com/betterleaks/betterleaks/regexp/re2"

// New returns the native reference adapter, which runs regular expressions
// with Betterleaks' RE2 engine. No shipped program uses it: tests compare the
// scan helper's results against it, so its responses carry the helper's
// build profile and must equal the helper's field for field. The WebAssembly
// guest does not link it, because go-re2 cannot run inside a wasip1 guest.
func New() (*Adapter, error) {
	return newWithEngine(re2.RE2{}, "re2", internalScanDeadline)
}
