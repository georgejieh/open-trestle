//go:build !wasip1

package adapter

import (
	"github.com/betterleaks/betterleaks/regexp/re2"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/protocol"
)

// New returns the native adapter, which runs regular expressions with
// Betterleaks' RE2 engine. The WebAssembly guest does not link it, because
// go-re2 cannot run inside a wasip1 guest.
func New() (*Adapter, error) {
	return newWithEngine(re2.RE2{}, "re2", protocol.BuildProfile)
}
