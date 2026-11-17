// Command open-trestle-scan-helper runs secret scans in the WebAssembly
// guest. The contract is in package scanhelper.
//
// The committed guest.wasm is empty and a helper built from it refuses to
// run. internal/helperbuild builds the guest, substitutes it for guest.wasm
// with a build overlay and pins its SHA-256 with
// -ldflags "-X main.expectedGuestSHA256=<hex>"; use
// go run ./internal/cmd/build-scan-helper -o <directory>.
package main

import (
	_ "embed"
	"os"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/scanhelper"
)

//go:embed guest.wasm
var guestImage []byte

// expectedGuestSHA256 is the hex SHA-256 of guestImage, set at link time.
// The helper checks the embedded guest against it before compiling it.
var expectedGuestSHA256 string

func main() {
	os.Exit(scanhelper.Main(os.Args, guestImage, expectedGuestSHA256))
}
