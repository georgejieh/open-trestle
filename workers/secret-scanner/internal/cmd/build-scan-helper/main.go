// Command build-scan-helper builds the scan guest and a scan helper that
// embeds it. Run it from the scanner module directory:
//
//	go run ./internal/cmd/build-scan-helper -o <directory> [-goos <os> -goarch <arch>]
//
// It writes <directory>/open-trestle-scan-guest.wasm and
// <directory>/open-trestle-scan-helper (with .exe for Windows), built for
// the host unless -goos and -goarch name another target, and prints the
// helper's path.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/helperbuild"
)

func main() {
	host := helperbuild.HostTarget()
	output := flag.String("o", "", "output directory")
	goos := flag.String("goos", host.GOOS, "target operating system")
	goarch := flag.String("goarch", host.GOARCH, "target architecture")
	flag.Parse()
	if *output == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: build-scan-helper -o <directory> [-goos <os> -goarch <arch>]")
		os.Exit(2)
	}
	result, err := helperbuild.Build(context.Background(), ".", *output, helperbuild.Target{GOOS: *goos, GOARCH: *goarch})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(result.Helper)
}
