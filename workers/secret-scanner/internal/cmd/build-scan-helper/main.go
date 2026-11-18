// Command build-scan-helper builds the scan guest and a scan helper that
// embeds it. Run it from the scanner module directory:
//
//	go run ./internal/cmd/build-scan-helper -o <directory>
//
// It writes <directory>/open-trestle-scan-guest.wasm and
// <directory>/open-trestle-scan-helper and prints the helper's path.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/helperbuild"
)

func main() {
	output := flag.String("o", "", "output directory")
	flag.Parse()
	if *output == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: build-scan-helper -o <directory>")
		os.Exit(2)
	}
	result, err := helperbuild.Build(context.Background(), ".", *output)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(result.Helper)
}
