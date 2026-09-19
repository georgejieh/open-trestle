package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/lspserver"
	"io"
	"os"
)

type staticDiagnosticReader struct{ set diagnostics.Set }

func (r staticDiagnosticReader) GetDiagnosticSet(_ context.Context, scope audit.ReviewScope) (diagnostics.Set, error) {
	if scope.Identity() != r.set.Scope().Identity() {
		return diagnostics.Set{}, diagnostics.ErrInvalidSet
	}
	return r.set, nil
}
func runLSP(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if stdin == nil || stdout == nil || stderr == nil {
		return 2
	}
	flags := flag.NewFlagSet("trestle lsp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	diagnosticPath := flags.String("diagnostics", "", "canonical verified diagnostic set file")
	serverURL := flags.String("server", apiURLFromEnvironment(), "Open Trestle API URL")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		writeLSPUsage(stderr)
		return 2
	}
	var reader lspserver.DiagnosticReader
	if *diagnosticPath != "" {
		encoded, err := readRegularBoundedFile(*diagnosticPath, 1<<20)
		if err != nil {
			fmt.Fprintf(stderr, "lsp: %v\n", err)
			return 1
		}
		set, err := diagnostics.ParseSet(encoded)
		if err != nil {
			fmt.Fprintf(stderr, "lsp: invalid diagnostic set: %v\n", err)
			return 1
		}
		reader = staticDiagnosticReader{set: set}
	} else {
		credential := os.Getenv("OPEN_TRESTLE_API_TOKEN")
		if credential == "" {
			fmt.Fprintln(stderr, "lsp: OPEN_TRESTLE_API_TOKEN is required")
			return 2
		}
		apiClient, err := client.New(*serverURL, credential, nil)
		if err != nil {
			fmt.Fprintf(stderr, "lsp: %v\n", err)
			return 2
		}
		reader = apiClient
	}
	server, err := lspserver.New(reader)
	if err != nil {
		fmt.Fprintf(stderr, "lsp: %v\n", err)
		return 1
	}
	if err := server.Serve(context.Background(), stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "lsp: %v\n", err)
		return 1
	}
	return 0
}
func writeLSPUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle lsp [--diagnostics PATH] [--server URL]")
}
