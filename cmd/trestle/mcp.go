package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/mcpserver"
	"io"
	"os"
)

func runMCP(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if stdin == nil || stdout == nil || stderr == nil {
		return 2
	}
	flags := flag.NewFlagSet("trestle mcp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	serverURL := flags.String("server", apiURLFromEnvironment(), "Open Trestle API URL")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		writeMCPUsage(stderr)
		return 2
	}
	credential := os.Getenv("OPEN_TRESTLE_API_TOKEN")
	if credential == "" {
		fmt.Fprintln(stderr, "mcp: OPEN_TRESTLE_API_TOKEN is required")
		return 2
	}
	apiClient, err := client.New(*serverURL, credential, nil)
	if err != nil {
		fmt.Fprintf(stderr, "mcp: %v\n", err)
		return 2
	}
	server, err := mcpserver.New(apiClient)
	if err != nil {
		fmt.Fprintf(stderr, "mcp: %v\n", err)
		return 1
	}
	if err := server.Serve(context.Background(), stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "mcp: %v\n", err)
		return 1
	}
	return 0
}
func writeMCPUsage(stderr io.Writer) { fmt.Fprintln(stderr, "usage: trestle mcp [--server URL]") }
