package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/georgejieh/open-trestle/acpserver"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"io"
	"os"
)

func runACP(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if stdin == nil || stdout == nil || stderr == nil {
		return 2
	}
	flags := flag.NewFlagSet("trestle acp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	serverURL := flags.String("server", apiURLFromEnvironment(), "Open Trestle API URL")
	tenantID := flags.String("tenant", "", "tenant identifier")
	repositoryID := flags.String("repository", "", "repository identifier")
	runID := flags.String("run", "", "review-run identifier")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *tenantID == "" || *repositoryID == "" || *runID == "" {
		writeACPUsage(stderr)
		return 2
	}
	credential := os.Getenv("OPEN_TRESTLE_API_TOKEN")
	if credential == "" {
		fmt.Fprintln(stderr, "acp: OPEN_TRESTLE_API_TOKEN is required")
		return 2
	}
	scope, err := audit.NewReviewScope(*tenantID, *repositoryID, *runID)
	if err != nil {
		fmt.Fprintf(stderr, "acp: invalid review scope: %v\n", err)
		return 2
	}
	apiClient, err := client.New(*serverURL, credential, nil)
	if err != nil {
		fmt.Fprintf(stderr, "acp: %v\n", err)
		return 2
	}
	server, err := acpserver.New(apiClient, scope)
	if err != nil {
		fmt.Fprintf(stderr, "acp: %v\n", err)
		return 1
	}
	if err := server.Serve(context.Background(), stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "acp: %v\n", err)
		return 1
	}
	return 0
}
func writeACPUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle acp --tenant ID --repository ID --run ID [--server URL]")
}
