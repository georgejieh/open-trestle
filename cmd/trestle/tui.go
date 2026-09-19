package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/tui"
)

func runTUI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trestle tui", flag.ContinueOnError)
	flags.SetOutput(stderr)
	serverURL := flags.String("server", apiURLFromEnvironment(), "Open Trestle API URL")
	tenantID := flags.String("tenant", "", "tenant identifier")
	repositoryID := flags.String("repository", "", "repository identifier")
	runID := flags.String("run", "", "review-run identifier")
	refresh := flags.Duration("refresh", 2*time.Second, "refresh interval")
	width := flags.Int("width", 100, "display width")
	plain := flags.Bool("plain", defaultPlainTerminalOutput(stdout), "disable terminal control sequences")
	once := flags.Bool("once", false, "render one snapshot and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *tenantID == "" || *repositoryID == "" || *runID == "" {
		writeTUIUsage(stderr)
		return 2
	}
	credential := os.Getenv("OPEN_TRESTLE_API_TOKEN")
	if credential == "" {
		fmt.Fprintln(stderr, "tui: OPEN_TRESTLE_API_TOKEN is required")
		return 2
	}
	scope, err := audit.NewReviewScope(*tenantID, *repositoryID, *runID)
	if err != nil {
		fmt.Fprintf(stderr, "tui: invalid review scope: %v\n", err)
		return 2
	}
	apiClient, err := client.New(*serverURL, credential, nil)
	if err != nil {
		fmt.Fprintf(stderr, "tui: %v\n", err)
		return 2
	}
	interface_, err := tui.New(apiClient, stdin, stdout, tui.Options{
		Scope: scope, RefreshInterval: *refresh, Width: *width, Plain: *plain, Once: *once,
	})
	if err != nil {
		fmt.Fprintf(stderr, "tui: %v\n", err)
		return 2
	}
	if err := interface_.Run(context.Background()); err != nil {
		fmt.Fprintf(stderr, "tui: %v\n", err)
		return 1
	}
	return 0
}

func defaultPlainTerminalOutput(output io.Writer) bool {
	file, ok := output.(*os.File)
	if !ok || os.Getenv("TERM") == "dumb" {
		return true
	}
	information, err := file.Stat()
	return err != nil || information.Mode()&os.ModeCharDevice == 0
}

func writeTUIUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle tui --tenant ID --repository ID --run ID [--server URL] [--refresh DURATION] [--width COLUMNS] [--plain] [--once]")
}
