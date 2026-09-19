package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
)

const (
	maxRunPlanFileBytes  = 1 << 20
	defaultAPIURL        = "http://127.0.0.1:8741"
	remoteCommandTimeout = 35 * time.Second
)

func runRemote(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeRunsUsage(stderr)
		return 2
	}
	switch args[0] {
	case "submit":
		return runRemoteSubmit(args[1:], stdout, stderr)
	case "status":
		return runRemoteScopeOperation("status", args[1:], stdout, stderr)
	case "cancel":
		return runRemoteScopeOperation("cancel", args[1:], stdout, stderr)
	default:
		writeRunsUsage(stderr)
		return 2
	}
}
func runRemoteSubmit(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trestle runs submit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	serverURL := flags.String("server", apiURLFromEnvironment(), "Open Trestle API URL")
	planPath := flags.String("plan", "", "canonical review-run plan file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *planPath == "" {
		writeRunsSubmitUsage(stderr)
		return 2
	}
	credential := os.Getenv("OPEN_TRESTLE_API_TOKEN")
	if credential == "" {
		fmt.Fprintln(stderr, "runs submit: OPEN_TRESTLE_API_TOKEN is required")
		return 2
	}
	encoded, err := readRegularBoundedFile(*planPath, maxRunPlanFileBytes)
	if err != nil {
		fmt.Fprintf(stderr, "runs submit: %v\n", err)
		return 1
	}
	plan, err := controlplane.ParseReviewRunPlan(encoded)
	if err != nil {
		fmt.Fprintf(stderr, "runs submit: invalid review run plan: %v\n", err)
		return 1
	}
	apiClient, err := client.New(*serverURL, credential, nil)
	if err != nil {
		fmt.Fprintf(stderr, "runs submit: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), remoteCommandTimeout)
	defer cancel()
	receipt, err := apiClient.SubmitRun(ctx, plan)
	if err != nil {
		fmt.Fprintf(stderr, "runs submit: %v\n", err)
		return 1
	}
	return writeRemoteReceipt(receipt, stdout, stderr)
}
func runRemoteScopeOperation(operation string, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trestle runs "+operation, flag.ContinueOnError)
	flags.SetOutput(stderr)
	serverURL := flags.String("server", apiURLFromEnvironment(), "Open Trestle API URL")
	tenantID := flags.String("tenant", "", "tenant identifier")
	repositoryID := flags.String("repository", "", "repository identifier")
	runID := flags.String("run", "", "review-run identifier")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *tenantID == "" || *repositoryID == "" || *runID == "" {
		writeRunsScopeUsage(stderr, operation)
		return 2
	}
	credential := os.Getenv("OPEN_TRESTLE_API_TOKEN")
	if credential == "" {
		fmt.Fprintf(stderr, "runs %s: OPEN_TRESTLE_API_TOKEN is required\n", operation)
		return 2
	}
	scope, err := audit.NewReviewScope(*tenantID, *repositoryID, *runID)
	if err != nil {
		fmt.Fprintf(stderr, "runs %s: invalid review scope: %v\n", operation, err)
		return 2
	}
	apiClient, err := client.New(*serverURL, credential, nil)
	if err != nil {
		fmt.Fprintf(stderr, "runs %s: %v\n", operation, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), remoteCommandTimeout)
	defer cancel()
	var receipt controlplane.ReviewRunReceipt
	if operation == "status" {
		receipt, err = apiClient.GetRun(ctx, scope)
	} else {
		receipt, err = apiClient.CancelRun(ctx, scope)
	}
	if err != nil {
		fmt.Fprintf(stderr, "runs %s: %v\n", operation, err)
		return 1
	}
	return writeRemoteReceipt(receipt, stdout, stderr)
}
func writeRemoteReceipt(receipt controlplane.ReviewRunReceipt, stdout, stderr io.Writer) int {
	encoded, err := controlplane.EncodeReviewRunReceipt(receipt)
	if err != nil {
		fmt.Fprintf(stderr, "encode run receipt: %v\n", err)
		return 1
	}
	if _, err := stdout.Write(append(encoded, '\n')); err != nil {
		fmt.Fprintf(stderr, "write run receipt: %v\n", err)
		return 1
	}
	return 0
}
func readRegularBoundedFile(path string, limit int64) ([]byte, error) {
	information, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !information.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	if information.Size() > limit {
		return nil, errors.New("input exceeds size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(information, opened) {
		return nil, errors.New("input must be an unchanged regular file")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(encoded)) > limit {
		return nil, errors.New("input exceeds size limit")
	}
	return encoded, nil
}
func apiURLFromEnvironment() string {
	if value := os.Getenv("OPEN_TRESTLE_API_URL"); value != "" {
		return value
	}
	return defaultAPIURL
}
func writeRunsUsage(stderr io.Writer) {
	writeRunsSubmitUsage(stderr)
	writeRunsScopeUsage(stderr, "status")
	writeRunsScopeUsage(stderr, "cancel")
}
func writeRunsSubmitUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle runs submit --plan PATH [--server URL]")
}
func writeRunsScopeUsage(stderr io.Writer, operation string) {
	fmt.Fprintf(stderr, "usage: trestle runs %s --tenant ID --repository ID --run ID [--server URL]\n", operation)
}
