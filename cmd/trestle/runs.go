package main

import (
	"bytes"
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
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/webhook"
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
	case "refusal":
		return runRemoteScopeOperation("refusal", args[1:], stdout, stderr)
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
	// The canonical plan has no terminal newline, but files written by editors
	// and shell redirection end with one. Accept exactly one; the client
	// re-encodes the parsed plan before sending.
	plan, err := controlplane.ParseReviewRunPlan(bytes.TrimSuffix(encoded, []byte("\n")))
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
	format := flags.String("format", "run", "status output: run, progress, json, or sarif")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || *tenantID == "" || *repositoryID == "" || *runID == "" || (*format != "run" && (*format != "progress" && *format != "json" && *format != "sarif" || operation != "status")) || (operation == "refusal" && *format != "run") {
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
	if operation == "refusal" {
		refusal, refusalErr := apiClient.GetDeliveryRefusal(ctx, scope)
		if refusalErr != nil {
			fmt.Fprintf(stderr, "runs refusal: %v\n", refusalErr)
			return 1
		}
		encoded, encodeErr := webhook.EncodeRefusalRecord(refusal)
		if encodeErr != nil {
			fmt.Fprintln(stderr, "runs refusal: encode refusal failed")
			return 1
		}
		if _, writeErr := stdout.Write(append(encoded, '\n')); writeErr != nil {
			fmt.Fprintln(stderr, "runs refusal: write refusal failed")
			return 1
		}
		return 0
	}
	if operation == "status" && *format == "progress" {
		progress, progressErr := apiClient.GetRunProgress(ctx, scope)
		if progressErr != nil {
			fmt.Fprintf(stderr, "runs status: %v\n", progressErr)
			return 1
		}
		return writeJSONResult(progress, stdout, stderr, 0)
	}
	var receipt controlplane.ReviewRunReceipt
	if operation == "status" {
		receipt, err = apiClient.GetRun(ctx, scope)
	} else {
		receipt, err = apiClient.CancelRun(ctx, scope)
	}
	if err != nil {
		fmt.Fprintf(stderr, "runs %s: %v\n", operation, err)
		var apiErr *client.APIError
		if operation == "status" && errors.As(err, &apiErr) && apiErr.Code() == "not_found" {
			if refusal, refusalErr := apiClient.GetDeliveryRefusal(ctx, scope); refusalErr == nil {
				fmt.Fprintf(stderr, "runs status: no run was opened; intake refused the delivery: %s (see trestle runs refusal)\n", refusal.Reason())
			}
		}
		return 1
	}
	if operation == "status" && *format != "run" {
		set, diagnosticErr := apiClient.GetDiagnosticSet(ctx, scope)
		if diagnosticErr != nil {
			fmt.Fprintln(stderr, "runs status: review result is unavailable")
			return 1
		}
		if *format == "json" {
			encoded, encodeErr := diagnostics.EncodeSet(set)
			if encodeErr != nil {
				fmt.Fprintln(stderr, "runs status: encode result failed")
				return 1
			}
			if _, writeErr := stdout.Write(append(encoded, '\n')); writeErr != nil {
				fmt.Fprintln(stderr, "runs status: write result failed")
				return 1
			}
			writeRefusalHint(stderr, setRefusalHint(set))
			return 0
		}
		log, buildErr := buildDiagnosticSetSARIF(set)
		if buildErr != nil {
			fmt.Fprintln(stderr, "runs status: build SARIF failed")
			return 1
		}
		code := writeJSONResult(log, stdout, stderr, 0)
		if code == 0 {
			writeRefusalHint(stderr, setRefusalHint(set))
		}
		return code
	}
	code := writeRemoteReceipt(receipt, stdout, stderr)
	if code == 0 && operation == "status" {
		writeRefusalHint(stderr, receiptRefusalHint(receipt))
	}
	return code
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
	return readRegularBoundedFileWithOpener(path, limit, openRegularInputFileNative)
}

func readRegularBoundedFileWithOpener(path string, limit int64, openFile func(string) (*os.File, error)) ([]byte, error) {
	information, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !information.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}

	file, err := openFile(path)
	if err != nil {
		information, statErr := os.Lstat(path)
		if statErr == nil && !information.Mode().IsRegular() {
			return nil, errors.New("input must be a regular file")
		}
		return nil, err
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	if !os.SameFile(information, opened) {
		return nil, errors.New("input must be an unchanged regular file")
	}
	if opened.Size() > limit {
		return nil, errors.New("input exceeds size limit")
	}

	information, err = os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !information.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	if !os.SameFile(information, opened) {
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
	fmt.Fprintln(stderr, "usage: trestle runs refusal --tenant ID --repository ID --run ID [--server URL]")
}
func writeRunsSubmitUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle runs submit --plan PATH [--server URL]")
}
func writeRunsScopeUsage(stderr io.Writer, operation string) {
	fmt.Fprintf(stderr, "usage: trestle runs %s --tenant ID --repository ID --run ID [--server URL] [--format run|progress|json|sarif]\n", operation)
}
