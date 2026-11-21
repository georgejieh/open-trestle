package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/runtimeadmin"
)

type runtimeAdminExecutor func(context.Context, string, string, string, string) (runtimeadmin.Snapshot, error)

func runAdmin(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "runtime" {
		return runRuntimeAdminWithExecutor(args[1:], stdout, stderr, executeRuntimeAdmin)
	}
	if len(args) > 0 && args[0] == "github" {
		return runGitHubAdmin(args[1:], stdout, stderr)
	}
	writeAdminUsage(stderr)
	return 2
}
func runRuntimeAdminWithExecutor(args []string, stdout, stderr io.Writer, execute runtimeAdminExecutor) int {
	if len(args) == 0 || args[0] != "status" || execute == nil {
		writeAdminUsage(stderr)
		return 2
	}
	flags := flag.NewFlagSet("trestle admin runtime status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	serverURL := flags.String("server", apiURLFromEnvironment(), "Open Trestle API URL")
	tenantID := flags.String("tenant", "", "tenant identifier")
	repositoryID := flags.String("repository", "", "repository identifier")
	timeout := flags.Duration("timeout", remoteCommandTimeout, "operation timeout")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *tenantID == "" || *repositoryID == "" || *timeout < time.Second || *timeout > 2*time.Minute {
		writeAdminUsage(stderr)
		return 2
	}
	credential := os.Getenv("OPEN_TRESTLE_API_TOKEN")
	if credential == "" {
		fmt.Fprintln(stderr, "runtime status failed")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	snapshot, err := execute(ctx, *serverURL, credential, *tenantID, *repositoryID)
	if err != nil {
		fmt.Fprintln(stderr, "runtime status failed")
		return 1
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		fmt.Fprintln(stderr, "runtime status failed")
		return 1
	}
	if _, err = stdout.Write(append(encoded, '\n')); err != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}
func executeRuntimeAdmin(ctx context.Context, serverURL, credential, tenantID, repositoryID string) (runtimeadmin.Snapshot, error) {
	apiClient, err := client.New(serverURL, credential, nil)
	if err != nil {
		return runtimeadmin.Snapshot{}, err
	}
	return apiClient.GetRuntimeStatus(ctx, tenantID, repositoryID)
}

func validAdminDigest(value string) bool {
	if len(value) != 64 || value == strings.Repeat("0", 64) || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
func writeAdminUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: trestle admin github permissions identity --api-endpoint URL --api-version YYYY-MM-DD --installation-id ID --repository-full-name OWNER/REPOSITORY")
	fmt.Fprintln(writer, "       trestle admin github permissions identity --broker-config PATH  (configuration-only; no token creation)")
	fmt.Fprintln(writer, "       trestle admin github webhook identity --tenant ID --repository ID --key-id ID")
	fmt.Fprintln(writer, "usage: trestle admin runtime status --tenant ID --repository ID [--server URL] [--timeout DURATION]")
}
