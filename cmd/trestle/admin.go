package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/runtimeadmin"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

type postgresAdminExecutor func(context.Context, string, string, string) (string, error)
type runtimeAdminExecutor func(context.Context, string, string, string, string) (runtimeadmin.Snapshot, error)

func runAdmin(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "runtime" {
		return runRuntimeAdminWithExecutor(args[1:], stdout, stderr, executeRuntimeAdmin)
	}
	if len(args) > 0 && args[0] == "kms" {
		return runKMSAdmin(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "envelope" {
		return runEnvelopeAdmin(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "github" {
		return runGitHubAdmin(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "bundle" {
		return runSignedBundleAdmin(args[1:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "postgres" && args[1] == "rate-limit" && args[2] == "identity" {
		return runPostgresRateLimitAdmin(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "postgres" && args[1] == "reconciliation" && args[2] == "identity" {
		return runPostgresReplicaReconciliationAdmin(args[3:], stdout, stderr)
	}
	return runAdminWithExecutor(args, stdout, stderr, executePostgresAdmin)
}
func runSignedBundleAdmin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "identity" && args[0] != "statement") {
		writeAdminUsage(stderr)
		return 2
	}
	action := args[0]
	flags := flag.NewFlagSet("trestle admin bundle "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	bundleDigest := flags.String("bundle-sha256", "", "exact opaque bundle SHA-256 digest")
	bundleBytes := flags.Uint64("bundle-bytes", 0, "exact opaque bundle byte count")
	publicKey := flags.String("public-key", "", "exact Ed25519 public key as lowercase hexadecimal")
	signature := flags.String("signature", "", "exact Ed25519 signature as lowercase hexadecimal")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || action == "statement" && (*publicKey != "" || *signature != "") {
		writeAdminUsage(stderr)
		return 2
	}
	statement, err := setupcore.EncodeSignedBundleStatement(*bundleDigest, *bundleBytes)
	if err != nil {
		writeAdminUsage(stderr)
		return 2
	}
	if action == "statement" {
		digest := sha256.Sum256(statement)
		result := struct {
			Contract          string `json:"contract"`
			SchemaVersion     int    `json:"schema_version"`
			Status            string `json:"status"`
			Operation         string `json:"operation"`
			StatementBase64   string `json:"statement_base64"`
			StatementIdentity string `json:"statement_identity"`
		}{"open-trestle/signed-bundle-statement-admin-result", 1, "valid", "statement", base64.StdEncoding.EncodeToString(statement), hex.EncodeToString(digest[:])}
		if json.NewEncoder(stdout).Encode(result) != nil {
			fmt.Fprintln(stderr, "write result failed")
			return 1
		}
		return 0
	}
	authority, err := setupcore.SignedBundleAuthorityIdentity(*bundleDigest, *bundleBytes, *publicKey, *signature)
	if err != nil {
		writeAdminUsage(stderr)
		return 2
	}
	result := struct {
		Contract                      string `json:"contract"`
		SchemaVersion                 int    `json:"schema_version"`
		Status                        string `json:"status"`
		Operation                     string `json:"operation"`
		SignedBundleAuthorityIdentity string `json:"signed_bundle_authority_identity"`
	}{"open-trestle/signed-bundle-admin-result", 1, "valid", "identity", authority}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}
func runPostgresReplicaReconciliationAdmin(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trestle admin postgres reconciliation identity", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databaseAuthority := flags.String("database-authority-identity", "", "exact PostgreSQL runtime database authority identity")
	setupRoot := flags.String("setup-root-identity", "", "exact initial setup plan identity")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !validAdminDigest(*databaseAuthority) || !validAdminDigest(*setupRoot) {
		writeAdminUsage(stderr)
		return 2
	}
	authority, err := postgresstore.ReplicaReconciliationConformanceAuthorityIdentity(*databaseAuthority, setupPostgresURLCredentialIdentity(), *setupRoot)
	if err != nil {
		fmt.Fprintln(stderr, "postgres reconciliation administration failed")
		return 1
	}
	result := struct {
		Contract                               string `json:"contract"`
		SchemaVersion                          int    `json:"schema_version"`
		Status                                 string `json:"status"`
		Operation                              string `json:"operation"`
		ReplicaReconciliationAuthorityIdentity string `json:"replica_reconciliation_authority_identity"`
	}{"open-trestle/postgres-replica-reconciliation-admin-result", 1, "valid", "identity", authority}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}

func runPostgresRateLimitAdmin(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trestle admin postgres rate-limit identity", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databaseAuthority := flags.String("database-authority-identity", "", "exact PostgreSQL runtime database authority identity")
	setupRoot := flags.String("setup-root-identity", "", "exact initial setup plan identity")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !validAdminDigest(*databaseAuthority) || !validAdminDigest(*setupRoot) {
		writeAdminUsage(stderr)
		return 2
	}
	authority, err := postgresstore.SharedRateLimitConformanceAuthorityIdentity(*databaseAuthority, setupPostgresURLCredentialIdentity(), *setupRoot)
	runtimeAuthority, runtimeErr := postgresstore.RuntimeAPIRateLimitAuthorityIdentity(*databaseAuthority)
	if err != nil || runtimeErr != nil {
		fmt.Fprintln(stderr, "postgres rate-limit administration failed")
		return 1
	}
	result := struct {
		Contract                          string `json:"contract"`
		SchemaVersion                     int    `json:"schema_version"`
		Status                            string `json:"status"`
		Operation                         string `json:"operation"`
		SharedRateLimitAuthorityIdentity  string `json:"shared_rate_limit_authority_identity"`
		RuntimeRateLimitAuthorityIdentity string `json:"runtime_rate_limit_authority_identity"`
	}{"open-trestle/postgres-rate-limit-admin-result", 1, "valid", "identity", authority, runtimeAuthority}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}

func runAdminWithExecutor(args []string, stdout, stderr io.Writer, execute postgresAdminExecutor) int {
	if len(args) < 2 || args[0] != "postgres" || (args[1] != "verify" && args[1] != "initialize" && args[1] != "identity" && args[1] != "migrate") || execute == nil {
		writeAdminUsage(stderr)
		return 2
	}
	action := args[1]
	flags := flag.NewFlagSet("trestle admin postgres "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	authority := flags.String("authority-identity", "", "expected non-secret publication authority digest")
	expectedReceipt := flags.String("expected-receipt-identity", "", "expected verified publication authority receipt digest")
	timeout := flags.Duration("timeout", time.Minute, "operation timeout")
	if flags.Parse(args[2:]) != nil || flags.NArg() != 0 || *timeout < time.Second || *timeout > 5*time.Minute || (*authority != "" && !validAdminDigest(*authority)) || (action == "initialize" && !validAdminDigest(*authority)) || (*expectedReceipt != "" && (!validAdminDigest(*expectedReceipt) || action != "verify" || *authority == "")) || (action == "identity" || action == "migrate") && (*authority != "" || *expectedReceipt != "") {
		writeAdminUsage(stderr)
		return 2
	}
	environment := "OPEN_TRESTLE_POSTGRES_URL"
	if action == "initialize" || action == "migrate" {
		environment = "OPEN_TRESTLE_POSTGRES_MIGRATION_URL"
	}
	dataSource := os.Getenv(environment)
	if dataSource == "" || len(dataSource) > 4096 || strings.ContainsAny(dataSource, "\x00\r\n") {
		fmt.Fprintln(stderr, "postgres administration failed")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	receipt, err := execute(ctx, action, dataSource, *authority)
	if err == nil {
		validResult := action == "identity" && validAdminDigest(receipt) || action == "migrate" && receipt == "" || action == "verify" && (*authority == "" && receipt == "" || *authority != "" && validAdminDigest(receipt)) || action == "initialize" && validAdminDigest(receipt)
		if !validResult {
			err = postgresstore.ErrInvalidDatabase
		}
	}
	if err == nil && *expectedReceipt != "" && receipt != *expectedReceipt {
		err = postgresstore.ErrPublicationAuthorityMismatch
	}
	if err != nil {
		fmt.Fprintln(stderr, "postgres administration failed")
		return 1
	}
	result := struct {
		Contract                            string `json:"contract"`
		SchemaVersion                       int    `json:"schema_version"`
		Status                              string `json:"status"`
		Operation                           string `json:"operation"`
		DatabaseAuthorityIdentity           string `json:"database_authority_identity,omitempty"`
		PublicationAuthorityReceiptIdentity string `json:"publication_authority_receipt_identity,omitempty"`
	}{Contract: "open-trestle/postgres-admin-result", SchemaVersion: 1, Status: "valid", Operation: action}
	if action == "identity" {
		result.DatabaseAuthorityIdentity = receipt
	} else if action != "migrate" {
		result.PublicationAuthorityReceiptIdentity = receipt
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(true)
	if encoder.Encode(result) != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
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

func executePostgresAdmin(ctx context.Context, operation, dataSource, authority string) (string, error) {
	database, err := postgresstore.Open(ctx, dataSource, postgresstore.PoolOptions{})
	if err != nil {
		return "", err
	}
	defer database.Close()
	switch operation {
	case "migrate":
		if err := postgresstore.ApplyMigrations(ctx, database); err != nil {
			return "", err
		}
		if err := postgresstore.VerifyMigrations(ctx, database); err != nil {
			return "", err
		}
		return "", nil
	case "identity":
		authority, err := postgresstore.VerifyDatabaseStorageAuthority(ctx, database)
		if err != nil {
			return "", err
		}
		return authority.Identity(), nil
	case "verify":
		if err := postgresstore.VerifyMigrations(ctx, database); err != nil {
			return "", err
		}
		if authority == "" {
			return "", nil
		}
		verified, err := postgresstore.VerifyPublicationAuthority(ctx, database, authority)
		if err != nil {
			return "", err
		}
		return verified.Identity(), nil
	case "initialize":
		if err := postgresstore.ApplyMigrations(ctx, database); err != nil {
			return "", err
		}
		if err := postgresstore.VerifyMigrations(ctx, database); err != nil {
			return "", err
		}
		verified, err := postgresstore.InitializePublicationAuthority(ctx, database, authority)
		if err != nil {
			return "", err
		}
		return verified.Identity(), nil
	default:
		return "", postgresstore.ErrInvalidDatabase
	}
}
func validAdminDigest(value string) bool {
	if len(value) != 64 || value == strings.Repeat("0", 64) || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
func writeAdminUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: trestle admin bundle statement --bundle-sha256 HEX64 --bundle-bytes BYTES")
	fmt.Fprintln(writer, "       trestle admin bundle identity --bundle-sha256 HEX64 --bundle-bytes BYTES --public-key HEX64 --signature HEX128")
	fmt.Fprintln(writer, "       trestle admin kms identity --tenant ID --region REGION --key-arn ARN")
	fmt.Fprintln(writer, "usage: trestle admin envelope identity --tenant ID --s3-endpoint URL --s3-region REGION --s3-bucket BUCKET --s3-prefix PREFIX --kms-region REGION --kms-key-arn ARN [--kms-endpoint URL]")
	fmt.Fprintln(writer, "usage: trestle admin github permissions identity --api-endpoint URL --api-version YYYY-MM-DD --installation-id ID --repository-full-name OWNER/REPOSITORY")
	fmt.Fprintln(writer, "       trestle admin github permissions identity --broker-config PATH  (configuration-only; no token creation)")
	fmt.Fprintln(writer, "       trestle admin github webhook identity --tenant ID --repository ID --key-id ID")
	fmt.Fprintln(writer, "usage: trestle admin runtime status --tenant ID --repository ID [--server URL] [--timeout DURATION]")
	fmt.Fprintln(writer, "       trestle admin postgres migrate [--timeout DURATION]")
	fmt.Fprintln(writer, "       trestle admin postgres identity [--timeout DURATION]")
	fmt.Fprintln(writer, "       trestle admin postgres rate-limit identity --database-authority-identity HEX64 --setup-root-identity HEX64")
	fmt.Fprintln(writer, "       trestle admin postgres reconciliation identity --database-authority-identity HEX64 --setup-root-identity HEX64")
	fmt.Fprintln(writer, "       trestle admin postgres verify [--authority-identity HEX64] [--expected-receipt-identity HEX64] [--timeout DURATION]")
	fmt.Fprintln(writer, "       trestle admin postgres initialize --authority-identity HEX64 [--timeout DURATION]")
}
