package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/runtimeadmin"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

func TestRunPostgresAdminUsesEnvironmentCredentialAndSanitizedOutput(t *testing.T) {
	secret := "postgres://operator:secret@database/trestle"
	t.Setenv("OPEN_TRESTLE_POSTGRES_URL", secret)
	var stdout, stderr bytes.Buffer
	called := false
	execute := func(_ context.Context, operation, dsn, authority string) (string, error) {
		called = true
		if operation != "verify" || dsn != secret || authority != strings.Repeat("a", 64) {
			t.Fatalf("request=(%q,%q,%q)", operation, dsn, authority)
		}
		return strings.Repeat("b", 64), nil
	}
	code := runAdminWithExecutor([]string{"postgres", "verify", "--authority-identity", strings.Repeat("a", 64)}, &stdout, &stderr, execute)
	if code != 0 || !called || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"status":"valid"`) || !strings.Contains(stdout.String(), strings.Repeat("b", 64)) || strings.Contains(stdout.String(), "secret") || strings.Contains(stdout.String(), strings.Repeat("a", 64)) {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
}
func TestRunPostgresAdminRequiresExplicitInitializationAuthority(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_POSTGRES_MIGRATION_URL", "postgres://secret")
	var stdout, stderr bytes.Buffer
	called := false
	code := runAdminWithExecutor([]string{"postgres", "initialize"}, &stdout, &stderr, func(context.Context, string, string, string) (string, error) { called = true; return "", nil })
	if code != 2 || called {
		t.Fatalf("result=(%d,%v,%q)", code, called, stderr.String())
	}
}
func TestRunDispatchesAdmin(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"admin"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "trestle admin postgres") {
		t.Fatalf("result=(%d,%q)", code, stderr.String())
	}
}

func TestRunPostgresAdminRejectsUnexpectedRestoreReceipt(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_POSTGRES_URL", "postgres://operator:secret@database/trestle")
	var stdout, stderr bytes.Buffer
	code := runAdminWithExecutor([]string{"postgres", "verify", "--authority-identity", strings.Repeat("a", 64), "--expected-receipt-identity", strings.Repeat("c", 64)}, &stdout, &stderr, func(context.Context, string, string, string) (string, error) { return strings.Repeat("b", 64), nil })
	if code != 1 || stdout.Len() != 0 || stderr.String() != "postgres administration failed\n" {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
}

func TestRunRuntimeAdminPrintsContentFreeSnapshot(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_API_TOKEN", strings.Repeat("t", 32))
	configuration, _ := runtimeadmin.NewConfiguration(runtimeadmin.ConfigurationOptions{TenantID: "tenant-a", RepositoryIDs: []string{"repo-a"}, MetadataBackend: runtimeadmin.MetadataLocal, ArtifactBackend: runtimeadmin.ArtifactLocal, ArtifactProtection: runtimeadmin.ProtectionProcessPrivate, NotificationBackend: runtimeadmin.NotificationProcessLocal, RateLimitBackend: runtimeadmin.RateLimitProcessLocal, ReviewMode: runtimeadmin.ReviewDisabled})
	service, _ := runtimeadmin.NewService(configuration, nil)
	snapshot, _ := service.Snapshot("tenant-a", "repo-a", time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC))
	var stdout, stderr bytes.Buffer
	called := false
	code := runRuntimeAdminWithExecutor([]string{"status", "--server", "http://127.0.0.1:8741", "--tenant", "tenant-a", "--repository", "repo-a"}, &stdout, &stderr, func(_ context.Context, server, token, tenant, repository string) (runtimeadmin.Snapshot, error) {
		called = true
		if server != "http://127.0.0.1:8741" || token != strings.Repeat("t", 32) || tenant != "tenant-a" || repository != "repo-a" {
			t.Fatal("cross-wired request")
		}
		return snapshot, nil
	})
	if code != 0 || !called || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"contract":"open-trestle/runtime-status"`) {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
}

func TestRunPostgresIdentityReportsOnlyDatabaseAuthority(t *testing.T) {
	secret := "postgres://operator:secret@database/trestle"
	t.Setenv("OPEN_TRESTLE_POSTGRES_URL", secret)
	var stdout, stderr bytes.Buffer
	called := false
	identity := strings.Repeat("d", 64)
	execute := func(_ context.Context, operation, dsn, authority string) (string, error) {
		called = true
		if operation != "identity" || dsn != secret || authority != "" {
			t.Fatalf("request=(%s,%s,%s)", operation, dsn, authority)
		}
		return identity, nil
	}
	code := runAdminWithExecutor([]string{"postgres", "identity"}, &stdout, &stderr, execute)
	if code != 0 || !called || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"contract":"open-trestle/postgres-admin-result"`) || !strings.Contains(stdout.String(), `"schema_version":1`) || !strings.Contains(stdout.String(), `"database_authority_identity":"`+identity+`"`) || strings.Contains(stdout.String(), "publication_authority") || strings.Contains(stdout.String(), "secret") {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	called = false
	if code = runAdminWithExecutor([]string{"postgres", "identity", "--authority-identity", strings.Repeat("a", 64)}, &stdout, &stderr, execute); code != 2 || called {
		t.Fatalf("flags=%d called=%v", code, called)
	}
}

func TestRunPostgresMigrateUsesMigrationAuthorityWithoutPublication(t *testing.T) {
	secret := "postgres://migration:secret@database/trestle"
	t.Setenv("OPEN_TRESTLE_POSTGRES_MIGRATION_URL", secret)
	identity := ""
	var stdout, stderr bytes.Buffer
	called := false
	execute := func(_ context.Context, operation, dsn, authority string) (string, error) {
		called = true
		if operation != "migrate" || dsn != secret || authority != "" {
			t.Fatalf("request=(%s,%s,%s)", operation, dsn, authority)
		}
		return identity, nil
	}
	code := runAdminWithExecutor([]string{"postgres", "migrate"}, &stdout, &stderr, execute)
	if code != 0 || !called || stderr.Len() != 0 || strings.Contains(stdout.String(), "database_authority_identity") || strings.Contains(stdout.String(), "publication_authority") {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
}

func TestRunPostgresAdminRejectsMalformedExecutorIdentity(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_POSTGRES_URL", "postgres://secret")
	var stdout, stderr bytes.Buffer
	code := runAdminWithExecutor([]string{"postgres", "identity"}, &stdout, &stderr, func(context.Context, string, string, string) (string, error) { return "not-a-digest", nil })
	if code != 1 || stdout.Len() != 0 || stderr.String() != "postgres administration failed\n" {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
}

func TestPostgresRateLimitAdminIdentityIsOfflineAndContentFree(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAdmin([]string{"postgres", "rate-limit", "identity", "--database-authority-identity", strings.Repeat("a", 64), "--setup-root-identity", strings.Repeat("b", 64)}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"contract":"open-trestle/postgres-rate-limit-admin-result"`) || !strings.Contains(stdout.String(), `"shared_rate_limit_authority_identity":"`) || !strings.Contains(stdout.String(), `"runtime_rate_limit_authority_identity":"`) {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), strings.Repeat("a", 64)) || strings.Contains(stdout.String(), strings.Repeat("b", 64)) {
		t.Fatal("input authority leaked")
	}
}

func TestPostgresReplicaReconciliationAdminIdentityIsOfflineAndContentFree(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAdmin([]string{"postgres", "reconciliation", "identity", "--database-authority-identity", strings.Repeat("a", 64), "--setup-root-identity", strings.Repeat("b", 64)}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"contract":"open-trestle/postgres-replica-reconciliation-admin-result"`) || !strings.Contains(stdout.String(), `"replica_reconciliation_authority_identity":"`) {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), strings.Repeat("a", 64)) || strings.Contains(stdout.String(), strings.Repeat("b", 64)) {
		t.Fatal("input authority leaked")
	}
}

func TestSignedBundleAdminIdentityIsOfflineAndContentFree(t *testing.T) {
	var stdout, stderr bytes.Buffer
	bundleDigest := strings.Repeat("a", 64)
	publicKey := strings.Repeat("b", 64)
	signature := strings.Repeat("c", 128)
	code := runAdmin([]string{"bundle", "identity", "--bundle-sha256", bundleDigest, "--bundle-bytes", "1024", "--public-key", publicKey, "--signature", signature}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"contract":"open-trestle/signed-bundle-admin-result"`) || !strings.Contains(stdout.String(), `"signed_bundle_authority_identity":"`) {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	for _, forbidden := range []string{bundleDigest, publicKey, signature} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatal("public authority input leaked")
		}
	}
}

func TestSignedBundleAdminEmitsExactStatementBytesWithoutSigning(t *testing.T) {
	var stdout, stderr bytes.Buffer
	digest := strings.Repeat("a", 64)
	code := runAdmin([]string{"bundle", "statement", "--bundle-sha256", digest, "--bundle-bytes", "1024"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
	var result struct {
		Contract        string `json:"contract"`
		StatementBase64 string `json:"statement_base64"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Contract != "open-trestle/signed-bundle-statement-admin-result" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	got, err := base64.StdEncoding.Strict().DecodeString(result.StatementBase64)
	want, wantErr := setupcore.EncodeSignedBundleStatement(digest, 1024)
	if err != nil || wantErr != nil || !bytes.Equal(got, want) {
		t.Fatalf("statement=%q want=%q err=%v/%v", got, want, err, wantErr)
	}
}
