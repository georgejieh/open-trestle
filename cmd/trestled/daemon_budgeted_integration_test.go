package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	s3store "github.com/georgejieh/open-trestle/adapters/storage/s3"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

type daemonBudgetedRawClock struct{ at time.Time }

func (c daemonBudgetedRawClock) Now() time.Time { return c.at }

type daemonBudgetedTypedNilClock struct{}

func (*daemonBudgetedTypedNilClock) Now() time.Time { return time.Time{} }

const (
	daemonBudgetedTenant     = "tenant-budgeted"
	daemonBudgetedRepository = "repo-budgeted"
	daemonBudgetedRegion     = "us-east-1"
	daemonBudgetedBucket     = "budgeted-artifacts"
	daemonBudgetedPrefix     = "budgeted-fixture"
	daemonBudgetedKMSKeyARN  = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-1234567890ab"
	daemonBudgetedS3Access   = "s3-fixture-access"
	daemonBudgetedS3Secret   = "s3-fixture-secret-000000000000000000000000000000"
	daemonBudgetedS3Session  = "s3-fixture-session-000000"
	daemonBudgetedKMSAccess  = "kms-fixture-access"
	daemonBudgetedKMSSecret  = "kms-fixture-secret-00000000000000000000000"
	daemonBudgetedKMSSession = "kms-fixture-session-0000"
)

func TestBuildDaemonBudgetedRejectsUnsafeConfigurations(t *testing.T) {
	localBase := func(t *testing.T) []string {
		t.Helper()
		return []string{"--listen", "127.0.0.1:0", "--state-dir", filepath.Join(t.TempDir(), "state"), "--tenant", daemonBudgetedTenant, "--repository", daemonBudgetedRepository}
	}
	withArg := func(args []string, name, value string) []string {
		out := append([]string(nil), args...)
		for i := 0; i+1 < len(out); i++ {
			if out[i] == name {
				out[i+1] = value
				return out
			}
		}
		panic("missing daemon budgeted test arg " + name)
	}
	withAppended := func(args []string, extra ...string) []string { return append(append([]string(nil), args...), extra...) }
	budgetedEnv := func() func(string) string {
		return daemonBudgetedEnvironment(nil, map[string]string{"OPEN_TRESTLE_POSTGRES_URL": "postgres://budgeted-runtime.fixture/open_trestle"})
	}
	migrationEnv := func() func(string) string {
		return daemonBudgetedEnvironment(map[string]string{"OPEN_TRESTLE_POSTGRES_MIGRATION_URL": "postgres://migration.invalid/db"}, map[string]string{"OPEN_TRESTLE_POSTGRES_URL": "postgres://budgeted-runtime.fixture/open_trestle"})
	}
	localEnv := daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": strings.Repeat("t", 32)})
	cases := []struct {
		name string
		args func(*testing.T, *daemonBudgetedHarness) []string
		env  func(*daemonBudgetedHarness) func(string) string
		deps func(*daemonBudgetedHarness, func(context.Context, string, postgresstore.PoolOptions) (*sql.DB, error)) daemonDependencies
	}{
		{"policy without budgeted", func(t *testing.T, h *daemonBudgetedHarness) []string {
			return withAppended(localBase(t), "--erasure-policy", h.policyPath)
		}, func(*daemonBudgetedHarness) func(string) string { return localEnv }, nil},
		{"ca without budgeted", func(t *testing.T, h *daemonBudgetedHarness) []string {
			return withAppended(localBase(t), "--s3-erasure-trusted-ca", h.caPath)
		}, func(*daemonBudgetedHarness) func(string) string { return localEnv }, nil},
		{"budgeted local metadata", func(t *testing.T, h *daemonBudgetedHarness) []string {
			return withArg(h.args(t), "--metadata-store", "local")
		}, func(*daemonBudgetedHarness) func(string) string { return budgetedEnv() }, nil},
		{"budgeted local artifact", func(t *testing.T, h *daemonBudgetedHarness) []string {
			return withArg(h.args(t), "--artifact-store", "local")
		}, func(*daemonBudgetedHarness) func(string) string { return budgetedEnv() }, nil},
		{"budgeted apply migrations", func(t *testing.T, h *daemonBudgetedHarness) []string {
			return withAppended(h.args(t), "--apply-migrations")
		}, func(*daemonBudgetedHarness) func(string) string { return migrationEnv() }, nil},
		{"budgeted migration url", func(t *testing.T, h *daemonBudgetedHarness) []string { return h.args(t) }, func(*daemonBudgetedHarness) func(string) string { return migrationEnv() }, nil},
		{"budgeted nil opener", func(t *testing.T, h *daemonBudgetedHarness) []string { return h.args(t) }, func(*daemonBudgetedHarness) func(string) string { return budgetedEnv() }, func(h *daemonBudgetedHarness, _ func(context.Context, string, postgresstore.PoolOptions) (*sql.DB, error)) daemonDependencies {
			return daemonDependencies{clock: h.clock}
		}},
		{"budgeted nil clock", func(t *testing.T, h *daemonBudgetedHarness) []string { return h.args(t) }, func(*daemonBudgetedHarness) func(string) string { return budgetedEnv() }, func(_ *daemonBudgetedHarness, open func(context.Context, string, postgresstore.PoolOptions) (*sql.DB, error)) daemonDependencies {
			return daemonDependencies{openPostgres: open}
		}},
		{"budgeted invalid mode", func(t *testing.T, h *daemonBudgetedHarness) []string {
			return withArg(h.args(t), "--artifact-erasure-mode", "instant")
		}, func(*daemonBudgetedHarness) func(string) string { return budgetedEnv() }, nil},
		{"budgeted typed nil clock", func(t *testing.T, h *daemonBudgetedHarness) []string { return h.args(t) }, func(*daemonBudgetedHarness) func(string) string { return budgetedEnv() }, func(_ *daemonBudgetedHarness, open func(context.Context, string, postgresstore.PoolOptions) (*sql.DB, error)) daemonDependencies {
			var clock *daemonBudgetedTypedNilClock
			return daemonDependencies{openPostgres: open, clock: clock}
		}},
		{"budgeted protected policy failure", func(t *testing.T, h *daemonBudgetedHarness) []string {
			return withArg(h.args(t), "--erasure-policy", filepath.Join(t.TempDir(), "missing-policy.json"))
		}, func(*daemonBudgetedHarness) func(string) string { return budgetedEnv() }, nil},
		{"budgeted protected ca failure", func(t *testing.T, h *daemonBudgetedHarness) []string {
			return withArg(h.args(t), "--s3-erasure-trusted-ca", filepath.Join(t.TempDir(), "missing-ca.pem"))
		}, func(*daemonBudgetedHarness) func(string) string { return budgetedEnv() }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newDaemonBudgetedHarness(t)
			rejectingOpen := func(context.Context, string, postgresstore.PoolOptions) (*sql.DB, error) {
				t.Fatal("postgres opener must not run for pre-resource validation")
				return nil, errors.New("unexpected open")
			}
			deps := daemonDependencies{openPostgres: rejectingOpen, clock: fixture.clock}
			if tc.deps != nil {
				deps = tc.deps(fixture, rejectingOpen)
			}
			d, err := buildDaemonWithDependencies(context.Background(), tc.args(t, fixture), tc.env(fixture), io.Discard, deps)
			if d != nil {
				_ = d.Close()
			}
			if d != nil || !errors.Is(err, ErrInvalidDaemonConfiguration) {
				t.Fatalf("buildDaemonWithDependencies returned (%#v,%v)", d, err)
			}
			snap := fixture.sql.Snapshot()
			if snap.Connections != 0 || snap.Closes != 0 || len(snap.Events) != 0 {
				t.Fatalf("pre-resource rejection touched SQL: %#v", snap)
			}
			if fixture.s3.RawRequests() != 0 || fixture.kms.RawRequests() != 0 {
				t.Fatalf("pre-resource rejection contacted providers: s3=%d kms=%d", fixture.s3.RawRequests(), fixture.kms.RawRequests())
			}
		})
	}
}

func TestBuildDaemonBudgetedStartupUsesVerifiedExternalDependencies(t *testing.T) {
	fixture := newDaemonBudgetedHarness(t)
	d := fixture.build(t)
	if d == nil || d.artifactStore == nil {
		t.Fatal("budgeted daemon did not expose artifact store")
	}
	defer d.Close()
	if fixture.s3.RawRequests() != 0 || fixture.kms.RawRequests() != 0 {
		t.Fatalf("startup contacted S3/KMS: s3=%d kms=%d", fixture.s3.RawRequests(), fixture.kms.RawRequests())
	}
	snap := fixture.sql.Snapshot()
	for _, id := range []string{"authority_schemas", "migration_rows", "authority_identity", "role", "relation", "attributes", "constraints", "indexes", "policies", "table_privileges", "user_triggers", "allowance_counter_privileges", "allowance_immutable_privileges"} {
		if !daemonBudgetedTraceContains(snap.Events, id) {
			t.Fatalf("startup did not execute %s; trace=%#v", id, snap.Events)
		}
	}
	readOnlyRR := 0
	for _, e := range snap.Events {
		if e.Kind == "begin" && e.ReadOnly && e.Isolation == driver.IsolationLevel(sql.LevelRepeatableRead) {
			readOnlyRR++
		}
	}
	if readOnlyRR < 2 {
		t.Fatalf("expected storage and budgeted schema verification snapshots, saw %d", readOnlyRR)
	}
	assertBudgetedRuntimeComponent(t, d)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if fixture.sql.Snapshot().Closes == 0 {
		t.Fatal("daemon close did not close SQL handle")
	}
}

func TestBuildDaemonBudgetedArtifactPutGetUsesRealAdmission(t *testing.T) {
	fixture := newDaemonBudgetedHarness(t)
	d := fixture.build(t)
	defer d.Close()
	if fixture.s3.RawRequests() != 0 || fixture.kms.RawRequests() != 0 {
		t.Fatalf("startup contacted external artifact services: s3=%d kms=%d", fixture.s3.RawRequests(), fixture.kms.RawRequests())
	}
	now := fixture.ClockUTCMS()
	at := now.Add(-time.Minute)
	scope, err := audit.NewReviewScope(daemonBudgetedTenant, daemonBudgetedRepository, "run-budgeted-putget")
	if err != nil {
		t.Fatal(err)
	}
	value, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationRestricted, artifact.OriginHost, artifact.ProtectionEnvelopeEncrypted, []string{strings.Repeat("a", 64)}, []byte(`{"message":"budgeted put get"}`), at.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	created, err := d.artifactStore.Put(context.Background(), value, at)
	if err != nil || !created {
		t.Fatalf("Put = (%t,%v)", created, err)
	}
	got, err := d.artifactStore.Get(context.Background(), scope, value.Identity(), at)
	if err != nil {
		t.Fatalf("Get = %v", err)
	}
	if got.Identity() != value.Identity() || !daemonBudgetedBytesEqual(got.Payload(), value.Payload()) {
		t.Fatalf("artifact mismatch got=%s want=%s", got.Identity(), value.Identity())
	}
	if _, err := d.artifactStore.Put(context.Background(), value, at.Add(time.Nanosecond)); !errors.Is(err, artifact.ErrInvalidErasureContract) {
		t.Fatalf("sub-millisecond direct Put was normalized or misclassified: %v", err)
	}
	sqlSnap := fixture.sql.Snapshot()
	for _, id := range []string{"scope_insert", "metadata_insert", "admission_insert", "confirmation_cas", "admission_read", "operation_read"} {
		if !daemonBudgetedTraceContains(sqlSnap.Events, id) {
			t.Fatalf("Put/Get did not execute %s; trace=%#v", id, sqlSnap.Events)
		}
	}
	s3Requests, kmsRequests := fixture.s3.Requests(), fixture.kms.Requests()
	if !daemonBudgetedS3SawArtifactWrite(s3Requests) || !daemonBudgetedS3SawMethod(s3Requests, http.MethodGet) {
		t.Fatalf("missing S3 create/read path: %#v", s3Requests)
	}
	if daemonBudgetedKMSTargetCount(kmsRequests, "TrentService.GenerateDataKey") == 0 || daemonBudgetedKMSTargetCount(kmsRequests, "TrentService.Decrypt") == 0 {
		t.Fatalf("missing KMS generate/decrypt path: %#v", kmsRequests)
	}
	if failures := fixture.s3.Failures(); len(failures) != 0 {
		t.Fatalf("S3 fixture rejected requests during positive path: %#v", failures)
	}
	if failures := fixture.kms.Failures(); len(failures) != 0 {
		t.Fatalf("KMS fixture rejected requests during positive path: %#v", failures)
	}
}

func TestBuildDaemonBudgetedSchemaMismatchRefusesAndCleansUp(t *testing.T) {
	fixture := newDaemonBudgetedHarness(t)
	fixture.sql.setSchemaMismatch()
	d, err := buildDaemonWithDependencies(context.Background(), fixture.args(t), fixture.env, io.Discard, daemonDependencies{openPostgres: fixture.sql.OpenPostgres, clock: fixture.clock})
	if d != nil || err == nil {
		t.Fatalf("schema mismatch accepted: (%#v,%v)", d, err)
	}
	if fixture.s3.RawRequests() != 0 || fixture.kms.RawRequests() != 0 {
		t.Fatalf("schema mismatch contacted providers: s3=%d kms=%d", fixture.s3.RawRequests(), fixture.kms.RawRequests())
	}
	if fixture.sql.Snapshot().Closes == 0 {
		t.Fatal("failed construction did not close SQL handle")
	}
}

type daemonBudgetedHarness struct {
	sql        *daemonBudgetedSQLService
	s3         *daemonBudgetedS3Fixture
	kms        *daemonBudgetedKMSFixture
	clock      daemonBudgetedRawClock
	env        func(string) string
	policyPath string
	caPath     string
	authority  string
}

func newDaemonBudgetedHarness(t *testing.T) *daemonBudgetedHarness {
	t.Helper()
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" || runtime.GOOS == "js" {
		t.Skip("protected file authority is not implemented on this platform")
	}
	sqlService := newDaemonBudgetedSQLService(t)
	s3 := newDaemonBudgetedS3Fixture(t, daemonBudgetedBucket, daemonBudgetedRegion, daemonBudgetedS3Access, daemonBudgetedS3Secret, daemonBudgetedS3Session)
	kms := newDaemonBudgetedKMSFixture(t, daemonBudgetedRegion, daemonBudgetedKMSKeyARN, daemonBudgetedKMSAccess, daemonBudgetedKMSSecret, daemonBudgetedKMSSession)
	clock := daemonBudgetedRawClock{at: time.Date(2026, 9, 6, 9, 32, 40, 987654321, time.FixedZone("fixture", -7*3600))}
	authority := daemonBudgetedAuthorityIdentity(sqlService.catalog)
	backendIdentity, err := s3store.ConfigurationIdentity(s3.Endpoint(), daemonBudgetedRegion, daemonBudgetedBucket)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := daemonBudgetedProtectedFile(t, "policy.json", daemonBudgetedPolicyWire(t, backendIdentity, authority, clock.Now().UTC().Truncate(time.Millisecond)))
	caPath := daemonBudgetedProtectedFile(t, "ca.pem", string(s3.CAPEM()))
	return &daemonBudgetedHarness{sql: sqlService, s3: s3, kms: kms, clock: clock, env: daemonBudgetedEnvironment(nil, map[string]string{"OPEN_TRESTLE_POSTGRES_URL": "postgres://budgeted-runtime.fixture/open_trestle"}), policyPath: policyPath, caPath: caPath, authority: authority}
}

func (h *daemonBudgetedHarness) ClockUTCMS() time.Time {
	return h.clock.Now().UTC().Truncate(time.Millisecond)
}
func (h *daemonBudgetedHarness) build(t *testing.T) *daemon {
	t.Helper()
	d, err := buildDaemonWithDependencies(context.Background(), h.args(t), h.env, io.Discard, daemonDependencies{openPostgres: h.sql.OpenPostgres, clock: h.clock})
	if err != nil {
		t.Fatalf("budgeted build failed: %v", err)
	}
	return d
}
func (h *daemonBudgetedHarness) args(t *testing.T) []string {
	t.Helper()
	return []string{"--listen", "127.0.0.1:0", "--state-dir", filepath.Join(t.TempDir(), "state"), "--tenant", daemonBudgetedTenant, "--repository", daemonBudgetedRepository, "--metadata-store", "postgres", "--postgres-database-authority-identity", h.authority, "--artifact-store", "s3", "--artifact-erasure-mode", "budgeted", "--erasure-policy", h.policyPath, "--s3-erasure-trusted-ca", h.caPath, "--s3-endpoint", h.s3.Endpoint(), "--s3-region", daemonBudgetedRegion, "--s3-bucket", daemonBudgetedBucket, "--s3-prefix", daemonBudgetedPrefix, "--kms-region", daemonBudgetedRegion, "--kms-key-arn", daemonBudgetedKMSKeyARN, "--kms-endpoint", h.kms.Endpoint()}
}

func daemonBudgetedEnvironment(extra map[string]string, override map[string]string) func(string) string {
	values := map[string]string{"OPEN_TRESTLE_API_TOKEN": strings.Repeat("t", 32), "OPEN_TRESTLE_POSTGRES_URL": "postgres://budgeted-runtime.fixture/open_trestle", "OPEN_TRESTLE_S3_ACCESS_KEY_ID": daemonBudgetedS3Access, "OPEN_TRESTLE_S3_SECRET_ACCESS_KEY": daemonBudgetedS3Secret, "OPEN_TRESTLE_S3_SESSION_TOKEN": daemonBudgetedS3Session, "OPEN_TRESTLE_AWS_ACCESS_KEY_ID": daemonBudgetedKMSAccess, "OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY": daemonBudgetedKMSSecret, "OPEN_TRESTLE_AWS_SESSION_TOKEN": daemonBudgetedKMSSession}
	for k, v := range extra {
		values[k] = v
	}
	for k, v := range override {
		values[k] = v
	}
	return daemonEnvironment(values)
}

func daemonBudgetedProtectedFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(clean)
}

func daemonBudgetedPolicyWire(t *testing.T, backendIdentity, databaseAuthorityIdentity string, now time.Time) string {
	t.Helper()
	epoch := strings.Repeat("2", 64)
	namespace, err := artifact.NewStorageNamespace(backendIdentity, daemonBudgetedPrefix, epoch)
	if err != nil {
		t.Fatal(err)
	}
	record := struct {
		Contract                      string `json:"contract"`
		SchemaVersion                 int    `json:"schema_version"`
		Identity                      string `json:"identity,omitempty"`
		NamespaceIdentity             string `json:"namespace_identity"`
		BackendConfigurationIdentity  string `json:"backend_configuration_identity"`
		Prefix                        string `json:"prefix"`
		NamespaceEpochIdentity        string `json:"namespace_epoch_identity"`
		BackendKind                   string `json:"backend_kind"`
		DatabaseAuthorityIdentity     string `json:"database_authority_identity"`
		NamespaceMode                 string `json:"namespace_mode"`
		Protocol                      string `json:"protocol"`
		Ownership                     string `json:"ownership"`
		FenceRetentionPolicyIdentity  string `json:"fence_retention_policy_identity"`
		ErasurePolicyIdentity         string `json:"erasure_policy_identity"`
		RecoveryPolicyIdentity        string `json:"recovery_policy_identity"`
		ConfigurationEvidenceIdentity string `json:"configuration_evidence_identity"`
		NotBeforeMilliseconds         int64  `json:"not_before_milliseconds"`
		NotAfterMilliseconds          int64  `json:"not_after_milliseconds"`
	}{"open-trestle/protected-artifact-erasure-policy", 1, "", namespace.Identity(), backendIdentity, daemonBudgetedPrefix, epoch, "aws_s3_general_purpose", databaseAuthorityIdentity, "protected_new_nonnull", "same-key-fence-v2", "all_versions_at_exact_key", strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64), now.Add(-time.Hour).UnixMilli(), now.Add(time.Hour).UnixMilli()}
	unsigned, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	record.Identity = daemonBudgetedDomainIdentity("open-trestle/protected-artifact-erasure-policy", unsigned)
	wire, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return string(wire)
}

func daemonBudgetedDomainIdentity(contract string, body []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(contract + "/v1\x00"))
	_, _ = digest.Write(body)
	return hex.EncodeToString(digest.Sum(nil))
}

func assertBudgetedRuntimeComponent(t *testing.T, d *daemon) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/api/v1/tenants/"+daemonBudgetedTenant+"/repositories/"+daemonBudgetedRepository+"/runtime", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	rec := httptest.NewRecorder()
	d.server.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("runtime status did not report budgeted startup component: %d %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Status struct {
			Components []struct {
				Name  string `json:"name"`
				State string `json:"state"`
			} `json:"components"`
		} `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("runtime status was not JSON: %v body=%s", err, rec.Body.String())
	}
	matches := 0
	for _, component := range response.Status.Components {
		if component.Name != "artifact_erasure_budgeted" {
			continue
		}
		matches++
		if component.State != "ready" {
			t.Fatalf("budgeted component state = %q, want ready; components=%#v", component.State, response.Status.Components)
		}
	}
	if matches != 1 {
		t.Fatalf("budgeted component matches = %d, want 1; components=%#v", matches, response.Status.Components)
	}
}
