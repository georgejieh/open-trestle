//go:build unix

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	s3store "github.com/georgejieh/open-trestle/adapters/storage/s3"
	"github.com/georgejieh/open-trestle/artifact"
)

func TestStartupGuardProtectedTrustedCALoader(t *testing.T) {
	fixture := newDaemonBudgetedHarness(t)
	want, err := os.ReadFile(fixture.caPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := loadProtectedErasureTrustedCA(context.Background(), fixture.caPath)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("valid protected CA changed or failed: len=%d err=%v", len(got), err)
	}

	mode0644 := daemonStartupGuardCAFile(t, []byte("0644 is not group-or-other writable\n"), 0644)
	got, err = loadProtectedErasureTrustedCA(context.Background(), mode0644)
	if err != nil || string(got) != "0644 is not group-or-other writable\n" {
		t.Fatalf("0644 CA rejected despite current fileauthority rules: got=%q err=%v", string(got), err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	separator := string(os.PathSeparator)
	cases := []struct {
		name string
		ctx  context.Context
		path string
	}{
		{"empty-path", context.Background(), ""},
		{"relative-path", context.Background(), filepath.Base(fixture.caPath)},
		{"nonclean-path", context.Background(), filepath.Dir(fixture.caPath) + separator + "." + separator + filepath.Base(fixture.caPath)},
		{"nul-path", context.Background(), fixture.caPath + "\x00suffix"},
		{"over-path-cap", context.Background(), separator + strings.Repeat("a", daemonErasureTrustedCAMaxPath+1)},
		{"nil-context", nil, fixture.caPath},
		{"canceled-context", canceled, fixture.caPath},
		{"empty-file", context.Background(), daemonStartupGuardCAFile(t, nil, 0600)},
		{"over-file-cap", context.Background(), daemonStartupGuardCAFile(t, bytes.Repeat([]byte("x"), daemonErasureTrustedCAMaxBytes+1), 0600)},
		{"symlink-leaf", context.Background(), daemonStartupGuardSymlinkLeafCA(t)},
		{"symlink-parent", context.Background(), daemonStartupGuardSymlinkParentCA(t)},
		{"writable-ancestor", context.Background(), daemonStartupGuardWritableParentCA(t)},
		{"writable-file-mode", context.Background(), daemonStartupGuardCAFile(t, []byte("writable file\n"), 0664)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadProtectedErasureTrustedCA(tc.ctx, tc.path)
			if got != nil || !errors.Is(err, ErrInvalidDaemonConfiguration) {
				t.Fatalf("loadProtectedErasureTrustedCA accepted guard case: got=%q err=%v", string(got), err)
			}
		})
	}
}

func TestBuildDaemonBudgetedRejectsStartupPolicyAndCABeforeExternalContact(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *daemonBudgetedHarness)
	}{
		{"expired-policy", func(t *testing.T, h *daemonBudgetedHarness) {
			now := h.ClockUTCMS()
			h.policyPath = daemonBudgetedProtectedFile(t, "policy.json", daemonStartupGuardPolicyWire(t, h, daemonStartupGuardBackendIdentity(t, h), h.authority, daemonBudgetedPrefix, now.Add(-2*time.Hour), now.Add(-time.Hour)))
		}},
		{"not-yet-valid-policy", func(t *testing.T, h *daemonBudgetedHarness) {
			now := h.ClockUTCMS()
			h.policyPath = daemonBudgetedProtectedFile(t, "policy.json", daemonStartupGuardPolicyWire(t, h, daemonStartupGuardBackendIdentity(t, h), h.authority, daemonBudgetedPrefix, now.Add(time.Hour), now.Add(2*time.Hour)))
		}},
		{"backend-binding-mismatch", func(t *testing.T, h *daemonBudgetedHarness) {
			otherBackend, err := s3store.ConfigurationIdentity(h.s3.Endpoint(), daemonBudgetedRegion, daemonBudgetedBucket+"-other")
			if err != nil {
				t.Fatal(err)
			}
			now := h.ClockUTCMS()
			h.policyPath = daemonBudgetedProtectedFile(t, "policy.json", daemonStartupGuardPolicyWire(t, h, otherBackend, h.authority, daemonBudgetedPrefix, now.Add(-time.Hour), now.Add(time.Hour)))
		}},
		{"database-authority-binding-mismatch", func(t *testing.T, h *daemonBudgetedHarness) {
			now := h.ClockUTCMS()
			h.policyPath = daemonBudgetedProtectedFile(t, "policy.json", daemonStartupGuardPolicyWire(t, h, daemonStartupGuardBackendIdentity(t, h), strings.Repeat("a", 64), daemonBudgetedPrefix, now.Add(-time.Hour), now.Add(time.Hour)))
		}},
		{"prefix-binding-mismatch", func(t *testing.T, h *daemonBudgetedHarness) {
			now := h.ClockUTCMS()
			h.policyPath = daemonBudgetedProtectedFile(t, "policy.json", daemonStartupGuardPolicyWire(t, h, daemonStartupGuardBackendIdentity(t, h), h.authority, daemonBudgetedPrefix+"-other", now.Add(-time.Hour), now.Add(time.Hour)))
		}},
		{"malformed-ca", func(t *testing.T, h *daemonBudgetedHarness) {
			h.caPath = daemonBudgetedProtectedFile(t, "ca.pem", "-----BEGIN CERTIFICATE-----\nbm90IERFUg==\n-----END CERTIFICATE-----\n")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newDaemonBudgetedHarness(t)
			tc.mutate(t, fixture)
			daemonStartupGuardRejectsBeforeExternalContact(t, fixture)
		})
	}
}

func TestStartupGuardErasureClockSampleBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		at    time.Time
		valid bool
	}{
		{"zero", time.Time{}, false},
		{"negative", time.UnixMilli(-1).UTC(), false},
		{"year-over-9999", time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC), false},
		{"submillisecond", time.UnixMilli(1000).UTC().Add(time.Nanosecond), false},
		{"non-utc", time.Date(2026, time.September, 6, 9, 32, 40, 987000000, time.FixedZone("fixture", -7*3600)), false},
		{"one-millisecond-utc", time.UnixMilli(1).UTC(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := daemonValidErasureClockSample(tc.at); got != tc.valid {
				t.Fatalf("daemonValidErasureClockSample(%s)=%t want %t", tc.at, got, tc.valid)
			}
		})
	}

	raw := time.Date(2026, time.September, 6, 9, 32, 40, 987654321, time.FixedZone("fixture", -7*3600))
	got := (daemonErasureClock{inner: daemonBudgetedRawClock{at: raw}}).Now()
	want := raw.UTC().Truncate(time.Millisecond)
	if !got.Equal(want) || got.Location() != time.UTC || got.Nanosecond()%int(time.Millisecond) != 0 || !daemonValidErasureClockSample(got) {
		t.Fatalf("daemonErasureClock did not normalize raw sample: got=%s want=%s", got, want)
	}
}

func daemonStartupGuardCAFile(t *testing.T, content []byte, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, append([]byte(nil), content...), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(clean)
}

func daemonStartupGuardSymlinkLeafCA(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.pem")
	if err := os.WriteFile(target, []byte("target\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(filepath.Base(target), link); err != nil {
		t.Fatal(err)
	}
	clean, err := filepath.Abs(link)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(clean)
}

func daemonStartupGuardSymlinkParentCA(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(realDir, "ca.pem")
	if err := os.WriteFile(path, []byte("parent\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	clean, err := filepath.Abs(filepath.Join(linkDir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(clean)
}

func daemonStartupGuardWritableParentCA(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "shared")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "ca.pem")
	if err := os.WriteFile(path, []byte("parent writable\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(clean)
}

func daemonStartupGuardRejectsBeforeExternalContact(t *testing.T, fixture *daemonBudgetedHarness) {
	t.Helper()
	openCalls := 0
	rejectingOpen := func(context.Context, string, postgresstore.PoolOptions) (*sql.DB, error) {
		openCalls++
		return nil, errors.New("unexpected postgres startup contact")
	}
	d, err := buildDaemonWithDependencies(context.Background(), fixture.args(t), fixture.env, io.Discard, daemonDependencies{openPostgres: rejectingOpen, clock: fixture.clock})
	if d != nil {
		_ = d.Close()
	}
	if d != nil || !errors.Is(err, ErrInvalidDaemonConfiguration) {
		t.Fatalf("buildDaemonWithDependencies returned (%#v,%v)", d, err)
	}
	if openCalls != 0 {
		t.Fatalf("startup guard opened SQL %d times", openCalls)
	}
	snap := fixture.sql.Snapshot()
	if snap.Connections != 0 || snap.Closes != 0 || len(snap.Events) != 0 {
		t.Fatalf("startup guard touched SQL fixture: %#v", snap)
	}
	if fixture.s3.RawRequests() != 0 || fixture.kms.RawRequests() != 0 {
		t.Fatalf("startup guard contacted providers: s3=%d kms=%d", fixture.s3.RawRequests(), fixture.kms.RawRequests())
	}
}

type daemonStartupGuardPolicyRecord struct {
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
}

func daemonStartupGuardPolicyWire(t *testing.T, h *daemonBudgetedHarness, backendIdentity, databaseAuthorityIdentity, prefix string, notBefore, notAfter time.Time) string {
	t.Helper()
	epoch := strings.Repeat("2", 64)
	namespace, err := artifact.NewStorageNamespace(backendIdentity, prefix, epoch)
	if err != nil {
		t.Fatal(err)
	}
	record := daemonStartupGuardPolicyRecord{
		Contract:                      "open-trestle/protected-artifact-erasure-policy",
		SchemaVersion:                 1,
		NamespaceIdentity:             namespace.Identity(),
		BackendConfigurationIdentity:  backendIdentity,
		Prefix:                        prefix,
		NamespaceEpochIdentity:        epoch,
		BackendKind:                   "aws_s3_general_purpose",
		DatabaseAuthorityIdentity:     databaseAuthorityIdentity,
		NamespaceMode:                 "protected_new_nonnull",
		Protocol:                      "same-key-fence-v2",
		Ownership:                     "all_versions_at_exact_key",
		FenceRetentionPolicyIdentity:  strings.Repeat("3", 64),
		ErasurePolicyIdentity:         strings.Repeat("4", 64),
		RecoveryPolicyIdentity:        strings.Repeat("5", 64),
		ConfigurationEvidenceIdentity: strings.Repeat("6", 64),
		NotBeforeMilliseconds:         notBefore.UTC().Truncate(time.Millisecond).UnixMilli(),
		NotAfterMilliseconds:          notAfter.UTC().Truncate(time.Millisecond).UnixMilli(),
	}
	unsigned, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	record.Identity = daemonBudgetedDomainIdentity("open-trestle/protected-artifact-erasure-policy", unsigned)
	wire, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		t.Fatal("missing harness")
	}
	return string(wire)
}

func daemonStartupGuardBackendIdentity(t *testing.T, h *daemonBudgetedHarness) string {
	t.Helper()
	identity, err := s3store.ConfigurationIdentity(h.s3.Endpoint(), daemonBudgetedRegion, daemonBudgetedBucket)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
