package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	awskms "github.com/georgejieh/open-trestle/adapters/keys/awskms"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

func TestSetupKMSProbeDefersCredentialsAndBindsConfiguration(t *testing.T) {
	values := map[string]string{"OPEN_TRESTLE_AWS_ACCESS_KEY_ID": "ACCESSKEY", "OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY": strings.Repeat("s", 32), "OPEN_TRESTLE_AWS_SESSION_TOKEN": strings.Repeat("t", 16)}
	reads, calls := 0, 0
	executor := func(_ context.Context, tenant, region, keyARN, endpoint, access, secret, session string) error {
		calls++
		if tenant != "tenant-a" || region != "us-east-1" || keyARN != tenantASetupKey || endpoint != "https://kms.example" || access != "ACCESSKEY" || secret != strings.Repeat("s", 32) || session != strings.Repeat("t", 16) {
			t.Fatal("crossed input")
		}
		return nil
	}
	probe, authority, err := newSetupKMSProbe(func(name string) string { reads++; return values[name] }, "tenant-a", "us-east-1", tenantASetupKey, "https://kms.example", executor)
	if err != nil || reads != 0 || calls != 0 {
		t.Fatalf("new=%v reads=%d calls=%d", err, reads, calls)
	}
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTimeCLI())
	checker, err := setupcore.NewSecretBackendChecker(plan, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != setupcore.CheckPassed || reads != 3 || calls != 1 {
		t.Fatalf("result=%s reads=%d calls=%d", result.State(), reads, calls)
	}
	if strings.Contains(fmt.Sprintf("%#v", probe), "kms.example") || strings.Contains(fmt.Sprintf("%#v", probe), tenantASetupKey) || strings.Contains(fmt.Sprintf("%#v", probe), "secret") {
		t.Fatal("probe formatter leaked")
	}
	pure, _ := awskms.ConfigurationIdentity("us-east-1", []awskms.TenantKey{{TenantID: "tenant-a", KeyARN: tenantASetupKey}})
	if authority != pure {
		t.Fatal("authority mismatch")
	}
}
func TestSetupKMSProbeClassifiesClosedFailures(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTimeCLI())
	for _, test := range []struct {
		err  error
		want setupcore.CheckState
	}{{awskms.ErrKMSUnavailable, setupcore.CheckUnavailable}, {awskms.ErrKMSResponse, setupcore.CheckBlocked}, {errors.New("unknown"), setupcore.CheckBlocked}} {
		probe, authority, _ := newSetupKMSProbe(func(string) string { return strings.Repeat("c", 32) }, "tenant-a", "us-east-1", tenantASetupKey, "", func(context.Context, string, string, string, string, string, string, string) error { return test.err })
		checker, _ := setupcore.NewSecretBackendChecker(plan, authority, "owner", probe)
		if result := checker.Check(context.Background(), plan); result.State() != test.want {
			t.Fatalf("%v=%s", test.err, result.State())
		}
	}
}

const tenantASetupKey = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-1234567890ab"

func TestSetupCLIRecordsExactSecretBackendReceipt(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "plan.json")
	var stdout, stderr bytes.Buffer
	if code := runSetupWithClock([]string{"init", "--profile", "controlled_hybrid", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", state}, &stdout, &stderr, fixedSetupClock{setupTimeCLI()}); code != 0 {
		t.Fatal(stderr.String())
	}
	t.Setenv("OPEN_TRESTLE_AWS_ACCESS_KEY_ID", "ACCESSKEY")
	t.Setenv("OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY", strings.Repeat("s", 32))
	t.Setenv("OPEN_TRESTLE_AWS_SESSION_TOKEN", strings.Repeat("t", 16))
	authority, _ := awskms.ConfigurationIdentity("us-east-1", []awskms.TenantKey{{TenantID: "tenant-a", KeyARN: tenantASetupKey}})
	calls := 0
	executor := func(context.Context, string, string, string, string, string, string, string) error {
		calls++
		return nil
	}
	inference, _ := newSetupLocalInferenceFactory(func(string) string { return "" })
	postgres, _ := newSetupPostgresStorageProbe(func(string) string { return "" }, func(context.Context, string) (string, error) { return "", errors.New("unused") })
	stdout.Reset()
	stderr.Reset()
	args := []string{"check", "secret", "--state", state, "--approve-kms-authority-identity", authority, "--kms-region", "us-east-1", "--kms-key-arn", tenantASetupKey, "--approved-by", "owner"}
	code := runSetupWithDependencies(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}, inference, postgres, executor, executeSetupEnvelopeStorage, executeSetupGitHubPermission, executeSetupGitHubWebhook, executeSetupSharedRateLimit, executeSetupReplicaReconciliation, executeSetupSignedBundle)
	if code != 0 || stderr.Len() != 0 || calls != 1 || !strings.Contains(stdout.String(), `"key":"secret_backend_validated"`) || !strings.Contains(stdout.String(), `"state":"passed"`) {
		t.Fatalf("result=(%d,%q,%q,%d)", code, stdout.String(), stderr.String(), calls)
	}
}

func TestSetupTUIServiceRunsSecretBackendChecker(t *testing.T) {
	root := t.TempDir()
	statePath := initializedSetupTUIStateForProfile(t, root, setupcore.ProfileControlledHybrid)
	state, err := setupcore.OpenStateFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	authority, _ := awskms.ConfigurationIdentity("us-east-1", []awskms.TenantKey{{TenantID: "tenant-a", KeyARN: tenantASetupKey}})
	calls := 0
	values := map[string]string{"OPEN_TRESTLE_AWS_ACCESS_KEY_ID": "ACCESSKEY", "OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY": strings.Repeat("s", 32), "OPEN_TRESTLE_AWS_SESSION_TOKEN": strings.Repeat("t", 16)}
	service := &setupTUIService{state: state, clock: fixedSetupClock{setupTimeCLI().Add(time.Second)}, getenv: func(name string) string { return values[name] }, kmsExecutor: func(context.Context, string, string, string, string, string, string, string) error {
		calls++
		return nil
	}, kmsAuthorityIdentity: authority, kmsRegion: "us-east-1", kmsKeyARN: tenantASetupKey, kmsApprovedBy: "owner"}
	plan, _ := service.Current(context.Background())
	_, receipt, err := service.RunCheck(context.Background(), setupcore.CheckSecretBackendValidated, plan.Identity())
	if err != nil || receipt.State() != setupcore.CheckPassed || calls != 1 {
		t.Fatalf("receipt=%s err=%v calls=%d", receipt.State(), err, calls)
	}
}

func TestSetupKMSCheckerRejectsUnapprovedAuthorityBeforeCredentialRead(t *testing.T) {
	reads, calls := 0, 0
	probe, _, err := newSetupKMSProbe(func(string) string { reads++; return strings.Repeat("c", 32) }, "tenant-a", "us-east-1", tenantASetupKey, "", func(context.Context, string, string, string, string, string, string, string) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTimeCLI())
	checker, err := setupcore.NewSecretBackendChecker(plan, strings.Repeat("f", 64), "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != setupcore.CheckBlocked || reads != 0 || calls != 0 {
		t.Fatalf("result=%s reads=%d calls=%d", result.State(), reads, calls)
	}
}

func TestSetupKMSCheckerFencesChangedConfigurationBeforeCredentialRead(t *testing.T) {
	reads, calls := 0, 0
	probe, authority, _ := newSetupKMSProbe(func(string) string { reads++; return strings.Repeat("c", 32) }, "tenant-a", "us-east-1", tenantASetupKey, "", func(context.Context, string, string, string, string, string, string, string) error {
		calls++
		return nil
	})
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTimeCLI())
	checker, _ := setupcore.NewSecretBackendChecker(plan, authority, "owner", probe)
	probe.region = "us-west-2"
	if result := checker.Check(context.Background(), plan); result.State() != setupcore.CheckBlocked || reads != 0 || calls != 0 {
		t.Fatalf("result=%s reads=%d calls=%d", result.State(), reads, calls)
	}
}

type setupKMSRoundTripper func(*http.Request) (*http.Response, error)

func (f setupKMSRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
func TestSetupKMSResponseBodyIsBounded(t *testing.T) {
	transport := setupKMSBoundedTransport{inner: setupKMSRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, ContentLength: -1, Body: io.NopCloser(strings.NewReader("12345")), Header: make(http.Header)}, nil
	}), maximum: 4}
	response, err := transport.RoundTrip(&http.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadAll(response.Body); !errors.Is(err, awskms.ErrKMSUnavailable) {
		t.Fatalf("err=%v", err)
	}
	_ = response.Body.Close()
}

func TestSetupKMSProbeRejectsUnsafeEndpointWithoutCredentialRead(t *testing.T) {
	reads := 0
	probe, authority, err := newSetupKMSProbe(func(string) string { reads++; return "" }, "tenant-a", "us-east-1", tenantASetupKey, "https://169.254.169.254", func(context.Context, string, string, string, string, string, string, string) error { return nil })
	if err == nil || probe != nil || authority != "" || reads != 0 {
		t.Fatalf("probe=%#v authority=%q err=%v reads=%d", probe, authority, err, reads)
	}
}
