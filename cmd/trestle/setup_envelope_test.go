package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	s3store "github.com/georgejieh/open-trestle/adapters/storage/s3"
	"github.com/georgejieh/open-trestle/artifact"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

func setupEnvelopeConfigFixture() setupEnvelopeConfiguration {
	return setupEnvelopeConfiguration{tenantID: "tenant-a", s3Endpoint: "https://s3.example.test", s3Region: "us-east-1", s3Bucket: "artifacts", s3Prefix: "reviews", kmsRegion: "us-east-1", kmsKeyARN: tenantASetupKey, kmsEndpoint: "https://kms.example.test"}
}
func TestSetupEnvelopeProbeDefersCredentialsAndBindsScope(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTimeCLI())
	values := map[string]string{"OPEN_TRESTLE_S3_ACCESS_KEY_ID": "S3ACCESS", "OPEN_TRESTLE_S3_SECRET_ACCESS_KEY": strings.Repeat("s", 32), "OPEN_TRESTLE_S3_SESSION_TOKEN": strings.Repeat("t", 16), "OPEN_TRESTLE_AWS_ACCESS_KEY_ID": "KMSACCESS", "OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY": strings.Repeat("k", 32), "OPEN_TRESTLE_AWS_SESSION_TOKEN": strings.Repeat("u", 16)}
	reads, calls := 0, 0
	conformance := strings.Repeat("c", 64)
	executor := func(_ context.Context, value setupEnvelopeExecution) (string, error) {
		calls++
		if value.rootIdentity != plan.RootIdentity() || value.repositoryID != "repo-a" || value.configuration.tenantID != "tenant-a" || value.s3Access != "S3ACCESS" || value.kmsAccess != "KMSACCESS" {
			t.Fatal("crossed execution")
		}
		return conformance, nil
	}
	probe, authority, err := newSetupEnvelopeStorageProbe(func(name string) string { reads++; return values[name] }, plan, setupEnvelopeConfigFixture(), executor)
	if err != nil || reads != 0 || calls != 0 {
		t.Fatalf("new=%v reads=%d calls=%d", err, reads, calls)
	}
	checker, err := setupcore.NewEnvelopeStorageChecker(plan, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != setupcore.CheckPassed || reads != 6 || calls != 1 {
		t.Fatalf("state=%s reads=%d calls=%d", result.State(), reads, calls)
	}
	formatted := fmt.Sprintf("%#v %#v %#v", probe, setupEnvelopeConfigFixture(), setupEnvelopeExecution{configuration: setupEnvelopeConfigFixture(), s3Secret: "s3-secret", kmsSecret: "kms-secret"})
	for _, value := range []string{"s3.example.test", tenantASetupKey, "s3-secret", "kms-secret"} {
		if strings.Contains(formatted, value) {
			t.Fatalf("formatter leaked %s", value)
		}
	}
}
func TestSetupEnvelopeProbeRejectsAuthorityBeforeCredentialsAndClassifiesErrors(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTimeCLI())
	reads, calls := 0, 0
	probe, _, _ := newSetupEnvelopeStorageProbe(func(string) string { reads++; return strings.Repeat("x", 32) }, plan, setupEnvelopeConfigFixture(), func(context.Context, setupEnvelopeExecution) (string, error) {
		calls++
		return strings.Repeat("c", 64), nil
	})
	checker, _ := setupcore.NewEnvelopeStorageChecker(plan, strings.Repeat("f", 64), "owner", probe)
	if result := checker.Check(context.Background(), plan); result.State() != setupcore.CheckBlocked || reads != 0 || calls != 0 {
		t.Fatalf("mismatch=%s reads=%d calls=%d", result.State(), reads, calls)
	}
	for _, test := range []struct {
		err  error
		want setupcore.CheckState
	}{{s3store.ErrS3Request, setupcore.CheckUnavailable}, {artifact.ErrEnvelopeKeyUnavailable, setupcore.CheckUnavailable}, {artifact.ErrRemoteStoreConflict, setupcore.CheckBlocked}, {artifact.ErrInvalidEnvelopeKey, setupcore.CheckBlocked}, {errors.New("invalid"), setupcore.CheckBlocked}} {
		probe, authority, _ := newSetupEnvelopeStorageProbe(func(name string) string {
			if strings.HasPrefix(name, "OPEN_TRESTLE_S3_") {
				return strings.Repeat("s", 32)
			}
			return strings.Repeat("k", 32)
		}, plan, setupEnvelopeConfigFixture(), func(context.Context, setupEnvelopeExecution) (string, error) { return "", test.err })
		checker, _ := setupcore.NewEnvelopeStorageChecker(plan, authority, "owner", probe)
		if result := checker.Check(context.Background(), plan); result.State() != test.want {
			t.Fatalf("err=%v state=%s", test.err, result.State())
		}
	}
}

func TestSetupCLIRecordsExactEnvelopeStorageReceipt(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "plan.json")
	var stdout, stderr bytes.Buffer
	if code := runSetupWithClock([]string{"init", "--profile", "controlled_hybrid", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", state}, &stdout, &stderr, fixedSetupClock{setupTimeCLI()}); code != 0 {
		t.Fatal(stderr.String())
	}
	for name, value := range map[string]string{"OPEN_TRESTLE_S3_ACCESS_KEY_ID": "S3ACCESS", "OPEN_TRESTLE_S3_SECRET_ACCESS_KEY": strings.Repeat("s", 32), "OPEN_TRESTLE_S3_SESSION_TOKEN": strings.Repeat("t", 16), "OPEN_TRESTLE_AWS_ACCESS_KEY_ID": "KMSACCESS", "OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY": strings.Repeat("k", 32), "OPEN_TRESTLE_AWS_SESSION_TOKEN": strings.Repeat("u", 16)} {
		t.Setenv(name, value)
	}
	configuration := setupEnvelopeConfigFixture()
	authority, _, _, _ := deriveSetupEnvelopeAuthority(configuration)
	calls := 0
	executor := func(context.Context, setupEnvelopeExecution) (string, error) {
		calls++
		return strings.Repeat("c", 64), nil
	}
	inference, _ := newSetupLocalInferenceFactory(func(string) string { return "" })
	postgres, _ := newSetupPostgresStorageProbe(func(string) string { return "" }, func(context.Context, string) (string, error) { return "", errors.New("unused") })
	stdout.Reset()
	stderr.Reset()
	args := []string{"check", "envelope", "--state", state, "--approve-envelope-storage-authority-identity", authority, "--s3-endpoint", configuration.s3Endpoint, "--s3-region", configuration.s3Region, "--s3-bucket", configuration.s3Bucket, "--s3-prefix", configuration.s3Prefix, "--kms-region", configuration.kmsRegion, "--kms-key-arn", configuration.kmsKeyARN, "--kms-endpoint", configuration.kmsEndpoint, "--approved-by", "owner"}
	code := runSetupWithDependencies(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}, inference, postgres, executeSetupKMS, executor, executeSetupGitHubPermission, executeSetupGitHubWebhook, executeSetupSharedRateLimit, executeSetupReplicaReconciliation, executeSetupSignedBundle)
	if code != 0 || stderr.Len() != 0 || calls != 1 || !strings.Contains(stdout.String(), `"key":"envelope_storage_validated"`) || !strings.Contains(stdout.String(), `"state":"passed"`) {
		t.Fatalf("result=(%d,%q,%q,%d)", code, stdout.String(), stderr.String(), calls)
	}
}

func TestSetupTUIServiceRunsEnvelopeStorageChecker(t *testing.T) {
	root := t.TempDir()
	statePath := initializedSetupTUIStateForProfile(t, root, setupcore.ProfileControlledHybrid)
	state, err := setupcore.OpenStateFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	plan, _ := state.Current(context.Background())
	configuration := setupEnvelopeConfigFixture()
	authority, _, _, _ := deriveSetupEnvelopeAuthority(configuration)
	values := map[string]string{"OPEN_TRESTLE_S3_ACCESS_KEY_ID": "S3ACCESS", "OPEN_TRESTLE_S3_SECRET_ACCESS_KEY": strings.Repeat("s", 32), "OPEN_TRESTLE_S3_SESSION_TOKEN": strings.Repeat("t", 16), "OPEN_TRESTLE_AWS_ACCESS_KEY_ID": "KMSACCESS", "OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY": strings.Repeat("k", 32), "OPEN_TRESTLE_AWS_SESSION_TOKEN": strings.Repeat("u", 16)}
	calls := 0
	service := &setupTUIService{state: state, clock: fixedSetupClock{setupTimeCLI().Add(time.Second)}, getenv: func(name string) string { return values[name] }, envelopeExecutor: func(context.Context, setupEnvelopeExecution) (string, error) {
		calls++
		return strings.Repeat("c", 64), nil
	}, envelopeAuthorityIdentity: authority, s3Endpoint: configuration.s3Endpoint, s3Region: configuration.s3Region, s3Bucket: configuration.s3Bucket, s3Prefix: configuration.s3Prefix, kmsRegion: configuration.kmsRegion, kmsKeyARN: configuration.kmsKeyARN, kmsEndpoint: configuration.kmsEndpoint, envelopeApprovedBy: "owner"}
	_, receipt, err := service.RunCheck(context.Background(), setupcore.CheckEnvelopeStorageValidated, plan.Identity())
	if err != nil || receipt.State() != setupcore.CheckPassed || calls != 1 {
		t.Fatalf("receipt=%s err=%v calls=%d", receipt.State(), err, calls)
	}
}

func TestSetupEnvelopeCheckerFencesChangedConfigurationBeforeCredentialRead(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTimeCLI())
	reads, calls := 0, 0
	probe, authority, _ := newSetupEnvelopeStorageProbe(func(string) string { reads++; return strings.Repeat("x", 32) }, plan, setupEnvelopeConfigFixture(), func(context.Context, setupEnvelopeExecution) (string, error) {
		calls++
		return strings.Repeat("c", 64), nil
	})
	checker, _ := setupcore.NewEnvelopeStorageChecker(plan, authority, "owner", probe)
	probe.configuration.s3Prefix = "changed"
	if result := checker.Check(context.Background(), plan); result.State() != setupcore.CheckBlocked || reads != 0 || calls != 0 {
		t.Fatalf("state=%s reads=%d calls=%d", result.State(), reads, calls)
	}
}

func TestSetupEnvelopeProbeRejectsTypedNilExecutor(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTimeCLI())
	var execute setupEnvelopeExecutor
	if probe, authority, err := newSetupEnvelopeStorageProbe(func(string) string { return "" }, plan, setupEnvelopeConfigFixture(), execute); err == nil || probe != nil || authority != "" {
		t.Fatalf("probe=%#v authority=%q err=%v", probe, authority, err)
	}
}

func TestSetupEnvelopeProbeRejectsReusedAccessKeyBeforeExecutor(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTimeCLI())
	calls := 0
	probe, authority, _ := newSetupEnvelopeStorageProbe(func(name string) string {
		if strings.HasSuffix(name, "ACCESS_KEY_ID") {
			return "SAMEACCESS"
		}
		return strings.Repeat("x", 32)
	}, plan, setupEnvelopeConfigFixture(), func(context.Context, setupEnvelopeExecution) (string, error) {
		calls++
		return strings.Repeat("c", 64), nil
	})
	checker, _ := setupcore.NewEnvelopeStorageChecker(plan, authority, "owner", probe)
	if result := checker.Check(context.Background(), plan); result.State() != setupcore.CheckBlocked || calls != 0 {
		t.Fatalf("state=%s calls=%d", result.State(), calls)
	}
}

func TestSetupRemoteTransportCannotReplayOnReusedConnection(t *testing.T) {
	transport := newSetupDirectTransport()
	if transport.Proxy != nil || !transport.DisableKeepAlives || transport.ForceAttemptHTTP2 || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.ResponseHeaderTimeout != 10*time.Second || transport.MaxResponseHeaderBytes != 1<<20 {
		t.Fatalf("transport=%#v", transport)
	}
	transport.CloseIdleConnections()
}

func TestSetupRemoteTransportUsesOneConnectionPerRequest(t *testing.T) {
	addresses := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		addresses = append(addresses, request.RemoteAddr)
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()
	transport := newSetupDirectTransport()
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for range 2 {
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
	if len(addresses) != 2 || addresses[0] == addresses[1] {
		t.Fatalf("addresses=%v", addresses)
	}
}
