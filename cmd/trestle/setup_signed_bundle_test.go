package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	setupcore "github.com/georgejieh/open-trestle/setup"
)

func TestSetupSignedBundleProbeDefersFileReadAndBindsPlan(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileAirGapped, "tenant-a", "repo-a", "owner", setupTimeCLI())
	configuration := setupSignedBundleConfiguration{
		bundlePath:   "/private/release.bundle",
		bundleDigest: strings.Repeat("a", 64),
		bundleBytes:  1024,
		publicKeyHex: strings.Repeat("b", 64),
		signatureHex: strings.Repeat("c", 128),
	}
	calls := 0
	probe, authority, err := newSetupSignedBundleProbe(plan, configuration, func(_ context.Context, got setupSignedBundleConfiguration) (string, error) {
		calls++
		if got != configuration {
			t.Fatal("crossed bundle configuration")
		}
		return strings.Repeat("d", 64), nil
	})
	if err != nil || probe.ConfigurationIdentity() == "" || probe.AuthorityIdentity() != authority || calls != 0 {
		t.Fatalf("probe=%#v authority=%s calls=%d err=%v", probe, authority, calls, err)
	}
	if result := probe.Probe(context.Background()); result != setupcore.NewVerifiedSignedBundleProbeResult(authority, strings.Repeat("d", 64)) || calls != 1 {
		t.Fatalf("result=%#v calls=%d", result, calls)
	}
	other, _ := setupcore.NewPlan(setupcore.ProfileAirGapped, "tenant-a", "repo-b", "owner", setupTimeCLI())
	changed, _, err := newSetupSignedBundleProbe(other, configuration, func(context.Context, setupSignedBundleConfiguration) (string, error) { return "", nil })
	if err != nil || changed.ConfigurationIdentity() == probe.ConfigurationIdentity() {
		t.Fatal("plan scope not bound")
	}
	probe.configuration.bundleDigest = strings.Repeat("e", 64)
	if result := probe.Probe(context.Background()); result != setupcore.NewInvalidSignedBundleProbeResult() || calls != 1 {
		t.Fatalf("mutated=%#v calls=%d", result, calls)
	}
}

func TestSetupCLIRecordsSignedBundleReceipt(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "plan.json")
	var stdout, stderr bytes.Buffer
	if code := runSetupWithClock([]string{"init", "--profile", "air_gapped", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", statePath}, &stdout, &stderr, fixedSetupClock{setupTimeCLI()}); code != 0 {
		t.Fatal(stderr.String())
	}
	configuration := setupSignedBundleConfiguration{
		bundlePath:   filepath.Join(root, "release.bundle"),
		bundleDigest: strings.Repeat("a", 64),
		bundleBytes:  1024,
		publicKeyHex: strings.Repeat("b", 64),
		signatureHex: strings.Repeat("c", 128),
	}
	authority, _ := deriveSetupSignedBundleAuthority(configuration)
	inference, _ := newSetupLocalInferenceFactory(func(string) string { return "" })
	postgresProbe, _ := newSetupPostgresStorageProbe(func(string) string { return "" }, executeSetupPostgresStorage)
	calls := 0
	executor := func(_ context.Context, got setupSignedBundleConfiguration) (string, error) {
		calls++
		if got != configuration {
			t.Fatal("crossed signed bundle configuration")
		}
		return strings.Repeat("d", 64), nil
	}
	args := []string{"check", "bundle", "--state", statePath, "--approve-signed-bundle-authority-identity", authority, "--bundle", configuration.bundlePath, "--bundle-sha256", configuration.bundleDigest, "--bundle-bytes", "1024", "--public-key", configuration.publicKeyHex, "--signature", configuration.signatureHex, "--approved-by", "owner"}
	stdout.Reset()
	stderr.Reset()
	code := runSetupWithDependencies(args, &stdout, &stderr, fixedSetupClock{setupTimeCLI().Add(time.Second)}, inference, postgresProbe, executeSetupKMS, executeSetupEnvelopeStorage, executeSetupGitHubPermission, executeSetupGitHubWebhook, executeSetupSharedRateLimit, executeSetupReplicaReconciliation, executor)
	if code != 0 || stderr.Len() != 0 || calls != 1 || !strings.Contains(stdout.String(), `"key":"signed_bundle_validated"`) || !strings.Contains(stdout.String(), `"state":"passed"`) {
		t.Fatalf("result=(%d,%q,%q,%d)", code, stdout.String(), stderr.String(), calls)
	}
	for _, forbidden := range []string{configuration.bundlePath, configuration.publicKeyHex, configuration.signatureHex} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatal("bundle input leaked")
		}
	}
}

func TestSetupTUIServiceRunsSignedBundleCheck(t *testing.T) {
	root := t.TempDir()
	statePath := initializedSetupTUIStateForProfile(t, root, setupcore.ProfileAirGapped)
	state, err := setupcore.OpenStateFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	configuration := setupSignedBundleConfiguration{bundlePath: filepath.Join(root, "release.bundle"), bundleDigest: strings.Repeat("a", 64), bundleBytes: 1024, publicKeyHex: strings.Repeat("b", 64), signatureHex: strings.Repeat("c", 128)}
	authority, _ := deriveSetupSignedBundleAuthority(configuration)
	calls := 0
	service := &setupTUIService{state: state, clock: fixedSetupClock{setupTimeCLI().Add(time.Second)}, getenv: func(string) string { return "" }, signedBundleExecutor: func(_ context.Context, got setupSignedBundleConfiguration) (string, error) {
		calls++
		if got != configuration {
			t.Fatal("crossed bundle configuration")
		}
		return strings.Repeat("d", 64), nil
	}, signedBundleAuthorityIdentity: authority, signedBundlePath: configuration.bundlePath, signedBundleDigest: configuration.bundleDigest, signedBundleBytes: configuration.bundleBytes, signedBundlePublicKey: configuration.publicKeyHex, signedBundleSignature: configuration.signatureHex, signedBundleApprovedBy: "owner"}
	plan, _ := state.Current(context.Background())
	_, receipt, err := service.RunCheck(context.Background(), setupcore.CheckSignedBundleValidated, plan.Identity())
	if err != nil || receipt.State() != setupcore.CheckPassed || calls != 1 {
		t.Fatalf("bundle=%s err=%v calls=%d", receipt.State(), err, calls)
	}
}

func TestSetupSignedBundleProbeSeparatesUnavailableAndInvalid(t *testing.T) {
	plan, _ := setupcore.NewPlan(setupcore.ProfileAirGapped, "tenant-a", "repo-a", "owner", setupTimeCLI())
	configuration := setupSignedBundleConfiguration{bundlePath: "/private/release.bundle", bundleDigest: strings.Repeat("a", 64), bundleBytes: 1024, publicKeyHex: strings.Repeat("b", 64), signatureHex: strings.Repeat("c", 128)}
	for _, test := range []struct {
		err         error
		unavailable bool
	}{{setupcore.ErrSignedBundleUnavailable, true}, {setupcore.ErrSignedBundleVerificationFailed, false}, {setupcore.ErrInvalidSignedBundle, false}, {errors.New("other"), false}} {
		probe, _, err := newSetupSignedBundleProbe(plan, configuration, func(context.Context, setupSignedBundleConfiguration) (string, error) { return "", test.err })
		if err != nil {
			t.Fatal(err)
		}
		result := probe.Probe(context.Background())
		if test.unavailable && result != setupcore.NewUnavailableSignedBundleProbeResult() {
			t.Fatalf("unavailable=%#v", result)
		}
		if !test.unavailable && result != setupcore.NewInvalidSignedBundleProbeResult() {
			t.Fatalf("invalid=%#v", result)
		}
	}
}

func TestSetupCLIRejectsSignedBundleFieldsOnOtherChecksBeforeStateAccess(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	var stdout, stderr bytes.Buffer
	code := runSetupWithClock([]string{"check", "rate-limit", "--state", missing, "--approve-shared-rate-limit-authority-identity", strings.Repeat("a", 64), "--postgres-database-authority-identity", strings.Repeat("b", 64), "--bundle", "/private/release.bundle", "--approved-by", "owner"}, &stdout, &stderr, fixedSetupClock{setupTimeCLI()})
	if code != 2 || stdout.Len() != 0 {
		t.Fatalf("result=(%d,%q,%q)", code, stdout.String(), stderr.String())
	}
}
