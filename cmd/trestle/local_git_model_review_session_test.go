package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/localreview"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type localModelSessionClock struct{}

func (localModelSessionClock) Now() time.Time { return time.Now().UTC() }

func localModelSessionOptions(t *testing.T, f *localModelFixture) (localreview.SessionOptions, *os.Root) {
	t.Helper()
	inventoryBytes, err := os.ReadFile(f.inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, err := os.ReadFile(f.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryBytes))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyBytes), inventory)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"private", "team"}, "sample")
	if err != nil {
		t.Fatal(err)
	}
	objects, err := os.OpenRoot(f.objects)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := runtimecatalog.NewEnvironmentOpenAICredentialResolver(func(name string) string {
		if name == "OPEN_TRESTLE_PROVIDER_LOCAL_TEST_A" || name == "OPEN_TRESTLE_PROVIDER_LOCAL_TEST_B" {
			return localModelKey
		}
		t.Error("session accessed an unapproved credential reference")
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	return localreview.SessionOptions{TenantID: "tenant-local", RepositoryID: "repository-local", Repository: repository, ObjectsRoot: objects, Inventory: inventory, Policy: policy, Egress: localreview.EgressLocalOnly, Credentials: credentials, Clock: localModelSessionClock{}, Timeout: 5 * time.Second, ArtifactCapacity: 128}, objects
}

func localModelNewSession(t *testing.T, options localreview.SessionOptions) *localreview.Session {
	t.Helper()
	session, err := localreview.NewSession(options)
	if err != nil {
		_ = options.ObjectsRoot.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := session.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return session
}

func localModelPrepare(t *testing.T, session *localreview.Session, f *localModelFixture, runID string) runtimecatalog.PreparedReviewRun {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-local", "repository-local", runID)
	if err != nil {
		t.Fatal(err)
	}
	base, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, f.base)
	if err != nil {
		t.Fatal(err)
	}
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, f.head)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := session.Prepare(context.Background(), scope, localModelDigest([]byte(runID)), base, head)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func localModelSessionReceipt(t *testing.T, result localreview.Result) localModelReceipt {
	t.Helper()
	encoded, err := localreview.EncodeResult(result)
	if err != nil || len(encoded) > 256<<10 {
		t.Fatal("session result is not bounded canonical JSON")
	}
	var receipt localModelReceipt
	if err := json.Unmarshal(encoded, &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestRunLocalGitModelReviewUsesDirectCallerContext(t *testing.T) {
	for _, canceledBefore := range []bool{true, false} {
		name := "during HTTP wait"
		if canceledBefore {
			name = "already canceled"
		}
		t.Run(name, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "wait"})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if canceledBefore {
				cancel()
			}
			var stdout, stderr bytes.Buffer
			done := make(chan int, 1)
			go func() { done <- runWithContext(ctx, f.args, &stdout, &stderr) }()
			if !canceledBefore {
				select {
				case <-f.generation.entered:
				case code := <-done:
					t.Fatalf("returned %d before provider wait", code)
				case <-time.After(3 * time.Second):
					t.Fatal("provider wait not reached")
				}
				cancel()
				select {
				case <-f.generation.canceled:
				case <-time.After(3 * time.Second):
					t.Fatal("caller cancellation did not reach real HTTP")
				}
			}
			select {
			case code := <-done:
				var receipt localModelReceipt
				if code != 3 || json.Unmarshal(stdout.Bytes(), &receipt) != nil || receipt.Status != "canceled" || receipt.CI != "inconclusive" || stderr.Len() != 0 {
					t.Fatal("direct caller cancellation did not produce bounded inconclusive disposition")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("context-aware CLI did not stop")
			}
			gc, _ := f.generation.snapshot()
			vc, _ := f.verification.snapshot()
			if vc != 0 || canceledBefore && gc != 0 || !canceledBefore && gc != 1 {
				t.Fatal("canceled caller gained a new model attempt")
			}
		})
	}
}

func TestLocalModelSessionCloseCancelsDrainsThenClosesRoot(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "wait"})
	options, objects := localModelSessionOptions(t, f)
	session := localModelNewSession(t, options)
	prepared := localModelPrepare(t, session, f, "close-while-dispatching")
	type outcome struct {
		result localreview.Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() { result, err := session.Run(context.Background(), prepared); done <- outcome{result, err} }()
	select {
	case <-f.generation.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("model was not dispatched")
	}
	if _, err := objects.Stat("."); err != nil {
		t.Fatal("session closed source root while work was active")
	}
	cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := session.Close(cleanup); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.generation.canceled:
	case <-cleanup.Done():
		t.Fatal("provider cancellation was not observed within the Close deadline")
	}
	select {
	case out := <-done:
		if out.err != nil {
			t.Fatal(out.err)
		}
		receipt := localModelSessionReceipt(t, out.result)
		if receipt.Status != "canceled" || receipt.RunStatus != "canceled" {
			t.Fatal("Close did not finalize canceled journal")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not drain the active Run owner")
	}
	if _, err := objects.Stat("."); err == nil {
		t.Fatal("Close retained a drained source root")
	}
	if err := session.Close(cleanup); err != nil {
		t.Fatal("Close is not idempotent")
	}
}

func TestLocalModelSessionRefusesDuplicateConcurrentAndClaimedRuns(t *testing.T) {
	for _, mode := range []string{"complete", "malformed", "wait"} {
		t.Run(mode, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: mode})
			options, _ := localModelSessionOptions(t, f)
			session := localModelNewSession(t, options)
			prepared := localModelPrepare(t, session, f, "same-run")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := session.Run(ctx, prepared); done <- err }()
			if mode == "wait" {
				select {
				case <-f.generation.entered:
				case <-time.After(3 * time.Second):
					t.Fatal("claimed attempt not reached")
				}
			} else {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("first run did not finish")
				}
			}
			duplicate, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if _, err := session.Run(duplicate, prepared); !errors.Is(err, localreview.ErrReviewRunAlreadyExists) {
				t.Fatalf("existing identity was not refused: %v", err)
			}
			if mode == "wait" {
				scope, _ := audit.NewReviewScope("tenant-local", "repository-local", "same-run")
				base, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, f.base)
				head, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, f.head)
				relabeled, err := session.Prepare(duplicate, scope, strings.Repeat("f", 64), base, head)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := session.Run(duplicate, relabeled); !errors.Is(err, localreview.ErrReviewRunAlreadyExists) {
					t.Fatal("new host label bypassed an existing scope claim")
				}
				other := localModelPrepare(t, session, f, "other-active-run")
				if _, err := session.Run(duplicate, other); !errors.Is(err, localreview.ErrSessionBusy) {
					t.Fatal("one session admitted concurrent work under another identity")
				}
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("claimed run did not cancel")
				}
				if _, err := session.Run(duplicate, prepared); !errors.Is(err, localreview.ErrReviewRunAlreadyExists) {
					t.Fatal("canceled claim became dispatchable")
				}
			}
			gc, _ := f.generation.snapshot()
			vc, _ := f.verification.snapshot()
			if gc != 1 || mode != "complete" && vc != 0 || mode == "complete" && vc != 1 {
				t.Fatal("duplicate admission repeated a model effect")
			}
		})
	}
}

func TestLocalModelSessionRejectsCrossBoundPreparedInput(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	options, _ := localModelSessionOptions(t, f)
	owner := localModelNewSession(t, options)
	prepared := localModelPrepare(t, owner, f, "bound-run")
	for _, mismatch := range []string{"tenant", "repository partition", "source root", "repository identity", "runtime policy", "review policy"} {
		t.Run(mismatch, func(t *testing.T) {
			other, _ := localModelSessionOptions(t, f)
			switch mismatch {
			case "tenant":
				other.TenantID = "other-tenant"
			case "repository partition":
				other.RepositoryID = "other-partition"
			case "source root":
				_ = other.ObjectsRoot.Close()
				var err error
				other.ObjectsRoot, err = os.OpenRoot(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
			case "runtime policy", "review policy":
				encoded, err := os.ReadFile(f.policyPath)
				if err != nil {
					t.Fatal(err)
				}
				var policy map[string]any
				if err := json.Unmarshal(encoded, &policy); err != nil {
					t.Fatal(err)
				}
				if mismatch == "runtime policy" {
					policy["max_output_tokens"] = 4097
				} else {
					policy["review_policy_identity"] = strings.Repeat("f", 64)
				}
				other.Policy, err = runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(localModelJSON(t, policy)), other.Inventory)
				if err != nil {
					t.Fatal(err)
				}
			case "repository identity":
				var err error
				other.Repository, err = evidence.NewRepositoryIdentity("example.test", []string{"other"}, "repository")
				if err != nil {
					t.Fatal(err)
				}
			}
			session := localModelNewSession(t, other)
			if _, err := session.Run(context.Background(), prepared); !errors.Is(err, localreview.ErrPreparedReviewMismatch) {
				t.Fatal("cross-bound prepared authority reached execution")
			}
		})
	}
	gc, _ := f.generation.snapshot()
	vc, _ := f.verification.snapshot()
	if gc != 0 || vc != 0 {
		t.Fatal("invalid prepared authority reached a provider")
	}
}

func TestLocalModelSessionCapacityAndTimingRemainBounded(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	options, _ := localModelSessionOptions(t, f)
	options.ArtifactCapacity = 2
	session := localModelNewSession(t, options)
	if session.RenewalInterval() != 10*time.Second {
		t.Fatal("production renewal default is not one-third of a 30-second lease")
	}
	prepared := localModelPrepare(t, session, f, "capacity-run")
	result, err := session.Run(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	receipt := localModelSessionReceipt(t, result)
	if receipt.CI == "pass" || receipt.RunStatus == "active" || receipt.Readiness != "" || !strings.Contains(receipt.Failure, "resource") {
		t.Fatal("artifact capacity failure produced downstream success")
	}
	gc, _ := f.generation.snapshot()
	vc, _ := f.verification.snapshot()
	if gc != 0 || vc != 0 {
		t.Fatal("artifact capacity failure reached model dispatch")
	}
}

func TestLocalModelSessionCannotReceiveForgeOrCustomHandlerCapabilities(t *testing.T) {
	allowed := map[string]bool{"TenantID": true, "RepositoryID": true, "Repository": true, "ObjectsRoot": true, "ObjectStoreProfile": true, "ObjectAlgorithm": true, "Inventory": true, "Policy": true, "Egress": true, "Credentials": true, "Clock": true, "Timeout": true, "ArtifactCapacity": true, "RenewalInterval": true, "Retention": true, "RetainedMemoryInput": true}
	options := reflect.TypeOf(localreview.SessionOptions{})
	for name, want := range map[string]reflect.Type{
		"ObjectStoreProfile": reflect.TypeOf(scm.LocalGitObjectStoreProfile("")),
		"ObjectAlgorithm":    reflect.TypeOf(evidence.RevisionAlgorithm("")),
	} {
		field, ok := options.FieldByName(name)
		if !ok || field.Type != want || field.Type.Kind() != reflect.String {
			t.Fatalf("%s must remain the exact scalar configuration type", name)
		}
	}
	retained, ok := options.FieldByName("RetainedMemoryInput")
	if !ok || retained.Type != reflect.TypeOf((*runtimeconfig.RetainedMemoryInput)(nil)) {
		t.Fatal("retained memory option must be a protected input pointer")
	}
	for i := 0; i < options.NumField(); i++ {
		field := options.Field(i)
		if !allowed[field.Name] {
			t.Fatalf("unexpected session authority option %s", field.Name)
		}
	}
}

func TestLocalModelSessionFailedConstructionLeavesRootWithCaller(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	options, objects := localModelSessionOptions(t, f)
	defer objects.Close()
	options.Timeout = 0
	if session, err := localreview.NewSession(options); err == nil || session != nil {
		t.Fatal("unbounded session was constructed")
	}
	if _, err := objects.Stat("."); err != nil {
		t.Fatal("failed constructor stole caller source-root ownership")
	}
}

func TestLocalModelSessionPrepareRefusesCrossScopeAndPreCanceledCaller(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	options, _ := localModelSessionOptions(t, f)
	session := localModelNewSession(t, options)
	scope, err := audit.NewReviewScope("other-tenant", "repository-local", "other-run")
	if err != nil {
		t.Fatal(err)
	}
	base, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, f.base)
	head, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, f.head)
	if _, err := session.Prepare(context.Background(), scope, strings.Repeat("a", 64), base, head); err == nil {
		t.Fatal("Prepare accepted a foreign audit/memory scope")
	}
	scope, _ = audit.NewReviewScope("tenant-local", "repository-local", "canceled-before-source")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := session.Prepare(ctx, scope, strings.Repeat("a", 64), base, head); err == nil {
		t.Fatal("Prepare ignored actual canceled caller")
	}
	gc, _ := f.generation.snapshot()
	vc, _ := f.verification.snapshot()
	if gc != 0 || vc != 0 {
		t.Fatal("invalid preparation executed a provider")
	}
}

func TestLocalModelSessionShortRenewalUsesRealPendingHTTPJournal(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "wait"})
	options, _ := localModelSessionOptions(t, f)
	options.RenewalInterval = 50 * time.Millisecond
	session := localModelNewSession(t, options)
	prepared := localModelPrepare(t, session, f, "short-renewal")
	for _, task := range prepared.Plan().Tasks() {
		if task.LeaseDurationMilliseconds() != 30000 {
			t.Fatal("test renewal setting changed immutable production lease identity")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		result localreview.Result
		err    error
	}
	done := make(chan outcome, 1)
	go func() { result, err := session.Run(ctx, prepared); done <- outcome{result, err} }()
	select {
	case <-f.generation.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("actual model wait not reached")
	}
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("caller context ended before renewal observation")
	}
	cancel()
	select {
	case out := <-done:
		if out.err != nil {
			t.Fatal(out.err)
		}
		receipt := localModelSessionReceipt(t, out.result)
		if receipt.Status != "canceled" || receipt.LeaseRenewals == 0 {
			t.Fatal("configured short renewal did not reach real pending HTTP journal")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("renewed model wait did not cancel")
	}
	gc, _ := f.generation.snapshot()
	vc, _ := f.verification.snapshot()
	if gc != 1 || vc != 0 {
		t.Fatal("renewal changed single-attempt model authority")
	}
}

func TestLocalModelUnstartedResultCannotAssertOpenedOrVerifiedWork(t *testing.T) {
	for _, status := range []string{"", "active", "succeeded", "findings", "no_candidates", "pass"} {
		result, err := localreview.NewUnstartedResult(status)
		if err == nil {
			t.Fatal("host-only result constructor admitted a work outcome")
		}
		if _, err := localreview.EncodeResult(result); err == nil {
			t.Fatal("refused constructor returned an encodable result")
		}
	}
	if _, err := localreview.EncodeResult(localreview.Result{}); err == nil {
		t.Fatal("zero result asserted a terminal receipt")
	}
	for status, code := range map[string]int{"refused": 4, "incomplete": 3, "canceled": 3, "failed": 1} {
		result, err := localreview.NewUnstartedResult(status)
		if err != nil || result.ExitCode() != code {
			t.Fatal("unstarted disposition mapping changed")
		}
		receipt := localModelSessionReceipt(t, result)
		if receipt.Status != status || receipt.RunStatus != "not_opened" || len(receipt.Tasks) != 0 || len(receipt.Audit) != 0 || receipt.Plan != "" || receipt.Request != "" || receipt.Output != "" || receipt.Context != "" || receipt.GenerationRequest != "" || receipt.VerificationRequest != "" || receipt.Readiness != "" || receipt.Diagnostics.Identity != "" || receipt.ComprehensiveClearance {
			t.Fatal("host-only result invented opened/verified authority")
		}
	}
}

func TestLocalModelFailedReadbackDoesNotClaimWorkNeverStarted(t *testing.T) {
	// This projection reads no source, model output, or claimed terminal state.
	var session *localreview.Session
	result := session.FailureResult()
	receipt := localModelSessionReceipt(t, result)
	if result.ExitCode() != 1 || receipt.Status != "failed" || receipt.RunStatus != "unknown" || receipt.Output != "" || receipt.Readiness != "" || len(receipt.Tasks) != 0 || len(receipt.Audit) != 0 || receipt.ComprehensiveClearance {
		t.Fatal("unavailable execution readback invented a lifecycle fact")
	}
}

type localModelForbiddenCredentialResolver struct{ calls int }

func (r *localModelForbiddenCredentialResolver) ResolveOpenAICredentials(string) (openai.APIKeyProvider, error) {
	r.calls++
	return nil, errors.New("credential resolution must not occur for unsupported storage")
}

func TestLocalModelSessionUnsupportedStorageRetainsRootBeforeCredentials(t *testing.T) {
	for _, mutation := range localModelUnsupportedStorageCases() {
		t.Run(mutation, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{})
			localModelMutateUnsupportedStorage(t, f, mutation)
			options, objects := localModelSessionOptions(t, f)
			defer objects.Close()
			resolver := &localModelForbiddenCredentialResolver{}
			options.Credentials = resolver
			session, err := localreview.NewSession(options)
			if session != nil || !errors.Is(err, localreview.ErrUnsupportedSource) {
				t.Fatal("unsupported storage did not return its closed source error")
			}
			if resolver.calls != 0 {
				t.Fatal("unsupported storage reached credential resolution")
			}
			if _, err := objects.Stat("."); err != nil {
				t.Fatal("failed storage admission stole caller root ownership")
			}
			if strings.Contains(err.Error(), f.objects) {
				t.Fatal("storage refusal disclosed the source-root path")
			}
			gc, _ := f.generation.snapshot()
			vc, _ := f.verification.snapshot()
			if gc != 0 || vc != 0 {
				t.Fatal("unsupported storage reached a provider")
			}
		})
	}
}
