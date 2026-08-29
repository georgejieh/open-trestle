package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestExecuteRepositoryAcquisitionBuildsAcquiredReceipts(t *testing.T) {
	for _, artifact := range []evidence.RepositoryAcquisitionArtifact{evidence.AcquisitionArtifactManifest, evidence.AcquisitionArtifactManifestAndContent} {
		t.Run(string(artifact), func(t *testing.T) {
			fixture := mustExecutionFixture(t, artifact)
			adapter := &fakeSourceAdapter{identity: fixture.adapter, result: fixture.acquiredResult()}
			receipt, err := ExecuteRepositoryAcquisition(context.Background(), fixture.request, adapter)
			if err != nil {
				t.Fatalf("ExecuteRepositoryAcquisition() error = %v", err)
			}
			expected, err := evidence.NewRepositoryAcquisitionReceipt(fixture.request, evidence.AcquisitionOutcomeAcquired, evidence.AcquisitionReasonNone, fixture.manifest, fixture.resultContents())
			if err != nil {
				t.Fatalf("NewRepositoryAcquisitionReceipt() error = %v", err)
			}
			if receipt != expected || adapter.calls != 1 || adapter.received.Identity() != fixture.request.Identity() {
				t.Fatalf("execution = (%#v, calls %d, received %#v), want %#v", receipt, adapter.calls, adapter.received, expected)
			}
		})
	}
}

func TestExecuteRepositoryAcquisitionBuildsBlockedAndFailedReceipts(t *testing.T) {
	fixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifestAndContent)
	testCases := []SourceAdapterResult{
		{Outcome: evidence.AcquisitionOutcomeBlocked, Reason: evidence.AcquisitionReasonPolicyBlocked},
		{Outcome: evidence.AcquisitionOutcomeFailed, Reason: evidence.AcquisitionReasonAdapterFailure},
	}
	for _, result := range testCases {
		t.Run(string(result.Outcome), func(t *testing.T) {
			adapter := &fakeSourceAdapter{identity: fixture.adapter, result: result}
			execution, err := ExecuteRepositoryAcquisitionWithEvidence(context.Background(), fixture.request, adapter)
			if err != nil || execution.Outcome() != result.Outcome || execution.Receipt().Reason() != result.Reason || execution.HasLocalGitEvidence() || adapter.calls != 1 {
				t.Fatalf("execution = (%#v, %v), calls = %d", execution, err, adapter.calls)
			}
			compatibility := &fakeSourceAdapter{identity: fixture.adapter, result: result}
			receipt, err := ExecuteRepositoryAcquisition(context.Background(), fixture.request, compatibility)
			if err != nil || receipt != execution.Receipt() || compatibility.calls != 1 {
				t.Fatalf("compatibility receipt = (%#v, %v), calls = %d", receipt, err, compatibility.calls)
			}
		})
	}
}

func TestExecuteRepositoryAcquisitionRejectsInvalidInputsBeforeAcquire(t *testing.T) {
	fixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifestAndContent)
	other, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "other-git", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	if err != nil {
		t.Fatalf("NewSourceAdapterIdentity() error = %v", err)
	}
	testCases := []struct {
		name    string
		ctx     context.Context
		request evidence.RepositoryAcquisitionRequest
		adapter SourceAdapter
	}{
		{name: "nil context", request: fixture.request, adapter: &fakeSourceAdapter{identity: fixture.adapter}},
		{name: "zero request", ctx: context.Background(), adapter: &fakeSourceAdapter{identity: fixture.adapter}},
		{name: "nil adapter", ctx: context.Background(), request: fixture.request},
		{name: "typed nil adapter", ctx: context.Background(), request: fixture.request, adapter: (*fakeSourceAdapter)(nil)},
		{name: "zero adapter identity", ctx: context.Background(), request: fixture.request, adapter: &fakeSourceAdapter{}},
		{name: "mismatched adapter identity", ctx: context.Background(), request: fixture.request, adapter: &fakeSourceAdapter{identity: other}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			receipt, err := ExecuteRepositoryAcquisition(testCase.ctx, testCase.request, testCase.adapter)
			if err == nil || receipt.Identity() != "" {
				t.Fatalf("ExecuteRepositoryAcquisition() = (%#v, %v)", receipt, err)
			}
			if adapter, ok := testCase.adapter.(*fakeSourceAdapter); ok && adapter != nil && adapter.calls != 0 {
				t.Fatalf("Acquire() calls = %d, want 0", adapter.calls)
			}
		})
	}
}

func TestExecuteRepositoryAcquisitionHonorsCancellation(t *testing.T) {
	fixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifestAndContent)
	t.Run("before call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		adapter := &fakeSourceAdapter{identity: fixture.adapter, result: fixture.acquiredResult()}
		receipt, err := ExecuteRepositoryAcquisition(ctx, fixture.request, adapter)
		if !errors.Is(err, context.Canceled) || receipt.Identity() != "" || adapter.calls != 0 {
			t.Fatalf("execution = (%#v, %v), calls = %d", receipt, err, adapter.calls)
		}
	})
	t.Run("during call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		adapter := &fakeSourceAdapter{identity: fixture.adapter}
		adapter.acquire = func(context.Context, evidence.RepositoryAcquisitionRequest) SourceAdapterResult {
			cancel()
			return fixture.acquiredResult()
		}
		receipt, err := ExecuteRepositoryAcquisition(ctx, fixture.request, adapter)
		if !errors.Is(err, context.Canceled) || receipt.Identity() != "" || adapter.calls != 1 {
			t.Fatalf("execution = (%#v, %v), calls = %d", receipt, err, adapter.calls)
		}
	})
}

func TestExecuteRepositoryAcquisitionRejectsInvalidResults(t *testing.T) {
	fixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifestAndContent)
	testCases := []struct {
		name   string
		result SourceAdapterResult
	}{
		{name: "invalid outcome", result: SourceAdapterResult{Outcome: evidence.RepositoryAcquisitionOutcome("unknown")}},
		{name: "acquired reason", result: SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonAdapterFailure, Manifest: fixture.manifest, Contents: fixture.resultContents()}},
		{name: "missing content", result: SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: fixture.manifest}},
		{name: "extra content", result: SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: fixture.manifest, Contents: map[string][]byte{"file": []byte("content"), "extra": nil}}},
		{name: "wrong content", result: SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: fixture.manifest, Contents: map[string][]byte{"file": []byte("changed")}}},
		{name: "blocked content", result: SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeBlocked, Reason: evidence.AcquisitionReasonPolicyBlocked, Contents: map[string][]byte{"file": nil}}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			adapter := &fakeSourceAdapter{identity: fixture.adapter, result: testCase.result}
			receipt, err := ExecuteRepositoryAcquisition(context.Background(), fixture.request, adapter)
			if err == nil || receipt.Identity() != "" || adapter.calls != 1 {
				t.Fatalf("execution = (%#v, %v), calls = %d", receipt, err, adapter.calls)
			}
		})
	}
}

func TestExecuteRepositoryAcquisitionIgnoresContentMapOrder(t *testing.T) {
	fixture := mustTwoFileExecutionFixture(t)
	first := &fakeSourceAdapter{identity: fixture.adapter, result: fixture.acquiredResult()}
	secondResult := fixture.acquiredResult()
	secondResult.Contents = map[string][]byte{"b": []byte("second"), "a": []byte("first")}
	second := &fakeSourceAdapter{identity: fixture.adapter, result: secondResult}
	firstReceipt, firstErr := ExecuteRepositoryAcquisition(context.Background(), fixture.request, first)
	secondReceipt, secondErr := ExecuteRepositoryAcquisition(context.Background(), fixture.request, second)
	if firstErr != nil || secondErr != nil || firstReceipt.Identity() != secondReceipt.Identity() {
		t.Fatalf("receipts = (%#v, %v) (%#v, %v)", firstReceipt, firstErr, secondReceipt, secondErr)
	}
}

func TestExecuteRepositoryAcquisitionDoesNotRetainResultContent(t *testing.T) {
	fixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifestAndContent)
	result := fixture.acquiredResult()
	adapter := &fakeSourceAdapter{identity: fixture.adapter, result: result}
	receipt, err := ExecuteRepositoryAcquisition(context.Background(), fixture.request, adapter)
	if err != nil {
		t.Fatalf("ExecuteRepositoryAcquisition() error = %v", err)
	}
	identity := receipt.Identity()
	result.Contents["file"][0] = 'X'
	adapter.result.Contents["file"][1] = 'Y'
	if receipt.Identity() != identity || receipt.ContentCoverage() != evidence.ContentCoverageComplete {
		t.Fatal("result mutation changed receipt")
	}
}

func TestExecuteRepositoryAcquisitionPropagatesAdapterPanic(t *testing.T) {
	fixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifest)
	adapter := &fakeSourceAdapter{identity: fixture.adapter}
	adapter.acquire = func(context.Context, evidence.RepositoryAcquisitionRequest) SourceAdapterResult {
		panic("adapter panic")
	}
	defer func() {
		if recovered := recover(); recovered != "adapter panic" {
			t.Fatalf("recovered = %#v", recovered)
		}
	}()
	_, _ = ExecuteRepositoryAcquisition(context.Background(), fixture.request, adapter)
}

func TestRepositoryAcquisitionExecutionZeroValue(t *testing.T) {
	var execution RepositoryAcquisitionExecution
	if execution.Identity() != "" || execution.Receipt().Identity() != "" || execution.ReceiptIdentity() != "" || execution.RequestIdentity() != "" || execution.SourceAdapterIdentity() != "" || execution.Outcome() != "" || execution.HasLocalGitEvidence() || execution.RevisionIdentity() != "" || execution.ManifestIdentity() != "" || execution.GitCommitIdentity() != "" || execution.GitTreeGraphIdentity() != "" || execution.CorrespondenceIdentity() != "" {
		t.Fatalf("zero execution = %#v", execution)
	}
}

func TestExecuteRepositoryAcquisitionWithEvidenceReturnsGenericExecution(t *testing.T) {
	fixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifestAndContent)
	firstAdapter := &fakeSourceAdapter{identity: fixture.adapter, result: fixture.acquiredResult()}
	first, err := ExecuteRepositoryAcquisitionWithEvidence(context.Background(), fixture.request, firstAdapter)
	if err != nil {
		t.Fatalf("ExecuteRepositoryAcquisitionWithEvidence() error = %v", err)
	}
	expectedReceipt, err := evidence.NewRepositoryAcquisitionReceipt(fixture.request, evidence.AcquisitionOutcomeAcquired, evidence.AcquisitionReasonNone, fixture.manifest, fixture.resultContents())
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionReceipt() error = %v", err)
	}
	if first.Identity() == "" || first.Receipt() != expectedReceipt || first.ReceiptIdentity() != expectedReceipt.Identity() || first.RequestIdentity() != fixture.request.Identity() || first.SourceAdapterIdentity() != fixture.adapter.Identity() || first.Outcome() != evidence.AcquisitionOutcomeAcquired || firstAdapter.calls != 1 {
		t.Fatalf("execution = %#v, calls = %d", first, firstAdapter.calls)
	}
	if first.HasLocalGitEvidence() || first.RevisionIdentity() != "" || first.ManifestIdentity() != "" || first.GitCommitIdentity() != "" || first.GitTreeGraphIdentity() != "" || first.CorrespondenceIdentity() != "" {
		t.Fatalf("generic execution reported local Git evidence: %#v", first)
	}
	if want := expectedRepositoryAcquisitionExecutionIdentity(first); first.Identity() != want {
		t.Fatalf("Identity() = %q, want %q", first.Identity(), want)
	}
	secondAdapter := &fakeSourceAdapter{identity: fixture.adapter, result: fixture.acquiredResult()}
	second, err := ExecuteRepositoryAcquisitionWithEvidence(context.Background(), fixture.request, secondAdapter)
	if err != nil || second != first || secondAdapter.calls != 1 {
		t.Fatalf("second execution = (%#v, %v), calls = %d", second, err, secondAdapter.calls)
	}
	compatibilityAdapter := &fakeSourceAdapter{identity: fixture.adapter, result: fixture.acquiredResult()}
	receipt, err := ExecuteRepositoryAcquisition(context.Background(), fixture.request, compatibilityAdapter)
	if err != nil || receipt != first.Receipt() || compatibilityAdapter.calls != 1 {
		t.Fatalf("compatibility receipt = (%#v, %v), calls = %d", receipt, err, compatibilityAdapter.calls)
	}
}

func TestExecuteRepositoryAcquisitionWithEvidenceReturnsZeroOnCancellation(t *testing.T) {
	fixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifestAndContent)
	t.Run("before call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		adapter := &fakeSourceAdapter{identity: fixture.adapter, result: fixture.acquiredResult()}
		execution, err := ExecuteRepositoryAcquisitionWithEvidence(ctx, fixture.request, adapter)
		if !errors.Is(err, context.Canceled) || execution.Identity() != "" || adapter.calls != 0 {
			t.Fatalf("execution = (%#v, %v), calls = %d", execution, err, adapter.calls)
		}
	})
	t.Run("during call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		adapter := &fakeSourceAdapter{identity: fixture.adapter}
		adapter.acquire = func(context.Context, evidence.RepositoryAcquisitionRequest) SourceAdapterResult {
			cancel()
			return fixture.acquiredResult()
		}
		execution, err := ExecuteRepositoryAcquisitionWithEvidence(ctx, fixture.request, adapter)
		if !errors.Is(err, context.Canceled) || execution.Identity() != "" || adapter.calls != 1 {
			t.Fatalf("execution = (%#v, %v), calls = %d", execution, err, adapter.calls)
		}
	})
}

func expectedRepositoryAcquisitionExecutionIdentity(execution RepositoryAcquisitionExecution) string {
	preimage := struct {
		Contract                string                                `json:"contract"`
		SchemaVersion           int                                   `json:"schema_version"`
		RequestIdentity         string                                `json:"request_identity"`
		ReceiptIdentity         string                                `json:"receipt_identity"`
		SourceAdapterIdentity   string                                `json:"source_adapter_identity"`
		Outcome                 evidence.RepositoryAcquisitionOutcome `json:"outcome"`
		LocalGitEvidencePresent bool                                  `json:"local_git_evidence_present"`
		RevisionIdentity        string                                `json:"revision_identity"`
		ManifestIdentity        string                                `json:"manifest_identity"`
		GitCommitIdentity       string                                `json:"git_commit_identity"`
		GitTreeGraphIdentity    string                                `json:"git_tree_graph_identity"`
		CorrespondenceIdentity  string                                `json:"correspondence_identity"`
	}{
		Contract:                "open-trestle/repository-acquisition-execution",
		SchemaVersion:           1,
		RequestIdentity:         execution.RequestIdentity(),
		ReceiptIdentity:         execution.ReceiptIdentity(),
		SourceAdapterIdentity:   execution.SourceAdapterIdentity(),
		Outcome:                 execution.Outcome(),
		LocalGitEvidencePresent: execution.HasLocalGitEvidence(),
		RevisionIdentity:        execution.RevisionIdentity(),
		ManifestIdentity:        execution.ManifestIdentity(),
		GitCommitIdentity:       execution.GitCommitIdentity(),
		GitTreeGraphIdentity:    execution.GitTreeGraphIdentity(),
		CorrespondenceIdentity:  execution.CorrespondenceIdentity(),
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func TestCloneSourceAdapterResultContentHonorsCancellation(t *testing.T) {
	content := make([]byte, 3<<20)
	ctx := &stagedCancellationContext{Context: context.Background(), remaining: 2}
	if cloned, err := cloneSourceAdapterResultContent(ctx, content); !errors.Is(err, context.Canceled) || cloned != nil {
		t.Fatalf("cloneSourceAdapterResultContent() = (%d bytes, %v)", len(cloned), err)
	}
	cloned, err := cloneSourceAdapterResultContent(context.Background(), []byte("content"))
	if err != nil || string(cloned) != "content" {
		t.Fatalf("cloneSourceAdapterResultContent() = (%q, %v)", cloned, err)
	}
}

type stagedCancellationContext struct {
	context.Context
	remaining int
	canceled  bool
}

func (c *stagedCancellationContext) Err() error {
	if c.canceled {
		return context.Canceled
	}
	if c.remaining == 0 {
		c.canceled = true
		return context.Canceled
	}
	c.remaining--
	return nil
}

func TestCheckedSourceAdapterResultContentAdd(t *testing.T) {
	limit := int(maxSourceAdapterResultContentBytes)
	if got, err := checkedSourceAdapterResultContentAdd(0, limit); err != nil || got != maxSourceAdapterResultContentBytes {
		t.Fatalf("checkedSourceAdapterResultContentAdd() = (%d, %v)", got, err)
	}
	if got, err := checkedSourceAdapterResultContentAdd(maxSourceAdapterResultContentBytes, 0); err != nil || got != maxSourceAdapterResultContentBytes {
		t.Fatalf("limit plus zero = (%d, %v)", got, err)
	}
	for _, values := range []struct {
		total int64
		size  int
	}{{total: maxSourceAdapterResultContentBytes, size: 1}, {total: -1}, {size: -1}} {
		if _, err := checkedSourceAdapterResultContentAdd(values.total, values.size); err == nil {
			t.Fatalf("checkedSourceAdapterResultContentAdd(%d, %d) succeeded", values.total, values.size)
		}
	}
}

type fakeSourceAdapter struct {
	identity evidence.SourceAdapterIdentity
	result   SourceAdapterResult
	calls    int
	received evidence.RepositoryAcquisitionRequest
	acquire  func(context.Context, evidence.RepositoryAcquisitionRequest) SourceAdapterResult
}

func (a *fakeSourceAdapter) Identity() evidence.SourceAdapterIdentity {
	return a.identity
}

func (a *fakeSourceAdapter) Acquire(ctx context.Context, request evidence.RepositoryAcquisitionRequest) SourceAdapterResult {
	a.calls++
	a.received = request
	if a.acquire != nil {
		return a.acquire(ctx, request)
	}
	return a.result
}

type executionFixture struct {
	adapter  evidence.SourceAdapterIdentity
	request  evidence.RepositoryAcquisitionRequest
	manifest evidence.RepositoryManifest
	contents map[string][]byte
}

func mustExecutionFixture(t *testing.T, artifact evidence.RepositoryAcquisitionArtifact) executionFixture {
	t.Helper()
	return mustExecutionFixtureWithFiles(t, artifact, map[string][]byte{"file": []byte("content")})
}

func mustTwoFileExecutionFixture(t *testing.T) executionFixture {
	t.Helper()
	return mustExecutionFixtureWithFiles(t, evidence.AcquisitionArtifactManifestAndContent, map[string][]byte{"a": []byte("first"), "b": []byte("second")})
}

func mustExecutionFixtureWithFiles(t *testing.T, artifact evidence.RepositoryAcquisitionArtifact, contents map[string][]byte) executionFixture {
	t.Helper()
	capabilities := []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest}
	if artifact == evidence.AcquisitionArtifactManifestAndContent {
		capabilities = append(capabilities, evidence.SourceCapabilityReadContent)
	}
	adapter, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "local-git", "1.0.0", capabilities)
	if err != nil {
		t.Fatalf("NewSourceAdapterIdentity() error = %v", err)
	}
	repository, err := evidence.NewRepositoryIdentity("git.example.com", []string{"team"}, "repo")
	if err != nil {
		t.Fatalf("NewRepositoryIdentity() error = %v", err)
	}
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, "0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatalf("NewRevisionIdentity() error = %v", err)
	}
	request, err := evidence.NewRepositoryAcquisitionRequest(repository, revision, adapter, artifact, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionRequest() error = %v", err)
	}
	files := make([]evidence.RepositoryFile, 0, len(contents))
	for path, content := range contents {
		file, err := evidence.NewRepositoryFile(path, content)
		if err != nil {
			t.Fatalf("NewRepositoryFile() error = %v", err)
		}
		files = append(files, file)
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	if err != nil {
		t.Fatalf("NewRepositoryManifest() error = %v", err)
	}
	return executionFixture{adapter: adapter, request: request, manifest: manifest, contents: cloneContents(contents)}
}

func (f executionFixture) acquiredResult() SourceAdapterResult {
	return SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: f.manifest, Contents: f.resultContents()}
}

func (f executionFixture) resultContents() map[string][]byte {
	if f.request.Artifact() == evidence.AcquisitionArtifactManifest {
		return nil
	}
	return cloneContents(f.contents)
}

func cloneContents(contents map[string][]byte) map[string][]byte {
	cloned := make(map[string][]byte, len(contents))
	for path, content := range contents {
		cloned[path] = append([]byte{}, content...)
	}
	return cloned
}
