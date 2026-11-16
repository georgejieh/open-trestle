package source

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

type mergeBaseAdapter struct {
	sourceAdapter
	result    scm.MergeBaseResult
	resolved  int
	requested []string
}

func (a *mergeBaseAdapter) Acquire(ctx context.Context, request evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	a.requested = append(a.requested, request.Revision().Digest())
	return a.sourceAdapter.Acquire(ctx, request)
}
func (a *mergeBaseAdapter) ResolveMergeBase(_ context.Context, _ scm.MergeBaseRequest) scm.MergeBaseResult {
	a.resolved++
	return a.result
}

func commitRevision(t *testing.T, digit string) evidence.RevisionIdentity {
	t.Helper()
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat(digit, 40))
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func executeMergeBaseInput(t *testing.T, adapter scm.SourceAdapter, input Input) (controlplane.TaskCompletion, artifact.Store, audit.ReviewScope) {
	t.Helper()
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	handler, err := NewHandler(store, adapter, fixedClock{at: time.UnixMilli(200)})
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-merge-base")
	inputArtifact, err := NewInputArtifact(scope, input, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("d", 64)}, time.UnixMilli(100), time.UnixMilli(10000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), inputArtifact, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	request := taskExecutionRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity())
	return handler.Execute(context.Background(), request), store, scope
}

// A merge-base input acquires the forge's merge base of the requested base
// and the head, and the snapshot records both and how the base was derived.
func TestHandlerAcquiresTheMergeBaseAndRecordsItsDerivation(t *testing.T) {
	repository, _, adapterIdentity, result := sourceFixture(t)
	requested, head, merge := commitRevision(t, "1"), commitRevision(t, "2"), commitRevision(t, "3")
	adapter := &mergeBaseAdapter{sourceAdapter: sourceAdapter{identity: adapterIdentity, result: result}, result: scm.MergeBaseResult{Outcome: scm.MergeBaseResolved, MergeBase: merge, Reason: evidence.AcquisitionReasonNone}}
	input, err := NewMergeBaseInput(repository, requested, head, adapterIdentity)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeInput(input)
	if err != nil || !strings.Contains(string(encoded), `"schema_version":3`) || !strings.Contains(string(encoded), `"base_derivation":"merge_base"`) {
		t.Fatalf("input=%s err=%v", encoded, err)
	}
	if parsed, err := ParseInput(encoded); err != nil || parsed.Identity() != input.Identity() {
		t.Fatalf("input readback: %v", err)
	} else if parsedHead, derived := parsed.MergeBaseHead(); !derived || parsedHead != head || parsed.Revision() != requested {
		t.Fatal("input readback lost the requested base or head")
	}
	completion, store, scope := executeMergeBaseInput(t, adapter, input)
	if completion.Status() != controlplane.TaskCompletionSucceeded || adapter.resolved != 1 || len(adapter.requested) != 1 || adapter.requested[0] != merge.Digest() {
		t.Fatalf("completion=%s resolved=%d acquired=%v", completion.Failure(), adapter.resolved, adapter.requested)
	}
	output, err := store.Get(context.Background(), scope, completion.OutputIdentity(), time.UnixMilli(201))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ParseSnapshotArtifact(output)
	if err != nil {
		t.Fatal(err)
	}
	derivation, derived := snapshot.Derivation()
	if snapshot.SchemaVersion() != 2 || !derived || snapshot.RevisionIdentity() != merge.Identity() || derivation.Method() != sourceoutput.RevisionDerivationForgeMergeBase || derivation.RequestedBaseIdentity() != requested.Identity() || derivation.HeadIdentity() != head.Identity() || derivation.MergeBase() != merge {
		t.Fatal("snapshot did not record the merge base and its derivation")
	}
	if !strings.Contains(string(output.Payload()), `"schema_version":2`) || !strings.Contains(string(output.Payload()), `"method":"forge_merge_base"`) {
		t.Fatalf("snapshot payload=%s", output.Payload())
	}
	assertClosedSchemaShape(t, "source-acquisition-input-v3.schema.json", encoded)
	assertClosedSchemaShape(t, "source-snapshot-v2.schema.json", output.Payload())
	payload := string(output.Payload())
	derivationStart := strings.Index(payload, `,"revision_derivation":`)
	for _, mutated := range []string{
		strings.Replace(payload, `"schema_version":2`, `"schema_version":1`, 1),
		payload[:derivationStart] + "}",
		strings.Replace(payload, `"merge_base_revision_digest":"`+merge.Digest()+`"`, `"merge_base_revision_digest":"`+head.Digest()+`"`, 1),
	} {
		forged, err := artifact.New(scope, artifact.KindSourceSnapshot, "application/json", output.Classification(), artifact.OriginRepository, output.Protection(), output.Provenance(), []byte(mutated), output.CreatedAt(), output.ExpiresAt())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseSnapshotArtifact(forged); err == nil {
			t.Fatal("snapshot readback accepted a mismatched version or derivation")
		}
	}
}

// assertClosedSchemaShape checks that a record has exactly the schema's
// required members and no undeclared member, one level deep.
func assertClosedSchemaShape(t *testing.T, name string, encoded []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "artifact", name))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	var record map[string]json.RawMessage
	if json.Unmarshal(raw, &schema) != nil || json.Unmarshal(encoded, &record) != nil {
		t.Fatalf("%s: undecodable schema or record", name)
	}
	if len(record) != len(schema.Required) {
		t.Fatalf("%s: record has %d members, schema requires %d", name, len(record), len(schema.Required))
	}
	for _, key := range schema.Required {
		if _, ok := record[key]; !ok {
			t.Fatalf("%s: required %q missing", name, key)
		}
		if _, ok := schema.Properties[key]; !ok {
			t.Fatalf("%s: required %q undeclared", name, key)
		}
	}
}

func TestHandlerRefusesMergeBaseInputsWithARecordedReason(t *testing.T) {
	repository, _, adapterIdentity, result := sourceFixture(t)
	requested, head := commitRevision(t, "1"), commitRevision(t, "2")
	resolved := func(revision evidence.RevisionIdentity) scm.MergeBaseResult {
		return scm.MergeBaseResult{Outcome: scm.MergeBaseResolved, MergeBase: revision, Reason: evidence.AcquisitionReasonNone}
	}
	cases := []struct {
		name      string
		base      evidence.RevisionIdentity
		result    scm.MergeBaseResult
		resolver  bool
		failure   controlplane.RunFailure
		reason    controlplane.TaskFailureReason
		resolving int
	}{
		{"unrelated histories", requested, scm.MergeBaseResult{Outcome: scm.MergeBaseNone, Reason: evidence.AcquisitionReasonNone}, true, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonNoMergeBase, 1},
		{"head contained in base", requested, resolved(head), true, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonNothingToReview, 1},
		{"base equals head", head, resolved(head), true, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonNothingToReview, 0},
		{"compare transiently unavailable", requested, scm.MergeBaseResult{Outcome: scm.MergeBaseUnavailable, Reason: evidence.AcquisitionReasonAdapterUnavailable}, true, controlplane.RunFailureTransient, controlplane.TaskFailureReasonMergeBaseUnavailable, 1},
		{"compare unauthorized", requested, scm.MergeBaseResult{Outcome: scm.MergeBaseUnavailable, Reason: evidence.AcquisitionReasonAuthorizationRequired}, true, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonMergeBaseUnavailable, 1},
		{"invalid resolver result", requested, scm.MergeBaseResult{Outcome: scm.MergeBaseResolved, Reason: evidence.AcquisitionReasonNone}, true, controlplane.RunFailureInternal, controlplane.TaskFailureReasonMergeBaseUnavailable, 1},
		{"adapter cannot resolve", requested, scm.MergeBaseResult{}, false, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonMergeBaseUnavailable, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			input, err := NewMergeBaseInput(repository, c.base, head, adapterIdentity)
			if err != nil {
				t.Fatal(err)
			}
			resolver := &mergeBaseAdapter{sourceAdapter: sourceAdapter{identity: adapterIdentity, result: result}, result: c.result}
			var adapter scm.SourceAdapter = resolver
			if !c.resolver {
				adapter = &resolver.sourceAdapter
			}
			completion, _, _ := executeMergeBaseInput(t, adapter, input)
			if completion.Status() != controlplane.TaskCompletionFailed || completion.Failure() != c.failure || completion.FailureReason() != c.reason || completion.OutputIdentity() != "" {
				t.Fatalf("completion failure=%s reason=%s", completion.Failure(), completion.FailureReason())
			}
			if resolver.resolved != c.resolving || len(resolver.requested) != 0 || resolver.sourceAdapter.calls != 0 {
				t.Fatalf("resolved=%d acquired=%v", resolver.resolved, resolver.requested)
			}
		})
	}
}

func TestMergeBaseInputRequiresOneObjectAlgorithm(t *testing.T) {
	repository, requested, adapterIdentity, _ := sourceFixture(t)
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA256, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewMergeBaseInput(repository, requested, head, adapterIdentity); err == nil {
		t.Fatal("mixed object algorithms accepted")
	}
	plain, err := NewInput(repository, requested, adapterIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if _, derived := plain.MergeBaseHead(); derived {
		t.Fatal("a plain input reported a merge-base head")
	}
}
