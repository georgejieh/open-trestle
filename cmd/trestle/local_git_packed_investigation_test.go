package main

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func newPackedInvestigationFixture(t *testing.T, mode string, cancel context.CancelFunc) (*localModelFixture, *investigationEndpoint, map[string]any, string) {
	t.Helper()
	f, endpoint, policy, path := newInvestigationFixture(t, mode, cancel)
	f.objects = packedCLIPackLooseRoot(t, f.objects, evidence.RevisionAlgorithmSHA1)
	f.args = packedCLIWithObjectStore(packedCLIReplaceArg(f.args, "--objects-root", f.objects))
	return f, endpoint, policy, path
}

func TestLocalGitPackedInvestigationReadsSnapshotToolsAndVerifies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	f, endpoint, policy, path := newPackedInvestigationFixture(t, "", cancel)
	writeInvestigationPolicy(t, path, policy)
	var stdout, stderr bytes.Buffer
	code := runWithContext(ctx, f.args, &stdout, &stderr)
	if code == 2 {
		t.Fatal("packed explicit snapshot investigation opt-in is not implemented")
	}
	var receipt struct {
		localModelReceipt
		Investigation struct {
			Turns []struct {
				Request        string   `json:"request_identity"`
				Authorization  string   `json:"authorization_identity"`
				Outcome        string   `json:"outcome_identity"`
				Reconciliation string   `json:"reconciliation_identity"`
				Results        []string `json:"tool_result_identities"`
			} `json:"turns"`
			ToolCalls     uint32 `json:"tool_calls"`
			ReturnedBytes uint64 `json:"returned_bytes"`
		} `json:"investigation"`
	}
	if json.Unmarshal(stdout.Bytes(), &receipt) != nil || code != 4 || receipt.Status != "findings" || receipt.RunStatus != "succeeded" || stderr.Len() != 0 || receipt.ComprehensiveClearance {
		t.Fatalf("packed investigation result code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	captures := endpoint.snapshot()
	if len(captures) != 5 || len(receipt.Investigation.Turns) != 5 || receipt.Investigation.ToolCalls != 3 || receipt.Investigation.ReturnedBytes == 0 || receipt.Investigation.ReturnedBytes > 32768 {
		t.Fatal("packed investigation did not execute bounded actual turn/tool graph")
	}
	if !slices.Contains(receipt.Limitations, "loose_and_pack_index_v1_subset") || slices.Contains(receipt.Limitations, "loose_git_objects_only") || !slices.Contains(receipt.Limitations, "bounded_source_context") || !slices.Contains(receipt.Limitations, "no_publication") {
		t.Fatalf("packed investigation limitations = %v", receipt.Limitations)
	}
	claimed := map[string]bool{}
	completed := map[string]bool{}
	reconciled := map[string]bool{}
	for _, event := range receipt.Audit {
		if strings.HasPrefix(event.Kind, "publication_") {
			t.Fatal("packed investigation gained publication authority")
		}
		if event.Kind == "route_attempt_claimed" {
			claimed[event.Subject] = true
		}
		if event.Kind == "route_dispatch_completed" {
			completed[event.Subject] = true
		}
		if event.Kind == "route_cost_reconciled" {
			reconciled[event.Subject] = true
		}
	}
	seenRequests := map[string]bool{}
	for i, capture := range captures {
		turn := receipt.Investigation.Turns[i]
		localModelRequireDigest(t, turn.Request, turn.Authorization, turn.Outcome, turn.Reconciliation)
		if seenRequests[capture.request] || turn.Request != capture.request || !claimed[turn.Authorization] || !completed[turn.Outcome] || !reconciled[turn.Reconciliation] {
			t.Fatal("packed investigation receipt is not bound to actual model turn ledger")
		}
		seenRequests[capture.request] = true
		if i > 0 && i < 4 {
			prior := receipt.Investigation.Turns[i-1]
			state := capture.packet.Investigation
			if state.PreviousRequest != prior.Request || state.PreviousOutcome != prior.Outcome || len(prior.Results) != 1 || strings.Join(state.PreviousResults, ",") != strings.Join(prior.Results, ",") {
				t.Fatal("packed investigation lost previous tool result lineage")
			}
		}
	}
	if receipt.GenerationRequest != captures[3].request || receipt.VerificationRequest != captures[4].request || receipt.Context != captures[4].packet.GenerationContext || receipt.CandidateBatch != captures[4].packet.CandidateBatch || receipt.Diagnostics.Coverage.VerifiedCount != 1 || len(receipt.Diagnostics.Findings) != 1 {
		t.Fatal("packed investigation final review disconnected from actual snapshot turns")
	}
	if strings.Contains(stdout.String()+stderr.String(), investigationLine) || stdout.Len() > 256<<10 {
		t.Fatal("packed investigation leaked snapshot bytes or exceeded result bounds")
	}
}

func TestLocalGitPackedInvestigationStillRequiresObjectStoreFlag(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	f, endpoint, policy, path := newInvestigationFixture(t, "", cancel)
	f.objects = packedCLIPackLooseRoot(t, f.objects, evidence.RevisionAlgorithmSHA1)
	f.args = packedCLIReplaceArg(f.args, "--objects-root", f.objects)
	writeInvestigationPolicy(t, path, policy)
	var stdout, stderr bytes.Buffer
	code := runWithContext(ctx, f.args, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("packed investigation without opt-in exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var receipt localModelReceipt
	if json.Unmarshal(stdout.Bytes(), &receipt) != nil || receipt.Status != "incomplete" || receipt.RunStatus != "not_opened" {
		t.Fatalf("packed investigation without opt-in receipt = %#v", receipt)
	}
	if len(endpoint.snapshot()) != 0 {
		t.Fatal("packed omitted opt-in dispatched investigation model calls")
	}
}
