package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestChatCompletionsCLIUsesCheckoutAndPackedSourceThroughNineTasks(t *testing.T) {
	for _, source := range []string{"checkout", "packed"} {
		t.Run(source, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true})
			args := localChatSourceArgs(t, f, source)
			result, _ := localModelExecute(t, f, args, 4)
			gc, generated := f.generation.snapshot()
			vc, verified := f.verification.snapshot()
			if result.Status != "findings" || result.CI != "blocked" || result.RunStatus != "succeeded" || result.ComprehensiveClearance || gc != 1 || vc != 1 || len(generated) != 1 || len(verified) != 1 {
				t.Fatalf("Chat CLI result=%s/%s calls=%d/%d", result.Status, result.RunStatus, gc, vc)
			}
			if result.GenerationRoute != f.generationRoute || result.VerificationRoute != f.verificationRoute || result.Independence != "distinct_provider" || result.Inventory != f.inventoryID || result.Policy != f.policyID {
				t.Fatal("Chat CLI lost pinned configuration or independent routes")
			}
			if result.Context != generated[0].ContextID || result.VerificationContext != verified[0].ContextID || verified[0].Packet.GenerationContext != generated[0].ContextID || result.CandidateBatch != verified[0].Packet.CandidateBatch || len(result.CandidateIDs) != 1 || len(verified[0].Packet.Candidates) != 1 || verified[0].Packet.Candidates[0].ID != "c1" {
				t.Fatal("Chat CLI receipt disconnected from actual model packets")
			}
			if len(result.Diagnostics.Findings) != 1 || result.Diagnostics.Coverage.CandidateCount != 1 || result.Diagnostics.Coverage.VerifiedCount != 1 || result.Diagnostics.SourceCoverage.Selected == 0 {
				t.Fatal("Chat CLI omitted actual source-backed verified finding")
			}
			finding := result.Diagnostics.Findings[0]
			// Both sources plan the caller: a checkout from its index, a packed
			// source from the snapshots it carries.
			if finding.Path != "a.go" || finding.Start != 2 || finding.End != 2 || finding.Severity != "error" || len(finding.Evidence) != 2 {
				t.Fatal("Chat finding lost exact changed line or caller evidence")
			}
			for _, packet := range []localModelPacket{generated[0].Packet, verified[0].Packet} {
				changed, caller := false, false
				for _, item := range packet.Sources {
					changed = changed || item.Path == "a.go" && item.Stage == "changed_hunk" && strings.Contains(item.Content, "return 10 / x")
					caller = caller || item.Path == "caller.go" && item.Stage == "direct_reference" && strings.Contains(item.Content, "Changed(0)")
					if !slices.Contains(finding.Evidence, item.ID) {
						t.Fatal("finding references were not model-visible source IDs")
					}
				}
				if !changed || !caller {
					t.Fatal("checkout/pack did not reach real changed context and its caller")
				}
			}
			keys := []string{}
			for _, task := range result.Tasks {
				keys = append(keys, task.Key)
				if task.Status != "succeeded" || task.Attempts != 1 || task.Output == "" {
					t.Fatal("Chat CLI task did not complete exactly once")
				}
			}
			slices.Sort(keys)
			if !slices.Equal(keys, []string{"analysis", "candidates", "change", "context", "memory", "readiness", "source-base", "source-head", "verification"}) {
				t.Fatalf("tasks=%v", keys)
			}
			counts := map[string]int{}
			for _, event := range result.Audit {
				counts[event.Kind]++
			}
			if len(result.Audit) != 8 || counts["route_selected"] != 2 || counts["route_attempt_claimed"] != 2 || counts["route_dispatch_completed"] != 2 || counts["route_cost_reconciled"] != 2 {
				t.Fatal("Chat CLI bypassed audited routing/dispatch accounting")
			}
			if !slices.Contains(result.Limitations, "loose_and_pack_index_v1_subset") || !slices.Contains(result.Limitations, "bounded_source_context") || !slices.Contains(result.Limitations, "no_publication") {
				t.Fatalf("limitations=%v", result.Limitations)
			}
		})
	}
}

func TestChatCompletionsCLIMalformedRefusalFailsWithoutReadiness(t *testing.T) {
	for _, source := range []string{"checkout", "packed"} {
		t.Run(source, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, generationMode: "malformed_refusal"})
			result, _ := localModelExecute(t, f, localChatSourceArgs(t, f, source), 1)
			gc, generated := f.generation.snapshot()
			vc, _ := f.verification.snapshot()
			if result.Status != "failed" || result.CI == "pass" || result.RunStatus == "active" || result.Readiness != "" || result.VerificationContext != "" || len(result.Diagnostics.Findings) != 0 || result.ComprehensiveClearance || gc != 1 || vc != 0 || len(generated) != 1 {
				t.Fatalf("malformed Chat refusal escaped: status=%s run=%s calls=%d/%d", result.Status, result.RunStatus, gc, vc)
			}
		})
	}
}

func localChatSourceArgs(t *testing.T, f *localModelFixture, source string) []string {
	t.Helper()
	if source == "packed" {
		f.objects = packedCLIPackLooseRoot(t, f.objects, "sha1")
		return packedCLIWithObjectStore(packedCLIReplaceArg(f.args, "--objects-root", f.objects))
	}
	directory := t.TempDir()
	checkoutGit(t, directory, "init")
	if err := os.CopyFS(filepath.Join(directory, ".git", "objects"), os.DirFS(f.objects)); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, directory, "update-ref", "refs/heads/base", f.base)
	checkoutGit(t, directory, "update-ref", "refs/heads/review", f.head)
	checkoutGit(t, directory, "gc", "--prune=now")
	args := []string{}
	for index := 0; index < len(f.args); index += 2 {
		switch f.args[index] {
		case "--objects-root", "--revision-algorithm", "--base-revision-digest", "--head-revision-digest":
			continue
		}
		args = append(args, f.args[index:index+2]...)
	}
	return append(args, "--checkout", directory, "--base", "refs/heads/base", "--head", "refs/heads/review")
}
