package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

func feedbackJourneyProtectedFile(t *testing.T, name string, encoded []byte) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func feedbackJourneyJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func feedbackJourneyArgs(f *localModelFixture, reviewPath, feedbackPath, output string) []string {
	args := rmiArgs(f, feedbackPath, output)
	args = rmiRemoveFlag(args, "--revision-algorithm")
	args = rmiRemoveFlag(args, "--head-revision-digest")
	return append(args, "--review-input", reviewPath)
}

func feedbackJourneyRun(t *testing.T, args []string, wantCode int) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWithContext(context.Background(), append([]string{"local-git", "retained-memory-input"}, args...), &stdout, &stderr)
	if code != wantCode {
		t.Fatalf("feedback exit=%d want=%d stderr=%q", code, wantCode, stderr.String())
	}
	if wantCode == 0 && (stdout.Len() == 0 || withoutIndexNotice(stderr.String()) != "") {
		t.Fatal("feedback operation did not emit a receipt on stdout only")
	}
	return stdout.String() + stderr.String()
}

func feedbackJourneyCalls(t *testing.T, f *localModelFixture, want int) {
	t.Helper()
	generation, _ := f.generation.snapshot()
	verification, _ := f.verification.snapshot()
	if generation != want || verification != want {
		t.Fatalf("model calls=%d/%d want=%d/%d", generation, verification, want, want)
	}
}

func newFeedbackJourneyFixture(t *testing.T) *localModelFixture {
	t.Helper()
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	base := map[string][]byte{
		"a.go":          []byte("package p\nfunc Changed(x int) int { if x == 0 { return 0 }; return 10 / x }\n// " + localModelSecret + "\n"),
		"caller.go":     []byte("package p\nfunc Consume() int { return Changed(0) }\n"),
		"preference.go": []byte("package p\nfunc PreferenceTarget() int { return 1 }\n"),
	}
	head := map[string][]byte{
		"a.go":          []byte("package p\nfunc Changed(x int) int { return 10 / x }\n// " + localModelSecret + "\n"),
		"caller.go":     base["caller.go"],
		"preference.go": []byte("package p\nfunc PreferenceTarget() int { return 2 }\n"),
	}
	f.objects, f.base, f.head = writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, base, head)
	f.args = rmiReplaceFlag(f.args, "--objects-root", f.objects)
	f.args = rmiReplaceFlag(f.args, "--base-revision-digest", f.base)
	f.args = rmiReplaceFlag(f.args, "--head-revision-digest", f.head)
	return f
}

func feedbackJourneyMemoryItems(packet localModelPacket) []localModelMemoryItem {
	items := append([]localModelMemoryItem(nil), packet.Memory.Items...)
	for _, retrieval := range packet.AdditionalMemory {
		items = append(items, retrieval.Items...)
	}
	return items
}

func feedbackJourneyPacketContains(t *testing.T, captures []localModelCapture, index int, path string, parts ...string) {
	t.Helper()
	if len(captures) <= index {
		t.Fatal("missing model request capture")
	}
	for _, item := range feedbackJourneyMemoryItems(captures[index].Packet) {
		if item.Path != path {
			continue
		}
		matches := true
		for _, part := range parts {
			matches = matches && strings.Contains(item.Text, part)
		}
		if matches {
			return
		}
	}
	t.Fatalf("model request %d missing scoped advisory at %s", index, path)
}

func TestLocalGitFeedbackJourneySelectsActualFindingReusesAndRemoves(t *testing.T) {
	for _, decision := range []string{"confirm", "dismiss", "advisory"} {
		t.Run(decision, func(t *testing.T) {
			f := newFeedbackJourneyFixture(t)
			original, reviewOut := localModelExecute(t, f, f.args, 4)
			if len(original.Diagnostics.Findings) != 1 {
				t.Fatal("fixture did not produce exactly one actual verified finding")
			}
			var result struct {
				Diagnostics json.RawMessage `json:"diagnostics"`
			}
			if err := json.Unmarshal([]byte(reviewOut), &result); err != nil {
				t.Fatal(err)
			}
			set, err := diagnostics.ParseSet(result.Diagnostics)
			if err != nil || len(set.Findings()) != 1 || set.Identity() != original.Diagnostics.Identity {
				t.Fatalf("actual result did not contain canonical diagnostics: %v", err)
			}
			finding := set.Findings()[0]
			reviewPath := feedbackJourneyProtectedFile(t, "review.json", []byte(reviewOut))
			rationale := "The caller rejects zero before this path."
			preference := "Prefer actionable defects over style suggestions."
			unselected := "Unchanged caller preference must remain unselected."
			feedback := feedbackJourneyProtectedFile(t, "feedback.json", feedbackJourneyJSON(t, []any{
				map[string]any{"path": finding.Path(), "start_line": finding.StartLine(), "decision": decision, "text": rationale},
				map[string]any{"path": "preference.go", "text": preference},
				map[string]any{"path": "caller.go", "text": unselected},
			}))
			output := rmiOutputPath(t)
			args := feedbackJourneyArgs(f, reviewPath, feedback, output)
			terminal := feedbackJourneyRun(t, args, 0)
			rmiNoLeak(t, terminal, reviewPath, feedback, output, rationale, preference, unselected, localModelKey, localModelSecret)
			loaded, before, _, _, scope := rmiLoadOutput(t, f, output)
			if loaded.Scope().Identity() != scope.Identity() || len(loaded.Records()) != 3 {
				t.Fatal("feedback did not keep exact loaded scope and all authored records")
			}
			foundDecision, foundPreference := false, false
			for _, record := range loaded.Records() {
				if record.Kind().String() != "human_feedback" || record.Taint().String() != "user_controlled" {
					t.Fatal("operator disposition gained trusted evidence authority")
				}
				if record.Path() == finding.Path() {
					foundDecision = strings.Contains(record.Text(), decision) && strings.Contains(record.Text(), rationale) && strings.Contains(record.Text(), finding.Identity()) && strings.Contains(record.Text(), set.Identity())
				}
				foundPreference = foundPreference || record.Path() == "preference.go" && record.Text() == preference
			}
			if !foundDecision || !foundPreference {
				t.Fatal("feedback lost explicit decision, derived provenance or preference")
			}
			feedbackJourneyCalls(t, f, 1)
			for call := 2; call <= 3; call++ {
				reused, _ := localModelExecute(t, f, rmCLIArgs(f, output), 4)
				if reused.Status != "findings" || len(reused.Diagnostics.Findings) != 1 || reused.Diagnostics.Findings[0].Path != finding.Path() {
					t.Fatal("advisory feedback suppressed or replaced independently verified finding output")
				}
				feedbackJourneyCalls(t, f, call)
				_, generation := f.generation.snapshot()
				_, verification := f.verification.snapshot()
				for _, captures := range [][]localModelCapture{generation, verification} {
					feedbackJourneyPacketContains(t, captures, call-1, finding.Path(), decision, rationale, finding.Identity(), set.Identity())
					feedbackJourneyPacketContains(t, captures, call-1, "preference.go", preference)
					items := feedbackJourneyMemoryItems(captures[call-1].Packet)
					if len(items) != 2 {
						t.Fatal("changed-path retrieval did not select exactly the decision and applicable preference")
					}
					for _, item := range items {
						if item.Path == "caller.go" || strings.Contains(item.Text, unselected) {
							t.Fatal("unchanged direct-reference source incorrectly widened memory selection")
						}
					}
				}
			}
			after, err := os.ReadFile(output)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("explicit reuse mutated sealed retained input")
			}
			removeArgs := rmiRemoveFlag(args, "--feedback-input")
			removeArgs = rmiRemoveFlag(removeArgs, "--output")
			removeArgs = rmiRemoveFlag(removeArgs, "--valid-for")
			removeArgs = append(removeArgs, "--remove-input", output)
			terminal = feedbackJourneyRun(t, removeArgs, 0)
			var receipt struct {
				Status string `json:"status"`
			}
			if json.Unmarshal([]byte(terminal), &receipt) != nil || receipt.Status != "removed" {
				t.Fatal("exact removal did not report removed")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatal("removed input remains available for accidental future reuse")
			}
			refused, _ := localModelExecute(t, f, rmCLIArgs(f, output), 4)
			if refused.Status != "refused" {
				t.Fatal("saved command unexpectedly reused removed input")
			}
			feedbackJourneyCalls(t, f, 3)
			localModelExecute(t, f, f.args, 4)
			feedbackJourneyCalls(t, f, 4)
			_, generation := f.generation.snapshot()
			_, verification := f.verification.snapshot()
			if len(feedbackJourneyMemoryItems(generation[3].Packet)) != 0 || len(feedbackJourneyMemoryItems(verification[3].Packet)) != 0 {
				t.Fatal("ordinary later review discovered withdrawn feedback")
			}
			historical, err := os.ReadFile(reviewPath)
			if err != nil || string(historical) != reviewOut {
				t.Fatal("feedback changed historical review bytes")
			}
		})
	}
}

func TestLocalGitFeedbackJourneyRefusesUnselectedAndCrossScopeFeedback(t *testing.T) {
	for _, kind := range []string{"unknown decision", "missing finding", "wrong tenant", "wrong repository", "wrong policy", "wrong outer head", "mixed head flags"} {
		t.Run(kind, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{})
			original, reviewOut := localModelExecute(t, f, f.args, 4)
			finding := original.Diagnostics.Findings[0]
			var wire map[string]json.RawMessage
			if err := json.Unmarshal([]byte(reviewOut), &wire); err != nil {
				t.Fatal(err)
			}
			item := map[string]any{"path": finding.Path, "start_line": finding.Start, "decision": "dismiss", "text": "Operator rationale."}
			switch kind {
			case "unknown decision":
				item["decision"] = "suppress"
			case "missing finding":
				item["start_line"] = finding.Start + 100
			case "wrong outer head":
				wire["head_revision_identity"] = feedbackJourneyJSON(t, strings.Repeat("a", 64))
			case "wrong policy":
				wire["runtime_policy_identity"] = feedbackJourneyJSON(t, strings.Repeat("a", 64))
			}
			reviewPath := feedbackJourneyProtectedFile(t, "review.json", feedbackJourneyJSON(t, wire))
			feedbackPath := feedbackJourneyProtectedFile(t, "feedback.json", feedbackJourneyJSON(t, []any{item}))
			output := rmiOutputPath(t)
			args := feedbackJourneyArgs(f, reviewPath, feedbackPath, output)
			wantCode := 4
			switch kind {
			case "wrong tenant":
				args = rmiReplaceFlag(args, "--tenant", "another-tenant")
			case "wrong repository":
				args = rmiReplaceFlag(args, "--repository", "another-repository")
			case "mixed head flags":
				args = append(args, "--revision-algorithm", "sha1", "--head-revision-digest", f.head)
				wantCode = 2
			}
			feedbackJourneyRun(t, args, wantCode)
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatal("refused feedback created an input")
			}
			feedbackJourneyCalls(t, f, 1)
		})
	}
}
