package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/georgejieh/open-trestle/evaluation"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/localreview"
)

// This exercises real pipeline lineage with fake loopback responses, not finding quality.
func modelResultCorpusCapture(t *testing.T, empty, unknownUsage bool) (*localModelFixture, []byte) {
	t.Helper()
	f := newLocalModelFixture(t, localModelFixtureOptions{noAuth: true})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request struct {
			Input []struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"input"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || len(request.Input) != 1 || len(request.Input[0].Content) != 1 {
			t.Error("invalid production request")
			w.WriteHeader(400)
			return
		}
		var packet localModelPacket
		if json.Unmarshal([]byte(request.Input[0].Content[0].Text), &packet) != nil || len(packet.Sources) == 0 {
			t.Error("missing actual corpus sources")
			w.WriteHeader(400)
			return
		}
		rows := []any{}
		key := "candidates"
		if packet.Task == "candidate_generation" {
			if !empty {
				s := packet.Sources[0]
				rows = append(rows, map[string]any{"title": "Synthetic contract candidate", "claim": "Synthetic loopback assertion, not a quality label.", "severity_hint": "high", "source_range": map[string]any{"source_id": s.ID, "start_line": s.Start, "end_line": s.Start}, "evidence_ids": []string{s.ID}})
			}
		} else {
			key = "verdicts"
			for _, c := range packet.Candidates {
				rows = append(rows, map[string]any{"candidate_id": c.ID, "outcome": "verified", "severity": "high", "rationale": "Synthetic loopback contract assertion.", "evidence_ids": c.Evidence})
			}
		}
		body, _ := json.Marshal(map[string]any{"schema_version": 1, key: rows})
		model := "model-a"
		if key == "verdicts" {
			model = "model-b"
		}
		response := map[string]any{"id": "response-eval", "object": "response", "status": "completed", "model": model, "output": []any{map[string]any{"id": "message-eval", "type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": string(body)}}}}, "usage": map[string]any{"input_tokens": 100, "output_tokens": 100, "total_tokens": 200}}
		if unknownUsage {
			delete(response, "usage")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(server.Close)
	var policy map[string]any
	b, err := os.ReadFile(f.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(b, &policy) != nil {
		t.Fatal("policy")
	}
	for _, raw := range policy["connections"].([]any) {
		raw.(map[string]any)["endpoint"] = server.URL + "/v1"
	}
	if err := os.WriteFile(f.policyPath, localModelJSON(t, policy), 0600); err != nil {
		t.Fatal(err)
	}
	sides := []map[string][]byte{}
	for _, side := range []string{"base", "head"} {
		content, err := os.ReadFile(filepath.Join("..", "..", "evaluation", "testdata", "deterministic-corpus-v1", "cases", "debug_direct_and_multiline", side, "main.go"))
		if err != nil {
			t.Fatal(err)
		}
		sides = append(sides, map[string][]byte{"main.go": content})
	}
	f.objects, f.base, f.head = writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, sides[0], sides[1])
	options, _ := localModelSessionOptions(t, f)
	session := localModelNewSession(t, options)
	prepared := localModelPrepare(t, session, f, "evaluation-corpus-loopback")
	result, err := session.Run(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	captured, err := localreview.EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("model calls=%d, want two fake loopback calls", calls.Load())
	}
	return f, captured
}

func TestEvaluateModelResultActualPipelineCorpusBridge(t *testing.T) {
	for _, tc := range []struct {
		name                string
		empty, unknownUsage bool
	}{{"finding", false, false}, {"no_candidates", true, false}, {"unknown_usage", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f, captured := modelResultCorpusCapture(t, tc.empty, tc.unknownUsage)
			parsed, err := localreview.ParseCompletedResult(captured)
			if err != nil {
				t.Fatalf("parse emitted result: %v", err)
			}
			metadata, err := parsed.CompletedMetadata()
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "result.json")
			if err := os.WriteFile(file, captured, 0600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"--result", file, "--result-sha256", localModelDigest(captured), "--case", "debug_direct_and_multiline"}, localGitChangeArgs(f.objects, evidence.RevisionAlgorithmSHA1, f.base, f.head)...)
			var out, stderr bytes.Buffer
			if code := run(append([]string{"evaluate", "model-result"}, args...), &out, &stderr); code != 4 || stderr.Len() != 0 {
				t.Fatalf("exit=%d stderr=%s", code, &stderr)
			}
			var report struct {
				Result                  json.RawMessage                             `json:"result"`
				CorpusIdentity          string                                      `json:"corpus_identity"`
				CaseID                  string                                      `json:"case_id"`
				ReviewState             string                                      `json:"review_state"`
				QualityMeasured         bool                                        `json:"quality_measured"`
				ReleaseEvidenceEligible bool                                        `json:"release_evidence_eligible"`
				Deterministic           json.RawMessage                             `json:"deterministic_candidate_report"`
				Units                   []struct{ Kind, Identity, Decision string } `json:"adjudication_units"`
				Cost                    struct {
					Known bool
					Value *uint64
				} `json:"cost"`
				Latency struct {
					Known bool
					Value *uint64
				} `json:"latency"`
			}
			if json.Unmarshal(out.Bytes(), &report) != nil {
				t.Fatal("report")
			}
			if !bytes.Equal(report.Result, bytes.TrimSuffix(captured, []byte{'\n'})) || report.ReviewState != "pending" || report.QualityMeasured || report.ReleaseEvidenceEligible || report.CaseID != "debug_direct_and_multiline" || len(report.Units) != len(metadata.CandidateIDs)+len(metadata.Diagnostics.Findings())+1 {
				t.Fatal("lost captured identities or invented adjudication")
			}
			for _, unit := range report.Units {
				if unit.Decision != "" || unit.Identity == "" {
					t.Fatal("invented human decision")
				}
			}
			if _, err := evaluation.ParseDeterministicCorpusReport(report.Deterministic); err != nil {
				t.Fatal(err)
			}
			if report.Cost.Known == tc.unknownUsage || !tc.unknownUsage && (report.Cost.Value == nil || *report.Cost.Value != 0) || tc.unknownUsage && report.Cost.Value != nil || report.Latency.Known || report.Latency.Value != nil {
				t.Fatal("known zero cost confused with unknown observation")
			}
			if strings.Contains(out.String(), "package main") {
				t.Fatal("source bytes leaked")
			}
			for _, bad := range []struct{ key, value string }{{"--result-sha256", strings.Repeat("f", 64)}, {"--case", "debug_near_misses"}, {"--head-revision-digest", f.base}} {
				changed := append([]string(nil), args...)
				for i := 0; i < len(changed); i += 2 {
					if changed[i] == bad.key {
						changed[i+1] = bad.value
					}
				}
				out.Reset()
				stderr.Reset()
				if code := runEvaluateModelResult(changed, &out, &stderr); code != 1 || out.Len() != 0 {
					t.Fatalf("mismatch %s accepted: %d", bad.key, code)
				}
			}
		})
	}
}

func TestEvaluateModelResultRejectsChangedSealedLineage(t *testing.T) {
	_, captured := modelResultCorpusCapture(t, false, false)
	var original map[string]json.RawMessage
	if json.Unmarshal(captured, &original) != nil {
		t.Fatal("capture")
	}
	mutations := []struct {
		name   string
		change func(map[string]json.RawMessage)
	}{
		{"diagnostic_only", func(m map[string]json.RawMessage) {
			for k := range m {
				if k != "diagnostics" {
					delete(m, k)
				}
			}
		}},
		{"unknown", func(m map[string]json.RawMessage) { m["invented"] = json.RawMessage(`true`) }},
		{"same_route", func(m map[string]json.RawMessage) {
			m["verification_route_record_identity"] = m["generation_route_record_identity"]
		}},
		{"wrong_context", func(m map[string]json.RawMessage) {
			m["verification_context_identity"] = json.RawMessage(`"` + strings.Repeat("f", 64) + `"`)
		}},
		{"wrong_head", func(m map[string]json.RawMessage) { m["head_revision_identity"] = m["base_revision_identity"] }},
		{"candidate_count", func(m map[string]json.RawMessage) { m["candidate_ids"] = json.RawMessage(`[]`) }},
		{"unknown_cost", func(m map[string]json.RawMessage) {
			m["usage_known"] = json.RawMessage(`false`)
			m["actual_cost_micro_usd"] = json.RawMessage(`7`)
		}},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			changed := map[string]json.RawMessage{}
			for k, v := range original {
				changed[k] = v
			}
			tc.change(changed)
			encoded := append([]byte(nil), captured...)
			for key, value := range original {
				oldField := append([]byte(`"`+key+`":`), value...)
				if replacement, ok := changed[key]; ok {
					encoded = bytes.Replace(encoded, oldField, append([]byte(`"`+key+`":`), replacement...), 1)
				} else {
					encoded = bytes.Replace(encoded, oldField, []byte{}, 1)
				}
			}
			if value, ok := changed["invented"]; ok {
				encoded = append(append(encoded[:len(encoded)-2], []byte(`,"invented":`)...), append(value, '}', '\n')...)
			}
			if _, err := localreview.ParseCompletedResult(encoded); err == nil {
				t.Fatal("changed sealed record accepted")
			}
		})
	}
	for _, bad := range [][]byte{captured[:len(captured)-1], append(append([]byte{}, captured...), '\n'), []byte(`{"candidates":[]}`)} {
		if _, err := localreview.ParseCompletedResult(bad); err == nil {
			t.Fatal("invalid framing/input accepted")
		}
	}
}
