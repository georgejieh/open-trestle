package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestRunLocalGitModelReviewBoundsMaximumEscapedFindings(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := httptest.NewRecorder()
				f.generation.serve(t, response, r)
				if response.Code != http.StatusOK {
					t.Error("real generation request was not admitted")
					w.WriteHeader(response.Code)
					return
				}
				var wire map[string]any
				if err := json.Unmarshal(response.Body.Bytes(), &wire); err != nil {
					t.Error(err)
					return
				}
				output := wire["output"].([]any)[0].(map[string]any)
				content := output["content"].([]any)[0].(map[string]any)
				var generated map[string]any
				if err := json.Unmarshal([]byte(content["text"].(string)), &generated); err != nil {
					t.Error(err)
					return
				}
				actual := generated["candidates"].([]any)[0].(map[string]any)
				candidates := make([]any, 16)
				for i := range candidates {
					candidate := map[string]any{}
					for key, value := range actual {
						candidate[key] = value
					}
					candidate["title"] = fmt.Sprintf("Independent proposal %02d", i)
					candidate["claim"] = fmt.Sprintf("Proposal %02d: ", i) + strings.Repeat("<", 1000)
					candidates[i] = candidate
				}
				generated["candidates"] = candidates
				encoded, err := json.Marshal(generated)
				if err != nil {
					t.Error(err)
					return
				}
				content["text"] = string(encoded)
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(wire); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(server.Close)
			encoded, err := os.ReadFile(f.policyPath)
			if err != nil {
				t.Fatal(err)
			}
			var policy map[string]any
			if err := json.Unmarshal(encoded, &policy); err != nil {
				t.Fatal(err)
			}
			for _, value := range policy["connections"].([]any) {
				connection := value.(map[string]any)
				if connection["adapter_id"] == "adapter-a" {
					connection["endpoint"] = server.URL + "/v1"
				}
			}
			if err := os.WriteFile(f.policyPath, localModelJSON(t, policy), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			args := replaceLocalGitChangeValue(f.args, "--format", format)
			args = replaceLocalGitChangeValue(args, "--timeout", "30s")
			if code := run(args, &stdout, &stderr); code != 4 || stderr.Len() != 0 {
				output := stdout.String()
				if len(output) > 1024 {
					output = output[:1024]
				}
				t.Fatalf("bounded review exit=%d stderr=%q stdout_prefix=%q", code, stderr.String(), output)
			}
			limit := 256 << 10
			if format == "text" {
				limit = 64 << 10
			}
			if stdout.Len() == 0 || stdout.Len() > limit || strings.Contains(stdout.String(), localModelKey) || strings.Contains(stdout.String(), localModelSecret) {
				t.Fatal("maximum model output exceeded terminal bounds or disclosed private data")
			}
			if format == "json" {
				var receipt localModelReceipt
				if json.Unmarshal(stdout.Bytes(), &receipt) != nil || receipt.Diagnostics.Coverage.CandidateCount != 16 || receipt.Diagnostics.Coverage.VerifiedCount != 16 || len(receipt.Diagnostics.Findings) != 16 {
					t.Fatal("bounded renderer silently truncated independently verified findings")
				}
			}
			gc, _ := f.generation.snapshot()
			vc, captures := f.verification.snapshot()
			if gc != 1 || vc != 1 || len(captures) != 1 || len(captures[0].Packet.Candidates) != 16 {
				t.Fatal("maximum candidate test did not traverse real generation/verifier IDs")
			}
		})
	}
}
