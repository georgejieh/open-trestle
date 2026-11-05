package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const profilesTestAssignments = `{"schema":"open-trestle/agent-profile-assignments","version":1,"independence":"distinct_provider",` +
	`"tiers":{"light":{"zone":"local","provider_id":"ollama","adapter_id":"chat-completions","connection_id":"local/ollama","model_id":"qwen3:8b","model_version":""},` +
	`"standard":{"zone":"local","provider_id":"ollama","adapter_id":"chat-completions","connection_id":"local/ollama","model_id":"qwen3:32b","model_version":""}},` +
	`"verifier_tiers":{"light":{"zone":"local","provider_id":"llamacpp","adapter_id":"chat-completions","connection_id":"local/llamacpp","model_id":"gemma-3-27b","model_version":""}}}`

const profilesTestFeatures = `{"schema":"open-trestle/agent-profile-change-features","version":1,` +
	`"files":[{"path":"web/src/Login.tsx","added_lines":40,"deleted_lines":2},{"path":"internal/auth/session.go","added_lines":12,"deleted_lines":0}],` +
	`"public_api_changes":0,"reference_fan_out":0,"intent":{"description_present":false}}`

func writeProfilesFixture(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProfilesListWritesCatalogJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"profiles", "list"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var catalog struct {
		Contract string `json:"contract"`
		Profiles []struct {
			ID string `json:"id"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &catalog); err != nil || catalog.Contract != "open-trestle/agent-profile-catalog" || len(catalog.Profiles) != 9 {
		t.Fatalf("catalog=%+v err=%v", catalog, err)
	}
	if bytes.Count(stdout.Bytes(), []byte{'\n'}) != 1 {
		t.Fatal("catalog output must be one JSON line")
	}
}

func TestProfilesPlanWritesRoutingPlanJSON(t *testing.T) {
	assignments := writeProfilesFixture(t, "assignments.json", profilesTestAssignments)
	features := writeProfilesFixture(t, "features.json", profilesTestFeatures)
	var first, second, stderr bytes.Buffer
	if code := run([]string{"profiles", "plan", "--assignments", assignments, "--features", features}, &first, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if code := run([]string{"profiles", "plan", "--features", features, "--assignments", assignments}, &second, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("plan output is not deterministic")
	}
	var plan struct {
		Contract string `json:"contract"`
		Identity string `json:"identity"`
		Entries  []struct {
			ProfileID    string `json:"profile_id"`
			Status       string `json:"status"`
			Verification string `json:"verification"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(first.Bytes(), &plan); err != nil || plan.Contract != "open-trestle/agent-profile-routing-plan" || len(plan.Identity) != 64 || len(plan.Entries) != 9 {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	statuses := map[string]string{}
	for _, entry := range plan.Entries {
		statuses[entry.ProfileID] = entry.Status + "/" + entry.Verification
	}
	if statuses["frontend"] != "planned/independent" || !strings.HasPrefix(statuses["security_probe"], "planned/") || statuses["orchestrator"] != "deterministic_only/not_applicable" {
		t.Fatalf("statuses=%v", statuses)
	}
}

func TestProfilesCommandErrors(t *testing.T) {
	assignments := writeProfilesFixture(t, "assignments.json", profilesTestAssignments)
	features := writeProfilesFixture(t, "features.json", profilesTestFeatures)
	badAssignments := writeProfilesFixture(t, "bad-assignments.json", strings.Replace(profilesTestAssignments, `"version":1,`, `"version":1,"extra":1,`, 1))
	badFeatures := writeProfilesFixture(t, "bad-features.json", `{"schema":"open-trestle/agent-profile-change-features","version":1,"files":[]}`)
	directory := t.TempDir()
	for _, test := range []struct {
		name string
		args []string
		want int
		text string
	}{
		{"no subcommand", []string{"profiles"}, 2, "usage: trestle profiles"},
		{"unknown subcommand", []string{"profiles", "run"}, 2, "usage: trestle profiles"},
		{"list with argument", []string{"profiles", "list", "extra"}, 2, "usage: trestle profiles"},
		{"plan missing features", []string{"profiles", "plan", "--assignments", assignments}, 2, "usage: trestle profiles"},
		{"plan missing value", []string{"profiles", "plan", "--assignments"}, 2, "usage: trestle profiles"},
		{"plan duplicate flag", []string{"profiles", "plan", "--assignments", assignments, "--assignments", assignments, "--features", features}, 2, "usage: trestle profiles"},
		{"plan unknown flag", []string{"profiles", "plan", "--assignments", assignments, "--features", features, "--verbose", "1"}, 2, "usage: trestle profiles"},
		{"plan missing file", []string{"profiles", "plan", "--assignments", filepath.Join(directory, "absent.json"), "--features", features}, 1, "read assignments"},
		{"plan directory input", []string{"profiles", "plan", "--assignments", assignments, "--features", directory}, 1, "read features"},
		{"plan invalid assignments", []string{"profiles", "plan", "--assignments", badAssignments, "--features", features}, 1, "parse assignments"},
		{"plan invalid features", []string{"profiles", "plan", "--assignments", assignments, "--features", badFeatures}, 1, "parse features"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(test.args, &stdout, &stderr); code != test.want || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.text) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}
