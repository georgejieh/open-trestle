package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/agentprofile"
	"github.com/georgejieh/open-trestle/internal/review"
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

func TestProfilesListDefaultsToOneTextLinePerProfile(t *testing.T) {
	catalog, err := agentprofile.DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, explicit, stderr bytes.Buffer
	if code := run([]string{"profiles", "list"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if code := run([]string{"profiles", "list", "--format", "text"}, &explicit, &stderr); code != 0 || stderr.Len() != 0 || !bytes.Equal(explicit.Bytes(), stdout.Bytes()) {
		t.Fatalf("--format text differs from the default: code=%d stderr=%q", code, stderr.String())
	}
	if stdout.Len() > 4096 || bytes.ContainsRune(stdout.Bytes(), '{') {
		t.Fatalf("text output is not a short listing: %d bytes", stdout.Len())
	}
	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	profiles := catalog.Profiles()
	if len(lines) != len(profiles)+4 {
		t.Fatalf("lines=%d, want header, %d profiles and three footer lines", len(lines), len(profiles))
	}
	if lines[0] != "PROFILE            MODEL     REVIEW     PURPOSE" {
		t.Fatalf("header=%q", lines[0])
	}
	accepted := map[string]bool{}
	for _, id := range review.ContextSpecialistProfileIDs() {
		accepted[id] = true
	}
	for i, profile := range profiles {
		fields := strings.Fields(lines[i+1])
		use := "plan only"
		if accepted[string(profile.ID())] {
			use = "--profile"
		}
		if len(fields) < 4 || fields[0] != string(profile.ID()) || fields[1] != string(profile.ModelCall()) || !strings.HasSuffix(lines[i+1], "  "+use+"  "+profile.Purpose()) {
			t.Fatalf("line %d = %q, want %s %s %s and its purpose", i+1, lines[i+1], profile.ID(), profile.ModelCall(), use)
		}
	}
	if !slices.Contains(lines, "orchestrator       none      plan only  "+mustProfile(t, catalog, "orchestrator").Purpose()) ||
		!slices.Contains(lines, "security_probe     required  --profile  "+mustProfile(t, catalog, "security_probe").Purpose()) {
		t.Fatal("columns are not aligned to the widest profile ID")
	}
	if want := fmt.Sprintf("%d profiles, catalog version %d, identity %s", len(profiles), catalog.Version(), catalog.Identity()); lines[len(profiles)+1] != want {
		t.Fatalf("catalog line=%q, want %q", lines[len(profiles)+1], want)
	}
	if !strings.Contains(lines[len(lines)-1], "--format json") {
		t.Fatal("text output does not point to the JSON catalog")
	}
}

func mustProfile(t *testing.T, catalog agentprofile.Catalog, id agentprofile.ProfileID) agentprofile.Profile {
	t.Helper()
	profile, ok := catalog.Profile(id)
	if !ok {
		t.Fatalf("catalog lacks %s", id)
	}
	return profile
}

func TestProfilesListFormatJSONWritesTheExactCatalogJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"profiles", "list", "--format", "json"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	catalogValue, err := agentprofile.DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	// The JSON form is the catalog encoding the command printed before text became the default.
	encoded, err := json.Marshal(catalogValue)
	if err != nil || !bytes.Equal(stdout.Bytes(), append(encoded, '\n')) {
		t.Fatal("JSON output is not the exact catalog encoding plus one newline")
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
		{"list format missing value", []string{"profiles", "list", "--format"}, 2, "usage: trestle profiles list [--format text|json]"},
		{"list unknown format", []string{"profiles", "list", "--format", "yaml"}, 2, "usage: trestle profiles"},
		{"list duplicate format", []string{"profiles", "list", "--format", "json", "--format", "json"}, 2, "usage: trestle profiles"},
		{"list joined format", []string{"profiles", "list", "--format=json"}, 2, "usage: trestle profiles"},
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
