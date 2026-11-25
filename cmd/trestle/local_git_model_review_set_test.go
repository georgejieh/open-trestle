package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/agentprofile"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/localreview"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type localModelSetReceipt struct {
	Contract  string `json:"contract"`
	Version   int    `json:"schema_version"`
	Status    string `json:"status"`
	CI        string `json:"ci_disposition"`
	Complete  bool   `json:"complete"`
	Selection struct {
		Mode     string `json:"mode"`
		Status   string `json:"status"`
		Features *struct {
			Identity                 string   `json:"identity"`
			ChangedFiles             int      `json:"changed_files"`
			Languages                []string `json:"languages"`
			StyleConfigurationUnread *int     `json:"style_configuration_unread"`
		} `json:"features"`
		Plan *struct {
			Identity         string `json:"identity"`
			AssignmentsBasis string `json:"assignments_basis"`
		} `json:"plan"`
		Selected []struct {
			ProfileID string `json:"profile_id"`
		} `json:"selected"`
		Dropped []struct {
			ProfileID string `json:"profile_id"`
			Reason    string `json:"reason"`
		} `json:"dropped"`
		Inactive        []string `json:"inactive"`
		RouteAssignment string   `json:"route_assignment"`
	} `json:"selection"`
	Members []struct {
		Member            string `json:"member"`
		Launched          bool   `json:"launched"`
		NotLaunchedReason string `json:"not_launched_reason"`
		Status            string `json:"status"`
		CI                string `json:"ci_disposition"`
		RunStatus         string `json:"run_status"`
		ReviewRunID       string `json:"review_run_id"`
		ContextIdentity   string `json:"context_identity"`
		GenerationRoute   string `json:"generation_route_record_identity"`
		VerificationRoute string `json:"verification_route_record_identity"`
		UsageKnown        bool   `json:"usage_known"`
		// TokenUsage is the member result's token_usage, absent for a member
		// that never ran.
		TokenUsage *localreview.TokenUsage `json:"token_usage"`
	} `json:"members"`
	Summary struct {
		MembersRun       int            `json:"members_run"`
		Findings         int            `json:"findings"`
		DuplicatesMerged int            `json:"duplicates_merged"`
		BySeverity       map[string]int `json:"by_severity"`
		ByCategory       map[string]int `json:"by_category"`
	} `json:"summary"`
	Findings []struct {
		FindingIdentity string `json:"finding_identity"`
		Severity        string `json:"severity"`
		Category        string `json:"category"`
		Path            string `json:"path"`
		Contributors    []struct {
			Member          string `json:"member"`
			FindingIdentity string `json:"finding_identity"`
			Severity        string `json:"severity"`
		} `json:"contributors"`
	} `json:"findings"`
	Bounds struct {
		MaxSpecialists         int   `json:"max_specialists"`
		MemberTimeoutMillis    int64 `json:"member_timeout_milliseconds"`
		MaxModelWallTimeMillis int64 `json:"max_model_wall_time_milliseconds"`
	} `json:"bounds"`
	ComprehensiveClearance bool `json:"comprehensive_clearance"`
}

func runLocalModelSet(t *testing.T, f *localModelFixture, extra []string, wantCode int) (localModelSetReceipt, string) {
	t.Helper()
	args := append([]string(nil), f.args...)
	for index := 0; index < len(extra); index += 2 {
		switch {
		case extra[index] == "--all" || extra[index] == "--verbose":
			// The bare flags take no value.
			args = append(args, extra[index])
			index--
		case index+1 == len(extra):
			t.Fatalf("flag %s has no value", extra[index])
		case extra[index] == "--format":
			args = replaceLocalGitChangeValue(args, "--format", extra[index+1])
		default:
			args = append(args, extra[index], extra[index+1])
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != wantCode {
		gc, _ := f.generation.snapshot()
		vc, _ := f.verification.snapshot()
		t.Fatalf("review set exit=%d want=%d calls=%d/%d stderr=%q stdout=%q", code, wantCode, gc, vc, stderr.String(), stdout.String())
	}
	if withoutIndexNotice(stderr.String()) != "" {
		t.Fatalf("review set wrote stderr: %q", stderr.String())
	}
	for _, forbidden := range []string{f.objects, f.inventoryPath, f.policyPath, localModelSecret, localModelKey, "return 10 / x", "Bearer "} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatal("review set output disclosed private input")
		}
	}
	for _, id := range review.ContextSpecialistProfileIDs() {
		specialist, err := review.NewContextSpecialist(id)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(stdout.String(), specialist.Instructions()) {
			t.Fatal("review set output disclosed specialist instructions")
		}
	}
	var receipt localModelSetReceipt
	if !strings.Contains(strings.Join(extra, " "), "sarif") && !strings.Contains(strings.Join(extra, " "), "text") {
		if strings.Count(stdout.String(), "\n") != 1 || json.Unmarshal(stdout.Bytes(), &receipt) != nil {
			t.Fatalf("review set did not emit one JSON document: %q", stdout.String())
		}
		if receipt.Contract != "open-trestle/local-git-model-review-set" || receipt.Version != 1 || receipt.ComprehensiveClearance {
			t.Fatal("review set lost its contract or claimed clearance")
		}
	}
	return receipt, stdout.String()
}

func selectedIDs(receipt localModelSetReceipt) []string {
	ids := []string{}
	for _, value := range receipt.Selection.Selected {
		ids = append(ids, value.ProfileID)
	}
	return ids
}

func droppedReason(receipt localModelSetReceipt, id string) string {
	for _, value := range receipt.Selection.Dropped {
		if value.ProfileID == id {
			return value.Reason
		}
	}
	return ""
}

// memberTokens is the token_usage of a member whose generation and
// verification attempts each reported 100 input and 100 output tokens.
const memberTokens = `{"known":true,"route_attempts":2,"input_tokens":200,"output_tokens":200,"cached_input_tokens":0,"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0},"verification":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0}}`

func TestParseSpecialistRequest(t *testing.T) {
	for name, tc := range map[string]struct {
		value, max string
		mode       string
		ids        []string
		limit      int
		unknown    bool
		invalid    bool
	}{
		"none":            {value: "none", mode: "none"},
		"auto default":    {value: "auto", mode: "auto", limit: 3},
		"auto max":        {value: "auto", max: "6", mode: "auto", limit: 6},
		"explicit":        {value: "backend,bug_hunter", mode: "explicit", ids: []string{"backend", "bug_hunter"}, limit: 3},
		"unknown":         {value: "backend,red_team", unknown: true},
		"non direct":      {value: "test_author", unknown: true},
		"duplicate":       {value: "backend,backend", invalid: true},
		"empty element":   {value: "backend,", invalid: true},
		"max zero":        {value: "auto", max: "0", invalid: true},
		"max seven":       {value: "auto", max: "7", invalid: true},
		"max padded":      {value: "auto", max: "03", invalid: true},
		"max with none":   {value: "none", max: "2", invalid: true},
		"max only":        {max: "2", invalid: true},
		"explicit over":   {value: "backend,bug_hunter", max: "1", invalid: true},
		"case sensitive":  {value: "Auto", unknown: true},
		"explicit at max": {value: "backend,bug_hunter,frontend", max: "3", mode: "explicit", ids: []string{"backend", "bug_hunter", "frontend"}, limit: 3},
	} {
		t.Run(name, func(t *testing.T) {
			request, err := parseSpecialistRequest(tc.value, tc.max)
			var unknown errUnknownModelReviewProfile
			switch {
			case tc.unknown:
				if !errors.As(err, &unknown) || !strings.HasPrefix(unknown.Error(), "unknown --specialists ") {
					t.Fatalf("err=%v", err)
				}
			case tc.invalid:
				if err == nil || errors.As(err, &unknown) {
					t.Fatalf("err=%v", err)
				}
			default:
				if err != nil || request.mode != tc.mode || tc.limit != 0 && request.max != tc.limit || len(request.explicit) != len(tc.ids) {
					t.Fatalf("request=%+v err=%v", request, err)
				}
				for index, id := range tc.ids {
					if request.explicit[index].ProfileID() != id {
						t.Fatal("explicit order changed")
					}
				}
			}
		})
	}
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	base := f.args[2:]
	for name, extra := range map[string][]string{
		"profile and specialists": {"--profile", "backend", "--specialists", "auto"},
		"profile and none":        {"--profile", "backend", "--specialists", "none"},
		"investigation":           {"--specialists", "auto", "--investigation-policy", "/protected/investigation.json"},
		"max alone":               {"--max-specialists", "2"},
	} {
		if _, _, _, _, err := parseLocalModelReview(append(append([]string(nil), base...), extra...)); err == nil {
			t.Fatalf("%s: parser accepted conflicting intent", name)
		}
	}
	options, _, _, _, err := parseLocalModelReview(append(append([]string(nil), base...), "--specialists", "none"))
	if err != nil || options.specialists.active() || !options.specialist.IsZero() {
		t.Fatal("--specialists none did not keep the single-run path")
	}
}

func TestPlanAutoSpecialistsSelectsByChangeKind(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	inventory, policy, err := runtimeconfig.LoadProtectedConfiguration(context.Background(), f.inventoryPath, f.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	plan := func(t *testing.T, limit int, paths ...string) (specialistSelectionWire, []review.ContextSpecialist) {
		t.Helper()
		spec := agentprofile.ChangeFeaturesSpec{}
		for _, path := range paths {
			spec.Files = append(spec.Files, agentprofile.ChangedFileSpec{Path: path, AddedLines: 12, DeletedLines: 3})
		}
		features, err := agentprofile.NewChangeFeatures(spec)
		if err != nil {
			t.Fatal(err)
		}
		general := localreview.Report{GenerationRoute: f.generationRoute, VerificationRoute: f.verificationRoute}
		selection, selected := planAutoSpecialists(features, policy, inventory, general, limit)
		if selection.Status != "planned" || selection.Plan == nil || selection.Plan.FeaturesIdentity != features.Identity() || selection.RouteAssignment != routeAssignmentNotApplied {
			t.Fatalf("selection=%+v", selection)
		}
		if len(selected) != len(selection.Selected) {
			t.Fatal("selected specialists and trace disagree")
		}
		return selection, selected
	}
	ids := func(selection specialistSelectionWire) string {
		out := []string{}
		for _, value := range selection.Selected {
			out = append(out, value.ProfileID)
		}
		return strings.Join(out, ",")
	}
	reason := func(selection specialistSelectionWire, id string) string {
		for _, value := range selection.Dropped {
			if value.ProfileID == id {
				return value.Reason
			}
		}
		return ""
	}
	inactive := func(selection specialistSelectionWire, id string) bool {
		for _, value := range selection.Inactive {
			if value == id {
				return true
			}
		}
		return false
	}

	backend, _ := plan(t, 3, "internal/calc/sum.go", "internal/calc/mean.go")
	if ids(backend) != "bug_hunter,backend" || !inactive(backend, "frontend") {
		t.Fatalf("Go backend change selected %q", ids(backend))
	}
	if reason(backend, "test_author") != dropReasonNotApplicable || reason(backend, "orchestrator") != dropReasonNotApplicable {
		t.Fatal("planning-only or deterministic profiles were not recorded as not applicable")
	}
	frontend, _ := plan(t, 3, "web/src/App.tsx")
	if ids(frontend) != "bug_hunter,frontend" || !inactive(frontend, "backend") {
		t.Fatalf("frontend change selected %q", ids(frontend))
	}
	if reason(frontend, "knowledge_graph") != dropReasonNotApplicable {
		t.Fatal("gap-only knowledge graph profile was not recorded as not applicable")
	}
	// The plan uses the general review's recorded routes; without them it is
	// unavailable rather than re-deriving route selection.
	features, _ := agentprofile.NewChangeFeatures(agentprofile.ChangeFeaturesSpec{Files: []agentprofile.ChangedFileSpec{{Path: "internal/calc/sum.go", AddedLines: 1}}})
	for name, general := range map[string]localreview.Report{
		"no routes":       {},
		"unknown route":   {GenerationRoute: strings.Repeat("e", 64), VerificationRoute: f.verificationRoute},
		"generation only": {GenerationRoute: f.generationRoute},
	} {
		if selection, selected := planAutoSpecialists(features, policy, inventory, general, 3); selection.Status != "plan_unavailable" || selected != nil || selection.Plan != nil {
			t.Fatalf("%s: selection=%+v", name, selection)
		}
	}
	cut, selected := plan(t, 1, "internal/calc/sum.go")
	if ids(cut) != "bug_hunter" || len(selected) != 1 || reason(cut, "backend") != dropReasonLimit {
		t.Fatalf("max-specialists cut selected %q dropped=%+v", ids(cut), cut.Dropped)
	}
}

func TestMergeVerifiedFindingsDeduplicatesOverlappingDuplicates(t *testing.T) {
	finding := func(id, title, category string, severity diagnostics.Severity, start, end uint32) localreview.ReportFinding {
		return localreview.ReportFinding{Identity: id, Title: title, Claim: "A zero-valued caller now reaches the division and panics.", Severity: severity, Path: "a.go", StartLine: start, EndLine: end, Category: category}
	}
	merged, duplicates := mergeVerifiedFindings([]string{"general", "bug_hunter", "backend"}, [][]localreview.ReportFinding{
		{finding("g1", "Zero-valued caller now panics", "correctness", diagnostics.SeverityWarning, 2, 2)},
		{finding("b1", "zero valued caller,  now PANICS!", "correctness", diagnostics.SeverityError, 1, 3)},
		{
			finding("k1", "Zero-valued caller now panics", "correctness", diagnostics.SeverityWarning, 10, 12),
			finding("k2", "Zero-valued caller now panics", "security", diagnostics.SeverityWarning, 2, 2),
			finding("k3", "Zero-valued caller now panics", "correctness", diagnostics.SeverityHint, 3, 4),
		},
	})
	if len(merged) != 3 || duplicates != 2 {
		t.Fatalf("merged=%d duplicates=%d", len(merged), duplicates)
	}
	first := merged[0]
	// The representative is the strongest verified finding (the most severe),
	// reported at its own range; findings are in rank order.
	if first.FindingIdentity != "b1" || first.Severity != "error" || first.StartLine != 1 || first.EndLine != 3 || first.Category != "correctness" || first.Rank != 1 {
		t.Fatalf("representative=%+v", first)
	}
	if got := strings.Join(first.contributorLabels(), ","); got != "general,bug_hunter,backend" || len(first.Contributors) != 3 || first.Contributors[0].FindingIdentity != "g1" {
		t.Fatalf("contributors=%q", got)
	}
	if merged[1].FindingIdentity != "k2" || merged[2].FindingIdentity != "k1" {
		t.Fatal("distinct category or non-overlapping range was merged")
	}
}

func TestRunLocalGitModelReviewAutoSpecialistsRunsAndMerges(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, specialist: true, verificationMode: "medium_after_first"})
	receipt, _ := runLocalModelSet(t, f, []string{"--specialists", "auto"}, 4)
	if receipt.Status != "findings" || receipt.CI != "blocked" || !receipt.Complete || receipt.Selection.Mode != "auto" || receipt.Selection.Status != "planned" {
		t.Fatalf("receipt=%+v", receipt)
	}
	// The commit messages are declared intent, so the drift auditor joins the
	// Go profiles.
	if got := strings.Join(selectedIDs(receipt), ","); got != "bug_hunter,backend,drift_auditor" {
		t.Fatalf("auto selected %q for a Go change", got)
	}
	if droppedReason(receipt, "test_author") != dropReasonNotApplicable || receipt.Selection.Plan == nil || receipt.Selection.Plan.AssignmentsBasis != "synthesized_single_route_pair_from_general_review" {
		t.Fatal("selection trace lost dropped profiles or the synthesized assignments basis")
	}
	if features := receipt.Selection.Features; features == nil || features.ChangedFiles != 1 || strings.Join(features.Languages, ",") != "go" {
		t.Fatal("selection trace did not summarize the recorded change features")
	}
	if len(receipt.Members) != 4 || receipt.Summary.MembersRun != 4 || receipt.Bounds.MaxModelWallTimeMillis != 4*receipt.Bounds.MemberTimeoutMillis {
		t.Fatal("review set did not run general plus three specialists within the stated bound")
	}
	runs := map[string]bool{}
	for index, member := range receipt.Members {
		want := []string{"general", "bug_hunter", "backend", "drift_auditor"}[index]
		if member.Member != want || !member.Launched || member.RunStatus != "succeeded" || member.Status != "findings" || runs[member.ReviewRunID] || member.ReviewRunID == "" {
			t.Fatalf("member %d=%+v", index, member)
		}
		if member.GenerationRoute != f.generationRoute || member.VerificationRoute != f.verificationRoute || !member.UsageKnown {
			t.Fatal("member did not use the runtime policy route pair")
		}
		if tokens, err := json.Marshal(member.TokenUsage); err != nil || string(tokens) != memberTokens {
			t.Fatalf("member %s token usage = %s", member.Member, tokens)
		}
		runs[member.ReviewRunID] = true
	}
	if len(receipt.Findings) != 1 || receipt.Summary.DuplicatesMerged != 3 || receipt.Summary.BySeverity["error"] != 1 || receipt.Summary.ByCategory["correctness"] != 1 {
		t.Fatalf("merged findings=%+v summary=%+v", receipt.Findings, receipt.Summary)
	}
	merged := receipt.Findings[0]
	if merged.Severity != "error" || len(merged.Contributors) != 4 || merged.Contributors[0].Member != "general" || merged.FindingIdentity != merged.Contributors[0].FindingIdentity || merged.Contributors[1].Severity != "warning" {
		t.Fatal("dedup did not keep the highest-severity verified finding with every contributor")
	}

	generationCalls, generated := f.generation.snapshot()
	verificationCalls, verified := f.verification.snapshot()
	if generationCalls != 4 || verificationCalls != 4 || len(generated) != 4 || len(verified) != 4 {
		t.Fatalf("model calls=%d/%d", generationCalls, verificationCalls)
	}
	if len(generated[0].Packet.Specialist) != 0 && string(generated[0].Packet.Specialist) != "null" {
		t.Fatal("general review generation carried a specialist block")
	}
	for index, id := range []string{"bug_hunter", "backend", "drift_auditor"} {
		specialist, err := review.NewContextSpecialist(id)
		if err != nil {
			t.Fatal(err)
		}
		var block struct {
			ProfileID    string `json:"profile_id"`
			Instructions string `json:"instructions"`
		}
		generation := generated[index+1]
		if json.Unmarshal(generation.Packet.Specialist, &block) != nil || block.ProfileID != id || block.Instructions != "" || !strings.HasSuffix(generation.Instructions, specialist.Instructions()) || receipt.Members[index+1].ContextIdentity != generation.ContextID {
			t.Fatalf("generation %d did not carry the %s profile block", index+1, id)
		}
		for _, verification := range verified {
			if verification.Packet.Specialist != nil || bytes.Contains(verification.Payload, []byte(specialist.Instructions())) || strings.Contains(verification.Instructions, specialist.Instructions()) {
				t.Fatal("verifier request received specialist instructions")
			}
		}
	}
}

// TestRunLocalGitModelReviewAutoSpecialistsUseBaseDeclaredStyle checks that
// auto selection detects declared style from the base tree only: a head-only
// style configuration is reviewed as code and does not activate the profile.
func TestRunLocalGitModelReviewAutoSpecialistsUseBaseDeclaredStyle(t *testing.T) {
	ruff := []byte("line-length = 100\n")
	for _, test := range []struct {
		name       string
		base, head map[string][]byte
		selected   bool
	}{
		{"ruff.toml in base", map[string][]byte{"ruff.toml": ruff, "tool.py": []byte("x = 1\n")}, map[string][]byte{"ruff.toml": ruff, "tool.py": []byte("x = 2\n")}, true},
		{"no declared style", map[string][]byte{"tool.py": []byte("x = 1\n")}, map[string][]byte{"tool.py": []byte("x = 2\n")}, false},
		{"ruff.toml only in head", map[string][]byte{"tool.py": []byte("x = 1\n")}, map[string][]byte{"ruff.toml": ruff, "tool.py": []byte("x = 2\n")}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{extraBase: test.base, extraHead: test.head})
			receipt, _ := runLocalModelSet(t, f, []string{"--specialists", "auto", "--max-specialists", "6"}, 4)
			selected := strings.Contains(","+strings.Join(selectedIDs(receipt), ",")+",", ",style_conformance,")
			inactive := strings.Contains(","+strings.Join(receipt.Selection.Inactive, ",")+",", ",style_conformance,")
			if receipt.Selection.Status != "planned" || selected != test.selected || inactive == test.selected {
				t.Fatalf("style_conformance selected=%t inactive=%t, want selected=%t (selection %+v)", selected, inactive, test.selected, receipt.Selection)
			}
			if features := receipt.Selection.Features; features == nil || !strings.Contains(strings.Join(features.Languages, ","), "python") {
				t.Fatal("selection trace did not record the changed Python file")
			}
		})
	}
}

// TestRunLocalGitModelReviewAutoSpecialistsCountUnreadStyleConfiguration
// requires the selection trace to count base style configuration that routing
// could not use, and to omit the count when every file was used.
func TestRunLocalGitModelReviewAutoSpecialistsCountUnreadStyleConfiguration(t *testing.T) {
	files := map[string][]byte{}
	for index := 0; index < 18; index++ {
		files[fmt.Sprintf(".prettierrc.%02d", index)] = []byte(strings.Repeat("a", 58<<10))
	}
	oversized := map[string][]byte{"pyproject.toml": []byte("[tool.ruff]\n" + strings.Repeat("#", 64<<10))}
	for _, test := range []struct {
		name   string
		files  map[string][]byte
		unread int
	}{
		{"beyond the document bound", files, 1},
		{"over the file bound", oversized, 1},
		{"every file used", map[string][]byte{"ruff.toml": []byte("line-length = 100\n")}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{extraBase: test.files, extraHead: test.files})
			receipt, encoded := runLocalModelSet(t, f, []string{"--specialists", "auto"}, 4)
			features := receipt.Selection.Features
			if features == nil || test.unread == 0 && (features.StyleConfigurationUnread != nil || strings.Contains(encoded, `"style_configuration_unread"`)) ||
				test.unread != 0 && (features.StyleConfigurationUnread == nil || *features.StyleConfigurationUnread != test.unread) {
				t.Fatalf("selection features = %+v, want unread %d", features, test.unread)
			}
		})
	}
}

func TestRunLocalGitModelReviewMaxSpecialistsAndExplicitList(t *testing.T) {
	t.Run("max cut", func(t *testing.T) {
		f := newLocalModelFixture(t, localModelFixtureOptions{})
		receipt, _ := runLocalModelSet(t, f, []string{"--specialists", "auto", "--max-specialists", "1"}, 4)
		if got := strings.Join(selectedIDs(receipt), ","); got != "bug_hunter" || droppedReason(receipt, "backend") != dropReasonLimit || receipt.Bounds.MaxSpecialists != 1 {
			t.Fatalf("selected=%q dropped=%+v", got, receipt.Selection.Dropped)
		}
		if gc, _ := f.generation.snapshot(); gc != 2 || len(receipt.Members) != 2 {
			t.Fatal("max-specialists did not bound model calls")
		}
	})
	t.Run("explicit", func(t *testing.T) {
		f := newLocalModelFixture(t, localModelFixtureOptions{})
		receipt, _ := runLocalModelSet(t, f, []string{"--specialists", "backend"}, 4)
		if receipt.Selection.Mode != "explicit" || receipt.Selection.Plan != nil || strings.Join(selectedIDs(receipt), ",") != "backend" || len(receipt.Members) != 2 || receipt.Members[1].Member != "backend" {
			t.Fatalf("explicit receipt=%+v", receipt.Selection)
		}
		if gc, generated := f.generation.snapshot(); gc != 2 || !bytes.Contains(generated[1].Packet.Specialist, []byte(`"profile_id":"backend"`)) {
			t.Fatal("explicit specialist did not run with its profile block")
		}
	})
	t.Run("text", func(t *testing.T) {
		f := newCheckoutModelFixture(t, localModelFixtureOptions{})
		// The default text is for people: status, reviewers, the walkthrough
		// and the findings with the members that confirmed each.
		_, text := runLocalModelSet(t, f, []string{"--specialists", "backend", "--format", "text"}, 4)
		requireInOrder(t, text, "status: findings\nci: blocked\nreviewers: general, backend (2 of 2 ran)\nwalkthrough:\n", "confirmed findings (ranked): 1\n", "confirmed by: general, backend\n", "comprehensive clearance: false\n")
		for _, internal := range []string{"specialist review set:", "selection:", "selected:", "route assignment:", "members run:", "member: ", "status=", "findings: 1 (merged", "limitations:", "contributors:"} {
			if strings.Contains(text, internal) {
				t.Fatalf("default text shows the internal %q: %q", internal, text)
			}
		}
		// --verbose keeps every internal line.
		_, verbose := runLocalModelSet(t, f, []string{"--specialists", "backend", "--format", "text", "--verbose"}, 4)
		for _, want := range []string{"status: findings\nci: blocked\nreviewers: general, backend (2 of 2 ran)\ncomplete: true\n", "members run: 2 of 2\n", "selected: backend\n", "route assignment: not_applied: ", "member: general status=findings run=succeeded verified_findings=1\n", "findings: 1 (merged duplicates: 1) severity: error=1 category: correctness=1\n", "files covered: analyzed=2 selected=2 omitted=0\n", "confirmed by: general, backend\n", "limitations: per_profile_route_assignment_not_applied, ", "comprehensive clearance: false\n"} {
			if !strings.Contains(verbose, want) {
				t.Fatalf("verbose text output missing %q: %q", want, verbose)
			}
		}
	})
}

var localModelHexIdentity = regexp.MustCompile(`[0-9a-f]{64}`)

func TestRunLocalGitModelReviewSpecialistsNoneIsUnchanged(t *testing.T) {
	for _, format := range []string{"json", "text", "sarif"} {
		t.Run(format, func(t *testing.T) {
			outputs := [][]byte{}
			codes := []int{}
			for _, extra := range [][]string{nil, {"--specialists", "none"}} {
				f := newLocalModelFixture(t, localModelFixtureOptions{})
				args := append(replaceLocalGitChangeValue(f.args, "--format", format), extra...)
				var stdout, stderr bytes.Buffer
				codes = append(codes, run(args, &stdout, &stderr))
				if gc, _ := f.generation.snapshot(); gc != 1 {
					t.Fatal("--specialists none made extra model calls")
				}
				// Run, scope and artifact identities are nonce-bound per invocation.
				outputs = append(outputs, localModelHexIdentity.ReplaceAll(stdout.Bytes(), []byte("<id>")))
			}
			if codes[0] != codes[1] || !bytes.Equal(outputs[0], outputs[1]) || bytes.Contains(outputs[0], []byte("local-git-model-review-set")) {
				t.Fatalf("--specialists none changed output: %q vs %q", outputs[0], outputs[1])
			}
		})
	}
}

func TestRunLocalGitModelReviewSpecialistFailureStopsFurtherMembers(t *testing.T) {
	for _, tc := range []struct {
		policy string
		code   int
	}{{"default", 4}, {"findings", 4}, {"strict", 4}, {"always-zero", 0}} {
		t.Run(tc.policy, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "malformed_specialist"})
			receipt, _ := runLocalModelSet(t, f, []string{"--specialists", "bug_hunter,backend", "--exit-code-policy", tc.policy}, tc.code)
			// A failed member makes the set incomplete, but the general review's
			// verified error-severity finding still blocks: it is never demoted.
			if receipt.Status != "failed" || receipt.CI != "blocked" || receipt.Complete || len(receipt.Members) != 3 || receipt.Summary.MembersRun != 2 {
				t.Fatalf("receipt=%+v", receipt)
			}
			general, failed, skipped := receipt.Members[0], receipt.Members[1], receipt.Members[2]
			if general.RunStatus != "succeeded" || failed.Member != "bug_hunter" || failed.Status != "failed" || !failed.Launched {
				t.Fatal("failing specialist was not reported")
			}
			if skipped.Member != "backend" || skipped.Launched || skipped.NotLaunchedReason != "stopped_after_bug_hunter_failed" || skipped.ReviewRunID != "" {
				t.Fatalf("further member was launched or mislabeled: %+v", skipped)
			}
			// The failed specialist's rejected generation and its one retry were
			// dispatched and reported their usage; the member that never ran
			// reports none.
			if tokens, err := json.Marshal(general.TokenUsage); err != nil || string(tokens) != memberTokens {
				t.Fatalf("member general token usage = %s", tokens)
			}
			const retried = `{"known":true,"route_attempts":2,"input_tokens":200,"output_tokens":200,"cached_input_tokens":0,"generation":{"known":true,"route_attempts":2,"input_tokens":200,"output_tokens":200,"cached_input_tokens":0},"verification":{"known":true,"route_attempts":0,"input_tokens":0,"output_tokens":0,"cached_input_tokens":0}}`
			if tokens, err := json.Marshal(failed.TokenUsage); err != nil || string(tokens) != retried {
				t.Fatalf("member bug_hunter token usage = %s", tokens)
			}
			if skipped.TokenUsage != nil {
				t.Fatalf("member that never ran reports token usage %+v", skipped.TokenUsage)
			}
			gc, _ := f.generation.snapshot()
			vc, _ := f.verification.snapshot()
			if gc != 3 || vc != 1 {
				t.Fatalf("model calls=%d/%d after a member failure", gc, vc)
			}
			if len(receipt.Findings) != 1 || receipt.Findings[0].Contributors[0].Member != "general" || receipt.Findings[0].Severity != "error" {
				t.Fatal("completed general review findings were not kept")
			}
		})
	}
}

func TestRunLocalGitModelReviewSetSARIFAndExitPolicy(t *testing.T) {
	decode := func(t *testing.T, text string) sarifLog {
		t.Helper()
		var log sarifLog
		if err := json.Unmarshal([]byte(text), &log); err != nil || len(log.Runs) != 1 {
			t.Fatalf("SARIF=%q", text)
		}
		return log
	}
	t.Run("merged contributors", func(t *testing.T) {
		f := newLocalModelFixture(t, localModelFixtureOptions{})
		_, text := runLocalModelSet(t, f, []string{"--specialists", "auto", "--format", "sarif"}, 4)
		log := decode(t, text)
		results := log.Runs[0].Results
		if len(results) != 1 || strings.Join(results[0].Properties.Contributors, ",") != "general,bug_hunter,backend,drift_auditor" || results[0].Level != "error" {
			t.Fatalf("SARIF results=%+v", results)
		}
		if !log.Runs[0].Invocations[0].ExecutionSuccessful || log.Runs[0].Properties.ModelReviewStatus != "findings" {
			t.Fatal("complete review set SARIF did not report a successful run")
		}
	})
	t.Run("incomplete set keeps completed findings", func(t *testing.T) {
		f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "malformed_specialist"})
		// The completed general review's verified error-severity finding keeps
		// the incomplete set blocked (exit 4).
		_, text := runLocalModelSet(t, f, []string{"--specialists", "bug_hunter", "--format", "sarif"}, 4)
		log := decode(t, text)
		invocation := log.Runs[0].Invocations[0]
		if len(log.Runs[0].Results) != 1 || invocation.ExecutionSuccessful || len(invocation.ToolExecutionNotifications) != 1 || !strings.Contains(invocation.ToolExecutionNotifications[0].Message.Text, "did not complete") || log.Runs[0].Properties.CIDisposition != "blocked" {
			t.Fatalf("incomplete set SARIF=%q", text)
		}
	})
	t.Run("incomplete set without error finding is not blocked", func(t *testing.T) {
		f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "malformed_specialist", verificationMode: "medium"})
		receipt, _ := runLocalModelSet(t, f, []string{"--specialists", "bug_hunter"}, 1)
		if receipt.Complete || receipt.Status != "failed" || receipt.CI != "error" || len(receipt.Findings) != 1 || receipt.Findings[0].Severity == "error" {
			t.Fatalf("receipt=%+v", receipt)
		}
	})
	for _, tc := range []struct {
		name, policy, mode string
		code               int
	}{
		{"findings policy high", "findings", "", 4},
		{"findings policy medium", "findings", "medium", 0},
		{"strict medium", "strict", "medium", 4},
		{"always-zero", "always-zero", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{verificationMode: tc.mode})
			receipt, _ := runLocalModelSet(t, f, []string{"--specialists", "auto", "--max-specialists", "1", "--exit-code-policy", tc.policy}, tc.code)
			if !receipt.Complete || receipt.Status != "findings" {
				t.Fatalf("receipt=%+v", receipt)
			}
		})
	}
	t.Run("refused general review", func(t *testing.T) {
		f := newLocalModelFixture(t, localModelFixtureOptions{expensive: true})
		receipt, _ := runLocalModelSet(t, f, []string{"--specialists", "auto", "--exit-code-policy", "always-zero"}, 4)
		if receipt.Status != "refused" || receipt.Complete || receipt.Summary.MembersRun != 1 || receipt.Members[0].Status != "refused" {
			t.Fatalf("refused general review receipt=%+v", receipt)
		}
		for _, member := range receipt.Members[1:] {
			if member.Launched || member.NotLaunchedReason != "general_review_did_not_complete" {
				t.Fatalf("specialist launched after a refused general review: %+v", member)
			}
		}
		if gc, _ := f.generation.snapshot(); gc != 0 {
			t.Fatal("refused general review reached a provider")
		}
	})
}

func TestRunLocalGitModelReviewSetReportsReviewerProgress(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, specialist: true, verificationMode: "medium_after_first"})
	p, buf, _ := testProgress(false, false, 60)
	var stdout, stderr bytes.Buffer
	args := append(append([]string(nil), f.args[2:]...), "--specialists", "auto")
	if code := runLocalGitModelReviewObserved(withReviewProgress(context.Background(), p), args, &stdout, &stderr, nil); code != 4 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	for _, want := range []string{"Finding problems · general\n", "Finding problems · bug_hunter (2 of 4 reviewers)\n", "Checking findings · drift_auditor (4 of 4 reviewers)\n", "Finishing\n"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("progress lacks %q:\n%s", want, buf.String())
		}
	}
}
