package main

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/localreview"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

type investigationSessionReceipt struct {
	localModelReceipt
	UsageKnown    bool `json:"usage_known"`
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

func newInvestigationSessionForTest(t *testing.T, options localreview.SessionOptions, policy review.InvestigationPolicy) *localreview.Session {
	t.Helper()
	session, err := localreview.NewInvestigationSession(options, policy)
	if err != nil {
		_ = options.ObjectsRoot.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := session.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return session
}

func investigationSessionHandlers(t *testing.T, prepared runtimecatalog.PreparedReviewRun) map[string]string {
	t.Helper()
	if err := prepared.Validate(); err != nil {
		t.Fatal(err)
	}
	expected := []struct {
		key          string
		kind         controlplane.TaskKind
		dependencies []string
	}{
		{"source-base", controlplane.TaskAcquireSource, nil},
		{"source-head", controlplane.TaskAcquireSource, nil},
		{"change", controlplane.TaskBuildChange, []string{"source-base", "source-head"}},
		{"analysis", controlplane.TaskInspectDeterministic, []string{"change"}},
		{"memory", controlplane.TaskRetrieveContext, []string{"change"}},
		{"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}},
		{"candidates", controlplane.TaskGenerateCandidates, []string{"context"}},
		{"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}},
		{"readiness", controlplane.TaskEvaluatePublication, []string{"analysis", "change", "verification"}},
	}
	plan := prepared.Plan()
	if plan.Mode() != controlplane.ReviewRunLocal || plan.TaskCount() != len(expected) {
		t.Fatal("prepared Session did not retain the exact nine-task local graph")
	}
	handlers := make(map[string]string, len(expected))
	for _, want := range expected {
		task, ok := plan.Task(want.key)
		if !ok || task.Kind() != want.kind || !task.Required() || !slices.Equal(task.Dependencies(), want.dependencies) {
			t.Fatalf("prepared task %s changed kind, dependencies, or required status", want.key)
		}
		attempts, err := controlplane.DefaultTaskAttemptPolicy(want.kind)
		if err != nil || task.MaxAttempts() != attempts.MaximumAttempts() || task.RetryDelayMilliseconds() != attempts.RetryDelayMilliseconds() || task.LeaseDurationMilliseconds() != attempts.LeaseDurationMilliseconds() {
			t.Fatalf("prepared task %s changed default attempt policy", want.key)
		}
		localModelRequireDigest(t, task.HandlerIdentity())
		handlers[want.key] = task.HandlerIdentity()
	}
	if handlers["source-base"] != handlers["source-head"] {
		t.Fatal("source tasks no longer share their handler identity")
	}
	return handlers
}

func requireInvestigationSessionReceipt(t *testing.T, prepared runtimecatalog.PreparedReviewRun, result localreview.Result, captures []investigationCapture) investigationSessionReceipt {
	t.Helper()
	investigationSessionHandlers(t, prepared)
	encoded, err := localreview.EncodeResult(result)
	if err != nil || len(encoded) == 0 || len(encoded) > 256<<10 {
		t.Fatal("completed investigation Result is not bounded JSON")
	}
	var receipt investigationSessionReceipt
	if err := json.Unmarshal(encoded, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Contract != "open-trestle/local-git-model-review-result" || receipt.Version != 2 || receipt.Status != "findings" || receipt.CI != "blocked" || receipt.RunStatus != "succeeded" || receipt.Failure != "" || receipt.ComprehensiveClearance || result.ExitCode() != 4 {
		t.Fatal("actual Session did not seal a schema2 independent finding")
	}
	if receipt.Request != prepared.RequestIdentity() || receipt.Plan != prepared.Plan().Identity() || receipt.Scope != prepared.Plan().Scope().Identity() || receipt.Run != prepared.Plan().Scope().ReviewRunID() {
		t.Fatal("receipt is not bound to the actual prepared run")
	}
	localModelRequireDigest(t, receipt.Output, receipt.Readiness, receipt.Context, receipt.CandidateBatch, receipt.VerificationContext)
	if len(receipt.Tasks) != 9 {
		t.Fatal("receipt omitted real task completions")
	}
	outputs := map[string]string{}
	for _, task := range receipt.Tasks {
		definition, ok := prepared.Plan().Task(task.Key)
		if !ok || outputs[task.Key] != "" || task.Status != "succeeded" || task.Attempts != 1 || task.MaxAttempts != definition.MaxAttempts() {
			t.Fatal("receipt has missing, duplicate, retried, or unsuccessful tasks")
		}
		localModelRequireDigest(t, task.Output)
		outputs[task.Key] = task.Output
	}
	if outputs["source-base"] == outputs["source-head"] || outputs["readiness"] != receipt.Output {
		t.Fatal("actual source/readiness outputs lost their task roles")
	}
	if len(captures) != 5 || len(receipt.Investigation.Turns) != 5 || receipt.Investigation.ToolCalls != 3 || receipt.Investigation.ReturnedBytes == 0 || receipt.Investigation.ReturnedBytes > 32768 || !receipt.UsageKnown {
		t.Fatal("receipt lost paid turns, tool work, or known cumulative usage")
	}
	claimed, completed, reconciled := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, event := range receipt.Audit {
		if strings.HasPrefix(event.Kind, "publication_") {
			t.Fatal("local investigation gained publication authority")
		}
		var subjects map[string]bool
		switch event.Kind {
		case "route_attempt_claimed":
			subjects = claimed
		case "route_dispatch_completed":
			subjects = completed
		case "route_cost_reconciled":
			subjects = reconciled
		}
		if subjects != nil {
			if subjects[event.Subject] {
				t.Fatal("receipt duplicated a route claim, outcome, or reconciliation")
			}
			subjects[event.Subject] = true
		}
	}
	if len(claimed) != 5 || len(completed) != 5 || len(reconciled) != 5 {
		t.Fatal("receipt audit omitted or invented a paid execution")
	}
	seen := map[string]bool{}
	for i, capture := range captures {
		turn := receipt.Investigation.Turns[i]
		localModelRequireDigest(t, turn.Request, turn.Authorization, turn.Outcome, turn.Reconciliation)
		if capture.packet.Scope != receipt.Scope || turn.Request != capture.request || seen[turn.Request] || !claimed[turn.Authorization] || !completed[turn.Outcome] || !reconciled[turn.Reconciliation] {
			t.Fatal("paid turn is not distinct and bound to the actual request and ledger")
		}
		seen[turn.Request] = true
		delete(claimed, turn.Authorization)
		delete(completed, turn.Outcome)
		delete(reconciled, turn.Reconciliation)
		if i < 4 {
			state := capture.packet.Investigation
			if capture.packet.Task != "candidate_generation" || capture.packet.Version != 4 || state.Turn != uint32(i+1) || state.Session != captures[0].packet.Investigation.Session {
				t.Fatal("actual generation turns lost their one-run investigation identity")
			}
			if i > 0 {
				prior := receipt.Investigation.Turns[i-1]
				if state.PreviousRequest != prior.Request || state.PreviousOutcome != prior.Outcome || !slices.Equal(state.PreviousResults, prior.Results) || len(prior.Results) != 1 {
					t.Fatal("continuation lost its actual preceding outcome and tool result")
				}
			}
		}
	}
	if len(claimed)+len(completed)+len(reconciled) != 0 {
		t.Fatal("actual route events were not all consumed by distinct receipt turns")
	}
	for i, tool := range []string{"snapshot.list", "snapshot.read", "snapshot.search"} {
		prior := receipt.Investigation.Turns[i]
		found := false
		for _, result := range captures[i+1].packet.Investigation.Results {
			if result.Tool == tool && len(prior.Results) == 1 && result.ArtifactIdentity == prior.Results[0] {
				localModelRequireDigest(t, result.Identity, result.ArtifactIdentity)
				found = true
			}
		}
		if !found {
			t.Fatalf("actual %s result never reached its successor model request", tool)
		}
	}
	verifier := captures[4]
	if verifier.packet.Task != "candidate_verification" || verifier.packet.Version != 3 || receipt.GenerationRequest != captures[3].request || receipt.VerificationRequest != verifier.request || receipt.Context != verifier.packet.GenerationContext || receipt.CandidateBatch != verifier.packet.CandidateBatch || len(verifier.packet.Candidates) != 1 || len(receipt.CandidateIDs) != 1 || receipt.CandidateIDs[0] != verifier.packet.Candidates[0].ID {
		t.Fatal("final result is disconnected from actual final generation and verifier")
	}
	if receipt.Independence != "distinct_provider" || receipt.GenerationRoute == receipt.VerificationRoute || receipt.Diagnostics.Coverage.VerifiedCount != 1 || len(receipt.Diagnostics.Findings) != 1 {
		t.Fatal("actual independent verification did not admit exactly one finding")
	}
	return receipt
}

func investigationSessionRender(t *testing.T, f *localModelFixture, result localreview.Result) ([]byte, []byte) {
	t.Helper()
	encoded, err := localreview.EncodeResult(result)
	if err != nil || len(encoded) == 0 || len(encoded) > 256<<10 {
		t.Fatal("Result JSON exceeded its bound or became unavailable")
	}
	var text bytes.Buffer
	if err := localreview.RenderResult(&text, result); err != nil || text.Len() == 0 || text.Len() > 64<<10 {
		t.Fatal("Result text exceeded its bound or became unavailable")
	}
	for _, output := range []string{string(encoded), text.String()} {
		for _, forbidden := range []string{f.objects, f.inventoryPath, f.policyPath, localModelKey, localModelSecret, "return 10 / x", "Consume is enabled for zero-valued requests.", "deployment notes", "OPEN_TRESTLE_PROVIDER_LOCAL_TEST", "Bearer "} {
			if strings.Contains(output, forbidden) {
				t.Fatal("sealed result disclosed source, configuration paths, or credentials")
			}
		}
	}
	if !strings.Contains(text.String(), "comprehensive clearance: false") {
		t.Fatal("text lost its explicit no-clearance limit")
	}
	return encoded, text.Bytes()
}

func TestLocalGitInvestigationSessionRunsDistinctScopesSequentially(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f, endpoint, limits, _ := newInvestigationFixture(t, "", cancel)
	policy, err := review.ParseInvestigationPolicy(localModelJSON(t, limits))
	if err != nil {
		t.Fatal(err)
	}
	options, _ := localModelSessionOptions(t, f)
	options.Timeout = 30 * time.Second
	options.ArtifactCapacity = 512
	session := newInvestigationSessionForTest(t, options, policy)
	var receipts []investigationSessionReceipt
	var sessions []string
	seenRequests, seenAuthorities := map[string]bool{}, map[string]bool{}
	for i, runID := range []string{"investigation-first-scope", "investigation-second-scope"} {
		prepared := localModelPrepare(t, session, f, runID)
		before := endpoint.snapshot()
		if len(before) != i*5 {
			t.Fatal("preparation performed or lost an external model call")
		}
		result, err := session.Run(ctx, prepared)
		if err != nil {
			t.Fatal(err)
		}
		all := endpoint.snapshot()
		if len(all) != (i+1)*5 {
			t.Fatal("sequential scope did not make exactly five new actual model calls")
		}
		for j := range before {
			if all[j].request != before[j].request {
				t.Fatal("earlier external evidence was reset or replaced")
			}
		}
		captures := all[i*5:]
		receipt := requireInvestigationSessionReceipt(t, prepared, result, captures)
		investigationSessionRender(t, f, result)
		receipts = append(receipts, receipt)
		sessions = append(sessions, captures[0].packet.Investigation.Session)
		for _, turn := range receipt.Investigation.Turns {
			if seenRequests[turn.Request] || seenAuthorities[turn.Authorization] {
				t.Fatal("a distinct scope reused an earlier model request or paid claim")
			}
			seenRequests[turn.Request], seenAuthorities[turn.Authorization] = true, true
		}
	}
	localModelRequireDigest(t, sessions...)
	if sessions[0] == sessions[1] || receipts[0].Run == receipts[1].Run || receipts[0].Scope == receipts[1].Scope || receipts[0].Request == receipts[1].Request || receipts[0].Plan == receipts[1].Plan {
		t.Fatal("sequential scopes reused run or investigation ownership identities")
	}
	if len(endpoint.snapshot()) != 10 || len(seenRequests) != 10 || len(seenAuthorities) != 10 {
		t.Fatal("both actual five-call executions were not retained")
	}
}

func TestLocalGitInvestigationSessionBindsPolicyToSemanticHandlers(t *testing.T) {
	f, endpoint, limits, _ := newInvestigationFixture(t, "", nil)
	policy, err := review.ParseInvestigationPolicy(localModelJSON(t, limits))
	if err != nil {
		t.Fatal(err)
	}
	limits["max_lines_per_read"] = 21
	changed, err := review.ParseInvestigationPolicy(localModelJSON(t, limits))
	if err != nil || changed.Identity() == policy.Identity() {
		t.Fatal("one-limit fixture change did not produce a distinct valid policy")
	}
	prepareDefault := func() runtimecatalog.PreparedReviewRun {
		options, _ := localModelSessionOptions(t, f)
		return localModelPrepare(t, localModelNewSession(t, options), f, "same-profile-scope")
	}
	prepareOptIn := func(p review.InvestigationPolicy) runtimecatalog.PreparedReviewRun {
		options, _ := localModelSessionOptions(t, f)
		return localModelPrepare(t, newInvestigationSessionForTest(t, options, p), f, "same-profile-scope")
	}
	baseline := investigationSessionHandlers(t, prepareDefault())
	first, second, different := prepareOptIn(policy), prepareOptIn(policy), prepareOptIn(changed)
	firstHandlers := investigationSessionHandlers(t, first)
	secondHandlers := investigationSessionHandlers(t, second)
	differentHandlers := investigationSessionHandlers(t, different)
	if first.RequestIdentity() == second.RequestIdentity() {
		t.Fatal("independent Sessions shared prepared authority")
	}
	if !maps.Equal(firstHandlers, secondHandlers) {
		t.Fatal("equal policy/config produced nonce-dependent semantic handler identities")
	}
	if maps.Equal(firstHandlers, baseline) || maps.Equal(firstHandlers, differentHandlers) {
		t.Fatal("opt-in profile or changed valid policy limit is absent from semantic handler identities")
	}
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory"} {
		if firstHandlers[key] != baseline[key] || differentHandlers[key] != baseline[key] {
			t.Fatalf("opt-in policy changed the default %s handler identity", key)
		}
	}
	if !maps.Equal(baseline, investigationSessionHandlers(t, prepareDefault())) {
		t.Fatal("opt-in construction changed later default Session identities")
	}
	generationCalls, _ := f.generation.snapshot()
	verificationCalls, _ := f.verification.snapshot()
	if len(endpoint.snapshot()) != 0 || generationCalls != 0 || verificationCalls != 0 {
		t.Fatal("pure profile preparation executed external models")
	}
}

func TestLocalGitInvestigationSessionResultRendersAfterClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f, endpoint, limits, _ := newInvestigationFixture(t, "", cancel)
	policy, err := review.ParseInvestigationPolicy(localModelJSON(t, limits))
	if err != nil {
		t.Fatal(err)
	}
	options, objects := localModelSessionOptions(t, f)
	options.Timeout = 30 * time.Second
	session := newInvestigationSessionForTest(t, options, policy)
	prepared := localModelPrepare(t, session, f, "sealed-investigation-result")
	result, err := session.Run(ctx, prepared)
	if err != nil {
		t.Fatal(err)
	}
	captures := endpoint.snapshot()
	requireInvestigationSessionReceipt(t, prepared, result, captures)
	beforeJSON, beforeText := investigationSessionRender(t, f, result)
	if _, err := objects.Stat("."); err != nil {
		t.Fatal("completed Run closed the Session root before explicit Close")
	}
	if len(endpoint.snapshot()) != len(captures) {
		t.Fatal("pre-close result projection repeated an external call")
	}
	closeCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := session.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.Stat("."); err == nil {
		t.Fatal("successful Session.Close left its actual ObjectsRoot open")
	}
	// The closed root is observed; source Get attempts are not observable here.
	for i := 0; i < 2; i++ {
		afterJSON, afterText := investigationSessionRender(t, f, result)
		if !bytes.Equal(beforeJSON, afterJSON) || !bytes.Equal(beforeText, afterText) {
			t.Fatal("sealed Result rendering changed or required live Session custody")
		}
	}
	if len(endpoint.snapshot()) != 5 {
		t.Fatal("Close or sealed Result rendering repeated an external model call")
	}
}
