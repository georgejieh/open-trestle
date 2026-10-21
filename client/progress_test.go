package client

import (
	"context"
	"encoding/json"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGetRunProgressPendingAndScopeBinding(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, 1, 1000, 30000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("c", 64), strings.Repeat("d", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	state, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := controlplane.NewReviewRunReceipt(state)
	encodedReceipt, _ := controlplane.EncodeReviewRunReceipt(receipt)
	principal, _ := httpapi.NewPrincipal("reader", "tenant-a", []string{"repo-a"}, []httpapi.Capability{httpapi.CapabilityRunRead})
	authenticator, _ := httpapi.NewStaticTokenAuthenticator([]httpapi.StaticToken{{Token: strings.Repeat("a", 32), Principal: principal}})
	api, _ := httpapi.NewServer(coordinator, authenticator, httpapi.SystemClock{})
	server := httptest.NewServer(api)
	defer server.Close()
	c, err := New(server.URL, strings.Repeat("a", 32), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	progress, err := c.GetRunProgress(context.Background(), scope)
	if err != nil || progress.Run.Identity() != receipt.Identity() || progress.Progress.Change.State != "not_run" || progress.Progress.Context.Analyzed != nil {
		t.Fatalf("result=%+v err=%v", progress, err)
	}
	marshaled, err := json.Marshal(progress)
	if err != nil {
		t.Fatal(err)
	}
	var serialized map[string]json.RawMessage
	if err = json.Unmarshal(marshaled, &serialized); err != nil {
		t.Fatal(err)
	}
	if len(serialized) != 2 || serialized["progress"] == nil {
		t.Fatal("progress JSON contains transport envelope fields")
	}
	parsed, err := controlplane.ParseReviewRunReceipt(serialized["run"])
	if err != nil || parsed.Identity() != receipt.Identity() {
		t.Fatal("JSON lost canonical receipt")
	}
	if _, err = json.Marshal(RunProgress{}); err == nil {
		t.Fatal("invalid run serialized")
	}
	baseline := map[string]any{"contract": "open-trestle/run-progress-response", "schema_version": 1, "request_id": "request-1", "run": json.RawMessage(encodedReceipt), "progress": map[string]any{"change": map[string]any{"state": "not_run"}, "deterministic": map[string]any{"state": "not_run"}, "context": map[string]any{"state": "not_run"}, "verification": map[string]any{"state": "not_run"}}}
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { v["schema_version"] = 2 }, func(v map[string]any) { v["unknown"] = 1 }, func(v map[string]any) {
			v["progress"].(map[string]any)["change"] = map[string]any{"state": "available", "files": 0, "ranges": 0}
		}, func(v map[string]any) {
			v["progress"].(map[string]any)["context"] = map[string]any{"state": "not_run", "selected": 0}
		}, func(v map[string]any) { delete(v["progress"].(map[string]any), "verification") },
	} {
		original, _ := json.Marshal(baseline)
		var v map[string]any
		json.Unmarshal(original, &v)
		v["run"] = json.RawMessage(encodedReceipt)
		mutate(v)
		encoded, _ := json.Marshal(v)
		if _, err := parseRunProgress(encoded, scope); err == nil {
			t.Fatalf("invalid accepted=%s", encoded)
		}
	}
	encoded, _ := json.Marshal(baseline)
	wrong, _ := audit.NewReviewScope("tenant-a", "repo-a", "other-run")
	if _, err := parseRunProgress(encoded, wrong); err == nil {
		t.Fatal("cross-run response accepted")
	}
}
func TestGetRunProgressRejectsRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusFound)
	}))
	defer server.Close()
	c, _ := New(server.URL, strings.Repeat("a", 32), server.Client())
	scope, _ := audit.NewReviewScope("tenant", "repo", "run")
	if _, err := c.GetRunProgress(context.Background(), scope); err != ErrRedirectRejected {
		t.Fatalf("err=%v", err)
	}
}

func TestProgressClientAvailableZeroAndCountInvariants(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant", "repo", "run")
	kinds := []controlplane.TaskKind{controlplane.TaskAcquireSource, controlplane.TaskBuildChange, controlplane.TaskInspectDeterministic, controlplane.TaskAssembleContext, controlplane.TaskGenerateCandidates, controlplane.TaskVerifyCandidates}
	keys := []string{"source", "change", "analysis", "context", "candidates", "verification"}
	var tasks []controlplane.TaskDefinition
	for i, kind := range kinds {
		var deps []string
		if i > 0 {
			deps = []string{keys[i-1]}
		}
		task, _ := controlplane.NewTaskDefinition(keys[i], kind, strings.Repeat("a", 64), strings.Repeat("b", 64), deps, 1, 1000, 30000, true)
		tasks = append(tasks, task)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("c", 64), strings.Repeat("d", 64), controlplane.ReviewRunAdvisory, tasks)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	at := int64(101)
	for _, task := range tasks {
		coordinator.Advance(context.Background(), plan, time.UnixMilli(at))
		at++
		lease, _, err := coordinator.ClaimTask(context.Background(), plan, task.Key(), task.HandlerIdentity(), "worker", time.UnixMilli(at))
		if err != nil {
			t.Fatal(err)
		}
		at++
		success, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
		if _, err = coordinator.CompleteTask(context.Background(), plan, lease, success, time.UnixMilli(at)); err != nil {
			t.Fatal(err)
		}
		at++
	}
	receipt, _ := coordinator.Receipt(context.Background(), scope)
	encodedReceipt, _ := controlplane.EncodeReviewRunReceipt(receipt)
	id := strings.Repeat("e", 64)
	coverage := map[string]any{"change": map[string]any{"state": "available", "artifact_identity": id, "files": 0, "ranges": 0}, "deterministic": map[string]any{"state": "available", "artifact_identity": id, "applicable_files": 0, "applicable_ranges": 0, "checked_files": 0, "checked_ranges": 0, "observations": 0}, "context": map[string]any{"state": "available", "artifact_identity": id, "analyzed": 0, "selected": 0, "omitted": 0}, "verification": map[string]any{"state": "available", "artifact_identity": id, "candidates": 0, "verified": 0, "rejected": 0, "inconclusive": 0}}
	envelope := map[string]any{"contract": "open-trestle/run-progress-response", "schema_version": 1, "request_id": "request-1", "run": json.RawMessage(encodedReceipt), "progress": coverage}
	encoded, _ := json.Marshal(envelope)
	got, err := parseRunProgress(encoded, scope)
	if err != nil || got.Progress.Verification.Verified == nil || *got.Progress.Verification.Verified != 0 {
		t.Fatalf("zero missing err=%v", err)
	}
	coverage["deterministic"].(map[string]any)["state"] = "partial"
	partial, _ := json.Marshal(envelope)
	if _, err := parseRunProgress(partial, scope); err != nil {
		t.Fatalf("partial deterministic check with zero counts rejected: %v", err)
	}
	coverage["deterministic"].(map[string]any)["state"] = "available"
	for _, axis := range []string{"change", "context", "verification", "deterministic"} {
		t.Run("partial/"+axis, func(t *testing.T) {
			raw, _ := json.Marshal(envelope)
			var value map[string]any
			json.Unmarshal(raw, &value)
			value["run"] = json.RawMessage(encodedReceipt)
			item := value["progress"].(map[string]any)[axis].(map[string]any)
			item["state"] = "partial"
			if axis == "deterministic" {
				for _, key := range []string{"applicable_files", "applicable_ranges", "checked_files", "checked_ranges"} {
					delete(item, key)
				}
			}
			encoded, _ := json.Marshal(value)
			if _, err := parseRunProgress(encoded, scope); err == nil {
				t.Fatalf("invalid partial state accepted: %s", encoded)
			}
		})
	}
	for _, mutation := range []struct {
		axis, key string
		value     any
	}{{"change", "files", 4097}, {"deterministic", "checked_ranges", 1}, {"context", "selected", 1}, {"verification", "verified", 1}, {"verification", "candidates", 17}, {"deterministic", "observations", -1}, {"change", "artifact_identity", strings.Repeat("f", 64)}, {"change", "state", "unavailable"}} {
		raw, _ := json.Marshal(envelope)
		var v map[string]any
		json.Unmarshal(raw, &v)
		v["run"] = json.RawMessage(encodedReceipt)
		v["progress"].(map[string]any)[mutation.axis].(map[string]any)[mutation.key] = mutation.value
		bad, _ := json.Marshal(v)
		if _, err := parseRunProgress(bad, scope); err == nil {
			t.Fatalf("invalid accepted=%s", bad)
		}
	}
}
