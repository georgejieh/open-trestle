//go:build unix

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func testTerminalCandidateExpiryProof(t *testing.T, ctx context.Context, d *daemon, args []string, repository evidence.RepositoryIdentity, policy runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, handler string, candidate artifact.Artifact, now time.Time) {
	t.Helper()
	facts, err := d.journal.(*controlplane.FileRunJournal).InspectHistoricalContextPackets(ctx)
	if err != nil || len(facts) != 1 {
		t.Fatalf("terminal facts: %v", err)
	}
	fact := facts[0]
	proof, err := validateTerminalModelExpiryJournal(fact, now)
	if err != nil || proof.task != "candidates" || proof.latestLease.LeaseExpiresAt().After(proof.failed.OccurredAt()) {
		t.Fatalf("expiry journal proof: %v", err)
	}
	if _, err := validateTerminalModelExpiryJournal(fact, proof.failed.OccurredAt().Add(-time.Millisecond)); err == nil {
		t.Fatal("future expiry admitted")
	}
	statePath := daemonTestFlagValue(t, args, "--state-dir")
	gitRoot, rootDigest, err := openDaemonLocalGitRoot(daemonTestFlagValue(t, args, "--local-git-objects-root"), repository)
	if err != nil {
		t.Fatal(err)
	}
	defer gitRoot.Close()
	objectStore, err := scm.NewLocalGitObjectStore(gitRoot, repository)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := scm.NewLocalGitSourceAdapter(objectStore)
	if err != nil {
		t.Fatal(err)
	}
	binding := historicalRecordedSourceBinding{RootIdentity: rootDigest, RepositoryIdentity: repository.Identity(), AdapterIdentity: adapter.Identity().Identity()}
	stateRoot, err := os.OpenRoot(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stateRoot.Close()
	artifactRoot, err := stateRoot.OpenRoot("artifacts")
	if err != nil {
		t.Fatal(err)
	}
	defer artifactRoot.Close()
	check := func(at time.Time, source historicalRecordedSourceBinding) error {
		_, err := observeTerminalModelExpiryPhysical(ctx, stateRoot, artifactRoot, fact, policy, inventory, handler, daemonTestGenerationSanitizer().ExpectedBinaryDigests(), daemonTestVerificationSanitizer().ExpectedBinaryDigests(), source, at)
		return err
	}
	if err := check(now, binding); err != nil {
		t.Fatalf("terminal physical proof: %v", err)
	}
	if err := check(candidate.ExpiresAt(), binding); err == nil {
		t.Fatal("expired candidate proof admitted")
	}
	foreign := binding
	foreign.RootIdentity = strings.Repeat("f", 64)
	if err := check(now, foreign); err == nil {
		t.Fatal("foreign source root admitted")
	}
	extra := filepath.Join(statePath, "artifacts", fact.Plan().Scope().Identity()+"-"+strings.Repeat("f", 64)+".artifact.json")
	if err := os.WriteFile(extra, []byte("unknown partial effect"), 0600); err != nil {
		t.Fatal(err)
	}
	refused := check(now, binding)
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if refused == nil {
		t.Fatal("unknown extra artifact admitted")
	}
	marker := filepath.Join(statePath, fact.Plan().Scope().Identity()+".scope-intent.json")
	if err := os.WriteFile(marker, []byte("unknown"), 0600); err != nil {
		t.Fatal(err)
	}
	refused = check(now, binding)
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if refused == nil {
		t.Fatal("pending marker admitted")
	}
	auditPath := filepath.Join(statePath, "audit", fact.Plan().Scope().Identity()+".audit.jsonl")
	original, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(original), []byte("\n"))
	// rewrite rechains the audit with each event's subject and parents mapped
	// through rename, and reports whether startup still proves it.
	rewrite := func(rename func(i int, identity string) string) error {
		t.Helper()
		var changed bytes.Buffer
		previous := ""
		for i, line := range lines {
			event, err := audit.ParseEvent(line)
			if err != nil {
				t.Fatal(err)
			}
			parents := event.CausalParentIdentities()
			for j, parent := range parents {
				parents[j] = rename(-1, parent)
			}
			event, err = audit.NewEvent(event.Scope(), event.Sequence(), previous, event.Kind(), rename(i, event.SubjectIdentity()), parents, time.UnixMilli(event.OccurredAtUnixMilliseconds()))
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := audit.EncodeEvent(event)
			if err != nil {
				t.Fatal(err)
			}
			changed.Write(encoded)
			changed.WriteByte(10)
			previous = event.Identity()
		}
		if err := os.WriteFile(auditPath, changed.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		refused := check(now, binding)
		if err := os.WriteFile(auditPath, original, 0600); err != nil {
			t.Fatal(err)
		}
		return refused
	}
	invented := strings.Repeat("f", 64)
	if rewrite(func(i int, identity string) string {
		if i == 1 {
			return invented
		}
		return identity
	}) == nil {
		t.Fatal("invented claim subject admitted")
	}
	// A refused attempt the handler retried left no artifact, so only its
	// lineage ties it to the input's authorization: a consistently renamed
	// retry claim is still not the one the gateway grants.
	if len(lines) > 7 {
		retry, err := audit.ParseEvent(lines[4])
		if err != nil || retry.Kind() != audit.EventRouteAttemptClaimed {
			t.Fatalf("retried audit shape: %v", err)
		}
		if rewrite(func(_ int, identity string) string {
			if identity == retry.SubjectIdentity() {
				return invented
			}
			return identity
		}) == nil {
			t.Fatal("renamed retry claim admitted")
		}
	}
	if err := check(now, binding); err != nil {
		t.Fatalf("restored proof: %v", err)
	}
	testTerminalExpiryRejectsHandlerFailure(t, fact, now)
}

func testTerminalExpiryRejectsHandlerFailure(t *testing.T, fact controlplane.HistoricalContextPacketFact, now time.Time) {
	t.Helper()
	plan, events := fact.Plan(), fact.ReplayEvents()
	result := make([]controlplane.RunEvent, 0, len(events))
	previous := ""
	var claimed controlplane.RunEvent
	for _, event := range events {
		if event.Kind() == controlplane.RunEventTaskLeased && event.TaskKey() == "candidates" {
			claimed = event
		}
		if event.Kind() == controlplane.RunEventTaskFailed || event.Kind() == controlplane.RunEventTaskSkipped || event.Kind() == controlplane.RunEventFailed {
			task, _ := plan.Task(event.TaskKey())
			current, err := controlplane.NewRunEvent(plan, uint64(len(result)+1), previous, event.Kind(), task, event.Attempt(), event.LeaseTokenIdentity(), event.WorkerIdentity(), event.LeaseExpiresAt(), event.OutputIdentity(), event.Failure(), event.RetryAt(), claimed.OccurredAt().Add(time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			event = current
		}
		result, previous = append(result, event), event.Identity()
	}
	if _, err := controlplane.ReplayReviewRun(plan, result); err != nil {
		t.Fatalf("handler resource_limit replay: %v", err)
	}
	path := t.TempDir()
	journal, err := controlplane.NewFileRunJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	if err := journal.SavePlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	for _, event := range result {
		encoded, err := controlplane.EncodeRunEvent(event)
		if err != nil {
			t.Fatal(err)
		}
		stream.Write(encoded)
		stream.WriteByte(10)
	}
	if err := os.WriteFile(filepath.Join(path, plan.Scope().Identity()+".run.jsonl"), stream.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	facts, err := journal.InspectHistoricalContextPackets(context.Background())
	if err != nil || len(facts) != 1 {
		t.Fatalf("handler failure fact: %v", err)
	}
	if _, err := validateTerminalModelExpiryJournal(facts[0], now); err == nil {
		t.Fatal("handler resource_limit completion admitted as lease expiry")
	}
}
