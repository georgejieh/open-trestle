package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

// A valid journal prefix through the durable prepare event is the exact state
// after a process stops between artifact Put and task-failure journal append.
func TestDaemonRecoversPreparedContextAbstentionBeforeExpiredLeaseSettlement(t *testing.T) {
	for _, missingArtifact := range []bool{false, true} {
		name := "after-put"
		if missingArtifact {
			name = "before-put"
		}
		t.Run(name, func(t *testing.T) {
			args, getenv, repository, base, _, policy, inventory := localFullDaemonFixture(t)
			objects, stateDir := "", ""
			for i, flag := range args {
				if flag == "--local-git-objects-root" {
					objects = args[i+1]
				}
				if flag == "--state-dir" {
					stateDir = args[i+1]
				}
			}
			head := abstentionHeadRevision(t, objects, "large.go", []byte("package main\n//"+strings.Repeat("oversized-marker", 22000)+"\nfunc Large() {}\n"))
			d, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(d.server.Handler)
			api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-interrupted-"+name)
			intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			supervisor := d.supervisors[1].(*worker.RepositorySupervisor)
			if worked, err := supervisor.RunOnce(context.Background()); err != nil || !worked {
				t.Fatalf("work=%t err=%v", worked, err)
			}
			receipt, err := api.GetRun(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			output := ""
			for _, task := range receipt.Tasks() {
				if task.Key() == "context" {
					output = task.OutputIdentity()
				}
			}
			if output == "" {
				t.Fatal("context output absent before simulated interruption")
			}
			events, err := d.journal.Read(context.Background(), scope, 1, 100)
			if err != nil {
				t.Fatal(err)
			}
			prepareIndex := -1
			for i, e := range events {
				if e.Kind().String() == "context_abstention_prepared" && e.TaskKey() == "context" && e.OutputIdentity() == output {
					prepareIndex = i
					break
				}
			}
			if prepareIndex < 0 {
				t.Fatal("durable prepare event absent")
			}
			server.Close()
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			streamPath := filepath.Join(stateDir, scope.Identity()+".run.jsonl")
			original, err := os.ReadFile(streamPath)
			if err != nil {
				t.Fatal(err)
			}
			lines := bytes.Split(bytes.TrimSpace(original), []byte("\n"))
			if len(lines) != len(events)+1 || prepareIndex+1 >= len(lines) || !bytes.Contains(lines[prepareIndex+1], []byte(`"kind":"context_abstention_prepared"`)) {
				t.Fatalf("prepared journal prefix missing: lines=%d events=%d prepare=%d", len(lines), len(events), prepareIndex)
			}
			stream, err := os.OpenFile(streamPath, os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				t.Fatal(err)
			}
			prefix := append(bytes.Join(lines[:prepareIndex+2], []byte("\n")), '\n')
			if _, err = stream.Write(prefix); err != nil {
				t.Fatal(err)
			}
			if err = stream.Sync(); err != nil {
				t.Fatal(err)
			}
			if err = stream.Close(); err != nil {
				t.Fatal(err)
			}
			artifactPath := filepath.Join(stateDir, "artifacts", scope.Identity()+"-"+output+".artifact.json")
			if missingArtifact {
				if err := os.Remove(artifactPath); err != nil {
					t.Fatal(err)
				}
			}
			futureClock := daemonBudgetedRawClock{at: time.Now().UTC().Add(35 * time.Second).Truncate(time.Millisecond)}
			d, err = buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{clock: futureClock, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
			if err != nil {
				t.Fatalf("recovery startup after lease expiry: %v", err)
			}
			server = httptest.NewServer(d.server.Handler)
			api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := api.GetRun(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			if recovered.Status() != controlplane.ReviewRunFailed {
				debugEvents, _ := d.journal.Read(context.Background(), scope, 1, 100)
				kinds := make([]string, len(debugEvents))
				for i, e := range debugEvents {
					kinds[i] = e.Kind().String() + ":" + e.TaskKey()
				}
				for _, task := range recovered.Tasks() {
					t.Logf("recovered %s %s failure=%s output=%s", task.Key(), task.Status(), task.Failure(), task.OutputIdentity())
				}
				t.Fatalf("recovered run=%s event kinds=%v", recovered.Status(), kinds)
			}
			for _, task := range recovered.Tasks() {
				if task.Key() == "context" && (task.Status() != controlplane.TaskRuntimeFailed || task.OutputIdentity() != output) {
					t.Fatalf("context=%s output=%q", task.Status(), task.OutputIdentity())
				}
				if (task.Key() == "candidates" || task.Key() == "verification" || task.Key() == "readiness") && task.Status() == controlplane.TaskRuntimeAvailable {
					t.Fatalf("model task became ready: %s", task.Key())
				}
			}
			if _, err := d.artifactStore.Get(context.Background(), scope, output, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			events, err = d.journal.Read(context.Background(), scope, 1, 100)
			if err != nil {
				t.Fatal(err)
			}
			failedCount := 0
			for _, e := range events {
				if e.Kind() == controlplane.RunEventTaskFailed && e.TaskKey() == "context" {
					failedCount++
				}
			}
			if failedCount != 1 {
				t.Fatalf("context terminal events=%d", failedCount)
			}
			server.Close()
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			d, err = buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			next, err := controlplane.NewCoordinator(d.journal)
			if err != nil {
				t.Fatal(err)
			}
			replay, err := next.Receipt(context.Background(), scope)
			if err != nil || replay.Identity() != recovered.Identity() {
				t.Fatalf("repeat restart receipt=%v err=%v", replay.Identity(), err)
			}
			nextEvents, err := d.journal.Read(context.Background(), scope, 1, 100)
			if err != nil || len(nextEvents) != len(events) {
				t.Fatalf("repeat restart events=%d want=%d err=%v", len(nextEvents), len(events), err)
			}
		})
	}
}
