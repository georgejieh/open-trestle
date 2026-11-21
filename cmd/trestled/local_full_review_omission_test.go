package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

func localFullMultiFileRevision(t *testing.T, objects string, contents map[string][]byte) evidence.RevisionIdentity {
	t.Helper()
	names := make([]string, 0, len(contents))
	for name := range contents {
		names = append(names, name)
	}
	sort.Strings(names)
	tree := []byte{}
	for _, name := range names {
		blob := daemonWriteLooseObject(t, objects, "blob", contents[name])
		digest, err := hex.DecodeString(blob)
		if err != nil {
			t.Fatal(err)
		}
		tree = append(tree, []byte("100644 "+name+"\x00")...)
		tree = append(tree, digest...)
	}
	root := daemonWriteLooseObject(t, objects, "tree", tree)
	commit := daemonWriteLooseObject(t, objects, "commit", []byte("tree "+root+"\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nmessage\n"))
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, commit)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func TestDaemonFullLocalReviewCountsOversizeSourceOmission(t *testing.T) {
	args, getenv, repository, base, _, policy, inventory := localFullDaemonFixture(t)
	objects := args[1]
	for index := range args {
		if args[index] == "--local-git-objects-root" {
			objects = args[index+1]
			break
		}
	}
	head := localFullMultiFileRevision(t, objects, map[string][]byte{
		"main.go":  []byte("package main\nfunc main(){println(2)}\n"),
		"large.go": []byte("package main\n//" + strings.Repeat("x", 300<<10) + "\nfunc Large() {}\n"),
	})
	d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	server := httptest.NewServer(d.server.Handler)
	defer server.Close()
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-omission")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	supervisor, ok := d.supervisors[1].(*worker.RepositorySupervisor)
	if !ok {
		t.Fatalf("unexpected supervisor %T", d.supervisors[1])
	}
	if worked, err := supervisor.RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("pre-model work=%t err=%v", worked, err)
	}
	receipt, err := api.GetRun(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	contextID := ""
	for _, task := range receipt.Tasks() {
		if task.Key() == "context" {
			if task.Status() != controlplane.TaskRuntimeSucceeded {
				t.Fatalf("context status=%s failure=%s", task.Status(), task.Failure())
			}
			contextID = task.OutputIdentity()
		}
		if task.Key() == "candidates" && task.Status() != controlplane.TaskRuntimeAvailable {
			t.Fatalf("candidate status=%s", task.Status())
		}
	}
	input, err := d.artifactStore.Get(context.Background(), scope, contextID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if input.Kind() != artifact.KindTaskInput {
		t.Fatalf("context output=%s", input.Kind())
	}
	parsed, err := modelhandler.ParseGenerationInput(input.Payload())
	if err != nil || !parsed.IsSanitized() {
		t.Fatalf("sanitized handoff: %v", err)
	}
	value, err := d.artifactStore.Get(context.Background(), scope, parsed.ContextArtifactIdentity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var packet struct {
		SourceCoverage struct {
			Analyzed            int `json:"analyzed"`
			PreselectionOmitted int `json:"preselection_omitted"`
			Available           int `json:"available"`
			Selected            int `json:"selected"`
			Omitted             int `json:"omitted"`
		} `json:"source_coverage"`
		Sources []struct {
			Path string `json:"path"`
		} `json:"sources"`
		Omissions []struct {
			Path   string `json:"path"`
			Reason string `json:"reason"`
			Count  int    `json:"count"`
		} `json:"source_omissions"`
	}
	if err := json.Unmarshal(value.Payload(), &packet); err != nil {
		t.Fatal(err)
	}
	if packet.SourceCoverage.Analyzed != packet.SourceCoverage.Selected+packet.SourceCoverage.Omitted || packet.SourceCoverage.Selected < 1 || packet.SourceCoverage.Omitted < 1 || packet.SourceCoverage.PreselectionOmitted < 1 || len(packet.Sources) != packet.SourceCoverage.Selected {
		t.Fatalf("coverage=%+v selected=%d", packet.SourceCoverage, len(packet.Sources))
	}
	found := false
	for _, entry := range packet.Omissions {
		if entry.Path == "large.go" && entry.Reason == "source_size_limit" && entry.Count == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("oversized source omission missing: %+v", packet.Omissions)
	}
	if bytes.Contains(value.Payload(), []byte(strings.Repeat("x", 100))) {
		t.Fatal("omitted source bytes leaked into context")
	}
}
