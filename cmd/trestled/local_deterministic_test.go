package main

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/setup"
)

func TestBuildDaemonUsesIncompleteSetupOnlyAsDeterministicScopeFence(t *testing.T) {
	root := t.TempDir()
	objects := filepath.Join(root, "repository", ".git", "objects")
	if err := os.MkdirAll(objects, 0o700); err != nil {
		t.Fatal(err)
	}
	base := daemonTestRevision(t, objects, []byte("package main\nfunc main() {}\n"))
	head := daemonTestRevision(t, objects, []byte("package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"debug\") }\n"))

	setupDirectory := filepath.Join(root, "setup")
	if err := os.Mkdir(setupDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	setupPath := filepath.Join(setupDirectory, "plan.json")
	plan, err := setup.NewPlan(setup.ProfileLocalSingleNode, "tenant-a", "repo-a", "platform-owner", time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	stateFile, err := setup.OpenStateFile(setupPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := stateFile.Initialize(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := stateFile.Close(); err != nil {
		t.Fatal(err)
	}

	stateDirectory := filepath.Join(root, "runtime")
	args := []string{"--listen", "127.0.0.1:0", "--state-dir", stateDirectory, "--tenant", "tenant-a", "--repository", "repo-a", "--setup-state", setupPath, "--expected-setup-root-identity", plan.RootIdentity(), "--local-git-objects-root", objects, "--local-git-repository-authority", "local.test", "--local-git-repository-namespace", "team", "--local-git-repository-name", "repository"}
	getenv := func(name string) string {
		if name == "OPEN_TRESTLE_API_TOKEN" {
			return "01234567890123456789012345678901"
		}
		return ""
	}
	d, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithCancel(context.Background())
	var supervisors sync.WaitGroup
	for _, supervisor := range d.supervisors {
		supervisors.Add(1)
		go func(value daemonSupervisor) {
			defer supervisors.Done()
			if runErr := value.Run(ctx); runErr != nil && ctx.Err() == nil {
				t.Errorf("supervisor: %v", runErr)
			}
		}(supervisor)
		select {
		case <-supervisor.Ready():
		case <-time.After(5 * time.Second):
			t.Fatal("supervisor did not become ready")
		}
	}
	defer func() { cancel(); supervisors.Wait() }()
	server := httptest.NewServer(d.server.Handler)
	defer server.Close()
	api, err := client.NewLocal(server.URL, "01234567890123456789012345678901", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	repository, _ := evidence.NewRepositoryIdentity("local.test", []string{"team"}, "repository")
	scope, _ := auditScope("tenant-a", "repo-a", "run-a")
	intent, err := runtimecatalog.NewLocalDeterministicReviewIntent(scope, repository, base, head, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := api.SubmitLocalDeterministicReview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for receipt.Status() == controlplane.ReviewRunActive && time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		receipt, err = api.GetRun(context.Background(), scope)
		if err != nil {
			t.Fatal(err)
		}
	}
	if receipt.Status() != controlplane.ReviewRunSucceeded || len(receipt.Tasks()) != 4 {
		encoded, _ := controlplane.EncodeReviewRunReceipt(receipt)
		t.Fatalf("terminal receipt=%s", encoded)
	}
	set, err := api.GetDiagnosticSet(context.Background(), scope)
	if err != nil || set.SchemaVersion() != 6 || set.AnalysisResultIdentity() == "" || len(set.Findings()) != 0 || len(set.DeterministicObservations()) != 1 || set.DeterministicObservations()[0].Path() != "main.go" || set.DeterministicChecks()[0].State().String() != "failed" {
		t.Fatalf("diagnostics=(%#v,%v)", set, err)
	}
	for _, task := range receipt.Tasks() {
		if task.Status() != controlplane.TaskRuntimeSucceeded || task.OutputIdentity() == "" {
			t.Fatalf("task=%#v", task)
		}
	}
}

func auditScope(tenant, repository, run string) (audit.ReviewScope, error) {
	return audit.NewReviewScope(tenant, repository, run)
}

func daemonTestRevision(t *testing.T, objects string, source []byte) evidence.RevisionIdentity {
	t.Helper()
	blob := daemonWriteLooseObject(t, objects, "blob", source)
	blobBytes, _ := hex.DecodeString(blob)
	tree := append([]byte("100644 main.go\x00"), blobBytes...)
	treeDigest := daemonWriteLooseObject(t, objects, "tree", tree)
	commit := []byte("tree " + treeDigest + "\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nmessage\n")
	commitDigest := daemonWriteLooseObject(t, objects, "commit", commit)
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, commitDigest)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}
func daemonWriteLooseObject(t *testing.T, objects, kind string, payload []byte) string {
	t.Helper()
	framed := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(payload))), payload...)
	digest := sha1.Sum(framed)
	identity := hex.EncodeToString(digest[:])
	path := filepath.Join(objects, identity[:2], identity[2:])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := zlib.NewWriter(file)
	if _, err := writer.Write(framed); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return identity
}
