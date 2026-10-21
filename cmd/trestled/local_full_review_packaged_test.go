//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// Set OPEN_TRESTLE_PACKAGED_PREMODEL=1 to exercise the provider-free boundary.
func TestPackagedLocalFullReviewPreModel(t *testing.T) {
	if os.Getenv("OPEN_TRESTLE_PACKAGED_PREMODEL") != "1" {
		t.Skip("opt-in packaged integration fixture")
	}
	testPackagedLocalFullReview(t, false)
}

// Set OPEN_TRESTLE_PACKAGED_MODEL_WORKERS=1 to exercise owned Responses routes.
func TestPackagedLocalFullReviewModelWorkers(t *testing.T) {
	if os.Getenv("OPEN_TRESTLE_PACKAGED_MODEL_WORKERS") != "1" {
		t.Skip("opt-in packaged model integration fixture")
	}
	testPackagedLocalFullReview(t, true)
}

func testPackagedLocalFullReview(t *testing.T, modelWorkers bool) {
	t.Helper()
	if _, err := os.Stat("/dev/shm"); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/dev/shm", "trestle-premodel-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if err := os.WriteFile(filepath.Join(root, "write-probe"), []byte("x"), 0600); err != nil {
		t.Fatalf("private /dev/shm is not writable (required source/state root): %v", err)
	}
	// /dev/shm is commonly noexec. Keep executable staging and destdir in Go's
	// ordinary test temporary directory; Git objects and daemon state stay private in shm.
	build := t.TempDir()
	if err := os.Chmod(build, 0700); err != nil {
		t.Fatal(err)
	}
	template := filepath.Join(build, "git-template")
	if err := os.Mkdir(template, 0700); err != nil {
		t.Fatal(err)
	}
	command := func(dir string, env []string, name string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), env...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, output)
		}
		return bytes.TrimSpace(output)
	}
	repo := filepath.Join(root, "synthetic")
	if err := os.Mkdir(repo, 0700); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) []byte {
		return command(repo, []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0"}, "git", args...)
	}
	git("init", "--quiet", "--object-format=sha1", "--template="+template)
	writeSource := func(body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeSource("package fixture\nfunc render(value int) int { return value }\nfunc call() int { return render(1) }\n")
	git("add", "main.go")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@local.test", "commit", "-qm", "base")
	base := string(git("rev-parse", "HEAD"))
	writeSource("package fixture\nimport \"fmt\"\nfunc render(value int) int { fmt.Println(\"debug\"); return value + 1 }\nfunc call() int { return render(1) }\n")
	git("add", "main.go")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@local.test", "commit", "-qm", "head")
	head := string(git("rev-parse", "HEAD"))
	if string(git("rev-list", "--count", head)) != "2" {
		t.Fatal("not two commits")
	}
	args, getenv, repository, _, _, _, _ := localFullDaemonFixture(t)
	var model *daemonBudgetedModelFixture
	var barrier *packagedVerifierBarrier
	if modelWorkers {
		args, getenv, model, repository, _, _, _, _ = localModelWorkerFixture(t)
		barrier = newPackagedVerifierBarrier(t, model.verification)
		args = append(args, "--local-model-workers")
	}
	for i := 0; i < len(args)-1; i += 2 {
		if args[i] == "--local-git-objects-root" {
			args[i+1] = filepath.Join(repo, ".git", "objects")
		}
		if args[i] == "--state-dir" {
			args[i+1] = filepath.Join(root, "state")
		}
	}
	var routeCalls atomic.Int64
	routeEndpoints := make([]string, 0, 2)
	if !modelWorkers {
		for range 2 {
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			routeEndpoints = append(routeEndpoints, "http://"+listener.Addr().String()+"/v1")
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { routeCalls.Add(1); w.WriteHeader(http.StatusForbidden) })}
			go server.Serve(listener)
			t.Cleanup(func() { server.Close() })
		}
	}
	policyPath := daemonTestFlagValue(t, args, "--runtime-policy")
	inventoryPath := daemonTestFlagValue(t, args, "--runtime-route-inventory")
	policyBytes, e := os.ReadFile(policyPath)
	if e != nil {
		t.Fatal(e)
	}
	if modelWorkers {
		policyBytes = bytes.Replace(policyBytes, []byte(model.verification.URL()+"/v1"), []byte(barrier.server.URL+"/v1"), 1)
	} else {
		for index, fixed := range []string{"http://127.0.0.1:11434/v1", "http://127.0.0.1:11435/v1"} {
			if bytes.Count(policyBytes, []byte(fixed)) != 1 {
				t.Fatal("route fixture endpoint inventory changed")
			}
			policyBytes = bytes.Replace(policyBytes, []byte(fixed), []byte(routeEndpoints[index]), 1)
		}
	}
	if e := os.WriteFile(policyPath, policyBytes, 0600); e != nil {
		t.Fatal(e)
	}
	inventoryBytes, e := os.ReadFile(inventoryPath)
	if e != nil {
		t.Fatal(e)
	}
	inventory, e := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryBytes))
	if e != nil {
		t.Fatal(e)
	}
	policy, e := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyBytes), inventory)
	if e != nil {
		t.Fatal(e)
	}
	revision := string(command("../..", nil, "git", "rev-parse", "HEAD"))
	scannerFlags := packagedScannerBuildFlags(t)
	for _, entry := range []struct{ name, kind string }{{"trestle", "./cmd/trestle"}, {"trestled", "./cmd/trestled"}} {
		flags := "-s -w -buildid="
		if entry.name == "trestled" {
			flags = scannerFlags
		}
		cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-trimpath", "-buildvcs=false", "-ldflags="+flags, "-o", filepath.Join(build, entry.name), entry.kind)
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("build %s: %v: %s", entry.name, e, out)
		}
	}
	stage := filepath.Join(build, "staging")
	if e := os.Mkdir(stage, 0755); e != nil {
		t.Fatal(e)
	}
	// Use the repository's fixed staged non-Go runtime members, but never reuse
	// the staged trestle binaries: those are rebuilt from this working tree.
	copyFile := func(source, target string, mode os.FileMode) {
		t.Helper()
		body, e := os.ReadFile(source)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.MkdirAll(filepath.Dir(target), 0755); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(target, body, mode); e != nil {
			t.Fatal(e)
		}
	}
	for _, name := range []string{"LICENSE", "NOTICE", "ca-certificates.crt", "release/secret-scanner-release.json", "release/secret-scanner.spdx.json", "release/vulnerability-scan.json", "libexec/open-trestle/open-trestle-secret-scanner", "libexec/open-trestle/open-trestle-secret-scanner-worker"} {
		mode := os.FileMode(0444)
		if strings.HasPrefix(name, "libexec/") {
			mode = 0555
		}
		copyFile(filepath.Join("../..", ".container", name), filepath.Join(stage, name), mode)
	}
	for _, name := range []string{"trestle", "trestled"} {
		copyFile(filepath.Join(build, name), filepath.Join(stage, name), 0555)
	}
	if e := os.Mkdir(filepath.Join(stage, "data"), 0755); e != nil {
		t.Fatal(e)
	}
	licenses, e := os.ReadDir("../../.container/licenses")
	if e != nil {
		t.Fatal(e)
	}
	for _, dir := range licenses {
		if !dir.IsDir() {
			t.Fatal("unexpected license entry")
		}
		files, e := os.ReadDir(filepath.Join("../../.container/licenses", dir.Name()))
		if e != nil {
			t.Fatal(e)
		}
		for _, file := range files {
			if file.IsDir() {
				t.Fatal("nested license directory")
			}
			name := filepath.Join("licenses", dir.Name(), file.Name())
			copyFile(filepath.Join("../../.container", name), filepath.Join(stage, name), 0444)
		}
	}
	archive := filepath.Join(build, "open-trestle-premodel.pyz")
	command("../..", nil, "python3", "tools/linux_distribution.py", "--staging", stage, "--version", "0.1.0-dev", "--revision", revision, "--created", "2026-10-19T00:00:00Z", "--output", archive)
	command("../..", nil, "python3", archive, "verify-archive")
	dest := filepath.Join(build, "installed")
	if e := os.Mkdir(dest, 0700); e != nil {
		t.Fatal(e)
	}
	command("../..", nil, "python3", archive, "install", "--destdir", dest)
	command("../..", nil, "python3", archive, "verify-installed", "--destdir", dest)
	cli := filepath.Join(dest, "usr/local/bin/trestle")
	daemon := filepath.Join(dest, "usr/local/bin/trestled")
	for _, item := range []string{"trestle", "trestled"} {
		built, err := os.ReadFile(filepath.Join(build, item))
		if err != nil {
			t.Fatal(err)
		}
		installed, err := os.ReadFile(filepath.Join(dest, "usr/local/bin", item))
		if err != nil || !bytes.Equal(built, installed) {
			t.Fatalf("installed %s differs from local build: %v", item, err)
		}
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	listener.Close()
	for i := 0; i < len(args)-1; i += 2 {
		if args[i] == "--listen" {
			args[i+1] = address
		}
	}
	proc := exec.Command(daemon, args...)
	isolatedEnv := []string{"PATH=/usr/bin:/bin", "HOME=" + root, "OPEN_TRESTLE_API_TOKEN=" + getenv("OPEN_TRESTLE_API_TOKEN"), "OPEN_TRESTLE_PROVIDER_FIXTURE_A=fixture-only-a", "OPEN_TRESTLE_PROVIDER_FIXTURE_B=fixture-only-b", "NO_PROXY=*"}
	if modelWorkers {
		isolatedEnv = append(isolatedEnv, daemonBudgetedModelGenerationKeyEnv+"="+daemonBudgetedModelGenerationKey, daemonBudgetedModelVerificationKeyEnv+"="+daemonBudgetedModelVerificationKey)
	}
	proc.Env = isolatedEnv
	logPath := filepath.Join(build, "daemon.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	proc.Stdout = logFile
	proc.Stderr = logFile
	daemonLog := func() string { body, _ := os.ReadFile(logPath); return string(body) }
	if e := proc.Start(); e != nil {
		logFile.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if proc.ProcessState == nil {
			proc.Process.Kill()
			proc.Wait()
		}
		logFile.Close()
	})
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-packaged-premodel")
	api, e := client.NewLocal("http://"+address, getenv("OPEN_TRESTLE_API_TOKEN"), nil)
	if e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(15 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		response, requestErr := http.Get("http://" + address + "/healthz")
		if requestErr == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("packaged daemon not ready: %s", daemonLog())
	}
	cliArgs := []string{"local-git", "submit-review", "--objects-root", filepath.Join(repo, ".git", "objects"), "--repository-authority", "local.test", "--repository-namespace", "team", "--repository-name", "repository", "--revision-algorithm", "sha1", "--base-revision-digest", base, "--head-revision-digest", head, "--server", "http://" + address, "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-packaged-premodel", "--review-policy-identity", policy.ReviewPolicyIdentity(), "--inventory-identity", inventory.Identity(), "--runtime-policy-identity", policy.Identity(), "--created-at-unix-milliseconds", "1792368000000"}
	submit := func() []byte {
		cmd := exec.Command(cli, cliArgs...)
		cmd.Env = isolatedEnv
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("packaged submit: %v %s daemon=%s", e, out, daemonLog())
		}
		return bytes.TrimSpace(out)
	}
	if modelWorkers {
		testPackagedModelWorkerLifecycle(t, packagedModelWorkerRun{
			api: api, model: model, barrier: barrier, scope: scope, cli: cli,
			cliArgs: cliArgs, daemon: daemon, daemonArgs: args, env: isolatedEnv,
			process: proc, logFile: logFile, log: daemonLog, state: daemonTestFlagValue(t, args, "--state-dir"),
		})
		return
	}
	first := submit()
	admitted, parseErr := controlplane.ParseReviewRunReceipt(first)
	if parseErr != nil || admitted.Scope().Identity() != scope.Identity() {
		t.Fatalf("packaged receipt scope: %v", parseErr)
	}
	plan, e := api.GetRunPlan(context.Background(), scope)
	if e != nil {
		t.Fatal(e)
	}
	expected := []string{"source-base", "source-head", "change", "analysis", "memory", "context", "candidates", "verification", "readiness"}
	keys := []string{}
	for _, task := range plan.Tasks() {
		keys = append(keys, task.Key())
	}
	if !reflect.DeepEqual(keys, expected) {
		t.Fatalf("plan keys=%v", keys)
	}
	if replay, err := controlplane.ParseReviewRunReceipt(submit()); err != nil || replay.PlanIdentity() != admitted.PlanIdentity() {
		t.Fatalf("fixed timestamp replay changed plan: %v", err)
	}
	var receipt controlplane.ReviewRunReceipt
	deadline = time.Now().Add(20 * time.Second)
	available := false
	for time.Now().Before(deadline) {
		receipt, e = api.GetRun(context.Background(), scope)
		if e == nil {
			statuses := map[string]controlplane.TaskRuntimeStatus{}
			for _, task := range receipt.Tasks() {
				statuses[task.Key()] = task.Status()
			}
			if statuses["candidates"] == controlplane.TaskRuntimeAvailable {
				available = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e != nil || !available {
		t.Fatalf("pre-model chain unavailable before deadline: %v daemon=%s", e, daemonLog())
	}
	statuses := map[string]controlplane.TaskRuntimeStatus{}
	outputs := map[string]string{}
	for _, task := range receipt.Tasks() {
		statuses[task.Key()] = task.Status()
		outputs[task.Key()] = task.OutputIdentity()
	}
	for _, key := range expected[:6] {
		if statuses[key] != controlplane.TaskRuntimeSucceeded {
			t.Fatalf("%s=%s daemon=%s", key, statuses[key], daemonLog())
		}
	}
	if statuses["candidates"] != controlplane.TaskRuntimeAvailable || statuses["verification"] != controlplane.TaskRuntimePending || statuses["readiness"] != controlplane.TaskRuntimePending {
		t.Fatalf("model boundary: %v", statuses)
	}
	state := daemonTestFlagValue(t, args, "--state-dir")
	artifacts := filepath.Join(state, "artifacts")
	physical := func(identity string, kind artifact.Kind) artifact.Artifact {
		t.Helper()
		matches, e := filepath.Glob(filepath.Join(artifacts, "*.artifact.json"))
		if e != nil {
			t.Fatal(e)
		}
		for _, name := range matches {
			body, e := os.ReadFile(name)
			if e != nil {
				t.Fatal(e)
			}
			value, e := artifact.Parse(body)
			if e != nil {
				t.Fatal(e)
			}
			if value.Scope().Identity() == scope.Identity() && value.Identity() == identity {
				if value.Kind() != kind {
					t.Fatalf("artifact %s kind=%s", identity, value.Kind())
				}
				return value
			}
		}
		t.Fatalf("missing physical artifact %s", identity)
		return artifact.Artifact{}
	}
	baseID, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, base)
	headID, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, head)
	for _, item := range []struct{ task, revision string }{{"source-base", baseID.Identity()}, {"source-head", headID.Identity()}} {
		snapshot, e := sourcehandler.ParseSnapshotArtifact(physical(outputs[item.task], artifact.KindSourceSnapshot))
		if e != nil || snapshot.RevisionIdentity() != item.revision || snapshot.RepositoryIdentity() != repository.Identity() {
			t.Fatalf("snapshot %s: %v", item.task, e)
		}
	}
	input := physical(outputs["context"], artifact.KindTaskInput)
	parsed, e := modelhandler.ParseGenerationInput(input.Payload())
	if e != nil || !parsed.IsSanitized() {
		t.Fatalf("v5 authorized input: %v", e)
	}
	packetID := parsed.ContextArtifactIdentity()
	packet := physical(packetID, artifact.KindContextPacket)
	var contextPacket struct {
		Contract       string `json:"contract"`
		SourceCoverage struct {
			Analyzed int `json:"analyzed"`
			Selected int `json:"selected"`
			Omitted  int `json:"omitted"`
		} `json:"source_coverage"`
		Sources []struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
			EndLine   int    `json:"end_line"`
			Content   string `json:"content"`
		} `json:"sources"`
	}
	if e = json.Unmarshal(packet.Payload(), &contextPacket); e != nil || contextPacket.Contract != "open-trestle/review-context-packet" || contextPacket.SourceCoverage.Selected < 1 || contextPacket.SourceCoverage.Selected != len(contextPacket.Sources) || contextPacket.SourceCoverage.Analyzed != contextPacket.SourceCoverage.Selected+contextPacket.SourceCoverage.Omitted {
		t.Fatalf("v4 packet: %+v %v", contextPacket, e)
	}
	headSource, err := os.ReadFile(filepath.Join(repo, "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(headSource), "\n")
	for _, slice := range contextPacket.Sources {
		if slice.Path != "main.go" || slice.StartLine < 1 || slice.EndLine < slice.StartLine || slice.EndLine >= len(lines) {
			t.Fatalf("invalid physical source range: %+v", slice)
		}
		actual := strings.Join(lines[slice.StartLine-1:slice.EndLine], "\n")
		if actual != slice.Content && actual+"\n" != slice.Content {
			t.Fatalf("packet source does not match physical head slice: %+v", slice)
		}
	}
	// Journal readback is physical JSONL, not a fabricated context descriptor.
	streams, e := filepath.Glob(filepath.Join(state, "*.run.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	events := []controlplane.RunEvent{}
	if len(streams) != 1 || filepath.Base(streams[0]) != scope.Identity()+".run.jsonl" {
		t.Fatalf("run journal stream inventory=%v", streams)
	}
	body, e := os.ReadFile(streams[0])
	if e != nil || len(body) == 0 || body[len(body)-1] != '\n' {
		t.Fatalf("physical run stream: %v", e)
	}
	previous := ""
	for _, line := range bytes.Split(bytes.TrimSuffix(body, []byte("\n")), []byte("\n")) {
		event, parseErr := controlplane.ParseRunEvent(line)
		if parseErr != nil || event.Scope().Identity() != scope.Identity() || event.PlanIdentity() != plan.Identity() || event.Sequence() != uint64(len(events)+1) || event.PreviousIdentity() != previous {
			t.Fatalf("physical run event sequence=%d: %v", len(events)+1, parseErr)
		}
		events = append(events, event)
		previous = event.Identity()
	}
	packetAt, inputAt, settledAt := -1, -1, -1
	for index, event := range events {
		if event.TaskKey() != "context" {
			continue
		}
		switch event.Kind() {
		case controlplane.RunEventContextPacketPrepared:
			packetAt = index
			if event.PacketDescriptor().ArtifactIdentity != packetID {
				t.Fatal("packet route mismatch")
			}
		case controlplane.RunEventContextInputPrepared:
			inputAt = index
			if event.InputDescriptor().Input.ArtifactIdentity != input.Identity() || event.InputDescriptor().PacketArtifactIdentity != packetID {
				t.Fatal("input route mismatch")
			}
		case controlplane.RunEventContextInputSettled:
			settledAt = index
			if event.OutputIdentity() != input.Identity() {
				t.Fatal("settlement mismatch")
			}
		case controlplane.RunEventTaskSucceeded:
			t.Fatal("generic context success bypassed owner")
		}
	}
	if packetAt < 0 || inputAt <= packetAt || settledAt <= inputAt {
		t.Fatalf("v4/v5/v6 route order packet=%d input=%d settled=%d events=%d", packetAt, inputAt, settledAt, len(events))
	}
	auditStream := filepath.Join(state, "audit", scope.Identity()+".audit.jsonl")
	if auditBytes, err := os.ReadFile(auditStream); err == nil {
		for _, line := range bytes.Split(bytes.TrimSuffix(auditBytes, []byte("\n")), []byte("\n")) {
			entry, parseErr := audit.ParseEvent(line)
			if parseErr != nil || entry.Scope().Identity() != scope.Identity() {
				t.Fatalf("invalid physical audit event: %v", parseErr)
			}
			if entry.Kind() == audit.EventRouteAttemptClaimed || entry.Kind() == audit.EventRouteDispatchCompleted || entry.Kind() == audit.EventPublicationClaimed || entry.Kind() == audit.EventPublicationCompleted {
				t.Fatalf("unexpected route/publication audit event %s", entry.Kind())
			}
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if routeCalls.Load() != 0 {
		t.Fatalf("fake provider route calls=%d", routeCalls.Load())
	}
	archiveBytes, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	archiveDigest := sha256.Sum256(archiveBytes)
	t.Logf("packaged pre-model: revision=%s base=%s head=%s archive_sha256=%s packet=%s input=%s events=%d route_calls=%d", revision, base, head, hex.EncodeToString(archiveDigest[:]), packetID, input.Identity(), len(events), routeCalls.Load())
}
