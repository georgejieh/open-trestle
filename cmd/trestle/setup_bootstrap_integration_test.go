package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
)

// This uses synthetic sanitizers and ordinary test storage, not installed-profile qualification.
func TestSetupBootstrapDevelopmentDaemonFirstReview(t *testing.T) {
	if os.Getenv("OPEN_TRESTLE_BOOTSTRAP_DEVELOPMENT") != "1" {
		t.Skip("opt-in compiled development integration; no intended-host qualification")
	}
	t.Log("development fixture: synthetic sanitizers, no scanner/storage qualification")
	args, dir, f, probes := bootstrapFixture(t)
	initial := bootstrapInvoke(t, args, 3)
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "operator-"+strings.Repeat("a", 32))
	t.Setenv("OPEN_TRESTLE_OBSERVER_TOKEN", "observer-"+strings.Repeat("b", 32))
	backup := t.TempDir()
	_ = os.Chmod(backup, 0700)
	ready := bootstrapInvoke(t, []string{"check", "--directory", dir, "--approved-by", "owner", "--allow-local-probe", "--backup-directory", backup}, 0)
	if !ready.Ready || probes.Load() != 2 || initial.Ready {
		t.Fatal("setup did not reach honestly checked readiness")
	}
	build := t.TempDir()
	mainPath, err := filepath.Abs("../trestled/main.go")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	needle := "generationSanitizer: reviewcore.NewFixedGenerationRequestSanitizer(), verificationSanitizer: reviewcore.NewFixedVerificationRequestSanitizer()"
	if bytes.Count(source, []byte(needle)) != 1 {
		t.Fatal("development sanitizer dependency seam changed")
	}
	source = bytes.Replace(source, []byte(needle), []byte("generationSanitizer: testsupport.NewCleanGenerationSanitizer(), verificationSanitizer: testsupport.NewCleanVerificationSanitizer()"), 1)
	source = bytes.Replace(source, []byte("import ("), []byte("import (\n \"github.com/georgejieh/open-trestle/internal/testsupport\""), 1)
	overlayMain := filepath.Join(build, "main.go")
	if err := os.WriteFile(overlayMain, source, 0600); err != nil {
		t.Fatal(err)
	}
	overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{mainPath: overlayMain}})
	overlayPath := filepath.Join(build, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(build, "trestled")
	compile := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-p=1", "-overlay="+overlayPath, "-o", binary, "./cmd/trestled")
	compile.Dir = "../.."
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("build development daemon: %v %s", err, output)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	launch := append([]string(nil), ready.LaunchCommand[1:]...)
	for i := 0; i < len(launch)-1; i++ {
		if launch[i] == "--listen" {
			launch[i+1] = address
		}
	}
	process := exec.Command(binary, launch...)
	process.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + build, "OPEN_TRESTLE_API_TOKEN=" + os.Getenv("OPEN_TRESTLE_API_TOKEN"), "OPEN_TRESTLE_OBSERVER_TOKEN=" + os.Getenv("OPEN_TRESTLE_OBSERVER_TOKEN")}
	log, err := os.OpenFile(filepath.Join(build, "daemon.log"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	process.Stdout = log
	process.Stderr = log
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = process.Process.Kill()
			_ = process.Wait()
		}
		_ = log.Close()
	})
	daemonLog := func() string { body, _ := os.ReadFile(filepath.Join(build, "daemon.log")); return string(body) }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	healthy := false
	for !healthy {
		select {
		case <-ctx.Done():
			t.Fatalf("daemon startup: %s", daemonLog())
		case <-tick.C:
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/healthz", nil)
			response, err := http.DefaultClient.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				healthy = response.StatusCode == 200
			}
		}
	}
	var preparedOut, preparedErr bytes.Buffer
	if code := runSetupBootstrap([]string{"prepare-review", "--directory", dir}, &preparedOut, &preparedErr); code != 0 || preparedErr.Len() != 0 || json.Unmarshal(preparedOut.Bytes(), &ready) != nil {
		t.Fatalf("prepare live first-review intent: %d %s %s", code, preparedOut.String(), preparedErr.String())
	}
	intentPath := filepath.Join(dir, "review-intent.json")
	retainedIntent, err := os.ReadFile(intentPath)
	if err != nil {
		t.Fatal(err)
	}
	retainedIntentIdentity := sha256.Sum256(retainedIntent)
	submit := replaceLocalGitChangeValue(append([]string(nil), ready.ReviewCommand[3:]...), "--server", "http://"+address)
	var stdout, stderr bytes.Buffer
	if code := runLocalGitSubmitReview(submit, &stdout, &stderr); code != 0 {
		t.Fatalf("submit=%d %s %s daemon=%s", code, stdout.String(), stderr.String(), daemonLog())
	}
	admitted, err := controlplane.ParseReviewRunReceipt(bytes.TrimSpace(stdout.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runLocalGitSubmitReview(submit, &stdout, &stderr); code != 0 {
		t.Fatal("replay", code, stderr.String())
	}
	replay, err := controlplane.ParseReviewRunReceipt(bytes.TrimSpace(stdout.Bytes()))
	if err != nil || replay.PlanIdentity() != admitted.PlanIdentity() {
		t.Fatal("replay changed admitted intent")
	}
	api, err := client.NewLocal("http://"+address, os.Getenv("OPEN_TRESTLE_API_TOKEN"), nil)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-local", "repository-local", "first-review")
	succeeded := false
	var lastRunErr error
	var lastRunStatus controlplane.ReviewRunStatus
	for !succeeded {
		select {
		case <-ctx.Done():
			t.Fatalf("daemon review timeout: last_error=%v last_status=%v log=%s", lastRunErr, lastRunStatus, daemonLog())
		case <-tick.C:
			receipt, err := api.GetRun(ctx, scope)
			lastRunErr = err
			if err == nil {
				lastRunStatus = receipt.Status()
				if receipt.Status() == controlplane.ReviewRunSucceeded {
					succeeded = true
				}
				if receipt.Status() == controlplane.ReviewRunFailed {
					t.Fatalf("daemon run failed: %+v log=%s", receipt, daemonLog())
				}
			}
		}
	}
	var lastDiagnosticErr error
	for {
		_, lastDiagnosticErr = api.GetDiagnosticSet(ctx, scope)
		if lastDiagnosticErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("diagnostics timeout: last_error=%v log=%s", lastDiagnosticErr, daemonLog())
		case <-tick.C:
		}
	}
	t.Setenv("OPEN_TRESTLE_API_URL", "http://"+address)
	stdout.Reset()
	stderr.Reset()
	statusArgs := replaceLocalGitChangeValue(append([]string(nil), ready.StatusCommand[1:]...), "--server", "http://"+address)
	if code := run(statusArgs, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "a.go") {
		t.Fatalf("canonical diagnostics code=%d %s %s", code, stdout.String(), stderr.String())
	}
	generation, _ := f.generation.snapshot()
	verification, _ := f.verification.snapshot()
	if generation != 1 || verification != 1 {
		t.Fatalf("durable fake pair calls=%d/%d", generation, verification)
	}
	currentIntent, err := os.ReadFile(intentPath)
	if err != nil || sha256.Sum256(currentIntent) != retainedIntentIdentity || !bytes.Equal(currentIntent, retainedIntent) {
		t.Fatal("review replay changed persisted first-review intent", err)
	}
	t.Logf("retained first-review intent sha256=%x admitted_plan=%s replay_plan=%s", retainedIntentIdentity, admitted.PlanIdentity(), replay.PlanIdentity())
	terminal, err := api.GetRun(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	diagnostic, err := api.GetDiagnosticSet(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitErr := process.Wait()
	waited = true
	if waitErr != nil {
		t.Fatalf("graceful daemon stop: %v log=%s", waitErr, daemonLog())
	}
	flagValue := func(name string) string {
		t.Helper()
		for i := 0; i < len(launch)-1; i++ {
			if launch[i] == name {
				return launch[i+1]
			}
		}
		t.Fatalf("missing emitted launch flag %s", name)
		return ""
	}
	state := flagValue("--state-dir")
	objects := flagValue("--local-git-objects-root")
	flags := []string{"--state-dir", state,
		"--repository-authority", flagValue("--local-git-repository-authority"),
		"--repository-namespace", flagValue("--local-git-repository-namespace"),
		"--repository-name", flagValue("--local-git-repository-name"),
		"--binary", binary}
	// Offline comparison retains inert scanner assets; this is not scanner execution.
	for _, role := range []string{"scanner", "scanner-worker"} {
		path := filepath.Join(build, role)
		if err := os.WriteFile(path, []byte("retained development fixture "+role), 0500); err != nil {
			t.Fatal(err)
		}
		flags = append(flags, "--"+role, path)
	}
	flags = append(flags, "--route-inventory", flagValue("--runtime-route-inventory"), "--runtime-policy", flagValue("--runtime-policy"))
	before, identities := bootstrapRecoveryInventory(t, state, objects)
	invokeRecovery := func(action string, extra ...string) ([]byte, []byte, error) {
		t.Helper()
		command := exec.Command(binary, append(append([]string{action}, flags...), extra...)...)
		command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + build}
		var output, failure bytes.Buffer
		command.Stdout, command.Stderr = &output, &failure
		err := command.Run()
		currentIntent, intentErr := os.ReadFile(intentPath)
		if intentErr != nil || sha256.Sum256(currentIntent) != retainedIntentIdentity || !bytes.Equal(currentIntent, retainedIntent) {
			t.Fatal("offline comparison changed persisted first-review intent", intentErr)
		}
		after, current := bootstrapRecoveryInventory(t, state, objects)
		if len(after) != len(before) {
			t.Fatal("offline comparison changed state or Git inventory")
		}
		for path, original := range before {
			if after[path] != original || !os.SameFile(identities[path], current[path]) {
				t.Fatalf("offline comparison mutated %s", path)
			}
		}
		return output.Bytes(), failure.Bytes(), err
	}
	raw, failure, err := invokeRecovery("recovery-point")
	if err != nil {
		_, layoutErr := os.Lstat(filepath.Join(state, "setup", "plan.json.lock"))
		if os.IsNotExist(layoutErr) && bytes.Contains(failure, []byte("invalid file lock path")) {
			t.Fatalf("bootstrap first review succeeded and daemon exited; offline recovery layout missing STATE/setup/plan.json.lock: %v %s", err, failure)
		}
		t.Fatalf("offline recovery failed outside expected layout boundary: %v %s", err, failure)
	}
	var point struct {
		SetupPath string `json:"setup_path"`
		Runs      []struct {
			Receipt    string `json:"receipt"`
			Diagnostic string `json:"diagnostic"`
		} `json:"runs"`
		Assets []struct {
			Role   string `json:"role"`
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"assets"`
	}
	if len(failure) != 0 || json.Unmarshal(raw, &point) != nil || point.SetupPath != filepath.Join(state, "setup", "plan.json") || len(point.Runs) != 1 || point.Runs[0].Receipt != terminal.Identity() || point.Runs[0].Diagnostic != diagnostic.Identity() || len(point.Assets) != 5 {
		t.Fatalf("recovery point lost setup/run/asset identity: %s stderr=%s", raw, failure)
	}
	for _, asset := range point.Assets {
		body, err := os.ReadFile(asset.Path)
		if err != nil || asset.SHA256 != fmt.Sprintf("%x", sha256.Sum256(body)) {
			t.Fatalf("recovery asset identity mismatch: %s %v", asset.Role, err)
		}
	}
	record := filepath.Join(build, "recovery-point.json")
	if err := os.WriteFile(record, raw, 0600); err != nil {
		t.Fatal(err)
	}
	output, failure, err := invokeRecovery("verify-restore", "--record", record)
	if err != nil || len(failure) != 0 || string(output) != "{\"status\":\"matched\",\"restart_authorized\":false}\n" {
		t.Fatalf("stopped bootstrap compare: %v %s %s", err, output, failure)
	}
}

func bootstrapRecoveryInventory(t *testing.T, roots ...string) (map[string]string, map[string]os.FileInfo) {
	t.Helper()
	entries := map[string]string{}
	identities := map[string]os.FileInfo{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			digest := ""
			if info.Mode().IsRegular() {
				body, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				digest = fmt.Sprintf("%x", sha256.Sum256(body))
			} else if !info.IsDir() {
				return fmt.Errorf("unsupported recovery fixture entry %s", path)
			}
			entries[path] = fmt.Sprintf("%v:%d:%s", info.Mode(), info.Size(), digest)
			identities[path] = info
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return entries, identities
}
