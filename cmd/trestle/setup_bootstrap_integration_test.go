package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
	ready = bootstrapInvoke(t, []string{"prepare-review", "--directory", dir}, 0)
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
	compile := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-overlay="+overlayPath, "-o", binary, "./cmd/trestled")
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
	t.Cleanup(func() { _ = process.Process.Kill(); _ = process.Wait(); _ = log.Close() })
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
}
