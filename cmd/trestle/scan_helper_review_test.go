package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/secretscan"
)

// scanHelperIntegrationVariable enables the review tests that build and run
// the real scan helper. Building it takes about a minute and needs the Go
// toolchain, so the default go test run skips them.
const scanHelperIntegrationVariable = "OPEN_TRESTLE_SCAN_HELPER_INTEGRATION"

// syntheticGitHubToken is a GitHub token shape the scanner detects, made of
// hex digits derived at run time, so no token appears in the source.
func syntheticGitHubToken() string {
	digest := sha256.Sum256([]byte("open-trestle synthetic review token"))
	return "gh" + "p_" + hex.EncodeToString(digest[:])[:36]
}

// buildScanHelperForReview builds the helper with the scanner module's build
// command and installs a read-only copy below directory.
func buildScanHelperForReview(t *testing.T, directory string) secretscan.SessionConfig {
	t.Helper()
	module, err := filepath.Abs(filepath.Join("..", "..", "workers", "secret-scanner"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "run", "./internal/cmd/build-scan-helper", "-o", filepath.Join(directory, "build"))
	build.Dir = module
	build.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
	var stdout, stderr bytes.Buffer
	build.Stdout, build.Stderr = &stdout, &stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build the scan helper: %v: %s", err, stderr.Bytes())
	}
	content, err := os.ReadFile(strings.TrimSpace(stdout.String()))
	if err != nil {
		t.Fatal(err)
	}
	install := filepath.Join(directory, "install")
	if err := os.Mkdir(install, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(install, "open-trestle-scan-helper")
	if runtime.GOOS == "windows" {
		helper += ".exe"
	}
	if err := os.WriteFile(helper, content, 0o555); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return secretscan.SessionConfig{HelperPath: helper, HelperSHA256: hex.EncodeToString(digest[:]), CacheDirectory: filepath.Join(directory, "user-cache", "open-trestle", "scan-cache")}
}

// recordingTransport keeps every request body the fixture provider received.
type recordingTransport struct {
	inner  *remoteModelTransport
	mu     sync.Mutex
	bodies [][]byte
}

func (r *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.bodies = append(r.bodies, body)
	r.mu.Unlock()
	request.Body = io.NopCloser(bytes.NewReader(body))
	return r.inner.RoundTrip(request)
}

// canceledScanSession passes every Sanitize to the real session with a
// context that is already done, as when a scan is stopped part way: the
// session kills its helper and fails closed.
type canceledScanSession struct {
	secretscan.ReviewSession
}

func (session canceledScanSession) Sanitize(ctx context.Context, sources [][]byte) secretscan.Projection {
	stopped, cancel := context.WithCancel(ctx)
	cancel()
	return session.ReviewSession.Sanitize(stopped, sources)
}

// TestRemoteReviewScansThroughTheScanHelper runs a remote-provider review
// against the offline fixture provider through the real scan helper: the
// planted token is masked before any request leaves, the run's scan receipts
// read back as scanned, and a missing helper, a wrong digest or a scan that
// fails part way each refuse the review before any request is sent.
func TestRemoteReviewScansThroughTheScanHelper(t *testing.T) {
	if os.Getenv(scanHelperIntegrationVariable) != "1" {
		t.Skip("set " + scanHelperIntegrationVariable + "=1 to build and run the real scan helper")
	}
	config := buildScanHelperForReview(t, t.TempDir())
	token := syntheticGitHubToken()

	generation, verification := localReviewGenerationSanitizer, localReviewVerificationSanitizer
	scanner := localReviewScanner
	localReviewGenerationSanitizer, localReviewVerificationSanitizer = nil, nil
	t.Cleanup(func() {
		localReviewGenerationSanitizer, localReviewVerificationSanitizer, localReviewScanner = generation, verification, scanner
	})

	remoteScannerInstalled(t)
	args, directory := remoteBootstrapArgs(t, "ollama-cloud")
	args = replaceLocalGitChangeValue(args, "--checkout", scanHelperReviewCheckout(t, token))
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	remoteBootstrapInvoke(t, args, 0)
	ready, _ := remoteBootstrapInvoke(t, []string{"check", "--directory", directory}, 0)
	if !ready.Ready {
		t.Fatalf("setup is not ready: %+v", ready)
	}
	reviewArgs := replaceLocalGitChangeValue(ready.ReviewCommand[1:], "--format", "json")

	review := func(t *testing.T, open func(context.Context, io.Writer) (secretscan.ReviewSessionOpener, error)) (int, *recordingTransport, []byte, string) {
		t.Helper()
		localReviewScanner = open
		transport := &recordingTransport{inner: &remoteModelTransport{t: t, target: "https://ollama.com/v1/chat/completions", models: map[string]string{"gemma4:31b": "", "qwen3.5:397b": ""}}}
		localReviewModelHTTPClient = &http.Client{Transport: transport, Timeout: time.Minute}
		localReviewModelHTTPClientIdentity = localModelDigest([]byte("offline scan helper review transport"))
		t.Cleanup(func() { localReviewModelHTTPClient, localReviewModelHTTPClientIdentity = nil, "" })
		var stdout, stderr bytes.Buffer
		code := run(reviewArgs, &stdout, &stderr)
		return code, transport, stdout.Bytes(), stderr.String()
	}
	preparing := func(config secretscan.SessionConfig) func(context.Context, io.Writer) (secretscan.ReviewSessionOpener, error) {
		return func(ctx context.Context, stderr io.Writer) (secretscan.ReviewSessionOpener, error) {
			return prepareReviewScanner(ctx, stderr, config)
		}
	}

	t.Run("masks the token and records the scans", func(t *testing.T) {
		code, transport, stdout, stderr := review(t, preparing(config))
		if code != 4 {
			t.Fatalf("review exit=%d out=%s err=%s", code, stdout, stderr)
		}
		if len(transport.bodies) != 2 || !slices.Equal(transport.inner.requests, []string{"candidate_generation:gemma4:31b", "candidate_verification:qwen3.5:397b"}) {
			t.Fatalf("requests = %v: out=%s err=%s", transport.inner.requests, stdout, stderr)
		}
		for _, body := range transport.bodies {
			if bytes.Contains(body, []byte(token)) || !bytes.Contains(body, []byte("Changed")) {
				t.Fatal("a request carried the token or lost the reviewed code")
			}
		}
		if !strings.Contains(stderr, "Preparing the secret scanner for first use") {
			t.Fatalf("no first-use notice: %s", stderr)
		}
		var result struct {
			Walkthrough struct {
				Verified struct {
					SecretScan struct {
						State         string `json:"state"`
						Requests      int    `json:"requests"`
						Matches       int    `json:"matches"`
						RedactedBytes int    `json:"redacted_bytes"`
					} `json:"secret_scan"`
				} `json:"verified"`
			} `json:"walkthrough"`
		}
		if err := json.Unmarshal(stdout, &result); err != nil {
			t.Fatal(err)
		}
		if scan := result.Walkthrough.Verified.SecretScan; scan.State != "scanned" || scan.Requests != 2 || scan.Matches < 2 || scan.RedactedBytes < 2*len(token) {
			t.Fatalf("secret scan summary = %+v", scan)
		}
		again, _, _, stderr := review(t, preparing(config))
		if again != 4 || strings.Contains(stderr, "Preparing the secret scanner") {
			t.Fatalf("second review exit=%d err=%s", again, stderr)
		}
	})

	missing := config
	missing.HelperPath = filepath.Join(filepath.Dir(config.HelperPath), "missing", filepath.Base(config.HelperPath))
	wrong := config
	wrong.HelperSHA256 = strings.Repeat("0", 64)
	for name, open := range map[string]func(context.Context, io.Writer) (secretscan.ReviewSessionOpener, error){
		"missing helper": preparing(missing),
		"wrong digest":   preparing(wrong),
		"scan fails part way": func(ctx context.Context, stderr io.Writer) (secretscan.ReviewSessionOpener, error) {
			opener, err := prepareReviewScanner(ctx, stderr, config)
			if err != nil {
				return nil, err
			}
			return func(ctx context.Context) (secretscan.ReviewSession, error) {
				session, err := opener(ctx)
				if err != nil {
					return nil, err
				}
				return canceledScanSession{session}, nil
			}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			code, transport, stdout, stderr := review(t, open)
			if code == 0 || len(transport.bodies) != 0 {
				t.Fatalf("review exit=%d with %d requests: out=%s err=%s", code, len(transport.bodies), stdout, stderr)
			}
			if name != "scan fails part way" && !strings.Contains(stderr, "the secret scanner is not available, so nothing was sent") {
				t.Fatalf("no scanner message: %s", stderr)
			}
			var result localModelReceipt
			if err := json.Unmarshal(stdout, &result); err != nil || result.Status != "refused" && result.Status != "failed" {
				t.Fatalf("result = %+v, %v", result, err)
			}
		})
	}
}

// scanHelperReviewCheckout is the remote fixture change with the token added
// to the changed file.
func scanHelperReviewCheckout(t *testing.T, token string) string {
	t.Helper()
	caller := []byte("package p\nfunc Consume() int { return Changed(0) }\n")
	base := map[string][]byte{
		"a.go":      []byte("package p\nfunc Changed(x int) int { if x == 0 { return 0 }; return 10 / x }\n"),
		"caller.go": caller,
	}
	head := map[string][]byte{
		"a.go":      []byte("package p\nfunc Changed(x int) int { return 10 / x }\nconst token = \"" + token + "\"\n"),
		"caller.go": caller,
	}
	objects, baseCommit, headCommit := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, base, head)
	checkout := t.TempDir()
	checkoutGit(t, checkout, "init")
	if err := os.CopyFS(filepath.Join(checkout, ".git", "objects"), os.DirFS(objects)); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, checkout, "update-ref", "refs/heads/base", baseCommit)
	checkoutGit(t, checkout, "update-ref", "refs/heads/review", headCommit)
	return checkout
}
