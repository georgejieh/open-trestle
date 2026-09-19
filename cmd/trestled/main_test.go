package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	githubsource "github.com/georgejieh/open-trestle/adapters/scm/github"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	reviewcore "github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func daemonEnvironment(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}
func TestBuildDaemonUsesPrivateDurableStateAndLoopback(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	daemon, err := buildDaemon(context.Background(), []string{"--listen", "127.0.0.1:0", "--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"}), os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	if daemon.server.Addr != "127.0.0.1:0" || daemon.tlsCertificate != "" || daemon.tlsKey != "" {
		t.Fatalf("daemon=%#v", daemon)
	}
	information, err := os.Stat(root)
	if err != nil || information.Mode().Perm() != 0o700 {
		t.Fatalf("state=(%v,%v)", information, err)
	}
	live := httptest.NewRecorder()
	daemon.server.Handler.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if live.Code != http.StatusOK || !strings.Contains(live.Body.String(), `"status":"live"`) {
		t.Fatalf("live=%d %s", live.Code, live.Body.String())
	}
	ready := httptest.NewRecorder()
	daemon.server.Handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready=%d %s", ready.Code, ready.Body.String())
	}
	runtimeRequest := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/tenant-a/repositories/repo-a/runtime", nil)
	runtimeRequest.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	runtimeStatus := httptest.NewRecorder()
	daemon.server.Handler.ServeHTTP(runtimeStatus, runtimeRequest)
	if runtimeStatus.Code != http.StatusOK || !strings.Contains(runtimeStatus.Body.String(), `"contract":"open-trestle/runtime-status"`) || !strings.Contains(runtimeStatus.Body.String(), `"metadata_backend":"local"`) || !strings.Contains(runtimeStatus.Body.String(), `"state":"starting"`) {
		t.Fatalf("runtime=%d %s", runtimeStatus.Code, runtimeStatus.Body.String())
	}
	unauthenticatedRuntime := httptest.NewRecorder()
	daemon.server.Handler.ServeHTTP(unauthenticatedRuntime, httptest.NewRequest(http.MethodGet, "/api/v1/tenants/tenant-a/repositories/repo-a/runtime", nil))
	if unauthenticatedRuntime.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated runtime=%d", unauthenticatedRuntime.Code)
	}
	console := httptest.NewRecorder()
	daemon.server.Handler.ServeHTTP(console, httptest.NewRequest(http.MethodGet, "/console/", nil))
	if console.Code != http.StatusOK || !strings.Contains(console.Body.String(), `id="root"`) || console.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("console=%d %s", console.Code, console.Body.String())
	}
}
func TestBuildDaemonRejectsUnsafeConfiguration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	validEnvironment := daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"})
	tests := []struct {
		name        string
		args        []string
		environment func(string) string
	}{{"missing token", []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a"}, daemonEnvironment(nil)}, {"short observer token", []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901", "OPEN_TRESTLE_OBSERVER_TOKEN": "short"})}, {"missing tenant", []string{"--state-dir", root, "--repository", "repo-a"}, validEnvironment}, {"missing repository", []string{"--state-dir", root, "--tenant", "tenant-a"}, validEnvironment}, {"remote plaintext", []string{"--listen", "0.0.0.0:8741", "--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a"}, validEnvironment}, {"partial TLS", []string{"--listen", "0.0.0.0:8741", "--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--tls-cert", "cert.pem"}, validEnvironment}, {"local with postgres authority", []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--postgres-authority-identity", strings.Repeat("a", 64)}, validEnvironment}, {"daemon authority initialization removed", []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--initialize-postgres-authority"}, validEnvironment}, {"unknown metadata store", []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--metadata-store", "unknown"}, validEnvironment}, {"postgres without URL", []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--metadata-store", "postgres"}, validEnvironment}, {"postgres without database authority", []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--metadata-store", "postgres"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901", "OPEN_TRESTLE_POSTGRES_URL": "postgres://user:password@127.0.0.1/reviews?sslmode=disable"})}, {"ignored postgres URL", []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901", "OPEN_TRESTLE_POSTGRES_URL": "postgres://ignored"})}, {"incomplete S3", []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--metadata-store", "postgres", "--artifact-store", "s3"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901", "OPEN_TRESTLE_POSTGRES_URL": "postgres://user:password@127.0.0.1/reviews?sslmode=disable"})}, {"ignored GitHub API token", []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901", "OPEN_TRESTLE_GITHUB_API_TOKEN": "ignored"})}, {"ignored AWS credential", []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901", "OPEN_TRESTLE_AWS_ACCESS_KEY_ID": "ignored-key"})}, {"ignored S3 credential", []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901", "OPEN_TRESTLE_S3_ACCESS_KEY_ID": "ignored-key"})}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			daemon, err := buildDaemon(context.Background(), test.args, test.environment, os.Stderr)
			if !errors.Is(err, ErrInvalidDaemonConfiguration) || daemon != nil {
				t.Fatalf("daemon=(%#v,%v)", daemon, err)
			}
		})
	}
}
func TestRunDaemonStopsWithContext(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output strings.Builder
	err := runDaemon(ctx, []string{"--listen", "127.0.0.1:0", "--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"}), &output, &output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "01234567890123456789012345678901") {
		t.Fatal("daemon output leaked credential")
	}
	if output.Len() != 0 {
		t.Fatal("canceled startup opened a listener")
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled startup created state: %v", err)
	}
}

func TestBuildDaemonMountsConfiguredGitHubWebhook(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	secret := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	environment := daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "abcdefghijklmnopqrstuvwxyz123456", "OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET": secret})
	args := []string{"--listen", "127.0.0.1:0", "--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--github-webhook-repository", "repo-a", "--github-webhook-key-id", "key-2026-01"}
	daemon, err := buildDaemon(context.Background(), args, environment, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	if daemon.inboxStore == nil {
		t.Fatal("webhook inbox was not configured")
	}
	payload := []byte(`{"action":"opened","number":1}`)
	digest := hmac.New(sha256.New, []byte(secret))
	_, _ = digest.Write(payload)
	request := httptest.NewRequest(http.MethodPost, "https://trestle.test/webhooks/github", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Delivery", "delivery-1")
	request.Header.Set("X-GitHub-Event", "pull_request")
	request.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(digest.Sum(nil)))
	response := httptest.NewRecorder()
	daemon.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
}

func TestSecureServiceEndpointRequiresHTTPSOrLoopback(t *testing.T) {
	for _, value := range []string{"https://kms.us-east-1.amazonaws.com", "http://127.0.0.1:4566"} {
		if !validSecureServiceEndpoint(value) {
			t.Errorf("rejected %q", value)
		}
	}
	for _, value := range []string{"http://kms.example.test", "http://localhost:4566", "https://user:secret@kms.example.test", "https://kms.example.test/path"} {
		if validSecureServiceEndpoint(value) {
			t.Errorf("accepted %q", value)
		}
	}
}

func TestBuildDaemonConfiguresDurableGitHubRunSupervisor(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	secret := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	environment := daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "abcdefghijklmnopqrstuvwxyz123456", "OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET": secret})
	args := []string{"--listen", "127.0.0.1:0", "--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--github-webhook-repository", "repo-a", "--github-webhook-key-id", "key-2026-01", "--github-open-runs", "--github-repository-full-name", "owner/repo", "--github-review-policy-identity", strings.Repeat("a", 64)}
	kinds := []string{"acquire_source", "build_change", "inspect_deterministic", "retrieve_context", "assemble_context", "generate_candidates", "verify_candidates", "evaluate_publication"}
	for index, kind := range kinds {
		args = append(args, "--github-handler", kind+"="+strings.Repeat(string("12345678"[index]), 64))
	}
	daemon, err := buildDaemon(context.Background(), args, environment, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	if len(daemon.supervisors) != 2 {
		t.Fatalf("supervisors=%d", len(daemon.supervisors))
	}
}

func TestBuildDaemonConfiguresLocalDeterministicWorkers(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	environment := daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "abcdefghijklmnopqrstuvwxyz123456", "OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "OPEN_TRESTLE_GITHUB_API_TOKEN": "github-api-token"})
	args := []string{"--listen", "127.0.0.1:0", "--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--github-webhook-repository", "repo-a", "--github-webhook-key-id", "key-2026-01", "--github-open-runs", "--github-local-deterministic-workers", "--github-repository-full-name", "owner/repo", "--github-review-policy-identity", strings.Repeat("a", 64)}
	kinds := []string{"assemble_context", "generate_candidates", "verify_candidates", "evaluate_publication"}
	for index, kind := range kinds {
		args = append(args, "--github-handler", kind+"="+strings.Repeat(string("5678"[index]), 64))
	}
	daemon, err := buildDaemon(context.Background(), args, environment, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	if len(daemon.supervisors) != 3 {
		t.Fatalf("supervisors=%d", len(daemon.supervisors))
	}
}

func TestBuildDaemonConfiguresCompletePolicyBoundLocalPipeline(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	inventoryPath := filepath.Join(t.TempDir(), "inventory.json")
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	manifest := base64.StdEncoding.EncodeToString([]byte(`{"benchmark":"approved"}`))
	inventoryDocument := fmt.Sprintf(`{"schema_version":1,"routes":[{"zone":"private_remote","provider_id":"openai","adapter_id":"openai-responses","connection_id":"primary/openai","model_id":"model-a","model_version":"2026-01","max_context_tokens":128000,"max_output_tokens":8192,"features":["structured_output"],"content_logging":"disabled","pricing_known":true,"input_micro_usd_per_million_tokens":1000,"output_micro_usd_per_million_tokens":2000,"quality":"tier_3","registry_revision":7,"registry_status":"approved","evidence_manifest_base64":"%s","operational_revision":9,"health":"healthy","quota":"available","performance_revision":11,"latency_known":true,"p95_latency_milliseconds":2500,"latency_sample_count":100}]}`, manifest)
	if err := os.WriteFile(inventoryPath, []byte(inventoryDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	inventoryFile, err := os.Open(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), inventoryFile)
	_ = inventoryFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	policyID := strings.Repeat("a", 64)
	record := inventory.Candidates()[0].ResolvedRecord().RouteRegistryRecord().Identity()
	policyDocument := fmt.Sprintf(`{"schema_version":1,"inventory_identity":"%s","review_policy_identity":"%s","min_context_tokens":32000,"min_output_tokens":4096,"required_features":["structured_output"],"classification":"confidential","allowed_zones":["private_remote"],"content_logging_allowed":false,"estimated_input_tokens":8000,"max_output_tokens":4096,"max_cost_micro_usd":100000,"pinned_route_record_identity":"","preferred_route_record_identities":["%s"],"verification_independence":"distinct_provider","publication_minimum_severity":"medium","publication_max_inline_findings":20,"publication_minimum_independence":"distinct_provider","publication_block_on_inconclusive":true,"connections":[{"implementation":"openai_responses","adapter_id":"openai-responses","endpoint":"https://api.openai.com/v1","credential_environment":"OPEN_TRESTLE_PROVIDER_OPENAI_PRIMARY"}]}`, inventory.Identity(), policyID, record)
	if err := os.WriteFile(policyPath, []byte(policyDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	environment := daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "abcdefghijklmnopqrstuvwxyz123456", "OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"})
	args := []string{"--listen", "127.0.0.1:0", "--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--github-webhook-repository", "repo-a", "--github-webhook-key-id", "key-2026-01", "--github-open-runs", "--github-local-deterministic-workers", "--github-repository-full-name", "owner/repo", "--github-review-policy-identity", policyID, "--runtime-route-inventory", inventoryPath, "--runtime-policy", policyPath}
	daemon, err := buildDaemon(context.Background(), args, environment, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	if len(daemon.supervisors) != 3 {
		t.Fatalf("supervisors=%d", len(daemon.supervisors))
	}
}
func TestBuildDaemonRejectsPartialRuntimePolicyConfiguration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	daemon, err := buildDaemon(context.Background(), []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--runtime-policy", "policy.json"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "abcdefghijklmnopqrstuvwxyz123456"}), os.Stderr)
	if !errors.Is(err, ErrInvalidDaemonConfiguration) || daemon != nil {
		t.Fatalf("daemon=(%#v,%v)", daemon, err)
	}
}

func TestOpenRuntimeConfigurationFileRejectsMutableOrIndirectAuthority(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private.json")
	if err := os.WriteFile(private, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := openRuntimeConfigurationFile(private)
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	writable := filepath.Join(root, "writable.json")
	if err := os.WriteFile(writable, []byte(`{}`), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o666); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(t.TempDir(), "linked-parent")
	if err := os.Symlink(root, parentLink); err != nil {
		t.Fatal(err)
	}
	indirect := filepath.Join(parentLink, "private.json")
	for _, path := range []string{writable, link, indirect, root} {
		if file, err := openRuntimeConfigurationFile(path); !errors.Is(err, ErrInvalidDaemonConfiguration) || file != nil {
			t.Fatalf("path %q accepted: (%#v,%v)", path, file, err)
		}
	}
}

func TestEnvironmentOpenAICredentialsAreReadOnlyOnRequest(t *testing.T) {
	calls := 0
	getenv := func(name string) string {
		calls++
		if name != "OPEN_TRESTLE_PROVIDER_OPENAI_PRIMARY" {
			t.Fatalf("name=%q", name)
		}
		return "provider-secret"
	}
	provider, err := environmentOpenAICredentialResolver{getenv: getenv}.ResolveOpenAICredentials("OPEN_TRESTLE_PROVIDER_OPENAI_PRIMARY")
	if err != nil || calls != 0 {
		t.Fatalf("resolve=(%#v,%v), calls=%d", provider, err, calls)
	}
	key, err := provider.Retrieve(context.Background())
	if err != nil || calls != 1 {
		t.Fatalf("retrieve=(%#v,%v), calls=%d", key, err, calls)
	}
	if strings.Contains(fmt.Sprintf("%#v", key), "provider-secret") {
		t.Fatal("credential formatting leaked secret")
	}
}

func TestRepositoryPublicationTokenProviderUsesExactRequestTimeAuthority(t *testing.T) {
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	if err != nil {
		t.Fatal(err)
	}
	target, err := reviewcore.NewPublicationTarget("tenant-github-review", repository, "pull-42", revision)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	provider := repositoryPublicationTokenProvider{tenantID: "tenant-a", repositoryID: "repo-a", repositoryFullName: "owner/repo", publisherID: "tenant-github-review", environment: "OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN", getenv: func(name string) string {
		calls++
		if name != "OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN" {
			t.Fatalf("name=%q", name)
		}
		return "publication-secret"
	}}
	token, err := provider.RetrievePublicationToken(context.Background(), scope, target)
	if err != nil || token.Validate() != nil || calls != 1 {
		t.Fatalf("token=(%#v,%v), calls=%d", token, err, calls)
	}
	otherScope, err := audit.NewReviewScope("tenant-a", "repo-b", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	if provider.ConfigurationIdentity() == "" {
		t.Fatal("missing credential provider identity")
	}
	otherProvider := provider
	otherProvider.repositoryFullName = "owner/other"
	if provider.ConfigurationIdentity() == otherProvider.ConfigurationIdentity() {
		t.Fatal("credential provider identity omitted repository scope")
	}
	if token, err := provider.RetrievePublicationToken(context.Background(), otherScope, target); !errors.Is(err, githubsource.ErrPublicationCredentialsUnavailable) || token.Validate() == nil || calls != 1 {
		t.Fatalf("cross-scope token=(%#v,%v), calls=%d", token, err, calls)
	}
}

func TestBuildDaemonObserverTokenIsReadOnly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	operator := "01234567890123456789012345678901"
	observer := "abcdefghijklmnopqrstuvwxyz123456"
	daemon, err := buildDaemon(context.Background(), []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": operator, "OPEN_TRESTLE_OBSERVER_TOKEN": observer}), os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	request := func(method, path, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		daemon.server.Handler.ServeHTTP(w, r)
		return w
	}
	if got := request(http.MethodGet, "/api/v1/tenants/tenant-a/repositories/repo-a/runtime", observer); got.Code != http.StatusOK {
		t.Fatalf("runtime=%d %s", got.Code, got.Body.String())
	}
	if got := request(http.MethodGet, "/api/v1/tenants/tenant-a/repositories/repo-a/runs/missing", observer); got.Code != http.StatusNotFound {
		t.Fatalf("run read=%d %s", got.Code, got.Body.String())
	}
	if got := request(http.MethodPost, "/api/v1/tenants/tenant-a/repositories/repo-a/runs/missing/cancel", observer); got.Code != http.StatusForbidden {
		t.Fatalf("cancel=%d %s", got.Code, got.Body.String())
	}
	if got := request(http.MethodPost, "/api/v1/tenants/tenant-a/repositories/repo-a/runs/missing/tasks/source/claim", observer); got.Code != http.StatusForbidden {
		t.Fatalf("claim=%d %s", got.Code, got.Body.String())
	}
}
func TestBuildDaemonRejectsDuplicateObserverAuthority(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	token := "01234567890123456789012345678901"
	daemon, err := buildDaemon(context.Background(), []string{"--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": token, "OPEN_TRESTLE_OBSERVER_TOKEN": token}), os.Stderr)
	if !errors.Is(err, ErrInvalidDaemonConfiguration) || daemon != nil {
		t.Fatalf("daemon=%#v err=%v", daemon, err)
	}
}

func TestRemoteStorageTransportIsDirectAndBounded(t *testing.T) {
	transport := newDaemonRemoteStorageTransport()
	if transport == nil || transport.Proxy != nil || !transport.DisableKeepAlives || transport.ForceAttemptHTTP2 || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.ResponseHeaderTimeout != 10*time.Second || transport.MaxResponseHeaderBytes != 1<<20 {
		t.Fatalf("transport=%#v", transport)
	}
	transport.CloseIdleConnections()
}

func TestBuildDaemonRejectsWebhookSecretReuse(t *testing.T) {
	for _, other := range []string{"OPEN_TRESTLE_API_TOKEN", "OPEN_TRESTLE_OBSERVER_TOKEN", "OPEN_TRESTLE_GITHUB_SETUP_TOKEN", "OPEN_TRESTLE_SETUP_TOKEN"} {
		t.Run(other, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			secret := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
			values := map[string]string{"OPEN_TRESTLE_API_TOKEN": "abcdefghijklmnopqrstuvwxyz123456", "OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET": secret}
			values[other] = secret
			daemon, err := buildDaemon(context.Background(), []string{"--listen", "127.0.0.1:0", "--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--github-webhook-repository", "repo-a", "--github-webhook-key-id", "key-2026-01"}, daemonEnvironment(values), os.Stderr)
			if daemon != nil {
				_ = daemon.Close()
			}
			if daemon != nil || !errors.Is(err, ErrInvalidDaemonConfiguration) {
				t.Fatalf("daemon=%#v err=%v", daemon, err)
			}
		})
	}
}

func TestPublicationCredentialProviderRejectsWebhookSecretReuseAtRetrieval(t *testing.T) {
	secret := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	digest := sha256.Sum256([]byte(secret))
	provider := repositoryPublicationTokenProvider{tenantID: "tenant-a", repositoryID: "repo-a", repositoryFullName: "owner/repo", publisherID: "tenant-github-review", environment: "OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN", forbiddenCredentialDigest: digest, getenv: func(string) string { return secret }}
	withoutFence := provider
	withoutFence.forbiddenCredentialDigest = [sha256.Size]byte{}
	if provider.ConfigurationIdentity() == withoutFence.ConfigurationIdentity() {
		t.Fatal("credential identity omitted webhook separation posture")
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	revision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	target, _ := reviewcore.NewPublicationTarget("tenant-github-review", repository, "pull-42", revision)
	if _, err := provider.RetrievePublicationToken(context.Background(), scope, target); !errors.Is(err, githubsource.ErrPublicationCredentialsUnavailable) {
		t.Fatalf("error=%v", err)
	}
}

func TestBuildDaemonRejectsRuntimeGitHubTokenMatchingWebhookSecret(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	secret := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	environment := daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "abcdefghijklmnopqrstuvwxyz123456", "OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET": secret, "OPEN_TRESTLE_GITHUB_API_TOKEN": secret})
	args := []string{"--listen", "127.0.0.1:0", "--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--github-webhook-repository", "repo-a", "--github-webhook-key-id", "key-2026-01", "--github-open-runs", "--github-local-deterministic-workers", "--github-repository-full-name", "owner/repo", "--github-review-policy-identity", strings.Repeat("a", 64)}
	for index, kind := range []string{"assemble_context", "generate_candidates", "verify_candidates", "evaluate_publication"} {
		args = append(args, "--github-handler", kind+"="+strings.Repeat(string("5678"[index]), 64))
	}
	daemon, err := buildDaemon(context.Background(), args, environment, os.Stderr)
	if daemon != nil {
		_ = daemon.Close()
	}
	if daemon != nil || !errors.Is(err, ErrInvalidDaemonConfiguration) {
		t.Fatalf("daemon=%#v err=%v", daemon, err)
	}
}

func TestBuildDaemonRejectsStructurallyWeakWebhookSecretBeforeStateCreation(t *testing.T) {
	for _, secret := range []string{"short", strings.Repeat("a", 64), strings.Repeat("0123456789abcdef", 4), "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"} {
		root := filepath.Join(t.TempDir(), "state")
		daemon, err := buildDaemon(context.Background(), []string{"--listen", "127.0.0.1:0", "--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a", "--github-webhook-repository", "repo-a", "--github-webhook-key-id", "key-2026-01"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "abcdefghijklmnopqrstuvwxyz123456", "OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET": secret}), os.Stderr)
		if daemon != nil {
			_ = daemon.Close()
		}
		if daemon != nil || !errors.Is(err, ErrInvalidDaemonConfiguration) {
			t.Fatalf("secret=%q daemon=%#v err=%v", secret, daemon, err)
		}
		if _, statErr := os.Lstat(root); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("state created for rejected secret: %v", statErr)
		}
	}
}

func TestBuildDaemonCancellationDuringConfigurationPreventsStateWrites(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	environment := func(key string) string {
		if key == "OPEN_TRESTLE_API_TOKEN" {
			cancel()
			return "01234567890123456789012345678901"
		}
		return ""
	}
	built, err := buildDaemon(ctx, []string{"--listen", "127.0.0.1:0", "--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a"}, environment, io.Discard)
	if built != nil {
		built.Close()
	}
	if !errors.Is(err, context.Canceled) || built != nil {
		t.Fatalf("startup ignored cancellation: %v", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled startup wrote state: %v", err)
	}
}
