//go:build unix

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	githubsource "github.com/georgejieh/open-trestle/adapters/scm/github"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/githubruntime"
)

const (
	daemonFixtureToken       = "fixture-issued-installation-token"
	daemonFixtureSetup       = "fixture-setup-sentinel-never-source"
	daemonFixtureStatic      = "fixture-static-sentinel-never-source"
	daemonFixturePublication = "fixture-publication-sentinel-never-source"
	daemonFixtureOperator    = "fixture-operator-token-0123456789abcdef"
	daemonFixtureWebhook     = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	daemonFixtureContent     = "package main\n"
)

type daemonBrokerFixture struct {
	key                                 *rsa.PrivateKey
	pem                                 []byte
	pin                                 string
	started                             time.Time
	expires                             time.Time
	api, archive                        *httptest.Server
	tree, blob                          string
	compressed                          []byte
	mu                                  sync.Mutex
	failures                            []string
	apiPaths, archivePaths              []string
	sourceHeaders, archiveHeaders       []http.Header
	jwtHeaders                          []string
	installationGETs, installationPOSTs int
}

func newDaemonBrokerFixture(t *testing.T) *daemonBrokerFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(public)
	f := &daemonBrokerFixture{
		key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		pin: hex.EncodeToString(pin[:]), started: time.Now().UTC().Truncate(time.Second),
	}
	f.expires = f.started.Add(time.Hour)
	f.blob = fixtureGitObject("blob", []byte(daemonFixtureContent))
	f.tree = fixtureGitTree("100644", "main.go", f.blob)
	f.compressed = fixtureArchive(t, "main.go", []byte(daemonFixtureContent))
	f.archive = httptest.NewServer(http.HandlerFunc(f.serveArchive))
	f.api = httptest.NewServer(http.HandlerFunc(f.serveAPI))
	t.Cleanup(f.archive.Close)
	t.Cleanup(f.api.Close)
	return f
}

func (f *daemonBrokerFixture) reject(w http.ResponseWriter, message string) {
	f.failures = append(f.failures, message)
	http.Error(w, "fixture rejected request", http.StatusBadRequest)
}

func (f *daemonBrokerFixture) checkJWT(r *http.Request) bool {
	authorization := r.Header.Get("Authorization")
	if len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(authorization, "Bearer ") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(authorization, "Bearer "), ".")
	if len(parts) != 3 {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	var h map[string]any
	if json.Unmarshal(header, &h) != nil || !reflect.DeepEqual(h, map[string]any{"alg": "RS256", "typ": "JWT"}) {
		return false
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil || len(claims) != 3 {
		return false
	}
	var issuer string
	var iat, exp int64
	if json.Unmarshal(claims["iss"], &issuer) != nil || issuer != "7" || json.Unmarshal(claims["iat"], &iat) != nil || json.Unmarshal(claims["exp"], &exp) != nil {
		return false
	}
	captured := iat + 60
	if exp != captured+300 || captured < f.started.Unix() || captured > time.Now().Unix() {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(&f.key.PublicKey, crypto.SHA256, digest[:], signature) == nil
}

func (f *daemonBrokerFixture) headersSeparated(r *http.Request, issuer bool) bool {
	for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Api-Key"} {
		if len(r.Header.Values(name)) != 0 {
			return false
		}
	}
	for name, values := range r.Header {
		for _, value := range values {
			for _, forbidden := range []string{daemonFixtureSetup, daemonFixtureStatic, daemonFixturePublication, daemonFixtureOperator, daemonFixtureWebhook, string(f.pem), "-----BEGIN RSA PRIVATE KEY-----"} {
				if strings.Contains(value, forbidden) {
					return false
				}
			}
			if !strings.EqualFold(name, "Authorization") {
				if strings.Contains(value, daemonFixtureToken) {
					return false
				}
				if issuer {
					currentJWT := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
					if currentJWT != "" && strings.Contains(value, currentJWT) {
						return false
					}
				}
				for _, jwt := range f.jwtHeaders {
					if strings.Contains(value, strings.TrimPrefix(jwt, "Bearer ")) {
						return false
					}
				}
			}
		}
	}
	if issuer {
		return !strings.Contains(r.Header.Get("Authorization"), daemonFixtureToken)
	}
	return true
}

func (f *daemonBrokerFixture) serveAPI(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.apiPaths = append(f.apiPaths, r.Method+" "+r.URL.RequestURI())
	w.Header().Set("Content-Type", "application/json")
	issuer := strings.HasPrefix(r.URL.Path, "/api/v3/app/")
	if r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || !f.headersSeparated(r, issuer) {
		f.reject(w, "API version or credential separation")
		return
	}
	if issuer {
		if !f.checkJWT(r) || r.URL.RawQuery != "" {
			f.reject(w, "issuer JWT or query")
			return
		}
		f.jwtHeaders = append(f.jwtHeaders, r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/app/installations/42":
			f.installationGETs++
			if f.installationGETs != 1 || f.installationPOSTs != 0 {
				f.reject(w, "installation GET repeated or reordered")
				return
			}
			_, _ = io.WriteString(w, `{"id":42,"app_id":7,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"read","pull_requests":"read"},"events":["pull_request"],"suspended_at":null}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v3/app/installations/42/access_tokens":
			f.installationPOSTs++
			if f.installationPOSTs != 1 || f.installationGETs != 1 || r.Header.Get("Content-Type") != "application/json" {
				f.reject(w, "installation POST repeated or reordered")
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
			var got map[string]any
			want := map[string]any{"repository_ids": []any{float64(99)}, "permissions": map[string]any{"contents": "read", "metadata": "read", "pull_requests": "read"}}
			if err != nil || len(body) > 4096 || json.Unmarshal(body, &got) != nil || !reflect.DeepEqual(got, want) {
				f.reject(w, "issuance narrowing")
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": daemonFixtureToken, "expires_at": f.expires.Format(time.RFC3339), "repository_selection": "selected", "permissions": want["permissions"], "repositories": []any{map[string]any{"id": 99, "full_name": "owner/repo"}}})
		default:
			f.reject(w, "unexpected issuer route")
		}
		return
	}
	f.sourceHeaders = append(f.sourceHeaders, r.Header.Clone())
	if r.Method != http.MethodGet || len(r.Header.Values("Authorization")) != 1 || r.Header.Get("Authorization") != "Bearer "+daemonFixtureToken || f.installationPOSTs != 1 {
		f.reject(w, "source did not consume issued token")
		return
	}
	prefix := "/api/v3/repos/owner/repo/"
	for _, commit := range []string{strings.Repeat("a", 40), strings.Repeat("b", 40)} {
		if r.URL.Path == prefix+"git/commits/"+commit && r.URL.RawQuery == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": commit, "tree": map[string]any{"sha": f.tree}})
			return
		}
		if r.URL.Path == prefix+"tarball/"+commit && r.URL.RawQuery == "" {
			http.Redirect(w, r, f.archive.URL+"/owner/repo/archive/"+commit, http.StatusFound)
			return
		}
	}
	if r.URL.Path == prefix+"git/trees/"+f.tree && r.URL.RawQuery == "recursive=1" {
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": f.tree, "truncated": false, "tree": []any{map[string]any{"path": "main.go", "mode": "100644", "type": "blob", "sha": f.blob, "size": len(daemonFixtureContent)}}})
		return
	}
	f.reject(w, "unexpected source route")
}

func (f *daemonBrokerFixture) serveArchive(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.archivePaths = append(f.archivePaths, r.Method+" "+r.URL.RequestURI())
	f.archiveHeaders = append(f.archiveHeaders, r.Header.Clone())
	validPath := r.URL.Path == "/owner/repo/archive/"+strings.Repeat("a", 40) || r.URL.Path == "/owner/repo/archive/"+strings.Repeat("b", 40)
	if r.Method != http.MethodGet || !validPath || r.URL.RawQuery != "" || len(r.Header.Values("Authorization")) != 0 || !f.headersSeparated(r, false) {
		f.reject(w, "archive route or credential leakage")
		return
	}
	for _, values := range r.Header {
		for _, value := range values {
			if strings.Contains(value, daemonFixtureToken) {
				f.reject(w, "archive issued-token leakage")
				return
			}
			for _, jwt := range f.jwtHeaders {
				if strings.Contains(value, strings.TrimPrefix(jwt, "Bearer ")) {
					f.reject(w, "archive JWT leakage")
					return
				}
			}
		}
	}
	w.Header().Set("Content-Type", "application/gzip")
	_, _ = w.Write(f.compressed)
}

func requireProtectedFixtureRoot(t *testing.T, root string) {
	t.Helper()
	if err := fileauthority.CheckDirectory(root); err != nil {
		t.Fatalf("unsafe native temporary root; configure a trusted test environment: %v", err)
	}
}

func writeProtectedBrokerDescriptor(t *testing.T, root string, f *daemonBrokerFixture) (path, authority string) {
	t.Helper()
	requireProtectedFixtureRoot(t, root)
	attempts := filepath.Join(root, "attempts")
	if err := os.Mkdir(attempts, 0o700); err != nil {
		t.Fatal(err)
	}
	archiveURL, err := url.Parse(f.archive.URL)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := map[string]any{
		"contract": "open-trestle/github-source-broker", "schema_version": 1,
		"tenant_id": "tenant-a", "repository_id": "repo-a", "repository_full_name": "owner/repo", "github_repository_id": 99,
		"repository_authority": "github.com", "api_endpoint": f.api.URL + "/api/v3", "api_version": "2026-03-10", "archive_authorities": []string{archiveURL.Host},
		"installation_id": 42, "app_id": 7, "app_key_version": "fixture-key-1", "app_public_key_sha256": f.pin,
		"credential_environment": "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY", "authorization_generation": strings.Repeat("d", 64),
		"ownership_mode": "single_host_exclusive", "attempt_state_directory": attempts,
		"allow_token_creation": true, "allow_demand_renewal": true,
	}
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(root, "broker.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := githubruntime.LoadConfig(context.Background(), path)
	if err != nil || config.Validate() != nil || config.AuthorityIdentity() == "" {
		t.Fatalf("protected config: %v", err)
	}
	entries, err := os.ReadDir(attempts)
	if err != nil || len(entries) != 0 {
		t.Fatal("offline authority derivation created guard state")
	}
	return path, config.AuthorityIdentity()
}

func findDaemonSourceRuntime(t *testing.T, d *daemon) *githubSourceRuntime {
	t.Helper()
	var found *githubSourceRuntime
	count := 0
	for _, closer := range d.closers {
		if source, ok := closer.(*githubSourceRuntime); ok {
			count++
			found = source
		}
	}
	if count != 1 || found == nil || found.handler == nil || found.adapter == nil || found.credentials == nil {
		t.Fatal("daemon did not register exactly one complete source owner")
	}
	if found.handler.Validate() != nil || found.adapter.Validate() != nil {
		t.Fatal("invalid registered source runtime")
	}
	expected, err := githubsource.BrokeredSourceAdapterIdentity()
	if err != nil || found.adapter.Identity().Identity() != expected.Identity() || expected.Name() != "open-trestle.github-rest-installation" || expected.Version() != "1.0.0" {
		t.Fatal("wrong source adapter identity")
	}
	return found
}

func daemonSourceExecutionRequest(t *testing.T, scope audit.ReviewScope, inputIdentity, handlerIdentity string, at time.Time) controlplane.TaskExecutionRequest {
	t.Helper()
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, inputIdentity, handlerIdentity, nil, 2, 1000, 30000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(context.Background(), plan, at); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Advance(context.Background(), plan, at); err != nil {
		t.Fatal(err)
	}
	lease, claimed, err := coordinator.ClaimTask(context.Background(), plan, task.Key(), handlerIdentity, "fixture-source-worker", at)
	if err != nil || !claimed {
		t.Fatalf("claim: %v", err)
	}
	request, err := controlplane.NewTaskExecutionRequest(plan, task, lease)
	if err != nil || request.Validate() != nil {
		t.Fatalf("source task request: %v", err)
	}
	return request
}

func executeDaemonSourceFixture(t *testing.T, d *daemon, source *githubSourceRuntime, commit string, at time.Time) {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "source-"+commit)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, commit)
	if err != nil {
		t.Fatal(err)
	}
	input, err := sourcehandler.NewInput(repository, revision, source.adapter.Identity())
	if err != nil {
		t.Fatal(err)
	}
	inputArtifact, err := sourcehandler.NewInputArtifact(scope, input, artifact.ClassificationRestricted, artifact.ProtectionProcessPrivate, []string{strings.Repeat("e", 64)}, at, at.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if created, err := d.artifactStore.Put(context.Background(), inputArtifact, at); err != nil || !created {
		t.Fatalf("persist source input: %v", err)
	}
	request := daemonSourceExecutionRequest(t, scope, inputArtifact.Identity(), source.handler.HandlerIdentity(), at)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	completion := source.handler.Execute(ctx, request)
	if completion.Validate() != nil || completion.Status() != controlplane.TaskCompletionSucceeded {
		t.Fatalf("native source completion: %s", completion.Failure())
	}
	now := time.Now().UTC()
	output, err := d.artifactStore.Get(context.Background(), scope, completion.OutputIdentity(), now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := sourcehandler.ParseSnapshotArtifact(output)
	if err != nil {
		t.Fatal(err)
	}
	expectedFile, err := evidence.NewRepositoryFile("main.go", []byte(daemonFixtureContent))
	if err != nil {
		t.Fatal(err)
	}
	expectedManifest, err := evidence.NewRepositoryManifest([]evidence.RepositoryFile{expectedFile})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.FileCount() != 1 || snapshot.ManifestIdentity() != expectedManifest.Identity() || snapshot.RevisionIdentity() != revision.Identity() || snapshot.RepositoryIdentity() != repository.Identity() || snapshot.SourceAdapterIdentity() != source.adapter.Identity().Identity() || snapshot.AcquisitionExecutionIdentity() == "" || snapshot.Protection() != artifact.ProtectionProcessPrivate {
		t.Fatal("source snapshot identity or manifest mismatch")
	}
	reference := snapshot.Files()[0]
	value, err := d.artifactStore.Get(context.Background(), scope, reference.ArtifactIdentity(), now)
	if err != nil {
		t.Fatal(err)
	}
	file, err := sourcehandler.ParseFileArtifact(value, snapshot, reference)
	if err != nil || file.Path() != "main.go" || file.Digest() != expectedFile.Digest() || file.SizeBytes() != len(daemonFixtureContent) || !bytes.Equal(file.Content(), []byte(daemonFixtureContent)) {
		t.Fatal("persisted native source content mismatch")
	}
}

func fixtureGitObject(kind string, content []byte) string {
	value := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(content))), content...)
	digest := sha1.Sum(value)
	return hex.EncodeToString(digest[:])
}

func fixtureGitTree(mode, name, objectID string) string {
	raw, err := hex.DecodeString(objectID)
	if err != nil {
		panic("invalid synthetic git object ID")
	}
	return fixtureGitObject("tree", append([]byte(mode+" "+name+"\x00"), raw...))
}

func fixtureArchive(t *testing.T, filePath string, content []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	root := "owner-repo-fixture/"
	if err := archive.WriteHeader(&tar.Header{Name: root, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if err := archive.WriteHeader(&tar.Header{Name: root + filePath, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestDaemonSourceConsumesBrokerIssuedInstallationToken(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		name := "success"
		if mixed {
			name = "mixed-static-sentinel"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			requireProtectedFixtureRoot(t, root)
			f := newDaemonBrokerFixture(t)
			path, authority := writeProtectedBrokerDescriptor(t, root, f)
			values := map[string]string{
				"OPEN_TRESTLE_API_TOKEN":                   daemonFixtureOperator,
				"OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET":       daemonFixtureWebhook,
				"OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG": path,
				"OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY":      string(f.pem),
				"OPEN_TRESTLE_GITHUB_SETUP_TOKEN":          daemonFixtureSetup,
				"OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN":    daemonFixturePublication,
			}
			if mixed {
				values["OPEN_TRESTLE_GITHUB_API_TOKEN"] = daemonFixtureStatic
			}
			var readMu sync.Mutex
			reads := map[string]int{}
			getenv := func(key string) string { readMu.Lock(); defer readMu.Unlock(); reads[key]++; return values[key] }
			args := []string{"--listen", "127.0.0.1:0", "--state-dir", filepath.Join(root, "state"), "--tenant", "tenant-a", "--repository", "repo-a", "--github-webhook-repository", "repo-a", "--github-webhook-key-id", "key-2026-01", "--github-open-runs", "--github-local-deterministic-workers", "--github-repository-full-name", "owner/repo", "--github-review-policy-identity", strings.Repeat("a", 64), "--approve-github-source-broker-authority-identity", authority}
			for index, kind := range []string{"assemble_context", "generate_candidates", "verify_candidates", "evaluate_publication"} {
				args = append(args, "--github-handler", kind+"="+strings.Repeat(string("5678"[index]), 64))
			}
			d, err := buildDaemon(context.Background(), args, getenv, io.Discard)
			if d != nil {
				t.Cleanup(func() {
					if err := d.Close(); err != nil {
						t.Errorf("daemon close: %v", err)
					}
				})
			}
			readMu.Lock()
			keyReads := reads["OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY"]
			publicationReads := reads["OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN"]
			readMu.Unlock()
			f.mu.Lock()
			beforeHTTP := len(f.apiPaths) + len(f.archivePaths)
			f.mu.Unlock()
			if keyReads != 0 || publicationReads != 0 || beforeHTTP != 0 {
				t.Fatal("daemon bootstrap consumed a source credential or performed HTTP")
			}
			if mixed {
				if d != nil || !errors.Is(err, ErrInvalidDaemonConfiguration) {
					t.Fatal("mixed source credentials were not refused")
				}
				entries, readErr := os.ReadDir(filepath.Join(root, "attempts"))
				if readErr != nil || len(entries) != 0 {
					t.Fatal("mixed mode created guard state")
				}
				return
			}
			if err != nil || d == nil {
				t.Fatalf("build daemon: %v", err)
			}
			if _, ok := d.artifactStore.(*artifact.FileStore); !ok {
				t.Fatal("fixture did not use native protected file store")
			}
			readMu.Lock()
			bootstrapReads := make(map[string]int, len(reads))
			for key, count := range reads {
				bootstrapReads[key] = count
			}
			readMu.Unlock()
			source := findDaemonSourceRuntime(t, d)
			readMu.Lock()
			keyReads = reads["OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY"]
			readMu.Unlock()
			f.mu.Lock()
			beforeHTTP = len(f.apiPaths) + len(f.archivePaths)
			f.mu.Unlock()
			if keyReads != 0 || beforeHTTP != 0 {
				t.Fatal("source validation consumed a credential or performed HTTP")
			}
			for _, commit := range []string{strings.Repeat("a", 40), strings.Repeat("b", 40)} {
				executeDaemonSourceFixture(t, d, source, commit, time.Now().UTC().Truncate(time.Millisecond))
				readMu.Lock()
				keyReads = reads["OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY"]
				publicationReads = reads["OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN"]
				readMu.Unlock()
				if keyReads != 1 || publicationReads != 0 {
					t.Fatal("source credential callback did not remain lazy and single-load")
				}
				readMu.Lock()
				changedEnvironment := false
				for key, count := range reads {
					if key != "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY" && count != bootstrapReads[key] {
						changedEnvironment = true
					}
				}
				readMu.Unlock()
				if changedEnvironment {
					t.Fatal("source acquisition read an unrelated environment credential")
				}
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.failures) != 0 {
				t.Fatalf("HTTP fixture refusals: %v", f.failures)
			}
			if f.installationGETs != 1 || f.installationPOSTs != 1 || len(f.apiPaths) != 8 || len(f.sourceHeaders) != 6 || len(f.archivePaths) != 2 || len(f.archiveHeaders) != 2 {
				t.Fatal("source did not reuse exactly one native issued grant")
			}
			expectedPaths := []string{"GET /api/v3/app/installations/42", "POST /api/v3/app/installations/42/access_tokens"}
			expectedArchives := []string{}
			for _, commit := range []string{strings.Repeat("a", 40), strings.Repeat("b", 40)} {
				expectedPaths = append(expectedPaths, "GET /api/v3/repos/owner/repo/git/commits/"+commit, "GET /api/v3/repos/owner/repo/git/trees/"+f.tree+"?recursive=1", "GET /api/v3/repos/owner/repo/tarball/"+commit)
				expectedArchives = append(expectedArchives, "GET /owner/repo/archive/"+commit)
			}
			if !reflect.DeepEqual(f.apiPaths, expectedPaths) || !reflect.DeepEqual(f.archivePaths, expectedArchives) {
				t.Fatal("unexpected request ordering, route or retry")
			}
			for _, headers := range f.sourceHeaders {
				if headers.Get("Authorization") != "Bearer "+daemonFixtureToken || len(headers.Values("Authorization")) != 1 {
					t.Fatal("source credential mismatch")
				}
			}
			for _, headers := range f.archiveHeaders {
				if len(headers.Values("Authorization")) != 0 {
					t.Fatal("cross-origin Authorization leakage")
				}
			}
			if f.api.URL == f.archive.URL {
				t.Fatal("archive fixture was not a separate origin")
			}
			entries, err := os.ReadDir(filepath.Join(root, "attempts"))
			if err != nil || len(entries) != 3 {
				t.Fatal("expected one real owner, pending and terminal record")
			}
			forbidden := []string{daemonFixtureToken, daemonFixtureSetup, daemonFixtureStatic, daemonFixturePublication, daemonFixtureOperator, daemonFixtureWebhook, string(f.pem), "-----BEGIN RSA PRIVATE KEY-----"}
			for _, jwt := range f.jwtHeaders {
				forbidden = append(forbidden, strings.TrimPrefix(jwt, "Bearer "))
			}
			for _, entry := range entries {
				info, err := entry.Info()
				if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 4096 || info.Size() == 0 {
					t.Fatal("unsafe or unbounded guard record")
				}
				body, err := os.ReadFile(filepath.Join(root, "attempts", entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range forbidden {
					if bytes.Contains(body, []byte(secret)) || strings.Contains(entry.Name(), secret) {
						t.Fatal("guard persisted credential material")
					}
				}
			}
		})
	}
}
