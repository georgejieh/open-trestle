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

	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/githubruntime"
)

const (
	daemonBudgetedGitHubIssuedToken = "fixture-budgeted-issued-installation-token"
	daemonBudgetedGitHubSetupToken  = "fixture-budgeted-setup-token-never-source"
	daemonBudgetedGitHubPubToken    = "fixture-budgeted-publication-token-never-source"
	daemonBudgetedGitHubWebhook     = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	daemonBudgetedGitHubBaseCommit  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	daemonBudgetedGitHubHeadCommit  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type daemonBudgetedGitHubRevision struct {
	commit  string
	content []byte
	blob    string
	tree    string
	archive []byte
}

type daemonBudgetedGitHubFixture struct {
	key               *rsa.PrivateKey
	pem               []byte
	pin               string
	started           time.Time
	expires           time.Time
	api, archive      *httptest.Server
	revisions         map[string]daemonBudgetedGitHubRevision
	mu                sync.Mutex
	failures          []string
	apiPaths          []string
	archivePaths      []string
	sourceHeaders     []http.Header
	archiveHeaders    []http.Header
	jwtHeaders        []string
	installationGETs  int
	installationPOSTs int
}

func newDaemonBudgetedGitHubFixture(t *testing.T, raw time.Time) *daemonBudgetedGitHubFixture {
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
	f := &daemonBudgetedGitHubFixture{
		key:       key,
		pem:       pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		pin:       hex.EncodeToString(pin[:]),
		started:   raw.UTC().Truncate(time.Second),
		revisions: map[string]daemonBudgetedGitHubRevision{},
	}
	f.expires = f.started.Add(time.Hour)
	f.addRevision(t, daemonBudgetedGitHubBaseCommit, []byte("package main\n\nfunc value() int {\n\treturn 1\n}\n"))
	f.addRevision(t, daemonBudgetedGitHubHeadCommit, []byte("package main\n\nfunc value() int {\n\tprintln(\"debug\")\n\treturn 2\n}\n"))
	newServer := func(handler http.HandlerFunc) *httptest.Server {
		server := httptest.NewUnstartedServer(handler)
		server.Config.ReadHeaderTimeout = 2 * time.Second
		server.Config.ReadTimeout = 5 * time.Second
		server.Config.WriteTimeout = 5 * time.Second
		server.Config.MaxHeaderBytes = 16 << 10
		server.Start()
		return server
	}
	f.archive = newServer(f.serveArchive)
	f.api = newServer(f.serveAPI)
	t.Cleanup(f.archive.Close)
	t.Cleanup(f.api.Close)
	return f
}

func (f *daemonBudgetedGitHubFixture) addRevision(t *testing.T, commit string, content []byte) {
	t.Helper()
	blob := daemonBudgetedGitObject("blob", content)
	tree := daemonBudgetedGitTree("100644", "main.go", blob)
	f.revisions[commit] = daemonBudgetedGitHubRevision{commit: commit, content: append([]byte(nil), content...), blob: blob, tree: tree, archive: daemonBudgetedGitArchive(t, commit, "main.go", content)}
}

func (f *daemonBudgetedGitHubFixture) reject(w http.ResponseWriter, reason string) {
	if len(f.failures) < 16 {
		f.failures = append(f.failures, reason)
	}
	http.Error(w, "fixture rejected request", http.StatusBadRequest)
}

func (f *daemonBudgetedGitHubFixture) checkJWT(r *http.Request) bool {
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

func (f *daemonBudgetedGitHubFixture) headersSeparated(r *http.Request, issuer bool) bool {
	for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Api-Key"} {
		if len(r.Header.Values(name)) != 0 {
			return false
		}
	}
	for name, values := range r.Header {
		for _, value := range values {
			for _, forbidden := range []string{daemonBudgetedGitHubSetupToken, daemonBudgetedGitHubPubToken, daemonBudgetedGitHubWebhook, string(f.pem), "-----BEGIN RSA PRIVATE KEY-----"} {
				if strings.Contains(value, forbidden) {
					return false
				}
			}
			if !strings.EqualFold(name, "Authorization") && strings.Contains(value, daemonBudgetedGitHubIssuedToken) {
				return false
			}
			if issuer && strings.Contains(value, daemonBudgetedGitHubIssuedToken) {
				return false
			}
			for _, jwt := range f.jwtHeaders {
				if !strings.EqualFold(name, "Authorization") && strings.Contains(value, strings.TrimPrefix(jwt, "Bearer ")) {
					return false
				}
			}
		}
	}
	return true
}

func (f *daemonBudgetedGitHubFixture) serveAPI(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.apiPaths) >= 16 {
		f.reject(w, "API request limit exceeded")
		return
	}
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
			_ = json.NewEncoder(w).Encode(map[string]any{"token": daemonBudgetedGitHubIssuedToken, "expires_at": f.expires.Format(time.RFC3339), "repository_selection": "selected", "permissions": want["permissions"], "repositories": []any{map[string]any{"id": 99, "full_name": "owner/repo"}}})
		default:
			f.reject(w, "unexpected issuer route")
		}
		return
	}
	f.sourceHeaders = append(f.sourceHeaders, r.Header.Clone())
	if r.Method != http.MethodGet || len(r.Header.Values("Authorization")) != 1 || r.Header.Get("Authorization") != "Bearer "+daemonBudgetedGitHubIssuedToken || f.installationPOSTs != 1 {
		f.reject(w, "source did not consume issued token")
		return
	}
	prefix := "/api/v3/repos/owner/repo/"
	for _, revision := range f.revisions {
		if r.URL.Path == prefix+"git/commits/"+revision.commit && r.URL.RawQuery == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": revision.commit, "tree": map[string]any{"sha": revision.tree}})
			return
		}
		if r.URL.Path == prefix+"git/trees/"+revision.tree && r.URL.RawQuery == "recursive=1" {
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": revision.tree, "truncated": false, "tree": []any{map[string]any{"path": "main.go", "mode": "100644", "type": "blob", "sha": revision.blob, "size": len(revision.content)}}})
			return
		}
		if r.URL.Path == prefix+"tarball/"+revision.commit && r.URL.RawQuery == "" {
			http.Redirect(w, r, f.archive.URL+"/owner/repo/archive/"+revision.commit, http.StatusFound)
			return
		}
	}
	f.reject(w, "unexpected source route")
}

func (f *daemonBudgetedGitHubFixture) serveArchive(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.archivePaths) >= 4 {
		f.reject(w, "archive request limit exceeded")
		return
	}
	f.archivePaths = append(f.archivePaths, r.Method+" "+r.URL.RequestURI())
	f.archiveHeaders = append(f.archiveHeaders, r.Header.Clone())
	commit := strings.TrimPrefix(r.URL.Path, "/owner/repo/archive/")
	revision, ok := f.revisions[commit]
	if r.Method != http.MethodGet || !ok || r.URL.RawQuery != "" || len(r.Header.Values("Authorization")) != 0 || !f.headersSeparated(r, false) {
		f.reject(w, "archive route or credential leakage")
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	_, _ = w.Write(revision.archive)
}

func (f *daemonBudgetedGitHubFixture) snapshot() (apiPaths, archivePaths []string, sourceHeaders, archiveHeaders int, failures []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.apiPaths...), append([]string(nil), f.archivePaths...), len(f.sourceHeaders), len(f.archiveHeaders), append([]string(nil), f.failures...)
}

func writeDaemonBudgetedGitHubBrokerDescriptor(t *testing.T, root string, f *daemonBudgetedGitHubFixture) (path, authority string) {
	t.Helper()
	if err := fileauthority.CheckDirectory(root); err != nil {
		t.Fatalf("unsafe native temporary root: %v", err)
	}
	attempts := filepath.Join(root, "github-attempts")
	if err := os.Mkdir(attempts, 0o700); err != nil {
		t.Fatal(err)
	}
	archiveURL, err := url.Parse(f.archive.URL)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := map[string]any{
		"contract": "open-trestle/github-source-broker", "schema_version": 1,
		"tenant_id": daemonBudgetedTenant, "repository_id": daemonBudgetedRepository, "repository_full_name": "owner/repo", "github_repository_id": 99,
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
	path = filepath.Join(root, "github-broker.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := githubruntime.LoadConfig(context.Background(), path)
	if err != nil || config.Validate() != nil || config.AuthorityIdentity() == "" {
		t.Fatalf("protected GitHub broker config: %v", err)
	}
	return path, config.AuthorityIdentity()
}

func daemonBudgetedGitObject(kind string, content []byte) string {
	value := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(content))), content...)
	digest := sha1.Sum(value)
	return hex.EncodeToString(digest[:])
}

func daemonBudgetedGitTree(mode, name, objectID string) string {
	raw, err := hex.DecodeString(objectID)
	if err != nil {
		panic("invalid synthetic git object ID")
	}
	return daemonBudgetedGitObject("tree", append([]byte(mode+" "+name+"\x00"), raw...))
}

func daemonBudgetedGitArchive(t *testing.T, commit, filePath string, content []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	root := "owner-repo-" + commit + "/"
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
