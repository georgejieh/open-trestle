package github

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

type tokenProvider struct {
	token Token
	err   error
	calls atomic.Int32
}

func (p *tokenProvider) Retrieve(context.Context) (Token, error) {
	p.calls.Add(1)
	return p.token, p.err
}

func testToken(t *testing.T) Token {
	t.Helper()
	token, err := NewToken([]byte("github-token"))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func gitObjectSHA1(kind string, content []byte) string {
	value := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(content))), content...)
	digest := sha1.Sum(value)
	return hex.EncodeToString(digest[:])
}

func gitTreeSHA1(mode, name, objectID string) string {
	rawID, _ := hex.DecodeString(objectID)
	content := append([]byte(mode+" "+name+"\x00"), rawID...)
	return gitObjectSHA1("tree", content)
}

func archiveBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	root := "owner-repo-aaaaaaaa/"
	if err := tarWriter.WriteHeader(&tar.Header{Name: root, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := tarWriter.WriteHeader(&tar.Header{Name: root + name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

type githubFixture struct {
	server          *httptest.Server
	commit          string
	tree            string
	subtree         string
	filePath        string
	fileContent     []byte
	blob            string
	archive         []byte
	truncated       bool
	commitStatus    int
	commitHeaders   http.Header
	archiveStatus   int
	authorizationOK atomic.Bool
	apiVersionOK    atomic.Bool
	archiveNoAuth   atomic.Bool
	calls           atomic.Int32
}

func newGitHubFixture(t *testing.T) *githubFixture {
	t.Helper()
	fixture := &githubFixture{
		commit:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		filePath:      "src/main.go",
		fileContent:   []byte("package main\n"),
		commitStatus:  http.StatusOK,
		archiveStatus: http.StatusOK,
	}
	fixture.blob = gitObjectSHA1("blob", fixture.fileContent)
	fixture.subtree = gitTreeSHA1("100644", "main.go", fixture.blob)
	fixture.tree = gitTreeSHA1("40000", "src", fixture.subtree)
	fixture.archive = archiveBytes(t, map[string][]byte{fixture.filePath: fixture.fileContent})
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	return fixture
}

func (f *githubFixture) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	f.calls.Add(1)
	commitPath := "/repos/owner/repo/git/commits/" + f.commit
	treePath := "/repos/owner/repo/git/trees/" + f.tree
	tarballPath := "/repos/owner/repo/tarball/" + f.commit
	archivePath := "/owner/repo/archive/" + f.commit
	switch request.URL.Path {
	case commitPath:
		for name, values := range f.commitHeaders {
			for _, value := range values {
				writer.Header().Add(name, value)
			}
		}
		f.authorizationOK.Store(request.Header.Get("Authorization") == "Bearer github-token")
		f.apiVersionOK.Store(request.Header.Get("X-GitHub-Api-Version") == defaultAPIVersion)
		if f.commitStatus != http.StatusOK {
			writer.WriteHeader(f.commitStatus)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"sha":  f.commit,
			"tree": map[string]any{"sha": f.tree},
		})
	case treePath:
		if request.URL.Query().Get("recursive") != "1" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"sha":       f.tree,
			"truncated": f.truncated,
			"tree": []any{
				map[string]any{"path": "src", "mode": "040000", "type": "tree", "sha": f.subtree},
				map[string]any{"path": f.filePath, "mode": "100644", "type": "blob", "sha": f.blob, "size": len(f.fileContent)},
			},
		})
	case tarballPath:
		http.Redirect(writer, request, f.server.URL+archivePath, http.StatusFound)
	case archivePath:
		f.archiveNoAuth.Store(request.Header.Get("Authorization") == "")
		writer.WriteHeader(f.archiveStatus)
		if f.archiveStatus == http.StatusOK {
			_, _ = writer.Write(f.archive)
		}
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

func (f *githubFixture) close() { f.server.Close() }

func testAdapter(t *testing.T, fixture *githubFixture, credentials TokenProvider) *Adapter {
	t.Helper()
	parsed, _ := url.Parse(fixture.server.URL)
	adapter, err := New(Config{
		RepositoryAuthority: "github.com",
		APIEndpoint:         fixture.server.URL,
		ArchiveAuthorities:  []string{parsed.Host},
		Credentials:         credentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func testRequest(t *testing.T, adapter *Adapter, artifact evidence.RepositoryAcquisitionArtifact) evidence.RepositoryAcquisitionRequest {
	t.Helper()
	repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	if err != nil {
		t.Fatal(err)
	}
	request, err := evidence.NewRepositoryAcquisitionRequest(repository, revision, adapter.Identity(), artifact, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestAcquireVerifiesTreeArchiveAndBlobContent(t *testing.T) {
	fixture := newGitHubFixture(t)
	defer fixture.close()
	credentials := &tokenProvider{token: testToken(t)}
	adapter := testAdapter(t, fixture, credentials)
	request := testRequest(t, adapter, evidence.AcquisitionArtifactManifestAndContent)

	execution, err := scm.ExecuteRepositoryAcquisitionWithEvidence(context.Background(), request, adapter)
	if err != nil {
		t.Fatal(err)
	}
	receipt := execution.Receipt()
	if receipt.Outcome() != evidence.AcquisitionOutcomeAcquired || receipt.Reason() != evidence.AcquisitionReasonNone || receipt.ContentCoverage() != evidence.ContentCoverageComplete || receipt.ManifestIdentity() == "" {
		t.Fatalf("receipt = %#v", receipt)
	}
	if !fixture.authorizationOK.Load() || !fixture.apiVersionOK.Load() || !fixture.archiveNoAuth.Load() || credentials.calls.Load() != 3 || fixture.calls.Load() != 4 {
		t.Fatalf("headers or calls were wrong: api auth=%v archive no auth=%v credentials=%d requests=%d", fixture.authorizationOK.Load(), fixture.archiveNoAuth.Load(), credentials.calls.Load(), fixture.calls.Load())
	}
	if adapter.Identity().Name() != "open-trestle.github-rest" || adapter.Identity().Version() != "1.0.0" || adapter.Validate() != nil {
		t.Fatalf("adapter identity = %#v", adapter.Identity())
	}
	if fmt.Sprint(adapter) != "GitHub source adapter" || fmt.Sprintf("%#v", adapter) != "github.Adapter{<redacted>}" {
		t.Fatalf("adapter formatting leaked: %v / %#v", adapter, adapter)
	}
}

func TestAcquireManifestModeDiscardsRetainedContent(t *testing.T) {
	fixture := newGitHubFixture(t)
	defer fixture.close()
	adapter := testAdapter(t, fixture, nil)
	request := testRequest(t, adapter, evidence.AcquisitionArtifactManifest)
	result := adapter.Acquire(context.Background(), request)
	if result.Outcome != evidence.AcquisitionOutcomeAcquired || result.Manifest.FileCount() != 1 || result.Manifest.TotalSizeBytes() != int64(len(fixture.fileContent)) || result.Contents != nil {
		t.Fatalf("result = %#v", result)
	}
}

func TestAcquireFailsClosedOnTreeOrContentMismatch(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*githubFixture)
		outcome evidence.RepositoryAcquisitionOutcome
		reason  evidence.RepositoryAcquisitionReason
	}{
		{"truncated", func(f *githubFixture) { f.truncated = true }, evidence.AcquisitionOutcomeFailed, evidence.AcquisitionReasonResourceLimit},
		{"blob mismatch", func(f *githubFixture) { f.blob = strings.Repeat("c", 40) }, evidence.AcquisitionOutcomeFailed, evidence.AcquisitionReasonArtifactIncomplete},
		{"archive missing file", func(f *githubFixture) { f.archive = archiveBytes(t, map[string][]byte{"other.go": []byte("x")}) }, evidence.AcquisitionOutcomeFailed, evidence.AcquisitionReasonArtifactIncomplete},
		{"archive unavailable", func(f *githubFixture) { f.archiveStatus = http.StatusBadGateway }, evidence.AcquisitionOutcomeBlocked, evidence.AcquisitionReasonAdapterUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newGitHubFixture(t)
			defer fixture.close()
			test.mutate(fixture)
			adapter := testAdapter(t, fixture, &tokenProvider{token: testToken(t)})
			result := adapter.Acquire(context.Background(), testRequest(t, adapter, evidence.AcquisitionArtifactManifestAndContent))
			if result.Outcome != test.outcome || result.Reason != test.reason || result.Manifest.Identity() != "" || result.Contents != nil {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func TestAcquireClassifiesAuthorizationAndCredentialFailures(t *testing.T) {
	fixture := newGitHubFixture(t)
	defer fixture.close()
	fixture.commitStatus = http.StatusUnauthorized
	adapter := testAdapter(t, fixture, &tokenProvider{token: testToken(t)})
	result := adapter.Acquire(context.Background(), testRequest(t, adapter, evidence.AcquisitionArtifactManifestAndContent))
	if result.Outcome != evidence.AcquisitionOutcomeBlocked || result.Reason != evidence.AcquisitionReasonAuthorizationRequired {
		t.Fatalf("authorization result = %#v", result)
	}

	rateLimited := newGitHubFixture(t)
	defer rateLimited.close()
	rateLimited.commitStatus = http.StatusForbidden
	rateLimited.commitHeaders = http.Header{"X-RateLimit-Remaining": []string{"0"}}
	adapter = testAdapter(t, rateLimited, &tokenProvider{token: testToken(t)})
	result = adapter.Acquire(context.Background(), testRequest(t, adapter, evidence.AcquisitionArtifactManifestAndContent))
	if result.Outcome != evidence.AcquisitionOutcomeBlocked || result.Reason != evidence.AcquisitionReasonAdapterUnavailable {
		t.Fatalf("rate-limit result = %#v", result)
	}

	fixture2 := newGitHubFixture(t)
	defer fixture2.close()
	adapter = testAdapter(t, fixture2, &tokenProvider{err: errors.New("secret service failed")})
	result = adapter.Acquire(context.Background(), testRequest(t, adapter, evidence.AcquisitionArtifactManifestAndContent))
	if result.Outcome != evidence.AcquisitionOutcomeBlocked || result.Reason != evidence.AcquisitionReasonAuthorizationRequired || fixture2.calls.Load() != 0 {
		t.Fatalf("credential result = %#v, calls = %d", result, fixture2.calls.Load())
	}
}

func TestAcquireRejectsCrossWiredScopeBeforeNetwork(t *testing.T) {
	fixture := newGitHubFixture(t)
	defer fixture.close()
	adapter := testAdapter(t, fixture, nil)
	repository, _ := evidence.NewRepositoryIdentity("git.example.com", []string{"owner"}, "repo")
	revision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	request, _ := evidence.NewRepositoryAcquisitionRequest(repository, revision, adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	result := adapter.Acquire(context.Background(), request)
	if result.Outcome != evidence.AcquisitionOutcomeBlocked || result.Reason != evidence.AcquisitionReasonPolicyBlocked || fixture.calls.Load() != 0 {
		t.Fatalf("result = %#v, calls = %d", result, fixture.calls.Load())
	}
}

func TestAcquireRejectsUnapprovedArchiveRedirect(t *testing.T) {
	fixture := newGitHubFixture(t)
	defer fixture.close()
	evil := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unapproved archive host was called")
	}))
	defer evil.Close()
	original := fixture.server.Config.Handler
	fixture.server.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "/tarball/") {
			http.Redirect(writer, request, evil.URL+"/owner/repo/archive/"+fixture.commit, http.StatusFound)
			return
		}
		original.ServeHTTP(writer, request)
	})
	adapter := testAdapter(t, fixture, nil)
	result := adapter.Acquire(context.Background(), testRequest(t, adapter, evidence.AcquisitionArtifactManifestAndContent))
	if result.Outcome != evidence.AcquisitionOutcomeBlocked || result.Reason != evidence.AcquisitionReasonPolicyBlocked {
		t.Fatalf("result = %#v", result)
	}
}

func TestNewRejectsUnsafeConfigurationAndTokens(t *testing.T) {
	validEndpoint := "https://api.github.com"
	tests := []Config{
		{},
		{RepositoryAuthority: "github.com", APIEndpoint: "http://api.github.com", ArchiveAuthorities: []string{"codeload.github.com"}},
		{RepositoryAuthority: "github.com", APIEndpoint: "https://user@api.github.com", ArchiveAuthorities: []string{"codeload.github.com"}},
		{RepositoryAuthority: "github.com", APIEndpoint: validEndpoint, ArchiveAuthorities: nil},
		{RepositoryAuthority: "github.com", APIEndpoint: validEndpoint, ArchiveAuthorities: []string{"codeload.github.com", "codeload.github.com"}},
		{RepositoryAuthority: "github.com", APIEndpoint: validEndpoint, ArchiveAuthorities: []string{"https://codeload.github.com"}},
		{RepositoryAuthority: "github.com", APIEndpoint: validEndpoint, APIVersion: "latest", ArchiveAuthorities: []string{"codeload.github.com"}},
	}
	for index, config := range tests {
		if adapter, err := New(config); !errors.Is(err, ErrInvalidConfig) || adapter != nil {
			t.Fatalf("config %d = (%#v, %v)", index, adapter, err)
		}
	}
	var nilCredentials *tokenProvider
	if adapter, err := New(Config{
		RepositoryAuthority: "github.com", APIEndpoint: validEndpoint,
		ArchiveAuthorities: []string{"codeload.github.com"}, Credentials: nilCredentials,
	}); !errors.Is(err, ErrInvalidConfig) || adapter != nil {
		t.Fatalf("typed-nil credentials = (%#v, %v)", adapter, err)
	}
	for _, raw := range [][]byte{nil, []byte(" token"), []byte("token\nvalue"), make([]byte, maximumTokenBytes+1)} {
		if token, err := NewToken(raw); !errors.Is(err, ErrInvalidToken) || token.Validate() == nil {
			t.Fatalf("NewToken(%d) = (%#v, %v)", len(raw), token, err)
		}
	}
	token := testToken(t)
	if token.Validate() != nil || fmt.Sprint(token) != "GitHub API token" || fmt.Sprintf("%#v", token) != "github.Token{<redacted>}" {
		t.Fatalf("token formatting leaked: %v / %#v", token, token)
	}
}

var _ scm.SourceAdapter = (*Adapter)(nil)
