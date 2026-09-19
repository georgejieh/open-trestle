//go:build unix

package main

// Source-only PF1 tests. Place in cmd/trestle only after separate admission.
// No substitute executor, inspector, grant, opener, or owner state is used.
import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
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

	githubadapter "github.com/georgejieh/open-trestle/adapters/scm/github"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
	githubruntime "github.com/georgejieh/open-trestle/internal/githubruntime"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

const (
	setupBrokerBoundaryUser         = "synthetic-setup-user-token-unique"
	setupBrokerBoundaryIssued       = "synthetic-issued-installation-token-unique"
	setupBrokerBoundaryService      = "synthetic-setup-service-token-012345678901234567890123456789"
	setupBrokerBoundaryCurrent      = "8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9"
	setupBrokerBoundaryConfirmation = "create GitHub installation token and run integration_permissions_validated"
)

var setupBrokerBoundaryComparisons = []string{
	"OPEN_TRESTLE_GITHUB_API_TOKEN", "OPEN_TRESTLE_SETUP_TOKEN", "OPEN_TRESTLE_API_TOKEN",
	"OPEN_TRESTLE_OBSERVER_TOKEN", "OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET",
}
var setupBrokerBoundaryRSA struct {
	once         sync.Once
	key          *rsa.PrivateKey
	encoded, pin string
	err          error
}

func setupBrokerBoundaryKey(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()
	setupBrokerBoundaryRSA.once.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			setupBrokerBoundaryRSA.err = err
			return
		}
		public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			setupBrokerBoundaryRSA.err = err
			return
		}
		sum := sha256.Sum256(public)
		setupBrokerBoundaryRSA.key = key
		setupBrokerBoundaryRSA.pin = hex.EncodeToString(sum[:])
		setupBrokerBoundaryRSA.encoded = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	})
	if setupBrokerBoundaryRSA.err != nil {
		t.Fatal("synthetic RSA fixture failed")
	}
	return setupBrokerBoundaryRSA.key, setupBrokerBoundaryRSA.encoded, setupBrokerBoundaryRSA.pin
}

type setupBrokerBoundaryClock struct{ at time.Time }

func (c setupBrokerBoundaryClock) Now() time.Time { return c.at }

type setupBrokerBoundaryFixture struct {
	key                                              *rsa.PrivateKey
	encoded, pin                                     string
	issuedToken                                      string
	root, attempts, descriptor, state                string
	configuration                                    githubruntime.Configuration
	server                                           *httptest.Server
	at                                               time.Time
	mu                                               sync.Mutex
	values                                           map[string]string
	reads, events, failures, jwts                    []string
	userGETs, appGETs, posts, keyReads               int
	denyFirstUser                                    bool
	deniedOwnerRecords                               map[string][]byte
	userEntered, userCanceled, userRelease, userDone chan struct{}
	// Only blocks lazy key retrieval AFTER real Open and user visibility.
	keyEntered  chan struct{}
	keyRelease  chan struct{}
	keyOnce     sync.Once
	releaseOnce sync.Once
}

func setupBrokerBoundaryNew(t *testing.T) *setupBrokerBoundaryFixture {
	t.Helper()
	key, encoded, pin := setupBrokerBoundaryKey(t)
	root := filepath.Join(t.TempDir(), "protected")
	if os.Mkdir(root, 0o700) != nil || fileauthority.CheckDirectory(root) != nil {
		t.Fatal("protected native fixture root required")
	}
	attempts := filepath.Join(root, "attempts")
	if os.Mkdir(attempts, 0o700) != nil {
		t.Fatal("protected attempts directory failed")
	}
	for _, path := range []string{root, attempts} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatal("fixture directory is not 0700")
		}
	}
	f := &setupBrokerBoundaryFixture{key: key, encoded: encoded, pin: pin, issuedToken: setupBrokerBoundaryIssued, root: root, attempts: attempts,
		descriptor: filepath.Join(root, "broker.json"), state: filepath.Join(root, "plan.json"),
		at: time.Now().UTC().Truncate(time.Second), values: map[string]string{
			"OPEN_TRESTLE_GITHUB_SETUP_TOKEN":    setupBrokerBoundaryUser,
			"OPEN_TRESTLE_SETUP_TOKEN":           setupBrokerBoundaryService,
			"OPEN_TRESTLE_API_TOKEN":             "synthetic-operator-comparison",
			"OPEN_TRESTLE_OBSERVER_TOKEN":        "synthetic-observer-comparison",
			"OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET": "synthetic-webhook-comparison",
		}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)
	endpoint, err := url.Parse(f.server.URL)
	if err != nil || net.ParseIP(endpoint.Hostname()) == nil || !net.ParseIP(endpoint.Hostname()).IsLoopback() {
		t.Fatal("numeric loopback fixture required")
	}
	f.values["OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG"] = f.descriptor
	f.writeDescriptor(t, strings.Repeat("d", 64), "2026-03-10")
	f.noEffects(t)
	return f
}

func (f *setupBrokerBoundaryFixture) writeDescriptor(t *testing.T, generation, version string) {
	t.Helper()
	u, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal("fixture endpoint invalid")
	}
	wire := map[string]any{
		"contract": "open-trestle/github-source-broker", "schema_version": 1,
		"tenant_id": "tenant-a", "repository_id": "repo-a", "repository_full_name": "owner/repo",
		"github_repository_id": 99, "installation_id": 42, "app_id": 7,
		"repository_authority": "github.com", "api_endpoint": f.server.URL + "/api/v3", "api_version": version,
		"archive_authorities": []string{u.Host}, "app_key_version": "synthetic-key-1", "app_public_key_sha256": f.pin,
		"credential_environment": "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY", "authorization_generation": generation,
		"ownership_mode": "single_host_exclusive", "attempt_state_directory": f.attempts,
		"allow_token_creation": true, "allow_demand_renewal": true,
	}
	if len(wire) != 20 {
		t.Fatal("source descriptor field inventory drift")
	}
	data, err := json.Marshal(wire)
	if err != nil || os.WriteFile(f.descriptor, data, 0o600) != nil {
		t.Fatal("protected descriptor write failed")
	}
	info, err := os.Lstat(f.descriptor)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("descriptor must be 0600")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f.configuration, err = githubruntime.LoadConfig(ctx, f.descriptor)
	if err != nil || f.configuration.Validate() != nil {
		t.Fatal("real protected LoadConfig failed")
	}
}

func (f *setupBrokerBoundaryFixture) getenv(name string) string {
	f.mu.Lock()
	f.reads = append(f.reads, name)
	if name != "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY" {
		value := f.values[name]
		if name == "OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN" {
			f.failures = append(f.failures, "source setup read publication credential")
		}
		f.mu.Unlock()
		return value
	}
	f.keyReads++
	f.events = append(f.events, "key")
	entered, release := f.keyEntered, f.keyRelease
	f.mu.Unlock()
	if entered != nil {
		f.keyOnce.Do(func() { close(entered) })
		<-release
	}
	return f.encoded
}

func (f *setupBrokerBoundaryFixture) setenv(t *testing.T) {
	t.Helper()
	// runSetupWithClock deliberately uses its production os.Getenv path.
	// This path has no injected read observer; no key-read counter is claimed.
	for name, value := range f.values {
		t.Setenv(name, value)
	}
	t.Setenv("OPEN_TRESTLE_GITHUB_API_TOKEN", "")
	t.Setenv("OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY", f.encoded)
	t.Setenv("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN", "synthetic-publication-must-not-be-forwarded")
}

func (f *setupBrokerBoundaryFixture) releaseKey() {
	if f.keyRelease != nil {
		f.releaseOnce.Do(func() { close(f.keyRelease) })
	}
}

func setupBrokerBoundaryJWT(r *http.Request, key *rsa.PublicKey) bool {
	parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
	if len(parts) != 3 {
		return false
	}
	header, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	payload, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	signature, e3 := base64.RawURLEncoding.DecodeString(parts[2])
	var h map[string]any
	var c map[string]json.RawMessage
	if e1 != nil || e2 != nil || e3 != nil || json.Unmarshal(header, &h) != nil ||
		!reflect.DeepEqual(h, map[string]any{"alg": "RS256", "typ": "JWT"}) || json.Unmarshal(payload, &c) != nil || len(c) != 3 {
		return false
	}
	var issuer string
	var issued, expires int64
	if json.Unmarshal(c["iss"], &issuer) != nil || issuer != "7" || json.Unmarshal(c["iat"], &issued) != nil || json.Unmarshal(c["exp"], &expires) != nil {
		return false
	}
	// Production uses SystemBrokerClock. Check the exact lifetime recipe and
	// a bounded real-time window, not an injected setup receipt clock.
	now := time.Now().Unix()
	if expires-issued != 360 || issued > now || issued < now-90 || expires <= now {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], signature) == nil
}

func (f *setupBrokerBoundaryFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reject := func(reason string) {
		f.failures = append(f.failures, reason)
		http.Error(w, "synthetic fixture refusal", 400)
	}
	user := r.Method == "GET" && r.URL.Path == "/api/v3/user/installations"
	if len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") ||
		len(r.Header.Values("X-GitHub-Api-Version")) != 1 || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || r.Header.Get("Accept") != "application/vnd.github+json" {
		reject("authority headers")
		return
	}
	for _, name := range []string{"Cookie", "Proxy-Authorization", "X-Api-Key"} {
		if len(r.Header.Values(name)) != 0 {
			reject("unexpected credential header")
			return
		}
	}
	for name, values := range r.Header {
		for _, value := range values {
			if strings.Contains(value, setupBrokerBoundaryIssued) || strings.Contains(value, "-----BEGIN") || strings.Contains(value, setupBrokerBoundaryService) || strings.Contains(value, "synthetic-operator") || strings.Contains(value, "synthetic-observer") || strings.Contains(value, "synthetic-webhook") || strings.Contains(value, "synthetic-publication") {
				reject("credential separation")
				return
			}
			if strings.Contains(value, setupBrokerBoundaryUser) && !(user && strings.EqualFold(name, "Authorization")) {
				reject("user credential crossed")
				return
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	installation := `{"id":42,"app_id":7,"account":{"login":"owner"},"repository_selection":"selected","permissions":{"metadata":"read","contents":"read","pull_requests":"read"},"events":["pull_request"],"suspended_at":null}`
	if user {
		if r.Header.Get("Authorization") != "Bearer "+setupBrokerBoundaryUser || r.Header.Get("User-Agent") != "open-trestle/setup-permission-inspector" || r.URL.RawQuery != "page=1&per_page=100" {
			reject("user route or credential")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			reject("user GET body")
			return
		}
		if f.userGETs == 0 && (f.keyReads != 0 || f.appGETs != 0 || f.posts != 0) {
			reject("key/issuer effect preceded first user visibility GET")
			return
		}
		f.userGETs++
		f.events = append(f.events, "user")
		if f.userEntered != nil {
			close(f.userEntered)
			f.mu.Unlock()
			select {
			case <-r.Context().Done():
				close(f.userCanceled)
			case <-f.userRelease:
			}
			f.mu.Lock()
			close(f.userDone)
			return
		}
		if f.denyFirstUser && f.userGETs == 1 {
			records, err := setupBrokerBoundaryReadRecords(f.attempts)
			if err != nil || len(records) != 1 || f.appGETs != 0 || f.posts != 0 || f.keyReads != 0 {
				reject("first TUI denial did not precede issuer/key effects with one native owner")
				return
			}
			f.deniedOwnerRecords = records
			w.WriteHeader(403)
			return
		}
		_, _ = io.WriteString(w, `{"total_count":1,"installations":[`+strings.Replace(installation, `,"app_id":7`, "", 1)+`]}`)
		return
	}
	if !setupBrokerBoundaryJWT(r, &f.key.PublicKey) || r.URL.RawQuery != "" || r.Header.Get("User-Agent") != "open-trestle/github-installation-broker" {
		reject("signed App identity")
		return
	}
	f.jwts = append(f.jwts, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v3/app/installations/42":
		if f.userGETs < 1 || f.appGETs != f.posts {
			reject("App GET ordering")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			reject("App GET body")
			return
		}
		f.appGETs++
		f.events = append(f.events, "app")
		_, _ = io.WriteString(w, installation)
	case r.Method == "POST" && r.URL.Path == "/api/v3/app/installations/42/access_tokens":
		if f.appGETs != f.posts+1 || r.Header.Get("Content-Type") != "application/json" {
			reject("POST ordering")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		var got map[string]any
		want := map[string]any{"repository_ids": []any{float64(99)}, "permissions": map[string]any{"contents": "read", "metadata": "read", "pull_requests": "read"}}
		if err != nil || len(body) > 4096 || json.Unmarshal(body, &got) != nil || !reflect.DeepEqual(got, want) {
			reject("POST scope not exact")
			return
		}
		records, err := setupBrokerBoundaryReadRecords(f.attempts)
		if err != nil {
			reject("reservation unreadable")
			return
		}
		lane, err := githubadapter.NewIssuanceAuthority(f.configuration.Authority(), githubadapter.IssuancePurposeSetup)
		if err != nil {
			reject("lane invalid")
			return
		}
		owner, pending := 0, 0
		for _, data := range records {
			var wire map[string]any
			if json.Unmarshal(data, &wire) != nil {
				reject("record malformed")
				return
			}
			if wire["authority_identity"] != lane.Identity() {
				continue
			}
			if wire["contract"] == "open-trestle/github-installation-issuance-owner" {
				owner++
			}
			if wire["state"] == "pending" && wire["sequence"] == float64(1) {
				pending++
			}
		}
		if owner != 1 || pending != 1 {
			reject("POST without exact durable owner/reservation")
			return
		}
		f.posts++
		f.events = append(f.events, "post")
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": f.issuedToken, "expires_at": f.at.Add(time.Hour).Format(time.RFC3339), "repository_selection": "selected", "permissions": want["permissions"], "repositories": []any{map[string]any{"id": 99, "full_name": "owner/repo"}}})
	default:
		reject("unexpected method or route")
	}
}

func setupBrokerBoundaryReadRecords(directory string) (map[string][]byte, error) {
	if fileauthority.CheckDirectory(directory) != nil {
		return nil, errors.New("untrusted fixture records")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) > 12 {
		return nil, errors.New("record inventory failed")
	}
	result := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		file, err := fileauthority.OpenReadOnly(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, errors.New("record read refused")
		}
		info, statErr := file.Stat()
		data, readErr := io.ReadAll(io.LimitReader(file, 4097))
		closeErr := file.Close()
		if statErr != nil || readErr != nil || closeErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || len(data) == 0 || len(data) > 4096 {
			return nil, errors.New("record metadata invalid")
		}
		result[entry.Name()] = data
	}
	return result, nil
}

func (f *setupBrokerBoundaryFixture) records(t *testing.T) map[string][]byte {
	t.Helper()
	records, err := setupBrokerBoundaryReadRecords(f.attempts)
	if err != nil {
		t.Fatal("protected records unreadable")
	}
	for name, data := range records {
		f.redacted(t, append([]byte(name), data...))
	}
	return records
}

func (f *setupBrokerBoundaryFixture) redacted(t *testing.T, data []byte) {
	t.Helper()
	f.mu.Lock()
	secrets := append([]string{setupBrokerBoundaryUser, setupBrokerBoundaryIssued, setupBrokerBoundaryService, f.encoded, "-----BEGIN", "synthetic-operator-comparison", "synthetic-observer-comparison", "synthetic-webhook-comparison", "synthetic-publication"}, f.jwts...)
	f.mu.Unlock()
	for _, secret := range secrets {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatal("raw output or durable record disclosed credential")
		}
	}
}

func (f *setupBrokerBoundaryFixture) noEffects(t *testing.T) {
	t.Helper()
	if len(f.records(t)) != 0 {
		t.Fatal("preadmission created credential owner or records")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keyReads != 0 || f.userGETs != 0 || f.appGETs != 0 || f.posts != 0 || len(f.failures) != 0 {
		t.Fatal("preadmission key or HTTP effect")
	}
}

func (f *setupBrokerBoundaryFixture) effects(t *testing.T, users, issues, keys int) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.userGETs != users || f.appGETs != issues || f.posts != issues || keys >= 0 && f.keyReads != keys || len(f.failures) != 0 {
		t.Fatalf("native effect counts user=%d app=%d post=%d key=%d failures=%v", f.userGETs, f.appGETs, f.posts, f.keyReads, f.failures)
	}
}

func (f *setupBrokerBoundaryFixture) accepted(t *testing.T, total int) {
	t.Helper()
	records := f.records(t)
	if len(records) != total {
		t.Fatal("owner/reservation/completion record count mismatch")
	}
	lane, err := githubadapter.NewIssuanceAuthority(f.configuration.Authority(), githubadapter.IssuancePurposeSetup)
	if err != nil {
		t.Fatal("setup lane derivation failed")
	}
	var pending, accepted map[string]any
	owners := 0
	for _, data := range records {
		var wire map[string]any
		if json.Unmarshal(data, &wire) != nil {
			t.Fatal("record JSON invalid")
		}
		if wire["authority_identity"] != lane.Identity() {
			continue
		}
		if wire["broker_authority_identity"] != f.configuration.AuthorityIdentity() || wire["authorization_generation"] != f.configuration.Authority().Configuration().AuthorizationGeneration || wire["schema_version"] != float64(1) {
			t.Fatal("record authority mismatch")
		}
		switch wire["contract"] {
		case "open-trestle/github-installation-issuance-owner":
			if len(wire) != 5 {
				t.Fatal("owner shape changed")
			}
			owners++
		case "open-trestle/github-installation-issuance-attempt":
			if wire["state"] == "pending" {
				pending = wire
			}
			if wire["state"] == "accepted" {
				accepted = wire
			}
		default:
			t.Fatal("unexpected native record contract")
		}
	}
	if owners != 1 || len(pending) != 9 || len(accepted) != 10 || pending["sequence"] != float64(1) || accepted["sequence"] != float64(1) || pending["attempt_identity"] != accepted["attempt_identity"] || pending["started_at"] != accepted["started_at"] || accepted["expires_at"] != f.at.Add(time.Hour).Format(time.RFC3339) {
		t.Fatal("accepted native attempt wire mismatch")
	}
	identity, ok := accepted["attempt_identity"].(string)
	if !ok || !validAdminDigest(identity) {
		t.Fatal("accepted attempt identity invalid")
	}
}

func (f *setupBrokerBoundaryFixture) host(t *testing.T) setupGitHubPermissionHostConfiguration {
	t.Helper()
	host, err := loadSetupGitHubPermissionHostConfiguration(context.Background(), f.descriptor, f.configuration.AuthorityIdentity(), "")
	if err != nil || host.Validate() != nil || !host.configured || host.broker.AuthorityIdentity() != f.configuration.AuthorityIdentity() {
		t.Fatal("captured host configuration failed")
	}
	return host
}

func (f *setupBrokerBoundaryFixture) permission(t *testing.T) string {
	t.Helper()
	identity, err := githubadapter.BrokeredPermissionAuthorityIdentity(f.configuration.Authority(), setupGitHubPermissionUserCredentialIdentity(), 30*time.Second)
	if err != nil {
		t.Fatal("pure native permission identity failed")
	}
	return identity
}

func (f *setupBrokerBoundaryFixture) initialize(t *testing.T, current bool, tenant, repository string) setupcore.Plan {
	t.Helper()
	var plan setupcore.Plan
	var err error
	if current {
		plan, err = setupcore.NewCurrentPlan(setupcore.ProfileControlledHybrid, tenant, repository, "owner", f.at)
	} else {
		plan, err = setupcore.NewPlan(setupcore.ProfileControlledHybrid, tenant, repository, "owner", f.at)
	}
	if err != nil {
		t.Fatal("plan fixture construction failed")
	}
	store, err := setupcore.OpenStateFile(f.state)
	if err != nil {
		t.Fatal("protected state open failed")
	}
	initErr := store.Initialize(context.Background(), plan)
	closeErr := store.Close()
	if initErr != nil || closeErr != nil {
		t.Fatal("protected state initialization failed")
	}
	return plan
}

func (f *setupBrokerBoundaryFixture) current(t *testing.T) setupcore.Plan {
	t.Helper()
	plan, err := setupcore.InspectStateFile(context.Background(), f.state)
	if err != nil || plan.Validate() != nil {
		t.Fatal("protected current plan read failed")
	}
	return plan
}

func setupBrokerBoundaryReceipt(t *testing.T, receipt setupcore.CheckReceipt, previous setupcore.Plan, want setupcore.CheckState) {
	t.Helper()
	if receipt.Validate() != nil || receipt.Key() != setupcore.CheckIntegrationPermissionsValidated || receipt.State() != want || receipt.CheckerIdentity() != setupBrokerBoundaryCurrent || receipt.PlanIdentity() != previous.Identity() || !validAdminDigest(receipt.EvidenceIdentity()) {
		t.Fatal("receipt is not exact CURRENT plan/checker authority")
	}
}

func (f *setupBrokerBoundaryFixture) cliArgs(t *testing.T) []string {
	t.Helper()
	return []string{"check", "integration", "--state", f.state, "--approve-integration-permission-authority-identity", f.permission(t), "--approve-github-source-broker-authority-identity", f.configuration.AuthorityIdentity(), "--allow-github-installation-token-creation", "--approved-by", "owner"}
}

func setupBrokerBoundaryReplace(args []string, flag, value string) []string {
	result := append([]string(nil), args...)
	for i := range result {
		if result[i] == flag && i+1 < len(result) {
			result[i+1] = value
			return result
		}
	}
	panic("fixture flag missing")
}

// This is an independent wire encoder, not the setuphttp builder seam.
func (f *setupBrokerBoundaryFixture) body(t *testing.T, plan setupcore.Plan) []byte {
	t.Helper()
	wire := struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		PlanIdentity  string `json:"plan_identity"`
		Key           string `json:"key"`
		Confirmation  string `json:"confirmation"`
		Permission    string `json:"approve_integration_permission_authority_identity"`
		Common        string `json:"approve_github_source_broker_authority_identity"`
		Consent       bool   `json:"allow_github_installation_token_creation"`
		Actor         string `json:"approved_by"`
	}{"open-trestle/setup-check-request", 2, plan.Identity(), "integration_permissions_validated", setupBrokerBoundaryConfirmation, f.permission(t), f.configuration.AuthorityIdentity(), true, "owner"}
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatal("request fixture encoding failed")
	}
	var shape map[string]json.RawMessage
	if json.Unmarshal(data, &shape) != nil || len(shape) != 9 {
		t.Fatal("v2 request not exact nine-key shape")
	}
	return data
}

func (f *setupBrokerBoundaryFixture) request(t *testing.T, h http.Handler, ctx context.Context, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "http://127.0.0.1:8742/api/v1/setup/check", bytes.NewReader(body)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+setupBrokerBoundaryService)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	f.redacted(t, w.Body.Bytes())
	return w
}

func TestSetupBrokerBoundaryCLIProductionReceiptAndExplicitRestart(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	f.setenv(t)
	var stdout, stderr bytes.Buffer
	if code := runSetupWithClock([]string{"init", "--profile", "controlled_hybrid", "--tenant", "tenant-a", "--repository", "repo-a", "--recovery-owner", "owner", "--state", f.state}, &stdout, &stderr, setupBrokerBoundaryClock{f.at}); code != 0 {
		t.Fatal("actual CLI init failed")
	}
	initial := f.current(t)
	found := false
	for _, a := range initial.CheckerAuthorities() {
		if a.Key == setupcore.CheckIntegrationPermissionsValidated {
			found = a.CheckerIdentity == setupBrokerBoundaryCurrent
		}
	}
	if !found {
		t.Fatal("actual CLI init did not use current catalog")
	}
	f.noEffects(t)
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClock(f.cliArgs(t), &stdout, &stderr, setupBrokerBoundaryClock{f.at.Add(time.Second)}); code != 0 || stderr.Len() != 0 {
		t.Fatal("actual CLI native integration failed")
	}
	receipt, err := setupcore.DecodeCheckReceipt(bytes.TrimSpace(stdout.Bytes()))
	if err != nil {
		t.Fatal("CLI did not emit receipt wire")
	}
	setupBrokerBoundaryReceipt(t, receipt, initial, setupcore.CheckPassed)
	f.redacted(t, stdout.Bytes())
	f.redacted(t, stderr.Bytes())
	f.effects(t, 1, 1, -1)
	f.accepted(t, 3)
	first := f.current(t)
	if len(first.Receipts()) != 1 || first.Receipts()[0].Identity() != receipt.Identity() {
		t.Fatal("stdout receipt was not persisted")
	}
	records := f.records(t)
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClock(f.cliArgs(t), &stdout, &stderr, setupBrokerBoundaryClock{f.at.Add(2 * time.Second)}); code == 0 {
		t.Fatal("standalone same generation silently reconstructed owner")
	}
	f.effects(t, 1, 1, -1)
	if !reflect.DeepEqual(records, f.records(t)) {
		t.Fatal("fenced standalone changed owner records")
	}
	for _, r := range f.current(t).Receipts() {
		if r.PlanIdentity() == first.Identity() && r.State() == setupcore.CheckPassed {
			t.Fatal("same-generation restart wrote passing receipt")
		}
	}
	// This is an explicit operator-supplied descriptor edit, not auto-retry.
	oldCommon, oldPermission := f.configuration.AuthorityIdentity(), f.permission(t)
	f.writeDescriptor(t, strings.Repeat("e", 64), "2026-03-10")
	if oldCommon == f.configuration.AuthorityIdentity() || oldPermission == f.permission(t) {
		t.Fatal("generation failed to change approval identities")
	}
	before := f.current(t)
	stdout.Reset()
	stderr.Reset()
	if code := runSetupWithClock(f.cliArgs(t), &stdout, &stderr, setupBrokerBoundaryClock{f.at.Add(3 * time.Second)}); code != 0 || stderr.Len() != 0 {
		t.Fatal("explicit new generation and new approvals did not succeed")
	}
	receipt, err = setupcore.DecodeCheckReceipt(bytes.TrimSpace(stdout.Bytes()))
	if err != nil {
		t.Fatal("new generation receipt missing")
	}
	setupBrokerBoundaryReceipt(t, receipt, before, setupcore.CheckPassed)
	f.effects(t, 2, 2, -1)
	f.accepted(t, 6)
	f.redacted(t, stdout.Bytes())
}

func TestSetupBrokerBoundaryCLIPreadmission(t *testing.T) {
	for _, name := range []string{"common", "permission", "actor", "scope", "historical", "missing-consent", "false-consent", "mixed-static", "legacy-endpoint-empty", "legacy-version-empty", "legacy-installation-zero", "legacy-repository-empty", "old-api-year"} {
		t.Run(name, func(t *testing.T) {
			f := setupBrokerBoundaryNew(t)
			tenant := "tenant-a"
			if name == "scope" {
				tenant = "tenant-b"
			}
			f.initialize(t, name != "historical", tenant, "repo-a")
			f.setenv(t)
			args := f.cliArgs(t)
			if name == "old-api-year" {
				f.writeDescriptor(t, strings.Repeat("d", 64), "1999-03-10")
				args = setupBrokerBoundaryReplace(args, "--approve-github-source-broker-authority-identity", f.configuration.AuthorityIdentity())
			}
			switch name {
			case "common":
				args = setupBrokerBoundaryReplace(args, "--approve-github-source-broker-authority-identity", strings.Repeat("a", 64))
			case "permission":
				args = setupBrokerBoundaryReplace(args, "--approve-integration-permission-authority-identity", strings.Repeat("a", 64))
			case "actor":
				args = setupBrokerBoundaryReplace(args, "--approved-by", "other-owner")
			case "missing-consent":
				for i, s := range args {
					if s == "--allow-github-installation-token-creation" {
						args = append(args[:i], args[i+1:]...)
						break
					}
				}
			case "false-consent":
				for i, s := range args {
					if s == "--allow-github-installation-token-creation" {
						args[i] += "=false"
					}
				}
			case "mixed-static":
				t.Setenv("OPEN_TRESTLE_GITHUB_API_TOKEN", "synthetic-static-token")
			case "legacy-endpoint-empty":
				args = append(args, "--github-api-endpoint=")
			case "legacy-version-empty":
				args = append(args, "--github-api-version=")
			case "legacy-installation-zero":
				args = append(args, "--github-installation-id=0")
			case "legacy-repository-empty":
				args = append(args, "--github-repository-full-name=")
			}
			var stdout, stderr bytes.Buffer
			if code := runSetupWithClock(args, &stdout, &stderr, setupBrokerBoundaryClock{f.at.Add(time.Second)}); code == 0 {
				t.Fatal("unapproved CLI setup succeeded")
			}
			f.noEffects(t)
			f.redacted(t, stdout.Bytes())
			f.redacted(t, stderr.Bytes())
			for _, r := range f.current(t).Receipts() {
				if r.State() == setupcore.CheckPassed {
					t.Fatal("unapproved CLI wrote passing receipt")
				}
			}
		})
	}
}

func TestSetupBrokerBoundaryTUIActualTypedChecksShareOwner(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	initial := f.initialize(t, true, "tenant-a", "repo-a")
	// TUI does not rerun a passing requirement. First native visibility denial
	// yields a blocked receipt; a second typed approval succeeds with SAME owner.
	f.denyFirstUser = true
	var input strings.Builder
	selected, target := -1, -1
	for i, r := range initial.Requirements() {
		if selected < 0 && r.State() != setupcore.CheckPassed {
			selected = i
		}
		if r.Key() == setupcore.CheckIntegrationPermissionsValidated {
			target = i
		}
	}
	if selected < 0 || target < 0 {
		t.Fatal("integration requirement absent")
	}
	for selected < target {
		input.WriteString("j\n")
		selected++
	}
	for selected > target {
		input.WriteString("k\n")
		selected--
	}
	input.WriteString("x\nrun integration_permissions_validated\nx\nrun integration_permissions_validated\nq\n")
	args := []string{"--state", f.state, "--plain", "--approve-integration-permission-authority-identity", f.permission(t), "--approve-github-source-broker-authority-identity", f.configuration.AuthorityIdentity(), "--allow-github-installation-token-creation", "--integration-approved-by", "owner"}
	var stdout, stderr bytes.Buffer
	if code := runSetupTUIWithClock(args, strings.NewReader(input.String()), &stdout, &stderr, setupBrokerBoundaryClock{f.at.Add(time.Second)}, f.getenv); code != 0 || stderr.Len() != 0 {
		t.Fatal("actual typed TUI command failed")
	}
	final := f.current(t)
	if len(final.Receipts()) != 2 || final.Receipts()[0].State() != setupcore.CheckBlocked || final.Receipts()[1].State() != setupcore.CheckPassed {
		t.Fatal("typed TUI did not produce blocked then passing native receipts")
	}
	for _, r := range final.Receipts() {
		if r.CheckerIdentity() != setupBrokerBoundaryCurrent {
			t.Fatal("TUI receipt is historical")
		}
	}
	f.effects(t, 2, 1, 1)
	f.accepted(t, 3)
	f.mu.Lock()
	deniedOwners := f.deniedOwnerRecords
	f.mu.Unlock()
	if len(deniedOwners) != 1 {
		t.Fatal("first native TUI visibility denial not observed")
	}
	records := f.records(t)
	for name, data := range deniedOwners {
		if !bytes.Equal(records[name], data) {
			t.Fatal("second typed TUI check replaced original native owner")
		}
	}
	f.redacted(t, stdout.Bytes())
	f.redacted(t, stderr.Bytes())
	if !strings.Contains(stdout.String(), "Check completed: passed.") {
		t.Fatal("TUI did not render native completion")
	}
}

func TestSetupBrokerBoundaryTUIOnceDoesNotCaptureBrokerCredentials(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	f.initialize(t, true, "tenant-a", "repo-a")
	var stdout, stderr bytes.Buffer
	if code := runSetupTUIWithClock([]string{"--state", f.state, "--once", "--plain"}, strings.NewReader("run integration_permissions_validated\n"), &stdout, &stderr, setupBrokerBoundaryClock{f.at}, f.getenv); code != 0 {
		t.Fatal("read-only TUI failed")
	}
	f.noEffects(t)
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, name := range f.reads {
		if name == "OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG" || name == "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY" || name == "OPEN_TRESTLE_GITHUB_SETUP_TOKEN" {
			t.Fatal("once initialized broker mode")
		}
		for _, comparison := range setupBrokerBoundaryComparisons {
			if name == comparison {
				t.Fatal("once read comparison credential")
			}
		}
	}
}

func TestSetupBrokerBoundaryOwnedWebCompletedRequestCancellationKeepsCache(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	initial := f.initialize(t, true, "tenant-a", "repo-a")
	owner, cancelOwner := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelOwner()
	h, err := newSetupWebHandler(owner, f.state, setupBrokerBoundaryService, f.getenv, setupBrokerBoundaryClock{f.at.Add(time.Second)}, "127.0.0.1:8742", f.host(t))
	if err != nil || h == nil {
		t.Fatal("real owned handler construction failed")
	}
	defer func() {
		if h.Close() != nil {
			t.Error("owned web cleanup failed")
		}
	}()
	f.noEffects(t)
	caller, cancel := context.WithCancel(owner)
	w := f.request(t, h, caller, f.body(t, initial))
	cancel()
	if w.Code != 200 {
		t.Fatal("first real web builder native check failed")
	}
	first := f.current(t)
	if len(first.Receipts()) != 1 {
		t.Fatal("first web receipt missing")
	}
	setupBrokerBoundaryReceipt(t, first.Receipts()[0], initial, setupcore.CheckPassed)
	f.accepted(t, 3)
	records := f.records(t)
	w = f.request(t, h, owner, f.body(t, first))
	if w.Code != 200 {
		t.Fatal("completed request cancellation poisoned owner lifetime")
	}
	second := f.current(t)
	if len(second.Receipts()) != 2 {
		t.Fatal("second web receipt missing")
	}
	setupBrokerBoundaryReceipt(t, second.Receipts()[1], first, setupcore.CheckPassed)
	f.effects(t, 2, 1, 1)
	if !reflect.DeepEqual(records, f.records(t)) {
		t.Fatal("web cache hit created a second owner or issuance")
	}
	if err = h.Close(); err != nil {
		t.Fatal("web Close failed")
	}
	if !reflect.DeepEqual(records, f.records(t)) {
		t.Fatal("web Close removed retained marker")
	}
	w = f.request(t, h, owner, f.body(t, second))
	if w.Code != 503 || strings.Contains(w.Body.String(), second.Identity()) || strings.Contains(w.Body.String(), "setup-check-result") || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("closed handler did not refuse content-free with safe headers")
	}
	f.effects(t, 2, 1, 1)
}

func TestSetupBrokerBoundaryOwnedWebGatesBeforeOwner(t *testing.T) {
	for _, name := range []string{"common", "permission", "actor", "scope", "stale", "historical", "missing-consent", "legacy-v1-before-state", "v2-extra-before-state", "canceled"} {
		t.Run(name, func(t *testing.T) {
			f := setupBrokerBoundaryNew(t)
			tenant := "tenant-a"
			if name == "scope" {
				tenant = "other-tenant"
			}
			plan := f.initialize(t, name != "historical", tenant, "repo-a")
			state := f.state
			if strings.Contains(name, "before-state") {
				state = filepath.Join(f.root, "absent-parent", "plan.json")
			}
			owner, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			h, err := newSetupWebHandler(owner, state, setupBrokerBoundaryService, f.getenv, setupBrokerBoundaryClock{f.at.Add(time.Second)}, "127.0.0.1:8742", f.host(t))
			if err != nil {
				t.Fatal("real web handler construction failed")
			}
			defer func() {
				if h.Close() != nil {
					t.Error("web cleanup failed")
				}
			}()
			body := f.body(t, plan)
			var wire map[string]any
			if json.Unmarshal(body, &wire) != nil {
				t.Fatal("fixture wire invalid")
			}
			caller, cancelCaller := context.WithCancel(owner)
			defer cancelCaller()
			want := 422
			errorCode := "check_unavailable"
			switch name {
			case "common":
				wire["approve_github_source_broker_authority_identity"] = strings.Repeat("a", 64)
			case "permission":
				wire["approve_integration_permission_authority_identity"] = strings.Repeat("a", 64)
				want = 200
				errorCode = ""
			case "actor":
				wire["approved_by"] = "other-owner"
				want = 200
				errorCode = ""
			case "stale":
				wire["plan_identity"] = strings.Repeat("a", 64)
				want = 409
				errorCode = "stale_plan"
			case "historical":
				errorCode = "check_failed"
			case "missing-consent":
				delete(wire, "allow_github_installation_token_creation")
				want = 400
				errorCode = "invalid_request"
			case "v2-extra-before-state":
				wire["github_api_endpoint"] = ""
				want = 400
				errorCode = "invalid_request"
			case "legacy-v1-before-state":
				delete(wire, "approve_github_source_broker_authority_identity")
				delete(wire, "allow_github_installation_token_creation")
				wire["schema_version"] = 1
				wire["confirmation"] = "run integration_permissions_validated"
				wire["github_api_endpoint"] = f.server.URL + "/api/v3"
				wire["github_api_version"] = "2026-03-10"
				wire["github_installation_id"] = 42
				wire["github_repository_full_name"] = "owner/repo"
			case "canceled":
				cancelCaller()
				want = 409
				errorCode = "state_conflict"
			}
			body, err = json.Marshal(wire)
			if err != nil {
				t.Fatal("fixture encoding failed")
			}
			w := f.request(t, h, caller, body)
			if w.Code != want || errorCode != "" && !strings.Contains(w.Body.String(), `"code":"`+errorCode+`"`) {
				t.Fatalf("web gate %s status=%d", name, w.Code)
			}
			f.noEffects(t)
			if name == "permission" || name == "actor" {
				receipts := f.current(t).Receipts()
				if len(receipts) != 1 {
					t.Fatal("blocked approval receipt missing")
				}
				setupBrokerBoundaryReceipt(t, receipts[0], plan, setupcore.CheckBlocked)
			}
			if strings.Contains(name, "before-state") {
				if _, err := os.Lstat(filepath.Dir(state)); !os.IsNotExist(err) {
					t.Fatal("wire refusal touched absent state parent")
				}
			}
		})
	}
}

func TestSetupBrokerBoundaryOwnedWebHostAndBearerBeforeBodyAndState(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	state := filepath.Join(f.root, "absent-parent", "plan.json")
	owner, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h, err := newSetupWebHandler(owner, state, setupBrokerBoundaryService, f.getenv, setupBrokerBoundaryClock{f.at}, "127.0.0.1:8742", f.host(t))
	if err != nil {
		t.Fatal("owned handler construction failed")
	}
	defer func() {
		if h.Close() != nil {
			t.Error("web cleanup failed")
		}
	}()
	for _, name := range []string{"host", "bearer"} {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8742/api/v1/setup/check", strings.NewReader("not-json"))
		r.Header.Set("Content-Type", "text/plain")
		want := 401
		if name == "host" {
			r.Host = "localhost:8742"
			r.Header.Set("Authorization", "Bearer "+setupBrokerBoundaryService)
			want = 421
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatal("actual outer Host/bearer fence ran after body/state")
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("refusal lost safe headers")
		}
		f.redacted(t, w.Body.Bytes())
		f.noEffects(t)
	}
	if _, err := os.Lstat(filepath.Dir(state)); !os.IsNotExist(err) {
		t.Fatal("outer fence touched nonexistent state parent")
	}
}

type setupBrokerBoundaryListener struct {
	net.Listener
	closed chan struct{}
	once   sync.Once
}

func (l *setupBrokerBoundaryListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}

type setupBrokerBoundaryWriter struct {
	ready chan struct{}
	once  sync.Once
	fail  bool
	bytes.Buffer
}

func (w *setupBrokerBoundaryWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.ready) })
	if w.fail {
		return 0, errors.New("synthetic output failure")
	}
	return w.Buffer.Write(p)
}

func TestSetupBrokerBoundaryRunWebStartupFailureOwnership(t *testing.T) {
	for _, name := range []string{"wrong-common-before-listen", "missing-common-before-listen", "static-before-listen", "listen-failure", "output-failure"} {
		t.Run(name, func(t *testing.T) {
			f := setupBrokerBoundaryNew(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			address := "127.0.0.1:8742"
			var listener *setupBrokerBoundaryListener
			if name == "output-failure" {
				base, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal("synthetic listener allocation failed")
				}
				listener = &setupBrokerBoundaryListener{Listener: base, closed: make(chan struct{})}
				defer listener.Close()
				address = listener.Addr().String()
			}
			args := []string{"--state", f.state, "--listen", address, "--approve-github-source-broker-authority-identity", f.configuration.AuthorityIdentity()}
			if name == "wrong-common-before-listen" {
				args = setupBrokerBoundaryReplace(args, "--approve-github-source-broker-authority-identity", strings.Repeat("a", 64))
			}
			if name == "missing-common-before-listen" {
				args = args[:4]
			}
			if name == "static-before-listen" {
				f.values["OPEN_TRESTLE_GITHUB_API_TOKEN"] = "synthetic-static-conflict"
			}
			calls := 0
			listen := func(network, got string) (net.Listener, error) {
				calls++
				if network != "tcp" || got != address {
					return nil, errors.New("synthetic listener authority mismatch")
				}
				if listener != nil {
					return listener, nil
				}
				return nil, errors.New("synthetic listen failure")
			}
			stdout := &setupBrokerBoundaryWriter{ready: make(chan struct{}), fail: name == "output-failure"}
			var stderr bytes.Buffer
			code := runSetupWebWithListener(ctx, args, f.getenv, stdout, &stderr, listen)
			wantCalls, wantCode := 0, 2
			if name == "listen-failure" || name == "output-failure" {
				wantCalls = 1
				wantCode = 1
			}
			if code != wantCode || calls != wantCalls {
				t.Fatal("actual runSetupWeb startup/failure ownership gate mismatch")
			}
			if listener != nil {
				setupBrokerBoundaryWait(t, listener.closed, "output failure listener cleanup")
			}
			f.noEffects(t)
			f.redacted(t, stdout.Bytes())
			f.redacted(t, stderr.Bytes())
		})
	}
}

func TestSetupBrokerBoundaryRunWebShutdownCancelsNativeAdmission(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	plan := f.initialize(t, true, "tenant-a", "repo-a")
	f.userEntered = make(chan struct{})
	f.userCanceled = make(chan struct{})
	f.userRelease = make(chan struct{})
	f.userDone = make(chan struct{})
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("native synthetic listener allocation failed")
	}
	listener := &setupBrokerBoundaryListener{Listener: base, closed: make(chan struct{})}
	address := listener.Addr().String()
	owner, cancelOwner := context.WithTimeout(context.Background(), 25*time.Second)
	caller, cancelCaller := context.WithTimeout(context.Background(), 20*time.Second)
	stdout := &setupBrokerBoundaryWriter{ready: make(chan struct{})}
	var stderr bytes.Buffer
	runDone := make(chan struct{})
	requestDone := make(chan struct{})
	var runCode int
	var responseCode int
	var responseBody []byte
	var requestErr error
	requestStarted := false
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	defer func() {
		close(f.userRelease)
		cancelCaller()
		cancelOwner()
		_ = listener.Close()
		transport.CloseIdleConnections()
		if requestStarted {
			setupBrokerBoundaryWait(t, requestDone, "web native request cleanup")
		}
		setupBrokerBoundaryWait(t, runDone, "actual web run cleanup")
		select {
		case <-f.userEntered:
			setupBrokerBoundaryWait(t, f.userDone, "native user HTTP handler cleanup")
		default:
		}
	}()
	args := []string{"--state", f.state, "--listen", address, "--approve-github-source-broker-authority-identity", f.configuration.AuthorityIdentity()}
	go func() {
		defer close(runDone)
		runCode = runSetupWebWithListener(owner, args, f.getenv, stdout, &stderr, func(network, got string) (net.Listener, error) {
			if network != "tcp" || got != address {
				return nil, errors.New("synthetic listen authority mismatch")
			}
			return listener, nil
		})
	}()
	setupBrokerBoundaryWait(t, stdout.ready, "actual web startup output")
	body := f.body(t, plan)
	request, err := http.NewRequestWithContext(caller, "POST", "http://"+address+"/api/v1/setup/check", bytes.NewReader(body))
	if err != nil {
		t.Fatal("synthetic HTTP request failed")
	}
	request.Header.Set("Authorization", "Bearer "+setupBrokerBoundaryService)
	request.Header.Set("Content-Type", "application/json")
	requestStarted = true
	go func() {
		defer close(requestDone)
		response, err := client.Do(request)
		if err != nil {
			requestErr = err
			return
		}
		responseCode = response.StatusCode
		responseBody, requestErr = io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err := response.Body.Close(); requestErr == nil {
			requestErr = err
		}
	}()
	setupBrokerBoundaryWait(t, f.userEntered, "actual web native Inspect entered user visibility GET")
	ownerRecords := f.records(t)
	if len(ownerRecords) != 1 {
		t.Fatal("real web request did not create native owner before user visibility")
	}
	f.effects(t, 1, 0, 0)
	cancelOwner()
	// Native user GET remains blocked until its REAL request context cancels.
	// If owned cancellation waits until after HTTP Shutdown, the command must
	// exhaust HTTP drain/force-close and return failure. Graceful code 0 below
	// therefore tests cancellation ordering without a scheduler-delay oracle.
	setupBrokerBoundaryWait(t, listener.closed, "shutdown initiation")
	setupBrokerBoundaryWait(t, f.userCanceled, "native user request owner cancellation")
	setupBrokerBoundaryWait(t, requestDone, "canceled native web response")
	setupBrokerBoundaryWait(t, runDone, "owned web shutdown completion")
	if runCode != 0 || requestErr != nil || responseCode != 200 {
		t.Fatal("bounded actual web shutdown failed")
	}
	f.redacted(t, responseBody)
	f.redacted(t, stdout.Bytes())
	f.redacted(t, stderr.Bytes())
	// The response Plan also contains passed deterministic requirements. Check
	// the exact integration receipt, not an unrelated state anywhere in JSON.
	var response struct {
		Contract      string          `json:"contract"`
		SchemaVersion int             `json:"schema_version"`
		Plan          json.RawMessage `json:"plan"`
		Receipt       json.RawMessage `json:"receipt"`
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || decoder.Decode(&struct{}{}) != io.EOF || response.Contract != "open-trestle/setup-check-result" || response.SchemaVersion != 1 {
		t.Fatal("shutdown returned an invalid check result")
	}
	responsePlan, planErr := setupcore.DecodePlan(response.Plan)
	responseReceipt, receiptErr := setupcore.DecodeCheckReceipt(response.Receipt)
	if planErr != nil || receiptErr != nil {
		t.Fatal("shutdown returned invalid plan or receipt bytes")
	}
	setupBrokerBoundaryReceipt(t, responseReceipt, plan, setupcore.CheckUnavailable)
	final := f.current(t)
	if len(final.Receipts()) != 1 {
		t.Fatal("native canceled request result receipt missing")
	}
	setupBrokerBoundaryReceipt(t, final.Receipts()[0], plan, setupcore.CheckUnavailable)
	if responsePlan.Identity() != final.Identity() || responseReceipt.Identity() != final.Receipts()[0].Identity() {
		t.Fatal("shutdown response does not match persisted unavailable result")
	}
	f.effects(t, 1, 0, 0)
	if !reflect.DeepEqual(ownerRecords, f.records(t)) {
		t.Fatal("shutdown changed retained owner or issued after cancellation")
	}
}

func setupBrokerBoundaryTypedIntegration(t *testing.T, plan setupcore.Plan) string {
	t.Helper()
	selected, target := -1, -1
	for i, r := range plan.Requirements() {
		if selected < 0 && r.State() != setupcore.CheckPassed {
			selected = i
		}
		if r.Key() == setupcore.CheckIntegrationPermissionsValidated {
			target = i
		}
	}
	if selected < 0 || target < 0 {
		t.Fatal("typed fixture requires pending integration")
	}
	var input strings.Builder
	for selected < target {
		input.WriteString("j\n")
		selected++
	}
	for selected > target {
		input.WriteString("k\n")
		selected--
	}
	input.WriteString("x\nrun integration_permissions_validated\nq\n")
	return input.String()
}

func TestSetupBrokerBoundaryTUITypedPreadmission(t *testing.T) {
	for _, name := range []string{"missing-consent", "legacy-empty-presence", "wrong-actor", "wrong-common"} {
		t.Run(name, func(t *testing.T) {
			f := setupBrokerBoundaryNew(t)
			plan := f.initialize(t, true, "tenant-a", "repo-a")
			args := []string{"--state", f.state, "--plain", "--approve-integration-permission-authority-identity", f.permission(t), "--approve-github-source-broker-authority-identity", f.configuration.AuthorityIdentity(), "--integration-approved-by", "owner"}
			if name != "missing-consent" {
				args = append(args, "--allow-github-installation-token-creation")
			}
			if name == "legacy-empty-presence" {
				args = append(args, "--github-api-endpoint=")
			}
			if name == "wrong-actor" {
				args = setupBrokerBoundaryReplace(args, "--integration-approved-by", "other-owner")
			}
			if name == "wrong-common" {
				args = setupBrokerBoundaryReplace(args, "--approve-github-source-broker-authority-identity", strings.Repeat("a", 64))
			}
			var stdout, stderr bytes.Buffer
			code := runSetupTUIWithClock(args, strings.NewReader(setupBrokerBoundaryTypedIntegration(t, plan)), &stdout, &stderr, setupBrokerBoundaryClock{f.at.Add(time.Second)}, f.getenv)
			if name == "wrong-actor" {
				if code != 0 {
					t.Fatal("valid typed TUI with unapproved actor did not render blocked result")
				}
				receipts := f.current(t).Receipts()
				if len(receipts) != 1 {
					t.Fatal("typed actor refusal receipt missing")
				}
				setupBrokerBoundaryReceipt(t, receipts[0], plan, setupcore.CheckBlocked)
			} else if code == 0 {
				t.Fatal("invalid TUI startup shape admitted command")
			}
			f.noEffects(t)
			f.redacted(t, stdout.Bytes())
			f.redacted(t, stderr.Bytes())
		})
	}
}

func TestSetupBrokerBoundaryWebRejectsUserEqualToActualNativeGrant(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	plan := f.initialize(t, true, "tenant-a", "repo-a")
	f.issuedToken = setupBrokerBoundaryUser
	owner, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	h, err := newSetupWebHandler(owner, f.state, setupBrokerBoundaryService, f.getenv, setupBrokerBoundaryClock{f.at.Add(time.Second)}, "127.0.0.1:8742", f.host(t))
	if err != nil {
		t.Fatal("owned handler construction failed")
	}
	defer func() {
		if h.Close() != nil {
			t.Error("owned handler cleanup failed")
		}
	}()
	w := f.request(t, h, owner, f.body(t, plan))
	if w.Code != 200 {
		t.Fatal("native equality failure lost closed receipt response")
	}
	receipts := f.current(t).Receipts()
	if len(receipts) != 1 {
		t.Fatal("actual grant equality refusal receipt missing")
	}
	setupBrokerBoundaryReceipt(t, receipts[0], plan, setupcore.CheckBlocked)
	// The issuer DID accept an explicitly requested token. User equality is a
	// later native observation refusal, not a no-effect preadmission claim.
	f.effects(t, 1, 1, 1)
	f.accepted(t, 3)
}
