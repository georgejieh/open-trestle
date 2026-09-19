//go:build unix

package githubruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	github "github.com/georgejieh/open-trestle/adapters/scm/github"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

type admissionBoundaryClock struct{ at time.Time }

func (c admissionBoundaryClock) Now() time.Time { return c.at }

type admissionBoundaryEffects struct {
	mu             sync.Mutex
	keys, requests int
}

func (e *admissionBoundaryEffects) getenv(string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.keys++
	return "fixture-admission-private-key-must-not-be-loaded"
}

func (e *admissionBoundaryEffects) assertInert(t *testing.T) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.keys != 0 || e.requests != 0 {
		t.Fatal("configuration admission read a key or performed HTTP")
	}
}

type admissionBoundaryFixture struct {
	root, path, attempts string
	descriptor           map[string]any
	effects              *admissionBoundaryEffects
}

func admissionBoundaryNewFixture(t *testing.T) *admissionBoundaryFixture {
	t.Helper()
	effects := &admissionBoundaryEffects{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		effects.mu.Lock()
		effects.requests++
		effects.mu.Unlock()
		http.Error(w, "unexpected configuration admission request", http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	root := filepath.Join(t.TempDir(), "protected")
	if os.Mkdir(root, 0o700) != nil {
		t.Fatal("explicit protected root creation failed")
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode().Perm() != 0o700 || fileauthority.CheckDirectory(root) != nil {
		t.Fatal("native file authority rejected explicit 0700 fixture root")
	}
	attempts := filepath.Join(root, "attempts")
	if os.Mkdir(attempts, 0o700) != nil {
		t.Fatal("protected attempts directory creation failed")
	}
	info, err = os.Lstat(attempts)
	if err != nil || info.Mode().Perm() != 0o700 || fileauthority.CheckDirectory(attempts) != nil {
		t.Fatal("native file authority rejected attempts directory")
	}
	f := &admissionBoundaryFixture{root: root, path: filepath.Join(root, "broker.json"), attempts: attempts, effects: effects}
	f.descriptor = map[string]any{
		"contract": "open-trestle/github-source-broker", "schema_version": uint64(1),
		"tenant_id": "tenant-a", "repository_id": "repo-a", "repository_full_name": "owner/repo",
		"github_repository_id": uint64(99), "installation_id": uint64(42), "app_id": uint64(7),
		"repository_authority": "github.com", "api_endpoint": server.URL + "/api/v3", "api_version": "2026-03-10",
		"archive_authorities": []string{"codeload.github.com"}, "app_key_version": "fixture-key-1",
		"app_public_key_sha256": strings.Repeat("b", 64), "credential_environment": "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY",
		"authorization_generation": strings.Repeat("d", 64), "ownership_mode": "single_host_exclusive",
		"attempt_state_directory": attempts, "allow_token_creation": true, "allow_demand_renewal": true,
	}
	if len(f.descriptor) != 20 {
		t.Fatal("descriptor fixture must have exactly 20 keys")
	}
	return f
}

func admissionBoundaryJSON(t *testing.T, descriptor map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal("fixture JSON encoding failed")
	}
	return encoded
}

func admissionBoundaryCopy(descriptor map[string]any) map[string]any {
	copy := make(map[string]any, len(descriptor))
	for name, value := range descriptor {
		if archives, ok := value.([]string); ok {
			value = append([]string(nil), archives...)
		}
		copy[name] = value
	}
	return copy
}

func (f *admissionBoundaryFixture) write(t *testing.T, content []byte) {
	t.Helper()
	if os.WriteFile(f.path, content, 0o600) != nil {
		t.Fatal("protected descriptor write failed")
	}
	info, err := os.Lstat(f.path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("descriptor must be regular 0600")
	}
}

func (f *admissionBoundaryFixture) assertNoRecords(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(f.attempts)
	if err != nil || len(entries) != 0 {
		t.Fatal("inert configuration admission created guard records")
	}
	f.effects.assertInert(t)
}

func (f *admissionBoundaryFixture) load(t *testing.T) Configuration {
	t.Helper()
	f.write(t, admissionBoundaryJSON(t, f.descriptor))
	c, err := LoadConfig(context.Background(), f.path)
	if err != nil || c.Validate() != nil || c.AuthorityIdentity() == "" || c.Authority().Validate() != nil || c.Authority().Identity() != c.AuthorityIdentity() {
		t.Fatal("real protected descriptor positive control failed")
	}
	f.assertNoRecords(t)
	return c
}

func admissionBoundaryRefuse(t *testing.T, c Configuration, err, want error) {
	t.Helper()
	if !errors.Is(err, want) || c.Validate() == nil || c.AuthorityIdentity() != "" || c.Authority().Validate() == nil {
		t.Fatal("invalid descriptor returned authority or wrong closed error")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if strings.Contains(fmt.Sprintf(format, err), "fixture-admission-secret") {
			t.Fatal("descriptor error leaked input")
		}
	}
}

func TestBrokerConfigurationAdmission(t *testing.T) {
	f := admissionBoundaryNewFixture(t)
	baseline := f.load(t)
	baselineID := baseline.AuthorityIdentity()
	t.Run("captured-detached-authority", func(t *testing.T) {
		common := baseline.Authority()
		original := common.Configuration()
		detached := common.Configuration()
		detached.ArchiveAuthorities[0] = "archive.example.org"
		detached.AppID = 8
		changed, err := github.NewInstallationBrokerAuthority(detached)
		if err != nil || changed.Identity() == baselineID {
			t.Fatal("real changed authority did not bind changed input")
		}
		detached.ArchiveAuthorities[0] = "mutated.example.org"
		if changed.Configuration().ArchiveAuthorities[0] != "archive.example.org" || changed.Validate() != nil {
			t.Fatal("authority retained caller-owned archive slice")
		}
		if baseline.AuthorityIdentity() != baselineID || baseline.Validate() != nil || !reflect.DeepEqual(common.Configuration(), original) || !reflect.DeepEqual(baseline.Authority().Configuration(), original) {
			t.Fatal("returned configuration mutated captured authority")
		}
		setup, err := github.NewIssuanceAuthority(common, github.IssuancePurposeSetup)
		if err != nil {
			t.Fatal("setup authority failed")
		}
		runtime, err := github.NewIssuanceAuthority(common, github.IssuancePurposeRuntime)
		if err != nil || runtime.Validate() != nil || setup.Validate() != nil || setup.Identity() == runtime.Identity() || setup.BrokerAuthorityIdentity() != baselineID || runtime.BrokerAuthorityIdentity() != baselineID {
			t.Fatal("pure common authority and separate purpose identities failed")
		}
		modified := admissionBoundaryCopy(f.descriptor)
		modified["app_key_version"] = "fixture-key-2"
		f.write(t, admissionBoundaryJSON(t, modified))
		reloaded, err := LoadConfig(context.Background(), f.path)
		if err != nil || reloaded.Validate() != nil || reloaded.AuthorityIdentity() == baselineID || baseline.AuthorityIdentity() != baselineID || !reflect.DeepEqual(baseline.Authority().Configuration(), original) {
			t.Fatal("external descriptor rewrite changed captured configuration or failed to change new authority")
		}
		for _, value := range []any{baseline, common, setup, runtime} {
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
				printed := fmt.Sprintf(format, value)
				if printed == "" || strings.Contains(printed, f.attempts) || strings.Contains(printed, "fixture-key-1") {
					t.Fatal("opaque configuration formatting exposed fields")
				}
			}
		}
		f.assertNoRecords(t)
	})
	base := admissionBoundaryJSON(t, f.descriptor)
	t.Run("exact-object-shape", func(t *testing.T) {
		cases := []struct {
			name    string
			content []byte
		}{
			{"unknown-key", append(append([]byte(nil), base[:len(base)-1]...), []byte(`,"fixture-admission-secret":true}`)...)},
			{"duplicate-key", append(append([]byte(nil), base[:len(base)-1]...), []byte(`,"app_id":7}`)...)},
			{"duplicate-escaped-key", append(append([]byte(nil), base[:len(base)-1]...), []byte(`,"\u0061pp_id":7}`)...)},
			{"case-folded-key", bytes.Replace(base, []byte(`"app_id"`), []byte(`"App_ID"`), 1)},
			{"trailing-object", append(append([]byte(nil), base...), []byte(` {}`)...)},
			{"trailing-junk", append(append([]byte(nil), base...), []byte(` fixture-admission-secret`)...)},
			{"array-root", []byte(`[]`)}, {"null-root", []byte(`null`)}, {"empty", nil},
			{"truncated", base[:len(base)-1]},
			{"invalid-UTF8", bytes.Replace(base, []byte("tenant-a"), []byte{0xff}, 1)},
		}
		for _, name := range []string{"contract", "schema_version", "tenant_id", "repository_id", "repository_full_name", "github_repository_id", "installation_id", "app_id", "repository_authority", "api_endpoint", "api_version", "archive_authorities", "app_key_version", "app_public_key_sha256", "credential_environment", "authorization_generation", "ownership_mode", "attempt_state_directory", "allow_token_creation", "allow_demand_renewal"} {
			missing := admissionBoundaryCopy(f.descriptor)
			delete(missing, name)
			cases = append(cases, struct {
				name    string
				content []byte
			}{"missing-" + name, admissionBoundaryJSON(t, missing)})
			null := admissionBoundaryCopy(f.descriptor)
			null[name] = nil
			cases = append(cases, struct {
				name    string
				content []byte
			}{"null-" + name, admissionBoundaryJSON(t, null)})
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				f.write(t, tc.content)
				c, err := LoadConfig(context.Background(), f.path)
				admissionBoundaryRefuse(t, c, err, github.ErrInvalidBrokerConfig)
				f.assertNoRecords(t)
			})
		}
	})
	t.Run("field-contract", func(t *testing.T) {
		for _, tc := range []struct {
			name, field string
			value       any
		}{
			{"wrong-contract", "contract", "fixture-admission-secret"},
			{"schema-zero", "schema_version", 0}, {"schema-new", "schema_version", 2},
			{"string-type", "tenant_id", 7}, {"integer-string-type", "app_id", "7"},
			{"integer-fraction", "app_id", 7.5}, {"integer-negative", "installation_id", -1},
			{"integer-overflow", "github_repository_id", json.Number("18446744073709551616")},
			{"bool-string-type", "allow_token_creation", "true"},
			{"archive-scalar-type", "archive_authorities", "codeload.github.com"},
			{"archive-element-type", "archive_authorities", []any{7}},
			{"app-zero", "app_id", 0}, {"app-above-bound", "app_id", uint64(9007199254740992)},
			{"installation-zero", "installation_id", 0}, {"installation-above-bound", "installation_id", uint64(9007199254740992)},
			{"repository-zero", "github_repository_id", 0}, {"repository-above-bound", "github_repository_id", uint64(9007199254740992)},
			{"tenant-empty", "tenant_id", ""}, {"logical-repository-empty", "repository_id", ""},
			{"repository-case", "repository_full_name", "Owner/repo"}, {"repository-extra-component", "repository_full_name", "owner/repo/extra"},
			{"repository-authority", "repository_authority", "example.org"},
			{"token-consent", "allow_token_creation", false}, {"renewal-consent", "allow_demand_renewal", false},
			{"generation-zero", "authorization_generation", strings.Repeat("0", 64)},
			{"generation-short", "authorization_generation", strings.Repeat("d", 63)},
			{"generation-case", "authorization_generation", strings.Repeat("D", 64)},
			{"key-reference", "credential_environment", "OPEN_TRESTLE_GITHUB_API_TOKEN"},
			{"ownership-mode", "ownership_mode", "shared"},
			{"key-version-empty", "app_key_version", ""}, {"key-version-129", "app_key_version", strings.Repeat("a", 129)},
			{"key-version-space", "app_key_version", "fixture key"}, {"key-version-non-ASCII", "app_key_version", "key-\u00e9"},
			{"pin-zero", "app_public_key_sha256", strings.Repeat("0", 64)}, {"pin-short", "app_public_key_sha256", strings.Repeat("b", 63)},
			{"pin-case", "app_public_key_sha256", strings.Repeat("B", 64)}, {"pin-nonhex", "app_public_key_sha256", strings.Repeat("g", 64)},
			{"archive-empty", "archive_authorities", []string{}},
			{"archive-unsorted", "archive_authorities", []string{"z.example.org", "a.example.org"}},
			{"archive-duplicate", "archive_authorities", []string{"codeload.github.com", "codeload.github.com"}},
			{"archive-case", "archive_authorities", []string{"CODELOAD.github.com"}},
			{"archive-path", "archive_authorities", []string{"codeload.github.com/path"}},
			{"archive-userinfo", "archive_authorities", []string{"user@codeload.github.com"}},
			{"archive-query", "archive_authorities", []string{"codeload.github.com?x=1"}},
			{"path-empty", "attempt_state_directory", ""}, {"path-relative", "attempt_state_directory", "attempts"},
			{"path-unclean", "attempt_state_directory", f.root + "/./attempts"},
			{"path-trailing-slash", "attempt_state_directory", f.attempts + "/"},
			{"path-NUL", "attempt_state_directory", f.attempts + "\x00"},
			{"path-newline", "attempt_state_directory", f.attempts + "\n"},
			{"path-4097", "attempt_state_directory", "/" + strings.Repeat("a", 4096)},
			{"endpoint-credentials", "api_endpoint", "https://fixture-admission-secret@api.github.com"},
			{"endpoint-external-HTTP", "api_endpoint", "http://api.github.com"},
			{"endpoint-query", "api_endpoint", "https://api.github.com?x=1"},
			{"api-version", "api_version", "2026-02-30"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				descriptor := admissionBoundaryCopy(f.descriptor)
				descriptor[tc.field] = tc.value
				f.write(t, admissionBoundaryJSON(t, descriptor))
				c, err := LoadConfig(context.Background(), f.path)
				admissionBoundaryRefuse(t, c, err, github.ErrInvalidBrokerConfig)
				f.assertNoRecords(t)
			})
		}
	})
	t.Run("positive-and-negative-bounds", func(t *testing.T) {
		archives := make([]string, 17)
		for n := range archives {
			archives[n] = fmt.Sprintf("a%02d.example.org", n)
		}
		for _, tc := range []struct {
			name, field string
			value       any
			valid       bool
		}{
			{"minimum-identifiers", "app_id", uint64(1), true},
			{"maximum-app", "app_id", uint64(9007199254740991), true},
			{"maximum-installation", "installation_id", uint64(9007199254740991), true},
			{"maximum-repository", "github_repository_id", uint64(9007199254740991), true},
			{"key-version-128", "app_key_version", strings.Repeat("a", 128), true},
			{"archives-16", "archive_authorities", archives[:16], true},
			{"archives-17", "archive_authorities", archives, false},
			{"path-4096-pure-authority", "attempt_state_directory", "/" + strings.Repeat("a", 4095), true},
			{"nonexistent-attempts-pure-authority", "attempt_state_directory", filepath.Join(f.root, "not-created"), true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				descriptor := admissionBoundaryCopy(f.descriptor)
				descriptor[tc.field] = tc.value
				f.write(t, admissionBoundaryJSON(t, descriptor))
				c, err := LoadConfig(context.Background(), f.path)
				if tc.valid {
					if err != nil || c.Validate() != nil || c.AuthorityIdentity() == "" {
						t.Fatal("valid pure configuration boundary refused")
					}
				} else {
					admissionBoundaryRefuse(t, c, err, github.ErrInvalidBrokerConfig)
				}
				f.assertNoRecords(t)
			})
		}
		for _, size := range []int{64 << 10, (64 << 10) + 1} {
			t.Run(fmt.Sprintf("descriptor-bytes-%d", size), func(t *testing.T) {
				padded := append(append([]byte(nil), base...), bytes.Repeat([]byte(" "), size-len(base))...)
				f.write(t, padded)
				c, err := LoadConfig(context.Background(), f.path)
				if size == 64<<10 {
					if err != nil || c.Validate() != nil || c.AuthorityIdentity() != baselineID {
						t.Fatal("exact 64KiB descriptor refused or changed authority")
					}
				} else {
					admissionBoundaryRefuse(t, c, err, github.ErrInvalidBrokerConfig)
				}
				f.assertNoRecords(t)
			})
		}
	})
}

func TestBrokerConfigurationProtectedFileAdmission(t *testing.T) {
	f := admissionBoundaryNewFixture(t)
	_ = f.load(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name, path string
		ctx        context.Context
		want       error
	}{
		{"nil-context", f.path, nil, github.ErrInvalidBrokerConfig},
		{"canceled-context", f.path, canceled, github.ErrBrokerUnavailable},
		{"empty-path", "", context.Background(), github.ErrInvalidBrokerConfig},
		{"relative-path", "broker.json", context.Background(), github.ErrInvalidBrokerConfig},
		{"unclean-path", f.root + "/./broker.json", context.Background(), github.ErrInvalidBrokerConfig},
		{"missing-file", filepath.Join(f.root, "absent.json"), context.Background(), github.ErrInvalidBrokerConfig},
		{"directory-not-file", f.attempts, context.Background(), github.ErrInvalidBrokerConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := LoadConfig(tc.ctx, tc.path)
			admissionBoundaryRefuse(t, c, err, tc.want)
			f.assertNoRecords(t)
		})
	}
	t.Run("symlink-descriptor", func(t *testing.T) {
		link := filepath.Join(f.root, "linked.json")
		if os.Symlink(f.path, link) != nil {
			t.Fatal("fixture symlink creation failed")
		}
		c, err := LoadConfig(context.Background(), link)
		admissionBoundaryRefuse(t, c, err, github.ErrInvalidBrokerConfig)
		f.assertNoRecords(t)
	})
	t.Run("group-writable-descriptor", func(t *testing.T) {
		if os.Chmod(f.path, 0o620) != nil {
			t.Fatal("fixture descriptor mode change failed")
		}
		defer func() {
			if os.Chmod(f.path, 0o600) != nil {
				t.Error("descriptor mode restore failed")
			}
		}()
		c, err := LoadConfig(context.Background(), f.path)
		admissionBoundaryRefuse(t, c, err, github.ErrInvalidBrokerConfig)
		f.assertNoRecords(t)
	})
}

func TestBrokerRuntimeOpenAdmission(t *testing.T) {
	f := admissionBoundaryNewFixture(t)
	c := f.load(t)
	clock := admissionBoundaryClock{time.Now().UTC().Truncate(time.Second)}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	lane, err := github.NewIssuanceAuthority(c.Authority(), github.IssuancePurposeRuntime)
	if err != nil {
		t.Fatal("pure runtime lane failed")
	}
	for _, tc := range []struct {
		name          string
		ctx           context.Context
		configuration Configuration
		expected      string
		purpose       github.IssuancePurpose
		getenv        func(string) string
		clock         github.BrokerClock
		want          error
	}{
		{"wrong-expected", context.Background(), c, strings.Repeat("e", 64), github.IssuancePurposeRuntime, f.effects.getenv, clock, github.ErrBrokerMismatch},
		{"empty-expected", context.Background(), c, "", github.IssuancePurposeRuntime, f.effects.getenv, clock, github.ErrBrokerMismatch},
		{"lane-not-common-expected", context.Background(), c, lane.Identity(), github.IssuancePurposeRuntime, f.effects.getenv, clock, github.ErrBrokerMismatch},
		{"unknown-purpose", context.Background(), c, c.AuthorityIdentity(), github.IssuancePurpose("other"), f.effects.getenv, clock, github.ErrInvalidBrokerConfig},
		{"empty-purpose", context.Background(), c, c.AuthorityIdentity(), github.IssuancePurpose(""), f.effects.getenv, clock, github.ErrInvalidBrokerConfig},
		{"pre-canceled", canceled, c, c.AuthorityIdentity(), github.IssuancePurposeRuntime, f.effects.getenv, clock, github.ErrBrokerUnavailable},
		{"nil-context", nil, c, c.AuthorityIdentity(), github.IssuancePurposeRuntime, f.effects.getenv, clock, github.ErrInvalidBrokerConfig},
		{"zero-configuration", context.Background(), Configuration{}, c.AuthorityIdentity(), github.IssuancePurposeRuntime, f.effects.getenv, clock, github.ErrInvalidBrokerConfig},
		{"nil-getenv", context.Background(), c, c.AuthorityIdentity(), github.IssuancePurposeRuntime, nil, clock, github.ErrInvalidBrokerConfig},
		{"nil-clock", context.Background(), c, c.AuthorityIdentity(), github.IssuancePurposeRuntime, f.effects.getenv, nil, github.ErrInvalidBrokerConfig},
		{"typed-nil-clock", context.Background(), c, c.AuthorityIdentity(), github.IssuancePurposeRuntime, f.effects.getenv, (*admissionBoundaryClock)(nil), github.ErrInvalidBrokerConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime, err := Open(tc.ctx, tc.configuration, tc.expected, tc.purpose, tc.getenv, tc.clock)
			if runtime != nil {
				defer runtime.Close()
			}
			if runtime != nil || !errors.Is(err, tc.want) {
				t.Fatal("invalid Open admitted an owner or returned wrong closed error")
			}
			f.assertNoRecords(t)
		})
	}
	t.Run("native-owner-without-credential-effect", func(t *testing.T) {
		runtime, err := Open(context.Background(), c, c.AuthorityIdentity(), github.IssuancePurposeRuntime, f.effects.getenv, clock)
		if runtime != nil {
			defer runtime.Close()
		}
		if err != nil || runtime == nil || runtime.Broker() == nil || runtime.Broker().Validate() != nil {
			t.Fatal("actual native runtime positive control failed")
		}
		broker := runtime.Broker()
		if broker.AuthorityIdentity() != c.AuthorityIdentity() || broker.IssuanceAuthorityIdentity() != lane.Identity() || broker.Purpose() != github.IssuancePurposeRuntime {
			t.Fatal("native runtime identity or lane mismatch")
		}
		f.effects.assertInert(t)
		entries, err := os.ReadDir(f.attempts)
		if err != nil || len(entries) != 1 {
			t.Fatal("Open must create exactly one durable owner marker and no attempts")
		}
		marker := filepath.Join(f.attempts, entries[0].Name())
		info, err := os.Lstat(marker)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > 4096 {
			t.Fatal("owner marker authority or bound failed")
		}
		before, err := os.ReadFile(marker)
		if err != nil {
			t.Fatal("native owner marker read failed")
		}
		var record map[string]any
		want := map[string]any{
			"contract": "open-trestle/github-installation-issuance-owner", "schema_version": float64(1),
			"authority_identity": lane.Identity(), "broker_authority_identity": c.AuthorityIdentity(),
			"authorization_generation": c.Authority().Configuration().AuthorizationGeneration,
		}
		if json.Unmarshal(before, &record) != nil || !reflect.DeepEqual(record, want) || bytes.Contains(before, []byte("fixture-admission-private-key")) {
			t.Fatal("native owner marker does not bind real common/lane/generation")
		}
		if runtime.Close() != nil || runtime.Close() != nil || runtime.Broker() != nil || !errors.Is(broker.Validate(), github.ErrBrokerClosed) {
			t.Fatal("runtime close did not permanently close broker admission")
		}
		after, err := os.ReadFile(marker)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("Close removed or changed durable owner marker")
		}
		entries, err = os.ReadDir(f.attempts)
		if err != nil || len(entries) != 1 {
			t.Fatal("Close changed marker count")
		}
		f.effects.assertInert(t)
		if c.Validate() != nil || c.AuthorityIdentity() != broker.AuthorityIdentity() {
			t.Fatal("live owner closure invalidated inert captured configuration")
		}
	})
}
