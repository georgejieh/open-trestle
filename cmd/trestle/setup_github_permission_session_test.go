//go:build unix

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	githubadapter "github.com/georgejieh/open-trestle/adapters/scm/github"
	githubruntime "github.com/georgejieh/open-trestle/internal/githubruntime"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

type setupBrokerBoundaryNilContext struct{ context.Context }

func setupBrokerBoundarySession(t *testing.T, f *setupBrokerBoundaryFixture, ctx context.Context) *setupGitHubPermissionSession {
	t.Helper()
	s, err := newSetupGitHubPermissionSession(ctx, f.configuration, f.getenv, githubadapter.SystemBrokerClock{})
	if err != nil || s == nil {
		t.Fatal("native lazy session construction failed")
	}
	t.Cleanup(func() {
		if s.Close() != nil {
			t.Error("session cleanup failed")
		}
	})
	return s
}

func setupBrokerBoundaryIdle(t *testing.T, s *setupGitHubPermissionSession) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != setupGitHubPermissionSessionIdle || s.runtime != nil || s.openDone != nil || s.closeDone == nil || s.openErr != nil {
		t.Fatal("unadmitted session did not remain idle")
	}
}

func setupBrokerBoundaryWait(t *testing.T, done <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatalf("bounded fixture join failed: %s", label)
	}
}

func TestSetupBrokerBoundarySessionConstructorAndLazyNativeOwner(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	owner, cancelOwner := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelOwner()
	s := setupBrokerBoundarySession(t, f, owner)
	setupBrokerBoundaryIdle(t, s)
	f.noEffects(t)
	f.mu.Lock()
	reads := len(f.reads)
	f.mu.Unlock()
	if reads != 0 {
		t.Fatal("constructor retrieved an environment credential")
	}
	for _, name := range []string{"nil-context", "typed-nil-context", "wrong-common", "canceled-caller"} {
		t.Run(name, func(t *testing.T) {
			var caller context.Context = owner
			common := f.configuration.AuthorityIdentity()
			want := githubadapter.ErrInvalidBrokerConfig
			switch name {
			case "nil-context":
				caller = nil
			case "typed-nil-context":
				var typed *setupBrokerBoundaryNilContext
				caller = typed
			case "wrong-common":
				common = strings.Repeat("a", 64)
				want = githubadapter.ErrBrokerMismatch
			case "canceled-caller":
				c, cancel := context.WithCancel(owner)
				cancel()
				caller = c
				want = githubadapter.ErrBrokerUnavailable
			}
			b, err := s.broker(caller, common)
			if b != nil || !errors.Is(err, want) {
				t.Fatal("closed dispatch vocabulary mismatch")
			}
			setupBrokerBoundaryIdle(t, s)
			f.noEffects(t)
		})
	}
	caller, cancelCaller := context.WithCancel(owner)
	broker, err := s.broker(caller, f.configuration.AuthorityIdentity())
	if err != nil || broker == nil || broker.Validate() != nil || broker.Purpose() != githubadapter.IssuancePurposeSetup || broker.AuthorityIdentity() != f.configuration.AuthorityIdentity() {
		t.Fatal("session did not call actual native Open")
	}
	cancelCaller()
	ownerRecords := f.records(t)
	if len(ownerRecords) != 1 {
		t.Fatal("actual native Open did not create one owner marker")
	}
	f.effects(t, 0, 0, 0)
	s.mu.Lock()
	runtime := s.runtime
	phase := s.phase
	done := s.openDone
	s.mu.Unlock()
	if runtime == nil || phase != setupGitHubPermissionSessionReady || runtime.Broker() != broker {
		t.Fatal("session did not publish native runtime")
	}
	setupBrokerBoundaryWait(t, done, "native Open publication")
	again, err := s.broker(owner, f.configuration.AuthorityIdentity())
	if err != nil || again != broker {
		t.Fatal("completed caller cancellation rebuilt or poisoned owner")
	}
	if b, err := s.broker(owner, strings.Repeat("a", 64)); b != nil || !errors.Is(err, githubadapter.ErrBrokerMismatch) {
		t.Fatal("wrong common reached cached owner")
	}
	again, err = s.broker(owner, f.configuration.AuthorityIdentity())
	if err != nil || again != broker || !reflect.DeepEqual(ownerRecords, f.records(t)) {
		t.Fatal("wrong common damaged valid cached owner")
	}
	if err := s.Close(); err != nil {
		t.Fatal("native session close failed")
	}
	if !reflect.DeepEqual(ownerRecords, f.records(t)) {
		t.Fatal("Close deleted retained owner marker")
	}
	if b, err := s.broker(owner, f.configuration.AuthorityIdentity()); b != nil || !errors.Is(err, githubadapter.ErrBrokerClosed) {
		t.Fatal("Close allowed owner reconstruction")
	}
	if s.Close() != nil {
		t.Fatal("successful Close was not stable")
	}
	s.mu.Lock()
	phase = s.phase
	cleared := s.runtime == nil && s.getenv == nil && s.clock == nil
	s.mu.Unlock()
	if phase != setupGitHubPermissionSessionClosed || !cleared {
		t.Fatal("closed session retained owned references")
	}
	// A second actual native Open fails and is latched, never repaired.
	second := setupBrokerBoundarySession(t, f, owner)
	for i := 0; i < 2; i++ {
		b, err := second.broker(owner, f.configuration.AuthorityIdentity())
		if b != nil || !errors.Is(err, githubadapter.ErrIssuanceFenced) {
			t.Fatal("retained owner did not fence new session")
		}
	}
	second.mu.Lock()
	failed := second.phase == setupGitHubPermissionSessionFailed && errors.Is(second.openErr, githubadapter.ErrIssuanceFenced)
	second.mu.Unlock()
	if !failed || !reflect.DeepEqual(ownerRecords, f.records(t)) {
		t.Fatal("native Open failure not latched")
	}
	f.effects(t, 0, 0, 0)
}

func TestSetupBrokerBoundarySessionInvalidConstructionAndCloseBeforeUse(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var nilCtx *setupBrokerBoundaryNilContext
	var nilClock *setupBrokerBoundaryClock
	for _, name := range []string{"nil-lifetime", "typed-nil-lifetime", "nil-getenv", "nil-clock", "typed-nil-clock", "invalid-config", "canceled-lifetime", "old-api-year"} {
		t.Run(name, func(t *testing.T) {
			lifetime := context.Context(ctx)
			configuration := f.configuration
			getenv := f.getenv
			var clock githubadapter.BrokerClock = githubadapter.SystemBrokerClock{}
			want := githubadapter.ErrInvalidBrokerConfig
			switch name {
			case "nil-lifetime":
				lifetime = nil
			case "typed-nil-lifetime":
				lifetime = nilCtx
			case "nil-getenv":
				getenv = nil
			case "nil-clock":
				clock = nil
			case "typed-nil-clock":
				clock = nilClock
			case "invalid-config":
				configuration = githubruntime.Configuration{}
			case "canceled-lifetime":
				dead, cancel := context.WithCancel(ctx)
				cancel()
				lifetime = dead
				want = githubadapter.ErrBrokerUnavailable
			case "old-api-year":
				f.writeDescriptor(t, strings.Repeat("d", 64), "1999-03-10")
				configuration = f.configuration
			}
			s, err := newSetupGitHubPermissionSession(lifetime, configuration, getenv, clock)
			if s != nil {
				_ = s.Close()
			}
			if s != nil || !errors.Is(err, want) {
				t.Fatal("invalid session constructor accepted or wrong closed error")
			}
			f.noEffects(t)
		})
	}
	f.writeDescriptor(t, strings.Repeat("d", 64), "2026-03-10")
	s := setupBrokerBoundarySession(t, f, ctx)
	if s.Close() != nil || s.Close() != nil {
		t.Fatal("idle Close not nil/stable")
	}
	if b, err := s.broker(ctx, f.configuration.AuthorityIdentity()); b != nil || !errors.Is(err, githubadapter.ErrBrokerClosed) {
		t.Fatal("Close-before-use allocated owner")
	}
	var absent *setupGitHubPermissionSession
	if absent.Close() != nil {
		t.Fatal("nil Close not no-op")
	}
	f.noEffects(t)
}

func TestSetupBrokerBoundaryHostCaptureAndMinimumAPIVersion(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	good := f.host(t)
	for _, test := range []struct{ name, path, cap, static string }{
		{"cap-without-path", "", f.configuration.AuthorityIdentity(), ""},
		{"path-without-cap", f.descriptor, "", ""},
		{"wrong-cap", f.descriptor, strings.Repeat("a", 64), ""},
		{"mixed-static", f.descriptor, f.configuration.AuthorityIdentity(), "synthetic-static-token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := loadSetupGitHubPermissionHostConfiguration(context.Background(), test.path, test.cap, test.static); err == nil {
				t.Fatal("partial/mixed host accepted")
			}
			f.noEffects(t)
		})
	}
	absent, err := loadSetupGitHubPermissionHostConfiguration(context.Background(), "", "", "unrelated-static-token")
	if err != nil || absent.Validate() != nil || absent.configured || absent.expectedBrokerAuthority != "" || absent.broker.AuthorityIdentity() != "" {
		t.Fatal("unrelated absent host acquired authority")
	}
	f.writeDescriptor(t, strings.Repeat("e", 64), "1999-03-10")
	if f.configuration.Validate() != nil {
		t.Fatal("source descriptor unexpectedly rejects native-valid year")
	}
	if validSetupGitHubPermissionBrokerConfiguration(f.configuration) {
		t.Fatal("setup accepted inspector-incompatible API year")
	}
	if _, err := loadSetupGitHubPermissionHostConfiguration(context.Background(), f.descriptor, f.configuration.AuthorityIdentity(), ""); err == nil {
		t.Fatal("host admitted API year below 2000")
	}
	if good.Validate() != nil || good.broker.AuthorityIdentity() == f.configuration.AuthorityIdentity() {
		t.Fatal("captured host reloaded descriptor or mutated")
	}
	f.noEffects(t)
}

func TestSetupBrokerBoundaryProbeIdentityAndComparisonPreadmission(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	plan := f.initialize(t, true, "tenant-a", "repo-a")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s := setupBrokerBoundarySession(t, f, ctx)
	configuration := setupGitHubPermissionConfiguration{host: f.host(t), session: s, expectedBrokerAuthority: f.configuration.AuthorityIdentity(), allowTokenCreation: true}
	probe, authority, err := newSetupGitHubPermissionProbe(f.getenv, plan, configuration, executeSetupGitHubPermission)
	if err != nil || authority != f.permission(t) || probe.AuthorityIdentity() != authority {
		t.Fatal("current request probe construction failed")
	}
	lane, err := githubadapter.NewIssuanceAuthority(f.configuration.Authority(), githubadapter.IssuancePurposeSetup)
	if err != nil {
		t.Fatal("native lane identity failed")
	}
	values := [15]any{"probe", 2, authority, f.configuration.AuthorityIdentity(), lane.Identity(), setupGitHubPermissionUserCredentialIdentity(), plan.RootIdentity(), plan.TenantID(), plan.RepositoryID(), plan.RecoveryOwner(), configuration.host.expectedBrokerAuthority, configuration.expectedBrokerAuthority, true, setupBrokerBoundaryComparisons, "reject-static-token;setup-purpose;owner-lifetime;foreground-demand-renewal;fresh-generation-on-restart"}
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal("identity preimage encoding failed")
	}
	sum := sha256.Sum256(append([]byte("open-trestle/setup-github-permission/v2\x00"), encoded...))
	if probe.ConfigurationIdentity() != hex.EncodeToString(sum[:]) || setupGitHubPermissionUserCredentialIdentity() != "27b37d6de18832c8cc9381754f4db8c00a4509a4994e04e6370f10ef37f83927" {
		t.Fatal("15-element native probe identity drift")
	}
	f.noEffects(t)
	for _, name := range append([]string{"missing-user", "late-static", "canceled"}, setupBrokerBoundaryComparisons...) {
		t.Run(name, func(t *testing.T) {
			f.mu.Lock()
			before := len(f.reads)
			oldUser := f.values["OPEN_TRESTLE_GITHUB_SETUP_TOKEN"]
			old := f.values[name]
			switch name {
			case "missing-user":
				f.values["OPEN_TRESTLE_GITHUB_SETUP_TOKEN"] = ""
			case "late-static":
				f.values["OPEN_TRESTLE_GITHUB_API_TOKEN"] = "synthetic-late-static"
			case "canceled":
			default:
				f.values[name] = setupBrokerBoundaryUser
			}
			f.mu.Unlock()
			caller, cancelCaller := context.WithCancel(ctx)
			if name == "canceled" {
				cancelCaller()
			}
			result := probe.Probe(caller)
			cancelCaller()
			want := setupcore.NewInvalidIntegrationPermissionProbeResult()
			if name == "canceled" {
				want = setupcore.NewUnavailableIntegrationPermissionProbeResult()
			}
			if !reflect.DeepEqual(result, want) {
				t.Fatal("invalid credential/cancellation did not produce closed probe outcome")
			}
			f.mu.Lock()
			reads := append([]string(nil), f.reads[before:]...)
			f.values["OPEN_TRESTLE_GITHUB_SETUP_TOKEN"] = oldUser
			if name == "late-static" {
				f.values["OPEN_TRESTLE_GITHUB_API_TOKEN"] = ""
			} else {
				f.values[name] = old
			}
			f.mu.Unlock()
			wantReads := append([]string{"OPEN_TRESTLE_GITHUB_SETUP_TOKEN"}, setupBrokerBoundaryComparisons...)
			if name == "canceled" {
				wantReads = nil
			}
			if !reflect.DeepEqual(reads, wantReads) {
				t.Fatal("dedicated user and unchanged five-comparison read order drift")
			}
			setupBrokerBoundaryIdle(t, s)
			f.noEffects(t)
		})
	}
	legacy := setupGitHubPermissionConfiguration{apiEndpoint: f.server.URL + "/api/v3", apiVersion: "2026-03-10", installationID: 42, repositoryFullName: "owner/repo"}
	if !validSetupGitHubPermissionConfiguration(legacy) {
		t.Fatal("legacy pure identity compatibility lost")
	}
	if _, _, err := newSetupGitHubPermissionProbe(f.getenv, plan, legacy, executeSetupGitHubPermission); err == nil {
		t.Fatal("legacy identity-only quartet became executable")
	}
	for _, name := range []string{"apiEndpoint", "apiVersion", "installationID", "repositoryFullName", "missing-consent", "wrong-common", "missing-session", "wrong-scope"} {
		t.Run(name, func(t *testing.T) {
			mixed := configuration
			boundPlan := plan
			switch name {
			case "apiEndpoint":
				mixed.apiEndpoint = f.server.URL + "/api/v3"
			case "apiVersion":
				mixed.apiVersion = "2026-03-10"
			case "installationID":
				mixed.installationID = 42
			case "repositoryFullName":
				mixed.repositoryFullName = "owner/repo"
			case "missing-consent":
				mixed.allowTokenCreation = false
			case "wrong-common":
				mixed.expectedBrokerAuthority = strings.Repeat("a", 64)
			case "missing-session":
				mixed.session = nil
			case "wrong-scope":
				var err error
				boundPlan, err = setupcore.NewCurrentPlan(setupcore.ProfileControlledHybrid, "tenant-a", "other-repo", "owner", f.at)
				if err != nil {
					t.Fatal("scope fixture failed")
				}
			}
			if _, _, err := newSetupGitHubPermissionProbe(f.getenv, boundPlan, mixed, executeSetupGitHubPermission); err == nil {
				t.Fatal("non-executable shape acquired probe")
			}
			f.noEffects(t)
		})
	}
	if value, err := executeSetupGitHubPermission(ctx, configuration, setupBrokerBoundaryUser, nil); err == nil || value != "" {
		t.Fatal("nil broker executor manufactured observation")
	}
	f.noEffects(t)
	for _, value := range []any{configuration.host, configuration, s, probe} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			data := []byte(fmt.Sprintf(format, value))
			f.redacted(t, data)
			for _, private := range []string{f.root, f.pin, f.configuration.AuthorityIdentity(), "owner/repo", "0x"} {
				if strings.Contains(string(data), private) {
					t.Fatal("private setup formatting exposed configuration or pointer")
				}
			}
		}
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal("private value JSON formatting failed")
		}
		f.redacted(t, data)
		for _, private := range []string{f.root, f.pin, f.configuration.AuthorityIdentity(), "owner/repo", "0x"} {
			if strings.Contains(string(data), private) {
				t.Fatal("private setup JSON exposed configuration or pointer")
			}
		}
	}
	identity := probe.ConfigurationIdentity()
	if s.Close() != nil || probe.ConfigurationIdentity() != identity || probe.AuthorityIdentity() != authority {
		t.Fatal("owner liveness changed immutable probe identity")
	}
}

func TestSetupBrokerBoundarySessionCloseDuringRealInspect(t *testing.T) {
	for _, name := range []string{"release-within-drain", "stable-incomplete-after-timeout"} {
		t.Run(name, func(t *testing.T) {
			f := setupBrokerBoundaryNew(t)
			plan := f.initialize(t, true, "tenant-a", "repo-a")
			owner, cancelOwner := context.WithTimeout(context.Background(), 30*time.Second)
			s, err := newSetupGitHubPermissionSession(owner, f.configuration, f.getenv, githubadapter.SystemBrokerClock{})
			if err != nil {
				cancelOwner()
				t.Fatal("session constructor failed")
			}
			// This call is actual Open. No getenv call is expected or blocked here.
			broker, err := s.broker(owner, f.configuration.AuthorityIdentity())
			if err != nil || broker == nil {
				_ = s.Close()
				cancelOwner()
				t.Fatal("actual native Open failed")
			}
			ownerRecords := f.records(t)
			if len(ownerRecords) != 1 {
				_ = s.Close()
				cancelOwner()
				t.Fatal("native owner marker missing")
			}
			f.effects(t, 0, 0, 0)
			f.keyEntered = make(chan struct{})
			f.keyRelease = make(chan struct{})
			probe, _, err := newSetupGitHubPermissionProbe(f.getenv, plan, setupGitHubPermissionConfiguration{host: f.host(t), session: s, expectedBrokerAuthority: f.configuration.AuthorityIdentity(), allowTokenCreation: true}, executeSetupGitHubPermission)
			if err != nil {
				_ = s.Close()
				cancelOwner()
				t.Fatal("real inspect probe construction failed")
			}
			caller, cancelCaller := context.WithTimeout(owner, 20*time.Second)
			probeDone := make(chan struct{})
			closeDone := make(chan struct{})
			var result setupcore.IntegrationPermissionProbeResult
			var closeErr error
			closeStarted := false
			defer func() {
				f.releaseKey()
				cancelCaller()
				cancelOwner()
				setupBrokerBoundaryWait(t, probeDone, "released native Inspect")
				if closeStarted {
					setupBrokerBoundaryWait(t, closeDone, "first session closer")
				} else {
					_ = s.Close()
				}
			}()
			go func() { defer close(probeDone); result = probe.Probe(caller) }()
			setupBrokerBoundaryWait(t, f.keyEntered, "lazy key callback after user visibility")
			f.effects(t, 1, 0, 1)
			closeStarted = true
			go func() { defer close(closeDone); closeErr = s.Close() }()
			// Observation only: no private phase/channel/owner mutation.
			setupBrokerBoundaryWait(t, s.lifetime.Done(), "owner cancellation at Close admission")
			if b, err := s.broker(owner, f.configuration.AuthorityIdentity()); b != nil || !errors.Is(err, githubadapter.ErrBrokerClosed) {
				t.Fatal("Close left admission open")
			}
			if err := s.Close(); !errors.Is(err, githubadapter.ErrBrokerCloseIncomplete) {
				t.Fatal("concurrent Close did not return per-call incomplete")
			}
			if name == "release-within-drain" {
				f.releaseKey()
			}
			setupBrokerBoundaryWait(t, closeDone, "bounded first Close publication")
			want := error(nil)
			if name == "stable-incomplete-after-timeout" {
				want = githubadapter.ErrBrokerCloseIncomplete
			}
			if !errors.Is(closeErr, want) {
				t.Fatal("first closer terminal result incorrect")
			}
			f.releaseKey()
			setupBrokerBoundaryWait(t, probeDone, "released caller")
			if !reflect.DeepEqual(result, setupcore.NewUnavailableIntegrationPermissionProbeResult()) {
				t.Fatal("canceled Inspect produced authority")
			}
			if !errors.Is(s.Close(), want) {
				t.Fatal("transient concurrent result overwrote stable Close, or incomplete was later repaired")
			}
			if !reflect.DeepEqual(ownerRecords, f.records(t)) {
				t.Fatal("canceled key callback altered retained marker")
			}
			f.effects(t, 1, 0, 1)
		})
	}
}

func TestSetupBrokerBoundarySessionNativeOpenVersusClose(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	owner, cancelOwner := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelOwner()
	s, err := newSetupGitHubPermissionSession(owner, f.configuration, f.getenv, githubadapter.SystemBrokerClock{})
	if err != nil {
		t.Fatal("session constructor failed")
	}
	start := make(chan struct{})
	borrowDone := make(chan struct{})
	closeDone := make(chan struct{})
	var broker *githubadapter.InstallationTokenBroker
	var borrowErr, closeErr error
	defer func() {
		cancelOwner()
		setupBrokerBoundaryWait(t, borrowDone, "native concurrent borrower")
		setupBrokerBoundaryWait(t, closeDone, "native concurrent closer")
		_ = s.Close()
	}()
	go func() {
		defer close(borrowDone)
		<-start
		broker, borrowErr = s.broker(owner, f.configuration.AuthorityIdentity())
	}()
	go func() { defer close(closeDone); <-start; closeErr = s.Close() }()
	close(start)
	setupBrokerBoundaryWait(t, borrowDone, "native borrow race")
	setupBrokerBoundaryWait(t, closeDone, "native close race")
	if closeErr != nil {
		t.Fatal("unblocked native Open/Close did not drain")
	}
	if borrowErr != nil && !errors.Is(borrowErr, githubadapter.ErrBrokerClosed) && !errors.Is(borrowErr, githubadapter.ErrBrokerUnavailable) {
		t.Fatal("native race returned unexpected sentinel")
	}
	if borrowErr == nil && broker == nil {
		t.Fatal("native race returned nil success")
	}
	if b, err := s.broker(context.Background(), f.configuration.AuthorityIdentity()); b != nil || !errors.Is(err, githubadapter.ErrBrokerClosed) {
		t.Fatal("native race reopened closed admission")
	}
	if len(f.records(t)) > 1 {
		t.Fatal("native race created repeated owner")
	}
	f.effects(t, 0, 0, 0)
	// This bounded real race does NOT claim it deterministically visited the
	// blocked-filesystem Opening window. That window has no admitted native
	// control seam. Do not seed phase/openDone/runtime to manufacture evidence.
}

func TestSetupBrokerBoundaryCapturedHostDoesNotReloadDescriptor(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	plan := f.initialize(t, true, "tenant-a", "repo-a")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	host := f.host(t)
	s := setupBrokerBoundarySession(t, f, ctx)
	probe, _, err := newSetupGitHubPermissionProbe(f.getenv, plan, setupGitHubPermissionConfiguration{host: host, session: s, expectedBrokerAuthority: host.expectedBrokerAuthority, allowTokenCreation: true}, executeSetupGitHubPermission)
	if err != nil {
		t.Fatal("captured current probe failed")
	}
	before := probe.ConfigurationIdentity()
	if err := os.Remove(f.descriptor); err != nil {
		t.Fatal("synthetic descriptor removal failed")
	}
	// Host/session already captured immutable protected configuration; no new
	// descriptor read is permitted at dispatch. Native guard still owns state.
	checker, err := setupcore.NewIntegrationPermissionChecker(plan, probe.AuthorityIdentity(), "owner", probe)
	if err != nil || checker == nil || checker.Check(ctx, plan).State() != setupcore.CheckPassed {
		t.Fatal("captured descriptor was reloaded or native inspect failed")
	}
	if before != probe.ConfigurationIdentity() {
		t.Fatal("descriptor pathname changed immutable probe identity")
	}
	f.effects(t, 1, 1, 1)
	f.accepted(t, 3)
}

func TestSetupBrokerBoundaryFrozenProbePreimageArithmetic(t *testing.T) {
	// Repeated digits below are HASH INPUTS ONLY, never broker/grant authority.
	values := [15]any{"probe", 2, strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), "27b37d6de18832c8cc9381754f4db8c00a4509a4994e04e6370f10ef37f83927", strings.Repeat("4", 64), "tenant-a", "repo-a", "owner", strings.Repeat("2", 64), strings.Repeat("2", 64), true, setupBrokerBoundaryComparisons, "reject-static-token;setup-purpose;owner-lifetime;foreground-demand-renewal;fresh-generation-on-restart"}
	data, err := json.Marshal(values)
	if err != nil {
		t.Fatal("frozen preimage JSON failed")
	}
	sum := sha256.Sum256(append([]byte("open-trestle/setup-github-permission/v2\x00"), data...))
	if hex.EncodeToString(sum[:]) != "6c1b6bbd3874e1f42587370b40f1fc72cb617d1d8a876067d3d25c202592eb8b" {
		t.Fatal("root-approved 15-element preimage arithmetic drift")
	}
}

func TestSetupBrokerBoundaryLazyConstructorDoesNotCreateMissingAttemptDirectory(t *testing.T) {
	f := setupBrokerBoundaryNew(t)
	if err := os.Remove(f.attempts); err != nil {
		t.Fatal("empty synthetic attempts removal failed")
	}
	owner, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := newSetupGitHubPermissionSession(owner, f.configuration, f.getenv, githubadapter.SystemBrokerClock{})
	if err != nil || s == nil {
		t.Fatal("pure lazy constructor performed filesystem admission")
	}
	defer func() {
		if s.Close() != nil {
			t.Error("idle cleanup failed")
		}
	}()
	setupBrokerBoundaryIdle(t, s)
	if _, err := os.Lstat(f.attempts); !os.IsNotExist(err) {
		t.Fatal("constructor created attempts directory")
	}
	f.effects(t, 0, 0, 0)
	f.mu.Lock()
	reads := len(f.reads)
	f.mu.Unlock()
	if reads != 0 {
		t.Fatal("constructor read environment")
	}
	if err := s.Close(); err != nil {
		t.Fatal("idle no-resource Close failed")
	}
	if _, err := os.Lstat(f.attempts); !os.IsNotExist(err) {
		t.Fatal("Close created attempts directory")
	}
}
