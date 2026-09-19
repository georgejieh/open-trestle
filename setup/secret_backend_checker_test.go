package setup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type secretProbeFixture struct {
	identity, authority string
	result              SecretBackendProbeResult
	calls               int
}

func (p *secretProbeFixture) ConfigurationIdentity() string { return p.identity }
func (p *secretProbeFixture) AuthorityIdentity() string     { return p.authority }
func (p *secretProbeFixture) Probe(context.Context) SecretBackendProbeResult {
	p.calls++
	return p.result
}
func TestSecretBackendCheckerBindsScopeActorAndKMSAuthority(t *testing.T) {
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("kms")
	probe := &secretProbeFixture{identity: setupDigest("probe"), authority: authority, result: NewVerifiedSecretBackendProbeResult(authority)}
	if strings.Contains(fmt.Sprintf("%#v", probe.result), authority) {
		t.Fatal("result formatter leaked authority")
	}
	checker, err := NewSecretBackendChecker(plan, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckPassed || probe.calls != 1 {
		t.Fatalf("result=%s calls=%d", result.State(), probe.calls)
	}
	other, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-b", "owner", setupTime(0))
	if result := checker.Check(context.Background(), other); result.State() != CheckBlocked {
		t.Fatalf("scope=%s", result.State())
	}
	denied, _ := NewSecretBackendChecker(plan, authority, "other", probe)
	if result := denied.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("actor=%s", result.State())
	}
}
func TestSecretBackendCheckerSeparatesClosedOutcomes(t *testing.T) {
	plan, _ := NewPlan(ProfileKubernetesHA, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("kms")
	for _, test := range []struct {
		probeAuthority string
		result         SecretBackendProbeResult
		want           CheckState
		wantCalls      int
	}{{authority, NewUnavailableSecretBackendProbeResult(), CheckUnavailable, 1}, {authority, NewInvalidSecretBackendProbeResult(), CheckBlocked, 1}, {setupDigest("other"), NewVerifiedSecretBackendProbeResult(setupDigest("other")), CheckBlocked, 0}} {
		probe := &secretProbeFixture{identity: setupDigest("probe"), authority: test.probeAuthority, result: test.result}
		checker, _ := NewSecretBackendChecker(plan, authority, "owner", probe)
		if result := checker.Check(context.Background(), plan); result.State() != test.want || probe.calls != test.wantCalls {
			t.Fatalf("state=%s want=%s calls=%d", result.State(), test.want, probe.calls)
		}
	}
}
func TestSecretBackendCheckerRejectsLocalAndMutableOrNilProbe(t *testing.T) {
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("kms")
	probe := &secretProbeFixture{identity: setupDigest("probe"), authority: authority, result: NewVerifiedSecretBackendProbeResult(authority)}
	checker, _ := NewSecretBackendChecker(plan, authority, "owner", probe)
	probe.identity = setupDigest("changed")
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked || probe.calls != 0 {
		t.Fatalf("mutable=%s calls=%d", result.State(), probe.calls)
	}
	local, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	fresh := &secretProbeFixture{identity: setupDigest("probe"), authority: authority, result: NewVerifiedSecretBackendProbeResult(authority)}
	checker, _ = NewSecretBackendChecker(local, authority, "owner", fresh)
	if result := checker.Check(context.Background(), local); result.State() != CheckBlocked || fresh.calls != 0 {
		t.Fatalf("local=%s calls=%d", result.State(), fresh.calls)
	}
	var nilProbe *secretProbeFixture
	if checker, err := NewSecretBackendChecker(plan, authority, "owner", nilProbe); !errors.Is(err, ErrInvalidCheckerRuntime) || checker != nil {
		t.Fatalf("nil=%#v %v", checker, err)
	}
}

func TestSecretBackendCheckerZeroValueFailsClosed(t *testing.T) {
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(0))
	if result := new(SecretBackendChecker).Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("state=%s", result.State())
	}
}
