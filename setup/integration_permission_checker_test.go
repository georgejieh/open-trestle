package setup

import (
	"context"
	"errors"
	"testing"
)

type integrationPermissionProbeFixture struct {
	identity, authority, observation string
	state                            string
	calls                            int
}

func (p *integrationPermissionProbeFixture) ConfigurationIdentity() string { return p.identity }
func (p *integrationPermissionProbeFixture) AuthorityIdentity() string     { return p.authority }
func (p *integrationPermissionProbeFixture) Probe(context.Context) IntegrationPermissionProbeResult {
	p.calls++
	switch p.state {
	case "valid":
		return NewVerifiedIntegrationPermissionProbeResult(p.authority, p.observation)
	case "unavailable":
		return NewUnavailableIntegrationPermissionProbeResult()
	default:
		return NewInvalidIntegrationPermissionProbeResult()
	}
}
func TestIntegrationPermissionCheckerBindsExactScopeAndAuthority(t *testing.T) {
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(0))
	authority, observation := setupDigest("permission"), setupDigest("observation")
	probe := &integrationPermissionProbeFixture{setupDigest("probe"), authority, observation, "valid", 0}
	checker, err := NewIntegrationPermissionChecker(plan, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckPassed || probe.calls != 1 {
		t.Fatalf("state=%s calls=%d", result.State(), probe.calls)
	}
	changed := &integrationPermissionProbeFixture{setupDigest("probe"), setupDigest("other"), observation, "valid", 0}
	checker, _ = NewIntegrationPermissionChecker(plan, authority, "owner", changed)
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked || changed.calls != 0 {
		t.Fatalf("authority=%s calls=%d", result.State(), changed.calls)
	}
	other, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-b", "owner", setupTime(0))
	if result := checker.Check(context.Background(), other); result.State() != CheckBlocked || probe.calls != 1 {
		t.Fatalf("scope=%s calls=%d", result.State(), probe.calls)
	}
}
func TestIntegrationPermissionCheckerSeparatesClosedOutcomesAndProfiles(t *testing.T) {
	plan, _ := NewPlan(ProfileKubernetesHA, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("permission")
	for _, test := range []struct {
		state string
		want  CheckState
	}{{"valid", CheckPassed}, {"unavailable", CheckUnavailable}, {"invalid", CheckBlocked}} {
		probe := &integrationPermissionProbeFixture{setupDigest("probe"), authority, setupDigest("observation"), test.state, 0}
		checker, _ := NewIntegrationPermissionChecker(plan, authority, "owner", probe)
		if result := checker.Check(context.Background(), plan); result.State() != test.want {
			t.Fatalf("%s=%s", test.state, result.State())
		}
	}
	local, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	probe := &integrationPermissionProbeFixture{setupDigest("probe"), authority, setupDigest("observation"), "valid", 0}
	checker, _ := NewIntegrationPermissionChecker(local, authority, "owner", probe)
	if result := checker.Check(context.Background(), local); result.State() != CheckBlocked || probe.calls != 0 {
		t.Fatalf("local=%s calls=%d", result.State(), probe.calls)
	}
	var nilProbe *integrationPermissionProbeFixture
	if checker, err := NewIntegrationPermissionChecker(plan, authority, "owner", nilProbe); checker != nil || !errors.Is(err, ErrInvalidCheckerRuntime) {
		t.Fatalf("nil=%#v %v", checker, err)
	}
}

func TestIntegrationPermissionCheckerEvidenceBindsObservation(t *testing.T) {
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("permission")
	evidence := []string{}
	for _, observation := range []string{setupDigest("one"), setupDigest("two")} {
		probe := &integrationPermissionProbeFixture{setupDigest("probe"), authority, observation, "valid", 0}
		checker, _ := NewIntegrationPermissionChecker(plan, authority, "owner", probe)
		evidence = append(evidence, checker.Check(context.Background(), plan).EvidenceIdentity())
	}
	if evidence[0] == evidence[1] {
		t.Fatal("observation not bound")
	}
}
