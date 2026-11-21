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
func TestIntegrationPermissionCheckerIsBlockedForLocalProfile(t *testing.T) {
	local, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("permission")
	probe := &integrationPermissionProbeFixture{setupDigest("probe"), authority, setupDigest("observation"), "valid", 0}
	checker, err := NewIntegrationPermissionChecker(local, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), local); result.State() != CheckBlocked || probe.calls != 0 {
		t.Fatalf("local=%s calls=%d", result.State(), probe.calls)
	}
	var nilProbe *integrationPermissionProbeFixture
	if checker, err := NewIntegrationPermissionChecker(local, authority, "owner", nilProbe); checker != nil || !errors.Is(err, ErrInvalidCheckerRuntime) {
		t.Fatalf("nil=%#v %v", checker, err)
	}
}
