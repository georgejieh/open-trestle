package setup

import (
	"context"
	"errors"
	"testing"
)

type signedBundleProbeFixture struct {
	identity, authority, observation string
	state                            string
	calls                            int
}

func (p *signedBundleProbeFixture) ConfigurationIdentity() string { return p.identity }
func (p *signedBundleProbeFixture) AuthorityIdentity() string     { return p.authority }
func (p *signedBundleProbeFixture) Probe(context.Context) SignedBundleProbeResult {
	p.calls++
	switch p.state {
	case "valid":
		return NewVerifiedSignedBundleProbeResult(p.authority, p.observation)
	case "unavailable":
		return NewUnavailableSignedBundleProbeResult()
	default:
		return NewInvalidSignedBundleProbeResult()
	}
}

func TestSignedBundleCheckerBindsAirGappedScopeActorAndAuthority(t *testing.T) {
	plan, err := NewPlan(ProfileAirGapped, "tenant-a", "repo-a", "owner", setupTime(0))
	if err != nil {
		t.Fatal(err)
	}
	authority := setupDigest("signed-bundle-authority")
	probe := &signedBundleProbeFixture{setupDigest("probe"), authority, setupDigest("observation"), "valid", 0}
	checker, err := NewSignedBundleChecker(plan, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckPassed || probe.calls != 1 {
		t.Fatalf("state=%s calls=%d", result.State(), probe.calls)
	}
	other, _ := NewPlan(ProfileAirGapped, "tenant-a", "repo-b", "owner", setupTime(0))
	if result := checker.Check(context.Background(), other); result.State() != CheckBlocked || probe.calls != 1 {
		t.Fatalf("scope=%s calls=%d", result.State(), probe.calls)
	}
	wrongAuthority := &signedBundleProbeFixture{setupDigest("probe"), setupDigest("other"), setupDigest("observation"), "valid", 0}
	checker, _ = NewSignedBundleChecker(plan, authority, "owner", wrongAuthority)
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked || wrongAuthority.calls != 0 {
		t.Fatalf("authority=%s calls=%d", result.State(), wrongAuthority.calls)
	}
	wrongActor, _ := NewSignedBundleChecker(plan, authority, "other", probe)
	if result := wrongActor.Check(context.Background(), plan); result.State() != CheckBlocked || probe.calls != 1 {
		t.Fatalf("actor=%s calls=%d", result.State(), probe.calls)
	}
	local, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	checker, _ = NewSignedBundleChecker(local, authority, "owner", probe)
	if result := checker.Check(context.Background(), local); result.State() != CheckBlocked || probe.calls != 1 {
		t.Fatalf("profile=%s calls=%d", result.State(), probe.calls)
	}
	var nilProbe *signedBundleProbeFixture
	if checker, err := NewSignedBundleChecker(plan, authority, "owner", nilProbe); checker != nil || !errors.Is(err, ErrInvalidCheckerRuntime) {
		t.Fatalf("nil=%#v err=%v", checker, err)
	}
}

func TestSignedBundleCheckerSeparatesOutcomesAndBindsObservation(t *testing.T) {
	plan, _ := NewPlan(ProfileAirGapped, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("signed-bundle-authority")
	evidence := []string{}
	for _, test := range []struct {
		state       string
		want        CheckState
		observation string
	}{{"valid", CheckPassed, "one"}, {"valid", CheckPassed, "two"}, {"unavailable", CheckUnavailable, "three"}, {"invalid", CheckBlocked, "four"}} {
		probe := &signedBundleProbeFixture{setupDigest("probe"), authority, setupDigest(test.observation), test.state, 0}
		checker, err := NewSignedBundleChecker(plan, authority, "owner", probe)
		if err != nil {
			t.Fatal(err)
		}
		result := checker.Check(context.Background(), plan)
		if result.State() != test.want {
			t.Fatalf("%s=%s", test.state, result.State())
		}
		evidence = append(evidence, result.EvidenceIdentity())
	}
	if evidence[0] == evidence[1] {
		t.Fatal("observation was not bound")
	}
}
