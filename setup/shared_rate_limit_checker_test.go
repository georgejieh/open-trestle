package setup

import (
	"context"
	"errors"
	"testing"
)

type sharedRateLimitProbeFixture struct {
	identity, authority, observation string
	state                            string
	calls                            int
}

func (p *sharedRateLimitProbeFixture) ConfigurationIdentity() string { return p.identity }
func (p *sharedRateLimitProbeFixture) AuthorityIdentity() string     { return p.authority }
func (p *sharedRateLimitProbeFixture) Probe(context.Context) SharedRateLimitProbeResult {
	p.calls++
	switch p.state {
	case "valid":
		return NewVerifiedSharedRateLimitProbeResult(p.authority, p.observation)
	case "unavailable":
		return NewUnavailableSharedRateLimitProbeResult()
	default:
		return NewInvalidSharedRateLimitProbeResult()
	}
}
func planWithPostgresAuthority(t *testing.T, profile Profile) Plan {
	t.Helper()
	plan, err := NewPlan(profile, "tenant-a", "repo-a", "owner", setupTime(0))
	if err != nil {
		t.Fatal(err)
	}
	checker, _ := plan.checkerCatalog.Resolve(CheckPostgresStorageValidated)
	receipt, err := newCheckReceipt(plan, CheckPostgresStorageValidated, checker, CheckPassed, setupDigest("postgres-evidence"), RecoveryNone, setupTime(1))
	if err != nil {
		t.Fatal(err)
	}
	source := plan
	source.receipts = []CheckReceipt{receipt}
	next, ok := replayPlan(source)
	if !ok {
		t.Fatal("could not replay PostgreSQL receipt")
	}
	return next
}
func TestSharedRateLimitCheckerBindsDependencyScopeActorAndAuthority(t *testing.T) {
	plan := planWithPostgresAuthority(t, ProfileKubernetesHA)
	authority := setupDigest("rate-limit-authority")
	probe := &sharedRateLimitProbeFixture{setupDigest("probe"), authority, setupDigest("observation"), "valid", 0}
	checker, err := NewSharedRateLimitChecker(plan, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckPassed || probe.calls != 1 {
		t.Fatalf("state=%s calls=%d", result.State(), probe.calls)
	}
	other, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-b", "owner", setupTime(0))
	if result := checker.Check(context.Background(), other); result.State() != CheckBlocked || probe.calls != 1 {
		t.Fatalf("scope=%s calls=%d", result.State(), probe.calls)
	}
	changed := &sharedRateLimitProbeFixture{setupDigest("probe"), setupDigest("changed"), setupDigest("observation"), "valid", 0}
	checker, _ = NewSharedRateLimitChecker(plan, authority, "owner", changed)
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked || changed.calls != 0 {
		t.Fatalf("authority=%s calls=%d", result.State(), changed.calls)
	}
	wrongActor, err := NewSharedRateLimitChecker(plan, authority, "other", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := wrongActor.Check(context.Background(), plan); result.State() != CheckBlocked || probe.calls != 1 {
		t.Fatalf("actor=%s calls=%d", result.State(), probe.calls)
	}
	var nilProbe *sharedRateLimitProbeFixture
	if checker, err := NewSharedRateLimitChecker(plan, authority, "owner", nilProbe); checker != nil || !errors.Is(err, ErrInvalidCheckerRuntime) {
		t.Fatalf("nil checker=%#v err=%v", checker, err)
	}
}
func TestSharedRateLimitCheckerRequiresPostgresReceiptAndKubernetesProfile(t *testing.T) {
	without, _ := NewPlan(ProfileKubernetesHA, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("rate-limit-authority")
	probe := &sharedRateLimitProbeFixture{setupDigest("probe"), authority, setupDigest("observation"), "valid", 0}
	checker, err := NewSharedRateLimitChecker(without, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), without); result.State() != CheckBlocked || probe.calls != 0 {
		t.Fatalf("dependency=%s calls=%d", result.State(), probe.calls)
	}
	controlled := planWithPostgresAuthority(t, ProfileControlledHybrid)
	checker, _ = NewSharedRateLimitChecker(controlled, authority, "owner", probe)
	if result := checker.Check(context.Background(), controlled); result.State() != CheckBlocked || probe.calls != 0 {
		t.Fatalf("controlled=%s calls=%d", result.State(), probe.calls)
	}
}
func TestSharedRateLimitCheckerSeparatesOutcomesAndBindsObservation(t *testing.T) {
	plan := planWithPostgresAuthority(t, ProfileKubernetesHA)
	authority := setupDigest("rate-limit-authority")
	evidence := []string{}
	for _, test := range []struct {
		state       string
		want        CheckState
		observation string
	}{{"valid", CheckPassed, "one"}, {"valid", CheckPassed, "two"}, {"unavailable", CheckUnavailable, "three"}, {"invalid", CheckBlocked, "four"}} {
		probe := &sharedRateLimitProbeFixture{setupDigest("probe"), authority, setupDigest(test.observation), test.state, 0}
		checker, err := NewSharedRateLimitChecker(plan, authority, "owner", probe)
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
