package setup

import (
	"context"
	"errors"
	"testing"
)

type replicaReconciliationProbeFixture struct {
	identity, authority, observation string
	state                            string
	calls                            int
}

func (p *replicaReconciliationProbeFixture) ConfigurationIdentity() string { return p.identity }
func (p *replicaReconciliationProbeFixture) AuthorityIdentity() string     { return p.authority }
func (p *replicaReconciliationProbeFixture) Probe(context.Context) ReplicaReconciliationProbeResult {
	p.calls++
	switch p.state {
	case "valid":
		return NewVerifiedReplicaReconciliationProbeResult(p.authority, p.observation)
	case "unavailable":
		return NewUnavailableReplicaReconciliationProbeResult()
	default:
		return NewInvalidReplicaReconciliationProbeResult()
	}
}

func TestReplicaReconciliationCheckerBindsScopeActorAndAuthority(t *testing.T) {
	plan := planWithPostgresAuthority(t, ProfileKubernetesHA)
	authority := setupDigest("replica-reconciliation-authority")
	probe := &replicaReconciliationProbeFixture{setupDigest("probe"), authority, setupDigest("observation"), "valid", 0}
	checker, err := NewReplicaReconciliationChecker(plan, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckPassed || probe.calls != 1 {
		t.Fatalf("state=%s calls=%d", result.State(), probe.calls)
	}
	other, _ := NewPlan(ProfileKubernetesHA, "tenant-a", "repo-b", "owner", setupTime(0))
	if result := checker.Check(context.Background(), other); result.State() != CheckBlocked || probe.calls != 1 {
		t.Fatalf("scope=%s calls=%d", result.State(), probe.calls)
	}
	changed := &replicaReconciliationProbeFixture{setupDigest("probe"), setupDigest("changed"), setupDigest("observation"), "valid", 0}
	checker, _ = NewReplicaReconciliationChecker(plan, authority, "owner", changed)
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked || changed.calls != 0 {
		t.Fatalf("authority=%s calls=%d", result.State(), changed.calls)
	}
	wrongActor, err := NewReplicaReconciliationChecker(plan, authority, "other", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := wrongActor.Check(context.Background(), plan); result.State() != CheckBlocked || probe.calls != 1 {
		t.Fatalf("actor=%s calls=%d", result.State(), probe.calls)
	}
	var nilProbe *replicaReconciliationProbeFixture
	if checker, err := NewReplicaReconciliationChecker(plan, authority, "owner", nilProbe); checker != nil || !errors.Is(err, ErrInvalidCheckerRuntime) {
		t.Fatalf("nil checker=%#v err=%v", checker, err)
	}
}

func TestReplicaReconciliationCheckerRequiresPostgresReceiptAndKubernetesProfile(t *testing.T) {
	without, _ := NewPlan(ProfileKubernetesHA, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("replica-reconciliation-authority")
	probe := &replicaReconciliationProbeFixture{setupDigest("probe"), authority, setupDigest("observation"), "valid", 0}
	checker, err := NewReplicaReconciliationChecker(without, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), without); result.State() != CheckBlocked || probe.calls != 0 {
		t.Fatalf("dependency=%s calls=%d", result.State(), probe.calls)
	}
	controlled := planWithPostgresAuthority(t, ProfileControlledHybrid)
	checker, _ = NewReplicaReconciliationChecker(controlled, authority, "owner", probe)
	if result := checker.Check(context.Background(), controlled); result.State() != CheckBlocked || probe.calls != 0 {
		t.Fatalf("controlled=%s calls=%d", result.State(), probe.calls)
	}
}

func TestReplicaReconciliationCheckerSeparatesOutcomesAndBindsObservation(t *testing.T) {
	plan := planWithPostgresAuthority(t, ProfileKubernetesHA)
	authority := setupDigest("replica-reconciliation-authority")
	evidence := []string{}
	for _, test := range []struct {
		state       string
		want        CheckState
		observation string
	}{{"valid", CheckPassed, "one"}, {"valid", CheckPassed, "two"}, {"unavailable", CheckUnavailable, "three"}, {"invalid", CheckBlocked, "four"}} {
		probe := &replicaReconciliationProbeFixture{setupDigest("probe"), authority, setupDigest(test.observation), test.state, 0}
		checker, err := NewReplicaReconciliationChecker(plan, authority, "owner", probe)
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
