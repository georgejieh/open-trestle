package setup

import (
	"context"
	"errors"
	"testing"
)

type webhookProbeFixture struct {
	identity, authority, observation string
	state                            string
	calls                            int
}

func (p *webhookProbeFixture) ConfigurationIdentity() string { return p.identity }
func (p *webhookProbeFixture) AuthorityIdentity() string     { return p.authority }
func (p *webhookProbeFixture) Probe(context.Context) WebhookProbeResult {
	p.calls++
	switch p.state {
	case "valid":
		return NewVerifiedWebhookProbeResult(p.authority, p.observation)
	case "unavailable":
		return NewUnavailableWebhookProbeResult()
	default:
		return NewInvalidWebhookProbeResult()
	}
}
func planWithIntegrationPermission(t *testing.T, profile Profile) Plan {
	t.Helper()
	plan, err := NewPlan(profile, "tenant-a", "repo-a", "owner", setupTime(0))
	if err != nil {
		t.Fatal(err)
	}
	checker, _ := plan.checkerCatalog.Resolve(CheckIntegrationPermissionsValidated)
	receipt, err := newCheckReceipt(plan, CheckIntegrationPermissionsValidated, checker, CheckPassed, setupDigest("integration-permission-evidence"), RecoveryNone, setupTime(1))
	if err != nil {
		t.Fatal(err)
	}
	source := plan
	source.receipts = []CheckReceipt{receipt}
	next, ok := replayPlan(source)
	if !ok {
		t.Fatal("could not replay permission receipt")
	}
	return next
}
func TestWebhookCheckerBindsDependencyScopeActorAndAuthority(t *testing.T) {
	plan := planWithIntegrationPermission(t, ProfileControlledHybrid)
	authority := setupDigest("webhook-authority")
	probe := &webhookProbeFixture{setupDigest("probe"), authority, setupDigest("observation"), "valid", 0}
	checker, err := NewWebhookChecker(plan, authority, "owner", probe)
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
	changed := &webhookProbeFixture{setupDigest("probe"), setupDigest("changed"), setupDigest("observation"), "valid", 0}
	checker, _ = NewWebhookChecker(plan, authority, "owner", changed)
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked || changed.calls != 0 {
		t.Fatalf("authority=%s calls=%d", result.State(), changed.calls)
	}
	wrongActor, err := NewWebhookChecker(plan, authority, "other", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := wrongActor.Check(context.Background(), plan); result.State() != CheckBlocked || probe.calls != 1 {
		t.Fatalf("actor=%s calls=%d", result.State(), probe.calls)
	}
	var nilProbe *webhookProbeFixture
	if checker, err := NewWebhookChecker(plan, authority, "owner", nilProbe); checker != nil || !errors.Is(err, ErrInvalidCheckerRuntime) {
		t.Fatalf("nil checker=%#v err=%v", checker, err)
	}
}
func TestWebhookCheckerRequiresPermissionReceiptAndSupportedProfile(t *testing.T) {
	without, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("webhook-authority")
	probe := &webhookProbeFixture{setupDigest("probe"), authority, setupDigest("observation"), "valid", 0}
	checker, err := NewWebhookChecker(without, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), without); result.State() != CheckBlocked || probe.calls != 0 {
		t.Fatalf("dependency=%s calls=%d", result.State(), probe.calls)
	}
	local, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	checker, _ = NewWebhookChecker(local, authority, "owner", probe)
	if result := checker.Check(context.Background(), local); result.State() != CheckBlocked || probe.calls != 0 {
		t.Fatalf("local=%s calls=%d", result.State(), probe.calls)
	}
}
func TestWebhookCheckerSeparatesOutcomesAndBindsObservation(t *testing.T) {
	plan := planWithIntegrationPermission(t, ProfileKubernetesHA)
	authority := setupDigest("webhook-authority")
	evidence := []string{}
	for _, test := range []struct {
		state       string
		want        CheckState
		observation string
	}{{"valid", CheckPassed, "one"}, {"valid", CheckPassed, "two"}, {"unavailable", CheckUnavailable, "three"}, {"invalid", CheckBlocked, "four"}} {
		probe := &webhookProbeFixture{setupDigest("probe"), authority, setupDigest(test.observation), test.state, 0}
		checker, err := NewWebhookChecker(plan, authority, "owner", probe)
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
