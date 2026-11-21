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
func TestWebhookCheckerIsBlockedForLocalProfile(t *testing.T) {
	local, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("webhook-authority")
	probe := &webhookProbeFixture{setupDigest("probe"), authority, setupDigest("observation"), "valid", 0}
	checker, err := NewWebhookChecker(local, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), local); result.State() != CheckBlocked || probe.calls != 0 {
		t.Fatalf("local=%s calls=%d", result.State(), probe.calls)
	}
	var nilProbe *webhookProbeFixture
	if checker, err := NewWebhookChecker(local, authority, "owner", nilProbe); checker != nil || !errors.Is(err, ErrInvalidCheckerRuntime) {
		t.Fatalf("nil checker=%#v err=%v", checker, err)
	}
}
