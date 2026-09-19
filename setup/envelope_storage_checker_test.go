package setup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type envelopeStorageProbeFixture struct {
	identity, authority string
	result              EnvelopeStorageProbeResult
	calls               int
}

func (p *envelopeStorageProbeFixture) ConfigurationIdentity() string { return p.identity }
func (p *envelopeStorageProbeFixture) AuthorityIdentity() string     { return p.authority }
func (p *envelopeStorageProbeFixture) Probe(context.Context) EnvelopeStorageProbeResult {
	p.calls++
	return p.result
}
func TestEnvelopeStorageCheckerRequiresExactAuthorityBeforeProbe(t *testing.T) {
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(0))
	authority, conformance := setupDigest("envelope"), setupDigest("round-trip")
	probe := &envelopeStorageProbeFixture{setupDigest("probe"), authority, NewVerifiedEnvelopeStorageProbeResult(authority, conformance), 0}
	if strings.Contains(fmt.Sprintf("%#v", probe.result), authority) || strings.Contains(fmt.Sprintf("%#v", probe.result), conformance) {
		t.Fatal("result formatter leaked identity")
	}
	checker, err := NewEnvelopeStorageChecker(plan, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckPassed || probe.calls != 1 {
		t.Fatalf("result=%s calls=%d", result.State(), probe.calls)
	}
	other, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-b", "owner", setupTime(0))
	if result := checker.Check(context.Background(), other); result.State() != CheckBlocked || probe.calls != 1 {
		t.Fatalf("scope=%s calls=%d", result.State(), probe.calls)
	}
	changed := &envelopeStorageProbeFixture{setupDigest("probe"), setupDigest("other"), NewVerifiedEnvelopeStorageProbeResult(setupDigest("other"), conformance), 0}
	checker, _ = NewEnvelopeStorageChecker(plan, authority, "owner", changed)
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked || changed.calls != 0 {
		t.Fatalf("mismatch=%s calls=%d", result.State(), changed.calls)
	}
}
func TestEnvelopeStorageCheckerSeparatesUnavailableInvalidAndProfileMismatch(t *testing.T) {
	plan, _ := NewPlan(ProfileKubernetesHA, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("envelope")
	for _, test := range []struct {
		result EnvelopeStorageProbeResult
		want   CheckState
	}{{NewUnavailableEnvelopeStorageProbeResult(), CheckUnavailable}, {NewInvalidEnvelopeStorageProbeResult(), CheckBlocked}, {NewVerifiedEnvelopeStorageProbeResult(authority, setupDigest("round-trip")), CheckPassed}} {
		probe := &envelopeStorageProbeFixture{setupDigest("probe"), authority, test.result, 0}
		checker, _ := NewEnvelopeStorageChecker(plan, authority, "owner", probe)
		if result := checker.Check(context.Background(), plan); result.State() != test.want {
			t.Fatalf("state=%s want=%s", result.State(), test.want)
		}
	}
	local, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	probe := &envelopeStorageProbeFixture{setupDigest("probe"), authority, NewVerifiedEnvelopeStorageProbeResult(authority, setupDigest("round-trip")), 0}
	checker, _ := NewEnvelopeStorageChecker(local, authority, "owner", probe)
	if result := checker.Check(context.Background(), local); result.State() != CheckBlocked || probe.calls != 0 {
		t.Fatalf("local=%s calls=%d", result.State(), probe.calls)
	}
}

func TestEnvelopeStorageCheckerEvidenceBindsConformanceReceipt(t *testing.T) {
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("envelope")
	evidence := []string{}
	for _, conformance := range []string{setupDigest("one"), setupDigest("two")} {
		probe := &envelopeStorageProbeFixture{setupDigest("probe"), authority, NewVerifiedEnvelopeStorageProbeResult(authority, conformance), 0}
		checker, _ := NewEnvelopeStorageChecker(plan, authority, "owner", probe)
		evidence = append(evidence, checker.Check(context.Background(), plan).EvidenceIdentity())
	}
	if evidence[0] == evidence[1] {
		t.Fatal("conformance receipt not bound")
	}
}

func TestEnvelopeStorageCheckerRejectsTypedNilProbe(t *testing.T) {
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(0))
	var probe *envelopeStorageProbeFixture
	if checker, err := NewEnvelopeStorageChecker(plan, setupDigest("envelope"), "owner", probe); checker != nil || !errors.Is(err, ErrInvalidCheckerRuntime) {
		t.Fatalf("checker=%#v err=%v", checker, err)
	}
}
