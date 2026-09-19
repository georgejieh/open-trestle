package setup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type postgresProbeFixture struct {
	identity string
	result   PostgresStorageProbeResult
	calls    int
}

func (p *postgresProbeFixture) ConfigurationIdentity() string { return p.identity }
func (p *postgresProbeFixture) Probe(context.Context) PostgresStorageProbeResult {
	p.calls++
	return p.result
}
func TestPostgresStorageCheckerBindsScopeActorAuthorityAndProbe(t *testing.T) {
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("database-authority")
	probe := &postgresProbeFixture{identity: setupDigest("probe"), result: NewVerifiedPostgresStorageProbeResult(authority)}
	checker, err := NewPostgresStorageChecker(plan, authority, "owner", probe)
	if err != nil {
		t.Fatal(err)
	}
	first := checker.Check(context.Background(), plan)
	second := checker.Check(context.Background(), plan)
	if first.State() != CheckPassed || first.EvidenceIdentity() != second.EvidenceIdentity() || probe.calls != 2 {
		t.Fatalf("results=%#v %#v calls=%d", first, second, probe.calls)
	}
	if strings.Contains(fmt.Sprintf("%#v", probe.result), authority) {
		t.Fatal("probe result leaked authority")
	}
	if strings.Contains(fmt.Sprintf("%#v", checker), authority) || strings.Contains(fmt.Sprintf("%#v", checker), "tenant-a") {
		t.Fatal("checker formatter leaked authority")
	}
	other, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-b", "owner", setupTime(0))
	if result := checker.Check(context.Background(), other); result.State() != CheckBlocked {
		t.Fatalf("scope=%s", result.State())
	}
	denied, _ := NewPostgresStorageChecker(plan, authority, "other", probe)
	if result := denied.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("actor=%s", result.State())
	}
}
func TestPostgresStorageCheckerSeparatesUnavailableInvalidAndSubstitutedAuthority(t *testing.T) {
	plan, _ := NewPlan(ProfileKubernetesHA, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("database-authority")
	for _, test := range []struct {
		result PostgresStorageProbeResult
		want   CheckState
	}{{NewUnavailablePostgresStorageProbeResult(), CheckUnavailable}, {NewInvalidPostgresStorageProbeResult(), CheckBlocked}, {NewVerifiedPostgresStorageProbeResult(setupDigest("other")), CheckBlocked}} {
		probe := &postgresProbeFixture{identity: setupDigest("probe"), result: test.result}
		checker, _ := NewPostgresStorageChecker(plan, authority, "owner", probe)
		if result := checker.Check(context.Background(), plan); result.State() != test.want {
			t.Fatalf("result=%s want=%s", result.State(), test.want)
		}
	}
}
func TestPostgresStorageCheckerRejectsLocalProfileAndMutableOrTypedNilProbe(t *testing.T) {
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(0))
	authority := setupDigest("database-authority")
	probe := &postgresProbeFixture{identity: setupDigest("probe"), result: NewVerifiedPostgresStorageProbeResult(authority)}
	checker, _ := NewPostgresStorageChecker(plan, authority, "owner", probe)
	probe.identity = setupDigest("changed")
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked || probe.calls != 0 {
		t.Fatalf("mutable=%s calls=%d", result.State(), probe.calls)
	}
	local, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	localProbe := &postgresProbeFixture{identity: setupDigest("probe"), result: NewVerifiedPostgresStorageProbeResult(authority)}
	checker, _ = NewPostgresStorageChecker(local, authority, "owner", localProbe)
	if result := checker.Check(context.Background(), local); result.State() != CheckBlocked || localProbe.calls != 0 {
		t.Fatalf("local=%s calls=%d", result.State(), localProbe.calls)
	}
	var nilProbe *postgresProbeFixture
	if checker, err := NewPostgresStorageChecker(plan, authority, "owner", nilProbe); !errors.Is(err, ErrInvalidCheckerRuntime) || checker != nil {
		t.Fatalf("nil=%#v %v", checker, err)
	}
}
