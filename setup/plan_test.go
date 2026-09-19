package setup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func setupDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func setupTime(second int) time.Time { return time.Date(2026, 9, 3, 12, 0, second, 0, time.UTC) }
func TestProfilesUseSafeEffectFreeDefaults(t *testing.T) {
	cases := map[Profile]struct {
		metadata  MetadataBackend
		artifacts ArtifactBackend
		inference InferencePosture
		egress    EgressPosture
	}{
		ProfileLocalSingleNode:  {MetadataLocal, ArtifactLocal, InferenceLocalOnly, EgressDenied},
		ProfileControlledHybrid: {MetadataPostgres, ArtifactS3, InferenceApprovedRemote, EgressAllowlisted},
		ProfileKubernetesHA:     {MetadataPostgres, ArtifactS3, InferenceApprovedRemote, EgressAllowlisted},
		ProfileAirGapped:        {MetadataLocal, ArtifactLocal, InferenceLocalOnly, EgressDenied},
	}
	for profile, want := range cases {
		plan, err := NewPlan(profile, "tenant-a", "repo-a", "platform-owner", setupTime(0))
		if err != nil {
			t.Fatalf("%s: %v", profile, err)
		}
		posture := plan.Posture()
		if posture.MetadataBackend() != want.metadata || posture.ArtifactBackend() != want.artifacts || posture.Inference() != want.inference || posture.Egress() != want.egress || posture.PublicationEnabled() || posture.DynamicValidationEnabled() || posture.ProviderFallbackEnabled() || posture.ContentLoggingAllowed() || posture.RetentionDays() != 30 || (profile == ProfileControlledHybrid || profile == ProfileKubernetesHA) && posture.MaxModelRequestCostMicroUSD() != 100_000 || (profile == ProfileLocalSingleNode || profile == ProfileAirGapped) && posture.MaxModelRequestCostMicroUSD() != 0 {
			t.Fatalf("%s posture=%#v", profile, posture)
		}
		if plan.Status() != StatusIncomplete || plan.Ready() {
			t.Fatalf("%s unexpectedly ready", profile)
		}
	}
}
func TestPlanRejectsSecretLikeOrInvalidSetupInputs(t *testing.T) {
	values := []struct{ tenant, repository, owner string }{{"../tenant", "repo-a", "owner"}, {"tenant-a", "repo/a", "owner"}, {"tenant-a", "repo-a", ""}, {"tenant-a", "repo-a", strings.Repeat("x", 129)}, {"tenant-a", "repo-a", "token=secret"}}
	for _, value := range values {
		if _, err := NewPlan(ProfileLocalSingleNode, value.tenant, value.repository, value.owner, setupTime(0)); !errors.Is(err, ErrInvalidPlan) {
			t.Fatalf("accepted %#v: %v", value, err)
		}
	}
}
func TestPlanEncodingIsCanonicalReconstructiveAndRedacted(t *testing.T) {
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "platform-owner", setupTime(0))
	encoded, err := EncodePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePlan(encoded)
	if err != nil || decoded.Identity() != plan.Identity() {
		t.Fatalf("decode=%v", err)
	}
	if strings.Contains(string(encoded), `"credential":`) || strings.Contains(string(encoded), `"endpoint":`) || strings.Contains(string(encoded), `"secret":`) || strings.Contains(string(encoded), `"token":`) {
		t.Fatalf("unsafe state: %s", encoded)
	}
	var value map[string]any
	_ = json.Unmarshal(encoded, &value)
	value["ready"] = true
	tampered, _ := json.Marshal(value)
	if _, err := DecodePlan(tampered); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("tamper=%v", err)
	}
	unknown := append(encoded[:len(encoded)-1], []byte(`,"extra":true}`)...)
	if _, err := DecodePlan(unknown); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("unknown=%v", err)
	}
}
func TestApprovedReceiptsDriveBlockedAndReadyState(t *testing.T) {
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "platform-owner", setupTime(0))
	requirements := plan.Requirements()
	catalog, err := BuiltInCheckerCatalog(plan.Profile())
	if err != nil {
		t.Fatal(err)
	}
	authorities := make([]CheckerAuthority, 0, len(requirements))
	for _, requirement := range requirements {
		if checker, found := catalog.Resolve(requirement.Key()); found {
			authorities = append(authorities, CheckerAuthority{Key: requirement.Key(), CheckerIdentity: checker})
		}
	}
	first := authorities[0]
	blocked, err := newCheckReceipt(plan, first.Key, first.CheckerIdentity, CheckBlocked, setupDigest("blocked"), RecoveryConfigureDependency, setupTime(1))
	if err != nil {
		t.Fatal(err)
	}
	plan, err = applyCheckReceipt(plan, blocked, catalog)
	if err != nil || plan.Status() != StatusBlocked || plan.Ready() {
		t.Fatalf("blocked=%v status=%s", err, plan.Status())
	}
	for index, authority := range authorities {
		receipt, receiptErr := newCheckReceipt(plan, authority.Key, authority.CheckerIdentity, CheckPassed, setupDigest(fmt.Sprintf("evidence-%d", index)), RecoveryNone, setupTime(index+2))
		if receiptErr != nil {
			t.Fatal(receiptErr)
		}
		plan, err = applyCheckReceipt(plan, receipt, catalog)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !plan.Ready() || plan.Status() != StatusReady || plan.Revision() != uint64(len(authorities)+2) {
		t.Fatalf("status=%s ready=%v revision=%d", plan.Status(), plan.Ready(), plan.Revision())
	}
	encoded, encodeErr := EncodePlan(plan)
	decoded, decodeErr := DecodePlan(encoded)
	if encodeErr != nil || decodeErr != nil || !decoded.Ready() || len(decoded.Receipts()) != len(authorities)+1 {
		t.Fatalf("ready replay encode=%v decode=%v", encodeErr, decodeErr)
	}
}
func TestReceiptRejectsUnapprovedCheckerAndStalePlan(t *testing.T) {
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "platform-owner", setupTime(0))
	key := pendingRequirement(t, plan)
	catalog, _ := BuiltInCheckerCatalog(plan.Profile())
	checker, _ := catalog.Resolve(key)
	receipt, _ := newCheckReceipt(plan, key, setupDigest("other"), CheckPassed, setupDigest("evidence"), RecoveryNone, setupTime(1))
	if _, err := applyCheckReceipt(plan, receipt, catalog); !errors.Is(err, ErrCheckNotAuthorized) {
		t.Fatalf("authority=%v", err)
	}
	receipt, _ = newCheckReceipt(plan, key, checker, CheckPassed, setupDigest("evidence"), RecoveryNone, setupTime(1))
	next, err := applyCheckReceipt(plan, receipt, catalog)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applyCheckReceipt(next, receipt, catalog); !errors.Is(err, ErrStaleCheckReceipt) {
		t.Fatalf("stale=%v", err)
	}
}
func pendingRequirement(t *testing.T, plan Plan) CheckKey {
	t.Helper()
	for _, r := range plan.Requirements() {
		if r.State() == CheckPending {
			return r.Key()
		}
	}
	t.Fatal("no pending requirement")
	return ""
}

func TestCheckReceiptEncodingIsStrictAndReconstructive(t *testing.T) {
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	key := pendingRequirement(t, plan)
	receipt, _ := newCheckReceipt(plan, key, setupDigest("checker"), CheckBlocked, setupDigest("evidence"), recoveryForKey(key), setupTime(1))
	encoded, err := EncodeCheckReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCheckReceipt(encoded)
	if err != nil || decoded.Identity() != receipt.Identity() {
		t.Fatalf("decode=%v", err)
	}
	unknown := append(encoded[:len(encoded)-1], []byte(`,"extra":true}`)...)
	if _, err := DecodeCheckReceipt(unknown); !errors.Is(err, ErrInvalidCheckReceipt) {
		t.Fatalf("unknown=%v", err)
	}
}

func TestSetupTimesAreCanonicalizedToUTCMilliseconds(t *testing.T) {
	raw := time.Date(2026, 9, 3, 8, 0, 0, 123456789, time.FixedZone("offset", -4*60*60))
	plan, err := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", raw)
	if err != nil || plan.CreatedAt().Location() != time.UTC || plan.CreatedAt().Nanosecond() != 123000000 {
		t.Fatalf("plan time=%s err=%v", plan.CreatedAt(), err)
	}
	key := pendingRequirement(t, plan)
	receipt, err := newCheckReceipt(plan, key, setupDigest("checker"), CheckPassed, setupDigest("evidence"), RecoveryNone, raw.Add(time.Second))
	if err != nil || receipt.CheckedAt().Location() != time.UTC || receipt.CheckedAt().Nanosecond() != 123000000 {
		t.Fatalf("receipt time=%s err=%v", receipt.CheckedAt(), err)
	}
}

func TestPlanBindsExactCheckerCatalog(t *testing.T) {
	_, specs, _ := profileDefaults(ProfileLocalSingleNode)
	firstAuthorities := make([]CheckerAuthority, len(specs))
	secondAuthorities := make([]CheckerAuthority, len(specs))
	for i, spec := range specs {
		firstAuthorities[i] = CheckerAuthority{Key: spec.key, CheckerIdentity: setupDigest("first-" + string(spec.key))}
		secondAuthorities[i] = CheckerAuthority{Key: spec.key, CheckerIdentity: setupDigest("second-" + string(spec.key))}
	}
	first, _ := NewCheckerCatalog(firstAuthorities)
	second, _ := NewCheckerCatalog(secondAuthorities)
	plan, err := NewPlanWithCheckerCatalog(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", first, setupTime(0))
	if err != nil || plan.CheckerCatalogIdentity() != first.Identity() || first.Identity() == second.Identity() {
		t.Fatalf("plan=%v", err)
	}
	key := pendingRequirement(t, plan)
	checker, _ := second.Resolve(key)
	receipt, _ := newCheckReceipt(plan, key, checker, CheckPassed, setupDigest("evidence"), RecoveryNone, setupTime(1))
	if _, err := applyCheckReceipt(plan, receipt, second); !errors.Is(err, ErrCheckNotAuthorized) {
		t.Fatalf("swapped catalog=%v", err)
	}
}

func TestPlanCannotClaimReadyWithoutReplayableApprovedReceipts(t *testing.T) {
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	for i, r := range plan.requirements {
		if r.source != CheckDeterministic {
			r.state = CheckPassed
			r.checkerIdentity = setupDigest("checker-" + string(r.key))
			r.evidenceIdentity = setupDigest("evidence-" + string(r.key))
			r.receiptIdentity = setupDigest("receipt-" + string(r.key))
			r.checkedAt = setupTime(1)
			plan.requirements[i] = r
		}
	}
	plan.revision = 2
	plan.previousIdentity = setupDigest("previous")
	plan.updatedAt = setupTime(1)
	plan.status = StatusReady
	plan.ready = true
	plan.identity = planIdentity(plan)
	if plan.Validate() == nil {
		t.Fatal("fabricated ready plan validated")
	}
	encoded, _ := json.Marshal(wirePlan(plan, true))
	if _, err := DecodePlan(encoded); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("decode=%v", err)
	}
}

func TestLocalInferenceFollowsPolicyAuthorityInSetupOrder(t *testing.T) {
	for _, profile := range []Profile{ProfileLocalSingleNode, ProfileAirGapped} {
		plan, err := NewPlan(profile, "tenant-a", "repo-a", "owner", setupTime(0))
		if err != nil {
			t.Fatal(err)
		}
		positions := map[CheckKey]int{}
		for index, requirement := range plan.Requirements() {
			positions[requirement.Key()] = index
		}
		if positions[CheckPolicyValidated] >= positions[CheckLocalInferenceValidated] || positions[CheckLocalInferenceValidated] >= positions[CheckDryRunValidated] {
			t.Fatalf("%s order=%v", profile, positions)
		}
	}
}
