package setup

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
	"time"
)

const currentCatalogBoundaryIntegrationIdentity = "8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9"

// Historical ledger fixtures do not establish live issuer observations or
// permission grants. The capture source is not part of normal CI.
const currentCatalogBoundaryHistorySHA256 = "016de20e8ed85dcc68192a635b0a46514fb7e198185ade99ffbca6102915e400"
const currentCatalogBoundaryHistoryGZIPBase64 = "H4sIAAAAAAACA+29aW/bypot/L1/ReN8vu7LKs5voz/YW0MkHFKQNiWafNFocDRFkY4RO5HEi/vf71ol27GdyPEcHyPnwDuJTJHF" +
	"qmdYz/x//u3f//0f2efTiy9JdvGP/+/f//H5rDg9uPhSnF80xf8++7L8llwUB2elOGiKkyTbHmTJ2cXXL8U//he/eJ5VRZv8z7fi" +
	"y/ny8ym+LtTHzbJdXpzzbhdfvp5fFDm+nJ8UXw6+ni4vDtTTPjfn/3n6+eLgNLlYfisOlufnX/H7sy+fP5f/eVF9KYqry/DNg2qb" +
	"flnmB+Vyw0ef/yf+gk/nwV8HF8u2OEhO8YAkLXBLvMTXpDmYfT09xe3+vsDiB8uGN8uL7Pw/8W758vTkIN0eFJus+XrOZ581yenB" +
	"+UVywt+UybLBM/6zTTbL9mt7oMuDL0VWLM8uzg/OcMvLNVz/XmiGY9rWQZucLktsGm59UZzvdudqvdiI/x///vd//z/qv/jNadIW" +
	"3J4vRZJv/6M+x979r6vfcTn43dW191/NM6gSaVr8fWmKvBSlXiSpqxuZY6elluamlLaRm5mZpalwhJ4WhZ2LpJCpLBwpLZnqdmrY" +
	"dmHcvOsyL04vlhdb3he/tITmujLXRFm6epKZwpC5rbuWmwrddC2jKBNN2qaep0aRS01P8yzP3cwxZanbN++72x7ctNiO61SaWtYO" +
	"6vyvkTVq3XUcGhf5p3GT6bPz+G+3i49nIvtLrNPh4OtouV5m0v8ch6I61uMmO/XPUmksJ3X/fNQ2qzg0teR4Zo7qz0u/l+l+3V9P" +
	"gtU27h1u4jYyPTmo/aCvee1U97qVnISjjdfNTb+eNXHbX3t1Jjw5W/rDxcqrD7uondXxcGpG3Ynw2qjzt6Pz0enRNj6Oz1J90R3L" +
	"28+MgkzgWVtvGBmexPWdp0fdyIjaSPO7aefVfXzeF34wN6Ngrk2CE8PrDVqv16wiGelxsGg9fObXh4Yv+2t13d94Zst39r/Ex+My" +
	"kgMtCjffYuGexcPF13zYaMXf2Lvarya9qo7qeBXV4xW+L6PaX07CRRUHVRUFnoyDWR0F48rrrTb+cC6jcCq8wMP6RmYczLd+byW9" +
	"Xr7ygnHt95qlF0bLf/41rpPhok7kYnssByIfVt+yttGScNGN6rMUZ4h1rZaT5XgZYY358VGZt4PzJJxVOfaRZxbJqonkRZM1d9eM" +
	"PQ5mK783MuJ6ZEzCMd5hsYravhF1s9YLR3o8nLVRGNfYPzHp+atJ4OFMT6Q/xP62fu23i3bSW239Otr47Uj63WpZ/r2xRy2EF5/R" +
	"zrbFwt3mofmIdYEWukMNewZ6xPq6lYEffHZixKAnT4J+5Kz1e/2NH44MPxhJr/Y2fj3dxMORiOp+h/s1k3C6xpm0WLMRD6M768Lz" +
	"2sV5qh81x7qvpfq4iuXi4Wts+6DhSMY1njGcd14vXsW9bO13oL+ub0ZtXMW9k87jLnWDxpdz08M5+1209odT0P64wbqw7tUmCo6W" +
	"k6Cq43B0Z40Nnrc4BX/ivN2vx1hr1oozcBb4zuzAg1U6BO0eg3/+uk2neIcmPZ2d5Z8UbdRxjdViD6NwJOKgv4nCaOP1ZlVU57Uv" +
	"Z7U/jJeKJ3qLZTz0wQcLnDX4qz7ZgA+wzqr1hp4BuhWkBa87Wo5OtfMb9HeeSr9KB24VD8VZ2jYd5Aj20d0+Yp0tzrgDr4OPT/CD" +
	"N+2m20lw1E6GI3D0iREFoDvwwwRrioPIiCRkBfZ7MoxXfhuDvyLQTbP0IW8mod/gPuaddX6LTn3IrphnWmftYidDwsE59vcb5J7A" +
	"Z4+g1VkV14vKw7PxTiu/bpqoOwTf9GXcxku/Bk/XffDOaB114+UEe+7VI+wf6CaYd1ixob4PGqYMgBwS4MfbdHB69A37V4OPIDM2" +
	"eP5Ai8PpHdlwR/4GkekPsZ7hrKEM8uvBEuevR3VT83yxT5A9kT4ZeuAnPDOcm5DV4K85eDtuomCKcz7Euhc19r2b9OLK/2vs/vPT" +
	"+RLPU8/Ihm6XD3PIY7/EvkEuDU7jR6wRPCknwz6e6UPmzEFnDegO+9E70cDLmhccVT75pNeHbJ5DVh1hf090r4drce7xcK5Pekc4" +
	"/0yLW3/pBXnr3V1ju7hI9Rl4/Gib6jHP7qYctX61Ri9YgY4WDe8PvoE8meLfgwZyCbQFfpYj0+sg99sR5HfV+CFkUm8OfUU+8uQk" +
	"yJeenIPfpzrkpojrWe39fWeNckE61I7luCKNpe3sEfQH3g4gG4NoG4fUWScyktjT4WjN84d8h+zpb2Kcb9xC3nSHXRzkjUfZ3ZG/" +
	"fOxfTL0M2XSC8/bMH2Tlad5EbfUtlRePWNdKi+qTDjqJugP6JNvwnP0e13so/drbRuAd7Bv09BH4frGEzKzBGxL4YBtBZkImklc6" +
	"7jPWTp25LBcaMMC4ySFfKBOxfxsP68B6vkY4N57fjjajzT8hb9J28DWnzMF3SK8412/ZaQO5M6UsWMd1/wJ7v04hUymrir9310bS" +
	"lZBP5rF09bRdbK/vGV7+m1jo0/hb3DbASZTV/jfIsW0qN+egjTL51ID2GrVHik8+Lba8DnLoApiqIn9EC1fpbNDb6jY/eaTJKoNc" +
	"jInNBneu6374/TprXfCbr13uyRLXyhg4JRsuSvy9xjuvr84sxbVJGJ8Ryyi9ck13uz3BXmixjv0i3oIOivG+vMfuPQdrvjd05+oY" +
	"16QhnqswEvXUosN3eM15OsQ+DaEDLp+Z4GziMN9CB+wwI/RFHA663dobmYSbhvoX+PJCrTEcGMdSfANNnfM52fGCmBT4y+V3LpLQ" +
	"36bCFZmcEn+uvd7h2vtrTX7XdvKc7zWrCuzlpPbW2C/ukaS+Aa0C02zOI+xdIlzSyDLlOuszft7Ff5OuXerer3gW9Fp+ivWfQm6o" +
	"96LMmEC/p5/8hvfNwzF4wgdPNN/S5uf3iz81oE9xFonv8nG3RtIt9+L7Pcu/1Xts8rDBvgvqx7tYj+/Scs+AXRo8q77a50xiT1q/" +
	"2clX7MXxGHtlAjPMziKFn32NenhHb4MOsud+Pl6qs1X7luK+d+Wjema7gO4DfQ1+8t1bvARa5R4tr+57iQPAL9Exae+u3vPrHT7b" +
	"4YcP937AzuAtxb/kufx4jOdvvnGdCied+t/w2SXfzRqc8TYNm6/JMflcyQDw10CLdxihgjT/Bb4a8TuUnSvFz4t977M4yz7NfvZd" +
	"0KNP3iemryL9ipdHN3XoCvugqb27jbtufvdbLk2eBXniI77rdxkqKNPdbRTmzQ84+OY7w65N5bhR9KZTv87VfaJjv/s9OOp+voBN" +
	"CNtgCpsCeDKY636QdXE7Aj7yNpTFwCKmF0wN2GfAkScGn+33IujbKda3Asb060kPmKXua/4Qe8Cfv+47k3FDe1M9D7aWD1wQ1VPY" +
	"VJHuDaeGF2TbqAVmlX3YB37lSdiiwXQTdQtgm3wZEXPXmYTchS3uw2Y96Xw51a74O1X+jKaMbujQm3Ijhl2jfCT1aO3V0QVsePzE" +
	"c+B2C++Ln0Fyhwaw9hiy2V2D9l6dBiLsv1/j9HqHoANv7be0mw9xxqPOgz0EnLDC2XTA+roXznXa0VG90v36UIt7EexV2KddBFtr" +
	"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" +
	"NhWLpf0u2uymah+xOThkCPiatLZ3uqnyW1eqJSrkFe67jLqmjlp8xk6C9Vx63Ur3h367q0ZktT87MNCXGOO6SPM7TlxXjdx0Fglf" +
	"Tml+akbW/spDyeYrnulRbofzjRdCvgaHnJqtQ6atGCeC7BNqHEnLkDX3akUfouGx6LtmbInTBWccZaKpScNPK6TWfeVr91deL2JF" +
	"m/CH0TYOfMYw2jgYtL6knjjZTFiZKdm/Ol5NOP11yH7SFX3ekL+HjCUJnKnBdrgvOxblh0lS4DHQ7/HROX0Vl8+qYr7PDV/Tq02U" +
	"etA0qZ+Fpf9VMmturflPVs2frJo/WTV/smp+OXMqMcrSsfRSuoV0U2GnhXCyHNLJKkrp2OBMs3SFTCwzLUrXsjXTyU0nNczcldLM" +
	"f92SxrULaRa55TqWZthlluiZ5bqladpphv8kuWmZdmGaUph66kjDMF2zMAqwrA4Ba6V7WtI8c9m/syUNyIoN48DI20kIFmPPJ1Xj" +
	"XNWM9LO+nhkoIDVo6gVQT3/LCHXE7BKwPmvDVXvaekp0sfXqxWp/S5qR5rPXRD3iEDuVkQNW2qhxd2BxzqqPWtZQZ2yevsGaNqoV" +
	"i4wk0BBEFTtj+suYze+Cwy1b2YC9jD9N59606dxN1sd///vf/u+//T+gnGXwv3UBAA=="

func currentCatalogBoundaryDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func currentCatalogBoundaryTime() time.Time {
	return time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
}

type currentCatalogBoundaryClock struct{}

func (currentCatalogBoundaryClock) Now() time.Time {
	return currentCatalogBoundaryTime().Add(time.Second)
}
func currentCatalogBoundaryNewPlan(t *testing.T, profile Profile) Plan {
	t.Helper()
	plan, err := NewCurrentPlan(profile, "pf1-tenant", "pf1-repository", "pf1-owner", currentCatalogBoundaryTime())
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
func currentCatalogBoundaryState(t *testing.T, plan Plan) (*StateFile, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "plan.json")
	state, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err = state.Initialize(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	return state, path
}
func currentCatalogBoundaryRunner(t *testing.T, state *StateFile, checker Checker) *Runner {
	t.Helper()
	runner, err := NewRunner(state, []Checker{checker}, currentCatalogBoundaryClock{})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}
func currentCatalogBoundaryRun(t *testing.T, state *StateFile, plan Plan, checker Checker) (Plan, CheckReceipt) {
	t.Helper()
	next, receipt, err := currentCatalogBoundaryRunner(t, state, checker).RunExpected(context.Background(), checker.Key(), plan.Identity())
	if err != nil || receipt.State() != CheckPassed || next.Validate() != nil {
		t.Fatalf("positive ledger transition failed: %v", err)
	}
	return next, receipt
}
func currentCatalogBoundaryAuthority(t *testing.T, plan Plan, key CheckKey) string {
	t.Helper()
	for _, a := range plan.CheckerAuthorities() {
		if a.Key == key {
			return a.CheckerIdentity
		}
	}
	t.Fatalf("missing authority %s", key)
	return ""
}
func currentCatalogBoundaryRequirement(t *testing.T, plan Plan, key CheckKey) Requirement {
	t.Helper()
	for _, r := range plan.Requirements() {
		if r.Key() == key {
			return r
		}
	}
	t.Fatalf("missing requirement %s", key)
	return Requirement{}
}

// Ledger controls deliberately do not prove real dependency readiness.
type currentCatalogBoundaryChecker struct {
	key      CheckKey
	identity string
	calls    int
}

func (c *currentCatalogBoundaryChecker) Key() CheckKey           { return c.key }
func (c *currentCatalogBoundaryChecker) CheckerIdentity() string { return c.identity }
func (c *currentCatalogBoundaryChecker) Check(context.Context, Plan) CheckResult {
	c.calls++
	return NewPassedCheckResult(currentCatalogBoundaryDigest([]byte("ledger-control:" + string(c.key))))
}

type currentCatalogBoundaryPermissionProbe struct {
	identity, authority, observation string
	calls                            int
}

func (p *currentCatalogBoundaryPermissionProbe) ConfigurationIdentity() string { return p.identity }
func (p *currentCatalogBoundaryPermissionProbe) AuthorityIdentity() string     { return p.authority }
func (p *currentCatalogBoundaryPermissionProbe) Probe(context.Context) IntegrationPermissionProbeResult {
	p.calls++
	return NewVerifiedIntegrationPermissionProbeResult(p.authority, p.observation)
}
func currentCatalogBoundaryProbe() *currentCatalogBoundaryPermissionProbe {
	return &currentCatalogBoundaryPermissionProbe{
		identity:    currentCatalogBoundaryDigest([]byte("unit-permission-configuration")),
		authority:   currentCatalogBoundaryDigest([]byte("unit-permission-authority")),
		observation: currentCatalogBoundaryDigest([]byte("unit-permission-observation")),
	}
}
func currentCatalogBoundaryPermission(t *testing.T, plan Plan, probe *currentCatalogBoundaryPermissionProbe) *IntegrationPermissionChecker {
	t.Helper()
	checker, err := NewIntegrationPermissionChecker(plan, probe.authority, plan.RecoveryOwner(), probe)
	if err != nil {
		t.Fatal(err)
	}
	return checker
}

type currentCatalogBoundaryWebhookProbe struct{ calls int }

func (*currentCatalogBoundaryWebhookProbe) ConfigurationIdentity() string {
	return currentCatalogBoundaryDigest([]byte("unit-webhook-config"))
}
func (*currentCatalogBoundaryWebhookProbe) AuthorityIdentity() string {
	return currentCatalogBoundaryDigest([]byte("unit-webhook-authority"))
}
func (p *currentCatalogBoundaryWebhookProbe) Probe(context.Context) WebhookProbeResult {
	p.calls++
	return NewVerifiedWebhookProbeResult(p.AuthorityIdentity(), currentCatalogBoundaryDigest([]byte("unit-webhook-observation")))
}
func currentCatalogBoundaryWebhook(t *testing.T, plan Plan, probe *currentCatalogBoundaryWebhookProbe) *WebhookChecker {
	t.Helper()
	checker, err := NewWebhookChecker(plan, probe.AuthorityIdentity(), plan.RecoveryOwner(), probe)
	if err != nil {
		t.Fatal(err)
	}
	return checker
}

func TestCurrentCatalogBoundaryExactCatalogAndHistoricalParity(t *testing.T) {
	if got := CurrentIntegrationPermissionCheckerIdentity(); got != currentCatalogBoundaryIntegrationIdentity || got != currentCatalogBoundaryDigest([]byte("open-trestle/setup-checker/v2\x00integration_permissions_validated")) {
		t.Fatal("current integration identity drift")
	}
	for _, profile := range []Profile{ProfileLocalSingleNode, ProfileControlledHybrid, ProfileKubernetesHA, ProfileAirGapped} {
		t.Run(string(profile), func(t *testing.T) {
			historical, err := BuiltInCheckerCatalog(profile)
			if err != nil {
				t.Fatal(err)
			}
			original := historical.Authorities()
			current, err := CurrentCheckerCatalog(profile)
			if err != nil || current.Validate() != nil {
				t.Fatalf("current catalog invalid: %v", err)
			}
			expected := historical.Authorities()
			changed := 0
			for i := range expected {
				if expected[i].CheckerIdentity != currentCatalogBoundaryDigest([]byte("open-trestle/setup-checker/v1\x00"+string(expected[i].Key))) {
					t.Fatal("historical recipe changed")
				}
				if expected[i].Key == CheckIntegrationPermissionsValidated {
					expected[i].CheckerIdentity = currentCatalogBoundaryIntegrationIdentity
					changed++
				}
			}
			if !reflect.DeepEqual(current.Authorities(), expected) {
				t.Fatal("current catalog changed more than integration")
			}
			if !reflect.DeepEqual(historical.Authorities(), original) {
				t.Fatal("current catalog mutated historical catalog")
			}
			wire, err := json.Marshal(struct {
				Contract    string             `json:"contract"`
				Version     int                `json:"version"`
				Authorities []CheckerAuthority `json:"authorities"`
			}{"open-trestle/setup-checker-catalog", 1, expected})
			if err != nil {
				t.Fatal(err)
			}
			if current.Identity() != currentCatalogBoundaryDigest(append([]byte("open-trestle/setup-checker-catalog/v1\x00"), wire...)) {
				t.Fatal("catalog identity recipe changed")
			}
			currentPlan := currentCatalogBoundaryNewPlan(t, profile)
			oldPlan, err := NewPlan(profile, "pf1-tenant", "pf1-repository", "pf1-owner", currentCatalogBoundaryTime())
			if err != nil {
				t.Fatal(err)
			}
			if currentPlan.CheckerCatalogIdentity() != current.Identity() || oldPlan.CheckerCatalogIdentity() != historical.Identity() {
				t.Fatal("plan selected wrong catalog")
			}
			if changed == 0 {
				a, err := EncodePlan(oldPlan)
				if err != nil {
					t.Fatal(err)
				}
				b, err := EncodePlan(currentPlan)
				if err != nil || !bytes.Equal(a, b) {
					t.Fatal("local/air-gapped bytes changed")
				}
			} else if changed != 1 || current.Identity() == historical.Identity() || currentPlan.Identity() == oldPlan.Identity() {
				t.Fatal("integration catalog did not change exactly once")
			}
			detached := current.Authorities()
			detached[0].CheckerIdentity = currentCatalogBoundaryDigest([]byte("mutation"))
			if !reflect.DeepEqual(current.Authorities(), expected) {
				t.Fatal("catalog leaked mutable authorities")
			}
		})
	}
	if _, err := CurrentCheckerCatalog(Profile("unknown")); !errors.Is(err, ErrInvalidCheckerCatalog) {
		t.Fatalf("unknown catalog: %v", err)
	}
	for _, spec := range []struct {
		profile                   Profile
		tenant, repository, owner string
		at                        time.Time
	}{
		{Profile("unknown"), "tenant", "repo", "owner", currentCatalogBoundaryTime()},
		{ProfileControlledHybrid, "", "repo", "owner", currentCatalogBoundaryTime()},
		{ProfileControlledHybrid, "tenant", "", "owner", currentCatalogBoundaryTime()},
		{ProfileControlledHybrid, "tenant", "repo", "", currentCatalogBoundaryTime()},
		{ProfileControlledHybrid, "tenant", "repo", "owner", time.Time{}},
	} {
		if _, err := NewCurrentPlan(spec.profile, spec.tenant, spec.repository, spec.owner, spec.at); !errors.Is(err, ErrInvalidPlan) {
			t.Fatalf("invalid current plan error changed: %v", err)
		}
	}
}

func currentCatalogBoundaryConfigurationIdentity(t *testing.T, key CheckKey, value string) string {
	t.Helper()
	encoded, err := json.Marshal(struct {
		Contract string   `json:"contract"`
		Version  int      `json:"version"`
		Key      CheckKey `json:"key"`
		Value    string   `json:"value"`
	}{"open-trestle/setup-checker-configuration", 1, key, value})
	if err != nil {
		t.Fatal(err)
	}
	return currentCatalogBoundaryDigest(encoded)
}
func currentCatalogBoundaryEvidenceIdentity(t *testing.T, plan, checker, configuration, outcome string) string {
	t.Helper()
	encoded, err := json.Marshal(struct {
		Contract              string `json:"contract"`
		Version               int    `json:"version"`
		PlanIdentity          string `json:"plan_identity"`
		CheckerIdentity       string `json:"checker_identity"`
		ConfigurationIdentity string `json:"configuration_identity"`
		Outcome               string `json:"outcome"`
	}{"open-trestle/setup-check-evidence", 1, plan, checker, configuration, outcome})
	if err != nil {
		t.Fatal(err)
	}
	return currentCatalogBoundaryDigest(encoded)
}

func TestCurrentCatalogBoundaryPermissionEvidenceAndExistingApprovalFences(t *testing.T) {
	for _, historical := range []bool{false, true} {
		t.Run(fmt.Sprintf("historical=%t", historical), func(t *testing.T) {
			plan := currentCatalogBoundaryNewPlan(t, ProfileControlledHybrid)
			if historical {
				var err error
				plan, err = NewPlan(ProfileControlledHybrid, "pf1-tenant", "pf1-repository", "pf1-owner", currentCatalogBoundaryTime())
				if err != nil {
					t.Fatal(err)
				}
			}
			probe := currentCatalogBoundaryProbe()
			checker := currentCatalogBoundaryPermission(t, plan, probe)
			result := checker.Check(context.Background(), plan)
			if checker.CheckerIdentity() != currentCatalogBoundaryIntegrationIdentity || result.State() != CheckPassed || probe.calls != 1 {
				t.Fatal("direct trusted checker positive/identity changed")
			}
			configuration := currentCatalogBoundaryConfigurationIdentity(t, CheckIntegrationPermissionsValidated, plan.RootIdentity()+"\x00"+plan.TenantID()+"\x00"+plan.RepositoryID()+"\x00"+plan.RecoveryOwner()+"\x00"+plan.RecoveryOwner()+"\x00"+probe.authority+"\x00"+probe.authority+"\x00"+probe.identity)
			expected := currentCatalogBoundaryEvidenceIdentity(t, plan.Identity(), currentCatalogBoundaryIntegrationIdentity, configuration, "valid:"+probe.observation)
			legacy := currentCatalogBoundaryEvidenceIdentity(t, plan.Identity(), currentCatalogBoundaryDigest([]byte("open-trestle/setup-checker/v1\x00integration_permissions_validated")), configuration, "valid:"+probe.observation)
			if result.EvidenceIdentity() != expected || result.EvidenceIdentity() == legacy {
				t.Fatal("evidence did not bind CURRENT checker identity with unchanged recipe")
			}
			for _, mismatch := range []string{"actor", "authority", "probe-identity", "probe-authority", "tenant", "repository", "owner", "root", "profile"} {
				t.Run(mismatch, func(t *testing.T) {
					probe := currentCatalogBoundaryProbe()
					expected, actor := probe.authority, plan.RecoveryOwner()
					if mismatch == "actor" {
						actor = "other-owner"
					}
					if mismatch == "authority" {
						expected = currentCatalogBoundaryDigest([]byte("wrong-authority"))
					}
					checker, err := NewIntegrationPermissionChecker(plan, expected, actor, probe)
					if err != nil {
						t.Fatal(err)
					}
					target := plan
					tenant, repository, owner, profile, at := plan.TenantID(), plan.RepositoryID(), plan.RecoveryOwner(), plan.Profile(), plan.CreatedAt()
					switch mismatch {
					case "probe-identity":
						probe.identity = currentCatalogBoundaryDigest([]byte("changed-probe"))
					case "probe-authority":
						probe.authority = currentCatalogBoundaryDigest([]byte("changed-authority"))
					case "tenant":
						tenant = "other-tenant"
					case "repository":
						repository = "other-repository"
					case "owner":
						owner = "other-owner"
					case "root":
						at = at.Add(time.Millisecond)
					case "profile":
						profile = ProfileLocalSingleNode
					}
					if mismatch == "tenant" || mismatch == "repository" || mismatch == "owner" || mismatch == "root" || mismatch == "profile" {
						if historical {
							target, err = NewPlan(profile, tenant, repository, owner, at)
						} else {
							target, err = NewCurrentPlan(profile, tenant, repository, owner, at)
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					if result := checker.Check(context.Background(), target); result.State() != CheckBlocked || probe.calls != 0 {
						t.Fatalf("%s bypassed pre-Probe fence", mismatch)
					}
				})
			}
		})
	}
}

type currentCatalogBoundaryHistoryRecord struct {
	Name     string `json:"name"`
	SHA256   string `json:"sha256"`
	Identity string `json:"identity"`
	Bytes    []byte `json:"bytes"`
}
type currentCatalogBoundaryHistoryFixture struct {
	Name                       string                                `json:"name"`
	Plan                       currentCatalogBoundaryHistoryRecord   `json:"plan"`
	RootIdentity               string                                `json:"root_identity"`
	CatalogIdentity            string                                `json:"catalog_identity"`
	IntegrationCheckerIdentity string                                `json:"integration_checker_identity"`
	Ready                      bool                                  `json:"ready"`
	Status                     Status                                `json:"status"`
	Revision                   uint64                                `json:"revision"`
	PendingKey                 CheckKey                              `json:"pending_key"`
	PendingIdentity            string                                `json:"pending_identity"`
	Receipts                   []currentCatalogBoundaryHistoryRecord `json:"receipts"`
}

func currentCatalogBoundaryHistory(t *testing.T) []currentCatalogBoundaryHistoryFixture {
	t.Helper()
	compressed, err := base64.StdEncoding.DecodeString(currentCatalogBoundaryHistoryGZIPBase64)
	if err != nil {
		t.Fatal("invalid historical capture encoding: ", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, 1048577))
	if err != nil || len(data) > 1048576 || currentCatalogBoundaryDigest(data) != currentCatalogBoundaryHistorySHA256 {
		t.Fatal("frozen historical capture changed")
	}
	var manifest struct {
		Contract      string                                 `json:"contract"`
		SchemaVersion int                                    `json:"schema_version"`
		Limits        string                                 `json:"limits"`
		Fixtures      []currentCatalogBoundaryHistoryFixture `json:"fixtures"`
		Files         []currentCatalogBoundaryHistoryRecord  `json:"files"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Contract != "open-trestle/private-pf1-legacy-capture" || manifest.SchemaVersion != 1 || len(manifest.Fixtures) != 3 {
		t.Fatal("wrong capture contract")
	}
	for i, name := range []string{"ready.json", "pending-integration.json", "pending-webhook.json"} {
		f := manifest.Fixtures[i]
		if f.Name != name || f.Plan.Name != name || currentCatalogBoundaryDigest(f.Plan.Bytes) != f.Plan.SHA256 || len(f.Receipts) > 32 {
			t.Fatal("capture fixture mismatch")
		}
		for j, r := range f.Receipts {
			if r.Name != fmt.Sprintf("%020d-%s.receipt.json", j+2, r.Identity) || currentCatalogBoundaryDigest(r.Bytes) != r.SHA256 {
				t.Fatal("capture receipt mismatch")
			}
		}
	}
	return manifest.Fixtures
}
func currentCatalogBoundaryRestore(t *testing.T, fixture currentCatalogBoundaryHistoryFixture) (*StateFile, string, Plan) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "plan.json")
	if err := os.Mkdir(path+".receipts", 0o700); err != nil {
		t.Fatal(err)
	}
	// Copy frozen bytes, never regenerate receipts under new current code.
	if err := os.WriteFile(path, fixture.Plan.Bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, r := range fixture.Receipts {
		if err := os.WriteFile(filepath.Join(path+".receipts", r.Name), r.Bytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	plan, err := state.Current(context.Background())
	if err != nil || plan.Identity() != fixture.Plan.Identity {
		t.Fatalf("frozen historical state rejected: %v", err)
	}
	return state, path, plan
}
func currentCatalogBoundarySnapshot(t *testing.T, path string) map[string][]byte {
	t.Helper()
	names := []string{path}
	entries, err := os.ReadDir(path + ".receipts")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		names = append(names, filepath.Join(path+".receipts", e.Name()))
	}
	result := map[string][]byte{}
	for _, name := range names {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		result[name] = data
	}
	return result
}
func TestCurrentCatalogBoundaryFrozenHistoryRemainsExactAndFreshInitIsExplicit(t *testing.T) {
	for _, fixture := range currentCatalogBoundaryHistory(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			decoded, err := DecodePlan(fixture.Plan.Bytes)
			if err != nil || decoded.Validate() != nil || decoded.Identity() != fixture.Plan.Identity || decoded.RootIdentity() != fixture.RootIdentity || decoded.CheckerCatalogIdentity() != fixture.CatalogIdentity || decoded.Ready() != fixture.Ready || decoded.Status() != fixture.Status || decoded.Revision() != fixture.Revision {
				t.Fatalf("historical decode drift: %v", err)
			}
			if currentCatalogBoundaryAuthority(t, decoded, CheckIntegrationPermissionsValidated) != fixture.IntegrationCheckerIdentity || fixture.IntegrationCheckerIdentity == currentCatalogBoundaryIntegrationIdentity {
				t.Fatal("historical authority upcast")
			}
			encoded, err := EncodePlan(decoded)
			if err != nil || !bytes.Equal(encoded, fixture.Plan.Bytes) {
				t.Fatal("historical plan byte rewrite")
			}
			for _, r := range fixture.Receipts {
				receipt, err := DecodeCheckReceipt(r.Bytes)
				if err != nil || receipt.Identity() != r.Identity {
					t.Fatal("historical receipt decode drift")
				}
				encoded, err := EncodeCheckReceipt(receipt)
				if err != nil || !bytes.Equal(encoded, r.Bytes) {
					t.Fatal("historical receipt byte rewrite")
				}
			}
			state, path, plan := currentCatalogBoundaryRestore(t, fixture)
			before := currentCatalogBoundarySnapshot(t, path)
			pending, found, err := state.PendingReceipt(context.Background())
			if err != nil || found != (fixture.PendingKey != "") || found && (pending.Key() != fixture.PendingKey || pending.Identity() != fixture.PendingIdentity) {
				t.Fatal("frozen pending situation lost")
			}
			inspected, err := InspectStateFile(context.Background(), path)
			if err != nil || inspected.Identity() != plan.Identity() || !reflect.DeepEqual(before, currentCatalogBoundarySnapshot(t, path)) {
				t.Fatal("historical inspection rewrote bytes")
			}
			if fixture.Name != "ready.json" {
				return
			}
			if !plan.Ready() {
				t.Fatal("historical fixture must be fully Ready")
			}
			fresh := currentCatalogBoundaryNewPlan(t, plan.Profile())
			if fresh.Ready() || fresh.Status() != StatusIncomplete || fresh.Revision() != 1 || fresh.PreviousIdentity() != "" || len(fresh.Receipts()) != 0 || fresh.RootIdentity() == plan.RootIdentity() {
				t.Fatal("explicit new plan imported historical completion")
			}
			for _, requirement := range fresh.Requirements() {
				if requirement.Source() != CheckDeterministic && (requirement.State() != CheckPending || requirement.ReceiptIdentity() != "" || requirement.EvidenceIdentity() != "" || requirement.CheckerIdentity() != "" || !requirement.CheckedAt().IsZero()) {
					t.Fatal("new nondeterministic gate is not fresh")
				}
			}
			if err = state.Initialize(context.Background(), fresh); !errors.Is(err, ErrStateConflict) {
				t.Fatalf("fresh init overwrote old path: %v", err)
			}
			if !reflect.DeepEqual(before, currentCatalogBoundarySnapshot(t, path)) {
				t.Fatal("fresh init altered historical state")
			}
			freshState, _ := currentCatalogBoundaryState(t, fresh)
			saved, err := freshState.Current(context.Background())
			if err != nil || saved.Identity() != fresh.Identity() {
				t.Fatal("fresh protected path positive failed")
			}
		})
	}
}

func TestCurrentCatalogBoundaryRunnerRejectsHistoricalOperationsBeforeCheckOrRecovery(t *testing.T) {
	for _, fixture := range currentCatalogBoundaryHistory(t) {
		for _, key := range []CheckKey{CheckIntegrationPermissionsValidated, CheckWebhookValidated} {
			for _, expectedMode := range []string{"none", "exact", "stale"} {
				t.Run(fixture.Name+"/"+string(key)+"/"+expectedMode, func(t *testing.T) {
					state, path, plan := currentCatalogBoundaryRestore(t, fixture)
					before := currentCatalogBoundarySnapshot(t, path)
					checker := &currentCatalogBoundaryChecker{key: key, identity: currentCatalogBoundaryAuthority(t, plan, key)}
					runner := currentCatalogBoundaryRunner(t, state, checker)
					var err error
					want := ErrCheckNotAuthorized
					switch expectedMode {
					case "none":
						_, _, err = runner.Run(context.Background(), key)
					case "exact":
						_, _, err = runner.RunExpected(context.Background(), key, plan.Identity())
					case "stale":
						_, _, err = runner.RunExpected(context.Background(), key, currentCatalogBoundaryDigest([]byte("stale-plan")))
						want = ErrStateConflict
					}
					if !errors.Is(err, want) || checker.calls != 0 {
						t.Fatalf("legacy execution/recovery admitted or wrong gate order: %v calls=%d", err, checker.calls)
					}
					if !reflect.DeepEqual(before, currentCatalogBoundarySnapshot(t, path)) {
						t.Fatal("denial changed or consumed durable historical bytes")
					}
					pending, found, err := state.PendingReceipt(context.Background())
					if err != nil || found != (fixture.PendingKey != "") || found && pending.Identity() != fixture.PendingIdentity {
						t.Fatal("denial consumed historical pending receipt")
					}
					after, err := state.Current(context.Background())
					if err != nil || after.Identity() != plan.Identity() {
						t.Fatal("denial changed historical plan")
					}
				})
			}
		}
	}
}

func TestCurrentCatalogBoundaryUnrelatedHistoricalOperationRemainsExecutable(t *testing.T) {
	fixture := currentCatalogBoundaryHistory(t)[0]
	state, _, plan := currentCatalogBoundaryRestore(t, fixture)
	key := CheckBackupValidated
	checker := &currentCatalogBoundaryChecker{key: key, identity: currentCatalogBoundaryAuthority(t, plan, key)}
	runner := currentCatalogBoundaryRunner(t, state, checker)
	if _, _, err := runner.RunExpected(context.Background(), key, currentCatalogBoundaryDigest([]byte("stale"))); !errors.Is(err, ErrStateConflict) || checker.calls != 0 {
		t.Fatal("unrelated historical expected-plan fence changed")
	}
	next, receipt := currentCatalogBoundaryRun(t, state, plan, checker)
	if checker.calls != 1 || next.Revision() != plan.Revision()+1 || receipt.Key() != key {
		t.Fatal("blanket historical deny-all")
	}
}

// The wrapper interrupts only normal plan replacement AFTER a real Check result.
// It does not construct a receipt or seed private StateFile/Runner fields.
type currentCatalogBoundaryInterruptChecker struct {
	Checker
	t    *testing.T
	path string
	info os.FileInfo
}

func (c *currentCatalogBoundaryInterruptChecker) Check(ctx context.Context, plan Plan) CheckResult {
	result := c.Checker.Check(ctx, plan)
	if result.State() != CheckPassed {
		c.t.Fatal("pending positive control did not pass")
	}
	file, err := os.OpenFile(c.path+".next", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		c.t.Fatal(err)
	}
	marker := []byte("current-catalog-fixture-plan-staging-blocker")
	if n, err := file.Write(marker); err != nil || n != len(marker) {
		_ = file.Close()
		c.t.Fatal("blocker write failed")
	}
	c.info, err = file.Stat()
	if err != nil {
		_ = file.Close()
		c.t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		c.t.Fatal(err)
	}
	return result
}
func (c *currentCatalogBoundaryInterruptChecker) removeBlocker() {
	c.t.Helper()
	info, err := os.Lstat(c.path + ".next")
	data, readErr := os.ReadFile(c.path + ".next")
	if err != nil || readErr != nil || c.info == nil || !os.SameFile(info, c.info) || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !fileOwnedByCurrentProcess(info) || !bytes.Equal(data, []byte("current-catalog-fixture-plan-staging-blocker")) {
		c.t.Fatal("fixture blocker changed; refusing removal")
	}
	if err := os.Remove(c.path + ".next"); err != nil {
		c.t.Fatal(err)
	}
}
func TestCurrentCatalogBoundaryCurrentPendingRecoversWithoutProbe(t *testing.T) {
	for _, key := range []CheckKey{CheckIntegrationPermissionsValidated, CheckWebhookValidated} {
		t.Run(string(key), func(t *testing.T) {
			plan := currentCatalogBoundaryNewPlan(t, ProfileControlledHybrid)
			state, path := currentCatalogBoundaryState(t, plan)
			permissionProbe := currentCatalogBoundaryProbe()
			permission := currentCatalogBoundaryPermission(t, plan, permissionProbe)
			var checker Checker = permission
			webhookProbe := &currentCatalogBoundaryWebhookProbe{}
			if key == CheckWebhookValidated {
				plan, _ = currentCatalogBoundaryRun(t, state, plan, permission)
				checker = currentCatalogBoundaryWebhook(t, plan, webhookProbe)
			}
			interrupt := &currentCatalogBoundaryInterruptChecker{Checker: checker, t: t, path: path}
			_, _, err := currentCatalogBoundaryRunner(t, state, interrupt).RunExpected(context.Background(), key, plan.Identity())
			if !errors.Is(err, ErrStatePersistence) {
				t.Fatalf("pending fixture did not cross actual persistence path: %v", err)
			}
			interrupt.removeBlocker()
			pending, found, err := state.PendingReceipt(context.Background())
			if err != nil || !found || pending.Key() != key || pending.CheckerIdentity() != checker.CheckerIdentity() || pending.PlanIdentity() != plan.Identity() {
				t.Fatal("missing valid current pending receipt")
			}
			before := currentCatalogBoundarySnapshot(t, path)
			runner := currentCatalogBoundaryRunner(t, state, checker)
			if _, _, err := runner.RunExpected(context.Background(), key, currentCatalogBoundaryDigest([]byte("stale"))); !errors.Is(err, ErrStateConflict) {
				t.Fatal("pending recovery bypassed expected-plan fence")
			}
			wrong := &currentCatalogBoundaryChecker{key: key, identity: currentCatalogBoundaryDigest([]byte("wrong-checker"))}
			if _, _, err := currentCatalogBoundaryRunner(t, state, wrong).RunExpected(context.Background(), key, plan.Identity()); !errors.Is(err, ErrStateConflict) || wrong.calls != 0 {
				t.Fatal("pending recovery bypassed checker authority")
			}
			if !reflect.DeepEqual(before, currentCatalogBoundarySnapshot(t, path)) {
				t.Fatal("failed current pending approval consumed receipt")
			}
			permissionCalls, webhookCalls := permissionProbe.calls, webhookProbe.calls
			next, receipt := currentCatalogBoundaryRun(t, state, plan, checker)
			if receipt.Identity() != pending.Identity() || next.Revision() != plan.Revision()+1 || permissionProbe.calls != permissionCalls || webhookProbe.calls != webhookCalls {
				t.Fatal("current pending recovery replayed Probe or changed receipt")
			}
			if _, found, err := state.PendingReceipt(context.Background()); err != nil || found {
				t.Fatal("current receipt did not recover")
			}
			after := currentCatalogBoundarySnapshot(t, path)
			if len(after) != len(before) {
				t.Fatal("recovery duplicated ledger record")
			}
			for name, data := range before {
				if name != path && !bytes.Equal(after[name], data) {
					t.Fatal("recovery rewrote immutable receipt")
				}
			}
		})
	}
}

func TestCurrentCatalogBoundaryReplacementResetsWebhookAndRequiresNewDependency(t *testing.T) {
	plan := currentCatalogBoundaryNewPlan(t, ProfileControlledHybrid)
	state, path := currentCatalogBoundaryState(t, plan)
	// Fill unrelated readiness gates with explicitly scoped ledger controls.
	for _, requirement := range plan.Requirements() {
		key := requirement.Key()
		if requirement.Source() == CheckDeterministic || key == CheckIntegrationPermissionsValidated || key == CheckWebhookValidated {
			continue
		}
		checker := &currentCatalogBoundaryChecker{key: key, identity: currentCatalogBoundaryAuthority(t, plan, key)}
		plan, _ = currentCatalogBoundaryRun(t, state, plan, checker)
	}
	permissionProbe := currentCatalogBoundaryProbe()
	permission := currentCatalogBoundaryPermission(t, plan, permissionProbe)
	plan, firstPermission := currentCatalogBoundaryRun(t, state, plan, permission)
	webhookProbe := &currentCatalogBoundaryWebhookProbe{}
	oldWebhook := currentCatalogBoundaryWebhook(t, plan, webhookProbe)
	plan, oldWebhookReceipt := currentCatalogBoundaryRun(t, state, plan, oldWebhook)
	if !plan.Ready() || permissionProbe.calls != 1 || webhookProbe.calls != 1 {
		t.Fatal("current Ready positive control failed")
	}
	before := plan
	plan, secondPermission := currentCatalogBoundaryRun(t, state, plan, permission)
	if secondPermission.Identity() == firstPermission.Identity() || secondPermission.CheckerIdentity() != currentCatalogBoundaryIntegrationIdentity || permissionProbe.calls != 2 {
		t.Fatal("replacement did not execute real integration checker")
	}
	reset := currentCatalogBoundaryRequirement(t, plan, CheckWebhookValidated)
	if plan.Ready() || reset.State() != CheckPending || reset.ReceiptIdentity() != "" || reset.EvidenceIdentity() != "" || reset.CheckerIdentity() != "" || !reset.CheckedAt().IsZero() {
		t.Fatal("replacement retained stale webhook readiness")
	}
	for _, old := range before.Requirements() {
		if old.Key() != CheckIntegrationPermissionsValidated && old.Key() != CheckWebhookValidated && !reflect.DeepEqual(old, currentCatalogBoundaryRequirement(t, plan, old.Key())) {
			t.Fatal("replacement changed unrelated requirement")
		}
	}
	for i, r := range before.Receipts() {
		if !reflect.DeepEqual(plan.Receipts()[i], r) {
			t.Fatal("replacement rewrote historical receipt")
		}
	}
	catalog, err := CurrentCheckerCatalog(plan.Profile())
	if err != nil {
		t.Fatal(err)
	}
	diskBefore := currentCatalogBoundarySnapshot(t, path)
	if _, err = state.applyReceipt(context.Background(), oldWebhookReceipt, catalog); !errors.Is(err, ErrStaleCheckReceipt) {
		t.Fatalf("old webhook receipt reused: %v", err)
	}
	if !reflect.DeepEqual(diskBefore, currentCatalogBoundarySnapshot(t, path)) {
		t.Fatal("old receipt rejection changed disk")
	}
	failedPlan, failedReceipt, err := currentCatalogBoundaryRunner(t, state, oldWebhook).RunExpected(context.Background(), CheckWebhookValidated, plan.Identity())
	if err != nil || failedReceipt.State() != CheckBlocked || failedPlan.Ready() || webhookProbe.calls != 1 {
		t.Fatalf("old dependency checker reached Probe: %v", err)
	}
	freshWebhook := currentCatalogBoundaryWebhook(t, failedPlan, webhookProbe)
	ready, freshReceipt := currentCatalogBoundaryRun(t, state, failedPlan, freshWebhook)
	if !ready.Ready() || webhookProbe.calls != 2 || freshReceipt.Identity() == oldWebhookReceipt.Identity() {
		t.Fatal("new exact webhook dependency did not restore readiness")
	}
	encoded, err := EncodePlan(ready)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := DecodePlan(encoded)
	if err != nil || !replay.Ready() || replay.Identity() != ready.Identity() {
		t.Fatal("replacement history failed replay")
	}
	if err = state.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, err := reopened.Current(context.Background())
	if err != nil || !loaded.Ready() || loaded.Identity() != ready.Identity() {
		t.Fatal("replacement history failed reopen")
	}
}

func TestCurrentCatalogBoundaryCurrentPlanRejectsHistoricalCheckerAndReceipt(t *testing.T) {
	plan := currentCatalogBoundaryNewPlan(t, ProfileControlledHybrid)
	state, path := currentCatalogBoundaryState(t, plan)
	before := currentCatalogBoundarySnapshot(t, path)
	legacy := currentCatalogBoundaryHistory(t)[1]
	oldChecker := &currentCatalogBoundaryChecker{key: CheckIntegrationPermissionsValidated, identity: legacy.IntegrationCheckerIdentity}
	if _, _, err := currentCatalogBoundaryRunner(t, state, oldChecker).RunExpected(context.Background(), oldChecker.Key(), plan.Identity()); !errors.Is(err, ErrCheckNotAuthorized) || oldChecker.calls != 0 {
		t.Fatalf("current catalog accepted historical integration checker: %v", err)
	}
	oldReceipt, err := DecodeCheckReceipt(legacy.Receipts[0].Bytes)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := CurrentCheckerCatalog(plan.Profile())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = state.applyReceipt(context.Background(), oldReceipt, catalog); !errors.Is(err, ErrStaleCheckReceipt) {
		t.Fatalf("current plan imported historical pending receipt: %v", err)
	}
	probe := currentCatalogBoundaryProbe()
	checker := currentCatalogBoundaryPermission(t, plan, probe)
	runner := currentCatalogBoundaryRunner(t, state, checker)
	if _, _, err = runner.RunExpected(context.Background(), checker.Key(), currentCatalogBoundaryDigest([]byte("old-current-stale-plan"))); !errors.Is(err, ErrStateConflict) || probe.calls != 0 {
		t.Fatal("current no-pending execution bypassed expected-plan fence")
	}
	if !reflect.DeepEqual(before, currentCatalogBoundarySnapshot(t, path)) {
		t.Fatal("refused old authority or stale plan changed current state")
	}
	next, receipt := currentCatalogBoundaryRun(t, state, plan, checker)
	if probe.calls != 1 || receipt.CheckerIdentity() != currentCatalogBoundaryIntegrationIdentity || next.Revision() != 2 {
		t.Fatal("current authority positive control failed after refusals")
	}
}

// Diagnostic source/schema parity only. Neither the browser marker nor this
// structural schema check confers token-creation or runtime authority.
func TestCurrentCatalogBoundaryBrowserDigestAndHistoricalPlanSchemaParity(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "web", "src", "api.ts"))
	if err != nil {
		t.Fatal(err)
	}
	matches := regexp.MustCompile(`(?m)^export const CURRENT_INTEGRATION_PERMISSION_CHECKER_IDENTITY\s*=\s*"([0-9a-f]{64})";`).FindAllSubmatch(source, -1)
	if len(matches) != 1 || string(matches[0][1]) != currentCatalogBoundaryIntegrationIdentity || string(matches[0][1]) != CurrentIntegrationPermissionCheckerIdentity() {
		t.Fatal("unique browser diagnostic digest diverged from native current catalog")
	}
	schemaBytes, err := os.ReadFile(filepath.Join("..", "schemas", "setup", "setup-plan-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if currentCatalogBoundaryDigest(schemaBytes) != "af61eb07c4a82cfea09a8b15fd2745489be529f6eeeb320857b7b3ededb37997" {
		t.Fatal("historical plan schema bytes changed")
	}
	var schema struct {
		ID         string                     `json:"$id"`
		Additional bool                       `json:"additionalProperties"`
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil || schema.ID != "urn:open-trestle:schema:setup:plan:v1" || schema.Additional {
		t.Fatal("historical plan schema contract changed")
	}
	plan := currentCatalogBoundaryNewPlan(t, ProfileControlledHybrid)
	encoded, err := EncodePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &record); err != nil {
		t.Fatal(err)
	}
	for _, key := range schema.Required {
		if _, ok := record[key]; !ok {
			t.Fatalf("native current plan missing schema field %s", key)
		}
	}
	for key := range record {
		if _, ok := schema.Properties[key]; !ok {
			t.Fatalf("native current plan added undeclared schema field %s", key)
		}
	}
	var version int
	if err := json.Unmarshal(record["schema_version"], &version); err != nil || version != 1 {
		t.Fatal("current plan silently bumped historical wire schema")
	}
}
