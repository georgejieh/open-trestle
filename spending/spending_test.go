package spending

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/schemacheck"
)

const testPolicy = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func mustScope(t *testing.T, provider, variable string) Scope {
	t.Helper()
	scope, err := NewScope(provider, variable)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func utc(t *testing.T, value string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func TestPeriodBoundsAreUTCCalendarPeriods(t *testing.T) {
	tests := []struct {
		period     Period
		at         string
		start, end string
	}{
		// A week runs from Monday 00:00 UTC; 2026-11-13 is a Friday.
		{PeriodWeek, "2026-11-13T12:00:00Z", "2026-11-09T00:00:00Z", "2026-11-16T00:00:00Z"},
		{PeriodWeek, "2026-11-09T00:00:00Z", "2026-11-09T00:00:00Z", "2026-11-16T00:00:00Z"},
		{PeriodWeek, "2026-11-15T23:59:59Z", "2026-11-09T00:00:00Z", "2026-11-16T00:00:00Z"},
		{PeriodWeek, "2026-11-16T00:00:00Z", "2026-11-16T00:00:00Z", "2026-11-23T00:00:00Z"},
		// A week that spans the end of a year.
		{PeriodWeek, "2027-01-01T08:00:00Z", "2026-12-28T00:00:00Z", "2027-01-04T00:00:00Z"},
		// A time zone ahead of UTC: Monday 01:00 in +02:00 is Sunday in UTC.
		{PeriodWeek, "2026-11-16T01:00:00+02:00", "2026-11-09T00:00:00Z", "2026-11-16T00:00:00Z"},
		{PeriodMonth, "2026-11-30T23:59:59Z", "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z"},
		{PeriodMonth, "2026-12-01T00:00:00Z", "2026-12-01T00:00:00Z", "2027-01-01T00:00:00Z"},
		{PeriodMonth, "2028-02-29T10:00:00Z", "2028-02-01T00:00:00Z", "2028-03-01T00:00:00Z"},
		{PeriodMonth, "2026-12-01T00:30:00+01:00", "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z"},
		{PeriodYear, "2026-12-31T23:59:59Z", "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"},
		{PeriodYear, "2027-01-01T00:00:00Z", "2027-01-01T00:00:00Z", "2028-01-01T00:00:00Z"},
	}
	for _, test := range tests {
		start, end := test.period.Bounds(utc(t, test.at))
		if !start.Equal(utc(t, test.start)) || !end.Equal(utc(t, test.end)) || start.Location() != time.UTC {
			t.Errorf("%s at %s: [%s, %s), want [%s, %s)", test.period, test.at, start, end, test.start, test.end)
		}
	}
	for _, refused := range []string{"", "day", "Month", "monthly"} {
		if _, err := ParsePeriod(refused); err == nil {
			t.Errorf("period %q was accepted", refused)
		}
	}
}

func TestLimitRecordIsCanonicalAndKeyedByTheCredentialReference(t *testing.T) {
	scope := mustScope(t, "openrouter", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	limit, err := NewLimit(scope, PeriodMonth, 10_000_000, DefaultAlertPercents, utc(t, "2026-11-13T10:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeLimit(limit)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"contract":"open-trestle/spending-limit","schema_version":1,"provider_id":"openrouter","credential_environment":"OPEN_TRESTLE_PROVIDER_OPENROUTER","credential_reference_identity":"` + scope.CredentialReferenceIdentity() + `","period":"month","limit_micro_usd":10000000,"alert_percents":[80,100],"set_at":"2026-11-13T10:00:00Z"}` + "\n"
	if string(encoded) != want {
		t.Fatalf("limit encoding:\n%s\nwant\n%s", encoded, want)
	}
	parsed, err := ParseLimit(encoded)
	if err != nil || parsed.Scope != scope || parsed.AmountMicroUSD != 10_000_000 || parsed.Period != PeriodMonth || !parsed.SetAt.Equal(limit.SetAt) {
		t.Fatalf("round trip: %v %+v", err, parsed)
	}
	validateSchema(t, "urn:open-trestle:schema:runtime:spending-limit:v1", encoded)
	other := mustScope(t, "opencode-go", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	if other.key() == scope.key() || mustScope(t, "openrouter", "OPEN_TRESTLE_PROVIDER_OTHER").key() == scope.key() {
		t.Fatal("different providers or key variables share a limit")
	}
	for name, mutate := range map[string]func(string) string{
		"unknown field": func(s string) string { return strings.Replace(s, `"period"`, `"note":"x","period"`, 1) },
		"duplicate member": func(s string) string {
			return strings.Replace(s, `"period":"month"`, `"period":"month","period":"week"`, 1)
		},
		"reordered": func(s string) string {
			return strings.Replace(s, `"schema_version":1,"provider_id":"openrouter"`, `"provider_id":"openrouter","schema_version":1`, 1)
		},
		"wrong identity": func(s string) string {
			return strings.Replace(s, scope.CredentialReferenceIdentity(), strings.Repeat("a", 64), 1)
		},
		"not whole cents":   func(s string) string { return strings.Replace(s, "10000000", "10000001", 1) },
		"zero limit":        func(s string) string { return strings.Replace(s, "10000000", "0", 1) },
		"alerts descending": func(s string) string { return strings.Replace(s, "[80,100]", "[100,80]", 1) },
		"alert over 100":    func(s string) string { return strings.Replace(s, "[80,100]", "[80,101]", 1) },
		"no alerts":         func(s string) string { return strings.Replace(s, "[80,100]", "[]", 1) },
		"local time":        func(s string) string { return strings.Replace(s, "10:00:00Z", "10:00:00+00:00", 1) },
		"day period":        func(s string) string { return strings.Replace(s, `"month"`, `"day"`, 1) },
		"no newline":        func(s string) string { return strings.TrimSuffix(s, "\n") },
		"trailing value":    func(s string) string { return s + "{}\n" },
		"spaced":            func(s string) string { return strings.Replace(s, `":`, `": `, 1) },
		"credential as name": func(s string) string {
			return strings.Replace(s, "OPEN_TRESTLE_PROVIDER_OPENROUTER", "sk-or-v1-0000000000000000", 1)
		},
	} {
		if _, err := ParseLimit([]byte(mutate(string(encoded)))); err == nil {
			t.Errorf("%s: a non-canonical or invalid limit was accepted", name)
		}
	}
	for _, alerts := range [][]int{nil, {0}, {50, 50}, {1, 2, 3, 4, 5, 6, 7, 8, 9}} {
		if _, err := NewLimit(scope, PeriodWeek, 10_000, alerts, time.Now()); err == nil {
			t.Errorf("alerts %v were accepted", alerts)
		}
	}
	if _, err := NewLimit(scope, PeriodWeek, MaxLimitMicroUSD+microUSDPerCent, DefaultAlertPercents, time.Now()); err == nil {
		t.Error("a limit over the bound was accepted")
	}
	for _, refused := range [][2]string{{"", "OPEN_TRESTLE_PROVIDER_X"}, {"OpenRouter", "OPEN_TRESTLE_PROVIDER_X"}, {"-x", "OPEN_TRESTLE_PROVIDER_X"}, {"openrouter", "OPENROUTER_API_KEY"}, {"openrouter", "OPEN_TRESTLE_PROVIDER_"}} {
		if _, err := NewScope(refused[0], refused[1]); !errors.Is(err, ErrInvalidScope) {
			t.Errorf("scope %q was accepted", refused)
		}
	}
}

func testEntry(t *testing.T, at string, cost uint64, known bool, scopes ...Scope) Entry {
	t.Helper()
	return Entry{RecordedAt: utc(t, at), ReviewRunID: "local-" + strings.Repeat("ab", 32), RuntimePolicyIdentity: testPolicy, Scopes: scopes, Models: []string{"vendor/generator", "other/verifier"}, RequestsSent: 2, UsageKnown: known, CostMicroUSD: cost}
}

func TestLedgerEntryIsCanonicalAndMarksItsBasis(t *testing.T) {
	openRouter := mustScope(t, "openrouter", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	other := mustScope(t, "ollama-cloud", "OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD")
	settled := testEntry(t, "2026-11-13T10:00:00Z", 612_345, true, openRouter, other)
	encoded, err := EncodeEntry(settled)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"contract":"open-trestle/usage-ledger-entry","schema_version":1,"recorded_at":"2026-11-13T10:00:00Z","review_run_id":"local-` + strings.Repeat("ab", 32) + `","runtime_policy_identity":"` + testPolicy + `","keys":[{"provider_id":"ollama-cloud","credential_environment":"OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD","credential_reference_identity":"` + other.CredentialReferenceIdentity() + `"},{"provider_id":"openrouter","credential_environment":"OPEN_TRESTLE_PROVIDER_OPENROUTER","credential_reference_identity":"` + openRouter.CredentialReferenceIdentity() + `"}],"models":["other/verifier","vendor/generator"],"requests_sent":2,"usage_known":true,"cost_micro_usd":612345,"cost":"settled_usage","price_basis":"route_max_price"}` + "\n"
	if string(encoded) != want {
		t.Fatalf("entry encoding:\n%s\nwant\n%s", encoded, want)
	}
	validateSchema(t, "urn:open-trestle:schema:runtime:usage-ledger-entry:v1", encoded)
	parsed, err := ParseEntry(encoded)
	if err != nil || !parsed.Charges(openRouter) || !parsed.Charges(other) || parsed.CostKind() != CostSettledUsage {
		t.Fatalf("round trip: %v %+v", err, parsed)
	}
	unknown, err := EncodeEntry(testEntry(t, "2026-11-13T10:00:00Z", 140_000, false, openRouter))
	if err != nil || !bytes.Contains(unknown, []byte(`"usage_known":false,"cost_micro_usd":140000,"cost":"reservation_upper_bound","price_basis":"route_max_price"`)) {
		t.Fatalf("an unknown-usage entry is not marked as the reservation upper bound: %v %s", err, unknown)
	}
	validateSchema(t, "urn:open-trestle:schema:runtime:usage-ledger-entry:v1", unknown)
	for name, mutate := range map[string]func(string) string{
		"cost kind contradicts usage": func(s string) string {
			return strings.Replace(s, `"cost":"settled_usage"`, `"cost":"reservation_upper_bound"`, 1)
		},
		"other price basis": func(s string) string { return strings.Replace(s, "route_max_price", "provider_bill", 1) },
		"no requests":       func(s string) string { return strings.Replace(s, `"requests_sent":2`, `"requests_sent":0`, 1) },
		"unsorted models": func(s string) string {
			return strings.Replace(s, `["other/verifier","vendor/generator"]`, `["vendor/generator","other/verifier"]`, 1)
		},
		"prompt field": func(s string) string { return strings.Replace(s, `"models"`, `"prompt":"secret","models"`, 1) },
		"wrong identity": func(s string) string {
			return strings.Replace(s, openRouter.CredentialReferenceIdentity(), other.CredentialReferenceIdentity(), 1)
		},
	} {
		if _, err := ParseEntry([]byte(mutate(want))); err == nil {
			t.Errorf("%s: an invalid entry was accepted", name)
		}
	}
	for name, entry := range map[string]Entry{
		"no key":        testEntry(t, "2026-11-13T10:00:00Z", 1, true),
		"duplicate key": testEntry(t, "2026-11-13T10:00:00Z", 1, true, openRouter, openRouter),
		"no policy":     {RecordedAt: utc(t, "2026-11-13T10:00:00Z"), ReviewRunID: "local-x", Scopes: []Scope{openRouter}, Models: []string{"m"}, RequestsSent: 1},
		"model space":   {RecordedAt: utc(t, "2026-11-13T10:00:00Z"), ReviewRunID: "local-x", RuntimePolicyIdentity: testPolicy, Scopes: []Scope{openRouter}, Models: []string{"a model"}, RequestsSent: 1},
		"cost bound":    {RecordedAt: utc(t, "2026-11-13T10:00:00Z"), ReviewRunID: "local-x", RuntimePolicyIdentity: testPolicy, Scopes: []Scope{openRouter}, Models: []string{"m"}, RequestsSent: 1, CostMicroUSD: MaxEntryCostMicroUSD + 1},
	} {
		if _, err := EncodeEntry(entry); err == nil {
			t.Errorf("%s: an invalid entry was encoded", name)
		}
	}
}

func TestAlertsAndAmounts(t *testing.T) {
	scope := mustScope(t, "openrouter", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	limit, err := NewLimit(scope, PeriodMonth, 10_000_000, []int{50, 80, 100}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		before, after uint64
		want          int
		crossed       bool
	}{
		{0, 4_999_999, 0, false},
		{0, 5_000_000, 50, true},
		{4_000_000, 8_120_000, 80, true}, // crosses 50 and 80: the highest is reported once
		{8_000_000, 8_120_000, 0, false}, // already past 80 before the run
		{7_999_999, 10_000_000, 100, true},
		{10_000_000, 12_000_000, 0, false}, // past every alert already
	}
	for _, test := range tests {
		got, crossed := CrossedAlert(limit, test.before, test.after)
		if got != test.want || crossed != test.crossed {
			t.Errorf("%d -> %d: %d %v, want %d %v", test.before, test.after, got, crossed, test.want, test.crossed)
		}
	}
	status := Status{Limit: limit, Spend: Spend{MicroUSD: 8_120_000}}
	if line := status.AlertLine(); line != "Spending alert: $8.12 of your $10.00 monthly limit for OPEN_TRESTLE_PROVIDER_OPENROUTER (81%)" {
		t.Fatalf("alert line: %s", line)
	}
	if status.Reached() || !status.WouldCross(1_880_000) || status.WouldCross(1_879_999) || status.WouldCross(0) {
		t.Fatal("reached or worst-case crossing is wrong")
	}
	if !(Status{Limit: limit, Spend: Spend{MicroUSD: 10_000_000}}).Reached() {
		t.Fatal("spend equal to the limit is not reached")
	}
	for micro, want := range map[uint64]string{0: "$0.00", 1: "$0.01", 79_000: "$0.08", 8_120_000: "$8.12", 8_120_001: "$8.13", 1_234_567_890_000: "$1234567.89"} {
		if got := FormatUSD(micro); got != want {
			t.Errorf("FormatUSD(%d)=%s, want %s", micro, got, want)
		}
	}
	for text, want := range map[string]uint64{"10": 10_000_000, "10.5": 10_500_000, "$0.25": 250_000, "  3.00 ": 3_000_000} {
		if got, err := ParseUSD(text); err != nil || got != want {
			t.Errorf("ParseUSD(%q)=%d %v, want %d", text, got, err, want)
		}
	}
	for _, refused := range []string{"", "1.234", "ten", "-1", "1e3", "1.", "12345678"} {
		if _, err := ParseUSD(refused); err == nil && refused != "" {
			t.Errorf("ParseUSD(%q) was accepted", refused)
		}
	}
	if alerts, err := ParseAlerts("80, 100"); err != nil || len(alerts) != 2 || AlertList(alerts) != "80% and 100%" || AlertList([]int{50, 80, 100}) != "50%, 80% and 100%" {
		t.Fatalf("alerts: %v %v", alerts, err)
	}
	for _, refused := range []string{"", "100,80", "0", "80,80", "101", "x"} {
		if _, err := ParseAlerts(refused); err == nil {
			t.Errorf("ParseAlerts(%q) was accepted", refused)
		}
	}
}

func validateSchema(t *testing.T, id string, encoded []byte) {
	t.Helper()
	registry, err := schemacheck.Load(filepath.Join("..", "schemas"))
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Validate(id, bytes.TrimSuffix(encoded, []byte("\n"))); err != nil {
		t.Fatalf("%s does not satisfy %s: %v", encoded, id, err)
	}
}
