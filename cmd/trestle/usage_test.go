package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/spending"
)

// offlineKeyTransport refuses every request, so no test reads OpenRouter's
// key report over the network.
type offlineKeyTransport struct{}

func (offlineKeyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network disabled in tests")
}

// fakeKeyReport is a synthetic, offline stand-in for OpenRouter's GET
// /api/v1/key, with a masked key label like the real report. Every value is
// made up.
type fakeKeyReport struct {
	t        *testing.T
	status   int
	body     string
	mu       sync.Mutex
	requests int
}

func (f *fakeKeyReport) RoundTrip(request *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.requests++
	f.mu.Unlock()
	if request.Method != http.MethodGet || request.URL.String() != spending.OpenRouterKeyURL || request.Header.Get("Authorization") != "Bearer "+remoteTestKey {
		f.t.Errorf("the key report was not one GET with the bearer key: %s %s", request.Method, request.URL)
	}
	return &http.Response{StatusCode: f.status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(f.body)), Request: request}, nil
}

const fakeKeyReportBody = `{"data":{"label":"sk-or-v1-fix...321","limit":50,"limit_remaining":49.92,"limit_reset":"monthly","include_byok_in_limit":false,"usage":0.079,"usage_daily":0.01,"usage_weekly":0.02,"usage_monthly":0.079,"byok_usage":0,"is_free_tier":false}}`

func useFakeKeyReport(t *testing.T, status int, body string) *fakeKeyReport {
	t.Helper()
	fake := &fakeKeyReport{t: t, status: status, body: body}
	previous := usageOpenRouterTransport
	usageOpenRouterTransport = fake
	t.Cleanup(func() { usageOpenRouterTransport = previous })
	return fake
}

func runUsageCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"usage"}, args...), &stdout, &stderr)
	if strings.Contains(stdout.String()+stderr.String(), remoteTestKey) || strings.Contains(stdout.String()+stderr.String(), "sk-or-v1-fix") {
		t.Fatalf("trestle usage printed a key or the key label:\n%s%s", stdout.String(), stderr.String())
	}
	return code, stdout.String(), stderr.String()
}

func TestUsageSetsShowsAndClearsALimit(t *testing.T) {
	store := spendingTestStore(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", "")
	code, out, _ := runUsageCommand(t)
	if code != 0 || !strings.Contains(out, "No spending limit is set and no spend is recorded this month.") || !strings.Contains(out, spending.Note) {
		t.Fatalf("empty status exit=%d:\n%s", code, out)
	}
	code, out, errText := runUsageCommand(t, "set", "--credential-env", "OPEN_TRESTLE_PROVIDER_OPENROUTER", "--limit", "10")
	if code != 0 {
		t.Fatalf("set exit=%d %s", code, errText)
	}
	want := "Spending limit set: $10.00 monthly limit for OPEN_TRESTLE_PROVIDER_OPENROUTER (openrouter), alerts at 80% and 100%.\nRecorded this month: $0.00 (0%).\nA review is refused once the recorded spend reaches the limit, and warns when it could pass it.\n" + spending.Note + "\n"
	if out != want {
		t.Fatalf("set output:\n%s\nwant:\n%s", out, want)
	}
	scope, _ := spending.NewScope("openrouter", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	limit, found, err := store.Limit(scope)
	if err != nil || !found || limit.AmountMicroUSD != 10_000_000 || limit.Period != spending.PeriodMonth || len(limit.AlertPercents) != 2 {
		t.Fatalf("stored limit %+v %v %v", limit, found, err)
	}
	entry := spending.Entry{RecordedAt: spendingTestNow.Add(-time.Hour), ReviewRunID: "local-a", RuntimePolicyIdentity: strings.Repeat("ab", 32), Scopes: []spending.Scope{scope}, Models: []string{"vendor/generator"}, RequestsSent: 2, UsageKnown: true, CostMicroUSD: 600_000}
	unknown := entry
	unknown.ReviewRunID, unknown.UsageKnown, unknown.CostMicroUSD = "local-b", false, 140_000
	other := entry
	other.ReviewRunID, other.Scopes, other.CostMicroUSD = "local-c", []spending.Scope{spendingTestScope(t)}, 70_000
	for _, e := range []spending.Entry{entry, unknown, other} {
		if err := store.Append(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
	// The key variable is not set: OpenRouter's figures are not read.
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", "")
	code, out, _ = runUsageCommand(t)
	for _, want := range []string{
		"  OPEN_TRESTLE_PROVIDER_OPENROUTER (openrouter): $0.74 of your $10.00 monthly limit this month (7%), alerts at 80% and 100%; 1 review counts at its reservation because its usage was not reported\n",
		"    OpenRouter's own figures are not read: OPEN_TRESTLE_PROVIDER_OPENROUTER is not set in this shell.\n",
		"  OPEN_TRESTLE_PROVIDER_REMOTE_TEST (ollama-cloud): $0.07 recorded this month; no limit set\n",
		spending.Note,
	} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("status lacks %q (exit %d):\n%s", want, code, out)
		}
	}
	// With the variable set, OpenRouter's own figures follow the local ones.
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	fake := useFakeKeyReport(t, http.StatusOK, fakeKeyReportBody)
	code, out, _ = runUsageCommand(t)
	if code != 0 || !strings.Contains(out, "(openrouter): $0.74 of your $10.00 monthly limit this month (7%)") || !strings.Contains(out, "\n    OpenRouter reports $0.08 used this month of this key's $50.00 monthly limit.\n") || fake.requests != 1 {
		t.Fatalf("status with OpenRouter's report (exit %d, %d reads):\n%s", code, fake.requests, out)
	}
	// A read failure degrades to one line and never fails the command.
	useFakeKeyReport(t, http.StatusUnauthorized, `{"error":{"message":"bad key"}}`)
	code, out, _ = runUsageCommand(t)
	if code != 0 || !strings.Contains(out, "    OpenRouter's usage could not be read: OpenRouter answered with HTTP status 401.\n") || strings.Contains(out, "bad key") {
		t.Fatalf("a failed read (exit %d):\n%s", code, out)
	}
	useFakeKeyReport(t, http.StatusOK, `{"data":{"label":"sk-or-v1-fix...321","usage":"lots"}}`)
	if code, out, _ = runUsageCommand(t); code != 0 || !strings.Contains(out, "    OpenRouter's usage could not be read: ") {
		t.Fatalf("a malformed report (exit %d):\n%s", code, out)
	}
	code, out, _ = runUsageCommand(t, "set", "--credential-env", "OPEN_TRESTLE_PROVIDER_OPENROUTER", "--limit", "25.50", "--period", "week", "--alert", "50,90")
	if code != 0 || !strings.Contains(out, "Spending limit set: $25.50 weekly limit for OPEN_TRESTLE_PROVIDER_OPENROUTER (openrouter), alerts at 50% and 90%.\nRecorded this week: $0.74 (2%).") {
		t.Fatalf("replacing the limit (exit %d):\n%s", code, out)
	}
	code, out, _ = runUsageCommand(t, "clear", "--credential-env", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	if code != 0 || out != "Spending limit cleared for OPEN_TRESTLE_PROVIDER_OPENROUTER (openrouter). Reviews still record their spend.\n"+spending.Note+"\n" {
		t.Fatalf("clear (exit %d):\n%s", code, out)
	}
	if code, out, _ = runUsageCommand(t, "clear", "--credential-env", "OPEN_TRESTLE_PROVIDER_OPENROUTER"); code != 0 || out != "No spending limit was set for OPEN_TRESTLE_PROVIDER_OPENROUTER (openrouter).\n" {
		t.Fatalf("clearing again (exit %d):\n%s", code, out)
	}
	if _, found, _ := store.Limit(scope); found {
		t.Fatal("the cleared limit is still stored")
	}
}

func TestUsageNeedsAProviderOnlyForAnUnusualVariable(t *testing.T) {
	store := spendingTestStore(t)
	code, _, errText := runUsageCommand(t, "set", "--credential-env", spendingTestVariable, "--limit", "5")
	if code != 2 || !strings.Contains(errText, "--provider is needed: OPEN_TRESTLE_PROVIDER_REMOTE_TEST is not a provider's usual key variable") {
		t.Fatalf("exit=%d %s", code, errText)
	}
	if code, _, errText = runUsageCommand(t, "set", "--credential-env", spendingTestVariable, "--limit", "5", "--provider", "ollama-cloud"); code != 0 {
		t.Fatalf("exit=%d %s", code, errText)
	}
	// Once one limit names the variable, its provider is found again.
	if code, _, errText = runUsageCommand(t, "clear", "--credential-env", spendingTestVariable); code != 0 {
		t.Fatalf("clear exit=%d %s", code, errText)
	}
	if limits, _ := store.Limits(); len(limits) != 0 {
		t.Fatalf("limits left: %+v", limits)
	}
}

func TestUsageRefusesUnusableAnswers(t *testing.T) {
	spendingTestStore(t)
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"set", "--limit", "5"}, "--credential-env is required"},
		{[]string{"set", "--credential-env", "sk-or-v1-0123456789abcdef", "--limit", "5"}, "never a key value"},
		{[]string{"set", "--credential-env", "OPEN_TRESTLE_PROVIDER_OPENROUTER"}, "--limit is required"},
		{[]string{"set", "--credential-env", "OPEN_TRESTLE_PROVIDER_OPENROUTER", "--limit", "1.234"}, "at most two decimals"},
		{[]string{"set", "--credential-env", "OPEN_TRESTLE_PROVIDER_OPENROUTER", "--limit", "0"}, "from $0.01"},
		{[]string{"set", "--credential-env", "OPEN_TRESTLE_PROVIDER_OPENROUTER", "--limit", "5", "--period", "day"}, "--period must be week, month or year"},
		{[]string{"set", "--credential-env", "OPEN_TRESTLE_PROVIDER_OPENROUTER", "--limit", "5", "--alert", "100,80"}, "ascending whole numbers"},
		{[]string{"set", "--credential-env", "OPEN_TRESTLE_PROVIDER_OPENROUTER", "--limit", "5", "--limit", "6"}, "--limit was given twice"},
		{[]string{"set", "--credential-env", "OPEN_TRESTLE_PROVIDER_OPENROUTER", "--limit", "5", "--provider", "Open Router"}, "--provider must be a provider ID"},
		{[]string{"clear", "--credential-env", "OPEN_TRESTLE_PROVIDER_OPENROUTER", "--limit", "5"}, "clear takes only"},
		{[]string{"reset"}, "unknown command"},
	} {
		code, _, errText := runUsageCommand(t, test.args...)
		if code != 2 || !strings.Contains(errText, test.want) {
			t.Errorf("%v: exit=%d %q, want %q", test.args, code, errText, test.want)
		}
	}
	if code, out, _ := runUsageCommand(t, "--help"); code != 0 || !strings.Contains(out, "trestle usage set --credential-env OPEN_TRESTLE_PROVIDER_NAME --limit USD") {
		t.Fatalf("help exit=%d %s", code, out)
	}
}

func TestUsageShowsOpenRouterFiguresForASetKeyWithoutALimit(t *testing.T) {
	spendingTestStore(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	useFakeKeyReport(t, http.StatusOK, fakeKeyReportBody)
	code, out, _ := runUsageCommand(t)
	for _, want := range []string{
		"  OPEN_TRESTLE_PROVIDER_OPENROUTER (openrouter): $0.00 recorded this month; no limit set\n",
		"    OpenRouter reports ",
		spending.Note,
	} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("status lacks %q (exit %d):\n%s", want, code, out)
		}
	}
	if strings.Contains(out, "No spending limit is set and no spend is recorded this month.") {
		t.Fatalf("a set OpenRouter key was reported as nothing to show:\n%s", out)
	}
}
