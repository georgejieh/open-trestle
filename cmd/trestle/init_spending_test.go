package main

import (
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/spending"
)

// The wizard's one optional spending question, with synthetic OpenRouter
// fixtures (fakeOpenRouter, remoteModelTransport and fakeKeyReport). Nothing
// here contacts OpenRouter.

func openRouterSpendingScope(t *testing.T) spending.Scope {
	t.Helper()
	scope, err := spending.NewScope("openrouter", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func TestInitAsksTheOptionalSpendingLimitAndSavesItAfterTheSetup(t *testing.T) {
	store := spendingTestStore(t)
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	fakeOpenRouter(t, initOpenRouterModels()...)
	report := useFakeKeyReport(t, http.StatusOK, fakeKeyReportBody)
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"},
		"1", "generator", "1", "", "other/verifier",
		"",      // require zero data retention
		"ten",   // not an amount: asked again
		"10.00", // a $10.00 monthly limit
		"",      // alert at the proposed 80%
		"",      // use the settings shown
		"yes",   // consent
		"n",     // no review now
	)
	if result.code != initExitDone {
		t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	// Lines wrap at 60 columns; compare positions in the unwrapped text.
	shown := strings.Join(strings.Fields(result.stdout), " ")
	reportAt := strings.Index(shown, "OpenRouter reports $0.08 used this month of this key's $50.00 monthly limit")
	questionAt := strings.Index(shown, "Spending limit for this key, USD per month (optional) [none]:")
	if reportAt < 0 || questionAt < 0 || reportAt > questionAt || report.requests != 1 {
		t.Fatalf("OpenRouter's own limit was not shown before the question (%d reads):\n%s", report.requests, shown)
	}
	initAssertOutput(t, result,
		"Type an amount in US dollars with at most two decimals, such as 10 or 25.50, or none.",
		"Alert at percent [80]:",
		"Spending $10.00 a month for this key · alerts at 80%",
		"Saved a $10.00 monthly limit for OPEN_TRESTLE_PROVIDER_OPENROUTER, alerts at 80% and 100%.",
		spending.Note,
	)
	if strings.Index(shown, "Saved protected configuration") > strings.Index(shown, "Saved a $10.00 monthly limit") {
		t.Fatal("the limit was saved before the setup")
	}
	limit, found, err := store.Limit(openRouterSpendingScope(t))
	if err != nil || !found || limit.AmountMicroUSD != 10_000_000 || limit.Period != spending.PeriodMonth || !slices.Equal(limit.AlertPercents, []int{80, 100}) {
		t.Fatalf("saved limit %+v %v %v", limit, found, err)
	}
	// Running init again shows the key's state as trestle usage does, and
	// changes nothing.
	again := runInitScript(t, checkout, []string{"--directory", dir}, "3")
	initAssertOutput(t, again,
		"Spending: $0.00 of your $10.00 monthly limit for OPEN_TRESTLE_PROVIDER_OPENROUTER this month (0%), alerts at 80% and 100%.",
		"OpenRouter reports $0.08 used this month of this key's $50.00 monthly limit.",
		spending.Note, "Nothing was changed.")
}

func TestInitKeepsAnExistingLimitAndTakesTheLimitAsFlags(t *testing.T) {
	store := spendingTestStore(t)
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	fakeOpenRouter(t, initOpenRouterModels()...)
	checkout := remoteBootstrapCheckout(t)
	existing, _ := spending.NewLimit(openRouterSpendingScope(t), spending.PeriodWeek, 3_000_000, []int{50, 100}, spendingTestNow)
	if err := store.SetLimit(t.Context(), existing); err != nil {
		t.Fatal(err)
	}
	result := runInitScript(t, checkout, []string{"--directory", filepath.Join(t.TempDir(), "setup"), "--base", "refs/heads/base", "--head", "refs/heads/review"},
		"1", "generator", "1", "", "other/verifier", "", "", "yes", "n")
	if result.code != initExitDone || initHas(result.stdout, "Spending limit for this key") {
		t.Fatalf("an existing limit was asked again: exit=%d\n%s", result.code, result.stdout)
	}
	initAssertOutput(t, result, "OPEN_TRESTLE_PROVIDER_OPENROUTER already has a $3.00 weekly limit, alerts at 50% and 100%. trestle usage set changes it.", "Spending $3.00 weekly limit (set earlier) ·", "alerts at")
	if limit, _, _ := store.Limit(openRouterSpendingScope(t)); limit.Period != spending.PeriodWeek || limit.AmountMicroUSD != 3_000_000 {
		t.Fatalf("the existing limit was changed: %+v", limit)
	}
	// With --no-input the limit and alert are flags; without them there is
	// no limit and nothing is missing.
	if _, err := store.ClearLimit(t.Context(), openRouterSpendingScope(t)); err != nil {
		t.Fatal(err)
	}
	flags := []string{"--no-input", "--provider", "openrouter", "--base", "refs/heads/base", "--head", "refs/heads/review", "--generation-model", "vendor/generator", "--verification-model", "other/verifier", "--declare-remote-route"}
	result = runInitScript(t, checkout, append([]string{"--directory", filepath.Join(t.TempDir(), "setup"), "--spending-limit", "5", "--spending-alert", "90"}, flags...))
	if result.code != initExitDone {
		t.Fatalf("--no-input with a limit: exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	if limit, found, _ := store.Limit(openRouterSpendingScope(t)); !found || limit.AmountMicroUSD != 5_000_000 || !slices.Equal(limit.AlertPercents, []int{90, 100}) {
		t.Fatalf("flag limit %+v %v", limit, found)
	}
	if _, err := store.ClearLimit(t.Context(), openRouterSpendingScope(t)); err != nil {
		t.Fatal(err)
	}
	result = runInitScript(t, checkout, append([]string{"--directory", filepath.Join(t.TempDir(), "setup")}, flags...))
	if result.code != initExitDone || !initHas(result.stdout, "no limit (optional; trestle usage set adds") {
		t.Fatalf("--no-input without a limit: exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	if _, found, _ := store.Limit(openRouterSpendingScope(t)); found {
		t.Fatal("a limit was saved without one being chosen")
	}
	for _, refused := range [][]string{{"--spending-alert", "90"}, {"--spending-limit", "ten"}, {"--spending-limit", "5", "--spending-alert", "0"}} {
		result = runInitScript(t, checkout, append(append([]string{"--directory", filepath.Join(t.TempDir(), "setup")}, refused...), flags...))
		if result.code != initExitUsage || !initHas(result.stderr, "--spending-") {
			t.Fatalf("%v: exit=%d %s", refused, result.code, result.stderr)
		}
	}
}

// A provider plan that does not charge per token has nothing to limit, so the
// question is not asked and a limit flag is refused.
func TestInitAsksNoSpendingLimitWithoutPerTokenPrices(t *testing.T) {
	spendingTestStore(t)
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD", remoteTestKey)
	initFakeModelList(t, "gemma4:31b", "qwen3.5:397b")
	checkout := remoteBootstrapCheckout(t)
	flags := []string{"--no-input", "--provider", "ollama-cloud", "--base", "refs/heads/base", "--head", "refs/heads/review", "--generation-model", "gemma4:31b", "--verification-model", "qwen3.5:397b", "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "0", "--output-micro-usd-per-million-tokens", "0", "--declare-remote-route"}
	result := runInitScript(t, checkout, append([]string{"--directory", filepath.Join(t.TempDir(), "setup")}, flags...))
	if result.code != initExitDone || initHas(result.stdout, "Spending limit") || initHas(result.stdout, "trestle usage set") || initHas(result.stdout, "│ Spending ") {
		t.Fatalf("exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	result = runInitScript(t, checkout, append([]string{"--directory", filepath.Join(t.TempDir(), "setup"), "--spending-limit", "5"}, flags...))
	if result.code != initExitUsage || !initHas(result.stderr, "apply only to a remote provider with an API key that charges per token") {
		t.Fatalf("exit=%d %s", result.code, result.stderr)
	}
}

// A first review refused at the limit says so, with the spending lines from
// the review kept in the result box.
func TestInitFirstReviewRefusedAtTheSpendingLimit(t *testing.T) {
	store := spendingTestStore(t)
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	fakeOpenRouter(t, initOpenRouterModels()...)
	transport := &remoteModelTransport{t: t, target: "https://openrouter.ai/api/v1/chat/completions", models: map[string]string{"vendor/generator": `["fixture-cloud","fixture-cloud/us"]`, "other/verifier": `["fixture-host/fp8"]`}, maxTokens: 16000}
	remoteModelClient(t, transport)
	scope := openRouterSpendingScope(t)
	limit, _ := spending.NewLimit(scope, spending.PeriodMonth, 10_000, spending.DefaultAlertPercents, spendingTestNow)
	if err := store.SetLimit(t.Context(), limit); err != nil {
		t.Fatal(err)
	}
	seed := spending.Entry{RecordedAt: spendingTestNow.Add(-time.Hour), ReviewRunID: "local-earlier", RuntimePolicyIdentity: strings.Repeat("ab", 32), Scopes: []spending.Scope{scope}, Models: []string{"vendor/generator"}, RequestsSent: 2, UsageKnown: true, CostMicroUSD: 10_000}
	if err := store.Append(t.Context(), seed); err != nil {
		t.Fatal(err)
	}
	result := runInitScript(t, remoteBootstrapCheckout(t), []string{"--directory", filepath.Join(t.TempDir(), "setup"), "--base", "refs/heads/base", "--head", "refs/heads/review"},
		"1", "generator", "1", "", "other/verifier", "", "", "yes", "y")
	if result.code != initExitRefused || len(transport.requests) != 0 {
		t.Fatalf("exit=%d requests=%v\n%s", result.code, transport.requests, result.stdout)
	}
	initAssertOutput(t, result, "│ failure: policy: spending_limit_reached", "│ Spending limit reached: $0.01 of your $0.01 monthly", "The review was refused before it started: a spending limit for this key is reached, so nothing was sent. Run trestle usage to see it.")
}
