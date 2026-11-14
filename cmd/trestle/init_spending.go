package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/georgejieh/open-trestle/spending"
)

// The spending part of `trestle init`: one optional question, a monthly
// spending limit for the key, asked only for a remote provider that charges
// per token. It replaces the per-request cost question; the per-request bound
// is now computed (costLimit). The limit is saved only after the setup is
// saved, in the same usage folder `trestle usage` and every review read.

// initSpendingProvider is the provider ID a provider's routes use, or "" for
// a provider without an API key.
func initSpendingProvider(key string) string {
	switch key {
	case "openrouter", "ollama-cloud", "opencode-go":
		return key
	}
	return ""
}

// initChargesPerToken reports whether the chosen prices are not both zero.
func (w *initWizard) initChargesPerToken() bool {
	input, _ := strconv.ParseUint(w.a.inputPrice, 10, 64)
	output, _ := strconv.ParseUint(w.a.outputPrice, 10, 64)
	return input+output > 0
}

func initSpendingAmount(value string) (string, error) {
	if trimmed := strings.ToLower(strings.TrimSpace(value)); trimmed == "none" || trimmed == "" {
		return "", nil
	}
	micro, err := spending.ParseUSD(value)
	if err != nil || micro < 10_000 || micro > spending.MaxLimitMicroUSD {
		return "", errors.New("Type an amount in US dollars with at most two decimals, such as 10 or 25.50, or none.")
	}
	return strconv.FormatUint(micro, 10), nil
}

func initSpendingPercent(value string) (string, error) {
	percent, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(value), "%"))
	if err != nil || percent < 1 || percent > 100 {
		return "", errors.New("Type a whole percentage from 1 to 100.")
	}
	return strconv.Itoa(percent), nil
}

// initSpendingAlerts alerts at the chosen percentage and at the limit.
func initSpendingAlerts(percent int) []int {
	if percent >= 100 {
		return []int{100}
	}
	return []int{percent, 100}
}

// spendingScope is the key this setup's limit is for, or false for a setup
// without one.
func (w *initWizard) spendingScope() (spending.Scope, bool) {
	scope, err := spending.NewScope(initSpendingProvider(w.a.provider.key), w.a.credentialEnv)
	return scope, err == nil
}

// spendingLimit asks the optional monthly spending limit for the key. It shows
// OpenRouter's own figures first when the key variable is set, and keeps a
// limit the key already has.
func (w *initWizard) spendingLimit() error {
	a := &w.a
	_, limitGiven := w.flags["spending-limit"]
	_, alertGiven := w.flags["spending-alert"]
	scope, keyed := w.spendingScope()
	if !keyed || !w.initChargesPerToken() {
		if limitGiven || alertGiven {
			return initStopf(initExitUsage, "--spending-limit and --spending-alert apply only to a remote provider with an API key that charges per token.")
		}
		return nil
	}
	if alertGiven && !limitGiven {
		return initStopf(initExitUsage, "--spending-alert needs --spending-limit.")
	}
	if limitGiven {
		value, err := initSpendingAmount(w.flags["spending-limit"])
		if err != nil || value == "" {
			return initStopf(initExitUsage, "--spending-limit: give an amount in US dollars with at most two decimals, such as 10 or 25.50.")
		}
		a.spendingLimit, _ = strconv.ParseUint(value, 10, 64)
		a.spendingAlert = 80
		if alertGiven {
			percent, err := initSpendingPercent(w.flags["spending-alert"])
			if err != nil {
				return initStopf(initExitUsage, "--spending-alert: %v", err)
			}
			a.spendingAlert, _ = strconv.Atoi(percent)
		}
		return nil
	}
	store, err := usageStore()
	if err != nil {
		w.say("  Spending limits are not available: the usage folder cannot be found (set HOME or XDG_STATE_HOME).")
		return nil
	}
	if limit, found, err := store.Limit(scope); err == nil && found {
		a.spendingExisting = &limit
		if w.prompt != nil {
			w.say("\n  Spending limit: %s already has a %s, alerts at %s. trestle usage set changes it.", scope.CredentialEnvironment, limit.Describe(), spending.AlertList(limit.AlertPercents))
		}
		return nil
	}
	if w.prompt == nil {
		return nil
	}
	w.say("\n  Optional: a spending limit for this key. Open Trestle adds up what each review may have cost, prints an alert when the month's total reaches the alert percent, and refuses to start a review once it reaches the limit. The total is an upper-bound estimate at the highest pinned price, not a bill, and the limit is best effort: other tools using this key and price changes are invisible to it, so your provider's own limit is the guarantee.")
	if lines := usageProviderLines(w.ctx, scope); len(lines) != 0 {
		for _, line := range lines {
			w.say("  %s", strings.TrimSpace(line))
		}
	}
	value, err := w.prompt.ask("Spending limit for this key, USD per month (optional)", "none", initSpendingAmount)
	if err != nil || value == "" {
		return err
	}
	a.spendingLimit, _ = strconv.ParseUint(value, 10, 64)
	percent, err := w.prompt.ask("Alert at percent", "80", initSpendingPercent)
	if err != nil {
		return err
	}
	a.spendingAlert, _ = strconv.Atoi(percent)
	return nil
}

// spendingRow is the summary panel's spending line, or false when the setup
// has no key that charges per token.
func (w *initWizard) spendingRow() (string, bool) {
	if _, keyed := w.spendingScope(); !keyed || !w.initChargesPerToken() {
		return "", false
	}
	// The Key row names the variable the limit is for.
	switch {
	case w.a.spendingLimit != 0:
		return fmt.Sprintf("%s a month for this key · alerts at %s", spending.FormatUSD(w.a.spendingLimit), spending.AlertList(initSpendingAlerts(w.a.spendingAlert))), true
	case w.a.spendingExisting != nil:
		return fmt.Sprintf("%s (set earlier) · alerts at %s", w.a.spendingExisting.Describe(), spending.AlertList(w.a.spendingExisting.AlertPercents)), true
	}
	return "no limit (optional; trestle usage set adds one)", true
}

// saveSpendingLimit writes the chosen limit once the setup is saved. A
// failure is reported with the command that sets it later; the setup stays
// saved.
func (w *initWizard) saveSpendingLimit() {
	scope, keyed := w.spendingScope()
	if !keyed || w.a.spendingLimit == 0 {
		return
	}
	command := fmt.Sprintf("trestle usage set --credential-env %s --limit %s --alert %s", scope.CredentialEnvironment, strings.TrimPrefix(spending.FormatUSD(w.a.spendingLimit), "$"), strings.Trim(strings.ReplaceAll(fmt.Sprint(initSpendingAlerts(w.a.spendingAlert)), " ", ","), "[]"))
	limit, err := spending.NewLimit(scope, spending.PeriodMonth, w.a.spendingLimit, initSpendingAlerts(w.a.spendingAlert), spendingNow())
	store, storeErr := usageStore()
	if err == nil && storeErr == nil {
		err = store.SetLimit(w.ctx, limit)
	} else if err == nil {
		err = storeErr
	}
	if err != nil {
		w.say("  %s The spending limit could not be saved (%v). Set it later with:", w.bad, err)
		w.sayVerbatim("    " + command)
		return
	}
	w.say("  %s Saved a %s for %s, alerts at %s.", w.ok, limit.Describe(), scope.CredentialEnvironment, spending.AlertList(limit.AlertPercents))
	w.hint("    " + spending.Note)
}

// spendingStatus shows a saved setup's keys as `trestle usage` does.
func (w *initWizard) spendingStatus(setup initSetup) {
	provider := initSpendingProvider(setup.provider.key)
	if !setup.remote || provider == "" {
		return
	}
	store, err := usageStore()
	if err != nil {
		return
	}
	shown := false
	for _, name := range setup.credentials {
		scope, err := spending.NewScope(provider, name)
		if err != nil {
			continue
		}
		limit, found, err := store.Limit(scope)
		if err != nil {
			continue
		}
		if !found {
			w.say("  Spending: no limit for %s (trestle usage set adds one).", name)
			continue
		}
		status, err := store.CurrentStatus(limit, spendingNow())
		if err != nil {
			continue
		}
		w.say("  Spending: %s.", status.Summary())
		shown = true
		if os.Getenv(name) != "" {
			for _, line := range usageProviderLines(w.ctx, scope) {
				w.say("  %s", strings.TrimSpace(line))
			}
		}
	}
	if shown {
		w.hint("  " + spending.Note)
	}
}
