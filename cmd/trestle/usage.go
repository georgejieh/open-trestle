package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/runtimeconfig"
	"github.com/georgejieh/open-trestle/spending"
)

// `trestle usage` shows and sets the local spending limits of API keys:
//
//	trestle usage
//	trestle usage set --credential-env VAR --limit USD [--period week|month|year] [--alert 80,100] [--provider ID]
//	trestle usage clear --credential-env VAR [--provider ID]
//
// It reads and writes only the usage folder, and for an OpenRouter key whose
// variable is set, OpenRouter's usage report (one GET that costs nothing and
// sends no source). The key's value is read only to send that GET and is never
// printed or stored.

// Tests replace the OpenRouter transport; production leaves it nil, a direct
// HTTPS transport.
var usageOpenRouterTransport http.RoundTripper

// usageUsualProviders maps each provider's usual key variable, the one
// `trestle init` proposes, to the provider ID its routes use, so --provider is
// needed only for another variable name.
func usageUsualProviders() map[string]string {
	providers := map[string]string{}
	for _, info := range initProviders {
		if info.credentialProposal != "" {
			providers[info.credentialProposal] = info.key
		}
	}
	return providers
}

func writeUsageUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle usage   (spending recorded this period against each API key's limit)")
	fmt.Fprintln(w, "       trestle usage set --credential-env OPEN_TRESTLE_PROVIDER_NAME --limit USD [--period week|month|year] [--alert 80,100] [--provider ID]")
	fmt.Fprintln(w, "       trestle usage clear --credential-env OPEN_TRESTLE_PROVIDER_NAME [--provider ID]")
}

func usageStore() (*spending.Store, error) {
	dir, err := spending.DefaultDirectory(os.Getenv)
	if err != nil {
		return nil, err
	}
	return spending.NewStore(dir)
}

func runUsage(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		writeUsageUsage(stdout)
		return 0
	}
	if len(args) == 0 {
		return runUsageStatus(ctx, stdout, stderr)
	}
	switch args[0] {
	case "set", "clear":
		return runUsageChange(ctx, args[0], args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "trestle usage: unknown command %q\n", args[0])
	writeUsageUsage(stderr)
	return 2
}

func usageFail(stderr io.Writer, code int, format string, values ...any) int {
	fmt.Fprintf(stderr, "trestle usage: "+format+"\n", values...)
	return code
}

func runUsageChange(ctx context.Context, command string, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trestle usage "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	variable := flags.String("credential-env", "", "")
	providerID := flags.String("provider", "", "")
	amount := flags.String("limit", "", "")
	period := flags.String("period", "month", "")
	alerts := flags.String("alert", "80,100", "")
	seen := map[string]bool{}
	for _, argument := range args {
		if name := strings.TrimLeft(strings.SplitN(argument, "=", 2)[0], "-"); strings.HasPrefix(argument, "-") && name != "" {
			if seen[name] {
				return usageFail(stderr, 2, "--%s was given twice", name)
			}
			seen[name] = true
		}
	}
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		writeUsageUsage(stderr)
		return 2
	}
	if command == "clear" && (seen["limit"] || seen["period"] || seen["alert"]) {
		return usageFail(stderr, 2, "clear takes only --credential-env and --provider")
	}
	if !runtimeconfig.ValidCredentialEnvironment(*variable) {
		if *variable == "" {
			return usageFail(stderr, 2, "--credential-env is required: the NAME of the variable that holds the key, such as OPEN_TRESTLE_PROVIDER_OPENROUTER")
		}
		return usageFail(stderr, 2, "--credential-env takes the NAME of an environment variable matching OPEN_TRESTLE_PROVIDER_[A-Z0-9_]+, never a key value")
	}
	store, err := usageStore()
	if err != nil {
		return usageFail(stderr, 1, "the usage folder cannot be found (set HOME or XDG_STATE_HOME)")
	}
	provider := *providerID
	if provider == "" {
		provider = usageUsualProviders()[*variable]
	}
	if provider == "" {
		limits, err := store.Limits()
		if err != nil {
			return usageFail(stderr, 1, "the usage folder cannot be used: %v", err)
		}
		for _, limit := range limits {
			if limit.Scope.CredentialEnvironment == *variable {
				if provider != "" {
					provider = ""
					break
				}
				provider = limit.Scope.ProviderID
			}
		}
	}
	if provider == "" {
		return usageFail(stderr, 2, "--provider is needed: %s is not a provider's usual key variable. Give the provider ID its routes use, such as openrouter, ollama-cloud or opencode-go", *variable)
	}
	scope, err := spending.NewScope(provider, *variable)
	if err != nil {
		return usageFail(stderr, 2, "--provider must be a provider ID of lowercase letters, digits, '.', '_' and '-', such as openrouter")
	}
	p := newOutPrinter(ctx, stdout)
	if command == "clear" {
		cleared, err := store.ClearLimit(ctx, scope)
		if err != nil {
			return usageFail(stderr, 1, "the limit could not be cleared: %v", err)
		}
		if !cleared {
			p.note(p.optional, fmt.Sprintf("No spending limit was set for %s.", usageKeyLabel(scope)))
			return 0
		}
		p.note(p.ok, fmt.Sprintf("Spending limit cleared for %s. Reviews still record their spend.", usageKeyLabel(scope)))
		p.aside(spending.Note)
		return 0
	}
	if *amount == "" {
		return usageFail(stderr, 2, "--limit is required: the most to spend each period, in US dollars, such as 10 or 25.50")
	}
	micro, err := spending.ParseUSD(*amount)
	if err != nil {
		return usageFail(stderr, 2, "--limit: %v", err)
	}
	parsedPeriod, err := spending.ParsePeriod(*period)
	if err != nil {
		return usageFail(stderr, 2, "--period must be week, month or year (calendar periods in UTC)")
	}
	percents, err := spending.ParseAlerts(*alerts)
	if err != nil {
		return usageFail(stderr, 2, "--alert: %v", err)
	}
	limit, err := spending.NewLimit(scope, parsedPeriod, micro, percents, spendingNow())
	if err != nil {
		return usageFail(stderr, 2, "--limit must be from $0.01 to $1000000.00")
	}
	if err := store.SetLimit(ctx, limit); err != nil {
		return usageFail(stderr, 1, "the limit could not be saved: %v", err)
	}
	p.note(p.ok, fmt.Sprintf("Spending limit set: %s for %s, alerts at %s.", limit.Describe(), usageKeyLabel(scope), spending.AlertList(limit.AlertPercents)))
	if status, err := store.CurrentStatus(limit, spendingNow()); err == nil {
		mark, tone := p.spendingState(status)
		p.note(mark, p.style.paint(tone, fmt.Sprintf("Recorded %s: %s (%d%%).", limit.Period.Current(), spending.FormatUSD(status.Spend.MicroUSD), status.Percent())))
	}
	p.note(p.optional, "A review is refused once the recorded spend reaches the limit, and warns when it could pass it.")
	p.aside(spending.Note)
	return 0
}

func runUsageStatus(ctx context.Context, stdout, stderr io.Writer) int {
	store, err := usageStore()
	if err != nil {
		return usageFail(stderr, 1, "the usage folder cannot be found (set HOME or XDG_STATE_HOME)")
	}
	keys, err := usageKeys(ctx, store)
	if err != nil {
		return usageFail(stderr, 1, "the usage folder %s cannot be used: %v", spending.DisplayDirectory(store.Directory()), err)
	}
	folder := spending.DisplayDirectory(store.Directory())
	p := newOutPrinter(ctx, stdout)
	if !p.terminal {
		fmt.Fprintln(stdout, "Spending recorded by Open Trestle (usage folder "+folder+"):")
		for _, key := range keys {
			fmt.Fprintln(stdout, "  "+usageKeyLabel(key.scope)+": "+key.text())
			for _, line := range key.provider {
				fmt.Fprintln(stdout, line)
			}
		}
		if len(keys) == 0 {
			fmt.Fprintln(stdout, "  No spending limit is set and no spend is recorded this month.")
			fmt.Fprintln(stdout, "  Set one: trestle usage set --credential-env OPEN_TRESTLE_PROVIDER_NAME --limit USD [--period week|month|year]")
		}
		fmt.Fprintln(stdout, spending.Note)
		return 0
	}
	p.heading("Spending recorded by Open Trestle")
	p.hint("  Usage folder " + folder + ".")
	for _, key := range keys {
		mark, tone := p.optional, initToneBody
		if key.status != nil {
			mark, tone = p.spendingState(*key.status)
		}
		p.rows(outRow{mark: mark, value: usageKeyLabel(key.scope)})
		p.detail(key.text(), tone)
		for _, line := range key.provider {
			p.detail(strings.TrimSpace(line), initToneDim)
		}
	}
	if len(keys) == 0 {
		p.rows(outRow{mark: p.optional, value: "No spending limit is set and no spend is recorded this month."})
		p.next("trestle usage set --credential-env OPEN_TRESTLE_PROVIDER_NAME --limit USD [--period week|month|year]")
	}
	p.aside(spending.Note)
	return 0
}

// usageKey is one key's spending: the status of its limit, or without a
// limit what is recorded this month, and OpenRouter's own figures.
type usageKey struct {
	scope    spending.Scope
	status   *spending.Status
	spend    spending.Spend
	provider []string
}

func (k usageKey) text() string {
	if k.status != nil {
		return k.status.Brief()
	}
	return k.spend.Unlimited(spending.PeriodMonth)
}

// usageKeys is every limited key, then every key with spend recorded this
// month, with OpenRouter's own figures for an OpenRouter key whose variable
// is set.
func usageKeys(ctx context.Context, store *spending.Store) ([]usageKey, error) {
	now := spendingNow()
	limits, err := store.Limits()
	if err != nil {
		return nil, err
	}
	start, end := spending.PeriodMonth.Bounds(now)
	entries, err := store.Entries(start, end)
	if err != nil {
		return nil, err
	}
	keys := []usageKey{}
	shown := map[spending.Scope]bool{}
	for _, limit := range limits {
		status, err := store.CurrentStatus(limit, now)
		if err != nil {
			return nil, err
		}
		shown[limit.Scope] = true
		keys = append(keys, usageKey{scope: limit.Scope, status: &status, provider: usageProviderLines(ctx, limit.Scope)})
	}
	for _, scope := range spending.Scopes(entries) {
		if shown[scope] {
			continue
		}
		keys = append(keys, usageKey{scope: scope, spend: spending.SumSpend(entries, scope), provider: usageProviderLines(ctx, scope)})
	}
	// An OpenRouter key in this shell or the credential store with no limit
	// and no spend yet still gets OpenRouter's own figures, which need no
	// limit to be useful.
	if scope, err := spending.NewScope("openrouter", usageOpenRouterKeyVariable); err == nil && !shown[scope] && providerKeyStatus(usageOpenRouterKeyVariable).available() && !slices.Contains(spending.Scopes(entries), scope) {
		keys = append(keys, usageKey{scope: scope, spend: spending.SumSpend(entries, scope), provider: usageProviderLines(ctx, scope)})
	}
	return keys, nil
}

// usageOpenRouterKeyVariable is the key variable `trestle init` names for
// OpenRouter.
const usageOpenRouterKeyVariable = "OPEN_TRESTLE_PROVIDER_OPENROUTER"

func usageKeyLabel(scope spending.Scope) string {
	return scope.CredentialEnvironment + " (" + scope.ProviderID + ")"
}

// usageProviderLines reads OpenRouter's report for an OpenRouter key that is
// set in the environment or saved in the credential store. A failure only
// says the report could not be read.
func usageProviderLines(ctx context.Context, scope spending.Scope) []string {
	if scope.ProviderID != "openrouter" {
		return nil
	}
	key, state := providerKey(scope.CredentialEnvironment)
	if key == "" {
		reason := " is not set in this shell and no key is saved for it."
		if state.problem != nil {
			reason = " is not set in this shell, and " + state.where() + "."
		}
		return []string{"    OpenRouter's own figures are not read: " + scope.CredentialEnvironment + reason}
	}
	usage, err := spending.ReadOpenRouterKeyUsage(ctx, usageOpenRouterTransport, key)
	if err != nil {
		if !errors.Is(err, spending.ErrOpenRouterKeyUnreadable) {
			err = spending.ErrOpenRouterKeyUnreadable
		}
		return []string{"    " + err.Error() + "."}
	}
	return []string{"    " + usage.Line() + "."}
}
