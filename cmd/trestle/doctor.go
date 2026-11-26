package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/internal/checksandbox"
	"github.com/georgejieh/open-trestle/internal/secretscan"
	"github.com/georgejieh/open-trestle/modelcatalog"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"github.com/georgejieh/open-trestle/spending"
)

// `trestle doctor` checks this program, the repository in the current
// directory and its setup, and names the command that fixes each problem. It
// reads local files and runs read-only Git queries: it writes nothing and
// sends nothing, and the update row reads only the cached notice. --live adds
// network checks that read the provider's model list, with the key where the
// provider takes one; they send no source either.

const doctorContract = "open-trestle/doctor"

// doctorSandbox reports whether the repository checks sandbox can run here.
// Tests replace it.
var doctorSandbox = checksandbox.Available

type doctorSection struct {
	Title string      `json:"title"`
	Rows  []healthRow `json:"rows"`
}

type doctorReport struct {
	Contract      string          `json:"contract"`
	SchemaVersion int             `json:"schema_version"`
	Live          bool            `json:"live"`
	Passed        bool            `json:"passed"`
	Sections      []doctorSection `json:"sections"`
	Problems      []healthRow     `json:"problems"`
}

func writeDoctorUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle doctor [--live] [--json]")
	fmt.Fprintln(w, "       check this install, the repository and its setup, and name the command that fixes each problem; it changes nothing and sends no source")
	fmt.Fprintln(w, "       --live also reads the provider's model list with the key (network checks)")
}

func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trestle doctor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	live := flags.Bool("live", false, "")
	asJSON := flags.Bool("json", false, "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		if errors.Is(err, flag.ErrHelp) {
			writeDoctorUsage(stdout)
			return 0
		}
		writeDoctorUsage(stderr)
		return 2
	}
	report := doctorReport{Contract: doctorContract, SchemaVersion: 1, Live: *live, Sections: doctorSections(ctx, *live), Problems: []healthRow{}}
	for _, section := range report.Sections {
		for _, row := range section.Rows {
			if row.State == healthFail {
				report.Problems = append(report.Problems, row)
			}
		}
	}
	report.Passed = len(report.Problems) == 0
	code := 0
	if !report.Passed {
		code = 1
	}
	if *asJSON {
		if err := json.NewEncoder(stdout).Encode(report); err != nil {
			fmt.Fprintln(stderr, "trestle doctor: the result could not be written")
			return 1
		}
		return code
	}
	renderDoctor(newOutPrinter(ctx, stdout), report)
	return code
}

// renderDoctor prints the sections, then what to fix. Labels line up across
// every section.
func renderDoctor(p outPrinter, report doctorReport) {
	title := "Open Trestle · doctor"
	if report.Live {
		title += " --live"
	}
	p.heading(title)
	p.hint("  Read-only: nothing is changed and no source is sent.")
	width := 0
	for _, section := range report.Sections {
		for _, row := range section.Rows {
			width = max(width, initVisible(row.Label))
		}
	}
	for _, section := range report.Sections {
		p.sayVerbatim("")
		p.heading(section.Title)
		rows := []outRow{}
		for _, row := range section.Rows {
			label := row.Label + strings.Repeat(" ", width-initVisible(row.Label))
			rows = append(rows, outRow{mark: p.style.markOf(row.State), label: label, value: row.Value, tone: row.tone, next: row.Next})
		}
		p.rows(rows...)
	}
	p.sayVerbatim("")
	if report.Passed {
		attention := 0
		for _, section := range report.Sections {
			for _, row := range section.Rows {
				if row.State == healthAttention {
					attention++
				}
			}
		}
		if attention == 0 {
			p.sayVerbatim(p.style.paint(initToneSuccess, "All checks passed."))
		} else {
			p.sayVerbatim(p.style.paint(initToneWarning, fmt.Sprintf("Nothing to fix. %d row%s above need%s a look.", attention, initPlural(attention), map[bool]string{true: "s", false: ""}[attention == 1])))
		}
		return
	}
	p.sayVerbatim(p.style.paint(initToneDanger, fmt.Sprintf("%d problem%s to fix:", len(report.Problems), initPlural(len(report.Problems)))))
	for i, row := range report.Problems {
		p.say("  %d. %s: %s", i+1, row.Label, row.Value)
		for _, command := range row.Next {
			p.sayVerbatim(p.style.paint(initToneDim, "     -> "+command))
		}
	}
}

func doctorSections(ctx context.Context, live bool) []doctorSection {
	repository := doctorSection{Title: "Repository"}
	setup := doctorSection{Title: "Setup"}
	var repo *repositorySetup
	checkout, err := findRepositoryCheckout(ctx)
	if err != nil {
		repository.Rows = []healthRow{{Label: "Checkout", Value: "this folder is not inside a Git checkout, or git is not installed", State: healthAttention, Next: []string{"cd REPOSITORY && trestle doctor"}}}
		setup.Rows = []healthRow{doctorNotChecked("Folder", "no Git checkout here")}
	} else {
		repository.Rows = doctorRepository(ctx, checkout)
		setup.Rows, repo = doctorSetup(ctx, checkout)
	}
	keys := doctorSection{Title: "Keys", Rows: []healthRow{doctorNotChecked("Key", "no usable setup")}}
	spend := doctorSection{Title: "Spending", Rows: []healthRow{doctorNotChecked("Spending", "no usable setup")}}
	if repo != nil {
		keys.Rows, spend.Rows = doctorKeys(repo.setup), doctorSpending(repo.setup)
	}
	sections := []doctorSection{
		{Title: "Install", Rows: doctorInstall()},
		repository, setup, keys, spend,
		{Title: "Repository checks", Rows: doctorChecks(ctx, repo)},
		{Title: "Update", Rows: []healthRow{doctorUpdate(ctx)}},
	}
	if live {
		sections = append(sections, doctorSection{Title: "Network checks (--live)", Rows: doctorLive(ctx, repo)})
	}
	return sections
}

func doctorNotChecked(label, reason string) healthRow {
	return healthRow{Label: label, Value: "not checked: " + reason, State: healthOptional}
}

func doctorInstall() []healthRow {
	var version strings.Builder
	writeVersion(&version)
	rows := []healthRow{{Label: "Version", Value: strings.TrimPrefix(strings.TrimSpace(version.String()), "Open Trestle "), State: healthOK}}
	helper := healthRow{Label: "Scanner", Value: "found, and it matches the SHA-256 this build pins", State: healthOK}
	build := "python3 tools/package_secret_scanner.py --development DIR"
	if runningInstalledTrestle() {
		build = "docs/install.md"
	}
	switch err := setupBootstrapScannerPrerequisite(); {
	case err == nil:
	case errors.Is(err, secretscan.ErrHelperNotPinned):
		helper.State, helper.Value, helper.Next = healthFail, "this build pins none, so every review is refused", []string{build}
	case errors.Is(err, secretscan.ErrScannerUnsupportedPlatform):
		helper.State, helper.Value, helper.Next = healthFail, "it does not run on this system, so every review is refused", []string{"docs/platforms.md"}
	default:
		helper.State, helper.Value, helper.Next = healthFail, "missing next to this program, or not the one this build pins, so every review is refused", []string{build}
	}
	platform := healthRow{Label: "Platform", Value: updatePlatform + ", supported", State: healthOK}
	switch updatePlatform {
	case "linux/amd64", "windows/amd64":
	case "linux/arm64", "windows/arm64":
		platform.State, platform.Value = healthOptional, updatePlatform+", which builds but is untested"
	default:
		platform.State, platform.Value, platform.Next = healthAttention, updatePlatform+" is not supported", []string{"docs/platforms.md"}
	}
	return append(rows, helper, platform)
}

func doctorRepository(ctx context.Context, checkout string) []healthRow {
	summary := initSummarizeChange(ctx, checkout, "HEAD", "HEAD")
	where := initDisplayPath(checkout)
	if summary.currentLabel != "" {
		where += " (on branch " + summary.currentLabel + ")"
	}
	rows := []healthRow{{Label: "Checkout", Value: where, State: healthOK}}
	branch := healthRow{Label: "Branch", Value: "no default branch: no main or master here or on origin, so a review needs --base", State: healthAttention, Next: []string{"trestle review --base REF"}}
	if name := initDefaultBranchName(ctx, checkout); name != "" {
		branch = healthRow{Label: "Branch", Value: "default branch " + name, State: healthOK}
	}
	history := healthRow{Label: "History", Value: "complete", State: healthOK}
	if shallow, _, err := initGit(ctx, checkout, "rev-parse", "--is-shallow-repository"); err == nil && strings.TrimSpace(shallow) == "true" {
		history = healthRow{Label: "History", Value: "a shallow clone: a review stops when its base commit is missing", State: healthAttention, Next: []string{"git fetch --unshallow"}}
	}
	tree := healthRow{Label: "Changes", Value: "clean", State: healthOK}
	if summary.uncommitted {
		tree.Value = "uncommitted changes, which reviews leave out"
	}
	return append(rows, branch, history, tree)
}

// doctorSetup checks the setup folder and returns the setup when it can be
// used for this checkout.
func doctorSetup(ctx context.Context, checkout string) ([]healthRow, *repositorySetup) {
	dir := discoverSetupDirectory(ctx, checkout)
	if !setupExists(dir) {
		return []healthRow{{Label: "Folder", Value: "none for this repository; looked in " + initDisplayPath(dir), State: healthFail, Next: []string{"trestle init"}}}, nil
	}
	repo, err := loadRepositorySetup(ctx, checkout, dir)
	if err != nil {
		return []healthRow{{Label: "Folder", Value: "cannot be used (" + err.Error() + "): " + initDisplayPath(dir), State: healthFail, Next: []string{"trestle setup bootstrap inspect --directory " + initShellQuote(dir), "trestle init"}}}, nil
	}
	if !sameCheckout(repo.templateCheckout, checkout) {
		return []healthRow{{Label: "Folder", Value: initDisplayPath(dir) + " is for " + initDisplayPath(repo.templateCheckout) + ", not this repository", State: healthFail, Next: []string{"trestle init"}}}, nil
	}
	setup := repo.setup
	provider := setup.destination()
	if setup.remote {
		provider = setup.provider.short + " (" + strings.Join(setup.endpoints, ", ") + ")"
	}
	rows := []healthRow{
		{Label: "Folder", Value: "loads from " + initDisplayPath(dir), State: healthOK},
		{Label: "Provider", Value: provider, State: healthOK},
		{Label: "Models", Value: "finder " + setup.generationModel + " · checker " + setup.verificationModel, State: healthOK},
		doctorRoute(ctx, repo),
	}
	switch setup.retention {
	case "required_per_request":
		rows = append(rows, healthRow{Label: "Retention", Value: "zero data retention required on every request", State: healthOK})
	case "not_required_by_open_trestle":
		rows = append(rows, healthRow{Label: "Retention", Value: "zero data retention not required by Open Trestle", State: healthOptional})
	}
	return rows, &repo
}

// doctorRoute runs the offline checks of `trestle setup bootstrap check` on a
// remote setup, leaving the key and the scan helper to their own rows. The
// signed-in Ollama check asks the local daemon, so doctor leaves it to
// trestle init.
func doctorRoute(ctx context.Context, repo repositorySetup) healthRow {
	row := healthRow{Label: "Route", Value: "ready: the saved route and policy load", State: healthOK}
	if !repo.setup.remote || repo.setup.provider.key == ollamaSigninProvider {
		return row
	}
	manifest, inventory, policy, err := loadRemoteSetupBootstrap(ctx, repo.directory)
	if err != nil {
		return healthRow{Label: "Route", Value: err.Error(), State: healthFail, Next: []string{"trestle init"}}
	}
	result := checkRemoteSetupBootstrap(ctx, manifest, inventory, policy, time.Now().UTC())
	for i, check := range result.checks {
		if check == "credential_environment_present" || check == setupScannerCheck {
			continue
		}
		state := healthAttention
		if slices.Contains(result.Refused, check) {
			state = healthFail
		}
		if state == healthFail || row.State == healthOK {
			row = healthRow{Label: "Route", Value: result.Messages[i], State: state, Next: []string{"trestle init"}}
		}
	}
	return row
}

func doctorKeys(setup initSetup) []healthRow {
	switch {
	case setup.provider.key == ollamaSigninProvider:
		return []healthRow{{Label: "Key", Value: "none needed: your local Ollama's signed-in account", State: healthOptional}}
	case !setup.remote || len(setup.credentials) == 0:
		return []healthRow{{Label: "Key", Value: "none needed for this setup", State: healthOptional}}
	}
	store, storeErr := providerCredentialStore()
	rows := []healthRow{}
	for _, name := range setup.credentials {
		key, state := providerKey(name)
		row := healthRow{Label: "Key", Value: name + " " + state.where(), State: healthOK}
		switch {
		case state.source == providerKeyFromStore:
			row.Value = name + " saved"
		case !state.available():
			row.State, row.Next = healthFail, []string{"trestle keys set " + name}
			if state.problem == nil {
				row.Value = name + " is not set in this shell and not saved"
			}
		}
		if storeErr == nil && keysBothSet(store, name, state) {
			row.Value += "; a saved key too, and the environment wins"
		}
		if suffix := keysMaskedSuffix(key); suffix != "" {
			row.Value += " · " + suffix
		}
		rows = append(rows, row)
	}
	return rows
}

// doctorSpending is each key's limit and its use this period, from the usage
// folder only.
func doctorSpending(setup initSetup) []healthRow {
	provider := initSpendingProvider(setup.provider.key)
	if !setup.remote || provider == "" {
		return []healthRow{{Label: "Spending", Value: "not tracked: these models cost nothing per request", State: healthOptional}}
	}
	store, err := usageStore()
	if err != nil {
		return []healthRow{{Label: "Spending", Value: "the usage folder cannot be found (set HOME or XDG_STATE_HOME)", State: healthFail, Next: []string{"trestle usage"}}}
	}
	now := spendingNow()
	start, end := spending.PeriodMonth.Bounds(now)
	rows := []healthRow{}
	for _, name := range setup.credentials {
		scope, err := spending.NewScope(provider, name)
		if err != nil {
			continue
		}
		subject := ""
		if len(setup.credentials) > 1 {
			subject = name + ": "
		}
		set := "trestle usage set --credential-env " + name + " --limit USD"
		var row healthRow
		limit, found, err := store.Limit(scope)
		switch {
		case err != nil:
		case found:
			var status spending.Status
			if status, err = store.CurrentStatus(limit, now); err == nil {
				state, tone := spendingLevel(status)
				row = healthRow{Label: "Spending", Value: subject + status.Brief(), State: state, tone: tone}
				switch state {
				case healthFail:
					row.Next = []string{set}
				case healthAttention:
					row.Next = []string{"trestle usage"}
				}
			}
		default:
			var spent spending.Spend
			if spent, err = store.Spent(scope, start, end); err == nil {
				row = healthRow{Label: "Spending", Value: subject + spent.Unlimited(spending.PeriodMonth), State: healthOptional, Next: []string{set}}
			}
		}
		if err != nil {
			row = healthRow{Label: "Spending", Value: subject + "the usage folder cannot be used: " + err.Error(), State: healthFail, Next: []string{"trestle usage"}}
		}
		rows = append(rows, row)
	}
	return rows
}

func doctorChecks(ctx context.Context, repo *repositorySetup) []healthRow {
	answer := doctorNotChecked("Checks", "no usable setup")
	on := false
	if repo != nil {
		allowed, decided := readChecksConsent(repo.directory, checksRepository(ctx, repo.checkout))
		switch {
		case !decided:
			answer = healthRow{Label: "Checks", Value: "not decided yet: the next review asks before it runs any", State: healthAttention, Next: []string{"trestle checks on", "trestle checks off"}}
		case allowed:
			answer, on = healthRow{Label: "Checks", Value: "on: each review first runs this repository's tests for the changed area in a sandbox", State: healthOK}, true
		default:
			answer = healthRow{Label: "Checks", Value: "off: reviews do not run this repository's code", State: healthOptional}
		}
	}
	box := healthRow{Label: "Sandbox", Value: "available here", State: healthOK}
	if err := doctorSandbox(); err != nil {
		box = healthRow{Label: "Sandbox", Value: fmt.Sprintf("not available on this machine, so checks would be reported as could not run (%v)", err), State: healthOptional}
		if on {
			box.State, box.Next = healthAttention, []string{"trestle checks off"}
		}
	}
	return []healthRow{answer, box}
}

// doctorUpdate reads the cached update notice and never the network.
func doctorUpdate(ctx context.Context) healthRow {
	row := healthRow{Label: "Update", State: healthOptional}
	if _, installed := updatePackageInstalled(); !installed {
		row.Value = "not a packaged install, so trestle update does not apply"
		return row
	}
	if updateCheckDisabled() {
		row.Value = "the update notice is off (OPEN_TRESTLE_UPDATE_CHECK)"
		return row
	}
	if notice := updateNoticeFrom(ctx, false); notice != "" {
		return healthRow{Label: "Update", Value: strings.TrimSuffix(notice, " Run trestle update."), State: healthAttention, Next: []string{"trestle update"}}
	}
	if path, err := updateCachePath(); err == nil {
		if cache, cached := readUpdateCache(path); cached {
			checked, _ := time.Parse(time.RFC3339, cache.CheckedAt)
			return healthRow{Label: "Update", Value: "no newer version known (checked " + checked.UTC().Format("2 Jan 15:04 UTC") + ")", State: healthOK}
		}
	}
	row.Value, row.Next = "not checked yet", []string{"trestle update --check"}
	return row
}

// doctorLive reads the provider's model list and finds both models in it; for
// OpenRouter it first asks whether the key is accepted.
func doctorLive(ctx context.Context, repo *repositorySetup) []healthRow {
	if repo == nil {
		return []healthRow{doctorNotChecked("Model list", "no usable setup")}
	}
	setup := repo.setup
	name, key := "", ""
	if setup.remote && len(setup.credentials) > 0 {
		name = setup.credentials[0]
		if key, _ = providerKey(name); key == "" {
			return []healthRow{doctorNotChecked("Model list", "no key for "+name)}
		}
	}
	rows := []healthRow{}
	sources, allowRemote := []modelcatalog.Source{}, true
	switch {
	case !setup.remote:
		for _, endpoint := range setup.endpoints {
			sources = append(sources, modelcatalog.Source{ID: "local-server", Kind: "openai_models", URL: endpoint + "/models"})
		}
		allowRemote = false
	case setup.provider.key == "openrouter":
		rows = append(rows, doctorOpenRouterKey(ctx, name, key))
		sources = append(sources, modelcatalog.Source{ID: "openrouter", Kind: "openai_models", URL: runtimeconfig.OpenRouterModelsURL})
	case setup.provider.catalog != nil:
		source := *setup.provider.catalog
		source.CredentialEnvironment = name
		sources = append(sources, source)
	default:
		return []healthRow{{Label: "Model list", Value: "not checked for this provider; trestle init runs its setup checks", State: healthOptional}}
	}
	listed := map[string]bool{}
	for _, source := range sources {
		host := source.URL
		if parsed, err := url.Parse(source.URL); err == nil {
			host = parsed.Host
		}
		var resolver modelcatalog.CredentialResolver
		if source.CredentialEnvironment != "" {
			value, err := runtimecatalog.NewEnvironmentOpenAICredentialResolver(providerCredentialLookup)
			if err != nil {
				rows = append(rows, healthRow{Label: "Model list", Value: "the key cannot be read: " + err.Error(), State: healthFail, Next: []string{"trestle keys set " + name}})
				continue
			}
			resolver = value
		}
		models, err := initListModels(ctx, source, allowRemote, resolver)
		if err != nil {
			next := "trestle init"
			if name != "" {
				next = "trestle keys set " + name
			}
			rows = append(rows, healthRow{Label: "Model list", Value: "could not be read from " + host + " (" + err.Error() + ")", State: healthFail, Next: []string{next}})
			continue
		}
		with := ""
		if source.CredentialEnvironment != "" {
			with = " with " + name
		}
		rows = append(rows, healthRow{Label: "Model list", Value: fmt.Sprintf("read from %s%s, %d models", host, with, len(models)), State: healthOK})
		for _, model := range models {
			listed[model.Selector] = true
		}
	}
	if len(listed) == 0 {
		return rows
	}
	for _, model := range [][2]string{{"Finder", setup.generationModel}, {"Checker", setup.verificationModel}} {
		row := healthRow{Label: model[0], Value: model[1] + " is listed", State: healthOK}
		if !listed[model[1]] {
			row = healthRow{Label: model[0], Value: model[1] + " is no longer listed", State: healthFail, Next: []string{"trestle init"}}
		}
		rows = append(rows, row)
	}
	return rows
}

// doctorOpenRouterKey asks OpenRouter whether it accepts the key, with the
// GET that `trestle keys set` uses, which costs nothing.
func doctorOpenRouterKey(ctx context.Context, name, key string) healthRow {
	_, err := spending.ReadOpenRouterKeyUsage(ctx, usageOpenRouterTransport, key)
	var status spending.OpenRouterKeyStatusError
	switch {
	case err == nil:
		return healthRow{Label: "Key check", Value: "OpenRouter accepts " + name, State: healthOK}
	case errors.As(err, &status) && status.KeyRefused():
		return healthRow{Label: "Key check", Value: fmt.Sprintf("OpenRouter refuses %s (HTTP %d)", name, status.StatusCode), State: healthFail, Next: []string{"trestle keys set " + name}}
	}
	return healthRow{Label: "Key check", Value: "could not be checked (" + strings.TrimPrefix(err.Error(), spending.ErrOpenRouterKeyUnreadable.Error()+": ") + ")", State: healthAttention, Next: []string{"trestle doctor --live"}}
}
