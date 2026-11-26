package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/spending"
)

// `trestle status` is the home screen's card without its actions: where the
// repository and its setup are, the models, the key, this month's spending,
// the last review and a known update. On a terminal it is the card; elsewhere
// one "Label:  value" line per row. It reads local state only and uses the
// cached update notice, so it sends nothing.

const statusContract = "open-trestle/status"

func writeStatusUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle status [--json]")
	fmt.Fprintln(w, "       this repository's setup, key, spending and last review; it changes nothing and sends nothing")
}

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trestle status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	asJSON := flags.Bool("json", false, "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		if errors.Is(err, flag.ErrHelp) {
			writeStatusUsage(stdout)
			return 0
		}
		writeStatusUsage(stderr)
		return 2
	}
	title, rows, ready := statusOfCurrentDirectory(ctx)
	code := 0
	if !ready {
		code = 1
	}
	if *asJSON {
		document := struct {
			Contract      string      `json:"contract"`
			SchemaVersion int         `json:"schema_version"`
			Ready         bool        `json:"ready"`
			Rows          []healthRow `json:"rows"`
		}{statusContract, 1, ready, rows}
		if err := json.NewEncoder(stdout).Encode(document); err != nil {
			fmt.Fprintln(stderr, "trestle status: the result could not be written")
			return 1
		}
		return code
	}
	p := newOutPrinter(ctx, stdout)
	if p.terminal {
		for _, line := range statusCard(p.style, title, rows) {
			p.sayVerbatim(line)
		}
		return code
	}
	width := 0
	for _, row := range rows {
		width = max(width, len(row.Label))
	}
	for _, row := range rows {
		fmt.Fprintf(stdout, "%-*s  %s\n", width+1, row.Label+":", statusValue(row))
	}
	return code
}

// statusOfCurrentDirectory is the card's title and rows for the repository
// in the current directory, and whether it has a usable setup.
func statusOfCurrentDirectory(ctx context.Context) (string, []healthRow, bool) {
	checkout, err := findRepositoryCheckout(ctx)
	if err != nil {
		return "Open Trestle", []healthRow{{Label: "Repository", Value: "none: this folder is not inside a Git checkout, or git is not installed", State: healthFail, Next: []string{"cd REPOSITORY && trestle status"}}}, false
	}
	title := initLabel(filepath.Base(checkout), "repository")
	where := healthRow{Label: "Repository", Value: initDisplayPath(checkout), State: healthOK}
	dir := discoverSetupDirectory(ctx, checkout)
	if !setupExists(dir) {
		return title, []healthRow{where, {Label: "Setup", Value: "none yet", State: healthFail, Next: []string{"trestle init"}}}, false
	}
	repo, err := loadRepositorySetup(ctx, checkout, dir)
	if err != nil {
		return title, []healthRow{where, {Label: "Setup", Value: initDisplayPath(dir) + " cannot be read (" + err.Error() + ")", State: healthFail, Next: []string{"trestle doctor"}}}, false
	}
	if !sameCheckout(repo.templateCheckout, checkout) {
		return title, []healthRow{where, {Label: "Setup", Value: initDisplayPath(dir) + " is for " + initDisplayPath(repo.templateCheckout), State: healthFail, Next: []string{"trestle init"}}}, false
	}
	return title, withUpdate(statusRows(ctx, repo), updateNoticeFrom(ctx, false)), true
}

// statusRows is the card of a usable setup.
func statusRows(ctx context.Context, repo repositorySetup) []healthRow {
	setup := repo.setup
	summary := initSummarizeChange(ctx, repo.checkout, "HEAD", "HEAD")
	where := initDisplayPath(repo.checkout)
	if summary.currentLabel != "" {
		where += " (on branch " + summary.currentLabel + ")"
	}
	rows := []healthRow{
		{Label: "Repository", Value: where, State: healthOK},
		{Label: "Setup", Value: initDisplayPath(repo.directory), State: healthOK},
		{Label: "Models", Value: "finder " + setup.generationModel + " · checker " + setup.verificationModel, State: healthOK},
		{Label: "Runs on", Value: setup.destination(), State: healthOK},
	}
	switch {
	case setup.provider.key == ollamaSigninProvider:
		rows = append(rows, healthRow{Label: "Key", Value: "none (your local Ollama's signed-in account)", State: healthOK})
	case len(setup.credentials) == 0:
		rows = append(rows, healthRow{Label: "Key", Value: "none", State: healthOK})
	default:
		for _, name := range setup.credentials {
			row := healthRow{Label: "Key", Value: name + " (" + providerKeyStatus(name).where() + ")", State: healthOK}
			if !providerKeyStatus(name).available() {
				row.State, row.Next = healthFail, []string{"trestle keys set " + name}
			}
			rows = append(rows, row)
		}
	}
	rows = append(rows, statusSpending(setup))
	last := "none recorded yet"
	if review, ok := readLastReview(repo.directory); ok {
		last = review.Status
		if review.Status == "findings" {
			last = fmt.Sprintf("%d confirmed finding%s", review.Findings, initPlural(review.Findings))
		} else if review.Status == "no_candidates" {
			last = "no confirmed findings"
		}
		if at, err := time.Parse(time.RFC3339, review.RecordedAt); err == nil {
			last += " · " + at.UTC().Format("2 Jan 15:04 UTC")
		}
		last += " · " + initShort(review.Base) + " → " + initShort(review.Head)
	}
	return append(rows, healthRow{Label: "Last run", Value: last, State: healthOK})
}

// withUpdate adds the update notice as the last row, when there is one.
func withUpdate(rows []healthRow, notice string) []healthRow {
	if notice == "" {
		return rows
	}
	value := strings.TrimSuffix(strings.TrimPrefix(notice, "Update available: "), ". Run trestle update.")
	return append(rows, healthRow{Label: "Update", Value: "available: " + value, State: healthAttention, Next: []string{"trestle update"}})
}

// statusSpending is this month's recorded spending for the setup's keys, as
// `trestle usage` reports it, from the local usage folder only. Its state and
// tone are those of the key nearest its limit.
func statusSpending(setup initSetup) healthRow {
	row := healthRow{Label: "Spending", State: healthOK}
	provider := initSpendingProvider(setup.provider.key)
	if !setup.remote || provider == "" {
		row.Value = "not tracked: these models cost nothing per request"
		return row
	}
	store, err := usageStore()
	if err != nil {
		row.Value = "unknown: the usage folder cannot be found"
		return row
	}
	now := spendingNow()
	start, end := spending.PeriodMonth.Bounds(now)
	parts := []string{}
	rank := map[healthState]int{healthOK: 0, healthAttention: 1, healthFail: 2}
	for _, name := range setup.credentials {
		scope, err := spending.NewScope(provider, name)
		if err != nil {
			continue
		}
		if limit, found, err := store.Limit(scope); err == nil && found {
			if status, err := store.CurrentStatus(limit, now); err == nil {
				parts = append(parts, status.Brief())
				if state, tone := spendingLevel(status); rank[state] > rank[row.State] || row.tone == initToneBody && rank[state] == rank[row.State] {
					row.State, row.tone = state, tone
				}
				continue
			}
		}
		spent, err := store.Spent(scope, start, end)
		if err != nil {
			parts = append(parts, "unknown: "+err.Error())
			continue
		}
		parts = append(parts, spent.Unlimited(spending.PeriodMonth))
	}
	if len(parts) == 0 {
		row.Value = "none recorded"
		return row
	}
	row.Value = strings.Join(parts, "; ") + " (an upper-bound estimate, not a bill)"
	if row.State != healthOK {
		row.Next = []string{"trestle usage"}
	}
	return row
}

// statusValue is a row's value with the command that fixes it.
func statusValue(row healthRow) string {
	if len(row.Next) == 0 {
		return row.Value
	}
	return row.Value + " -> " + strings.Join(row.Next, " | ")
}

// statusCard frames rows as the home screen's card. A row that needs action
// starts with its mark and has its commands beneath it, and the spending row
// keeps its tone.
func statusCard(style initStyle, title string, rows []healthRow) []string {
	paint := func(tone initTone, text string) string {
		words := strings.Fields(text)
		for i, word := range words {
			words[i] = style.paint(tone, word)
		}
		return strings.Join(words, " ")
	}
	cells := make([][2]string, 0, len(rows))
	for _, row := range rows {
		value := paint(row.tone, row.Value)
		if row.State == healthAttention || row.State == healthFail {
			value = style.markOf(row.State) + " " + value
		}
		cells = append(cells, [2]string{row.Label, value})
		for _, command := range row.Next {
			cells = append(cells, [2]string{"", paint(initToneDim, "-> "+command)})
		}
	}
	return style.framed(initPanel(title, cells, style.ascii))
}
