package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/localreview"
	"github.com/georgejieh/open-trestle/spending"
)

// Spending limits for `trestle local-git model-review`. Before each review
// run starts, and before any credential is read for model dispatch, the
// limits of the API keys the routes use are compared with the local usage
// ledger: a key at or over its limit refuses the run, and one that this run's
// worst case could take past its limit only warns. After a run that sent at
// least one request, one ledger entry is appended and any alert percentage it
// crossed is printed. Every message goes to standard error, so JSON and SARIF
// output stay one document, and every message carries spending.Note. The
// ledger and limits are best effort; the provider's own limit is the
// guarantee.

// Tests replace the clock and the credential lookup; production reads the
// system clock and each provider key from the environment, then the
// credential store (providerCredentialLookup).
var (
	spendingNow                 = func() time.Time { return time.Now().UTC() }
	localReviewCredentialLookup = providerCredentialLookup
)

// spendingRecordTimeout bounds the ledger append after a run, which uses its
// own context so a canceled review still records requests it already sent.
const spendingRecordTimeout = 15 * time.Second

// reviewSpending is the spending state of one review invocation.
type reviewSpending struct {
	store  *spending.Store
	scopes []spending.Scope
	models []string
	policy string
	// worst is the most one review run may cost: the per-request bound for
	// each of its two requests, or an investigation policy's run budget.
	worst uint64
	// runs is how many review runs the invocation may start: 1, or for a
	// specialist review set the general review plus every specialist it may
	// select. The first check warns for all of them.
	runs   int
	text   bool
	stderr io.Writer
	// shown records keys whose status was already printed this invocation.
	shown map[spending.Scope]bool
	// mu serializes checks, ledger appends and messages: specialist members
	// may run concurrently.
	mu sync.Mutex
	// warned is set once the invocation's worst case was checked.
	warned bool
}

// invocationRuns is how many review runs an invocation may start.
func invocationRuns(options localModelReviewOptions) int {
	switch request := options.specialists; request.mode {
	case specialistModeExplicit:
		return 1 + len(request.explicit)
	case specialistModeAuto:
		return 1 + request.max
	}
	return 1
}

// timesRuns multiplies a per-run bound by runs, saturating.
func timesRuns(bound uint64, runs int) uint64 {
	if runs <= 1 {
		return bound
	}
	if bound > ^uint64(0)/uint64(runs) {
		return ^uint64(0)
	}
	return bound * uint64(runs)
}

// newReviewSpending returns nil when no remote route uses an API key: the
// Ollama sign-in route sends none, and a model server on this machine costs
// nothing per request, so there is nothing to limit.
func newReviewSpending(inputs localModelReviewInputs, options localModelReviewOptions, stderr io.Writer) *reviewSpending {
	providers := map[string]string{}
	remote := map[string]bool{}
	var models []string
	for _, candidate := range inputs.inventory.Candidates() {
		route := candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		providers[route.AdapterID()] = route.ProviderID()
		remote[route.AdapterID()] = route.Zone() != provider.ProviderZoneLocal
		if !slices.Contains(models, route.ModelID()) {
			models = append(models, route.ModelID())
		}
	}
	var scopes []spending.Scope
	for _, connection := range inputs.policy.Connections() {
		if connection.CredentialEnvironment() == "" || !remote[connection.AdapterID()] {
			continue
		}
		scope, err := spending.NewScope(providers[connection.AdapterID()], connection.CredentialEnvironment())
		if err != nil || slices.Contains(scopes, scope) {
			continue
		}
		scopes = append(scopes, scope)
	}
	if len(scopes) == 0 {
		return nil
	}
	worst := inputs.policy.Budget().MaxCostMicroUSD()
	if worst > ^uint64(0)/2 {
		worst = ^uint64(0)
	} else {
		worst *= 2
	}
	if options.investigation != "" {
		worst = inputs.investigationPolicy.MaxCostMicroUSD()
	}
	s := &reviewSpending{scopes: scopes, models: models, policy: inputs.policy.Identity(), worst: worst, runs: invocationRuns(options), text: options.format == "text", stderr: stderr, shown: map[spending.Scope]bool{}}
	dir, err := spending.DefaultDirectory(os.Getenv)
	if err == nil {
		s.store, err = spending.NewStore(dir)
	}
	if err != nil {
		s.say("Spending is not tracked: the usage folder could not be found (set HOME or XDG_STATE_HOME); your provider's own limit still applies.")
	}
	return s
}

// say prints spending lines followed by the note.
func (s *reviewSpending) say(lines ...string) {
	for _, line := range lines {
		fmt.Fprintln(s.stderr, line)
	}
	fmt.Fprintln(s.stderr, spending.Note)
}

// refuse checks every limited key before a run. It reports true when a key is
// at or over its limit; the caller then returns the refusal result without
// opening a session, reading a credential or sending a request. The first
// check of an invocation also warns when its worst case, every run it may
// start, could pass a limit; later checks of a review set only refuse.
func (s *reviewSpending) refuse() bool {
	if s == nil || s.store == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	worst := uint64(0)
	if !s.warned {
		worst, s.warned = timesRuns(s.worst, s.runs), true
	}
	now := spendingNow()
	refused := false
	var lines []string
	for _, scope := range s.scopes {
		limit, found, err := s.store.Limit(scope)
		if err == nil && !found {
			continue
		}
		var status spending.Status
		if err == nil {
			status, err = s.store.CurrentStatus(limit, now)
		}
		if err != nil {
			lines = append(lines, fmt.Sprintf("Spending limit not checked for %s: %v. The review runs; your provider's own limit still applies.", scope.CredentialEnvironment, err))
			continue
		}
		switch {
		case status.Reached():
			refused = true
			lines = append(lines, status.ReachedLine())
		case status.WouldCross(worst):
			lines = append(lines, status.WarningLine(worst))
			if s.runs > 1 {
				lines = append(lines, fmt.Sprintf("That counts every review this command may run: the general review and up to %d specialist review%s, each up to %s.", s.runs-1, map[bool]string{true: "", false: "s"}[s.runs == 2], spending.FormatUSD(s.worst)))
			}
		}
	}
	if len(lines) != 0 {
		s.say(lines...)
	}
	return refused
}

// record appends the ledger entry of one run that sent at least one request:
// the settled cost when the result's usage is known, otherwise the observed
// upper bound, in which every request of unknown usage counts at its
// reservation. It then prints any alert percentage the run crossed.
func (s *reviewSpending) record(runID string, result localreview.Result, observed localreview.SpendObservation) {
	if s == nil || observed.RequestsSent == 0 {
		return
	}
	if s.store == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cost, known := observed.UpperBoundMicroUSD, false
	if report, err := result.Report(); err == nil && report.UsageKnown {
		cost, known = report.ActualCostMicroUSD, true
	}
	now := spendingNow()
	entry := spending.Entry{RecordedAt: now, ReviewRunID: runID, RuntimePolicyIdentity: s.policy, Scopes: s.scopes, Models: s.models, RequestsSent: min(observed.RequestsSent, spending.MaxRequestsSent), UsageKnown: known, CostMicroUSD: min(cost, spending.MaxEntryCostMicroUSD)}
	// Read each limited key's spend before the append, to see what it crossed.
	before := map[spending.Scope]spending.Status{}
	for _, scope := range s.scopes {
		if limit, found, err := s.store.Limit(scope); err == nil && found {
			if status, err := s.store.CurrentStatus(limit, now); err == nil {
				before[scope] = status
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), spendingRecordTimeout)
	defer cancel()
	if err := s.store.Append(ctx, entry); err != nil {
		s.say(fmt.Sprintf("This review's spend (up to %s) was not recorded in the usage ledger: %v. Spending limits do not count it; your provider's own limit still applies.", spending.FormatUSD(entry.CostMicroUSD), err))
		return
	}
	var lines []string
	for _, scope := range s.scopes {
		status, ok := before[scope]
		if !ok {
			continue
		}
		previous := status.Spend.MicroUSD
		status.Spend.MicroUSD = previous + entry.CostMicroUSD
		if status.Spend.MicroUSD < previous {
			status.Spend.MicroUSD = ^uint64(0)
		}
		status.Spend.Entries++
		if _, crossed := spending.CrossedAlert(status.Limit, previous, status.Spend.MicroUSD); crossed {
			lines = append(lines, status.AlertLine())
		}
	}
	if len(lines) != 0 {
		s.say(lines...)
	}
}

// finish prints, for text output, each limited key's state once at the end of
// the invocation, as `trestle usage` and `trestle init` show it.
func (s *reviewSpending) finish() {
	if s == nil || s.store == nil || !s.text {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := spendingNow()
	var lines []string
	for _, scope := range s.scopes {
		if s.shown[scope] {
			continue
		}
		limit, found, err := s.store.Limit(scope)
		if err != nil || !found {
			continue
		}
		status, err := s.store.CurrentStatus(limit, now)
		if err != nil {
			continue
		}
		s.shown[scope] = true
		lines = append(lines, "Spending: "+status.Summary()+".")
	}
	if len(lines) != 0 {
		s.say(lines...)
	}
}

// batchWithinLimits reports whether runs more review runs could start at once
// without any limited key's recorded spend plus their worst case reaching its
// limit. Specialist members run concurrently only then, so concurrency never
// defeats the one-by-one limit check. Without a usage folder no limit is
// enforced, so nothing is defeated.
func (s *reviewSpending) batchWithinLimits(runs int) bool {
	if s == nil || s.store == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := spendingNow()
	for _, scope := range s.scopes {
		limit, found, err := s.store.Limit(scope)
		if err == nil && !found {
			continue
		}
		if err != nil {
			return false
		}
		status, err := s.store.CurrentStatus(limit, now)
		if err != nil || status.Reached() || status.WouldCross(timesRuns(s.worst, runs)) {
			return false
		}
	}
	return true
}
