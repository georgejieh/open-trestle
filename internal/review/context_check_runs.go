package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Check runs are an optional object of a version 11 generation context and a
// version 10 verification context: the outcomes of the reviewed repository's
// own tests and linters, which the host ran in an isolated sandbox on the
// base and the head of the change, tests twice each and linters once. The
// host reads exit status and runner output; run names, reasons and test IDs
// come from the repository and are data, never instructions.

const (
	maxCheckRuns           = 16
	maxCheckRunNameBytes   = 200
	maxCheckRunReasonBytes = 300
	maxCheckRunTestIDBytes = 200
	// maxCheckRunListIDs bounds each run's regression, new-failure and
	// stopped-running lists; maxCheckRunListedIDs bounds every list together,
	// so the object adds a bounded number of secret-scanned fields to a
	// request.
	maxCheckRunListIDs   = 32
	maxCheckRunListedIDs = 64
	maxCheckRunCount     = 1 << 24

	checkRunsSource = "sandboxed_check_runs"
	// checkRunsAuthority differs from pattern hygiene's: the host records the
	// outcomes exactly, but the repository's own code produced them.
	checkRunsAuthority = "host_observed_execution"
)

// Check run states.
const (
	CheckRunRan         = "ran"
	CheckRunCouldNotRun = "could_not_run"
)

// Check run scopes: whether the repository index supplied all the dependents
// of the change, so the checks of the packages that use the changed code ran
// too, only some of them, because the index did not cover the whole closure,
// or none, so only the checks of the changed files ran.
const (
	CheckRunsChangedAndDependents        = "changed_and_dependents"
	CheckRunsChangedAndPartialDependents = "changed_and_partial_dependents"
	CheckRunsChangedOnly                 = "changed_only"
)

func validCheckRunsScope(scope string) bool {
	return scope == CheckRunsChangedAndDependents || scope == CheckRunsChangedAndPartialDependents || scope == CheckRunsChangedOnly
}

// ErrInvalidCheckRuns identifies malformed check run outcomes.
var ErrInvalidCheckRuns = errors.New("invalid check runs")

// checkRunNotBound is the reason a run takes when its outcome is out of the
// object's bounds, so the other runs are kept.
const checkRunNotBound = "its outcome could not be recorded"

// CheckRun is the outcome of one repository check. State is CheckRunRan or
// CheckRunCouldNotRun; a run that could not run has a Reason and no results.
// Tests counts the results with a stable head outcome and FlakyDropped the
// tests dropped because two runs of one side disagreed. Regressions passed on
// base and failed on head, as a test or as the package, module or file that
// holds tests that passed on base, or are the run itself when it passed a
// limit only on head; NewFailures are absent on base and fail on head; Fixed
// failed on base and pass on head; StillFailing fail on both. StoppedRunning
// passed on base and have no head result: a rename or removal does that too,
// so they are not regressions. The Omitted counts cover the IDs not listed.
type CheckRun struct {
	Name, State, Reason                                           string
	Tests, FlakyDropped, Fixed, StillFailing                      int
	Regressions, NewFailures, StoppedRunning                      []string
	RegressionsOmitted, NewFailuresOmitted, StoppedRunningOmitted int
}

// CheckRuns is the bounded outcome of the checks run on one change, named by
// its full base and head commit IDs.
type CheckRuns struct {
	baseCommit, headCommit string
	scope                  string
	runs                   []CheckRun
	omitted                int
}

// NewCheckRuns validates and bounds check outcomes. At most 16 runs are kept
// and the rest counted. Names keep at most 200 bytes, reasons 300 and test IDs
// 200, as valid UTF-8 with control and format characters replaced and cut on
// a character boundary. Each list keeps at most 32 IDs and all lists together
// 64, regressions first, then new failures, then tests that stopped running;
// the rest are counted. A run whose outcome is still out of bounds becomes
// one that could not run, so it never costs the others theirs. Only the
// commit IDs and the scope can refuse the whole value.
func NewCheckRuns(baseCommit, headCommit, scope string, runs []CheckRun) (CheckRuns, error) {
	if !validIntentCommitID(baseCommit) || !validIntentCommitID(headCommit) || len(baseCommit) != len(headCommit) || !validCheckRunsScope(scope) || len(runs)-maxCheckRuns > maxCheckRunCount {
		return CheckRuns{}, ErrInvalidCheckRuns
	}
	kept := runs[:min(len(runs), maxCheckRuns)]
	value := CheckRuns{baseCommit: baseCommit, headCommit: headCommit, scope: scope, runs: make([]CheckRun, len(kept)), omitted: len(runs) - len(kept)}
	for index, run := range kept {
		value.runs[index] = CheckRun{
			Name: checkRunText(run.Name, maxCheckRunNameBytes), State: run.State,
			Reason: checkRunText(run.Reason, maxCheckRunReasonBytes), Tests: run.Tests, FlakyDropped: run.FlakyDropped, Fixed: run.Fixed, StillFailing: run.StillFailing,
			RegressionsOmitted: run.RegressionsOmitted, NewFailuresOmitted: run.NewFailuresOmitted, StoppedRunningOmitted: run.StoppedRunningOmitted,
		}
	}
	listed := 0
	list := func(ids []string, omitted *int) []string {
		var values []string
		for _, id := range ids {
			if len(values) == maxCheckRunListIDs || listed == maxCheckRunListedIDs {
				*omitted++
				continue
			}
			values = append(values, checkRunText(id, maxCheckRunTestIDBytes))
			listed++
		}
		return values
	}
	for index := range kept {
		value.runs[index].Regressions = list(kept[index].Regressions, &value.runs[index].RegressionsOmitted)
	}
	for index := range kept {
		value.runs[index].NewFailures = list(kept[index].NewFailures, &value.runs[index].NewFailuresOmitted)
	}
	for index := range kept {
		value.runs[index].StoppedRunning = list(kept[index].StoppedRunning, &value.runs[index].StoppedRunningOmitted)
	}
	for index, run := range value.runs {
		if wire := run.wire(); !validCheckRunWire(&wire) {
			value.runs[index] = notBoundCheckRun(run.Name)
		}
	}
	if !validCheckRunsWire(value.wire()) {
		return CheckRuns{}, ErrInvalidCheckRuns
	}
	return value, nil
}

// notBoundCheckRun is the run that replaces one out of bounds.
func notBoundCheckRun(name string) CheckRun {
	if !validCheckRunText(name, maxCheckRunNameBytes) {
		name = "unnamed check"
	}
	return CheckRun{Name: name, State: CheckRunCouldNotRun, Reason: checkRunNotBound}
}

// checkRunText trims surrounding space, replaces invalid UTF-8 and control
// and format characters, which could move a terminal cursor or hide text, and
// cuts the result on a character boundary within limit bytes.
func checkRunText(value string, limit int) string {
	cleaned := strings.Map(func(character rune) rune {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return utf8.RuneError
		}
		return character
	}, strings.ToValidUTF8(strings.TrimSpace(value), string(utf8.RuneError)))
	cut, _ := intentText([]byte(cleaned), limit)
	return cut
}

func validCheckRunText(value string, limit int) bool {
	return value != "" && checkRunText(value, limit) == value
}

// IsZero reports a value that names no change.
func (c CheckRuns) IsZero() bool { return c.baseCommit == "" }

// BaseCommit and HeadCommit are the full commit IDs the checks ran on.
func (c CheckRuns) BaseCommit() string { return c.baseCommit }
func (c CheckRuns) HeadCommit() string { return c.headCommit }

// Scope is CheckRunsChangedAndDependents, CheckRunsChangedAndPartialDependents
// or CheckRunsChangedOnly.
func (c CheckRuns) Scope() string { return c.scope }

// RunsOmitted counts the runs past the listing bound.
func (c CheckRuns) RunsOmitted() int { return c.omitted }

// Runs returns a copy of the listed runs.
func (c CheckRuns) Runs() []CheckRun {
	values := make([]CheckRun, len(c.runs))
	for index, run := range c.runs {
		values[index] = run.clone()
	}
	return values
}

func (r CheckRun) clone() CheckRun {
	r.Regressions = append([]string(nil), r.Regressions...)
	r.NewFailures = append([]string(nil), r.NewFailures...)
	r.StoppedRunning = append([]string(nil), r.StoppedRunning...)
	return r
}

// Identity is the SHA-256 digest of the object as a context carries it; the
// context assembly handler binds it into its identity.
func (c CheckRuns) Identity() string {
	if c.IsZero() {
		return ""
	}
	encoded, _ := json.Marshal(c.wire())
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (c CheckRuns) wire() *checkRunsWire {
	if c.IsZero() {
		return nil
	}
	wire := &checkRunsWire{Source: checkRunsSource, Authority: checkRunsAuthority, BaseCommitID: c.baseCommit, HeadCommitID: c.headCommit, Scope: c.scope, Runs: make([]checkRunWire, len(c.runs)), RunsOmitted: c.omitted}
	for index, run := range c.runs {
		wire.Runs[index] = run.wire()
	}
	return wire
}

func (r CheckRun) wire() checkRunWire {
	r = r.clone()
	return checkRunWire{
		Name: r.Name, State: r.State, Reason: r.Reason, Tests: r.Tests, FlakyDropped: r.FlakyDropped, Fixed: r.Fixed, StillFailing: r.StillFailing,
		Regressions: r.Regressions, RegressionsOmitted: r.RegressionsOmitted, NewFailures: r.NewFailures, NewFailuresOmitted: r.NewFailuresOmitted,
		StoppedRunning: r.StoppedRunning, StoppedRunningOmitted: r.StoppedRunningOmitted,
	}
}

func checkRunsFromWire(wire *checkRunsWire) CheckRuns {
	if wire == nil {
		return CheckRuns{}
	}
	value := CheckRuns{baseCommit: wire.BaseCommitID, headCommit: wire.HeadCommitID, scope: wire.Scope, runs: make([]CheckRun, len(wire.Runs)), omitted: wire.RunsOmitted}
	for index, run := range wire.Runs {
		value.runs[index] = CheckRun{
			Name: run.Name, State: run.State, Reason: run.Reason, Tests: run.Tests, FlakyDropped: run.FlakyDropped, Fixed: run.Fixed, StillFailing: run.StillFailing,
			Regressions: run.Regressions, RegressionsOmitted: run.RegressionsOmitted, NewFailures: run.NewFailures, NewFailuresOmitted: run.NewFailuresOmitted,
			StoppedRunning: run.StoppedRunning, StoppedRunningOmitted: run.StoppedRunningOmitted,
		}.clone()
	}
	return value
}

type checkRunsWire struct {
	Source       string         `json:"source"`
	Authority    string         `json:"authority"`
	BaseCommitID string         `json:"base_commit_id"`
	HeadCommitID string         `json:"head_commit_id"`
	Scope        string         `json:"scope"`
	Runs         []checkRunWire `json:"runs"`
	RunsOmitted  int            `json:"runs_omitted,omitempty"`
}

type checkRunWire struct {
	Name                  string   `json:"name"`
	State                 string   `json:"state"`
	Reason                string   `json:"reason,omitempty"`
	Tests                 int      `json:"tests"`
	FlakyDropped          int      `json:"flaky_dropped"`
	Fixed                 int      `json:"fixed"`
	StillFailing          int      `json:"still_failing"`
	Regressions           []string `json:"regressions,omitempty"`
	RegressionsOmitted    int      `json:"regressions_omitted,omitempty"`
	NewFailures           []string `json:"new_failures,omitempty"`
	NewFailuresOmitted    int      `json:"new_failures_omitted,omitempty"`
	StoppedRunning        []string `json:"stopped_running,omitempty"`
	StoppedRunningOmitted int      `json:"stopped_running_omitted,omitempty"`
}

// validCheckRunsWire checks a recorded check_runs object: its constants,
// commit IDs, scope and runs, and the bound on all listed IDs. Secret
// scanning masks text in place with as many bytes, so a sanitized copy still
// passes.
func validCheckRunsWire(wire *checkRunsWire) bool {
	if wire == nil {
		return true
	}
	if wire.Source != checkRunsSource || wire.Authority != checkRunsAuthority || !validIntentCommitID(wire.BaseCommitID) || !validIntentCommitID(wire.HeadCommitID) ||
		len(wire.BaseCommitID) != len(wire.HeadCommitID) || !validCheckRunsScope(wire.Scope) ||
		wire.Runs == nil || len(wire.Runs) > maxCheckRuns || !validCheckRunCount(wire.RunsOmitted) {
		return false
	}
	listed := 0
	for index := range wire.Runs {
		run := &wire.Runs[index]
		if !validCheckRunWire(run) {
			return false
		}
		listed += len(run.Regressions) + len(run.NewFailures) + len(run.StoppedRunning)
	}
	return listed <= maxCheckRunListedIDs
}

// validCheckRunWire checks one run: its state, text bounds and counts. Each
// head result is a regression, a new failure, fixed, still failing or none
// of these, so together they never pass Tests; tests that stopped running
// have no head result and are not counted there.
func validCheckRunWire(run *checkRunWire) bool {
	if !validCheckRunText(run.Name, maxCheckRunNameBytes) {
		return false
	}
	for _, count := range []int{run.Tests, run.FlakyDropped, run.Fixed, run.StillFailing, run.RegressionsOmitted, run.NewFailuresOmitted, run.StoppedRunningOmitted} {
		if !validCheckRunCount(count) {
			return false
		}
	}
	classified := len(run.Regressions) + run.RegressionsOmitted + len(run.NewFailures) + run.NewFailuresOmitted + run.Fixed + run.StillFailing
	stopped := len(run.StoppedRunning) + run.StoppedRunningOmitted
	switch run.State {
	case CheckRunRan:
		if run.Reason != "" || classified > run.Tests {
			return false
		}
	case CheckRunCouldNotRun:
		if !validCheckRunText(run.Reason, maxCheckRunReasonBytes) || run.Tests != 0 || run.FlakyDropped != 0 || classified != 0 || stopped != 0 {
			return false
		}
	default:
		return false
	}
	for _, ids := range [][]string{run.Regressions, run.NewFailures, run.StoppedRunning} {
		if len(ids) > maxCheckRunListIDs {
			return false
		}
		for _, id := range ids {
			if !validCheckRunText(id, maxCheckRunTestIDBytes) {
				return false
			}
		}
	}
	return true
}

func validCheckRunCount(value int) bool {
	return value >= 0 && value <= maxCheckRunCount
}

// CheckRuns returns the bound check run outcomes; the zero value means none.
func (p ContextPacket) CheckRuns() CheckRuns { return p.checkRuns }

// WithCheckRuns returns a copy that carries the outcomes of the repository's
// own checks as the check_runs object of context version 11. The object is
// bounded on its own and does not count toward the source byte budget.
func (p ContextPacket) WithCheckRuns(runs CheckRuns) (ContextPacket, error) {
	if err := p.Validate(); err != nil {
		return ContextPacket{}, err
	}
	if !p.checkRuns.IsZero() || runs.IsZero() {
		return ContextPacket{}, ErrInvalidCheckRuns
	}
	value := p
	value.checkRuns = runs
	value.identity = deriveContextPacketIdentity(value)
	if err := value.Validate(); err != nil {
		return ContextPacket{}, err
	}
	return value, nil
}

// ContextCheckRuns reads the check runs of exact recorded generation context
// bytes. A context recorded without the object has none: the zero value.
func ContextCheckRuns(payload []byte) (CheckRuns, error) {
	if len(payload) == 0 || len(payload) > maxProviderContextPacketBytes {
		return CheckRuns{}, ErrInvalidContextPacketRequest
	}
	wire, err := decodeGenerationContextWire(payload)
	if err != nil || wire.Contract != "open-trestle/review-context-packet" || wire.CheckRuns != nil && wire.SchemaVersion != modelGenerationContextVersion || !validCheckRunsWire(wire.CheckRuns) {
		return CheckRuns{}, ErrInvalidContextPacketRequest
	}
	return checkRunsFromWire(wire.CheckRuns), nil
}
