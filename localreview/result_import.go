package localreview

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
)

// CompletedResultMetadata contains only identities and observations in a completed v1, v4, v5 or v6 result.
type CompletedResultMetadata struct {
	RepositoryIdentity   string
	BaseRevisionIdentity string
	HeadRevisionIdentity string
	CandidateIDs         []string
	UsageKnown           bool
	ActualCostMicroUSD   uint64
	Diagnostics          diagnostics.Set
}

// ParseCompletedResult reads the canonical emitted v1 result, a v4 result that
// differs only by finding_guidance, a v5 result that adds style advice (and
// may carry finding_guidance), or a v6 result that adds token_usage to any of
// them and may carry the recorded judgement (rank, checked against its own
// diagnostics, and an advisory pre_existing list), a walkthrough and check
// regressions, not candidate or diagnostic JSON.
// Structural consistency and a capture hash do not authenticate its producer.
//
// It is the strict reader: the CI disposition must be the one the recorded
// findings re-derive, so a disposition relaxed by the recorded pre-existing
// class, which a reader cannot re-derive, is refused. ObserveCompletedResult
// reads such a result for evaluation without trusting the relaxation.
func ParseCompletedResult(encoded []byte) (Result, error) {
	return parseCompletedResult(encoded, false)
}

// ObserveCompletedResult reads a completed result as ParseCompletedResult
// does, and also accepts a version 6 result whose CI disposition its recorded
// pre_existing list relaxed: status findings, ci_disposition inconclusive, and
// every medium, high or critical finding listed as pre-existing. That is what
// a run records when it proved its blocking findings pre-existing, and the
// reader can observe it but cannot prove it again. So it returns only the
// metadata that evaluation records, never a Result, and nothing it returns can
// set an exit code or relax a gate.
func ObserveCompletedResult(encoded []byte) (CompletedResultMetadata, error) {
	result, err := parseCompletedResult(encoded, true)
	if err != nil {
		return CompletedResultMetadata{}, err
	}
	return result.CompletedMetadata()
}

// parseCompletedResult is ParseCompletedResult; observe also accepts a
// disposition that the recorded pre_existing list relaxed.
func parseCompletedResult(encoded []byte, observe bool) (Result, error) {
	if len(encoded) == 0 || len(encoded) > MaxResultJSONBytes || encoded[len(encoded)-1] != '\n' {
		return Result{}, ErrInvalidResult
	}
	var wire resultWire
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil {
		return Result{}, ErrInvalidResult
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(append(canonical, '\n'), encoded) || wire.Contract != "open-trestle/local-git-model-review-result" || !importableResultVersion(wire) || wire.Investigation != nil || wire.Specialist != nil || wire.ComprehensiveClearance || wire.RunStatus != "succeeded" || wire.Failure != "" || wire.FailureDetail != "" {
		return Result{}, ErrInvalidResult
	}
	for _, id := range []string{wire.Scope, wire.Request, wire.Plan, wire.Output, wire.Repository, wire.Base, wire.Head, wire.Inventory, wire.Policy, wire.Context, wire.GenerationRequest, wire.VerificationRequest, wire.VerificationContext, wire.CandidateBatch, wire.Readiness, wire.GenerationRoute, wire.VerificationRoute} {
		if !importDigest(id) {
			return Result{}, ErrInvalidResult
		}
	}
	_, independenceErr := gateway.ParseRouteIndependenceLevel(wire.Independence)
	if wire.Base == wire.Head || wire.GenerationRoute == wire.VerificationRoute || wire.GenerationRequest == wire.VerificationRequest || independenceErr != nil {
		return Result{}, ErrInvalidResult
	}
	set, err := diagnostics.ParseSet(wire.Diagnostics)
	if err != nil || set.SchemaVersion() == 7 && set.Outcome() != diagnostics.FinalOutcomeCompleted || set.Scope().Identity() != wire.Scope || set.Scope().ReviewRunID() != wire.Run || set.VerificationContextIdentity() != wire.VerificationContext || int(set.CandidateCount()) != len(wire.CandidateIDs) {
		return Result{}, ErrInvalidResult
	}
	if !validImportedGuidance(wire.Guidance, set) {
		return Result{}, ErrInvalidResult
	}
	algorithm := evidence.RevisionAlgorithmSHA1
	if len(set.HeadRevision()) == 64 {
		algorithm = evidence.RevisionAlgorithmSHA256
	}
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, algorithm, set.HeadRevision())
	if err != nil || head.Identity() != wire.Head {
		return Result{}, ErrInvalidResult
	}
	status, ci := localReadinessDisposition(uint32(set.VerifiedCount()), set.SourceOmittedCount(), uint32(set.InconclusiveCount()))
	// The CI disposition must be the one the recorded findings re-derive: the
	// readiness disposition, or inconclusive for a version 6 result whose
	// verified findings are all low severity (expectedImportedCI). Any other
	// disposition is refused, so a self-asserted relaxation never imports. A
	// recorded pre_existing list is advisory: the reader cannot re-derive it
	// without the change, so a result that relaxed its disposition by it
	// (inconclusive although a medium, high or critical finding is recorded)
	// is refused. Only an observing read accepts that relaxation
	// (recordedRelaxation).
	// Check regressions only ever block, so a version 6 result that lists
	// them must be blocked.
	expected := expectedImportedCI(wire.Version, set.Findings(), ci)
	if wire.CheckRegressions != nil {
		if wire.Version != tokenUsageResultVersion || !wire.CheckRegressions.valid() {
			return Result{}, ErrInvalidResult
		}
		expected = "blocked"
	}
	if wire.Status != status || wire.CI != expected && !(observe && wire.CheckRegressions == nil && recordedRelaxation(wire, set.Findings(), ci)) || !wire.UsageKnown && wire.ActualCostMicroUSD != 0 {
		return Result{}, ErrInvalidResult
	}
	if wire.ModelWrittenChecks != nil && (wire.Version != tokenUsageResultVersion || !wire.ModelWrittenChecks.valid(func(id string) bool {
		return slices.ContainsFunc(set.Findings(), func(finding diagnostics.Finding) bool { return finding.Identity() == id })
	})) {
		return Result{}, ErrInvalidResult
	}
	if wire.TokenUsage != nil && !validCompletedTokenUsage(*wire.TokenUsage, wire.UsageKnown) {
		return Result{}, ErrInvalidResult
	}
	ids := make(map[string]bool, len(wire.CandidateIDs))
	for _, id := range wire.CandidateIDs {
		if !importDigest(id) || ids[id] {
			return Result{}, ErrInvalidResult
		}
		ids[id] = true
	}
	keys := map[string]bool{"source-base": false, "source-head": false, "change": false, "analysis": false, "memory": false, "context": false, "candidates": false, "verification": false, "readiness": false}
	if len(wire.Tasks) != len(keys) || wire.Audit == nil || wire.Limitations == nil || wire.CandidateIDs == nil {
		return Result{}, ErrInvalidResult
	}
	for _, task := range wire.Tasks {
		seen, ok := keys[task.Key]
		maxAttempts := uint8(3)
		if task.Key == "context" || task.Key == "candidates" || task.Key == "verification" {
			maxAttempts = 1
		}
		if !ok || seen || task.Status != "succeeded" || task.Attempts == 0 || task.Attempts > maxAttempts || task.MaxAttempts != maxAttempts || !importDigest(task.Output) {
			return Result{}, ErrInvalidResult
		}
		keys[task.Key] = true
		if task.Key == "readiness" && task.Output != wire.Output {
			return Result{}, ErrInvalidResult
		}
	}
	counts := map[string]int{"route_selected": 0, "route_attempt_claimed": 0, "route_dispatch_completed": 0, "route_cost_reconciled": 0}
	if len(wire.Audit) != 8 {
		return Result{}, ErrInvalidResult
	}
	for _, event := range wire.Audit {
		if _, ok := counts[event.Kind]; !ok || !importDigest(event.Subject) {
			return Result{}, ErrInvalidResult
		}
		counts[event.Kind]++
	}
	for _, count := range counts {
		if count != 2 {
			return Result{}, ErrInvalidResult
		}
	}
	result := Result{wire: wire, diagnostics: set, valid: true, sealedJSON: append([]byte(nil), encoded...)}
	if !validRecordedJudgement(result) {
		return Result{}, ErrInvalidResult
	}
	return result, nil
}

// recordedRelaxation reports a version 6 result whose findings status and
// inconclusive disposition its recorded pre_existing list explains: the
// readiness disposition is blocked, and every finding that would block (see
// BlocksCI) is listed as pre-existing. validRecordedJudgement still checks
// the list itself.
func recordedRelaxation(wire resultWire, findings []diagnostics.Finding, readinessCI string) bool {
	if wire.Version != tokenUsageResultVersion || wire.Status != "findings" || readinessCI != "blocked" || wire.CI != "inconclusive" || len(findings) == 0 {
		return false
	}
	for _, finding := range findings {
		if BlocksCI(finding.Severity(), false) && !slices.Contains(wire.PreExisting, finding.Identity()) {
			return false
		}
	}
	return true
}

func (r Result) CompletedMetadata() (CompletedResultMetadata, error) {
	if !r.valid || !importableResultVersion(r.wire) || r.wire.RunStatus != "succeeded" || r.diagnostics.Validate() != nil {
		return CompletedResultMetadata{}, ErrInvalidResult
	}
	return CompletedResultMetadata{r.wire.Repository, r.wire.Base, r.wire.Head, append([]string{}, r.wire.CandidateIDs...), r.wire.UsageKnown, r.wire.ActualCostMicroUSD, r.diagnostics}, nil
}

// importableResultVersion accepts v1 without guidance or style advice, v4 with
// guidance and no style advice, v5 with style advice that a review could have
// recorded (agentprofile.RecordedStyleAdvice.Validate) and optional guidance,
// and v6 with token usage and optional guidance and style advice. Only v6
// carries token usage. Style advice is never imported as a finding.
func importableResultVersion(wire resultWire) bool {
	styled := !wire.StyleAdvice.Empty()
	counted := wire.TokenUsage != nil
	return wire.Version == 1 && wire.Guidance == nil && !styled && !counted ||
		wire.Version == guidanceResultVersion && len(wire.Guidance) > 0 && !styled && !counted ||
		wire.Version == styleResultVersion && styled && wire.StyleAdvice.Validate() == nil && !counted ||
		wire.Version == tokenUsageResultVersion && counted && (!styled || wire.StyleAdvice.Validate() == nil)
}

// validImportedGuidance requires guidance for distinct diagnostic findings, in
// diagnostic order, with a closed category and bounded, labeled fix text.
func validImportedGuidance(values []findingGuidanceWire, set diagnostics.Set) bool {
	findings := set.Findings()
	next := 0
	for _, value := range values {
		for next < len(findings) && findings[next].SourceIdentity() != value.FindingIdentity {
			next++
		}
		if next == len(findings) || review.CandidateCategory(value.Category).Validate() != nil ||
			(value.Fix == "") != (value.FixAuthority == "") || value.Fix != "" && (value.FixAuthority != FixAuthority || !validImportedFix(value.Fix)) {
			return false
		}
		next++
	}
	return true
}

func validImportedFix(value string) bool {
	return len(value) <= 1024 && utf8.ValidString(value) && strings.TrimSpace(value) != "" && !strings.ContainsRune(value, 0)
}

func importDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value || strings.Trim(value, "0") == "" {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
