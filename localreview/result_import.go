package localreview

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
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
// them, not candidate or diagnostic JSON.
// Structural consistency and a capture hash do not authenticate its producer.
func ParseCompletedResult(encoded []byte) (Result, error) {
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
	status, ci := localReadinessDisposition(uint32(set.VerifiedCount()), set.SourceOmittedCount(), uint32(set.InconclusiveCount()), uint32(set.CandidateCount()))
	if wire.Status != status || wire.CI != ci || !wire.UsageKnown && wire.ActualCostMicroUSD != 0 {
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
	return Result{wire: wire, diagnostics: set, valid: true, sealedJSON: append([]byte(nil), encoded...)}, nil
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
