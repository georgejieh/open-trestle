package diagnostics

import (
	"encoding/json"

	"github.com/georgejieh/open-trestle/audit"
)

// FinalOutcome is the terminal state of a full review, not a finding verdict.
type FinalOutcome string

const (
	FinalOutcomeCompleted    FinalOutcome = "completed"
	FinalOutcomeFailed       FinalOutcome = "failed"
	FinalOutcomeCanceled     FinalOutcome = "canceled"
	FinalOutcomeAbstained    FinalOutcome = "abstained"
	FinalOutcomeInconclusive FinalOutcome = "inconclusive"
)

func (o FinalOutcome) valid() bool {
	switch o {
	case FinalOutcomeCompleted, FinalOutcomeFailed, FinalOutcomeCanceled, FinalOutcomeAbstained, FinalOutcomeInconclusive:
		return true
	}
	return false
}

// NewFinalReviewSet creates a terminal full-review set from independently validated
// V6 observations and V5 verification, or V8 verification when a verified
// finding is on removed base lines. Zero parts mean evidence was not available;
// absence of a check must not be interpreted as a passed check.
func NewFinalReviewSet(scope audit.ReviewScope, snapshotIdentity, headRevision string, outcome FinalOutcome, deterministic, verified Set) (Set, error) {
	hasDeterministic := deterministic.schemaVersion != 0
	hasVerified := verified.schemaVersion != 0
	validSource := snapshotIdentity == "" && headRevision == "" || validDigest(snapshotIdentity) && validRevision(headRevision)
	if scope.Validate() != nil || !outcome.valid() || !validSource || outcome == FinalOutcomeCompleted && !hasVerified || hasVerified && !hasDeterministic {
		return Set{}, ErrInvalidSet
	}
	if hasDeterministic && (deterministic.schemaVersion != 6 || deterministic.Validate() != nil || deterministic.scope.Identity() != scope.Identity() || deterministic.snapshotIdentity != snapshotIdentity || deterministic.headRevision != headRevision) {
		return Set{}, ErrInvalidSet
	}
	if hasVerified && (!verifiedVersion(verified.schemaVersion) || verified.Validate() != nil || verified.scope.Identity() != scope.Identity() || verified.headRevision != headRevision || verified.deterministicChecks[0].Identity() != deterministic.deterministicChecks[0].Identity()) {
		return Set{}, ErrInvalidSet
	}
	set := Set{scope: scope, snapshotIdentity: snapshotIdentity, headRevision: headRevision, schemaVersion: 7, finalOutcome: outcome}
	if hasDeterministic {
		set.analysisResultIdentity = deterministic.analysisResultIdentity
		set.deterministicChecks = deterministic.DeterministicChecks()
		set.deterministicObservations = deterministic.DeterministicObservations()
	}
	if hasVerified {
		set.verifiedSetIdentity = verified.verifiedSetIdentity
		set.reviewSnapshotIdentity = verified.snapshotIdentity
		set.sourceContextIdentity = verified.sourceContextIdentity
		set.candidateCount = verified.candidateCount
		set.rejectedCount = verified.rejectedCount
		set.inconclusiveCount = verified.inconclusiveCount
		set.sourceAnalyzedCount = verified.sourceAnalyzedCount
		set.sourceSelectedCount = verified.sourceSelectedCount
		set.sourceOmittedCount = verified.sourceOmittedCount
		set.omissionSummaries = verified.OmissionSummaries()
		set.findings = verified.Findings()
	}
	return finalizeFinalSet(set)
}

// finalizeFinalSet derives a v7 identity and enforces the encoded budget.
func finalizeFinalSet(set Set) (Set, error) {
	set.identity = deriveSetIdentity(set)
	encoded, err := json.Marshal(setToRecordV7(set))
	if err != nil || len(encoded) > MaxEncodedSetBytes {
		return Set{}, ErrSetResourceLimit
	}
	return set, nil
}

func (s Set) finalParts() (Set, Set) {
	var deterministic, verified Set
	if s.analysisResultIdentity != "" {
		deterministic, _ = NewSetWithDeterministicObservations(s.scope, s.snapshotIdentity, s.headRevision, s.analysisResultIdentity, s.deterministicChecks, s.deterministicObservations)
	}
	if s.verifiedSetIdentity != "" {
		verified, _ = NewSetWithDeterministicChecks(s.scope, s.reviewSnapshotIdentity, s.headRevision, s.verifiedSetIdentity, s.sourceContextIdentity, s.candidateCount, s.rejectedCount, s.inconclusiveCount, s.sourceAnalyzedCount, s.sourceSelectedCount, s.sourceOmittedCount, s.omissionSummaries, s.deterministicChecks, s.findings)
	}
	return deterministic, verified
}

type setRecordV7 struct {
	Contract         string       `json:"contract"`
	SchemaVersion    int          `json:"schema_version"`
	Identity         string       `json:"identity"`
	TenantID         string       `json:"tenant_id"`
	RepositoryID     string       `json:"repository_id"`
	ReviewRunID      string       `json:"review_run_id"`
	SnapshotIdentity string       `json:"snapshot_identity"`
	HeadRevision     string       `json:"head_revision"`
	Outcome          FinalOutcome `json:"outcome"`
	Deterministic    *setRecordV6 `json:"deterministic,omitempty"`
	Verified         *setRecordV5 `json:"verified,omitempty"`

	ContextRefusal *contextRefusalRecord `json:"context_refusal,omitempty"`
}

func setToRecordV7(s Set) setRecordV7 {
	r := setRecordV7{Contract: "open-trestle/review-diagnostic-set", SchemaVersion: 7, Identity: s.identity, TenantID: s.scope.TenantID(), RepositoryID: s.scope.RepositoryID(), ReviewRunID: s.scope.ReviewRunID(), SnapshotIdentity: s.snapshotIdentity, HeadRevision: s.headRevision, Outcome: s.finalOutcome}
	deterministic, verified := s.finalParts()
	if deterministic.schemaVersion == 6 {
		value := setToRecordV6(deterministic)
		r.Deterministic = &value
	}
	if verifiedVersion(verified.schemaVersion) {
		value := setToRecordV5(verified)
		r.Verified = &value
	}
	r.ContextRefusal = contextRefusalToRecord(s.contextRefusal)
	return r
}
func parseSetV7(encoded []byte) (Set, error) {
	var r setRecordV7
	if err := decodeCanonicalSetRecord(encoded, &r); err != nil || r.Contract != "open-trestle/review-diagnostic-set" || r.SchemaVersion != 7 {
		return Set{}, ErrInvalidSetEncoding
	}
	scope, err := audit.NewReviewScope(r.TenantID, r.RepositoryID, r.ReviewRunID)
	if err != nil {
		return Set{}, ErrInvalidSetEncoding
	}
	var deterministic, verified Set
	if r.Deterministic != nil {
		raw, err := json.Marshal(r.Deterministic)
		if err != nil {
			return Set{}, ErrInvalidSetEncoding
		}
		deterministic, err = parseSetV6(raw)
		if err != nil {
			return Set{}, err
		}
	}
	if r.Verified != nil {
		raw, err := json.Marshal(r.Verified)
		if err != nil {
			return Set{}, ErrInvalidSetEncoding
		}
		verified, err = parseSetV5(raw)
		if err != nil {
			return Set{}, err
		}
	}
	result, err := NewFinalReviewSet(scope, r.SnapshotIdentity, r.HeadRevision, r.Outcome, deterministic, verified)
	if err == nil && r.ContextRefusal != nil {
		refusal, ok := contextRefusalFromRecord(r.ContextRefusal)
		if !ok {
			return Set{}, ErrInvalidSetEncoding
		}
		result, err = result.WithContextRefusal(refusal)
	}
	if err != nil || result.identity != r.Identity {
		return Set{}, ErrInvalidSetIdentity
	}
	return verifyParsedSetEncoding(result, encoded)
}
