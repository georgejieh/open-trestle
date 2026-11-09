package diagnostics

// EvidenceExpired reports a final result recorded after its run's evidence
// retention lapsed. It carries no deterministic or verified part: its outcome
// is only what the run journal proves, and absent evidence is unknown, not
// clean.
func (s Set) EvidenceExpired() bool { return s.evidenceExpired }

// WithEvidenceExpired marks a v7 set without evidence parts as recorded after
// the evidence expired, and derives the new identity. A completed outcome
// always needs its verified evidence, so it cannot be marked.
func (s Set) WithEvidenceExpired() (Set, error) {
	if s.schemaVersion != 7 || s.evidenceExpired || s.finalOutcome == FinalOutcomeCompleted || s.analysisResultIdentity != "" || s.verifiedSetIdentity != "" || s.snapshotIdentity != "" || s.headRevision != "" {
		return Set{}, ErrInvalidSet
	}
	s.evidenceExpired = true
	return finalizeFinalSet(s)
}
