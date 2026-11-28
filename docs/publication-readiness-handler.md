# Publication readiness task handler

The publication readiness handler, `handlers/publication.ReadinessHandler`, runs as the last task of a run and decides which verified findings are ready to report. Its decision is advisory, and it does not write to source control.

The handler takes three protected dependency artifacts as input: `analysis`, `change` and `verification`. It validates the change result against its base and head source snapshots. It then reloads the generation result, the dynamic generation input and the context artifact that the verification result references, and from them reconstructs the source head revision, the verification receipt and the verified finding set. Only then does it apply one configured `PublicationPolicy`. The handler identity, which identifies this implementation in the run plan, includes the run's review-policy identity, the publication-policy identity and the diagnostic materialization behavior.

Before readiness succeeds, the handler exports a diagnostic set: version 5, or version 8 when a verified finding is on removed base lines. The set contains the validated source head, the candidate outcomes, the source coverage and omission reasons, and the deterministic check, which the handler rebuilds from the same validated analysis result and change. The handler writes the set through the daemon's configured diagnostic store. The write is idempotent, so a retry finds the same set. The task does not report success if it is canceled or if the store reports a capacity, conflicting-set, corruption or backend failure.

These outcomes are successful readiness results, not runtime failures:

- blocked independence;
- inconclusive verification;
- no verified findings; and
- findings below the configured threshold.

An `advisory_ready` outcome records counts of inline and summary-only findings, and `PublicationReadiness.AuthorizesPublication()` returns false.

The protected `publication_plan` artifact has policy origin. It binds the following:

- the analysis artifact and the deterministic check;
- the change artifact and the validated source head;
- the verification artifact, the verification result, the verification receipt and the verified finding set; and
- the publication policy and the review policy.

Its expiry is no later than that of any reconstructed source, model input or context artifact. The daemon does not publish reviews to a forge.
