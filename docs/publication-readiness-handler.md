# Publication readiness task handler

The publication readiness handler, `handlers/publication.ReadinessHandler`, decides which verified findings are ready to report. The decision is advisory. It is the last task of a run. The handler does not write to source control.

The handler takes three protected dependency artifacts as input: `analysis`, `change` and `verification`. It validates the change result against its base and head source snapshots. It then reloads the generation result, the dynamic generation input, and the context artifact that the verification result references. From these it reconstructs the source head revision, the verification receipt and the verified finding set. Only then does it apply one configured `PublicationPolicy`. The run's review-policy identity, the publication-policy identity and the diagnostic materialization behavior are all part of the handler identity, which identifies this implementation in the run plan.

Before readiness succeeds, the handler exports a diagnostic set. This is version 5, or version 8 when a verified finding is on removed base lines. The set contains the validated source head, the candidate outcomes, the source coverage and omission reasons, and the deterministic check that the handler rebuilds from the same validated analysis result and change. The handler writes the set through the daemon's configured diagnostic store. The write is idempotent, so a retry finds the same set. If the task is cancelled, or if the store reports a capacity, conflicting-set, corruption or backend failure, the task does not report success.

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

Its expiry is not later than that of any reconstructed source, model input or context artifact. The daemon does not publish reviews to a forge.
