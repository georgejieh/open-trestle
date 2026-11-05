# Orchestrator profile

The orchestrator is the deterministic router itself. It makes **no model call**
and has no prompt; this document describes its behaviour so that plans are
explainable.

## Inputs

1. The packaged profile catalog (content-identified).
2. User assignments: exact provider routes per tier (`light`, `standard`,
   `deep`), globally and per profile, plus verifier routes, the independence
   level, an optional escalation order, and an optional total token cap.
3. Change features: changed paths and line counts, analyzer signals, public
   API changes, reference fan-out, coverage, declared intent presence, and
   repository configuration files.

## Behaviour

- **Activation**: each profile's path globs, languages, file classes, signals,
  and conditions are OR-combined. Vendor and generated files never activate a
  profile. Each activation records why it matched, or why nothing matched.
- **Difficulty**: a fixed integer table scores the profile's scope (changed
  lines, files, languages, public API changes, reference fan-out,
  security-sensitive signals, concurrency, test absence, coverage gaps). Every
  row of the breakdown is recorded.
- **Tier**: the score maps to a tier through the profile's declared thresholds.
- **Route**: the tier's exact route comes from the profile override, then the
  global assignment. An unassigned tier omits the profile with a recorded
  reason unless an explicit escalation order supplies a later tier; every
  borrow is recorded.
- **Verifier**: an assigned verifier route must satisfy the independence level
  against the generator route. Otherwise the profile's results are marked
  unverifiable; the router never invents a verifier.
- **Budget**: when planned tokens exceed the cap, the lowest-priority profiles
  are dropped one at a time, ties broken by profile ID, and each drop is
  recorded.

## Boundaries

The plan is advisory. Gateway eligibility (policy zones, local-only, capacity,
cost budgets, and independence) still runs at dispatch. The orchestrator
never calls a model, reads a clock, uses randomness, or touches the network.
