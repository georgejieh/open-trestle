const digest = /^[0-9a-f]{64}$/;
const scopeValue = /^[A-Za-z0-9._:-]{1,128}$/;
export const browserPhases = new Set(["before_restart", "after_restart"]);

export function buildDaemonVisualReceipt({
  phase,
  scope,
  observed,
  metrics,
  captures,
}) {
  if (!browserPhases.has(phase))
    throw new Error("invalid daemon browser phase");
  if (
    !scope ||
    ![scope.tenant, scope.repository, scope.run].every(
      (value) => typeof value === "string" && scopeValue.test(value),
    )
  )
    throw new Error("invalid daemon browser scope");
  if (
    !observed ||
    !digest.test(observed.run_identity ?? "") ||
    !digest.test(observed.diagnostic_set_identity ?? "") ||
    !digest.test(observed.deterministic_check_identity ?? "") ||
    !Number.isSafeInteger(observed.observation_count) ||
    observed.observation_count < 0 ||
    observed.observation_count > 8192 ||
    !Array.isArray(observed.observation_identities) ||
    observed.observation_identities.length !== observed.observation_count ||
    !observed.observation_identities.every((value) => digest.test(value))
  )
    throw new Error("invalid daemon browser identities");
  if (
    !metrics ||
    metrics.console_errors !== 0 ||
    metrics.unexpected_egress !== 0 ||
    metrics.horizontal_overflow !== false ||
    metrics.keyboard_focus_visible !== true ||
    metrics.evidence_disclosure_focus_visible !== true ||
    metrics.reduced_motion !== true ||
    metrics.tap_targets_minimum !== 44
  )
    throw new Error("invalid daemon browser metrics");
  if (
    !Array.isArray(captures) ||
    captures.length !== 5 ||
    captures.some(
      (capture) =>
        typeof capture.name !== "string" ||
        !digest.test(capture.sha256 ?? "") ||
        !Number.isSafeInteger(capture.bytes) ||
        capture.bytes <= 0 ||
        !Number.isSafeInteger(capture.width) ||
        capture.width < 390 ||
        !Number.isSafeInteger(capture.height) ||
        capture.height < 1 ||
        !Number.isSafeInteger(capture.image_width) ||
        capture.image_width !== capture.width ||
        !Number.isSafeInteger(capture.image_height) ||
        capture.image_height < capture.height ||
        typeof capture.view !== "string",
    )
  )
    throw new Error("invalid daemon browser captures");
  return {
    contract: "open-trestle/daemon-console-visual-receipt",
    schema_version: 2,
    phase,
    scope,
    ...observed,
    ...metrics,
    captures,
  };
}
