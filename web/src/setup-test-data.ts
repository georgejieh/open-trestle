import type { SetupPlan } from "./types";
const keys = [
  "backup_validated",
  "dry_run_validated",
  "local_administrator_validated",
  "local_inference_validated",
  "observer_credential_posture_validated",
  "policy_validated",
  "state_storage_posture_validated",
] as const;
const authority = Object.fromEntries(
  keys.map((key, index) => [key, String(index + 1).repeat(64)]),
) as Record<(typeof keys)[number], string>;
export function setupTestPlan(observerPassed = false): SetupPlan {
  const initial = "a".repeat(64);
  const receipt = observerPassed
    ? {
        contract: "open-trestle/setup-check-receipt" as const,
        schema_version: 1 as const,
        identity: "b".repeat(64),
        plan_identity: initial,
        key: "observer_credential_posture_validated" as const,
        checker_identity: authority.observer_credential_posture_validated,
        state: "passed" as const,
        evidence_identity: "c".repeat(64),
        recovery_action: "",
        checked_at: "2026-09-03T12:00:01Z",
      }
    : undefined;
  const definitions = [
    ...[
      "profile_selected",
      "scope_valid",
      "effect_posture_locked",
      "recovery_owner_named",
    ].map((key) => ({ key, source: "deterministic", state: "passed" })),
    ...[
      ["state_storage_posture_validated", "probe"],
      ["backup_validated", "probe"],
      ["local_administrator_validated", "authorization"],
      ["observer_credential_posture_validated", "probe"],
      ["policy_validated", "authorization"],
      ["local_inference_validated", "probe"],
      ["dry_run_validated", "dry_run"],
    ].map(([key, source]) => ({
      key,
      source,
      state:
        key === "observer_credential_posture_validated" && observerPassed
          ? "passed"
          : "pending",
    })),
  ];
  return {
    contract: "open-trestle/setup-plan",
    schema_version: 1,
    identity: observerPassed ? "d".repeat(64) : initial,
    previous_identity: observerPassed ? initial : "",
    checker_catalog_identity: "e".repeat(64),
    checker_authorities: keys.map((key) => ({
      key,
      checker_identity: authority[key],
    })),
    revision: observerPassed ? 2 : 1,
    tenant_id: "tenant-a",
    repository_id: "repo-a",
    recovery_owner: "owner",
    profile: "local_single_node",
    posture: {
      metadata_backend: "local",
      artifact_backend: "local",
      artifact_protection: "process_private",
      notification_backend: "process_local",
      inference: "local_only",
      egress: "denied",
      integration: "local",
      max_model_request_cost_micro_usd: 0,
      retention_days: 30,
      provider_fallback_enabled: false,
      content_logging_allowed: false,
      publication_enabled: false,
      dynamic_validation_enabled: false,
    },
    requirements: definitions.map(({ key, source, state }) => {
      const passed =
        key === "observer_credential_posture_validated" && observerPassed;
      return {
        key: key as SetupPlan["requirements"][number]["key"],
        source: source as SetupPlan["requirements"][number]["source"],
        state: state as SetupPlan["requirements"][number]["state"],
        checker_identity: passed ? receipt!.checker_identity : "",
        evidence_identity: passed ? receipt!.evidence_identity : "",
        receipt_identity: passed ? receipt!.identity : "",
        recovery_action: "",
        checked_at: passed ? receipt!.checked_at : "",
      };
    }),
    receipts: receipt ? [receipt] : [],
    status: "incomplete",
    ready: false,
    created_at: "2026-09-03T12:00:00Z",
    updated_at: receipt ? receipt.checked_at : "2026-09-03T12:00:00Z",
  };
}
