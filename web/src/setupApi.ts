import type {
  SetupCheckInput,
  SetupCheckKey,
  SetupCheckResult,
  SetupInitInput,
  SetupPlan,
  SetupProfile,
  SetupReceipt,
  SetupRequirement,
  SetupSession,
  SetupSource,
  SetupState,
} from "./types";
import {
  ApiError,
  exact,
  integer,
  invalidResponse,
  record,
  request,
  validDigest,
  validScope,
  validRuntimeObservedAt,
  type Fetcher,
} from "./api";
// Display/action diagnostic only. Server approval and native grants remain independent.
export const CURRENT_INTEGRATION_PERMISSION_CHECKER_IDENTITY =
  "8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9";
export function hasCurrentIntegrationPermissionAuthority(
  plan: SetupPlan,
): boolean {
  return plan.checker_authorities.some(
    (entry) =>
      entry.key === "integration_permissions_validated" &&
      entry.checker_identity ===
        CURRENT_INTEGRATION_PERMISSION_CHECKER_IDENTITY,
  );
}
const setupProfiles = new Set<SetupProfile>([
  "local_single_node",
  "controlled_hybrid",
  "kubernetes_ha",
  "air_gapped",
]);
const setupStates = new Set<SetupState>([
  "pending",
  "passed",
  "blocked",
  "unavailable",
]);
const setupSources = new Set<SetupSource>([
  "deterministic",
  "probe",
  "authorization",
  "dry_run",
]);
const setupKeys = new Set<SetupCheckKey>([
  "profile_selected",
  "scope_valid",
  "effect_posture_locked",
  "recovery_owner_named",
  "local_administrator_validated",
  "state_storage_posture_validated",
  "postgres_storage_validated",
  "envelope_storage_validated",
  "backup_validated",
  "observer_credential_posture_validated",
  "secret_backend_validated",
  "local_inference_validated",
  "remote_provider_authorized",
  "integration_permissions_validated",
  "webhook_validated",
  "shared_rate_limit_validated",
  "replica_reconciliation_validated",
  "signed_bundle_validated",
  "no_egress_validated",
  "policy_validated",
  "dry_run_validated",
]);
const setupErrorCodes = new Set([
  "invalid_request",
  "unauthorized",
  "not_found",
  "method_not_allowed",
  "state_unavailable",
  "state_invalid",
  "state_conflict",
  "stale_plan",
  "check_unavailable",
  "check_failed",
  "request_too_large",
  "unsupported_media_type",
  "encode_failed",
]);
const setupErrorStatus: Record<string, number> = {
  invalid_request: 400,
  unauthorized: 401,
  not_found: 404,
  method_not_allowed: 405,
  state_unavailable: 503,
  state_invalid: 409,
  state_conflict: 409,
  stale_plan: 409,
  check_unavailable: 422,
  check_failed: 422,
  request_too_large: 413,
  unsupported_media_type: 415,
  encode_failed: 500,
};
function parseSetupError(value: unknown): string {
  if (
    !record(value) ||
    !exact(value, ["contract", "schema_version", "code"]) ||
    value.contract !== "open-trestle/setup-error" ||
    value.schema_version !== 1 ||
    typeof value.code !== "string" ||
    !setupErrorCodes.has(value.code)
  )
    invalidResponse();
  return value.code;
}
function parseSetupHTTP<T>(
  response: { status: number; body: unknown },
  successStatus: number,
  parser: (value: unknown) => T,
): T {
  if (response.status === successStatus) {
    if (
      record(response.body) &&
      response.body.contract === "open-trestle/setup-error"
    )
      invalidResponse();
    return parser(response.body);
  }
  const code = parseSetupError(response.body);
  if (setupErrorStatus[code] !== response.status) invalidResponse();
  throw new ApiError(code);
}
const setupRecoveries = new Set([
  "",
  "configure_dependency",
  "provide_backup",
  "configure_observer_authority",
  "configure_identity",
  "approve_provider",
  "correct_permissions",
  "verify_webhook",
  "import_signed_bundle",
  "restore_no_egress",
  "run_dry_run",
  "correct_policy",
]);
const setupBaseKeys: SetupCheckKey[] = [
  "profile_selected",
  "scope_valid",
  "effect_posture_locked",
  "recovery_owner_named",
];
const setupLocalKeys: SetupCheckKey[] = [
  "state_storage_posture_validated",
  "backup_validated",
  "local_administrator_validated",
  "observer_credential_posture_validated",
];
const setupHybridStorageKeys: SetupCheckKey[] = [
  "postgres_storage_validated",
  "envelope_storage_validated",
  "backup_validated",
  "secret_backend_validated",
];
const setupHybridReviewKeys: SetupCheckKey[] = [
  "local_administrator_validated",
  "observer_credential_posture_validated",
  "remote_provider_authorized",
  "integration_permissions_validated",
  "webhook_validated",
  "policy_validated",
  "dry_run_validated",
];
const setupProfileKeys: Record<SetupProfile, SetupCheckKey[]> = {
  local_single_node: [
    ...setupBaseKeys,
    ...setupLocalKeys,
    "policy_validated",
    "local_inference_validated",
    "dry_run_validated",
  ],
  controlled_hybrid: [
    ...setupBaseKeys,
    ...setupHybridStorageKeys,
    ...setupHybridReviewKeys,
  ],
  kubernetes_ha: [
    ...setupBaseKeys,
    ...setupHybridStorageKeys,
    "shared_rate_limit_validated",
    "replica_reconciliation_validated",
    ...setupHybridReviewKeys,
  ],
  air_gapped: [
    ...setupBaseKeys,
    ...setupLocalKeys,
    "signed_bundle_validated",
    "no_egress_validated",
    "policy_validated",
    "local_inference_validated",
    "dry_run_validated",
  ],
};
function setupRecoveryFor(key: SetupCheckKey): string {
  const values: Partial<Record<SetupCheckKey, string>> = {
    local_administrator_validated: "configure_identity",
    state_storage_posture_validated: "configure_dependency",
    postgres_storage_validated: "configure_dependency",
    envelope_storage_validated: "configure_dependency",
    backup_validated: "provide_backup",
    observer_credential_posture_validated: "configure_observer_authority",
    secret_backend_validated: "configure_dependency",
    local_inference_validated: "configure_dependency",
    remote_provider_authorized: "approve_provider",
    integration_permissions_validated: "correct_permissions",
    webhook_validated: "verify_webhook",
    shared_rate_limit_validated: "configure_dependency",
    replica_reconciliation_validated: "configure_dependency",
    signed_bundle_validated: "import_signed_bundle",
    no_egress_validated: "restore_no_egress",
    policy_validated: "correct_policy",
    dry_run_validated: "run_dry_run",
  };
  return values[key] ?? "";
}
function setupSourceFor(key: SetupCheckKey): SetupSource {
  if (
    [
      "profile_selected",
      "scope_valid",
      "effect_posture_locked",
      "recovery_owner_named",
    ].includes(key)
  )
    return "deterministic";
  if (
    [
      "local_administrator_validated",
      "remote_provider_authorized",
      "integration_permissions_validated",
      "policy_validated",
    ].includes(key)
  )
    return "authorization";
  if (key === "dry_run_validated") return "dry_run";
  return "probe";
}
function setupTimestamp(value: unknown): value is string {
  return validRuntimeObservedAt(value);
}
function parseSetupRequirement(value: unknown): SetupRequirement {
  const keys = [
    "key",
    "source",
    "state",
    "checker_identity",
    "evidence_identity",
    "receipt_identity",
    "recovery_action",
    "checked_at",
  ] as const;
  if (
    !record(value) ||
    !exact(value, keys) ||
    typeof value.key !== "string" ||
    !setupKeys.has(value.key as SetupCheckKey) ||
    typeof value.source !== "string" ||
    !setupSources.has(value.source as SetupSource) ||
    value.source !== setupSourceFor(value.key as SetupCheckKey) ||
    typeof value.state !== "string" ||
    !setupStates.has(value.state as SetupState) ||
    !validDigest(value.checker_identity, true) ||
    !validDigest(value.evidence_identity, true) ||
    !validDigest(value.receipt_identity, true) ||
    typeof value.recovery_action !== "string" ||
    !setupRecoveries.has(value.recovery_action) ||
    typeof value.checked_at !== "string"
  )
    invalidResponse();
  const deterministic = value.source === "deterministic",
    pending = value.state === "pending",
    passed = value.state === "passed";
  if (
    (deterministic &&
      (value.state !== "passed" ||
        value.checker_identity !== "" ||
        value.evidence_identity !== "" ||
        value.receipt_identity !== "" ||
        value.recovery_action !== "" ||
        value.checked_at !== "")) ||
    (pending &&
      (value.checker_identity !== "" ||
        value.evidence_identity !== "" ||
        value.receipt_identity !== "" ||
        value.recovery_action !== "" ||
        value.checked_at !== "")) ||
    (!deterministic &&
      !pending &&
      (!validDigest(value.checker_identity) ||
        !validDigest(value.evidence_identity) ||
        !validDigest(value.receipt_identity) ||
        !setupTimestamp(value.checked_at))) ||
    (passed && value.recovery_action !== "") ||
    ((value.state === "blocked" || value.state === "unavailable") &&
      value.recovery_action !== setupRecoveryFor(value.key as SetupCheckKey))
  )
    invalidResponse();
  return value as unknown as SetupRequirement;
}
function parseSetupReceipt(value: unknown): SetupReceipt {
  const keys = [
    "contract",
    "schema_version",
    "identity",
    "plan_identity",
    "key",
    "checker_identity",
    "state",
    "evidence_identity",
    "recovery_action",
    "checked_at",
  ] as const;
  if (
    !record(value) ||
    !exact(value, keys) ||
    value.contract !== "open-trestle/setup-check-receipt" ||
    value.schema_version !== 1 ||
    !validDigest(value.identity) ||
    !validDigest(value.plan_identity) ||
    typeof value.key !== "string" ||
    !setupKeys.has(value.key as SetupCheckKey) ||
    setupSourceFor(value.key as SetupCheckKey) === "deterministic" ||
    !validDigest(value.checker_identity) ||
    typeof value.state !== "string" ||
    !(["passed", "blocked", "unavailable"] as string[]).includes(value.state) ||
    !validDigest(value.evidence_identity) ||
    typeof value.recovery_action !== "string" ||
    !setupRecoveries.has(value.recovery_action) ||
    !setupTimestamp(value.checked_at) ||
    (value.state === "passed" && value.recovery_action !== "") ||
    (value.state !== "passed" &&
      value.recovery_action !== setupRecoveryFor(value.key as SetupCheckKey))
  )
    invalidResponse();
  return value as unknown as SetupReceipt;
}
function parseSetupPlan(value: unknown): SetupPlan {
  const keys = [
    "contract",
    "schema_version",
    "identity",
    "previous_identity",
    "checker_catalog_identity",
    "checker_authorities",
    "revision",
    "tenant_id",
    "repository_id",
    "recovery_owner",
    "profile",
    "posture",
    "requirements",
    "receipts",
    "status",
    "ready",
    "created_at",
    "updated_at",
  ] as const;
  if (
    !record(value) ||
    !exact(value, keys) ||
    value.contract !== "open-trestle/setup-plan" ||
    value.schema_version !== 1 ||
    !validDigest(value.identity) ||
    !validDigest(value.previous_identity, true) ||
    !validDigest(value.checker_catalog_identity) ||
    !integer(value.revision, 1, 257) ||
    typeof value.tenant_id !== "string" ||
    typeof value.repository_id !== "string" ||
    !validScope({
      tenant: value.tenant_id,
      repository: value.repository_id,
      run: "setup",
    }) ||
    typeof value.recovery_owner !== "string" ||
    !/^[A-Za-z0-9_.:@-]{1,128}$/.test(value.recovery_owner) ||
    typeof value.profile !== "string" ||
    !setupProfiles.has(value.profile as SetupProfile) ||
    !record(value.posture) ||
    !Array.isArray(value.requirements) ||
    !Array.isArray(value.receipts) ||
    !Array.isArray(value.checker_authorities) ||
    typeof value.status !== "string" ||
    !["incomplete", "blocked", "ready"].includes(value.status) ||
    typeof value.ready !== "boolean" ||
    !setupTimestamp(value.created_at) ||
    !setupTimestamp(value.updated_at)
  )
    invalidResponse();
  const posture = value.posture;
  const postureKeys = [
    "metadata_backend",
    "artifact_backend",
    "artifact_protection",
    "notification_backend",
    "inference",
    "egress",
    "integration",
    "max_model_request_cost_micro_usd",
    "retention_days",
    "provider_fallback_enabled",
    "content_logging_allowed",
    "publication_enabled",
    "dynamic_validation_enabled",
  ] as const;
  if (
    !exact(posture, postureKeys) ||
    posture.retention_days !== 30 ||
    posture.provider_fallback_enabled !== false ||
    posture.content_logging_allowed !== false ||
    posture.publication_enabled !== false ||
    posture.dynamic_validation_enabled !== false ||
    !integer(posture.max_model_request_cost_micro_usd, 0, 1000000000)
  )
    invalidResponse();
  const profile = value.profile as SetupProfile;
  const local = profile === "local_single_node" || profile === "air_gapped";
  if (
    (local &&
      (posture.metadata_backend !== "local" ||
        posture.artifact_backend !== "local" ||
        posture.artifact_protection !== "process_private" ||
        posture.notification_backend !== "process_local" ||
        posture.inference !== "local_only" ||
        posture.egress !== "denied" ||
        posture.max_model_request_cost_micro_usd !== 0)) ||
    (!local &&
      (posture.metadata_backend !== "postgres" ||
        posture.artifact_backend !== "s3" ||
        posture.artifact_protection !== "envelope_encrypted" ||
        posture.notification_backend !== "postgres" ||
        posture.inference !== "approved_remote" ||
        posture.egress !== "allowlisted" ||
        posture.max_model_request_cost_micro_usd !== 100000)) ||
    posture.integration !==
      (profile === "air_gapped"
        ? "offline_bundle"
        : local
          ? "local"
          : "least_privilege_scm")
  )
    invalidResponse();
  const requirements = value.requirements.map(parseSetupRequirement);
  const expectedKeys = setupProfileKeys[profile];
  if (
    requirements.length !== expectedKeys.length ||
    requirements.some(
      (requirement, index) => requirement.key !== expectedKeys[index],
    )
  )
    invalidResponse();
  const authorities = value.checker_authorities as unknown[];
  const authorityMap = new Map<SetupCheckKey, string>();
  let previous = "";
  for (const authority of authorities) {
    if (
      !record(authority) ||
      !exact(authority, ["key", "checker_identity"]) ||
      typeof authority.key !== "string" ||
      !setupKeys.has(authority.key as SetupCheckKey) ||
      setupSourceFor(authority.key as SetupCheckKey) === "deterministic" ||
      !validDigest(authority.checker_identity) ||
      authority.key <= previous ||
      authorityMap.has(authority.key as SetupCheckKey)
    )
      invalidResponse();
    authorityMap.set(
      authority.key as SetupCheckKey,
      authority.checker_identity as string,
    );
    previous = authority.key;
  }
  if (
    new Set(authorityMap.values()).size !== authorityMap.size ||
    authorityMap.size !==
      requirements.filter((r) => r.source !== "deterministic").length ||
    requirements.some(
      (r) => r.source !== "deterministic" && !authorityMap.has(r.key),
    )
  )
    invalidResponse();
  const receipts = value.receipts.map(parseSetupReceipt);
  if (
    receipts.length > 256 ||
    value.revision !== receipts.length + 1 ||
    new Set(receipts.map((r) => r.identity)).size !== receipts.length ||
    new Set(receipts.map((r) => r.checked_at)).size !== receipts.length
  )
    invalidResponse();
  let previousReceipt: SetupReceipt | undefined;
  for (const receipt of receipts) {
    if (
      authorityMap.get(receipt.key) !== receipt.checker_identity ||
      (previousReceipt !== undefined &&
        Date.parse(receipt.checked_at) <=
          Date.parse(previousReceipt.checked_at))
    )
      invalidResponse();
    previousReceipt = receipt;
  }
  const dependents: Partial<Record<SetupCheckKey, SetupCheckKey[]>> = {
    policy_validated: ["local_inference_validated", "dry_run_validated"],
    postgres_storage_validated: [
      "shared_rate_limit_validated",
      "replica_reconciliation_validated",
    ],
    integration_permissions_validated: ["webhook_validated"],
  };
  const latest = new Map<SetupCheckKey, SetupReceipt>();
  for (const receipt of receipts) {
    if (latest.has(receipt.key)) {
      for (const key of dependents[receipt.key] ?? []) latest.delete(key);
    }
    latest.set(receipt.key, receipt);
  }
  for (const requirement of requirements) {
    const receipt = latest.get(requirement.key);
    if (
      receipt &&
      (requirement.state !== receipt.state ||
        requirement.receipt_identity !== receipt.identity ||
        requirement.checker_identity !== receipt.checker_identity ||
        requirement.evidence_identity !== receipt.evidence_identity ||
        requirement.recovery_action !== receipt.recovery_action ||
        requirement.checked_at !== receipt.checked_at)
    )
      invalidResponse();
    if (
      !receipt &&
      requirement.source !== "deterministic" &&
      requirement.state !== "pending"
    )
      invalidResponse();
  }
  const all = requirements.every((r) => r.state === "passed"),
    blocked = requirements.some(
      (r) => r.state === "blocked" || r.state === "unavailable",
    ),
    derived = blocked ? "blocked" : all ? "ready" : "incomplete";
  if (
    Date.parse(value.updated_at as string) <
      Date.parse(value.created_at as string) ||
    (receipts.length > 0 &&
      Date.parse(receipts[0]!.checked_at) <=
        Date.parse(value.created_at as string)) ||
    value.status !== derived ||
    value.ready !== (derived === "ready") ||
    (receipts.length === 0
      ? value.previous_identity !== "" || value.updated_at !== value.created_at
      : value.previous_identity !== receipts.at(-1)?.plan_identity ||
        value.updated_at !== receipts.at(-1)?.checked_at)
  )
    invalidResponse();
  return {
    ...value,
    posture,
    requirements,
    receipts,
    checker_authorities: authorities,
  } as unknown as SetupPlan;
}
export function parseSetupSession(value: unknown): SetupSession {
  if (
    !record(value) ||
    value.contract !== "open-trestle/setup-session" ||
    value.schema_version !== 1 ||
    typeof value.initialized !== "boolean"
  )
    invalidResponse();
  if (value.initialized) {
    if (!exact(value, ["contract", "schema_version", "initialized", "plan"]))
      invalidResponse();
    return { ...value, plan: parseSetupPlan(value.plan) } as SetupSession;
  }
  if (!exact(value, ["contract", "schema_version", "initialized"]))
    invalidResponse();
  return value as unknown as SetupSession;
}
export function parseSetupCheckResult(value: unknown): SetupCheckResult {
  if (!record(value)) {
    invalidResponse();
  }
  if (value.contract === "open-trestle/setup-error") {
    if (
      !exact(value, ["contract", "schema_version", "code"]) ||
      value.schema_version !== 1 ||
      typeof value.code !== "string" ||
      !setupErrorCodes.has(value.code)
    )
      invalidResponse();
    throw new ApiError(value.code);
  }
  if (
    !exact(value, ["contract", "schema_version", "plan", "receipt"]) ||
    value.contract !== "open-trestle/setup-check-result" ||
    value.schema_version !== 1
  )
    invalidResponse();
  const plan = parseSetupPlan(value.plan),
    receipt = parseSetupReceipt(value.receipt);
  const latest = plan.receipts.at(-1);
  if (
    latest === undefined ||
    latest.identity !== receipt.identity ||
    latest.plan_identity !== receipt.plan_identity ||
    latest.key !== receipt.key ||
    latest.checker_identity !== receipt.checker_identity ||
    latest.state !== receipt.state ||
    latest.evidence_identity !== receipt.evidence_identity ||
    latest.recovery_action !== receipt.recovery_action ||
    latest.checked_at !== receipt.checked_at ||
    plan.previous_identity !== receipt.plan_identity
  )
    invalidResponse();
  return {
    contract: "open-trestle/setup-check-result",
    schema_version: 1,
    plan,
    receipt,
  };
}

const maximumSetupResponseBytes = 2 << 20;
function validSetupPath(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 4096 &&
    !/[\u0000\r\n]/.test(value)
  );
}
export function validSetupBundlePath(value: unknown): value is string {
  if (!validSetupPath(value)) return false;
  const validSegments = (segments: string[]) =>
    segments.every(
      (segment) => segment !== "" && segment !== "." && segment !== "..",
    );
  if (value.startsWith("/")) {
    return (
      value === "/" ||
      (!value.endsWith("/") && validSegments(value.slice(1).split("/")))
    );
  }
  if (/^[A-Za-z]:\\/.test(value)) {
    if (value.includes("/")) return false;
    const rest = value.slice(3);
    return (
      rest === "" || (!value.endsWith("\\") && validSegments(rest.split("\\")))
    );
  }
  if (value.startsWith("\\\\")) {
    if (value.includes("/") || value.endsWith("\\")) return false;
    const segments = value.slice(2).split("\\");
    return segments.length >= 2 && validSegments(segments);
  }
  return false;
}

function validSetupSecretValue(
  value: unknown,
  maximum: number,
): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= maximum &&
    !/[\u0000-\u0020\u007f]/.test(value)
  );
}
function validSetupLabel(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_.:@-]{1,128}$/.test(value);
}

export async function fetchSetupSession(
  token: string,
  fetcher: Fetcher = fetch,
): Promise<SetupSession> {
  const response = await request(
    "/api/v1/setup",
    token,
    fetcher,
    "GET",
    undefined,
    maximumSetupResponseBytes,
  );
  return parseSetupHTTP(response, 200, parseSetupSession);
}
export async function initializeSetup(
  input: SetupInitInput,
  token: string,
  fetcher: Fetcher = fetch,
): Promise<SetupSession> {
  if (
    !setupProfiles.has(input.profile) ||
    !validScope({
      tenant: input.tenant_id,
      repository: input.repository_id,
      run: "setup",
    }) ||
    !/^[A-Za-z0-9_.:@-]{1,128}$/.test(input.recovery_owner)
  )
    throw new ApiError("invalid_scope");
  const body = {
    contract: "open-trestle/setup-init-request",
    schema_version: 1,
    ...input,
    confirmation: "create setup plan",
  };
  const response = await request(
    "/api/v1/setup/init",
    token,
    fetcher,
    "POST",
    body,
    maximumSetupResponseBytes,
  );
  const session = parseSetupHTTP(response, 201, parseSetupSession);
  const plan = session.plan;
  if (
    !session.initialized ||
    plan === undefined ||
    plan.profile !== input.profile ||
    plan.tenant_id !== input.tenant_id ||
    plan.repository_id !== input.repository_id ||
    plan.recovery_owner !== input.recovery_owner
  )
    invalidResponse();
  return session;
}
const setupCheckFields: Partial<
  Record<SetupCheckKey, Record<string, (value: unknown) => boolean>>
> = {
  state_storage_posture_validated: { storage_root: validSetupPath },
  backup_validated: { backup_snapshot_path: validSetupPath },
  postgres_storage_validated: {
    approve_postgres_authority_identity: validDigest,
    approved_by: validSetupLabel,
  },
  shared_rate_limit_validated: {
    approve_shared_rate_limit_authority_identity: validDigest,
    postgres_database_authority_identity: validDigest,
    approved_by: validSetupLabel,
  },
  replica_reconciliation_validated: {
    approve_replica_reconciliation_authority_identity: validDigest,
    postgres_database_authority_identity: validDigest,
    approved_by: validSetupLabel,
  },
  webhook_validated: {
    approve_webhook_authority_identity: validDigest,
    github_webhook_key_id: (value) => validSetupSecretValue(value, 128),
    approved_by: validSetupLabel,
  },
  envelope_storage_validated: {
    approve_envelope_storage_authority_identity: validDigest,
    s3_endpoint: (value) => validSetupSecretValue(value, 2048),
    s3_region: (value) => validSetupSecretValue(value, 128),
    s3_bucket: (value) => validSetupSecretValue(value, 128),
    s3_prefix: (value) => validSetupSecretValue(value, 1024),
    kms_region: (value) => validSetupSecretValue(value, 128),
    kms_key_arn: (value) => validSetupSecretValue(value, 2048),
    kms_endpoint: (value) =>
      value === undefined || validSetupSecretValue(value, 2048),
    approved_by: validSetupLabel,
  },
  secret_backend_validated: {
    approve_kms_authority_identity: validDigest,
    kms_region: (value) => validSetupSecretValue(value, 128),
    kms_key_arn: (value) => validSetupSecretValue(value, 2048),
    kms_endpoint: (value) =>
      value === undefined || validSetupSecretValue(value, 2048),
    approved_by: validSetupLabel,
  },
  local_administrator_validated: { approved_by: validSetupLabel },
};
const reviewPolicyFields = {
  route_inventory_path: validSetupPath,
  runtime_policy_path: validSetupPath,
  approve_inventory_identity: validDigest,
  approve_runtime_policy_identity: validDigest,
  approve_review_policy_identity: validDigest,
  approved_by: validSetupLabel,
};
for (const key of [
  "remote_provider_authorized",
  "policy_validated",
  "dry_run_validated",
  "local_inference_validated",
] as const)
  setupCheckFields[key] = reviewPolicyFields;
export async function runSetupCheck(
  input: SetupCheckInput,
  token: string,
  fetcher: Fetcher = fetch,
): Promise<SetupCheckResult> {
  const supported = new Set<SetupCheckKey>([
    "postgres_storage_validated",
    "integration_permissions_validated",
    "webhook_validated",
    "shared_rate_limit_validated",
    "replica_reconciliation_validated",
    "signed_bundle_validated",
    "remote_provider_authorized",
    "envelope_storage_validated",
    "secret_backend_validated",
    "local_administrator_validated",
    "backup_validated",
    "state_storage_posture_validated",
    "observer_credential_posture_validated",
    "local_inference_validated",
    "policy_validated",
    "dry_run_validated",
  ]);
  if (
    !supported.has(input.key) ||
    !validDigest(input.plan_identity) ||
    (input.key !== "integration_permissions_validated" &&
      ("approve_github_source_broker_authority_identity" in input ||
        "allow_github_installation_token_creation" in input))
  )
    throw new ApiError("invalid_scope");
  const base = {
    contract: "open-trestle/setup-check-request",
    schema_version: 1,
    plan_identity: input.plan_identity,
    key: input.key,
    confirmation: `run ${input.key}`,
  };
  let body: Record<string, unknown> = { ...base };
  const fields = setupCheckFields[input.key];
  if (fields) {
    const values = input as unknown as Record<string, unknown>;
    for (const [key, validate] of Object.entries(fields)) {
      if (!validate(values[key])) throw new ApiError("invalid_scope");
      if (values[key] !== undefined) body[key] = values[key];
    }
  } else if (input.key === "signed_bundle_validated") {
    if (
      !validDigest(input.approve_signed_bundle_authority_identity) ||
      !validSetupBundlePath(input.bundle_path) ||
      !validDigest(input.bundle_sha256) ||
      !Number.isSafeInteger(input.bundle_bytes) ||
      Number(input.bundle_bytes) <= 0 ||
      Number(input.bundle_bytes) > 1073741824 ||
      !validDigest(input.public_key) ||
      typeof input.signature !== "string" ||
      !/^[0-9a-f]{128}$/.test(input.signature) ||
      input.signature === "0".repeat(128) ||
      !validSetupLabel(input.approved_by)
    )
      throw new ApiError("invalid_scope");
    body = {
      ...body,
      approve_signed_bundle_authority_identity:
        input.approve_signed_bundle_authority_identity,
      bundle_path: input.bundle_path,
      bundle_sha256: input.bundle_sha256,
      bundle_bytes: input.bundle_bytes,
      public_key: input.public_key,
      signature: input.signature,
      approved_by: input.approved_by,
    };
  } else if (input.key === "integration_permissions_validated") {
    if (
      !validDigest(input.approve_integration_permission_authority_identity) ||
      !validDigest(input.approve_github_source_broker_authority_identity) ||
      input.allow_github_installation_token_creation !== true ||
      !validSetupLabel(input.approved_by) ||
      Object.keys(input).some(
        (key) =>
          ![
            "plan_identity",
            "key",
            "approve_integration_permission_authority_identity",
            "approve_github_source_broker_authority_identity",
            "allow_github_installation_token_creation",
            "approved_by",
          ].includes(key),
      )
    )
      throw new ApiError("invalid_scope");
    body = {
      ...base,
      schema_version: 2,
      confirmation:
        "create GitHub installation token and run integration_permissions_validated",
      approve_integration_permission_authority_identity:
        input.approve_integration_permission_authority_identity,
      approve_github_source_broker_authority_identity:
        input.approve_github_source_broker_authority_identity,
      allow_github_installation_token_creation: true,
      approved_by: input.approved_by,
    };
  }
  const response = await request(
    "/api/v1/setup/check",
    token,
    fetcher,
    "POST",
    body,
    maximumSetupResponseBytes,
    input.key === "local_inference_validated" ||
      input.key === "signed_bundle_validated"
      ? 100000
      : input.key === "integration_permissions_validated"
        ? 70000
        : input.key === "shared_rate_limit_validated" ||
            input.key === "replica_reconciliation_validated"
          ? 70000
          : input.key === "webhook_validated"
            ? 40000
            : input.key === "envelope_storage_validated"
              ? 100000
              : input.key === "secret_backend_validated"
                ? 70000
                : input.key === "postgres_storage_validated"
                  ? 40000
                  : 15000,
  );
  const result = parseSetupHTTP(response, 200, parseSetupCheckResult);
  if (
    result.receipt.plan_identity !== input.plan_identity ||
    result.receipt.key !== input.key
  )
    invalidResponse();
  return result;
}
