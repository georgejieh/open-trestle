import type {
  Diagnostic,
  DiagnosticSet,
  Failure,
  RunReceipt,
  RunTask,
  RuntimeStatus,
  Scope,
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
  TaskKind,
  TaskStatus,
} from "./types";
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
const maximumResponseBytes = (1 << 20) + (4 << 10);
const identifier = /^[a-z0-9](?:[a-z0-9._:-]*[a-z0-9])?$/;
const digest = /^[0-9a-f]{64}$/;
const taskKey = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/;
const failures = new Set<Failure>([
  "",
  "transient",
  "resource_limit",
  "policy",
  "invalid_input",
  "canceled",
  "dependency",
  "internal",
]);
const taskStatuses = new Set<TaskStatus>([
  "pending",
  "available",
  "leased",
  "succeeded",
  "failed",
  "skipped",
]);
const taskKinds = new Set<TaskKind>([
  "acquire_source",
  "build_change",
  "inspect_deterministic",
  "retrieve_context",
  "assemble_context",
  "generate_candidates",
  "verify_candidates",
  "evaluate_publication",
  "publish_result",
]);
export class ApiError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(publicMessage(code));
    this.name = "ApiError";
    this.code = code;
  }
}
function publicMessage(code: string): string {
  switch (code) {
    case "unauthenticated":
    case "unauthorized":
      return "The access token was not accepted. Check it and connect again.";
    case "stale_plan":
      return "The setup plan changed. Inspect it again before running this check.";
    case "state_unavailable":
      return "Protected setup state is unavailable. Check the local state path and permissions.";
    case "state_invalid":
    case "state_conflict":
      return "Protected setup state could not be verified. Inspect its plan and receipt ledger.";
    case "check_unavailable":
      return "This setup check is not available with the supplied configuration.";
    case "check_failed":
      return "The setup check failed without changing verified state.";
    case "invalid_request":
    case "unsupported_media_type":
    case "request_too_large":
      return "The setup request was rejected before any check ran.";
    case "forbidden":
      return "This token cannot read the requested tenant or repository.";
    case "not_found":
      return "No review run exists at this exact scope.";
    case "timeout":
      return "The daemon did not answer in time. Try again.";
    case "unavailable":
      return "The daemon is not available. Check its address and readiness.";
    default:
      return "The daemon returned a response the console could not verify.";
  }
}
function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function exact(
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}
function string(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length <= max;
}
function integer(
  value: unknown,
  min = 0,
  max = Number.MAX_SAFE_INTEGER,
): value is number {
  return (
    Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= max
  );
}
function validDigest(value: unknown, allowEmpty = false): value is string {
  return (
    (allowEmpty && value === "") ||
    (typeof value === "string" &&
      digest.test(value) &&
      value !== "0".repeat(64))
  );
}
export function validAccessToken(token: string): boolean {
  return (
    token.length >= 32 && token.length <= 512 && !/[\x00-\x20\x7f]/.test(token)
  );
}
export function validScope(scope: Scope): boolean {
  return [scope.tenant, scope.repository, scope.run].every(
    (value) =>
      value.length >= 1 && value.length <= 128 && identifier.test(value),
  );
}
function parseTask(value: unknown): RunTask {
  const keys = [
    "key",
    "task_identity",
    "input_identity",
    "handler_identity",
    "kind",
    "required",
    "status",
    "attempts",
    "max_attempts",
    "lease_expires_at_milliseconds",
    "output_identity",
    "failure",
    "retry_at_milliseconds",
  ] as const;
  if (
    !record(value) ||
    !exact(value, keys) ||
    !string(value.key, 64) ||
    !taskKey.test(value.key) ||
    !validDigest(value.task_identity) ||
    !validDigest(value.input_identity) ||
    !validDigest(value.handler_identity) ||
    typeof value.kind !== "string" ||
    !taskKinds.has(value.kind as TaskKind) ||
    typeof value.required !== "boolean" ||
    typeof value.status !== "string" ||
    !taskStatuses.has(value.status as TaskStatus) ||
    !integer(value.attempts, 0, 5) ||
    !integer(value.max_attempts, 1, 5) ||
    !integer(value.lease_expires_at_milliseconds, 0, 253402300799999) ||
    !validDigest(value.output_identity, true) ||
    typeof value.failure !== "string" ||
    !failures.has(value.failure as Failure) ||
    !integer(value.retry_at_milliseconds, 0, 253402300799999)
  ) {
    throw new ApiError("invalid_response");
  }
  return value as unknown as RunTask;
}
function parseRun(value: unknown): RunReceipt {
  const keys = [
    "contract",
    "schema_version",
    "identity",
    "plan_identity",
    "tenant_id",
    "repository_id",
    "review_run_id",
    "status",
    "revision",
    "head_identity",
    "last_occurred_at_milliseconds",
    "output_identity",
    "failure",
    "tasks",
  ] as const;
  if (
    !record(value) ||
    !exact(value, keys) ||
    value.contract !== "open-trestle/review-run-receipt" ||
    value.schema_version !== 1 ||
    !validDigest(value.identity) ||
    !validDigest(value.plan_identity) ||
    !string(value.tenant_id, 128) ||
    !string(value.repository_id, 128) ||
    !string(value.review_run_id, 128) ||
    !validScope({
      tenant: value.tenant_id,
      repository: value.repository_id,
      run: value.review_run_id,
    }) ||
    typeof value.status !== "string" ||
    !["active", "succeeded", "failed", "canceled"].includes(value.status) ||
    !integer(value.revision, 1) ||
    !validDigest(value.head_identity) ||
    !integer(value.last_occurred_at_milliseconds, 1, 253402300799999) ||
    !validDigest(value.output_identity, true) ||
    typeof value.failure !== "string" ||
    !failures.has(value.failure as Failure) ||
    !Array.isArray(value.tasks) ||
    value.tasks.length < 1 ||
    value.tasks.length > 64
  ) {
    throw new ApiError("invalid_response");
  }
  const tasks = value.tasks.map(parseTask);
  if (
    new Set(tasks.map((task) => task.key)).size !== tasks.length ||
    new Set(tasks.map((task) => task.task_identity)).size !== tasks.length
  ) {
    throw new ApiError("invalid_response");
  }
  return { ...value, tasks } as RunReceipt;
}
export function parseRunEnvelope(value: unknown, scope?: Scope): RunReceipt {
  if (!record(value)) throw new ApiError("invalid_response");
  if ("error" in value) {
    if (
      !exact(value, ["contract", "schema_version", "request_id", "error"]) ||
      value.contract !== "open-trestle/api-response" ||
      value.schema_version !== 1 ||
      !string(value.request_id, 128) ||
      value.request_id.length === 0 ||
      !record(value.error) ||
      !exact(value.error, ["code", "message"]) ||
      !string(value.error.code, 64) ||
      value.error.code.length === 0 ||
      !string(value.error.message, 512) ||
      value.error.message.length === 0
    ) {
      throw new ApiError("invalid_response");
    }
    throw new ApiError(value.error.code);
  }
  if (
    !exact(value, ["contract", "schema_version", "request_id", "run"]) ||
    value.contract !== "open-trestle/api-response" ||
    value.schema_version !== 1 ||
    !string(value.request_id, 128) ||
    value.request_id.length === 0
  ) {
    throw new ApiError("invalid_response");
  }
  const run = parseRun(value.run);
  if (
    scope &&
    (run.tenant_id !== scope.tenant ||
      run.repository_id !== scope.repository ||
      run.review_run_id !== scope.run)
  )
    throw new ApiError("invalid_response");
  return run;
}
function parseDiagnostic(value: unknown): Diagnostic {
  const keys = [
    "identity",
    "source_identity",
    "fingerprint",
    "title",
    "message",
    "severity",
    "path",
    "start_line",
    "end_line",
    "evidence_ids",
  ] as const;
  if (
    !record(value) ||
    !exact(value, keys) ||
    !validDigest(value.identity) ||
    !validDigest(value.source_identity) ||
    !validDigest(value.fingerprint) ||
    !string(value.title, 256) ||
    value.title.length === 0 ||
    !string(value.message, 4096) ||
    value.message.length === 0 ||
    typeof value.severity !== "string" ||
    !["error", "warning", "information", "hint"].includes(value.severity) ||
    !string(value.path, 1024) ||
    value.path.length === 0 ||
    !integer(value.start_line, 1, 10000000) ||
    !integer(value.end_line, value.start_line as number, 10000000) ||
    !Array.isArray(value.evidence_ids) ||
    value.evidence_ids.length < 1 ||
    value.evidence_ids.length > 16 ||
    !value.evidence_ids.every((v) => string(v, 128) && v.length > 0) ||
    new Set(value.evidence_ids).size !== value.evidence_ids.length
  )
    throw new ApiError("invalid_response");
  return value as unknown as Diagnostic;
}
export function parseDiagnosticEnvelope(
  value: unknown,
  scope: Scope,
): DiagnosticSet {
  if (!record(value)) throw new ApiError("invalid_response");
  if ("error" in value) {
    if (
      exact(value, ["contract", "schema_version", "request_id", "error"]) &&
      value.contract === "open-trestle/api-response" &&
      value.schema_version === 1 &&
      string(value.request_id, 128) &&
      value.request_id.length > 0 &&
      record(value.error) &&
      exact(value.error, ["code", "message"]) &&
      string(value.error.code, 64) &&
      value.error.code.length > 0 &&
      string(value.error.message, 512) &&
      value.error.message.length > 0
    )
      throw new ApiError(value.error.code);
    throw new ApiError("invalid_response");
  }
  if (
    !exact(value, [
      "contract",
      "schema_version",
      "request_id",
      "diagnostics",
    ]) ||
    value.contract !== "open-trestle/api-response" ||
    value.schema_version !== 1 ||
    !string(value.request_id, 128) ||
    value.request_id.length === 0 ||
    !record(value.diagnostics)
  )
    throw new ApiError("invalid_response");
  const d = value.diagnostics;
  const baseKeys = [
    "contract",
    "schema_version",
    "identity",
    "tenant_id",
    "repository_id",
    "review_run_id",
    "snapshot_identity",
    "head_revision",
    "verified_set_identity",
  ] as const;
  const keys =
    d.schema_version === 1
      ? [...baseKeys, "findings"]
      : d.schema_version === 2
        ? [...baseKeys, "coverage", "findings"]
        : d.schema_version === 5
          ? [...baseKeys, "coverage", "source_coverage", "checks", "findings"]
          : [...baseKeys, "coverage", "source_coverage", "findings"];
  if (
    !exact(d, keys) ||
    d.contract !== "open-trestle/review-diagnostic-set" ||
    (d.schema_version !== 1 &&
      d.schema_version !== 2 &&
      d.schema_version !== 3 &&
      d.schema_version !== 4 &&
      d.schema_version !== 5) ||
    !validDigest(d.identity) ||
    d.tenant_id !== scope.tenant ||
    d.repository_id !== scope.repository ||
    d.review_run_id !== scope.run ||
    !validDigest(d.snapshot_identity) ||
    typeof d.head_revision !== "string" ||
    !/^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(d.head_revision) ||
    !validDigest(d.verified_set_identity) ||
    !Array.isArray(d.findings) ||
    d.findings.length > 100
  )
    throw new ApiError("invalid_response");
  const findings = d.findings.map(parseDiagnostic);
  if (
    new Set(findings.map((finding) => finding.identity)).size !==
    findings.length
  ) {
    throw new ApiError("invalid_response");
  }
  if (d.schema_version === 1) return { ...d, findings } as DiagnosticSet;
  if (
    !record(d.coverage) ||
    !exact(d.coverage, [
      "candidate_count",
      "verified_count",
      "rejected_count",
      "inconclusive_count",
    ]) ||
    !integer(d.coverage.candidate_count, 0, 100) ||
    !integer(d.coverage.verified_count, 0, 100) ||
    !integer(d.coverage.rejected_count, 0, 100) ||
    !integer(d.coverage.inconclusive_count, 0, 100) ||
    d.coverage.verified_count !== findings.length ||
    d.coverage.verified_count +
      d.coverage.rejected_count +
      d.coverage.inconclusive_count !==
      d.coverage.candidate_count
  )
    throw new ApiError("invalid_response");
  if (d.schema_version === 2)
    return {
      ...d,
      coverage: { ...d.coverage },
      findings,
    } as unknown as DiagnosticSet;
  if (
    !record(d.source_coverage) ||
    !exact(
      d.source_coverage,
      d.schema_version === 4 || d.schema_version === 5
        ? [
            "verification_context_identity",
            "analyzed_count",
            "selected_count",
            "omitted_count",
            "omissions",
          ]
        : [
            "verification_context_identity",
            "analyzed_count",
            "selected_count",
            "omitted_count",
          ],
    ) ||
    !validDigest(d.source_coverage.verification_context_identity) ||
    !integer(d.source_coverage.analyzed_count, 1, 65664) ||
    !integer(d.source_coverage.selected_count, 1, 32) ||
    !integer(d.source_coverage.omitted_count, 0, 65664) ||
    d.source_coverage.selected_count + d.source_coverage.omitted_count !==
      d.source_coverage.analyzed_count
  )
    throw new ApiError("invalid_response");
  if (d.schema_version === 3)
    return {
      ...d,
      coverage: { ...d.coverage },
      source_coverage: { ...d.source_coverage },
      findings,
    } as unknown as DiagnosticSet;
  if (
    !Array.isArray(d.source_coverage.omissions) ||
    d.source_coverage.omissions.length > 6
  )
    throw new ApiError("invalid_response");
  const reasons = new Set([
    "authorization",
    "resource_limit",
    "unsupported",
    "analysis_failure",
    "duplicate",
    "selection_limit",
  ]);
  let previous = "";
  let omitted = 0;
  const omissions = d.source_coverage.omissions.map((summary) => {
    if (
      !record(summary) ||
      !exact(summary, ["reason", "count"]) ||
      typeof summary.reason !== "string" ||
      !reasons.has(summary.reason) ||
      summary.reason <= previous ||
      !integer(summary.count, 1, 65664)
    )
      throw new ApiError("invalid_response");
    previous = summary.reason;
    omitted += summary.count;
    return { ...summary };
  });
  if (
    omitted !== d.source_coverage.omitted_count ||
    (omitted === 0) !== (omissions.length === 0)
  )
    throw new ApiError("invalid_response");
  if (d.schema_version === 4)
    return {
      ...d,
      coverage: { ...d.coverage },
      source_coverage: { ...d.source_coverage, omissions },
      findings,
    } as unknown as DiagnosticSet;
  if (!Array.isArray(d.checks) || d.checks.length !== 1)
    throw new ApiError("invalid_response");
  const check = d.checks[0];
  if (!record(check)) throw new ApiError("invalid_response");
  if (
    Object.keys(check).length !== 12 ||
    !validDigest(check.identity) ||
    !validDigest(check.source_check_identity) ||
    !validDigest(check.analysis_result_identity) ||
    !validDigest(check.change_identity) ||
    check.key !== "static_debug_output" ||
    check.rule_version !== 1 ||
    !integer(check.applicable_files, 0, 4096) ||
    !integer(check.applicable_ranges, 0, 1_000_000) ||
    !integer(check.checked_files, 0, 4096) ||
    !integer(check.checked_ranges, 0, 1_000_000) ||
    !integer(check.matches, 0, 1 << 24) ||
    check.applicable_files > check.applicable_ranges ||
    check.checked_files > check.applicable_files ||
    check.checked_files > check.checked_ranges ||
    check.checked_ranges > check.applicable_ranges ||
    (check.applicable_files === 0) !== (check.applicable_ranges === 0) ||
    (check.checked_files === 0) !== (check.checked_ranges === 0)
  )
    throw new ApiError("invalid_response");
  const complete =
    check.checked_files === check.applicable_files &&
    check.checked_ranges === check.applicable_ranges;
  const validState =
    (check.state === "passed" &&
      check.applicable_ranges > 0 &&
      complete &&
      check.matches === 0) ||
    (check.state === "failed" &&
      check.applicable_ranges > 0 &&
      check.checked_ranges > 0 &&
      check.matches > 0) ||
    (check.state === "incomplete" &&
      check.applicable_ranges > 0 &&
      !complete &&
      check.matches === 0) ||
    (check.state === "not_applicable" &&
      check.applicable_ranges === 0 &&
      check.matches === 0);
  if (!validState) throw new ApiError("invalid_response");
  return {
    ...d,
    coverage: { ...d.coverage },
    source_coverage: { ...d.source_coverage, omissions },
    checks: [{ ...check }],
    findings,
  } as unknown as DiagnosticSet;
}
function validRuntimeObservedAt(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match =
    /^(\d{4})-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.(\d{1,3}))?Z$/.exec(
      value,
    );
  if (!match || Number(match[1]) < 1970) return false;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return false;
  const normalized = match[2]
    ? value.replace(`.${match[2]}Z`, `.${match[2].padEnd(3, "0")}Z`)
    : value.replace("Z", ".000Z");
  return new Date(milliseconds).toISOString() === normalized;
}

export function parseRuntimeStatusEnvelope(
  value: unknown,
  scope: Pick<Scope, "tenant" | "repository">,
): RuntimeStatus {
  if (!record(value)) throw new ApiError("invalid_response");
  if ("error" in value) {
    if (
      exact(value, ["contract", "schema_version", "request_id", "error"]) &&
      value.contract === "open-trestle/api-response" &&
      value.schema_version === 1 &&
      string(value.request_id, 128) &&
      value.request_id.length > 0 &&
      record(value.error) &&
      exact(value.error, ["code", "message"]) &&
      string(value.error.code, 64) &&
      value.error.code.length > 0 &&
      string(value.error.message, 512) &&
      value.error.message.length > 0
    )
      throw new ApiError(value.error.code);
    throw new ApiError("invalid_response");
  }
  if (
    !exact(value, ["contract", "schema_version", "request_id", "status"]) ||
    value.contract !== "open-trestle/runtime-status-response" ||
    value.schema_version !== 1 ||
    !string(value.request_id, 128) ||
    value.request_id.length === 0 ||
    !record(value.status)
  )
    throw new ApiError("invalid_response");
  const status = value.status;
  if (
    !exact(status, [
      "contract",
      "schema_version",
      "identity",
      "configuration_identity",
      "tenant_id",
      "repository_id",
      "observed_at",
      "ready",
      "configuration",
      "components",
    ]) ||
    status.contract !== "open-trestle/runtime-status" ||
    status.schema_version !== 1 ||
    !validDigest(status.identity) ||
    !validDigest(status.configuration_identity) ||
    status.tenant_id !== scope.tenant ||
    status.repository_id !== scope.repository ||
    !validRuntimeObservedAt(status.observed_at) ||
    typeof status.ready !== "boolean" ||
    !record(status.configuration) ||
    !Array.isArray(status.components) ||
    status.components.length > 64
  )
    throw new ApiError("invalid_response");
  const configuration = status.configuration;
  const baseKeys = [
    "tenant_id",
    "repository_ids",
    "metadata_backend",
    "artifact_backend",
    "artifact_protection",
    "notification_backend",
    "rate_limit_backend",
    "review_mode",
    "webhook_ingress",
    "local_workers",
    "publication_enabled",
    "publication_fence_verified",
    "route_count",
    "handlers",
  ];
  const hasRoutes =
    "route_inventory_identity" in configuration ||
    "runtime_policy_identity" in configuration;
  const hasDatabaseAuthority = "database_authority_identity" in configuration;
  const hasRateLimitAuthority =
    "rate_limit_authority_identity" in configuration;
  let expected = [...baseKeys];
  if (hasDatabaseAuthority) expected.push("database_authority_identity");
  if (hasRateLimitAuthority) expected.push("rate_limit_authority_identity");
  if (hasRoutes)
    expected.push("route_inventory_identity", "runtime_policy_identity");
  if (
    !exact(configuration, expected) ||
    configuration.tenant_id !== scope.tenant ||
    !Array.isArray(configuration.repository_ids) ||
    configuration.repository_ids.length !== 1 ||
    configuration.repository_ids[0] !== scope.repository ||
    !["local", "postgres"].includes(configuration.metadata_backend as string) ||
    !["local", "s3"].includes(configuration.artifact_backend as string) ||
    !["process_private", "envelope_encrypted"].includes(
      configuration.artifact_protection as string,
    ) ||
    !["process_local", "postgres"].includes(
      configuration.notification_backend as string,
    ) ||
    !["process_local", "postgres"].includes(
      configuration.rate_limit_backend as string,
    ) ||
    !["disabled", "local", "advisory", "required"].includes(
      configuration.review_mode as string,
    ) ||
    typeof configuration.webhook_ingress !== "boolean" ||
    typeof configuration.local_workers !== "boolean" ||
    typeof configuration.publication_enabled !== "boolean" ||
    typeof configuration.publication_fence_verified !== "boolean" ||
    !integer(configuration.route_count, 0, 64) ||
    !Array.isArray(configuration.handlers) ||
    configuration.handlers.length > 64
  )
    throw new ApiError("invalid_response");
  const routeConfigured = Number(configuration.route_count) > 0;
  if (
    hasRoutes !== routeConfigured ||
    hasDatabaseAuthority !== (configuration.metadata_backend === "postgres") ||
    hasRateLimitAuthority !==
      (configuration.rate_limit_backend === "postgres") ||
    (hasRateLimitAuthority &&
      !validDigest(configuration.rate_limit_authority_identity)) ||
    (hasDatabaseAuthority &&
      !validDigest(configuration.database_authority_identity)) ||
    (hasRoutes &&
      (!validDigest(configuration.route_inventory_identity) ||
        !validDigest(configuration.runtime_policy_identity))) ||
    (routeConfigured && configuration.local_workers !== true) ||
    (configuration.review_mode === "disabled" &&
      (configuration.local_workers ||
        routeConfigured ||
        configuration.handlers.length > 0)) ||
    (configuration.local_workers && configuration.handlers.length === 0)
  )
    throw new ApiError("invalid_response");
  if (
    (configuration.review_mode === "required") !==
      configuration.publication_enabled ||
    (configuration.publication_enabled &&
      !configuration.publication_fence_verified) ||
    (configuration.publication_fence_verified &&
      configuration.metadata_backend !== "postgres") ||
    (configuration.metadata_backend === "local" &&
      (configuration.artifact_backend !== "local" ||
        configuration.artifact_protection !== "process_private" ||
        configuration.notification_backend !== "process_local" ||
        configuration.rate_limit_backend !== "process_local")) ||
    (configuration.artifact_backend === "local" &&
      configuration.artifact_protection !== "process_private") ||
    (configuration.notification_backend === "postgres" &&
      configuration.metadata_backend !== "postgres") ||
    (configuration.rate_limit_backend === "postgres" &&
      configuration.metadata_backend !== "postgres") ||
    (configuration.metadata_backend === "postgres" &&
      configuration.rate_limit_backend !== "postgres") ||
    (configuration.artifact_backend === "s3" &&
      (configuration.metadata_backend !== "postgres" ||
        configuration.artifact_protection !== "envelope_encrypted"))
  )
    throw new ApiError("invalid_response");
  const handlers = configuration.handlers as unknown[];
  let previousHandlerKind = "";
  for (const handler of handlers) {
    if (
      !record(handler) ||
      !exact(handler, ["kind", "identity"]) ||
      typeof handler.kind !== "string" ||
      !taskKinds.has(handler.kind as TaskKind) ||
      !validDigest(handler.identity) ||
      handler.kind <= previousHandlerKind
    )
      throw new ApiError("invalid_response");
    previousHandlerKind = handler.kind;
  }
  let allReady = true,
    previousComponent = "";
  for (const component of status.components) {
    if (
      !record(component) ||
      !exact(component, ["name", "state"]) ||
      typeof component.name !== "string" ||
      !/^[a-z0-9_]{1,64}$/.test(component.name) ||
      component.name <= previousComponent ||
      (component.state !== "starting" && component.state !== "ready")
    )
      throw new ApiError("invalid_response");
    previousComponent = component.name;
    allReady = allReady && component.state === "ready";
  }
  if (status.ready !== allReady) throw new ApiError("invalid_response");
  return status as unknown as RuntimeStatus;
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
    throw new ApiError("invalid_response");
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
      throw new ApiError("invalid_response");
    return parser(response.body);
  }
  const code = parseSetupError(response.body);
  if (setupErrorStatus[code] !== response.status)
    throw new ApiError("invalid_response");
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
const setupProfileKeys: Record<SetupProfile, SetupCheckKey[]> = {
  local_single_node: [
    "profile_selected",
    "scope_valid",
    "effect_posture_locked",
    "recovery_owner_named",
    "state_storage_posture_validated",
    "backup_validated",
    "local_administrator_validated",
    "observer_credential_posture_validated",
    "policy_validated",
    "local_inference_validated",
    "dry_run_validated",
  ],
  controlled_hybrid: [
    "profile_selected",
    "scope_valid",
    "effect_posture_locked",
    "recovery_owner_named",
    "postgres_storage_validated",
    "envelope_storage_validated",
    "backup_validated",
    "secret_backend_validated",
    "local_administrator_validated",
    "observer_credential_posture_validated",
    "remote_provider_authorized",
    "integration_permissions_validated",
    "webhook_validated",
    "policy_validated",
    "dry_run_validated",
  ],
  kubernetes_ha: [
    "profile_selected",
    "scope_valid",
    "effect_posture_locked",
    "recovery_owner_named",
    "postgres_storage_validated",
    "envelope_storage_validated",
    "backup_validated",
    "secret_backend_validated",
    "shared_rate_limit_validated",
    "replica_reconciliation_validated",
    "local_administrator_validated",
    "observer_credential_posture_validated",
    "remote_provider_authorized",
    "integration_permissions_validated",
    "webhook_validated",
    "policy_validated",
    "dry_run_validated",
  ],
  air_gapped: [
    "profile_selected",
    "scope_valid",
    "effect_posture_locked",
    "recovery_owner_named",
    "state_storage_posture_validated",
    "backup_validated",
    "local_administrator_validated",
    "observer_credential_posture_validated",
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
    throw new ApiError("invalid_response");
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
    throw new ApiError("invalid_response");
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
    throw new ApiError("invalid_response");
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
    throw new ApiError("invalid_response");
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
    throw new ApiError("invalid_response");
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
    throw new ApiError("invalid_response");
  const requirements = value.requirements.map(parseSetupRequirement);
  const expectedKeys = setupProfileKeys[profile];
  if (
    requirements.length !== expectedKeys.length ||
    requirements.some(
      (requirement, index) => requirement.key !== expectedKeys[index],
    )
  )
    throw new ApiError("invalid_response");
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
      throw new ApiError("invalid_response");
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
    throw new ApiError("invalid_response");
  const receipts = value.receipts.map(parseSetupReceipt);
  if (
    receipts.length > 256 ||
    value.revision !== receipts.length + 1 ||
    new Set(receipts.map((r) => r.identity)).size !== receipts.length ||
    new Set(receipts.map((r) => r.checked_at)).size !== receipts.length
  )
    throw new ApiError("invalid_response");
  let previousReceipt: SetupReceipt | undefined;
  for (const receipt of receipts) {
    if (
      authorityMap.get(receipt.key) !== receipt.checker_identity ||
      (previousReceipt !== undefined &&
        Date.parse(receipt.checked_at) <=
          Date.parse(previousReceipt.checked_at))
    )
      throw new ApiError("invalid_response");
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
      throw new ApiError("invalid_response");
    if (
      !receipt &&
      requirement.source !== "deterministic" &&
      requirement.state !== "pending"
    )
      throw new ApiError("invalid_response");
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
    throw new ApiError("invalid_response");
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
    throw new ApiError("invalid_response");
  if (value.initialized) {
    if (!exact(value, ["contract", "schema_version", "initialized", "plan"]))
      throw new ApiError("invalid_response");
    return { ...value, plan: parseSetupPlan(value.plan) } as SetupSession;
  }
  if (!exact(value, ["contract", "schema_version", "initialized"]))
    throw new ApiError("invalid_response");
  return value as unknown as SetupSession;
}
export function parseSetupCheckResult(value: unknown): SetupCheckResult {
  if (!record(value)) {
    throw new ApiError("invalid_response");
  }
  if (value.contract === "open-trestle/setup-error") {
    if (
      !exact(value, ["contract", "schema_version", "code"]) ||
      value.schema_version !== 1 ||
      typeof value.code !== "string" ||
      !setupErrorCodes.has(value.code)
    )
      throw new ApiError("invalid_response");
    throw new ApiError(value.code);
  }
  if (
    !exact(value, ["contract", "schema_version", "plan", "receipt"]) ||
    value.contract !== "open-trestle/setup-check-result" ||
    value.schema_version !== 1
  )
    throw new ApiError("invalid_response");
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
    throw new ApiError("invalid_response");
  return {
    contract: "open-trestle/setup-check-result",
    schema_version: 1,
    plan,
    receipt,
  };
}

type Fetcher = (input: string, init: RequestInit) => Promise<Response>;
function assertUniqueJSONKeys(text: string): void {
  let index = 0;
  const whitespace = () => {
    while (index < text.length && /[\t\n\r ]/.test(text[index]!)) index++;
  };
  const stringValue = (): string => {
    const start = index;
    if (text[index] !== '"') throw new ApiError("invalid_response");
    index++;
    for (; index < text.length; index++) {
      const character = text[index]!;
      if (character === '"') {
        index++;
        try {
          return JSON.parse(text.slice(start, index)) as string;
        } catch {
          throw new ApiError("invalid_response");
        }
      }
      if (character === "\\") {
        index++;
        if (index >= text.length) break;
        if (text[index] === "u") {
          for (let count = 0; count < 4; count++) {
            index++;
            if (index >= text.length || !/[0-9a-f]/i.test(text[index]!))
              throw new ApiError("invalid_response");
          }
        }
      } else if (character.charCodeAt(0) < 0x20)
        throw new ApiError("invalid_response");
    }
    throw new ApiError("invalid_response");
  };
  const value = (depth: number): void => {
    if (depth > 128) throw new ApiError("invalid_response");
    whitespace();
    const character = text[index];
    if (character === "{") {
      index++;
      whitespace();
      const keys = new Set<string>();
      if (text[index] === "}") {
        index++;
        return;
      }
      for (;;) {
        whitespace();
        const key = stringValue();
        if (keys.has(key)) throw new ApiError("invalid_response");
        keys.add(key);
        whitespace();
        if (text[index] !== ":") throw new ApiError("invalid_response");
        index++;
        value(depth + 1);
        whitespace();
        if (text[index] === "}") {
          index++;
          return;
        }
        if (text[index] !== ",") throw new ApiError("invalid_response");
        index++;
      }
    } else if (character === "[") {
      index++;
      whitespace();
      if (text[index] === "]") {
        index++;
        return;
      }
      for (;;) {
        value(depth + 1);
        whitespace();
        if (text[index] === "]") {
          index++;
          return;
        }
        if (text[index] !== ",") throw new ApiError("invalid_response");
        index++;
      }
    } else if (character === '"') {
      stringValue();
    } else {
      const start = index;
      while (index < text.length && !/[\t\n\r ,\]}]/.test(text[index]!))
        index++;
      if (start === index) throw new ApiError("invalid_response");
      try {
        JSON.parse(text.slice(start, index));
      } catch {
        throw new ApiError("invalid_response");
      }
    }
  };
  value(0);
  whitespace();
  if (index !== text.length) throw new ApiError("invalid_response");
}
function validJSONMediaType(value: string | null): boolean {
  return (
    value !== null &&
    /^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(value.trim())
  );
}

async function readBoundedJSONBody(
  response: Response,
  controller: AbortController,
  maximumBytes = maximumResponseBytes,
): Promise<unknown> {
  const announced = response.headers.get("content-length");
  if (
    announced !== null &&
    (!/^\d+$/.test(announced) || Number(announced) > maximumBytes)
  ) {
    controller.abort();
    throw new ApiError("invalid_response");
  }
  if (response.body === null) throw new ApiError("invalid_response");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maximumBytes) {
          try {
            await reader.cancel();
          } catch {}
          controller.abort();
          throw new ApiError("invalid_response");
        }
        chunks.push(value);
      }
    }
  } finally {
    reader.releaseLock();
  }
  const encoded = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    encoded.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(encoded);
  } catch {
    throw new ApiError("invalid_response");
  }
  try {
    assertUniqueJSONKeys(text);
    return JSON.parse(text) as unknown;
  } catch {
    throw new ApiError("invalid_response");
  }
}
async function request(
  path: string,
  token: string,
  fetcher: Fetcher,
  method: "GET" | "POST" = "GET",
  body?: unknown,
  maximumBytes = maximumResponseBytes,
  timeoutMilliseconds = 15000,
): Promise<{ status: number; body: unknown }> {
  if (!validAccessToken(token)) throw new ApiError("unauthenticated");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMilliseconds);
  try {
    const headers = new Headers({
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
    });
    let encoded: string | undefined;
    if (body !== undefined) {
      encoded = JSON.stringify(body);
      headers.set("Content-Type", "application/json");
    }
    const response = await fetcher(path, {
      method,
      headers,
      body: encoded,
      signal: controller.signal,
      redirect: "error",
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
    if (!validJSONMediaType(response.headers.get("content-type")))
      throw new ApiError("invalid_response");
    return {
      status: response.status,
      body: await readBoundedJSONBody(response, controller, maximumBytes),
    };
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (controller.signal.aborted) throw new ApiError("timeout");
    throw new ApiError("unavailable");
  } finally {
    clearTimeout(timer);
  }
}
function scopePath(scope: Scope): string {
  if (!validScope(scope)) throw new ApiError("invalid_scope");
  return `/api/v1/tenants/${encodeURIComponent(scope.tenant)}/repositories/${encodeURIComponent(scope.repository)}/runs/${encodeURIComponent(scope.run)}`;
}
export async function fetchRun(
  scope: Scope,
  token: string,
  fetcher: Fetcher = fetch,
): Promise<RunReceipt> {
  const response = await request(scopePath(scope), token, fetcher);
  const run = parseRunEnvelope(response.body, scope);
  if (response.status !== 200) throw new ApiError("invalid_response");
  return run;
}
export async function fetchDiagnostics(
  scope: Scope,
  token: string,
  fetcher: Fetcher = fetch,
): Promise<DiagnosticSet> {
  const response = await request(
    `${scopePath(scope)}/diagnostics`,
    token,
    fetcher,
  );
  const diagnostics = parseDiagnosticEnvelope(response.body, scope);
  if (response.status !== 200) throw new ApiError("invalid_response");
  return diagnostics;
}

function validRuntimeScope(
  scope: Pick<Scope, "tenant" | "repository">,
): boolean {
  return [scope.tenant, scope.repository].every(
    (value) =>
      value.length >= 1 && value.length <= 128 && identifier.test(value),
  );
}
export async function fetchRuntimeStatus(
  scope: Pick<Scope, "tenant" | "repository">,
  token: string,
  fetcher: Fetcher = fetch,
): Promise<RuntimeStatus> {
  if (!validRuntimeScope(scope)) throw new ApiError("invalid_scope");
  const path = `/api/v1/tenants/${encodeURIComponent(scope.tenant)}/repositories/${encodeURIComponent(scope.repository)}/runtime`;
  const response = await request(path, token, fetcher);
  const status = parseRuntimeStatusEnvelope(response.body, scope);
  if (response.status !== 200) throw new ApiError("invalid_response");
  return status;
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
    throw new ApiError("invalid_response");
  return session;
}
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
  if (input.key === "state_storage_posture_validated") {
    if (!validSetupPath(input.storage_root))
      throw new ApiError("invalid_scope");
    body = { ...body, storage_root: input.storage_root };
  } else if (input.key === "backup_validated") {
    if (!validSetupPath(input.backup_snapshot_path))
      throw new ApiError("invalid_scope");
    body = { ...body, backup_snapshot_path: input.backup_snapshot_path };
  } else if (input.key === "postgres_storage_validated") {
    if (
      !validDigest(input.approve_postgres_authority_identity) ||
      !validSetupLabel(input.approved_by)
    )
      throw new ApiError("invalid_scope");
    body = {
      ...body,
      approve_postgres_authority_identity:
        input.approve_postgres_authority_identity,
      approved_by: input.approved_by,
    };
  } else if (input.key === "shared_rate_limit_validated") {
    if (
      !validDigest(input.approve_shared_rate_limit_authority_identity) ||
      !validDigest(input.postgres_database_authority_identity) ||
      !validSetupLabel(input.approved_by)
    )
      throw new ApiError("invalid_scope");
    body = {
      ...body,
      approve_shared_rate_limit_authority_identity:
        input.approve_shared_rate_limit_authority_identity,
      postgres_database_authority_identity:
        input.postgres_database_authority_identity,
      approved_by: input.approved_by,
    };
  } else if (input.key === "replica_reconciliation_validated") {
    if (
      !validDigest(input.approve_replica_reconciliation_authority_identity) ||
      !validDigest(input.postgres_database_authority_identity) ||
      !validSetupLabel(input.approved_by)
    )
      throw new ApiError("invalid_scope");
    body = {
      ...body,
      approve_replica_reconciliation_authority_identity:
        input.approve_replica_reconciliation_authority_identity,
      postgres_database_authority_identity:
        input.postgres_database_authority_identity,
      approved_by: input.approved_by,
    };
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
  } else if (input.key === "webhook_validated") {
    if (
      !validDigest(input.approve_webhook_authority_identity) ||
      !validSetupSecretValue(input.github_webhook_key_id, 128) ||
      !validSetupLabel(input.approved_by)
    )
      throw new ApiError("invalid_scope");
    body = {
      ...body,
      approve_webhook_authority_identity:
        input.approve_webhook_authority_identity,
      github_webhook_key_id: input.github_webhook_key_id,
      approved_by: input.approved_by,
    };
  } else if (input.key === "envelope_storage_validated") {
    if (
      !validDigest(input.approve_envelope_storage_authority_identity) ||
      !validSetupSecretValue(input.s3_endpoint, 2048) ||
      !validSetupSecretValue(input.s3_region, 128) ||
      !validSetupSecretValue(input.s3_bucket, 128) ||
      !validSetupSecretValue(input.s3_prefix, 1024) ||
      !validSetupSecretValue(input.kms_region, 128) ||
      !validSetupSecretValue(input.kms_key_arn, 2048) ||
      (input.kms_endpoint !== undefined &&
        !validSetupSecretValue(input.kms_endpoint, 2048)) ||
      !validSetupLabel(input.approved_by)
    )
      throw new ApiError("invalid_scope");
    body = {
      ...body,
      approve_envelope_storage_authority_identity:
        input.approve_envelope_storage_authority_identity,
      s3_endpoint: input.s3_endpoint,
      s3_region: input.s3_region,
      s3_bucket: input.s3_bucket,
      s3_prefix: input.s3_prefix,
      kms_region: input.kms_region,
      kms_key_arn: input.kms_key_arn,
      ...(input.kms_endpoint === undefined
        ? {}
        : { kms_endpoint: input.kms_endpoint }),
      approved_by: input.approved_by,
    };
  } else if (input.key === "secret_backend_validated") {
    if (
      !validDigest(input.approve_kms_authority_identity) ||
      !validSetupSecretValue(input.kms_region, 128) ||
      !validSetupSecretValue(input.kms_key_arn, 2048) ||
      (input.kms_endpoint !== undefined &&
        !validSetupSecretValue(input.kms_endpoint, 2048)) ||
      !validSetupLabel(input.approved_by)
    )
      throw new ApiError("invalid_scope");
    body = {
      ...body,
      approve_kms_authority_identity: input.approve_kms_authority_identity,
      kms_region: input.kms_region,
      kms_key_arn: input.kms_key_arn,
      ...(input.kms_endpoint === undefined
        ? {}
        : { kms_endpoint: input.kms_endpoint }),
      approved_by: input.approved_by,
    };
  } else if (input.key === "local_administrator_validated") {
    if (!validSetupLabel(input.approved_by))
      throw new ApiError("invalid_scope");
    body = { ...body, approved_by: input.approved_by };
  } else if (
    input.key === "remote_provider_authorized" ||
    input.key === "policy_validated" ||
    input.key === "dry_run_validated" ||
    input.key === "local_inference_validated"
  ) {
    if (
      !validSetupPath(input.route_inventory_path) ||
      !validSetupPath(input.runtime_policy_path) ||
      !validDigest(input.approve_inventory_identity) ||
      !validDigest(input.approve_runtime_policy_identity) ||
      !validDigest(input.approve_review_policy_identity) ||
      !validSetupLabel(input.approved_by)
    )
      throw new ApiError("invalid_scope");
    body = {
      ...body,
      route_inventory_path: input.route_inventory_path,
      runtime_policy_path: input.runtime_policy_path,
      approve_inventory_identity: input.approve_inventory_identity,
      approve_runtime_policy_identity: input.approve_runtime_policy_identity,
      approve_review_policy_identity: input.approve_review_policy_identity,
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
    throw new ApiError("invalid_response");
  return result;
}
