import type {
  ContextRefusal,
  ContextShortfall,
  Diagnostic,
  DiagnosticSet,
  DeliveryRefusal,
  DeterministicObservation,
  Failure,
  FailureReason,
  RunReceipt,
  RunProgress,
  RunTask,
  RuntimeStatus,
  Scope,
  TaskKind,
  TaskStatus,
} from "./types";
import {
  canonicalRuntimeConfiguration,
  runtimeConfigurationIdentity,
  runtimeStatusIdentity,
  type RuntimeComponentWire,
  type RuntimeHandlerWire,
} from "./runtimeIdentity";
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
const sourceFailureReasons = new Set<FailureReason>([
  "no_merge_base",
  "nothing_to_review",
  "merge_base_unavailable",
]);
/** Each provider refusal reason and the run failure it is recorded with. */
const providerFailureReasons = new Map<FailureReason, Failure>([
  ["provider_payment_required", "policy"],
  ["provider_model_unavailable", "policy"],
  ["provider_model_retired", "policy"],
  ["provider_authentication_failed", "policy"],
  ["provider_authorization_denied", "policy"],
  ["provider_rate_limited", "transient"],
  ["provider_response_invalid", "internal"],
  ["model_output_invalid", "internal"],
  ["provider_request_rejected", "policy"],
]);
const contextFailureReasons = new Set<FailureReason>([
  "route_context_insufficient",
  "no_eligible_route",
]);
const maxUint32 = 4294967295;
/** Reports a route_context_insufficient count set with its host invariants. */
function validContextShortfall(value: unknown): value is ContextShortfall {
  return (
    record(value) &&
    exact(value, [
      "required_tokens",
      "estimated_input_tokens",
      "max_output_tokens",
      "declared_context_tokens",
    ]) &&
    integer(value.estimated_input_tokens, 1, maxUint32) &&
    integer(value.max_output_tokens, 1, maxUint32) &&
    integer(value.declared_context_tokens, 1, maxUint32) &&
    value.required_tokens ===
      value.estimated_input_tokens + value.max_output_tokens &&
    value.declared_context_tokens < value.required_tokens
  );
}
/** The daemon's fixed hint for a route_context_insufficient refusal. */
export function contextShortfallHint(s: ContextShortfall): string {
  return `the review needs up to ${s.required_tokens} tokens (a byte-based upper bound: ${s.estimated_input_tokens} input plus ${s.max_output_tokens} output) but the route declares max_context_tokens ${s.declared_context_tokens}; raise max_context_tokens on the route and the model server's context length to at least ${s.required_tokens} (docs/named-local-runtimes.md#context-length)`;
}
/** Reports a v7 refusal copy: a context reason and counts exactly with it. */
function validContextRefusal(value: unknown): value is ContextRefusal {
  if (!record(value) || typeof value.reason !== "string") return false;
  const counted = value.reason === "route_context_insufficient";
  return (
    contextFailureReasons.has(value.reason as FailureReason) &&
    exact(value, counted ? ["reason", "context_shortfall"] : ["reason"]) &&
    (!counted || validContextShortfall(value.context_shortfall))
  );
}
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
export function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
export function exact(
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
export function string(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length <= max;
}
export function nonemptyString(value: unknown, max: number): value is string {
  return string(value, max) && value.length > 0;
}
export function integer(
  value: unknown,
  min = 0,
  max = Number.MAX_SAFE_INTEGER,
): value is number {
  return (
    Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= max
  );
}
export function validDigest(
  value: unknown,
  allowEmpty = false,
): value is string {
  return (
    (allowEmpty && value === "") ||
    (typeof value === "string" &&
      digest.test(value) &&
      value !== "0".repeat(64))
  );
}
export function invalidResponse(): never {
  throw new ApiError("invalid_response");
}
function parseAPIError(value: Record<string, unknown>): never {
  if (
    !exact(value, ["contract", "schema_version", "request_id", "error"]) ||
    value.contract !== "open-trestle/api-response" ||
    value.schema_version !== 1 ||
    !nonemptyString(value.request_id, 128) ||
    !record(value.error) ||
    !exact(value.error, ["code", "message"]) ||
    !nonemptyString(value.error.code, 64) ||
    !nonemptyString(value.error.message, 512)
  )
    invalidResponse();
  throw new ApiError(value.error.code);
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
  ];
  const optional = record(value)
    ? ["output_kind", "failure_reason", "context_shortfall"].filter(
        (key) => key in value,
      )
    : [];
  if (
    !record(value) ||
    !exact(value, [...keys, ...optional]) ||
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
    invalidResponse();
  }
  // A failed task carries an output only as a context abstention, and a
  // content-free reason only without output: a source reason on source
  // acquisition, a route refusal on context assembly, a provider refusal on
  // a model task with its fixed failure, and counts exactly with
  // route_context_insufficient.
  const linkedOutput =
    value.status === "failed" && value.output_identity !== "";
  const reason = value.failure_reason;
  const providerFailure =
    typeof reason === "string"
      ? providerFailureReasons.get(reason as FailureReason)
      : undefined;
  const reasonKinds: readonly string[] =
    typeof reason !== "string"
      ? []
      : sourceFailureReasons.has(reason as FailureReason)
        ? ["acquire_source"]
        : contextFailureReasons.has(reason as FailureReason)
          ? ["assemble_context"]
          : providerFailure !== undefined
            ? ["generate_candidates", "verify_candidates"]
            : [];
  if (
    "output_kind" in value !== linkedOutput ||
    (linkedOutput &&
      (value.output_kind !== "context_abstention" ||
        value.kind !== "assemble_context")) ||
    ("failure_reason" in value &&
      (!reasonKinds.includes(value.kind as string) ||
        value.status !== "failed" ||
        value.output_identity !== "" ||
        (providerFailure !== undefined &&
          value.failure !== providerFailure))) ||
    "context_shortfall" in value !==
      (reason === "route_context_insufficient") ||
    ("context_shortfall" in value &&
      !validContextShortfall(value.context_shortfall))
  ) {
    invalidResponse();
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
    ![1, 2, 3].includes(value.schema_version as number) ||
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
    invalidResponse();
  }
  const tasks = value.tasks.map(parseTask);
  const version = tasks.some((task) => task.failure_reason)
    ? 3
    : tasks.some((task) => task.output_kind)
      ? 2
      : 1;
  if (
    value.schema_version !== version ||
    new Set(tasks.map((task) => task.key)).size !== tasks.length ||
    new Set(tasks.map((task) => task.task_identity)).size !== tasks.length
  ) {
    invalidResponse();
  }
  return { ...value, tasks } as RunReceipt;
}
export function parseRunEnvelope(value: unknown, scope?: Scope): RunReceipt {
  if (!record(value)) invalidResponse();
  if ("error" in value) parseAPIError(value);
  if (
    !exact(value, ["contract", "schema_version", "request_id", "run"]) ||
    value.contract !== "open-trestle/api-response" ||
    value.schema_version !== 1 ||
    !nonemptyString(value.request_id, 128)
  ) {
    invalidResponse();
  }
  const run = parseRun(value.run);
  if (
    scope &&
    (run.tenant_id !== scope.tenant ||
      run.repository_id !== scope.repository ||
      run.review_run_id !== scope.run)
  )
    invalidResponse();
  return run;
}
export function parseRunProgressEnvelope(
  value: unknown,
  scope: Scope,
  expected: RunReceipt,
): RunProgress {
  if (!record(value)) invalidResponse();
  if ("error" in value) {
    parseRunEnvelope(value, scope);
    invalidResponse();
  }
  if (
    !exact(value, [
      "contract",
      "schema_version",
      "request_id",
      "run",
      "progress",
    ]) ||
    value.contract !== "open-trestle/run-progress-response" ||
    value.schema_version !== 1 ||
    !nonemptyString(value.request_id, 128) ||
    !record(value.progress)
  )
    invalidResponse();
  const run = parseRunEnvelope(
    {
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: value.request_id,
      run: value.run,
    },
    scope,
  );
  if (
    run.identity !== expected.identity ||
    run.head_identity !== expected.head_identity ||
    run.plan_identity !== expected.plan_identity ||
    run.revision !== expected.revision ||
    run.tenant_id !== expected.tenant_id ||
    run.repository_id !== expected.repository_id ||
    run.review_run_id !== expected.review_run_id ||
    run.status !== expected.status ||
    run.failure !== expected.failure ||
    run.output_identity !== expected.output_identity ||
    run.last_occurred_at_milliseconds !==
      expected.last_occurred_at_milliseconds ||
    run.tasks.length !== expected.tasks.length ||
    run.tasks.some((task, index) =>
      Object.entries(task).some(
        ([key, entry]) =>
          entry !== expected.tasks[index]?.[key as keyof RunTask],
      ),
    ) ||
    !exact(value.progress, [
      "change",
      "deterministic",
      "context",
      "verification",
    ])
  )
    invalidResponse();
  const fields = {
    change: ["files", "ranges"],
    deterministic: [
      "applicable_files",
      "applicable_ranges",
      "checked_files",
      "checked_ranges",
      "observations",
    ],
    context: ["analyzed", "selected", "omitted"],
    verification: ["candidates", "verified", "rejected", "inconclusive"],
  } as const;
  const kinds = {
    change: "build_change",
    deterministic: "inspect_deterministic",
    context: "assemble_context",
    verification: "verify_candidates",
  } as const;
  for (const name of Object.keys(fields) as (keyof typeof fields)[]) {
    const axis = value.progress[name];
    if (
      !record(axis) ||
      !exact(axis, [
        "state",
        ...(Object.hasOwn(axis, "artifact_identity")
          ? ["artifact_identity"]
          : []),
        ...fields[name].filter((key) => Object.hasOwn(axis, key)),
      ]) ||
      !["not_run", "available", "partial", "unavailable"].includes(
        axis.state as string,
      )
    )
      invalidResponse();
    const available = axis.state === "available" || axis.state === "partial";
    const tasks = run.tasks.filter((task) => task.kind === kinds[name]);
    const completed = tasks.length === 1 && tasks[0]!.status === "succeeded";
    const hasArtifact = Object.hasOwn(axis, "artifact_identity");
    if (
      (hasArtifact &&
        (!validDigest(axis.artifact_identity) ||
          !completed ||
          (name !== "context" &&
            axis.artifact_identity !== tasks[0]!.output_identity))) ||
      (axis.state === "partial" && name !== "deterministic") ||
      (available && (!hasArtifact || !completed)) ||
      (axis.state === "not_run" &&
        tasks.some((task) => task.status === "succeeded")) ||
      fields[name].some(
        (key) =>
          Object.hasOwn(axis, key) &&
          (!available || !integer(axis[key], 0, 1 << 30)),
      )
    )
      invalidResponse();
    if (
      available &&
      name !== "deterministic" &&
      fields[name].some((key) => !Object.hasOwn(axis, key))
    )
      invalidResponse();
  }
  const progress = value.progress as unknown as RunProgress["progress"];
  const c = progress.change,
    d = progress.deterministic,
    x = progress.context,
    v = progress.verification;
  const checkCounts = [
    d.applicable_files,
    d.applicable_ranges,
    d.checked_files,
    d.checked_ranges,
  ];
  const checkCount = checkCounts.filter((count) => count !== undefined).length;
  if (
    (c.files !== undefined && c.files > 4096) ||
    (c.ranges !== undefined && c.ranges > 1_000_000) ||
    (d.state === "partial" && checkCount !== 4) ||
    (checkCount !== 0 && checkCount !== 4) ||
    (checkCount === 4 &&
      (d.applicable_files! > 4096 ||
        d.applicable_ranges! > 1_000_000 ||
        d.checked_files! > d.applicable_files! ||
        d.checked_ranges! > d.applicable_ranges! ||
        d.applicable_files! > d.applicable_ranges! ||
        d.checked_files! > d.checked_ranges!)) ||
    (d.observations !== undefined && d.observations > 8192) ||
    (x.analyzed !== undefined &&
      (x.analyzed > 65664 ||
        x.selected! > 32 ||
        x.analyzed !== x.selected! + x.omitted!)) ||
    (v.candidates !== undefined &&
      (v.candidates > 16 ||
        v.candidates !== v.verified! + v.rejected! + v.inconclusive!))
  )
    invalidResponse();
  return { run, progress };
}
// sided admits the version 8 "side" field: present only as "base", for
// removed lines of the base revision; absent means head lines.
function parseDiagnostic(
  value: unknown,
  observation = false,
  sided = false,
): Diagnostic {
  const keys = [
    "identity",
    "source_identity",
    "fingerprint",
    ...(observation ? ["analysis_result_identity", "check_identity"] : []),
    "title",
    "message",
    "severity",
    "path",
    "start_line",
    "end_line",
    ...(sided && record(value) && Object.hasOwn(value, "side") ? ["side"] : []),
    ...(sided && record(value) && Object.hasOwn(value, "head_line")
      ? ["head_line"]
      : []),
    "evidence_ids",
  ] as const;
  if (
    !record(value) ||
    !exact(value, keys) ||
    (Object.hasOwn(value, "side") && value.side !== "base") ||
    (Object.hasOwn(value, "head_line") &&
      (value.side !== "base" || !integer(value.head_line, 1, 10000000))) ||
    !validDigest(value.identity) ||
    !validDigest(value.source_identity) ||
    !validDigest(value.fingerprint) ||
    (observation &&
      (!validDigest(value.analysis_result_identity) ||
        !validDigest(value.check_identity))) ||
    !nonemptyString(value.title, 256) ||
    !nonemptyString(value.message, 4096) ||
    typeof value.severity !== "string" ||
    !["error", "warning", "information", "hint"].includes(value.severity) ||
    !nonemptyString(value.path, 1024) ||
    !integer(value.start_line, 1, 10000000) ||
    !integer(value.end_line, value.start_line as number, 10000000) ||
    !Array.isArray(value.evidence_ids) ||
    value.evidence_ids.length < 1 ||
    value.evidence_ids.length > 16 ||
    !value.evidence_ids.every((v) => nonemptyString(v, 128)) ||
    new Set(value.evidence_ids).size !== value.evidence_ids.length
  )
    invalidResponse();
  return value as unknown as Diagnostic;
}
function parseDeterministicCheck(value: unknown) {
  const keys = [
    "identity",
    "source_check_identity",
    "analysis_result_identity",
    "change_identity",
    "key",
    "rule_version",
    "state",
    "applicable_files",
    "applicable_ranges",
    "checked_files",
    "checked_ranges",
    "matches",
  ] as const;
  if (
    !record(value) ||
    !exact(value, keys) ||
    !validDigest(value.identity) ||
    !validDigest(value.source_check_identity) ||
    !validDigest(value.analysis_result_identity) ||
    !validDigest(value.change_identity) ||
    value.key !== "static_debug_output" ||
    value.rule_version !== 1 ||
    !integer(value.applicable_files, 0, 4096) ||
    !integer(value.applicable_ranges, 0, 1_000_000) ||
    !integer(value.checked_files, 0, 4096) ||
    !integer(value.checked_ranges, 0, 1_000_000) ||
    !integer(value.matches, 0, 1 << 24) ||
    value.applicable_files > value.applicable_ranges ||
    value.checked_files > value.applicable_files ||
    value.checked_files > value.checked_ranges ||
    value.checked_ranges > value.applicable_ranges ||
    (value.applicable_files === 0) !== (value.applicable_ranges === 0) ||
    (value.checked_files === 0) !== (value.checked_ranges === 0)
  )
    invalidResponse();
  const complete =
    value.checked_files === value.applicable_files &&
    value.checked_ranges === value.applicable_ranges;
  const validState =
    (value.state === "passed" &&
      value.applicable_ranges > 0 &&
      complete &&
      value.matches === 0) ||
    (value.state === "failed" &&
      value.applicable_ranges > 0 &&
      value.checked_ranges > 0 &&
      value.matches > 0) ||
    (value.state === "incomplete" &&
      value.applicable_ranges > 0 &&
      !complete &&
      value.matches === 0) ||
    (value.state === "not_applicable" &&
      value.applicable_ranges === 0 &&
      value.matches === 0);
  if (!validState) invalidResponse();
  return {
    ...value,
  } as unknown as import("./types").DiagnosticDeterministicCheck;
}
function parseDeterministicObservation(
  value: unknown,
): DeterministicObservation {
  const parsed = parseDiagnostic(value, true) as DeterministicObservation;
  return { ...parsed, evidence_ids: [...parsed.evidence_ids] };
}
function validDiagnosticSetCommon(
  value: Record<string, unknown>,
  scope: Scope,
): boolean {
  return (
    value.contract === "open-trestle/review-diagnostic-set" &&
    validDigest(value.identity) &&
    value.tenant_id === scope.tenant &&
    value.repository_id === scope.repository &&
    value.review_run_id === scope.run &&
    validDigest(value.snapshot_identity) &&
    typeof value.head_revision === "string" &&
    /^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(value.head_revision)
  );
}

export function parseDiagnosticEnvelope(
  value: unknown,
  scope: Scope,
): DiagnosticSet {
  if (!record(value)) invalidResponse();
  if ("error" in value) parseAPIError(value);
  if (
    !exact(value, [
      "contract",
      "schema_version",
      "request_id",
      "diagnostics",
    ]) ||
    value.contract !== "open-trestle/api-response" ||
    value.schema_version !== 1 ||
    !nonemptyString(value.request_id, 128) ||
    !record(value.diagnostics)
  )
    invalidResponse();
  const d = value.diagnostics;
  if (d.schema_version === 7) {
    const keys = [
      "contract",
      "schema_version",
      "identity",
      "tenant_id",
      "repository_id",
      "review_run_id",
      "snapshot_identity",
      "head_revision",
      "outcome",
      ...(Object.hasOwn(d, "deterministic") ? ["deterministic"] : []),
      ...(Object.hasOwn(d, "verified") ? ["verified"] : []),
      ...(Object.hasOwn(d, "context_refusal") ? ["context_refusal"] : []),
      ...(Object.hasOwn(d, "evidence_expired") ? ["evidence_expired"] : []),
    ];
    const emptySource = d.snapshot_identity === "" && d.head_revision === "";
    const completeSource =
      validDigest(d.snapshot_identity) &&
      typeof d.head_revision === "string" &&
      /^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(d.head_revision);
    if (
      !exact(d, keys) ||
      d.contract !== "open-trestle/review-diagnostic-set" ||
      !validDigest(d.identity) ||
      d.tenant_id !== scope.tenant ||
      d.repository_id !== scope.repository ||
      d.review_run_id !== scope.run ||
      !(emptySource || completeSource) ||
      ![
        "completed",
        "failed",
        "canceled",
        "abstained",
        "inconclusive",
      ].includes(d.outcome as string) ||
      (d.outcome === "completed" && !Object.hasOwn(d, "verified")) ||
      (Object.hasOwn(d, "verified") && !Object.hasOwn(d, "deterministic")) ||
      (Object.hasOwn(d, "context_refusal") &&
        (d.outcome !== "failed" ||
          Object.hasOwn(d, "verified") ||
          !validContextRefusal(d.context_refusal))) ||
      // An expired-evidence result has no evidence part and is never completed.
      (Object.hasOwn(d, "evidence_expired") &&
        (d.evidence_expired !== true ||
          d.outcome === "completed" ||
          !emptySource ||
          Object.hasOwn(d, "deterministic") ||
          Object.hasOwn(d, "verified")))
    )
      invalidResponse();
    const parsePart = (part: unknown, ...versions: number[]) => {
      const parsed = parseDiagnosticEnvelope(
        {
          contract: "open-trestle/api-response",
          schema_version: 1,
          request_id: value.request_id,
          diagnostics: part,
        },
        scope,
      );
      if (
        !versions.includes(parsed.schema_version) ||
        (parsed.schema_version === 6 &&
          parsed.snapshot_identity !== d.snapshot_identity) ||
        parsed.head_revision !== d.head_revision
      )
        invalidResponse();
      return parsed;
    };
    const deterministic = Object.hasOwn(d, "deterministic")
      ? (parsePart(d.deterministic, 6) as Extract<
          DiagnosticSet,
          { schema_version: 6 }
        >)
      : undefined;
    const verified = Object.hasOwn(d, "verified")
      ? (parsePart(d.verified, 5, 8) as Extract<
          DiagnosticSet,
          { schema_version: 5 | 8 }
        >)
      : undefined;
    if (
      verified &&
      verified.checks[0].identity !== deterministic?.checks[0].identity
    )
      invalidResponse();
    return {
      ...d,
      ...(deterministic ? { deterministic } : {}),
      ...(verified ? { verified } : {}),
    } as DiagnosticSet;
  }
  if (d.schema_version === 6) {
    const keys = [
      "contract",
      "schema_version",
      "identity",
      "tenant_id",
      "repository_id",
      "review_run_id",
      "snapshot_identity",
      "head_revision",
      "analysis_result_identity",
      "checks",
      "observations",
    ] as const;
    if (
      !exact(d, keys) ||
      !validDiagnosticSetCommon(d, scope) ||
      !validDigest(d.analysis_result_identity) ||
      !Array.isArray(d.checks) ||
      d.checks.length !== 1 ||
      !Array.isArray(d.observations) ||
      d.observations.length > 8192
    )
      invalidResponse();
    const check = parseDeterministicCheck(d.checks[0]);
    const observations = d.observations.map(parseDeterministicObservation);
    if (
      check.analysis_result_identity !== d.analysis_result_identity ||
      check.matches !== observations.length ||
      new Set(observations.map((entry) => entry.identity)).size !==
        observations.length ||
      observations.some(
        (entry) =>
          entry.analysis_result_identity !== d.analysis_result_identity ||
          entry.check_identity !== check.identity,
      )
    )
      invalidResponse();
    return { ...d, checks: [check], observations } as unknown as DiagnosticSet;
  }
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
        : d.schema_version === 5 || d.schema_version === 8
          ? [...baseKeys, "coverage", "source_coverage", "checks", "findings"]
          : [...baseKeys, "coverage", "source_coverage", "findings"];
  if (
    !exact(d, keys) ||
    d.contract !== "open-trestle/review-diagnostic-set" ||
    (d.schema_version !== 1 &&
      d.schema_version !== 2 &&
      d.schema_version !== 3 &&
      d.schema_version !== 4 &&
      d.schema_version !== 5 &&
      d.schema_version !== 8) ||
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
    invalidResponse();
  const findings = d.findings.map((finding) =>
    parseDiagnostic(finding, false, d.schema_version === 8),
  );
  if (
    new Set(findings.map((finding) => finding.identity)).size !==
      findings.length ||
    // Version 8 is used exactly when a finding is on removed base lines.
    (d.schema_version === 8) !==
      findings.some((finding) => finding.side === "base")
  ) {
    invalidResponse();
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
    invalidResponse();
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
      d.schema_version === 4 || d.schema_version === 5 || d.schema_version === 8
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
    invalidResponse();
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
    invalidResponse();
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
      invalidResponse();
    previous = summary.reason;
    omitted += summary.count;
    return { ...summary };
  });
  if (
    omitted !== d.source_coverage.omitted_count ||
    (omitted === 0) !== (omissions.length === 0)
  )
    invalidResponse();
  if (d.schema_version === 4)
    return {
      ...d,
      coverage: { ...d.coverage },
      source_coverage: { ...d.source_coverage, omissions },
      findings,
    } as unknown as DiagnosticSet;
  if (!Array.isArray(d.checks) || d.checks.length !== 1) invalidResponse();
  const check = parseDeterministicCheck(d.checks[0]);
  return {
    ...d,
    coverage: { ...d.coverage },
    source_coverage: { ...d.source_coverage, omissions },
    checks: [{ ...check }],
    findings,
  } as unknown as DiagnosticSet;
}
export function validRuntimeObservedAt(value: unknown): value is string {
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

export async function parseRuntimeStatusEnvelope(
  value: unknown,
  scope: Pick<Scope, "tenant" | "repository">,
): Promise<RuntimeStatus> {
  if (!validRuntimeScope(scope)) throw new ApiError("invalid_scope");
  if (!record(value)) invalidResponse();
  if ("error" in value) parseAPIError(value);
  if (
    !exact(value, ["contract", "schema_version", "request_id", "status"]) ||
    value.contract !== "open-trestle/runtime-status-response" ||
    value.schema_version !== 1 ||
    !nonemptyString(value.request_id, 128) ||
    !record(value.status)
  )
    invalidResponse();
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
    invalidResponse();
  const configuration = status.configuration;
  const rawHandlers = configuration.handlers;
  const handlers: unknown[] = Array.isArray(rawHandlers) ? rawHandlers : [];
  const hasRoutes =
    "route_inventory_identity" in configuration ||
    "runtime_policy_identity" in configuration;
  const hasDatabaseAuthority = "database_authority_identity" in configuration;
  const hasRateLimitAuthority =
    "rate_limit_authority_identity" in configuration;
  const expected = ["tenant_id", "repository_ids", "metadata_backend"];
  if (hasDatabaseAuthority) expected.push("database_authority_identity");
  expected.push(
    "artifact_backend",
    "artifact_protection",
    "notification_backend",
    "rate_limit_backend",
  );
  if (hasRateLimitAuthority) expected.push("rate_limit_authority_identity");
  expected.push(
    "review_mode",
    "webhook_ingress",
    "local_workers",
    "publication_enabled",
    "publication_fence_verified",
  );
  if (hasRoutes)
    expected.push("route_inventory_identity", "runtime_policy_identity");
  expected.push("route_count", "handlers");
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
    (!Array.isArray(rawHandlers) && rawHandlers !== null) ||
    handlers.length > 64
  )
    invalidResponse();
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
        handlers.length > 0)) ||
    (configuration.local_workers && handlers.length === 0)
  )
    invalidResponse();
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
    invalidResponse();
  const runtimeHandlers = handlers as unknown[];
  const canonicalHandlers: RuntimeHandlerWire[] = [];
  let previousHandlerKind = "";
  for (const handler of runtimeHandlers) {
    if (
      !record(handler) ||
      !exact(handler, ["kind", "identity"]) ||
      typeof handler.kind !== "string" ||
      !taskKinds.has(handler.kind as TaskKind) ||
      !validDigest(handler.identity) ||
      handler.kind <= previousHandlerKind
    )
      invalidResponse();
    previousHandlerKind = handler.kind;
    canonicalHandlers.push({
      kind: handler.kind,
      identity: handler.identity as string,
    });
  }
  const canonicalComponents: RuntimeComponentWire[] = [];
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
      invalidResponse();
    previousComponent = component.name;
    allReady = allReady && component.state === "ready";
    canonicalComponents.push({
      name: component.name,
      state: component.state as "starting" | "ready",
    });
  }
  if (status.ready !== allReady) invalidResponse();
  const wireConfiguration = canonicalRuntimeConfiguration(
    configuration,
    rawHandlers === null ? null : canonicalHandlers,
    expected,
  );
  const configurationIdentity =
    await runtimeConfigurationIdentity(wireConfiguration);
  if (status.configuration_identity !== configurationIdentity)
    invalidResponse();
  const statusIdentity = await runtimeStatusIdentity({
    configuration_identity: configurationIdentity,
    tenant_id: status.tenant_id as string,
    repository_id: status.repository_id as string,
    observed_at: status.observed_at as string,
    ready: status.ready as boolean,
    configuration: wireConfiguration,
    components: canonicalComponents,
  });
  if (status.identity !== statusIdentity) invalidResponse();
  return {
    ...status,
    configuration: { ...configuration, handlers: runtimeHandlers },
  } as unknown as RuntimeStatus;
}

export type Fetcher = (input: string, init: RequestInit) => Promise<Response>;
function assertUniqueJSONKeys(text: string): void {
  let index = 0;
  const whitespace = () => {
    while (index < text.length && /[\t\n\r ]/.test(text[index]!)) index++;
  };
  const stringValue = (): string => {
    const start = index;
    if (text[index] !== '"') invalidResponse();
    index++;
    for (; index < text.length; index++) {
      const character = text[index]!;
      if (character === '"') {
        index++;
        try {
          return JSON.parse(text.slice(start, index)) as string;
        } catch {
          invalidResponse();
        }
      }
      if (character === "\\") {
        index++;
        if (index >= text.length) break;
        if (text[index] === "u") {
          for (let count = 0; count < 4; count++) {
            index++;
            if (index >= text.length || !/[0-9a-f]/i.test(text[index]!))
              invalidResponse();
          }
        }
      } else if (character.charCodeAt(0) < 0x20) invalidResponse();
    }
    invalidResponse();
  };
  const value = (depth: number): void => {
    if (depth > 128) invalidResponse();
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
        if (keys.has(key)) invalidResponse();
        keys.add(key);
        whitespace();
        if (text[index] !== ":") invalidResponse();
        index++;
        value(depth + 1);
        whitespace();
        if (text[index] === "}") {
          index++;
          return;
        }
        if (text[index] !== ",") invalidResponse();
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
        if (text[index] !== ",") invalidResponse();
        index++;
      }
    } else if (character === '"') {
      stringValue();
    } else {
      const start = index;
      while (index < text.length && !/[\t\n\r ,\]}]/.test(text[index]!))
        index++;
      if (start === index) invalidResponse();
      try {
        JSON.parse(text.slice(start, index));
      } catch {
        invalidResponse();
      }
    }
  };
  value(0);
  whitespace();
  if (index !== text.length) invalidResponse();
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
    invalidResponse();
  }
  if (response.body === null) invalidResponse();
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
          invalidResponse();
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
    invalidResponse();
  }
  try {
    assertUniqueJSONKeys(text);
    return JSON.parse(text) as unknown;
  } catch {
    invalidResponse();
  }
}
export async function request(
  path: string,
  token: string,
  fetcher: Fetcher,
  method: "GET" | "POST" = "GET",
  body?: unknown,
  maximumBytes = maximumResponseBytes,
  timeoutMilliseconds = 15000,
  signal?: AbortSignal,
): Promise<{ status: number; body: unknown }> {
  if (!validAccessToken(token)) throw new ApiError("unauthenticated");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMilliseconds);
  const abort = () => controller.abort();
  signal?.addEventListener("abort", abort, { once: true });
  if (signal?.aborted) controller.abort();
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
      invalidResponse();
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
    signal?.removeEventListener("abort", abort);
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
  signal?: AbortSignal,
): Promise<RunReceipt> {
  const response = await request(
    scopePath(scope),
    token,
    fetcher,
    "GET",
    undefined,
    maximumResponseBytes,
    15000,
    signal,
  );
  const run = parseRunEnvelope(response.body, scope);
  if (response.status !== 200) invalidResponse();
  return run;
}
const refusalReasonPattern = /^[a-z][a-z0-9_]{0,63}$/;
export function parseDeliveryRefusalEnvelope(
  value: unknown,
  scope: Scope,
): DeliveryRefusal {
  if (!record(value)) invalidResponse();
  if ("error" in value) parseAPIError(value);
  if (
    !exact(value, ["contract", "schema_version", "request_id", "refusal"]) ||
    value.contract !== "open-trestle/delivery-refusal-response" ||
    value.schema_version !== 1 ||
    !nonemptyString(value.request_id, 128)
  )
    invalidResponse();
  const refusal = value.refusal;
  if (
    !record(refusal) ||
    !exact(refusal, [
      "contract",
      "schema_version",
      "identity",
      "tenant_id",
      "repository_id",
      "source",
      "deduplication_key",
      "delivery_identity",
      "planner_identity",
      "reason",
      "refused_at_milliseconds",
    ]) ||
    refusal.contract !== "open-trestle/webhook-delivery-refusal" ||
    refusal.schema_version !== 1 ||
    !validDigest(refusal.identity) ||
    refusal.tenant_id !== scope.tenant ||
    refusal.repository_id !== scope.repository ||
    typeof refusal.source !== "string" ||
    !["github", "gitlab", "bitbucket_cloud", "gitea", "forgejo"].includes(
      refusal.source,
    ) ||
    !validDigest(refusal.deduplication_key) ||
    `webhook-${refusal.deduplication_key as string}` !== scope.run ||
    !validDigest(refusal.delivery_identity) ||
    !validDigest(refusal.planner_identity) ||
    typeof refusal.reason !== "string" ||
    !refusalReasonPattern.test(refusal.reason) ||
    !integer(refusal.refused_at_milliseconds, 1, 253402300799999)
  )
    invalidResponse();
  return refusal as unknown as DeliveryRefusal;
}
export async function fetchDeliveryRefusal(
  scope: Scope,
  token: string,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
): Promise<DeliveryRefusal> {
  const response = await request(
    `${scopePath(scope)}/refusal`,
    token,
    fetcher,
    "GET",
    undefined,
    maximumResponseBytes,
    15000,
    signal,
  );
  const refusal = parseDeliveryRefusalEnvelope(response.body, scope);
  if (response.status !== 200) invalidResponse();
  return refusal;
}
export async function fetchDiagnostics(
  scope: Scope,
  token: string,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
): Promise<DiagnosticSet> {
  const response = await request(
    `${scopePath(scope)}/diagnostics`,
    token,
    fetcher,
    "GET",
    undefined,
    maximumResponseBytes,
    15000,
    signal,
  );
  const diagnostics = parseDiagnosticEnvelope(response.body, scope);
  if (response.status !== 200) invalidResponse();
  return diagnostics;
}

export async function fetchRunProgress(
  scope: Scope,
  token: string,
  expected: RunReceipt,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
): Promise<RunProgress> {
  const response = await request(
    `${scopePath(scope)}/progress`,
    token,
    fetcher,
    "GET",
    undefined,
    maximumResponseBytes,
    15000,
    signal,
  );
  const progress = parseRunProgressEnvelope(response.body, scope, expected);
  if (response.status !== 200) invalidResponse();
  return progress;
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
  signal?: AbortSignal,
): Promise<RuntimeStatus> {
  if (!validRuntimeScope(scope)) throw new ApiError("invalid_scope");
  const path = `/api/v1/tenants/${encodeURIComponent(scope.tenant)}/repositories/${encodeURIComponent(scope.repository)}/runtime`;
  const response = await request(
    path,
    token,
    fetcher,
    "GET",
    undefined,
    maximumResponseBytes,
    15000,
    signal,
  );
  const status = await parseRuntimeStatusEnvelope(response.body, scope);
  if (response.status !== 200) invalidResponse();
  return status;
}
