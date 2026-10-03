import { createHash } from "node:crypto";

const digest = /^[0-9a-f]{64}$/;
const zeroDigest = /^0{64}$/;
const scopeValue = /^[A-Za-z0-9._:-]{1,128}$/;
const componentNames = new Set(["local_workers", "task_notifications"]);
const taskKinds = new Set([
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
export const browserPhases = new Set(["before_restart", "after_restart"]);
const exact = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const validDigest = (value) =>
  typeof value === "string" && digest.test(value) && !zeroDigest.test(value);
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const sha256 = (prefix, value) =>
  createHash("sha256")
    .update(prefix)
    .update(JSON.stringify(value))
    .digest("hex");
const validObservedAt = (value) => {
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
};

function canonicalConfiguration(configuration, scope) {
  if (
    configuration === null ||
    typeof configuration !== "object" ||
    Array.isArray(configuration)
  )
    throw new Error("invalid runtime configuration");
  const hasDatabase = Object.hasOwn(
    configuration,
    "database_authority_identity",
  );
  const hasRateLimit = Object.hasOwn(
    configuration,
    "rate_limit_authority_identity",
  );
  const hasRoutes =
    Object.hasOwn(configuration, "route_inventory_identity") ||
    Object.hasOwn(configuration, "runtime_policy_identity");
  const keys = [
    "tenant_id",
    "repository_ids",
    "metadata_backend",
    ...(hasDatabase ? ["database_authority_identity"] : []),
    "artifact_backend",
    "artifact_protection",
    "notification_backend",
    "rate_limit_backend",
    ...(hasRateLimit ? ["rate_limit_authority_identity"] : []),
    "review_mode",
    "webhook_ingress",
    "local_workers",
    "publication_enabled",
    "publication_fence_verified",
    ...(hasRoutes
      ? ["route_inventory_identity", "runtime_policy_identity"]
      : []),
    "route_count",
    "handlers",
  ];
  if (!exact(configuration, keys))
    throw new Error("invalid runtime configuration");
  const handlers =
    configuration.handlers === null ? [] : configuration.handlers;
  if (
    configuration.tenant_id !== scope.tenant ||
    !Array.isArray(configuration.repository_ids) ||
    configuration.repository_ids.length !== 1 ||
    configuration.repository_ids[0] !== scope.repository ||
    !["local", "postgres"].includes(configuration.metadata_backend) ||
    !["local", "s3"].includes(configuration.artifact_backend) ||
    !["process_private", "envelope_encrypted"].includes(
      configuration.artifact_protection,
    ) ||
    !["process_local", "postgres"].includes(
      configuration.notification_backend,
    ) ||
    !["process_local", "postgres"].includes(configuration.rate_limit_backend) ||
    !["disabled", "local", "advisory", "required"].includes(
      configuration.review_mode,
    ) ||
    typeof configuration.webhook_ingress !== "boolean" ||
    typeof configuration.local_workers !== "boolean" ||
    typeof configuration.publication_enabled !== "boolean" ||
    typeof configuration.publication_fence_verified !== "boolean" ||
    !Number.isSafeInteger(configuration.route_count) ||
    configuration.route_count < 0 ||
    configuration.route_count > 64 ||
    (!Array.isArray(configuration.handlers) &&
      configuration.handlers !== null) ||
    handlers.length > 64
  )
    throw new Error("invalid runtime configuration");
  if (
    hasDatabase !== (configuration.metadata_backend === "postgres") ||
    hasRateLimit !== (configuration.rate_limit_backend === "postgres") ||
    hasRoutes !== configuration.route_count > 0 ||
    (hasDatabase && !validDigest(configuration.database_authority_identity)) ||
    (hasRateLimit &&
      !validDigest(configuration.rate_limit_authority_identity)) ||
    (hasRoutes &&
      (!validDigest(configuration.route_inventory_identity) ||
        !validDigest(configuration.runtime_policy_identity))) ||
    (configuration.route_count > 0 && configuration.local_workers !== true) ||
    (configuration.review_mode === "disabled" &&
      (configuration.local_workers ||
        configuration.route_count > 0 ||
        handlers.length > 0)) ||
    (configuration.local_workers && handlers.length === 0) ||
    configuration.publication_enabled !==
      (configuration.review_mode === "required") ||
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
    (configuration.artifact_backend === "s3" &&
      (configuration.metadata_backend !== "postgres" ||
        configuration.artifact_protection !== "envelope_encrypted")) ||
    (configuration.notification_backend === "postgres" &&
      configuration.metadata_backend !== "postgres") ||
    (configuration.rate_limit_backend === "postgres" &&
      configuration.metadata_backend !== "postgres") ||
    (configuration.metadata_backend === "postgres" &&
      configuration.rate_limit_backend !== "postgres")
  )
    throw new Error("invalid runtime configuration");
  let previous = "";
  for (const handler of handlers) {
    if (
      !exact(handler, ["kind", "identity"]) ||
      !taskKinds.has(handler.kind) ||
      !validDigest(handler.identity) ||
      handler.kind <= previous
    )
      throw new Error("invalid runtime handler");
    previous = handler.kind;
  }
  const canonical = {
    tenant_id: configuration.tenant_id,
    repository_ids: [...configuration.repository_ids],
    metadata_backend: configuration.metadata_backend,
    ...(hasDatabase
      ? {
          database_authority_identity:
            configuration.database_authority_identity,
        }
      : {}),
    artifact_backend: configuration.artifact_backend,
    artifact_protection: configuration.artifact_protection,
    notification_backend: configuration.notification_backend,
    rate_limit_backend: configuration.rate_limit_backend,
    ...(hasRateLimit
      ? {
          rate_limit_authority_identity:
            configuration.rate_limit_authority_identity,
        }
      : {}),
    review_mode: configuration.review_mode,
    webhook_ingress: configuration.webhook_ingress,
    local_workers: configuration.local_workers,
    publication_enabled: configuration.publication_enabled,
    publication_fence_verified: configuration.publication_fence_verified,
    ...(hasRoutes
      ? {
          route_inventory_identity: configuration.route_inventory_identity,
          runtime_policy_identity: configuration.runtime_policy_identity,
        }
      : {}),
    route_count: configuration.route_count,
    handlers:
      configuration.handlers === null
        ? null
        : handlers.map((handler) => ({
            kind: handler.kind,
            identity: handler.identity,
          })),
  };
  return { wire: canonical, normalized: { ...canonical, handlers } };
}

export function validateRuntimeEnvelope(envelope, scope) {
  if (
    !exact(envelope, ["contract", "schema_version", "request_id", "status"]) ||
    envelope.contract !== "open-trestle/runtime-status-response" ||
    envelope.schema_version !== 1 ||
    typeof envelope.request_id !== "string" ||
    envelope.request_id.length < 1 ||
    envelope.request_id.length > 128
  )
    throw new Error("invalid runtime envelope");
  const status = envelope.status;
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
    !validObservedAt(status.observed_at) ||
    typeof status.ready !== "boolean" ||
    !Array.isArray(status.components) ||
    status.components.length > 64
  )
    throw new Error("invalid runtime status");
  const configuration = canonicalConfiguration(status.configuration, scope);
  const expectedConfigurationIdentity = sha256(
    "open-trestle/runtime-configuration/v1\0",
    configuration.wire,
  );
  if (status.configuration_identity !== expectedConfigurationIdentity)
    throw new Error("invalid runtime configuration identity");
  let previous = "";
  let ready = true;
  const components = status.components.map((component) => {
    if (
      !exact(component, ["name", "state"]) ||
      !componentNames.has(component.name) ||
      component.name <= previous ||
      !["starting", "ready"].includes(component.state)
    )
      throw new Error("invalid runtime component");
    previous = component.name;
    ready = ready && component.state === "ready";
    return { name: component.name, state: component.state };
  });
  if (status.ready !== ready) throw new Error("invalid runtime readiness");
  const canonicalStatus = {
    contract: "open-trestle/runtime-status",
    schema_version: 1,
    identity: "",
    configuration_identity: status.configuration_identity,
    tenant_id: status.tenant_id,
    repository_id: status.repository_id,
    observed_at: status.observed_at,
    ready: status.ready,
    configuration: configuration.wire,
    components,
  };
  if (
    status.identity !==
    sha256("open-trestle/runtime-status/v1\0", canonicalStatus)
  )
    throw new Error("invalid runtime status identity");
  return {
    ...canonicalStatus,
    identity: status.identity,
    configuration: configuration.normalized,
  };
}

export function validateRuntimeEvidence(runtime, phase, scope, captures) {
  const keys = [
    "phase",
    "endpoint",
    "displayed_received_at_milliseconds",
    "post_capture_received_at_milliseconds",
    "displayed",
    "post_capture",
    "dom",
    "runtime_screenshot_sha256",
  ];
  if (
    !exact(runtime, keys) ||
    runtime.phase !== phase ||
    runtime.endpoint !==
      `/api/v1/tenants/${encodeURIComponent(scope.tenant)}/repositories/${encodeURIComponent(scope.repository)}/runtime` ||
    !Number.isSafeInteger(runtime.displayed_received_at_milliseconds) ||
    !Number.isSafeInteger(runtime.post_capture_received_at_milliseconds) ||
    runtime.displayed_received_at_milliseconds < 0 ||
    runtime.post_capture_received_at_milliseconds <
      runtime.displayed_received_at_milliseconds ||
    !validDigest(runtime.runtime_screenshot_sha256)
  )
    throw new Error("invalid runtime evidence");
  const displayed = validateRuntimeEnvelope(runtime.displayed, scope);
  const post = validateRuntimeEnvelope(runtime.post_capture, scope);
  const displayedObserved = Date.parse(displayed.observed_at);
  const postObserved = Date.parse(post.observed_at);
  if (
    displayedObserved > runtime.displayed_received_at_milliseconds + 1000 ||
    runtime.displayed_received_at_milliseconds - displayedObserved > 30_000 ||
    postObserved > runtime.post_capture_received_at_milliseconds + 1000 ||
    runtime.post_capture_received_at_milliseconds - postObserved > 30_000 ||
    postObserved < displayedObserved ||
    displayed.configuration_identity !== post.configuration_identity ||
    displayed.tenant_id !== post.tenant_id ||
    displayed.repository_id !== post.repository_id ||
    displayed.ready !== post.ready ||
    !same(displayed.configuration, post.configuration) ||
    !same(displayed.components, post.components)
  )
    throw new Error("runtime changed during screenshot capture");
  const expectedDOM = {
    status_identity: displayed.identity,
    configuration_identity: displayed.configuration_identity,
    observed_at: displayed.observed_at,
    ready: displayed.ready,
    configuration: displayed.configuration,
    components: displayed.components,
  };
  if (!same(runtime.dom, expectedDOM))
    throw new Error("runtime DOM does not match response");
  const runtimeCaptures = captures.filter(
    (capture) => capture.view === "runtime",
  );
  if (
    runtimeCaptures.length !== 1 ||
    runtimeCaptures[0].sha256 !== runtime.runtime_screenshot_sha256
  )
    throw new Error("runtime screenshot is not bound to runtime evidence");
  return {
    ...runtime,
    displayed: runtime.displayed,
    post_capture: runtime.post_capture,
    dom: expectedDOM,
  };
}

export function buildDaemonVisualReceipt({
  phase,
  scope,
  observed,
  runtime,
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
    !exact(observed, [
      "run_identity",
      "diagnostic_set_identity",
      "deterministic_check_identity",
      "deterministic_check_state",
      "observation_count",
      "observation_identities",
    ]) ||
    !validDigest(observed.run_identity) ||
    !validDigest(observed.diagnostic_set_identity) ||
    !validDigest(observed.deterministic_check_identity) ||
    !["passed", "failed"].includes(observed.deterministic_check_state) ||
    !Number.isSafeInteger(observed.observation_count) ||
    observed.observation_count < 0 ||
    observed.observation_count > 8192 ||
    !Array.isArray(observed.observation_identities) ||
    observed.observation_identities.length !== observed.observation_count ||
    !observed.observation_identities.every(validDigest)
  )
    throw new Error("invalid daemon browser identities");
  if (
    !metrics ||
    !exact(metrics, [
      "console_errors",
      "unexpected_egress",
      "horizontal_overflow",
      "keyboard_focus_visible",
      "evidence_disclosure_focus_visible",
      "focus_order_steps",
      "reduced_motion",
      "tap_targets_minimum",
    ]) ||
    metrics.console_errors !== 0 ||
    metrics.unexpected_egress !== 0 ||
    metrics.horizontal_overflow !== false ||
    metrics.keyboard_focus_visible !== true ||
    metrics.evidence_disclosure_focus_visible !== true ||
    metrics.reduced_motion !== true ||
    metrics.tap_targets_minimum !== 44 ||
    !Number.isSafeInteger(metrics.focus_order_steps) ||
    metrics.focus_order_steps < 1 ||
    metrics.focus_order_steps > 32
  )
    throw new Error("invalid daemon browser metrics");
  if (
    !Array.isArray(captures) ||
    captures.length !== 5 ||
    captures.some(
      (capture) =>
        !exact(capture, [
          "name",
          "view",
          "width",
          "height",
          "image_width",
          "image_height",
          "bytes",
          "sha256",
        ]) ||
        typeof capture.name !== "string" ||
        !validDigest(capture.sha256) ||
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
  const boundRuntime = validateRuntimeEvidence(runtime, phase, scope, captures);
  return {
    contract: "open-trestle/daemon-console-visual-receipt",
    schema_version: 3,
    phase,
    scope,
    ...observed,
    runtime: boundRuntime,
    ...metrics,
    captures,
  };
}
