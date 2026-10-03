import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  buildDaemonVisualReceipt,
  validateRuntimeEnvelope,
} from "./daemon-visual-contract.mjs";

const digest = (value) => value.repeat(64);

const hash = (prefix, value) =>
  createHash("sha256")
    .update(prefix)
    .update(JSON.stringify(value))
    .digest("hex");
const runtimeConfiguration = {
  tenant_id: "tenant-a",
  repository_ids: ["repository-a"],
  metadata_backend: "local",
  artifact_backend: "local",
  artifact_protection: "process_private",
  notification_backend: "process_local",
  rate_limit_backend: "process_local",
  review_mode: "local",
  webhook_ingress: false,
  local_workers: true,
  publication_enabled: false,
  publication_fence_verified: false,
  route_count: 0,
  handlers: [
    { kind: "acquire_source", identity: digest("a") },
    { kind: "build_change", identity: digest("b") },
    { kind: "inspect_deterministic", identity: digest("c") },
  ],
};
const runtimeStatus = (observed_at, componentState = "ready") => {
  const configuration_identity = hash(
    "open-trestle/runtime-configuration/v1\0",
    runtimeConfiguration,
  );
  const unsigned = {
    contract: "open-trestle/runtime-status",
    schema_version: 1,
    identity: "",
    configuration_identity,
    tenant_id: "tenant-a",
    repository_id: "repository-a",
    observed_at,
    ready: componentState === "ready",
    configuration: runtimeConfiguration,
    components: [
      { name: "local_workers", state: componentState },
      { name: "task_notifications", state: componentState },
    ],
  };
  return {
    ...unsigned,
    identity: hash("open-trestle/runtime-status/v1\0", unsigned),
  };
};
const runtimeEnvelope = (status, request_id) => ({
  contract: "open-trestle/runtime-status-response",
  schema_version: 1,
  request_id,
  status,
});
const displayedRuntime = runtimeStatus("2026-10-03T05:00:00.000Z");
const rereadRuntime = runtimeStatus("2026-10-03T05:00:00.100Z");
const runtimeEvidence = {
  phase: "before_restart",
  endpoint: "/api/v1/tenants/tenant-a/repositories/repository-a/runtime",
  displayed_received_at_milliseconds: Date.parse("2026-10-03T05:00:00.010Z"),
  post_capture_received_at_milliseconds: Date.parse("2026-10-03T05:00:00.110Z"),
  displayed: runtimeEnvelope(displayedRuntime, "request-runtime-1"),
  post_capture: runtimeEnvelope(rereadRuntime, "request-runtime-2"),
  dom: {
    status_identity: displayedRuntime.identity,
    configuration_identity: displayedRuntime.configuration_identity,
    observed_at: displayedRuntime.observed_at,
    ready: displayedRuntime.ready,
    configuration: runtimeConfiguration,
    components: displayedRuntime.components,
  },
  runtime_screenshot_sha256: digest("7"),
};
const input = {
  phase: "before_restart",
  scope: { tenant: "tenant-a", repository: "repository-a", run: "local-alpha" },
  observed: {
    run_identity: digest("1"),
    diagnostic_set_identity: digest("2"),
    deterministic_check_identity: digest("3"),
    deterministic_check_state: "failed",
    observation_count: 1,
    observation_identities: [digest("4")],
  },
  runtime: runtimeEvidence,
  metrics: {
    console_errors: 0,
    unexpected_egress: 0,
    horizontal_overflow: false,
    keyboard_focus_visible: true,
    evidence_disclosure_focus_visible: true,
    focus_order_steps: 3,
    reduced_motion: true,
    tap_targets_minimum: 44,
  },
  captures: ["overview", "findings", "runtime", "tablet", "mobile"].map(
    (view, index) => ({
      name: `${view}.png`,
      view,
      width: index === 4 ? 390 : 900,
      height: 844,
      image_width: index === 4 ? 390 : 900,
      image_height: 900,
      bytes: 10,
      sha256: digest(String(index + 5)),
    }),
  ),
};

test("binds one visual receipt to an exact restart phase and review identities", () => {
  const receipt = buildDaemonVisualReceipt(input);
  assert.equal(receipt.phase, "before_restart");
  assert.equal(receipt.run_identity, digest("1"));
  assert.equal(receipt.diagnostic_set_identity, digest("2"));
  assert.equal(receipt.deterministic_check_identity, digest("3"));
  assert.equal(receipt.observation_count, 1);
});

test("rejects an unbound or unknown visual phase", () => {
  assert.throws(
    () => buildDaemonVisualReceipt({ ...input, phase: "" }),
    /phase/,
  );
  assert.throws(
    () =>
      buildDaemonVisualReceipt({
        ...input,
        observed: { ...input.observed, diagnostic_set_identity: "" },
      }),
    /identities/,
  );
});

test("binds Runtime screenshot to strict displayed and post-capture snapshots", () => {
  const receipt = buildDaemonVisualReceipt(input);
  assert.equal(receipt.schema_version, 3);
  assert.equal(receipt.runtime.phase, "before_restart");
  assert.equal(
    receipt.runtime.displayed.status.identity,
    displayedRuntime.identity,
  );
  assert.equal(
    receipt.runtime.post_capture.status.configuration_identity,
    displayedRuntime.configuration_identity,
  );
  assert.equal(receipt.runtime.runtime_screenshot_sha256, digest("7"));
});

test("rejects missing and malformed Runtime bindings", () => {
  assert.throws(
    () => buildDaemonVisualReceipt({ ...input, runtime: undefined }),
    /runtime/i,
  );
  for (const mutation of [
    {
      displayed: {
        ...runtimeEvidence.displayed,
        status: { ...displayedRuntime, identity: "" },
      },
    },
    {
      displayed: {
        ...runtimeEvidence.displayed,
        status: { ...displayedRuntime, schema_version: true },
      },
    },
    {
      displayed: {
        ...runtimeEvidence.displayed,
        status: {
          ...displayedRuntime,
          configuration: { ...runtimeConfiguration, route_count: true },
        },
      },
    },
    {
      displayed: {
        ...runtimeEvidence.displayed,
        status: {
          ...displayedRuntime,
          components: [{ name: "unknown_component", state: "ready" }],
        },
      },
    },
    { dom: { ...runtimeEvidence.dom, status_identity: digest("f") } },
    {
      post_capture: {
        ...runtimeEvidence.post_capture,
        status: { ...rereadRuntime, configuration_identity: digest("e") },
      },
    },
  ]) {
    assert.throws(
      () =>
        buildDaemonVisualReceipt({
          ...input,
          runtime: { ...runtimeEvidence, ...mutation },
        }),
      /runtime/i,
    );
  }
});

test("rejects stale, substituted, and capture-mutated Runtime evidence", () => {
  const stale = runtimeStatus("1970-01-01T00:00:00.000Z");
  assert.throws(
    () =>
      buildDaemonVisualReceipt({
        ...input,
        runtime: {
          ...runtimeEvidence,
          displayed: runtimeEnvelope(stale, "stale"),
        },
      }),
    /runtime/i,
  );
  assert.throws(
    () =>
      buildDaemonVisualReceipt({
        ...input,
        phase: "after_restart",
        runtime: runtimeEvidence,
      }),
    /runtime/i,
  );
  const mutated = runtimeStatus("2026-10-03T05:00:00.100Z", "starting");
  assert.throws(
    () =>
      buildDaemonVisualReceipt({
        ...input,
        runtime: {
          ...runtimeEvidence,
          post_capture: runtimeEnvelope(mutated, "mutated"),
        },
      }),
    /runtime/i,
  );
});

test("matches Go runtimeadmin identity golden", () => {
  const status = {
    contract: "open-trestle/runtime-status",
    schema_version: 1,
    identity:
      "7140112d9eee5bd9287fe98dc1a2985e79ebf4c00baf33975504c8691830c576",
    configuration_identity:
      "f89cbad323eb45449637dd40eba77f7eb63a987754270b85c2f9ec2db5c9be98",
    tenant_id: "tenant-a",
    repository_id: "repository-a",
    observed_at: "2026-10-03T05:00:00Z",
    ready: true,
    configuration: runtimeConfiguration,
    components: [
      { name: "local_workers", state: "ready" },
      { name: "task_notifications", state: "ready" },
    ],
  };
  const parsed = validateRuntimeEnvelope(runtimeEnvelope(status, "go-golden"), {
    tenant: "tenant-a",
    repository: "repository-a",
  });
  assert.equal(parsed.identity, status.identity);
  assert.equal(parsed.configuration_identity, status.configuration_identity);
});

test("reconstructs Go handler key order independent of JSON object order", () => {
  const status = runtimeStatus("2026-10-03T05:00:00.000Z");
  const reordered = {
    ...status,
    configuration: {
      ...status.configuration,
      handlers: status.configuration.handlers.map((handler) => ({
        identity: handler.identity,
        kind: handler.kind,
      })),
    },
  };
  const parsed = validateRuntimeEnvelope(
    runtimeEnvelope(reordered, "reordered"),
    {
      tenant: "tenant-a",
      repository: "repository-a",
    },
  );
  assert.equal(parsed.identity, status.identity);
});

test("normalizes Go runtimeadmin null handlers after identity validation", () => {
  const status = {
    contract: "open-trestle/runtime-status",
    schema_version: 1,
    identity:
      "8e915eaca0878ba00b7acc3c2ed907333b13e1ff1b825f60c43b8ab0832dd931",
    configuration_identity:
      "26ab6e2eb1f2b47d3c8e7f6b8eacb65c76d3594a223a7c9c73ac23f8b08b2d5a",
    tenant_id: "tenant-a",
    repository_id: "repository-a",
    observed_at: "2026-10-03T05:00:00Z",
    ready: true,
    configuration: {
      tenant_id: "tenant-a",
      repository_ids: ["repository-a"],
      metadata_backend: "local",
      artifact_backend: "local",
      artifact_protection: "process_private",
      notification_backend: "process_local",
      rate_limit_backend: "process_local",
      review_mode: "disabled",
      webhook_ingress: false,
      local_workers: false,
      publication_enabled: false,
      publication_fence_verified: false,
      route_count: 0,
      handlers: null,
    },
    components: [],
  };
  const parsed = validateRuntimeEnvelope(
    runtimeEnvelope(status, "go-empty-golden"),
    { tenant: "tenant-a", repository: "repository-a" },
  );
  assert.deepEqual(parsed.configuration.handlers, []);
  assert.equal(parsed.identity, status.identity);
});

test("reads semantic Runtime state labels without decorative icon text", async () => {
  const source = await readFile(
    new URL("./daemon-visual-check.mjs", import.meta.url),
    "utf8",
  );
  assert.equal(source.match(/lastElementChild\?\.textContent/g)?.length, 2);
});

test("captures the UI Runtime response before fulfilling the intercepted request", async () => {
  const source = await readFile(
    new URL("./daemon-visual-check.mjs", import.meta.url),
    "utf8",
  );
  assert.match(
    source,
    /const response = await route\.fetch\(\{ maxRedirects: 0 \}\)/,
  );
  assert.match(source, /new URL\(response\.url\(\)\)\.origin !== daemonOrigin/);
  assert.match(source, /await route\.fulfill\(\{ response, body \}\)/);
  assert.doesNotMatch(source, /page\.on\("response"/);
});
