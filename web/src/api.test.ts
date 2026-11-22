import { describe, expect, it, vi } from "vitest";
import {
  ApiError,
  contextShortfallHint,
  fetchRun,
  fetchRuntimeStatus,
  parseDiagnosticEnvelope,
  parseDeliveryRefusalEnvelope,
  parseRunEnvelope,
  parseRuntimeStatusEnvelope,
} from "./api";
import {
  runtimeConfigurationIdentity,
  runtimeStatusIdentity,
  type RuntimeConfigurationWire,
} from "./runtimeIdentity";

const digest = "a".repeat(64);
const run = {
  contract: "open-trestle/review-run-receipt",
  schema_version: 1,
  identity: digest,
  plan_identity: digest,
  tenant_id: "tenant-a",
  repository_id: "repo-a",
  review_run_id: "run-a",
  status: "active",
  revision: 1,
  head_identity: digest,
  last_occurred_at_milliseconds: 1000,
  output_identity: "",
  failure: "",
  tasks: [
    {
      key: "source",
      task_identity: digest,
      input_identity: digest,
      handler_identity: digest,
      kind: "acquire_source",
      required: true,
      status: "available",
      attempts: 0,
      max_attempts: 1,
      lease_expires_at_milliseconds: 0,
      output_identity: "",
      failure: "",
      retry_at_milliseconds: 0,
    },
  ],
};

const runtimeStatus = {
  contract: "open-trestle/runtime-status",
  schema_version: 1,
  identity: "5d7b86d0e18ba6c26c49d349221b99e41f0dc78994cd36477b12b6f11aab64fd",
  configuration_identity:
    "d625957a083abd5743f09c5ee719c15afc19b2615c144644b8394bf5b85d3256",
  tenant_id: "tenant-a",
  repository_id: "repo-a",
  observed_at: "2026-09-03T12:00:00Z",
  ready: true,
  configuration: {
    tenant_id: "tenant-a",
    repository_ids: ["repo-a"],
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

describe("API client", () => {
  it("accepts an exact scoped run envelope", () => {
    expect(
      parseRunEnvelope({
        contract: "open-trestle/api-response",
        schema_version: 1,
        request_id: "request-a",
        run,
      }),
    ).toEqual(run);
  });
  it("rejects unknown and cross-scoped response fields", () => {
    expect(() =>
      parseRunEnvelope({
        contract: "open-trestle/api-response",
        schema_version: 1,
        request_id: "request-a",
        run: { ...run, extra: true },
      }),
    ).toThrow(ApiError);
    expect(() =>
      parseRunEnvelope(
        {
          contract: "open-trestle/api-response",
          schema_version: 1,
          request_id: "request-a",
          run: { ...run, tenant_id: "tenant-b" },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow(ApiError);
  });
  it("accepts recorded failure reasons and context abstentions by receipt version", () => {
    const envelope = (value: unknown) => ({
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      run: value,
    });
    const failedSource = {
      ...run.tasks[0],
      status: "failed",
      attempts: 1,
      failure: "policy",
      failure_reason: "no_merge_base",
    };
    const reasoned = {
      ...run,
      schema_version: 3,
      status: "failed",
      failure: "policy",
      tasks: [failedSource],
    };
    expect(parseRunEnvelope(envelope(reasoned)).tasks[0]?.failure_reason).toBe(
      "no_merge_base",
    );
    const abstained = {
      ...run,
      schema_version: 2,
      status: "failed",
      failure: "policy",
      tasks: [
        {
          ...run.tasks[0],
          kind: "assemble_context",
          status: "failed",
          attempts: 1,
          output_identity: digest,
          output_kind: "context_abstention",
          failure: "policy",
        },
      ],
    };
    expect(parseRunEnvelope(envelope(abstained)).tasks[0]?.output_kind).toBe(
      "context_abstention",
    );
    for (const forged of [
      { ...reasoned, schema_version: 1 },
      { ...reasoned, schema_version: 2 },
      { ...abstained, schema_version: 3 },
      { ...reasoned, tasks: [{ ...failedSource, failure_reason: "other" }] },
      { ...reasoned, tasks: [{ ...failedSource, kind: "build_change" }] },
      { ...reasoned, tasks: [{ ...failedSource, status: "succeeded" }] },
      {
        ...reasoned,
        tasks: [{ ...failedSource, output_identity: digest }],
      },
      {
        ...abstained,
        tasks: [{ ...abstained.tasks[0], kind: "acquire_source" }],
      },
    ]) {
      expect(() => parseRunEnvelope(envelope(forged))).toThrow(ApiError);
    }
  });
  it("accepts a provider refusal reason only on a model task with its failure", () => {
    const envelope = (value: unknown) => ({
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      run: value,
    });
    const reasons = [
      ["provider_payment_required", "policy"],
      ["provider_model_unavailable", "policy"],
      ["provider_model_retired", "policy"],
      ["provider_authentication_failed", "policy"],
      ["provider_authorization_denied", "policy"],
      ["provider_rate_limited", "transient"],
      ["provider_response_invalid", "internal"],
      ["model_output_invalid", "internal"],
      ["provider_request_rejected", "policy"],
    ] as const;
    for (const [reason, failure] of reasons) {
      for (const kind of ["generate_candidates", "verify_candidates"]) {
        const refused = {
          ...run.tasks[0],
          kind,
          status: "failed",
          attempts: 1,
          failure,
          failure_reason: reason,
        };
        const receipt = {
          ...run,
          schema_version: 3,
          status: "failed",
          failure,
          tasks: [refused],
        };
        expect(
          parseRunEnvelope(envelope(receipt)).tasks[0]?.failure_reason,
        ).toBe(reason);
        for (const forged of [
          { ...refused, kind: "assemble_context" },
          { ...refused, kind: "acquire_source" },
          ...(["policy", "transient", "internal", "resource_limit"] as const)
            .filter((other) => other !== failure)
            .map((other) => ({ ...refused, failure: other })),
          { ...refused, status: "succeeded" },
          { ...refused, output_identity: digest },
          {
            ...refused,
            context_shortfall: {
              required_tokens: 14282,
              estimated_input_tokens: 10186,
              max_output_tokens: 4096,
              declared_context_tokens: 4097,
            },
          },
        ]) {
          expect(() =>
            parseRunEnvelope(envelope({ ...receipt, tasks: [forged] })),
          ).toThrow(ApiError);
        }
      }
    }
  });
  it("parses a scope-bound delivery refusal and rejects forgeries", () => {
    const key = "b".repeat(64);
    const scope = {
      tenant: "tenant-a",
      repository: "repo-a",
      run: `webhook-${key}`,
    };
    const refusal = {
      contract: "open-trestle/webhook-delivery-refusal",
      schema_version: 1,
      identity: digest,
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      source: "github",
      deduplication_key: key,
      delivery_identity: digest,
      planner_identity: digest,
      reason: "retries_exhausted",
      refused_at_milliseconds: 2000,
    };
    const envelope = (value: unknown) => ({
      contract: "open-trestle/delivery-refusal-response",
      schema_version: 1,
      request_id: "request-a",
      refusal: value,
    });
    expect(parseDeliveryRefusalEnvelope(envelope(refusal), scope).reason).toBe(
      "retries_exhausted",
    );
    for (const forged of [
      { ...refusal, reason: "Not A Token" },
      { ...refusal, tenant_id: "tenant-b" },
      { ...refusal, deduplication_key: "c".repeat(64) },
      { ...refusal, extra: true },
      { ...refusal, schema_version: 2 },
    ]) {
      expect(() =>
        parseDeliveryRefusalEnvelope(envelope(forged), scope),
      ).toThrow(ApiError);
    }
  });
  it("accepts a context route refusal with its counts only on context assembly", () => {
    const envelope = (value: unknown) => ({
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      run: value,
    });
    const shortfall = {
      required_tokens: 14282,
      estimated_input_tokens: 10186,
      max_output_tokens: 4096,
      declared_context_tokens: 4097,
    };
    const refusedContext = {
      ...run.tasks[0],
      kind: "assemble_context",
      status: "failed",
      attempts: 1,
      failure: "policy",
      failure_reason: "route_context_insufficient",
      context_shortfall: shortfall,
    };
    const refused = {
      ...run,
      schema_version: 3,
      status: "failed",
      failure: "policy",
      tasks: [refusedContext],
    };
    const parsed = parseRunEnvelope(envelope(refused)).tasks[0];
    expect(parsed?.failure_reason).toBe("route_context_insufficient");
    expect(parsed?.context_shortfall).toEqual(shortfall);
    const { context_shortfall: _counts, ...uncounted } = refusedContext;
    const noRoute = { ...uncounted, failure_reason: "no_eligible_route" };
    expect(
      parseRunEnvelope(envelope({ ...refused, tasks: [noRoute] })).tasks[0]
        ?.failure_reason,
    ).toBe("no_eligible_route");
    for (const forged of [
      { ...refusedContext, kind: "acquire_source" },
      { ...noRoute, kind: "acquire_source" },
      { ...refusedContext, failure_reason: "no_merge_base" },
      uncounted,
      { ...noRoute, context_shortfall: shortfall },
      { ...refusedContext, output_identity: digest },
      {
        ...refusedContext,
        context_shortfall: { ...shortfall, required_tokens: 14283 },
      },
      {
        ...refusedContext,
        context_shortfall: { ...shortfall, declared_context_tokens: 20000 },
      },
      {
        ...refusedContext,
        context_shortfall: { ...shortfall, estimated_input_tokens: 0 },
      },
      { ...refusedContext, context_shortfall: { ...shortfall, extra: 1 } },
    ]) {
      expect(() =>
        parseRunEnvelope(envelope({ ...refused, tasks: [forged] })),
      ).toThrow(ApiError);
    }
    expect(() =>
      parseRunEnvelope(envelope({ ...refused, schema_version: 2 })),
    ).toThrow(ApiError);
  });
  it("renders the daemon's fixed context shortfall hint", () => {
    expect(
      contextShortfallHint({
        required_tokens: 14282,
        estimated_input_tokens: 10186,
        max_output_tokens: 4096,
        declared_context_tokens: 4097,
      }),
    ).toBe(
      "the review needs up to 14282 tokens (a byte-based upper bound: 10186 input plus 4096 output) but the route declares max_context_tokens 4097; raise max_context_tokens on the route and the model server's context length to at least 14282 (docs/named-local-runtimes.md#context-length)",
    );
  });
  it("rejects duplicate durable task identities", () => {
    expect(() =>
      parseRunEnvelope({
        contract: "open-trestle/api-response",
        schema_version: 1,
        request_id: "request-a",
        run: { ...run, tasks: [run.tasks[0], run.tasks[0]] },
      }),
    ).toThrow(ApiError);
  });
  it("parses diagnostic v2 coverage and rejects impossible accounting", () => {
    const diagnostic = {
      identity: "b".repeat(64),
      source_identity: "c".repeat(64),
      fingerprint: "d".repeat(64),
      title: "Verified issue",
      message: "The independently verified issue remains.",
      severity: "warning",
      path: "internal/example.go",
      start_line: 4,
      end_line: 4,
      evidence_ids: ["evidence"],
    };
    const diagnostics = {
      contract: "open-trestle/review-diagnostic-set",
      schema_version: 2,
      identity: "f".repeat(64),
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
      snapshot_identity: "1".repeat(64),
      head_revision: "2".repeat(40),
      verified_set_identity: "3".repeat(64),
      coverage: {
        candidate_count: 3,
        verified_count: 1,
        rejected_count: 1,
        inconclusive_count: 1,
      },
      findings: [diagnostic],
    };
    const envelope = {
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      diagnostics,
    };
    expect(
      (
        parseDiagnosticEnvelope(envelope, {
          tenant: "tenant-a",
          repository: "repo-a",
          run: "run-a",
        }) as Extract<import("./types").DiagnosticSet, { schema_version: 2 }>
      ).coverage,
    ).toEqual(diagnostics.coverage);
    expect(() =>
      parseDiagnosticEnvelope(
        {
          ...envelope,
          diagnostics: {
            ...diagnostics,
            coverage: { ...diagnostics.coverage, rejected_count: 2 },
          },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow(ApiError);
  });

  it("parses diagnostic v3 source coverage and rejects impossible accounting", () => {
    const diagnostics = {
      contract: "open-trestle/review-diagnostic-set",
      schema_version: 3,
      identity: "f".repeat(64),
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
      snapshot_identity: "1".repeat(64),
      head_revision: "2".repeat(40),
      verified_set_identity: "3".repeat(64),
      coverage: {
        candidate_count: 1,
        verified_count: 0,
        rejected_count: 1,
        inconclusive_count: 0,
      },
      source_coverage: {
        verification_context_identity: "4".repeat(64),
        analyzed_count: 173,
        selected_count: 1,
        omitted_count: 172,
      },
      findings: [],
    };
    const envelope = {
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      diagnostics,
    };
    expect(
      (
        parseDiagnosticEnvelope(envelope, {
          tenant: "tenant-a",
          repository: "repo-a",
          run: "run-a",
        }) as Extract<
          import("./types").DiagnosticSet,
          { schema_version: 3 | 4 | 5 }
        >
      ).source_coverage,
    ).toEqual(diagnostics.source_coverage);
    expect(() =>
      parseDiagnosticEnvelope(
        {
          ...envelope,
          diagnostics: {
            ...diagnostics,
            source_coverage: {
              ...diagnostics.source_coverage,
              omitted_count: 171,
            },
          },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow(ApiError);
    expect(() =>
      parseDiagnosticEnvelope(
        {
          ...envelope,
          diagnostics: { ...diagnostics, schema_version: 2 },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow(ApiError);
    expect(() =>
      parseDiagnosticEnvelope(
        {
          ...envelope,
          diagnostics: {
            ...diagnostics,
            source_coverage: {
              verification_context_identity: "4".repeat(64),
              analyzed_count: 0,
              selected_count: 0,
              omitted_count: 0,
            },
          },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow(ApiError);
  });

  it("parses diagnostic v4 omission reasons and rejects noncanonical summaries", () => {
    const diagnostics = {
      contract: "open-trestle/review-diagnostic-set",
      schema_version: 4,
      identity: "f".repeat(64),
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
      snapshot_identity: "1".repeat(64),
      head_revision: "2".repeat(40),
      verified_set_identity: "3".repeat(64),
      coverage: {
        candidate_count: 0,
        verified_count: 0,
        rejected_count: 0,
        inconclusive_count: 0,
      },
      source_coverage: {
        verification_context_identity: "4".repeat(64),
        analyzed_count: 3,
        selected_count: 1,
        omitted_count: 2,
        omissions: [
          { reason: "authorization", count: 1 },
          { reason: "selection_limit", count: 1 },
        ],
      },
      findings: [],
    };
    const envelope = {
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      diagnostics,
    };
    expect(
      (
        parseDiagnosticEnvelope(envelope, {
          tenant: "tenant-a",
          repository: "repo-a",
          run: "run-a",
        }) as Extract<
          import("./types").DiagnosticSet,
          { schema_version: 3 | 4 | 5 }
        >
      ).source_coverage,
    ).toEqual(diagnostics.source_coverage);
    expect(() =>
      parseDiagnosticEnvelope(
        {
          ...envelope,
          diagnostics: {
            ...diagnostics,
            source_coverage: {
              ...diagnostics.source_coverage,
              omissions: [...diagnostics.source_coverage.omissions].reverse(),
            },
          },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow(ApiError);
  });

  it("parses diagnostic v5 deterministic checks and rejects impossible state", () => {
    const diagnostics = {
      contract: "open-trestle/review-diagnostic-set",
      schema_version: 5,
      identity: "f".repeat(64),
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
      snapshot_identity: "1".repeat(64),
      head_revision: "2".repeat(40),
      verified_set_identity: "3".repeat(64),
      coverage: {
        candidate_count: 0,
        verified_count: 0,
        rejected_count: 0,
        inconclusive_count: 0,
      },
      source_coverage: {
        verification_context_identity: "4".repeat(64),
        analyzed_count: 1,
        selected_count: 1,
        omitted_count: 0,
        omissions: [],
      },
      checks: [
        {
          identity: "5".repeat(64),
          source_check_identity: "6".repeat(64),
          analysis_result_identity: "7".repeat(64),
          change_identity: "8".repeat(64),
          key: "static_debug_output",
          rule_version: 1,
          state: "passed",
          applicable_files: 1,
          applicable_ranges: 2,
          checked_files: 1,
          checked_ranges: 2,
          matches: 0,
        },
      ],
      findings: [],
    };
    const envelope = {
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      diagnostics,
    };
    const parsed = parseDiagnosticEnvelope(envelope, {
      tenant: "tenant-a",
      repository: "repo-a",
      run: "run-a",
    });
    expect(parsed.schema_version).toBe(5);
    if (parsed.schema_version !== 5) throw new Error("expected v5");
    expect(parsed.checks).toEqual(diagnostics.checks);
    expect(() =>
      parseDiagnosticEnvelope(
        {
          ...envelope,
          diagnostics: {
            ...diagnostics,
            checks: [{ ...diagnostics.checks[0], matches: 1 }],
          },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow(ApiError);
  });

  it("parses diagnostic v8 base-side findings and refuses a side elsewhere", () => {
    const scope = { tenant: "tenant-a", repository: "repo-a", run: "run-a" };
    const finding = {
      identity: "a".repeat(64),
      source_identity: "b".repeat(64),
      fingerprint: "c".repeat(64),
      title: "Removed guard",
      message: "The zero check was removed.",
      severity: "error",
      path: "calc.go",
      start_line: 4,
      end_line: 6,
      side: "base",
      head_line: 3,
      evidence_ids: ["d".repeat(64)],
    };
    const diagnostics = {
      contract: "open-trestle/review-diagnostic-set",
      schema_version: 8,
      identity: "f".repeat(64),
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
      snapshot_identity: "1".repeat(64),
      head_revision: "2".repeat(40),
      verified_set_identity: "3".repeat(64),
      coverage: {
        candidate_count: 1,
        verified_count: 1,
        rejected_count: 0,
        inconclusive_count: 0,
      },
      source_coverage: {
        verification_context_identity: "4".repeat(64),
        analyzed_count: 1,
        selected_count: 1,
        omitted_count: 0,
        omissions: [],
      },
      checks: [
        {
          identity: "5".repeat(64),
          source_check_identity: "6".repeat(64),
          analysis_result_identity: "7".repeat(64),
          change_identity: "8".repeat(64),
          key: "static_debug_output",
          rule_version: 1,
          state: "passed",
          applicable_files: 1,
          applicable_ranges: 2,
          checked_files: 1,
          checked_ranges: 2,
          matches: 0,
        },
      ],
      findings: [finding],
    };
    const envelope = {
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      diagnostics,
    };
    const parsed = parseDiagnosticEnvelope(envelope, scope);
    expect(parsed.schema_version).toBe(8);
    if (parsed.schema_version !== 8) throw new Error("expected v8");
    expect(parsed.findings[0]?.side).toBe("base");
    expect(parsed.findings[0]?.head_line).toBe(3);
    const head = { ...finding } as Partial<typeof finding>;
    delete head.side;
    for (const forged of [
      { ...diagnostics, schema_version: 5 },
      { ...diagnostics, findings: [head] },
      { ...diagnostics, findings: [{ ...finding, side: "head" }] },
      { ...diagnostics, findings: [{ ...finding, head_line: 0 }] },
    ]) {
      expect(() =>
        parseDiagnosticEnvelope({ ...envelope, diagnostics: forged }, scope),
      ).toThrow(ApiError);
    }
  });

  it("uses a bounded, no-store, no-redirect authenticated request", async () => {
    const fetcher = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            contract: "open-trestle/api-response",
            schema_version: 1,
            request_id: "request-a",
            run,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    await fetchRun(
      { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      "x".repeat(32),
      fetcher,
    );
    const [url, init] = fetcher.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toBe("/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a");
    expect(init.redirect).toBe("error");
    expect(init.cache).toBe("no-store");
    expect((init.headers as Headers).get("Authorization")).toBe(
      `Bearer ${"x".repeat(32)}`,
    );
  });

  it("allows bounded API framing beyond a one MiB payload", async () => {
    const envelope = JSON.stringify({
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      run,
    });
    const framed = " ".repeat((1 << 20) + 128 - envelope.length) + envelope;
    const fetcher = vi.fn(
      async () =>
        new Response(framed, {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    const received = await fetchRun(
      { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      "x".repeat(32),
      fetcher,
    );
    expect(received).toEqual(run);
  });

  it("stops an unframed response once the byte limit is exceeded", async () => {
    const chunk = new Uint8Array(600_000);
    const fetcher = vi.fn(
      async () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(chunk);
              controller.enqueue(chunk);
              controller.close();
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    await expect(
      fetchRun(
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
        "x".repeat(32),
        fetcher,
      ),
    ).rejects.toThrow(ApiError);
  });
  it("rejects forged Runtime configuration and status identities", async () => {
    const envelope = {
      contract: "open-trestle/runtime-status-response",
      schema_version: 1,
      request_id: "request-forged",
      status: {
        ...runtimeStatus,
        identity: "b".repeat(64),
        configuration_identity: "c".repeat(64),
      },
    };
    await expect(
      parseRuntimeStatusEnvelope(envelope, {
        tenant: "tenant-a",
        repository: "repo-a",
      }),
    ).rejects.toThrow(ApiError);
  });

  it("accepts exact scoped runtime status and rejects cross-scope metadata", async () => {
    const envelope = {
      contract: "open-trestle/runtime-status-response",
      schema_version: 1,
      request_id: "request-a",
      status: runtimeStatus,
    };
    expect(
      await parseRuntimeStatusEnvelope(envelope, {
        tenant: "tenant-a",
        repository: "repo-a",
      }),
    ).toEqual({
      ...runtimeStatus,
      configuration: { ...runtimeStatus.configuration, handlers: [] },
    });
    await expect(
      parseRuntimeStatusEnvelope(
        {
          ...envelope,
          status: {
            ...runtimeStatus,
            configuration: {
              ...runtimeStatus.configuration,
              repository_ids: ["repo-a", "repo-b"],
            },
          },
        },
        { tenant: "tenant-a", repository: "repo-a" },
      ),
    ).rejects.toThrow(ApiError);
    await expect(
      parseRuntimeStatusEnvelope(
        { ...envelope, status: { ...runtimeStatus, ready: false } },
        { tenant: "tenant-a", repository: "repo-a" },
      ),
    ).rejects.toThrow(ApiError);
  });
  it("normalizes Go runtime status null handlers after strict validation", async () => {
    const status = {
      ...runtimeStatus,
      ready: true,
      configuration: {
        ...runtimeStatus.configuration,
        review_mode: "disabled",
        local_workers: false,
        handlers: null,
      },
      components: [],
    };
    const parsed = await parseRuntimeStatusEnvelope(
      {
        contract: "open-trestle/runtime-status-response",
        schema_version: 1,
        request_id: "request-disabled",
        status,
      },
      { tenant: "tenant-a", repository: "repo-a" },
    );
    expect(parsed.configuration.handlers).toEqual([]);
  });

  it("rejects every forged Runtime identity-bearing mutation and accepts object reordering", async () => {
    const configuration: RuntimeConfigurationWire = {
      tenant_id: "tenant-a",
      repository_ids: ["repo-a"],
      metadata_backend: "local",
      artifact_backend: "local",
      artifact_protection: "process_private",
      notification_backend: "process_local",
      rate_limit_backend: "process_local",
      review_mode: "advisory",
      webhook_ingress: true,
      local_workers: true,
      publication_enabled: false,
      publication_fence_verified: false,
      route_inventory_identity: "f".repeat(64),
      runtime_policy_identity: "1".repeat(64),
      route_count: 2,
      handlers: [
        { kind: "generate_candidates", identity: "2".repeat(64) },
        { kind: "verify_candidates", identity: "3".repeat(64) },
      ],
    };
    const components = [
      { name: "local_workers", state: "ready" as const },
      { name: "task_notifications", state: "ready" as const },
    ];
    const configuration_identity =
      await runtimeConfigurationIdentity(configuration);
    const signed = {
      contract: "open-trestle/runtime-status",
      schema_version: 1,
      identity: await runtimeStatusIdentity({
        configuration_identity,
        tenant_id: "tenant-a",
        repository_id: "repo-a",
        observed_at: "2026-10-03T12:00:01Z",
        ready: true,
        configuration,
        components,
      }),
      configuration_identity,
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      observed_at: "2026-10-03T12:00:01Z",
      ready: true,
      configuration,
      components,
    };
    const parse = (
      status: unknown,
      scope = { tenant: "tenant-a", repository: "repo-a" },
    ) =>
      parseRuntimeStatusEnvelope(
        {
          contract: "open-trestle/runtime-status-response",
          schema_version: 1,
          request_id: "hostile",
          status,
        },
        scope,
      );
    const mutations = [
      (value: any) => (value.identity = "4".repeat(64)),
      (value: any) => (value.configuration_identity = "5".repeat(64)),
      (value: any) =>
        (value.configuration.route_inventory_identity = "8".repeat(64)),
      (value: any) =>
        (value.configuration.runtime_policy_identity = "9".repeat(64)),
      (value: any) =>
        (value.configuration.handlers[0].identity = "a".repeat(64)),
      (value: any) => value.configuration.handlers.reverse(),
      (value: any) => value.components.reverse(),
      (value: any) => (value.components[0].state = "starting"),
      (value: any) => (value.observed_at = "2026-10-03T12:00:02Z"),
      (value: any) => (value.ready = false),
    ];
    for (const mutate of mutations) {
      const value = structuredClone(signed);
      mutate(value);
      await expect(parse(value)).rejects.toThrow(ApiError);
    }
    await expect(
      parse(signed, { tenant: "tenant-b", repository: "repo-a" }),
    ).rejects.toThrow(ApiError);
    const reordered = {
      components: signed.components.map((component) => ({
        state: component.state,
        name: component.name,
      })),
      configuration: {
        handlers: signed.configuration.handlers?.map((handler) => ({
          identity: handler.identity,
          kind: handler.kind,
        })),
        route_count: signed.configuration.route_count,
        runtime_policy_identity: signed.configuration.runtime_policy_identity,
        route_inventory_identity: signed.configuration.route_inventory_identity,
        publication_fence_verified:
          signed.configuration.publication_fence_verified,
        publication_enabled: signed.configuration.publication_enabled,
        local_workers: signed.configuration.local_workers,
        webhook_ingress: signed.configuration.webhook_ingress,
        review_mode: signed.configuration.review_mode,
        rate_limit_backend: signed.configuration.rate_limit_backend,
        notification_backend: signed.configuration.notification_backend,
        artifact_protection: signed.configuration.artifact_protection,
        artifact_backend: signed.configuration.artifact_backend,
        metadata_backend: signed.configuration.metadata_backend,
        repository_ids: signed.configuration.repository_ids,
        tenant_id: signed.configuration.tenant_id,
      },
      ready: signed.ready,
      observed_at: signed.observed_at,
      repository_id: signed.repository_id,
      tenant_id: signed.tenant_id,
      configuration_identity: signed.configuration_identity,
      identity: signed.identity,
      schema_version: signed.schema_version,
      contract: signed.contract,
    };
    expect(await parse(reordered)).toMatchObject({
      identity: signed.identity,
      configuration_identity,
    });
  });

  it("rejects impossible runtime state and normalized calendar dates", async () => {
    const envelope = (status: unknown) => ({
      contract: "open-trestle/runtime-status-response",
      schema_version: 1,
      request_id: "request-a",
      status,
    });
    const configurations = [
      {
        ...runtimeStatus.configuration,
        handlers: [{ kind: "acquire_source", identity: "d".repeat(64) }],
      },
      {
        ...runtimeStatus.configuration,
        review_mode: "advisory",
        local_workers: true,
      },
      {
        ...runtimeStatus.configuration,
        review_mode: "advisory",
        handlers: [
          { kind: "acquire_source", identity: "d".repeat(64) },
          { kind: "acquire_source", identity: "e".repeat(64) },
        ],
      },
    ];
    for (const configuration of configurations)
      await expect(
        parseRuntimeStatusEnvelope(
          envelope({ ...runtimeStatus, configuration }),
          { tenant: "tenant-a", repository: "repo-a" },
        ),
      ).rejects.toThrow(ApiError);
    await expect(
      parseRuntimeStatusEnvelope(
        envelope({ ...runtimeStatus, observed_at: "2026-02-30T12:00:00Z" }),
        { tenant: "tenant-a", repository: "repo-a" },
      ),
    ).rejects.toThrow(ApiError);
  });

  it("fetches runtime status through the repository endpoint", async () => {
    const fetcher = vi.fn(
      async (_input: string, _init: RequestInit) =>
        new Response(
          JSON.stringify({
            contract: "open-trestle/runtime-status-response",
            schema_version: 1,
            request_id: "request-a",
            status: runtimeStatus,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    await fetchRuntimeStatus(
      { tenant: "tenant-a", repository: "repo-a" },
      "x".repeat(32),
      fetcher,
    );
    expect(fetcher.mock.calls[0]?.[0]).toBe(
      "/api/v1/tenants/tenant-a/repositories/repo-a/runtime",
    );
  });

  it("rejects duplicate response keys and malformed JSON media types", async () => {
    const duplicate = `{"contract":"open-trestle/api-response","contract":"open-trestle/api-response","schema_version":1,"request_id":"request-a","run":${JSON.stringify(run)}}`;
    const duplicateFetcher = vi.fn(
      async () =>
        new Response(duplicate, {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    await expect(
      fetchRun(
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
        "x".repeat(32),
        duplicateFetcher,
      ),
    ).rejects.toThrow(ApiError);
    const mediaFetcher = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            contract: "open-trestle/api-response",
            schema_version: 1,
            request_id: "request-a",
            run,
          }),
          {
            status: 200,
            headers: { "content-type": "application/json-whatever" },
          },
        ),
    );
    await expect(
      fetchRun(
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
        "x".repeat(32),
        mediaFetcher,
      ),
    ).rejects.toThrow(ApiError);
  });

  it("rejects escaped and nested duplicate response members", async () => {
    const scope = { tenant: "tenant-a", repository: "repo-a", run: "run-a" };
    const escaped = String.raw`{"contract":"open-trestle/api-response","schema_version":1,"schema_version":1,"request_id":"request-a","run":${JSON.stringify(run)}}`;
    const fetcher = vi.fn(
      async () =>
        new Response(escaped, {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    await expect(fetchRun(scope, "x".repeat(32), fetcher)).rejects.toThrow(
      ApiError,
    );
    const nested = `{"contract":"open-trestle/api-response","schema_version":1,"request_id":"request-a","run":{"x":1,"x":1}}`;
    const nestedFetcher = vi.fn(
      async () =>
        new Response(nested, {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    await expect(
      fetchRun(scope, "x".repeat(32), nestedFetcher),
    ).rejects.toThrow(ApiError);
  });

  it("parses deterministic diagnostics without promoting observations to verified findings", () => {
    const digest = (value: string) => value.repeat(64);
    const check = {
      identity: digest("a"),
      source_check_identity: digest("b"),
      analysis_result_identity: digest("c"),
      change_identity: digest("d"),
      key: "static_debug_output",
      rule_version: 1,
      state: "failed",
      applicable_files: 1,
      applicable_ranges: 1,
      checked_files: 1,
      checked_ranges: 1,
      matches: 1,
    };
    const observation = {
      identity: digest("e"),
      source_identity: digest("f"),
      fingerprint: digest("1"),
      analysis_result_identity: digest("c"),
      check_identity: digest("a"),
      title: "Debug output left in source",
      message: "Deterministic observation; human review required.",
      severity: "warning",
      path: "main.go",
      start_line: 3,
      end_line: 3,
      evidence_ids: [digest("2")],
    };
    const envelope = {
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-v6",
      diagnostics: {
        contract: "open-trestle/review-diagnostic-set",
        schema_version: 6,
        identity: digest("3"),
        tenant_id: "tenant-a",
        repository_id: "repo-a",
        review_run_id: "run-a",
        snapshot_identity: digest("4"),
        head_revision: "5".repeat(40),
        analysis_result_identity: digest("c"),
        checks: [check],
        observations: [observation],
      },
    };
    const parsed = parseDiagnosticEnvelope(envelope, {
      tenant: "tenant-a",
      repository: "repo-a",
      run: "run-a",
    });
    expect(parsed.schema_version).toBe(6);
    if (parsed.schema_version !== 6) throw new Error("unexpected schema");
    expect(parsed.observations).toEqual([observation]);
    expect("findings" in parsed).toBe(false);
    for (const patch of [
      { analysis_result_identity: "" },
      { check_identity: "0".repeat(64) },
      { extra: "not admitted" },
      { title: "" },
      { evidence_ids: [digest("2"), digest("2")] },
    ]) {
      expect(() =>
        parseDiagnosticEnvelope(
          {
            ...envelope,
            diagnostics: {
              ...envelope.diagnostics,
              observations: [{ ...observation, ...patch }],
            },
          },
          { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
        ),
      ).toThrow(ApiError);
    }
    expect(() =>
      parseDiagnosticEnvelope(
        {
          ...envelope,
          diagnostics: {
            ...envelope.diagnostics,
            verified_set_identity: digest("6"),
          },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow();
    expect(() =>
      parseDiagnosticEnvelope(
        {
          ...envelope,
          diagnostics: {
            ...envelope.diagnostics,
            observations: [{ ...observation, check_identity: digest("9") }],
          },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow();
  });

  it("parses nested V7 evidence and refuses incomplete or mismatched terminal parts", () => {
    const hex = (char: string) => char.repeat(64);
    const scope = { tenant: "tenant-a", repository: "repo-a", run: "run-a" };
    const root = {
      contract: "open-trestle/review-diagnostic-set",
      schema_version: 7,
      identity: hex("1"),
      tenant_id: scope.tenant,
      repository_id: scope.repository,
      review_run_id: scope.run,
      snapshot_identity: hex("2"),
      head_revision: "3".repeat(40),
      outcome: "completed",
    };
    const { outcome: _outcome, ...partCommon } = root;
    const check = {
      identity: hex("4"),
      source_check_identity: hex("5"),
      analysis_result_identity: hex("6"),
      change_identity: hex("7"),
      key: "static_debug_output",
      rule_version: 1,
      state: "failed",
      applicable_files: 1,
      applicable_ranges: 1,
      checked_files: 1,
      checked_ranges: 1,
      matches: 1,
    };
    const deterministic = {
      ...partCommon,
      schema_version: 6,
      identity: hex("8"),
      analysis_result_identity: hex("6"),
      checks: [check],
      observations: [
        {
          identity: hex("9"),
          source_identity: hex("a"),
          fingerprint: hex("b"),
          analysis_result_identity: hex("6"),
          check_identity: hex("4"),
          title: "Exact source match",
          message: "Human review required.",
          severity: "warning",
          path: "main.go",
          start_line: 1,
          end_line: 1,
          evidence_ids: [hex("c")],
        },
      ],
    };
    const verified = {
      ...partCommon,
      schema_version: 5,
      identity: hex("d"),
      verified_set_identity: hex("e"),
      coverage: {
        candidate_count: 1,
        verified_count: 1,
        rejected_count: 0,
        inconclusive_count: 0,
      },
      source_coverage: {
        verification_context_identity: hex("f"),
        analyzed_count: 1,
        selected_count: 1,
        omitted_count: 0,
        omissions: [],
      },
      checks: [check],
      findings: [
        {
          identity: hex("a"),
          source_identity: hex("b"),
          fingerprint: hex("c"),
          title: "Verified issue",
          message: "Independent route.",
          severity: "error",
          path: "main.go",
          start_line: 2,
          end_line: 2,
          evidence_ids: [hex("d")],
        },
      ],
    };
    const envelope = (diagnostics: unknown) => ({
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-v7",
      diagnostics,
    });
    const parsed = parseDiagnosticEnvelope(
      envelope({ ...root, deterministic, verified }),
      scope,
    );
    expect(parsed.schema_version).toBe(7);
    if (parsed.schema_version !== 7) throw new Error("unexpected schema");
    expect(parsed.deterministic?.observations).toHaveLength(1);
    expect(parsed.verified?.findings).toHaveLength(1);
    const selectedSnapshot = hex("f");
    const withDistinctV5Snapshot = parseDiagnosticEnvelope(
      envelope({
        ...root,
        deterministic,
        verified: {
          ...verified,
          snapshot_identity: selectedSnapshot,
        },
      }),
      scope,
    );
    expect(withDistinctV5Snapshot.schema_version).toBe(7);
    if (withDistinctV5Snapshot.schema_version === 7)
      expect(withDistinctV5Snapshot.verified?.snapshot_identity).toBe(
        selectedSnapshot,
      );
    for (const outcome of ["failed", "canceled", "abstained", "inconclusive"]) {
      const early = parseDiagnosticEnvelope(
        envelope({
          ...root,
          outcome,
          snapshot_identity: "",
          head_revision: "",
        }),
        scope,
      );
      expect(early.schema_version).toBe(7);
      if (early.schema_version === 7) expect(early.verified).toBeUndefined();
    }
    for (const bad of [
      { ...root },
      { ...root, deterministic },
      { ...root, verified },
      {
        ...root,
        deterministic,
        verified: { ...verified, checks: [{ ...check, identity: hex("a") }] },
      },
      {
        ...root,
        deterministic: { ...deterministic, snapshot_identity: hex("f") },
        verified,
      },
      {
        ...root,
        deterministic,
        verified: { ...verified, head_revision: "f".repeat(40) },
      },
      {
        ...root,
        deterministic,
        verified: { ...verified, snapshot_identity: "" },
      },
      {
        ...root,
        deterministic: {
          ...deterministic,
          observations: [
            { ...deterministic.observations[0], check_identity: hex("a") },
          ],
        },
        verified,
      },
      { ...root, deterministic, verified, unexpected: "field" },
    ])
      expect(() => parseDiagnosticEnvelope(envelope(bad), scope)).toThrow(
        ApiError,
      );
    const shortfall = {
      required_tokens: 14282,
      estimated_input_tokens: 10186,
      max_output_tokens: 4096,
      declared_context_tokens: 4097,
    };
    const counted = {
      reason: "route_context_insufficient",
      context_shortfall: shortfall,
    };
    const failed = { ...root, outcome: "failed", deterministic };
    for (const refusal of [counted, { reason: "no_eligible_route" }]) {
      const refused = parseDiagnosticEnvelope(
        envelope({ ...failed, context_refusal: refusal }),
        scope,
      );
      if (refused.schema_version !== 7) throw new Error("unexpected schema");
      expect(refused.context_refusal).toEqual(refusal);
    }
    for (const bad of [
      { ...failed, outcome: "canceled", context_refusal: counted },
      { ...failed, verified, context_refusal: counted },
      { ...failed, context_refusal: { reason: "route_context_insufficient" } },
      {
        ...failed,
        context_refusal: {
          reason: "no_eligible_route",
          context_shortfall: shortfall,
        },
      },
      { ...failed, context_refusal: { reason: "no_merge_base" } },
      {
        ...failed,
        context_refusal: {
          ...counted,
          context_shortfall: { ...shortfall, required_tokens: 1 },
        },
      },
      { ...failed, context_refusal: { ...counted, extra: true } },
    ])
      expect(() => parseDiagnosticEnvelope(envelope(bad), scope)).toThrow(
        ApiError,
      );
    const bare = {
      ...root,
      outcome: "inconclusive",
      snapshot_identity: "",
      head_revision: "",
    };
    const expired = parseDiagnosticEnvelope(
      envelope({ ...bare, evidence_expired: true }),
      scope,
    );
    if (expired.schema_version !== 7) throw new Error("unexpected schema");
    expect(expired.evidence_expired).toBe(true);
    const expiredRefusal = parseDiagnosticEnvelope(
      envelope({
        ...bare,
        outcome: "failed",
        context_refusal: counted,
        evidence_expired: true,
      }),
      scope,
    );
    if (expiredRefusal.schema_version !== 7)
      throw new Error("unexpected schema");
    expect(expiredRefusal.context_refusal).toEqual(counted);
    for (const bad of [
      { ...bare, evidence_expired: false },
      { ...bare, outcome: "completed", evidence_expired: true },
      { ...root, outcome: "failed", deterministic, evidence_expired: true },
      { ...root, outcome: "failed", evidence_expired: true },
    ])
      expect(() => parseDiagnosticEnvelope(envelope(bad), scope)).toThrow(
        ApiError,
      );
  });
});
