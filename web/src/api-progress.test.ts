import { describe, expect, it, vi } from "vitest";
import { ApiError, fetchRunProgress, parseRunProgressEnvelope } from "./api";
import type { RunReceipt, TaskKind } from "./types";

const scope = { tenant: "tenant-a", repository: "repo-a", run: "run-a" };
const identity = "a".repeat(64);
const kinds: TaskKind[] = [
  "build_change",
  "inspect_deterministic",
  "assemble_context",
  "verify_candidates",
];
const run: RunReceipt = {
  contract: "open-trestle/review-run-receipt",
  schema_version: 1,
  identity,
  plan_identity: identity,
  tenant_id: scope.tenant,
  repository_id: scope.repository,
  review_run_id: scope.run,
  status: "active",
  revision: 4,
  head_identity: identity,
  last_occurred_at_milliseconds: 1000,
  output_identity: "",
  failure: "",
  tasks: kinds.map((kind, index) => ({
    key: kind,
    task_identity: String(index + 1).repeat(64),
    input_identity: identity,
    handler_identity: identity,
    kind,
    required: true,
    status: "succeeded",
    attempts: 1,
    max_attempts: 1,
    lease_expires_at_milliseconds: 0,
    output_identity: identity,
    failure: "",
    retry_at_milliseconds: 0,
  })),
};
function envelope() {
  return {
    contract: "open-trestle/run-progress-response",
    schema_version: 1,
    request_id: "request-a",
    run: structuredClone(run),
    progress: {
      change: {
        state: "available",
        artifact_identity: identity,
        files: 3,
        ranges: 4,
      },
      deterministic: {
        state: "partial",
        artifact_identity: identity,
        applicable_files: 2,
        applicable_ranges: 3,
        checked_files: 1,
        checked_ranges: 2,
        observations: 0,
      },
      context: {
        state: "available",
        artifact_identity: "b".repeat(64),
        analyzed: 5,
        selected: 2,
        omitted: 3,
      },
      verification: {
        state: "available",
        artifact_identity: identity,
        candidates: 4,
        verified: 1,
        rejected: 2,
        inconclusive: 1,
      },
    },
  };
}
describe("run progress", () => {
  it("keeps four independent axes, proven zero and omitted counts distinct", () => {
    const parsed = parseRunProgressEnvelope(envelope(), scope, run);
    expect(parsed.progress.change.files).toBe(3);
    expect(parsed.progress.deterministic.observations).toBe(0);
    expect(parsed.progress.context.omitted).toBe(3);
    expect(parsed.progress.verification.verified).toBe(1);
    const value = envelope();
    Reflect.deleteProperty(value.progress.deterministic, "observations");
    expect(
      parseRunProgressEnvelope(value, scope, run).progress.deterministic
        .observations,
    ).toBeUndefined();
  });
  it.each([
    "identity",
    "head_identity",
    "plan_identity",
    "tenant_id",
    "repository_id",
    "review_run_id",
    "revision",
  ] as const)("rejects stale or foreign receipt %s", (field) => {
    const value = envelope();
    Object.assign(value.run, {
      [field]: field === "revision" ? 5 : "b".repeat(64),
    });
    expect(() => parseRunProgressEnvelope(value, scope, run)).toThrow(ApiError);
  });
  it("rejects invalid counts, unknown fields and unsupported task outputs", () => {
    const changes: ((value: ReturnType<typeof envelope>) => void)[] = [
      (value) => {
        value.progress.change.files = -1;
      },
      (value) => {
        value.progress.change.files = 1.5;
      },
      (value) => {
        value.progress.verification.verified = 4;
      },
      (value) => {
        value.progress.context.omitted = 0;
      },
      (value) => {
        value.progress.deterministic.checked_ranges = 9;
      },
      (value) => {
        Reflect.deleteProperty(value.progress.deterministic, "checked_files");
      },
      (value) => {
        Reflect.deleteProperty(value.progress.change, "files");
      },
      (value) => {
        Object.assign(value.progress.change, { extra: 1 });
      },
      (value) => {
        value.progress.change.state = "unavailable";
      },
      (value) => {
        value.progress.change.artifact_identity = "c".repeat(64);
      },
      (value) => {
        value.run.tasks[0]!.status = "leased";
      },
    ];
    for (const change of changes) {
      const value = envelope();
      change(value);
      expect(() => parseRunProgressEnvelope(value, scope, run)).toThrow(
        ApiError,
      );
    }
  });
  it("rejects out-of-contract axis states, missing partial coverage and count bounds", () => {
    const changes: ((value: ReturnType<typeof envelope>) => void)[] = [
      ...(["change", "context", "verification"] as const).map(
        (name) => (value: ReturnType<typeof envelope>) => {
          value.progress[name].state = "partial";
        },
      ),
      (value) => {
        for (const key of [
          "applicable_files",
          "applicable_ranges",
          "checked_files",
          "checked_ranges",
        ])
          Reflect.deleteProperty(value.progress.deterministic, key);
      },
      (value) => {
        value.progress.change.ranges = 1_000_001;
      },
      (value) => {
        Object.assign(value.progress.context, {
          analyzed: 65665,
          selected: 32,
          omitted: 65633,
        });
      },
      (value) => {
        Object.assign(value.progress.context, {
          analyzed: 33,
          selected: 33,
          omitted: 0,
        });
      },
      (value) => {
        Object.assign(value.progress.verification, {
          candidates: 17,
          verified: 17,
          rejected: 0,
          inconclusive: 0,
        });
      },
    ];
    for (const change of changes) {
      const value = envelope();
      change(value);
      expect(() => parseRunProgressEnvelope(value, scope, run)).toThrow(
        ApiError,
      );
    }
  });
  it("accepts deterministic partial zero checks and exact upper count bounds", () => {
    const value = envelope();
    Object.assign(value.progress.deterministic, {
      checked_files: 0,
      checked_ranges: 0,
      observations: 0,
    });
    Object.assign(value.progress.change, { ranges: 1_000_000 });
    Object.assign(value.progress.context, {
      analyzed: 65664,
      selected: 32,
      omitted: 65632,
    });
    Object.assign(value.progress.verification, {
      candidates: 16,
      verified: 0,
      rejected: 16,
      inconclusive: 0,
    });
    const parsed = parseRunProgressEnvelope(value, scope, run).progress;
    expect(parsed.deterministic.state).toBe("partial");
    expect(parsed.deterministic.checked_ranges).toBe(0);
    expect(parsed.verification.verified).toBe(0);
  });
  it("preserves unavailable counts as absent and accepts not-run axes", () => {
    const value = envelope();
    Object.assign(value.progress, {
      change: { state: "unavailable", artifact_identity: identity },
    });
    expect(
      parseRunProgressEnvelope(value, scope, run).progress.change.files,
    ).toBeUndefined();
    value.run.tasks[0]!.status = "pending";
    Object.assign(value.progress, { change: { state: "not_run" } });
    expect(
      parseRunProgressEnvelope(value, scope, value.run).progress.change.state,
    ).toBe("not_run");
  });
  it("rejects altered task or receipt contents even with copied receipt identities", () => {
    const value = envelope();
    value.run.tasks[0]!.output_identity = "d".repeat(64);
    value.progress.change.artifact_identity = "d".repeat(64);
    expect(() => parseRunProgressEnvelope(value, scope, run)).toThrow(ApiError);
    const changedStatus = envelope();
    changedStatus.run.status = "failed";
    expect(() => parseRunProgressEnvelope(changedStatus, scope, run)).toThrow(
      ApiError,
    );
  });
  it("preserves the run-advanced error without accepting a success-shaped error", () => {
    const value = {
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      error: { code: "progress_changed", message: "Run advanced" },
    };
    expect(() => parseRunProgressEnvelope(value, scope, run)).toThrowError(
      expect.objectContaining({ code: "progress_changed" }),
    );
    expect(() =>
      parseRunProgressEnvelope(
        { ...envelope(), error: value.error },
        scope,
        run,
      ),
    ).toThrowError(expect.objectContaining({ code: "invalid_response" }));
  });
  it("uses bounded read-only no-store requests and forwards disconnect abort", async () => {
    const controller = new AbortController();
    let signal: AbortSignal | undefined;
    const fetcher = vi.fn(async (_path: string, init: RequestInit) => {
      signal = init.signal as AbortSignal;
      controller.abort();
      expect(signal.aborted).toBe(true);
      throw new Error("aborted");
    });
    await expect(
      fetchRunProgress(scope, "x".repeat(32), run, fetcher, controller.signal),
    ).rejects.toBeInstanceOf(ApiError);
    expect(fetcher).toHaveBeenCalledWith(
      "/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/progress",
      expect.objectContaining({
        method: "GET",
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
      }),
    );
    const response = () =>
      new Response(JSON.stringify(envelope()), {
        headers: { "content-type": "application/json" },
      });
    expect(
      (
        await fetchRunProgress(scope, "x".repeat(32), run, async () =>
          response(),
        )
      ).progress.change.files,
    ).toBe(3);
    await expect(
      fetchRunProgress(
        scope,
        "x".repeat(32),
        run,
        async () =>
          new Response("{}", {
            headers: {
              "content-type": "application/json",
              "content-length": "2000000",
            },
          }),
      ),
    ).rejects.toBeInstanceOf(ApiError);
  });
});
