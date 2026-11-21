import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import {
  ApiError,
  fetchDeliveryRefusal,
  fetchDiagnostics,
  fetchRun,
  fetchRunProgress,
  fetchRuntimeStatus,
} from "./api";
import type { DiagnosticSet, RunReceipt } from "./types";
vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return {
    ...actual,
    fetchRun: vi.fn(),
    fetchDeliveryRefusal: vi.fn(),
    fetchRunProgress: vi.fn(),
    fetchDiagnostics: vi.fn(),
    fetchRuntimeStatus: vi.fn(),
  };
});
const digest = "a".repeat(64);
const receipt = {
  contract: "open-trestle/review-run-receipt" as const,
  schema_version: 1 as const,
  identity: digest,
  plan_identity: digest,
  tenant_id: "tenant-a",
  repository_id: "repo-a",
  review_run_id: "run-a",
  status: "active" as const,
  revision: 4,
  head_identity: digest,
  last_occurred_at_milliseconds: 1000,
  output_identity: "",
  failure: "" as const,
  tasks: [
    {
      key: "source",
      task_identity: digest,
      input_identity: digest,
      handler_identity: digest,
      kind: "acquire_source" as const,
      required: true,
      status: "succeeded" as const,
      attempts: 1,
      max_attempts: 1,
      lease_expires_at_milliseconds: 0,
      output_identity: digest,
      failure: "" as const,
      retry_at_milliseconds: 0,
    },
  ],
};

const runtimeStatus = {
  contract: "open-trestle/runtime-status" as const,
  schema_version: 1 as const,
  identity: "b".repeat(64),
  configuration_identity: "c".repeat(64),
  tenant_id: "tenant-a",
  repository_id: "repo-a",
  observed_at: "2026-09-03T12:00:00Z",
  ready: true,
  configuration: {
    tenant_id: "tenant-a",
    repository_ids: ["repo-a"],
    metadata_backend: "local" as const,
    artifact_backend: "local" as const,
    artifact_protection: "process_private" as const,
    notification_backend: "process_local" as const,
    rate_limit_backend: "process_local" as const,
    review_mode: "advisory" as const,
    webhook_ingress: true,
    local_workers: false,
    publication_enabled: false,
    publication_fence_verified: false,
    route_count: 0,
    handlers: [],
  },
  components: [{ name: "task_notifications", state: "ready" as const }],
};

describe("console", () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.mocked(fetchRun).mockReset();
    vi.mocked(fetchRunProgress).mockReset();
    vi.mocked(fetchRunProgress).mockRejectedValue(new Error("not available"));
    vi.mocked(fetchDiagnostics).mockReset();
    vi.mocked(fetchRuntimeStatus).mockReset();
    window.history.replaceState({}, "", "/console/");
    vi.mocked(fetchRuntimeStatus).mockRejectedValue(
      new Error("not authorized"),
    );
  });
  it("refreshes artifact counts without replacing diagnostics or treating unknown as zero", async () => {
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    vi.mocked(fetchDiagnostics).mockRejectedValue(new Error("not ready"));
    vi.mocked(fetchRunProgress)
      .mockResolvedValueOnce({
        run: receipt,
        progress: {
          change: { state: "available", files: 3, ranges: 8 },
          deterministic: {
            state: "partial",
            applicable_files: 2,
            applicable_ranges: 4,
            checked_files: 1,
            checked_ranges: 2,
            observations: 0,
          },
          context: { state: "not_run" },
          verification: { state: "unavailable" },
        },
      })
      .mockRejectedValueOnce(new ApiError("progress_changed"));
    render(<App />);
    for (const [name, value] of [
      ["Tenant", "tenant-a"],
      ["Repository", "repo-a"],
      ["Run", "run-a"],
      ["Access token", "x".repeat(32)],
    ])
      fireEvent.change(screen.getByLabelText(name!), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await screen.findByText("Changed files: 3");
    expect(screen.getByText("Changed ranges: 8")).toBeInTheDocument();
    expect(screen.getByText("Checked ranges: 2")).toBeInTheDocument();
    expect(screen.getByText("Observations: 0")).toBeInTheDocument();
    expect(screen.getByText("Selected sources: Unknown")).toBeInTheDocument();
    expect(screen.getByText("Verified: Unknown")).toBeInTheDocument();
    expect(screen.getByText(/These counts do not approve/)).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Refresh" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByText(/run advanced while progress was read/i);
    expect(screen.queryByText("Changed files: 3")).not.toBeInTheDocument();
    expect(screen.getByText("Changed files: Unknown")).toBeInTheDocument();
    expect(fetchRunProgress).toHaveBeenCalledTimes(2);
    expect(fetchDiagnostics).toHaveBeenCalledTimes(2);
  });
  const twoTaskReceipt: RunReceipt = {
    ...receipt,
    tasks: [
      receipt.tasks[0]!,
      {
        ...receipt.tasks[0]!,
        key: "change",
        kind: "build_change",
        task_identity: "2".repeat(64),
      },
    ],
  };
  async function connectTwoTaskRun() {
    vi.mocked(fetchDiagnostics).mockRejectedValue(new Error("not ready"));
    vi.mocked(fetchRunProgress).mockRejectedValue(new Error("not ready"));
    render(<App />);
    for (const [name, value] of [
      ["Tenant", "tenant-a"],
      ["Repository", "repo-a"],
      ["Run", "run-a"],
      ["Access token", "x".repeat(32)],
    ])
      fireEvent.change(screen.getByLabelText(name!), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Refresh" })).toBeEnabled(),
    );
  }
  it("moves focus into the task view after a focused overview task is activated", async () => {
    vi.mocked(fetchRun).mockResolvedValue(twoTaskReceipt);
    await connectTwoTaskRun();
    const overviewTask = screen.getByRole("button", { name: /^change/ });
    overviewTask.focus();
    expect(overviewTask).toHaveFocus();
    fireEvent.click(overviewTask);
    const selectedTask = await screen.findByRole("button", { name: /^change/ });
    expect(selectedTask).toHaveFocus();
    expect(
      within(
        screen.getByRole("complementary", { name: "Task evidence inspector" }),
      ).getByRole("heading", { name: "change" }),
    ).toBeInTheDocument();
  });
  it("keeps the session and selection when a refresh fails transiently", async () => {
    vi.mocked(fetchRun)
      .mockResolvedValueOnce(twoTaskReceipt)
      .mockRejectedValueOnce(new ApiError("unavailable"));
    await connectTwoTaskRun();
    fireEvent.click(screen.getByRole("button", { name: /^change/ }));
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Refresh failed");
    expect(alert).toHaveTextContent(
      "Showing the last verified journal revision",
    );
    expect(screen.getByRole("button", { name: "Refresh" })).toBeEnabled();
    expect(
      within(
        screen.getByRole("complementary", { name: "Task evidence inspector" }),
      ).getByRole("heading", { name: "change" }),
    ).toBeInTheDocument();
  });
  it("keeps the access token after a timed-out refresh", async () => {
    vi.mocked(fetchRun)
      .mockResolvedValueOnce(twoTaskReceipt)
      .mockRejectedValueOnce(new ApiError("timeout"))
      .mockResolvedValueOnce(twoTaskReceipt);
    await connectTwoTaskRun();
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByRole("alert");
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(fetchRun).toHaveBeenCalledTimes(3));
    const expectedScope = {
      tenant: "tenant-a",
      repository: "repo-a",
      run: "run-a",
    };
    expect(fetchRun).toHaveBeenNthCalledWith(
      2,
      expectedScope,
      "x".repeat(32),
      undefined,
      expect.any(AbortSignal),
    );
    expect(fetchRun).toHaveBeenNthCalledWith(
      3,
      expectedScope,
      "x".repeat(32),
      undefined,
      expect.any(AbortSignal),
    );
    expect(
      screen.getByRole("heading", { name: "Execution in progress" }),
    ).toBeInTheDocument();
  });
  it("ends the session when a refresh is no longer authenticated", async () => {
    vi.mocked(fetchRun)
      .mockResolvedValueOnce(twoTaskReceipt)
      .mockRejectedValueOnce(new ApiError("unauthenticated"));
    await connectTwoTaskRun();
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByRole("heading", { name: "Locate a review run" });
    expect(screen.getByRole("alert")).toHaveTextContent(
      "The access token was not accepted",
    );
  });
  it("aborts and ignores a late progress response after changing scope", async () => {
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    let finish!: (value: import("./types").RunProgress) => void;
    let signal: AbortSignal | undefined;
    vi.mocked(fetchRunProgress).mockImplementation(
      (_scope, _token, _receipt, _fetcher, requestSignal) => {
        signal = requestSignal;
        return new Promise((resolve) => {
          finish = resolve;
        });
      },
    );
    render(<App />);
    for (const [name, value] of [
      ["Tenant", "tenant-a"],
      ["Repository", "repo-a"],
      ["Run", "run-a"],
      ["Access token", "x".repeat(32)],
    ])
      fireEvent.change(screen.getByLabelText(name!), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await screen.findByRole("heading", { name: "Artifact-backed progress" });
    fireEvent.click(screen.getByRole("button", { name: "Change scope" }));
    expect(signal?.aborted).toBe(true);
    await act(async () =>
      finish({
        run: receipt,
        progress: {
          change: { state: "available", files: 999 },
          deterministic: { state: "not_run" },
          context: { state: "not_run" },
          verification: { state: "not_run" },
        },
      }),
    );
    expect(screen.queryByText("Changed files: 999")).not.toBeInTheDocument();
    expect(fetchDiagnostics).not.toHaveBeenCalled();
    expect(
      screen.getByRole("heading", { name: "Locate a review run" }),
    ).toBeInTheDocument();
  });
  it("keeps V7 observations separate from findings and names missing terminal evidence", async () => {
    const base = {
      contract: "open-trestle/review-diagnostic-set" as const,
      identity: digest,
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
      snapshot_identity: "1".repeat(64),
      head_revision: "2".repeat(40),
    };
    const check = {
      identity: "3".repeat(64),
      source_check_identity: "4".repeat(64),
      analysis_result_identity: "5".repeat(64),
      change_identity: "6".repeat(64),
      key: "static_debug_output" as const,
      rule_version: 1 as const,
      state: "failed" as const,
      applicable_files: 1,
      applicable_ranges: 1,
      checked_files: 1,
      checked_ranges: 1,
      matches: 1,
    };
    const deterministic: Extract<DiagnosticSet, { schema_version: 6 }> = {
      ...base,
      schema_version: 6,
      analysis_result_identity: check.analysis_result_identity,
      checks: [check],
      observations: [
        {
          identity: "7".repeat(64),
          source_identity: "8".repeat(64),
          fingerprint: "9".repeat(64),
          analysis_result_identity: check.analysis_result_identity,
          check_identity: check.identity,
          title: "Exact match",
          message: "Observed in changed range",
          severity: "warning",
          path: "main.go",
          start_line: 1,
          end_line: 1,
          evidence_ids: [digest],
        },
      ],
    };
    const verified: Extract<DiagnosticSet, { schema_version: 5 }> = {
      ...base,
      schema_version: 5,
      verified_set_identity: "b".repeat(64),
      coverage: {
        candidate_count: 1,
        verified_count: 1,
        rejected_count: 0,
        inconclusive_count: 0,
      },
      source_coverage: {
        verification_context_identity: "c".repeat(64),
        analyzed_count: 1,
        selected_count: 1,
        omitted_count: 0,
        omissions: [],
      },
      checks: [check],
      findings: [
        {
          identity: "d".repeat(64),
          source_identity: "e".repeat(64),
          fingerprint: "f".repeat(64),
          title: "Verified issue",
          message: "Independent confirmation",
          severity: "error",
          path: "other.go",
          start_line: 2,
          end_line: 2,
          evidence_ids: [digest],
        },
      ],
    };
    vi.mocked(fetchRun).mockResolvedValue({
      ...receipt,
      status: "succeeded",
      output_identity: digest,
    });
    vi.mocked(fetchDiagnostics)
      .mockResolvedValueOnce({
        ...base,
        schema_version: 7,
        outcome: "completed",
        deterministic,
        verified,
      })
      .mockResolvedValueOnce({
        ...base,
        schema_version: 7,
        outcome: "inconclusive",
        evidence_expired: true,
      })
      .mockResolvedValueOnce({
        ...base,
        schema_version: 7,
        outcome: "completed",
        deterministic: {
          ...deterministic,
          checks: [{ ...check, state: "passed", matches: 0 }],
          observations: [],
        },
        verified: {
          ...verified,
          checks: [{ ...check, state: "passed", matches: 0 }],
          coverage: {
            candidate_count: 0,
            verified_count: 0,
            rejected_count: 0,
            inconclusive_count: 0,
          },
          findings: [],
        },
      });
    render(<App />);
    for (const [name, value] of [
      ["Tenant", "tenant-a"],
      ["Repository", "repo-a"],
      ["Run", "run-a"],
      ["Access token", "x".repeat(32)],
    ] as const)
      fireEvent.change(screen.getByLabelText(name), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await screen.findByRole("heading", {
      name: "Execution complete, advisory review",
    });
    fireEvent.click(screen.getByRole("button", { name: /Review 2/i }));
    expect(
      screen.getByRole("heading", { name: "Full review completed" }),
    ).toBeInTheDocument();
    expect(
      within(
        screen.getByRole("region", { name: "Deterministic observations" }),
      ).getByText("Exact match"),
    ).toBeInTheDocument();
    expect(
      within(
        screen.getByRole("region", { name: "Verified findings" }),
      ).getByText("Verified issue"),
    ).toBeInTheDocument();
    const coverageSections = [
      screen.getByRole("region", { name: "Deterministic rule coverage" }),
      screen.getByRole("region", { name: "Review coverage" }),
    ];
    const coverageIds = coverageSections.map((section) => {
      const titleId = section.getAttribute("aria-labelledby");
      expect(titleId).toBeTruthy();
      expect(section.querySelector(`[id="${titleId}"]`)).toBeInTheDocument();
      return titleId;
    });
    expect(new Set(coverageIds).size).toBe(coverageIds.length);
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByRole("heading", {
      name: "Execution complete, review inconclusive",
    });
    expect(
      screen.getByText(/Missing evidence was not run/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Verification is not available/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Evidence expired: this result was recorded after/),
    ).toBeInTheDocument();
    expect(screen.queryByText("Verified issue")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByRole("heading", {
      name: "Execution complete, advisory review",
    });
    expect(
      screen
        .getByRole("heading", { name: "No verified findings" })
        .closest("section"),
    ).not.toHaveClass("verified");
    expect(
      screen.getByText(/empty final finding list is not a clear result/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "No deterministic observations" }),
    ).toBeInTheDocument();
  });
  it("starts with a scoped connection form and does not persist tokens", () => {
    render(<App />);
    expect(
      screen.getByRole("heading", { name: "Locate a review run" }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Access token")).toHaveAttribute(
      "autocomplete",
      "off",
    );
    expect(sessionStorage.getItem("open-trestle-token")).toBeNull();
  });
  it("renders exact run and task state", async () => {
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    vi.mocked(fetchDiagnostics).mockRejectedValue(new Error("not ready"));
    render(<App />);
    fireEvent.change(screen.getByLabelText("Tenant"), {
      target: { value: "tenant-a" },
    });
    fireEvent.change(screen.getByLabelText("Repository"), {
      target: { value: "repo-a" },
    });
    fireEvent.change(screen.getByLabelText("Run"), {
      target: { value: "run-a" },
    });
    fireEvent.change(screen.getByLabelText("Access token"), {
      target: { value: "x".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: "Execution in progress" }),
      ).toBeInTheDocument(),
    );
    expect(screen.getByText("source")).toBeInTheDocument();
    expect(screen.getByText("succeeded")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: `Copy Run receipt: ${digest}` }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Review n\/a/i }),
    ).toBeInTheDocument();
    expect(sessionStorage.getItem("open-trestle-scope")).toContain("tenant-a");
    expect(sessionStorage.getItem("open-trestle-token")).toBeNull();
  });

  it("names a recorded source refusal reason beside the failure", async () => {
    vi.mocked(fetchRun).mockResolvedValue({
      ...receipt,
      schema_version: 3,
      status: "failed",
      failure: "policy",
      tasks: receipt.tasks.map((task) => ({
        ...task,
        status: "failed" as const,
        output_identity: "",
        failure: "policy" as const,
        failure_reason: "no_merge_base" as const,
      })),
    });
    vi.mocked(fetchDiagnostics).mockRejectedValue(new Error("not ready"));
    render(<App />);
    fireEvent.change(screen.getByLabelText("Tenant"), {
      target: { value: "tenant-a" },
    });
    fireEvent.change(screen.getByLabelText("Repository"), {
      target: { value: "repo-a" },
    });
    fireEvent.change(screen.getByLabelText("Run"), {
      target: { value: "run-a" },
    });
    fireEvent.change(screen.getByLabelText("Access token"), {
      target: { value: "x".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await waitFor(() =>
      expect(
        screen.getAllByText(
          /No merge base: the requested base and the head share no history/,
        ).length,
      ).toBeGreaterThan(0),
    );
    expect(screen.getAllByText("policy").length).toBeGreaterThan(0);
  });

  it("names a context route refusal and its hint beside the failure", async () => {
    const shortfall = {
      required_tokens: 14282,
      estimated_input_tokens: 10186,
      max_output_tokens: 4096,
      declared_context_tokens: 4097,
    };
    vi.mocked(fetchRun).mockResolvedValue({
      ...receipt,
      schema_version: 3,
      status: "failed",
      failure: "policy",
      tasks: receipt.tasks.map((task) => ({
        ...task,
        kind: "assemble_context" as const,
        status: "failed" as const,
        output_identity: "",
        failure: "policy" as const,
        failure_reason: "route_context_insufficient" as const,
        context_shortfall: shortfall,
      })),
    });
    vi.mocked(fetchDiagnostics).mockRejectedValue(new Error("not ready"));
    render(<App />);
    fireEvent.change(screen.getByLabelText("Tenant"), {
      target: { value: "tenant-a" },
    });
    fireEvent.change(screen.getByLabelText("Repository"), {
      target: { value: "repo-a" },
    });
    fireEvent.change(screen.getByLabelText("Run"), {
      target: { value: "run-a" },
    });
    fireEvent.change(screen.getByLabelText("Access token"), {
      target: { value: "x".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await waitFor(() =>
      expect(
        screen.getAllByText(
          /Route context insufficient: the review request needs more context than the route declares/,
        ).length,
      ).toBeGreaterThan(0),
    );
    expect(
      screen.getAllByText(
        /the review needs up to 14282 tokens \(a byte-based upper bound: 10186 input plus 4096 output\) but the route declares max_context_tokens 4097/,
      ).length,
    ).toBeGreaterThan(0);
  });

  it.each([
    {
      failure: "policy" as const,
      reason: "provider_payment_required" as const,
      label:
        /Provider payment required: the provider refused the request for billing/,
      hint: "add credit or a subscription to the provider account, or choose another route",
    },
    {
      failure: "internal" as const,
      reason: "provider_response_invalid" as const,
      label:
        /Provider reply refused: the provider answered, but its reply did not match what Open Trestle accepts/,
      hint: "run the review again; if it repeats, choose another model or route and report it",
    },
    {
      failure: "internal" as const,
      reason: "model_output_invalid" as const,
      label:
        /Model answer not a review document: the model's answer was not a valid review document/,
      hint: "run the review again; if it repeats, choose another model",
    },
    {
      failure: "policy" as const,
      reason: "provider_request_rejected" as const,
      label:
        /Provider request rejected: the provider rejected the request as invalid, for example an unknown model ID or a parameter the model or endpoint does not accept/,
      hint: "check the model ID, the endpoint and its transport, and that the model and endpoint accept structured output and the requested output allowance; then re-run setup",
    },
  ])(
    "names a provider refusal ($reason) and its hint beside the failure",
    async ({ failure, reason, label, hint }) => {
      vi.mocked(fetchRun).mockResolvedValue({
        ...receipt,
        schema_version: 3,
        status: "failed",
        failure,
        tasks: receipt.tasks.map((task) => ({
          ...task,
          kind: "generate_candidates" as const,
          status: "failed" as const,
          output_identity: "",
          failure,
          failure_reason: reason,
        })),
      });
      vi.mocked(fetchDiagnostics).mockRejectedValue(new Error("not ready"));
      render(<App />);
      fireEvent.change(screen.getByLabelText("Tenant"), {
        target: { value: "tenant-a" },
      });
      fireEvent.change(screen.getByLabelText("Repository"), {
        target: { value: "repo-a" },
      });
      fireEvent.change(screen.getByLabelText("Run"), {
        target: { value: "run-a" },
      });
      fireEvent.change(screen.getByLabelText("Access token"), {
        target: { value: "x".repeat(32) },
      });
      fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
      await waitFor(() =>
        expect(screen.getAllByText(label).length).toBeGreaterThan(0),
      );
      expect(screen.getAllByText(hint).length).toBeGreaterThan(0);
    },
  );

  it("names a recorded delivery refusal when no run was opened", async () => {
    const key = "b".repeat(64);
    vi.mocked(fetchRun).mockRejectedValue(new ApiError("not_found"));
    vi.mocked(fetchDeliveryRefusal).mockResolvedValue({
      contract: "open-trestle/webhook-delivery-refusal",
      schema_version: 1,
      identity: digest,
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      source: "github",
      deduplication_key: key,
      delivery_identity: digest,
      planner_identity: digest,
      reason: "invalid_pull_request_payload",
      refused_at_milliseconds: 2000,
    });
    render(<App />);
    fireEvent.change(screen.getByLabelText("Tenant"), {
      target: { value: "tenant-a" },
    });
    fireEvent.change(screen.getByLabelText("Repository"), {
      target: { value: "repo-a" },
    });
    fireEvent.change(screen.getByLabelText("Run"), {
      target: { value: `webhook-${key}` },
    });
    fireEvent.change(screen.getByLabelText("Access token"), {
      target: { value: "x".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await waitFor(() =>
      expect(
        screen.getByText(
          /No run was opened: intake refused this delivery \(invalid_pull_request_payload: the pull request payload cannot be planned\)/,
        ),
      ).toBeInTheDocument(),
    );
  });

  it("discloses exact verified finding evidence lineage", async () => {
    const findingIdentity = "d".repeat(64);
    const sourceIdentity = "e".repeat(64);
    const fingerprint = "f".repeat(64);
    const evidenceReference = "evidence-authorization-84";
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    vi.mocked(fetchDiagnostics).mockResolvedValue({
      contract: "open-trestle/review-diagnostic-set",
      schema_version: 1,
      identity: "b".repeat(64),
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
      snapshot_identity: "1".repeat(64),
      head_revision: "2".repeat(40),
      verified_set_identity: "3".repeat(64),
      findings: [
        {
          identity: findingIdentity,
          source_identity: sourceIdentity,
          fingerprint,
          title: "Authorization check can be bypassed",
          message: "Move the capability check ahead of the early return.",
          severity: "error",
          path: "internal/access/policy.go",
          start_line: 84,
          end_line: 91,
          evidence_ids: [evidenceReference],
        },
      ],
    });
    render(<App />);
    for (const [name, value] of [
      ["Tenant", "tenant-a"],
      ["Repository", "repo-a"],
      ["Run", "run-a"],
      ["Access token", "x".repeat(32)],
    ] as const)
      fireEvent.change(screen.getByLabelText(name), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await screen.findByRole("heading", { name: "Execution in progress" });
    fireEvent.click(screen.getByRole("button", { name: /Review 1/i }));
    const summary = await screen.findByText("Inspect evidence");
    const details = summary.closest("details");
    expect(details).not.toHaveAttribute("open");
    fireEvent.click(summary);
    expect(details).toHaveAttribute("open");
    for (const [label, identity] of [
      ["Diagnostic identity", findingIdentity],
      ["Source finding identity", sourceIdentity],
      ["Finding fingerprint", fingerprint],
      ["Evidence reference 1", evidenceReference],
    ])
      expect(
        screen.getByRole("button", { name: `Copy ${label}: ${identity}` }),
      ).toBeInTheDocument();
    const originalClipboard = navigator.clipboard;
    const writeText = vi
      .fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("permission denied with secret detail"));
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    fireEvent.click(
      screen.getByRole("button", {
        name: `Copy Diagnostic identity: ${findingIdentity}`,
      }),
    );
    expect(await screen.findByRole("status")).toHaveTextContent("Copied");
    fireEvent.click(
      screen.getByRole("button", {
        name: `Copy Source finding identity: ${sourceIdentity}`,
      }),
    );
    expect(await screen.findByText("Copy failed")).toHaveAttribute(
      "role",
      "status",
    );
    expect(writeText).toHaveBeenNthCalledWith(1, findingIdentity);
    expect(writeText).toHaveBeenNthCalledWith(2, sourceIdentity);
    expect(screen.queryByText(/permission denied/i)).not.toBeInTheDocument();
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: originalClipboard,
    });
  });

  it("labels a finding on removed base lines instead of showing head lines", async () => {
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    vi.mocked(fetchDiagnostics).mockResolvedValue({
      contract: "open-trestle/review-diagnostic-set",
      schema_version: 8,
      identity: "b".repeat(64),
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
      findings: [
        {
          identity: "d".repeat(64),
          source_identity: "e".repeat(64),
          fingerprint: "f".repeat(64),
          title: "Removed zero guard",
          message: "Div no longer checks b before dividing.",
          severity: "error",
          path: "calc.go",
          start_line: 4,
          end_line: 6,
          side: "base",
          evidence_ids: ["evidence-removed-4"],
        },
      ],
    });
    render(<App />);
    for (const [name, value] of [
      ["Tenant", "tenant-a"],
      ["Repository", "repo-a"],
      ["Run", "run-a"],
      ["Access token", "x".repeat(32)],
    ] as const)
      fireEvent.change(screen.getByLabelText(name), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await screen.findByRole("heading", { name: "Execution in progress" });
    fireEvent.click(screen.getByRole("button", { name: /Review 1/i }));
    expect(
      await screen.findByText("calc.go · removed base lines 4-6"),
    ).toBeInTheDocument();
    expect(screen.queryByText("calc.go:4-6")).not.toBeInTheDocument();
  });

  it("renders deterministic observations without calling them verified", async () => {
    const analysis = "7".repeat(64),
      checkIdentity = "5".repeat(64),
      observationIdentity = "9".repeat(64);
    vi.mocked(fetchRun).mockResolvedValue({
      ...receipt,
      status: "succeeded",
      output_identity: digest,
    });
    vi.mocked(fetchDiagnostics).mockResolvedValue({
      contract: "open-trestle/review-diagnostic-set",
      schema_version: 6,
      identity: "f".repeat(64),
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
      snapshot_identity: "1".repeat(64),
      head_revision: "2".repeat(40),
      analysis_result_identity: analysis,
      checks: [
        {
          identity: checkIdentity,
          source_check_identity: "6".repeat(64),
          analysis_result_identity: analysis,
          change_identity: "8".repeat(64),
          key: "static_debug_output",
          rule_version: 1,
          state: "failed",
          applicable_files: 1,
          applicable_ranges: 1,
          checked_files: 1,
          checked_ranges: 1,
          matches: 1,
        },
      ],
      observations: [
        {
          identity: observationIdentity,
          source_identity: "a".repeat(64),
          fingerprint: "b".repeat(64),
          analysis_result_identity: analysis,
          check_identity: checkIdentity,
          title: "Debug output left in source",
          message:
            "The deterministic static rule matched this exact changed range; human review is required.",
          severity: "warning",
          path: "main.go",
          start_line: 3,
          end_line: 3,
          evidence_ids: ["c".repeat(64)],
        },
      ],
    });
    render(<App />);
    for (const [name, value] of [
      ["Tenant", "tenant-a"],
      ["Repository", "repo-a"],
      ["Run", "run-a"],
      ["Access token", "x".repeat(32)],
    ] as const)
      fireEvent.change(screen.getByLabelText(name), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await screen.findByRole("heading", {
      name: "Execution complete, review required",
    });
    expect(
      screen.getByLabelText("Operational run status succeeded"),
    ).toHaveTextContent(/succeeded/i);
    expect(
      screen.queryByRole("heading", { name: "Run succeeded" }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Review 1/i }));
    expect(
      await screen.findByRole("heading", {
        name: "Deterministic rule coverage",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/not independently verified findings/i),
    ).toBeInTheDocument();
    expect(screen.getByText("warning · deterministic")).toBeInTheDocument();
    expect(screen.getByText("main.go:3-3")).toBeInTheDocument();
    expect(screen.queryByText(/1 verified/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByText("Inspect evidence"));
    expect(
      screen.getByRole("button", {
        name: `Copy Observation identity: ${observationIdentity}`,
      }),
    ).toBeInTheDocument();
  });

  it("renders incomplete candidate and source coverage without implying approval", async () => {
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    vi.mocked(fetchDiagnostics).mockResolvedValue({
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
        candidate_count: 2,
        verified_count: 0,
        rejected_count: 1,
        inconclusive_count: 1,
      },
      source_coverage: {
        verification_context_identity: "4".repeat(64),
        analyzed_count: 173,
        selected_count: 1,
        omitted_count: 172,
        omissions: [
          { reason: "selection_limit", count: 170 },
          { reason: "unsupported", count: 2 },
        ],
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
    });
    render(<App />);
    for (const [name, value] of [
      ["Tenant", "tenant-a"],
      ["Repository", "repo-a"],
      ["Run", "run-a"],
      ["Access token", "x".repeat(32)],
    ] as const)
      fireEvent.change(screen.getByLabelText(name), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await screen.findByRole("heading", { name: "Execution in progress" });
    fireEvent.click(screen.getByRole("button", { name: /Review 0/i }));
    expect(
      await screen.findByRole("heading", { name: "Human review queue" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Review coverage" }),
    ).toBeInTheDocument();
    expect(screen.getByText("1 rejected")).toBeInTheDocument();
    expect(screen.getByText("1 inconclusive")).toBeInTheDocument();
    expect(screen.getByText("173 sources analyzed")).toBeInTheDocument();
    expect(screen.getByText("1 selected for model review")).toBeInTheDocument();
    expect(
      screen.getByText("172 omitted from model context"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Source coverage is incomplete/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Omission reasons: 170 selection limit, 2 unsupported/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Cleared gate: Static debug output passed/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Cleared for this exact rule only/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/does not approve the change/i),
    ).toBeInTheDocument();
    expect(
      screen
        .getByRole("heading", { name: "No verified findings" })
        .closest("section"),
    ).not.toHaveClass("verified");
  });

  it("does not present a failed deterministic check as a clean empty state", async () => {
    vi.mocked(fetchRun).mockResolvedValue({
      ...receipt,
      status: "succeeded",
      output_identity: digest,
    });
    vi.mocked(fetchDiagnostics).mockResolvedValue({
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
          state: "failed",
          applicable_files: 1,
          applicable_ranges: 1,
          checked_files: 1,
          checked_ranges: 1,
          matches: 1,
        },
      ],
      findings: [],
    });
    render(<App />);
    for (const [name, value] of [
      ["Tenant", "tenant-a"],
      ["Repository", "repo-a"],
      ["Run", "run-a"],
      ["Access token", "x".repeat(32)],
    ] as const)
      fireEvent.change(screen.getByLabelText(name), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await screen.findByRole("heading", {
      name: "Execution complete, review required",
    });
    fireEvent.click(screen.getByRole("button", { name: /Review 0/i }));
    expect(
      await screen.findByText(/Failed check: Static debug output failed/i),
    ).toBeInTheDocument();
    const empty = screen
      .getByRole("heading", { name: "No verified findings" })
      .closest("section");
    expect(empty).not.toHaveClass("verified");
    expect(empty).toHaveTextContent(/deterministic check requires review/i);
  });

  it.each([false, true])(
    "does not dispatch with a disconnected token after late diagnostics (reconnect: %s)",
    async (reconnect) => {
      let resolveDiagnostics!: (value: DiagnosticSet) => void;
      const lateDiagnostics: DiagnosticSet = {
        contract: "open-trestle/review-diagnostic-set",
        schema_version: 1,
        identity: digest,
        tenant_id: "tenant-a",
        repository_id: "repo-a",
        review_run_id: "run-a",
        snapshot_identity: digest,
        head_revision: "abc123",
        verified_set_identity: digest,
        findings: [],
      };
      vi.mocked(fetchRun).mockResolvedValueOnce(receipt);
      vi.mocked(fetchDiagnostics).mockReturnValueOnce(
        new Promise((resolve) => {
          resolveDiagnostics = resolve;
        }),
      );
      render(<App />);
      for (const [name, value] of [
        ["Tenant", "tenant-a"],
        ["Repository", "repo-a"],
        ["Run", "run-a"],
        ["Access token", "x".repeat(32)],
      ] as const)
        fireEvent.change(screen.getByLabelText(name), { target: { value } });
      fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
      await screen.findByRole("heading", { name: "Execution in progress" });
      expect(fetchDiagnostics).toHaveBeenCalledTimes(1);
      fireEvent.click(screen.getByRole("button", { name: "Change scope" }));
      if (reconnect) {
        vi.mocked(fetchRun).mockResolvedValueOnce({
          ...receipt,
          tenant_id: "tenant-b",
          repository_id: "repo-b",
          review_run_id: "run-b",
        });
        vi.mocked(fetchDiagnostics).mockRejectedValueOnce(
          new Error("not ready"),
        );
        for (const [name, value] of [
          ["Tenant", "tenant-b"],
          ["Repository", "repo-b"],
          ["Run", "run-b"],
          ["Access token", "y".repeat(32)],
        ] as const)
          fireEvent.change(screen.getByLabelText(name), { target: { value } });
        fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
        await waitFor(() =>
          expect(fetchRuntimeStatus).toHaveBeenCalledTimes(1),
        );
      }
      await act(async () => resolveDiagnostics(lateDiagnostics));
      if (reconnect) {
        expect(fetchRuntimeStatus).toHaveBeenCalledExactlyOnceWith(
          { tenant: "tenant-b", repository: "repo-b", run: "run-b" },
          "y".repeat(32),
          undefined,
          expect.any(AbortSignal),
        );
        expect(screen.getByText("run-b")).toBeInTheDocument();
      } else {
        expect(fetchRuntimeStatus).not.toHaveBeenCalled();
        expect(
          screen.getByRole("heading", { name: "Locate a review run" }),
        ).toBeInTheDocument();
      }
    },
  );
  it.each(["SecurityError", "QuotaExceededError"])(
    "connects and disconnects when optional scope storage throws %s",
    async (name) => {
      const write = vi
        .spyOn(Object.getPrototypeOf(sessionStorage), "setItem")
        .mockImplementation(() => {
          throw new DOMException("Storage unavailable", name);
        });
      try {
        vi.mocked(fetchRun).mockResolvedValue(receipt);
        vi.mocked(fetchDiagnostics).mockResolvedValue({
          contract: "open-trestle/review-diagnostic-set",
          schema_version: 1,
          identity: digest,
          tenant_id: "tenant-a",
          repository_id: "repo-a",
          review_run_id: "run-a",
          snapshot_identity: digest,
          head_revision: "abc123",
          verified_set_identity: digest,
          findings: [],
        });
        vi.mocked(fetchRuntimeStatus).mockResolvedValue(runtimeStatus);
        render(<App />);
        for (const [label, value] of [
          ["Tenant", "tenant-a"],
          ["Repository", "repo-a"],
          ["Run", "run-a"],
          ["Access token", "x".repeat(32)],
        ] as const)
          fireEvent.change(screen.getByLabelText(label), { target: { value } });
        fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
        await screen.findByRole("button", { name: /Runtime ready/i });
        expect(fetchDiagnostics).toHaveBeenCalledTimes(1);
        expect(fetchRuntimeStatus).toHaveBeenCalledTimes(1);
        expect(
          screen.getByRole("button", { name: /Review 0/i }),
        ).toBeInTheDocument();
        expect(screen.queryByRole("alert")).not.toBeInTheDocument();
        expect(write).toHaveBeenCalledExactlyOnceWith(
          "open-trestle-scope",
          JSON.stringify({
            tenant: "tenant-a",
            repository: "repo-a",
            run: "run-a",
          }),
        );
        expect(sessionStorage.length).toBe(0);
        fireEvent.click(screen.getByRole("button", { name: "Change scope" }));
        expect(screen.getByLabelText("Access token")).toHaveValue("");
        expect(sessionStorage.length).toBe(0);
      } finally {
        write.mockRestore();
      }
    },
  );
  it("copies exact runtime handler identities even when their visible ends match", async () => {
    const handlers = [
      { kind: "acquire_source" as const, identity: "1".repeat(64) },
      {
        kind: "build_change" as const,
        identity: "1".repeat(10) + "2".repeat(46) + "1".repeat(8),
      },
    ];
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    vi.mocked(fetchDiagnostics).mockRejectedValue(new Error("not ready"));
    vi.mocked(fetchRuntimeStatus).mockResolvedValue({
      ...runtimeStatus,
      configuration: {
        ...runtimeStatus.configuration,
        handlers,
      },
    });
    const originalClipboard = navigator.clipboard;
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    try {
      render(<App />);
      for (const [name, value] of [
        ["Tenant", "tenant-a"],
        ["Repository", "repo-a"],
        ["Run", "run-a"],
        ["Access token", "x".repeat(32)],
      ] as const)
        fireEvent.change(screen.getByLabelText(name), { target: { value } });
      fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
      fireEvent.click(
        await screen.findByRole("button", { name: /Runtime ready/i }),
      );
      const section = screen
        .getByRole("heading", { name: "Handler authority" })
        .closest("section")!;
      for (const { kind, identity } of handlers) {
        expect(within(section).getByText(identity)).toHaveClass("sr-only");
        const button = within(section).getByRole("button", {
          name: `Copy ${kind.replaceAll("_", " ")}: ${identity}`,
        });
        button.focus();
        expect(button).toHaveFocus();
        fireEvent.click(button);
        await waitFor(() =>
          expect(writeText).toHaveBeenLastCalledWith(identity),
        );
      }
      expect(writeText).toHaveBeenCalledTimes(2);
    } finally {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: originalClipboard,
      });
    }
  });
  it("renders authenticated content-free runtime status", async () => {
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    vi.mocked(fetchDiagnostics).mockRejectedValue(new Error("not ready"));
    vi.mocked(fetchRuntimeStatus).mockResolvedValue(runtimeStatus);
    render(<App />);
    fireEvent.change(screen.getByLabelText("Tenant"), {
      target: { value: "tenant-a" },
    });
    fireEvent.change(screen.getByLabelText("Repository"), {
      target: { value: "repo-a" },
    });
    fireEvent.change(screen.getByLabelText("Run"), {
      target: { value: "run-a" },
    });
    fireEvent.change(screen.getByLabelText("Access token"), {
      target: { value: "x".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await screen.findByRole("heading", { name: "Execution in progress" });
    fireEvent.click(screen.getByRole("button", { name: /Runtime ready/i }));
    expect(
      await screen.findByRole("heading", { name: "Runtime state" }),
    ).toBeInTheDocument();
    expect(screen.getByText("task notifications")).toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name: `Copy Configuration: ${"c".repeat(64)}`,
      }),
    ).toBeInTheDocument();
  });

  it("shows bounded Runtime unavailable state without stale identities", async () => {
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    vi.mocked(fetchDiagnostics).mockRejectedValue(new Error("not ready"));
    vi.mocked(fetchRuntimeStatus).mockRejectedValue(
      new ApiError("invalid_response"),
    );
    render(<App />);
    fireEvent.change(screen.getByLabelText("Tenant"), {
      target: { value: "tenant-a" },
    });
    fireEvent.change(screen.getByLabelText("Repository"), {
      target: { value: "repo-a" },
    });
    fireEvent.change(screen.getByLabelText("Run"), {
      target: { value: "run-a" },
    });
    fireEvent.change(screen.getByLabelText("Access token"), {
      target: { value: "x".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await screen.findByRole("heading", { name: "Execution in progress" });
    fireEvent.click(screen.getByRole("button", { name: /Runtime n\/a/i }));
    expect(
      await screen.findByRole("heading", {
        name: "Runtime status is not available",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Runtime status could not be loaded with this token."),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Copy Status:/i }),
    ).not.toBeInTheDocument();
  });
  it("explains locator validation and links errors without exposing tokens", () => {
    render(<App />);
    expect(
      screen.getAllByText(
        /1-128 lowercase letters or numbers; \. _ : - are allowed/i,
      ),
    ).toHaveLength(3);
    expect(
      screen.getByText(/32-512 non-space characters.*hidden and never saved/i),
    ).toBeInTheDocument();
    const tenant = screen.getByLabelText("Tenant");
    fireEvent.change(tenant, { target: { value: "Tenant A" } });
    fireEvent.blur(tenant);
    expect(tenant).toHaveAttribute("aria-invalid", "true");
    expect(tenant).toHaveAccessibleDescription(
      expect.stringMatching(/start and end with a lowercase letter or number/i),
    );
    const token = screen.getByLabelText("Access token");
    fireEvent.change(token, { target: { value: "short secret" } });
    fireEvent.blur(token);
    expect(token).toHaveAttribute("aria-invalid", "true");
    expect(token).toHaveAccessibleDescription(
      expect.stringMatching(/32-512 non-space characters/i),
    );
    expect(screen.queryByText("short secret")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Connect to run" }),
    ).toHaveAccessibleDescription(/correct fields to connect/i);
  });
});
