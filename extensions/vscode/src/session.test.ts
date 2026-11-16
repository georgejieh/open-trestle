import { afterEach, describe, expect, it, vi } from "vitest";
import { resolve } from "node:path";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { spawn } from "node:child_process";
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: vi.fn(actual.spawn) };
});
import { Session } from "./session";
import type { LaunchConfiguration } from "./config";

const rootUri = "file:///chosen/root";
const token = "token-canary-".repeat(3);
const sessions: Session[] = [];
function session(mode = "normal", onFailure: () => void = vi.fn()): Session {
  const launch: LaunchConfiguration = {
    command: process.execPath,
    args: [resolve("test/fixtures/session-server.cjs"), mode],
    initializationOptions: {
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
    },
    environment: { OPEN_TRESTLE_API_TOKEN: token },
  };
  const value = new Session(
    launch,
    rootUri,
    {
      PATH: process.env.PATH,
      AWS_SECRET_ACCESS_KEY: "do-not-forward",
    },
    onFailure,
  );
  sessions.push(value);
  return value;
}
afterEach(async () => {
  vi.useRealTimers();
  for (const value of sessions.splice(0)) expect(await value.stop()).toBe(true);
  vi.restoreAllMocks();
});
describe("owned read-only protocol session", () => {
  it("rejects concurrent pulls without widening the one-request scheduler", async () => {
    const value = session("late");
    await value.start();
    const first = value.pull(`${rootUri}/first.ts`);
    await expect(value.pull(`${rootUri}/second.ts`)).rejects.toThrow();
    await expect(first).resolves.toEqual({ late: true });
  });
  it("observes a real missing-executable spawn failure", async () => {
    const value = new Session(
      {
        command: resolve("test/fixtures/no-such-executable"),
        args: [],
        initializationOptions: {
          tenant_id: "a",
          repository_id: "b",
          review_run_id: "c",
        },
        environment: { OPEN_TRESTLE_API_TOKEN: token },
      },
      rootUri,
      {},
      vi.fn(),
    );
    sessions.push(value);
    await expect(value.start()).rejects.toThrow(
      "Open Trestle protocol session is unavailable.",
    );
    expect(await value.stop()).toBe(true);
    expect(value.closed).toBe(true);
  });
  it("denies server effects and bounds configuration replies", async () => {
    const value = session("denials");
    await value.start();
    const result = (await value.pull(`${rootUri}/file.ts`)) as {
      refusals: unknown[];
    };
    expect(result.refusals).toEqual([
      { applied: false, failureReason: "Open Trestle is read-only." },
      { success: false },
      null,
      null,
      [null, null],
      { code: -32602 },
      { code: -32602 },
      { code: -32601 },
      { code: -32601 },
      { code: -32601 },
    ]);
  });
  it.each([
    "wrong-encoding",
    "sync",
    "workspace-diagnostics",
    "wrong-identity",
    "no-interfile",
    "malformed",
    "oversize",
  ])(
    "fails closed on %s initialization",
    async (mode) => {
      const onFailure = vi.fn();
      const value = session(mode, onFailure);
      await expect(value.start()).rejects.toThrow(
        "Open Trestle protocol session is unavailable.",
      );
      expect(onFailure).toHaveBeenCalledTimes(1);
      expect(await value.stop()).toBe(true);
      expect(value.closed).toBe(true);
    },
    10_000,
  );
  it("drains stderr without logging untrusted text", async () => {
    const log = vi.spyOn(console, "log");
    const error = vi.spyOn(console, "error");
    const value = session("stderr");
    await value.start();
    await value.pull(`${rootUri}/file.ts`);
    expect(log).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
  });
  it.each(["hang-init", "hang-pull"])(
    "bounds %s by 35 seconds",
    async (mode) => {
      const value = session(mode);
      if (mode === "hang-pull") await value.start();
      const schedule = globalThis.setTimeout;
      const timer = vi
        .spyOn(globalThis, "setTimeout")
        .mockImplementation((handler, delay, ...args) =>
          schedule(handler, delay === 35_000 ? 100 : delay, ...args),
        );
      const pending =
        mode === "hang-init" ? value.start() : value.pull(`${rootUri}/file.ts`);
      await expect(pending).rejects.toThrow(
        "Open Trestle protocol session is unavailable.",
      );
      expect(timer.mock.calls.some((call) => call[1] === 35_000)).toBe(true);
      expect(await value.stop()).toBe(true);
    },
    10_000,
  );
  it("invalidates before failure callbacks can start more work", async () => {
    let value: Session;
    let callbackPull: Promise<unknown> | undefined;
    value = session("wrong-encoding", () => {
      callbackPull = value.pull(`${rootUri}/file.ts`);
      void callbackPull.catch(() => undefined);
    });
    await expect(value.start()).rejects.toThrow();
    await expect(callbackPull).rejects.toThrow();
  });
  it("rejects late replies after immediate invalidation", async () => {
    const value = session("late");
    await value.start();
    const pending = value.pull(`${rootUri}/file.ts`);
    const rejected = expect(pending).rejects.toThrow();
    value.invalidate();
    await rejected;
    await expect(value.pull(`${rootUri}/file.ts`)).rejects.toThrow();
    expect(await value.stop()).toBe(true);
  });
  it("retires a child ignoring cancellation and graceful shutdown", async () => {
    const value = session("resist");
    await value.start();
    const pending = value.pull(`${rootUri}/file.ts`);
    const rejected = expect(pending).rejects.toThrow();
    expect(await value.stop()).toBe(true);
    await rejected;
    expect(value.closed).toBe(true);
  }, 10_000);
  it("retains ownership after exit without close and rechecks a later close", async () => {
    const child = Object.assign(new EventEmitter(), {
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      pid: 12345,
      kill: vi.fn(() => true),
    });
    vi.mocked(spawn).mockReturnValueOnce(
      child as unknown as ReturnType<typeof spawn>,
    );
    const value = session();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const starting = value.start();
    const rejected = expect(starting).rejects.toThrow();
    const stopping = value.stop();
    child.emit("exit", 0, null);
    await vi.advanceTimersByTimeAsync(3_001);
    expect(await stopping).toBe(false);
    await rejected;
    expect(value.closed).toBe(false);
    expect(child.stdout.destroyed).toBe(false);
    expect(child.stderr.destroyed).toBe(false);
    expect(child.kill.mock.calls).toEqual([["SIGTERM"], ["SIGKILL"]]);
    child.emit("close", 0, null);
    expect(value.closed).toBe(true);
    expect(await value.stop()).toBe(true);
    vi.useRealTimers();
  });
  it("observes failed-spawn closure without a PID", async () => {
    const value = session();
    vi.mocked(spawn).mockImplementationOnce(() => {
      const child = Object.assign(new EventEmitter(), {
        stdin: new PassThrough(),
        stdout: new PassThrough(),
        stderr: new PassThrough(),
        pid: undefined,
        kill: vi.fn(() => false),
      });
      queueMicrotask(() => {
        child.emit("error", new Error("untrusted-token-canary"));
        child.emit("close", -2, null);
      });
      return child as unknown as ReturnType<typeof spawn>;
    });
    await expect(value.start()).rejects.toThrow(
      "Open Trestle protocol session is unavailable.",
    );
    expect(value.closed).toBe(true);
    expect(await value.stop()).toBe(true);
  });
  it("sends only exact initialize and URI pull fields to a real child", async () => {
    const value = session();
    await value.start();
    const uri = `${rootUri}/file.ts`;
    const result = await value.pull(uri, "a".repeat(64));
    expect(result).toEqual({
      initialize: {
        processId: null,
        rootUri,
        workspaceFolders: [{ uri: rootUri, name: "Open Trestle" }],
        initializationOptions: {
          tenant_id: "tenant-a",
          repository_id: "repo-a",
          review_run_id: "run-a",
        },
        capabilities: {
          workspace: { applyEdit: false },
          window: { showDocument: { support: false } },
          textDocument: {
            diagnostic: {
              dynamicRegistration: false,
              relatedDocumentSupport: false,
              markupMessageSupport: false,
            },
          },
        },
      },
      received: [
        { method: "initialize", params: expect.any(Object) },
        { method: "initialized", params: {} },
        {
          method: "textDocument/diagnostic",
          params: {
            textDocument: { uri },
            previousResultId: "a".repeat(64),
          },
        },
      ],
      environment: { token },
    });
    expect(value.closed).toBe(false);
    expect(await value.stop()).toBe(true);
    expect(value.closed).toBe(true);
    await expect(value.pull(uri)).rejects.toThrow();
  });
});
