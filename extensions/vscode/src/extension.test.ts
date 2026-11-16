import { beforeEach, describe, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({
  commands: new Map<string, () => Promise<void>>(),
  sessions: [] as any[],
  diagnostics: [] as any[],
  configuration: undefined as any,
  secret: undefined as any,
  closed: true,
  trusted: true,
}));
vi.mock("vscode", () => ({
  workspace: {
    get isTrusted() {
      return h.trusted;
    },
    workspaceFolders: [
      { uri: { scheme: "file", toString: () => "file:///root" } },
    ],
    getConfiguration: () => ({
      get: (key: string, fallback: unknown) =>
        ({ executable: "trestle", tenant: "t", repository: "r", run: "run" })[
          key as "tenant"
        ] ?? fallback,
    }),
    onDidChangeConfiguration: (fn: any) => {
      h.configuration = fn;
      return { dispose() {} };
    },
    onDidChangeWorkspaceFolders: () => ({ dispose() {} }),
  },
  window: {
    createOutputChannel: () => ({ dispose() {} }),
    createStatusBarItem: () => ({ show() {}, dispose() {} }),
    showErrorMessage: vi.fn(),
    showInformationMessage: vi.fn(),
    showWarningMessage: vi.fn(),
    showInputBox: vi.fn(),
  },
  StatusBarAlignment: { Left: 1 },
  commands: {
    registerCommand: (name: string, fn: any) => {
      h.commands.set(name, fn);
      return { dispose() {} };
    },
    executeCommand: vi.fn(),
  },
}));
vi.mock("./session", () => ({
  Session: class {
    closed = false;
    active = true;
    start = vi.fn(async () => {});
    pull = vi.fn();
    invalidate = vi.fn(() => {
      this.active = false;
    });
    stop = vi.fn(async () => {
      this.closed = h.closed;
      return this.closed;
    });
    constructor(..._args: any[]) {
      h.sessions.push(this);
    }
  },
}));
vi.mock("./diagnostics", () => ({
  Diagnostics: class {
    start = vi.fn();
    dispose = vi.fn();
    constructor(..._args: any[]) {
      h.diagnostics.push(this);
    }
  },
}));
import { activate, deactivate } from "./extension";
beforeEach(async () => {
  h.closed = true;
  await deactivate();
  h.commands.clear();
  h.sessions.length = 0;
  h.diagnostics.length = 0;
  h.trusted = true;
  const secrets = {
    get: vi.fn(async () => "x".repeat(32)),
    store: vi.fn(),
    delete: vi.fn(),
    onDidChange: (fn: any) => {
      h.secret = fn;
      return { dispose() {} };
    },
  };
  await activate({ secrets, subscriptions: [] } as never);
});
describe("owned editor lifecycle", () => {
  it("refuses startup invalidated while SecretStorage is pending", async () => {
    await deactivate();
    let resolveToken!: (token: string) => void;
    await activate({
      secrets: {
        get: () =>
          new Promise<string>((resolve) => {
            resolveToken = resolve;
          }),
        onDidChange: (fn: any) => {
          h.secret = fn;
          return { dispose() {} };
        },
      },
      subscriptions: [],
    } as never);
    const starting = h.commands.get("openTrestle.connect")!();
    await Promise.resolve();
    h.configuration({ affectsConfiguration: () => true });
    resolveToken("x".repeat(32));
    await starting;
    expect(h.sessions).toHaveLength(0);
  });

  it("blocks a successor when prior child closure is unobserved", async () => {
    await h.commands.get("openTrestle.connect")!();
    h.closed = false;
    await h.commands.get("openTrestle.restart")!();
    expect(h.sessions).toHaveLength(1);
    expect(h.sessions[0].active).toBe(false);
    expect(h.diagnostics[0].dispose).toHaveBeenCalled();
    h.closed = true;
    await h.commands.get("openTrestle.restart")!();
    expect(h.sessions).toHaveLength(2);
  });
  it("invalidates publication synchronously on configuration and secret events", async () => {
    await h.commands.get("openTrestle.connect")!();
    h.configuration({ affectsConfiguration: () => true });
    expect(h.sessions[0].active).toBe(false);
    expect(h.diagnostics[0].dispose).toHaveBeenCalled();
    await deactivate();
    await activate({
      secrets: {
        get: async () => "x".repeat(32),
        onDidChange: (fn: any) => {
          h.secret = fn;
          return { dispose() {} };
        },
      },
      subscriptions: [],
    } as never);
    await h.commands.get("openTrestle.connect")!();
    const last = h.sessions.at(-1);
    h.secret({ key: "openTrestle.apiToken" });
    expect(last.active).toBe(false);
  });
  it("refuses untrusted startup and invalidates before deactivation awaits", async () => {
    h.trusted = false;
    await h.commands.get("openTrestle.connect")!();
    expect(h.sessions).toHaveLength(0);
    h.trusted = true;
    await h.commands.get("openTrestle.connect")!();
    const done = deactivate();
    expect(h.sessions[0].active).toBe(false);
    await done;
  });
});
