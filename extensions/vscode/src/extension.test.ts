import { beforeEach, describe, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({
  commands: new Map<string, () => Promise<void> | void>(),
  trusted: true,
  scheme: "file",
  runs: [] as { finish: (value: unknown) => void; cancel: () => void }[],
  collection: { clear: vi.fn(), set: vi.fn(), dispose() {} },
}));
vi.mock("vscode", () => ({
  workspace: {
    get isTrusted() {
      return h.trusted;
    },
    get workspaceFolders() {
      return [{ uri: { scheme: h.scheme, fsPath: "/repo/sub" } }];
    },
    getWorkspaceFolder: () => undefined,
    getConfiguration: () => ({
      get: (_key: string, fallback: unknown) => fallback,
    }),
  },
  window: {
    activeTextEditor: undefined,
    createOutputChannel: () => ({
      appendLine: vi.fn(),
      show: vi.fn(),
      dispose() {},
    }),
    showErrorMessage: vi.fn(async () => undefined),
    showInformationMessage: vi.fn(async () => undefined),
    withProgress: (_options: unknown, task: any) =>
      task({ report: vi.fn() }, { onCancellationRequested: vi.fn() }),
    createTerminal: vi.fn(() => ({ show: vi.fn() })),
  },
  languages: { createDiagnosticCollection: () => h.collection },
  commands: {
    registerCommand: (name: string, fn: any) => {
      h.commands.set(name, fn);
      return { dispose() {} };
    },
  },
  Uri: {
    file: (path: string) => ({ path }),
    joinPath: (base: { path: string }, ...parts: string[]) => ({
      path: [base.path, ...parts].join("/"),
    }),
  },
  Range: class {
    constructor(...values: number[]) {
      Object.assign(this, { values });
    }
  },
  Diagnostic: class {
    constructor(
      public range: unknown,
      public message: string,
      public severity: number,
    ) {}
  },
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2 },
  ProgressLocation: { Notification: 15 },
}));
vi.mock("./run", () => ({
  reviewArguments: ["review", "--format", "sarif", "--stop-on-stdin-close"],
  repositoryRoot: vi.fn(async () => "/repo"),
  startRun: vi.fn(() => {
    let finish!: (value: unknown) => void;
    const result = new Promise((resolve) => (finish = resolve));
    const run = { result, finish, cancel: vi.fn() };
    h.runs.push(run);
    return run;
  }),
}));
import * as vscode from "vscode";
import { activate } from "./extension";
import { startRun } from "./run";
const sarif = JSON.stringify({
  version: "2.1.0",
  runs: [
    {
      invocations: [{ executionSuccessful: true }],
      results: [
        {
          ruleId: "open-trestle/correctness",
          level: "warning",
          message: { text: "Bug" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/a.go" },
                region: { startLine: 2, endLine: 2 },
              },
            },
          ],
        },
      ],
      properties: { trestleModelReviewStatus: "findings" },
    },
  ],
});
function ended(stdout: string, stderrTail: string[] = []) {
  return { code: 3, stdout, stderrTail, canceled: false, overflow: false };
}
async function review(stdout: string, stderrTail: string[] = []) {
  const started = h.commands.get("openTrestle.reviewBranch")!();
  await vi.waitFor(() => expect(h.runs).toHaveLength(1));
  h.runs[0]!.finish(ended(stdout, stderrTail));
  await started;
}
beforeEach(() => {
  vi.clearAllMocks();
  h.runs.length = 0;
  h.trusted = true;
  h.scheme = "file";
  activate({ subscriptions: [] } as never);
});
describe("review command", () => {
  it("starts nothing in an untrusted workspace or a non-file folder", async () => {
    h.trusted = false;
    await h.commands.get("openTrestle.reviewBranch")!();
    h.trusted = true;
    h.scheme = "vscode-vfs";
    await h.commands.get("openTrestle.reviewBranch")!();
    await h.commands.get("openTrestle.setUp")!();
    expect(startRun).not.toHaveBeenCalled();
    expect(vscode.window.createTerminal).not.toHaveBeenCalled();
    expect(vscode.window.showErrorMessage).toHaveBeenCalledTimes(3);
  });
  it("runs one review at a time", async () => {
    const first = h.commands.get("openTrestle.reviewBranch")!();
    await h.commands.get("openTrestle.reviewBranch")!();
    await vi.waitFor(() => expect(h.runs).toHaveLength(1));
    h.runs[0]!.finish(ended(""));
    await first;
    expect(startRun).toHaveBeenCalledTimes(1);
    expect(startRun).toHaveBeenCalledWith(
      expect.objectContaining({ command: "trestle", cwd: "/repo/sub" }),
    );
  });
  it("replaces the findings with a valid result", async () => {
    await review(sarif);
    expect(h.collection.clear).toHaveBeenCalledTimes(1);
    const [uri, diagnostics] = h.collection.set.mock.calls[0]!;
    expect(uri).toEqual({ path: "/repo/src/a.go" });
    expect(diagnostics[0]).toMatchObject({
      severity: 1,
      source: "open-trestle",
      code: "open-trestle/correctness",
    });
    expect(diagnostics[0].range.values).toEqual([
      1,
      0,
      1,
      Number.MAX_SAFE_INTEGER,
    ]);
  });
  it("keeps the findings and shows the last line when there is no result", async () => {
    await review("", [
      "looking",
      "trestle review: this repository has no Open Trestle setup yet. Nothing was sent.",
      "  -> trestle init",
    ]);
    expect(h.collection.clear).not.toHaveBeenCalled();
    expect(h.collection.set).not.toHaveBeenCalled();
    expect(vscode.window.showErrorMessage).toHaveBeenCalledWith(
      "trestle review: this repository has no Open Trestle setup yet. Nothing was sent.",
      "Show Output",
      "Set Up Repository",
    );
  });
  it("opens trestle init in a terminal without a shell string", async () => {
    await h.commands.get("openTrestle.setUp")!();
    expect(vscode.window.createTerminal).toHaveBeenCalledWith({
      name: "Open Trestle setup",
      shellPath: "trestle",
      shellArgs: ["init"],
      cwd: { scheme: "file", fsPath: "/repo/sub" },
    });
  });
});
