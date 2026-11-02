import { beforeEach, describe, expect, it, vi } from "vitest";
import * as vscode from "vscode";
import { Diagnostics } from "./diagnostics";

const host = vi.hoisted(() => ({
  visible: [] as vscode.TextEditor[],
  visibleListeners: new Set<(editors: readonly vscode.TextEditor[]) => void>(),
  closeListeners: new Set<(document: vscode.TextDocument) => void>(),
  collection: new Map<string, readonly vscode.Diagnostic[]>(),
  published: vi.fn(),
  cleared: vi.fn(),
  disposed: vi.fn(),
  collectionName: "",
  folder: undefined as vscode.WorkspaceFolder | undefined,
  membership: vi.fn(),
  trusted: true,
  readText: vi.fn(() => {
    throw new Error("document content must not be read");
  }),
}));

vi.mock("vscode", () => {
  class Uri {
    constructor(
      readonly scheme: string,
      readonly authority: string,
      readonly path: string,
      readonly query = "",
      readonly fragment = "",
    ) {}
    static parse(raw: string): Uri {
      const match =
        /^([^:]+):(?:\/\/([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/.exec(
          raw,
        )!;
      return new Uri(
        match[1]!,
        match[2] ?? "",
        decodeURIComponent(match[3]!),
        match[4],
        match[5],
      );
    }
    static file(path: string): Uri {
      return new Uri("file", "", path);
    }
    toString(): string {
      return `${this.scheme}://${this.authority}${this.path.split("/").map(encodeURIComponent).join("/")}${this.query ? `?${this.query}` : ""}${this.fragment ? `#${this.fragment}` : ""}`;
    }
  }
  class Position {
    constructor(
      readonly line: number,
      readonly character: number,
    ) {}
  }
  class Range {
    readonly start: Position;
    readonly end: Position;
    constructor(sl: number, sc: number, el: number, ec: number) {
      this.start = new Position(sl, sc);
      this.end = new Position(el, ec);
    }
  }
  class Diagnostic {
    constructor(
      readonly range: Range,
      readonly message: string,
      readonly severity: number,
    ) {}
  }
  return {
    Uri,
    Position,
    Range,
    Diagnostic,
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
    languages: {
      createDiagnosticCollection: (name: string) => {
        host.collectionName = name;
        return {
          set: (uri: Uri, items: readonly vscode.Diagnostic[]) => {
            host.published(uri.toString(), items);
            host.collection.set(uri.toString(), items);
          },
          delete: (uri: Uri) => host.collection.delete(uri.toString()),
          clear: () => {
            host.cleared();
            host.collection.clear();
          },
          dispose: () => {
            host.disposed();
            host.collection.clear();
          },
        };
      },
    },
    window: {
      get visibleTextEditors() {
        expect(host.visibleListeners.size).toBe(1);
        expect(host.closeListeners.size).toBe(1);
        return host.visible;
      },
      onDidChangeVisibleTextEditors: (
        listener: (editors: readonly vscode.TextEditor[]) => void,
      ) => {
        host.visibleListeners.add(listener);
        return { dispose: () => host.visibleListeners.delete(listener) };
      },
    },
    workspace: {
      get isTrusted() {
        return host.trusted;
      },
      getWorkspaceFolder: (uri: Uri) => host.membership(uri),
      onDidCloseTextDocument: (
        listener: (document: vscode.TextDocument) => void,
      ) => {
        host.closeListeners.add(listener);
        return { dispose: () => host.closeListeners.delete(listener) };
      },
    },
  };
});

const warning = "\n\n[untrusted review output; verify before editing]";
const firstId = "a".repeat(64);
const nextId = "b".repeat(64);
function item(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    range: { start: { line: 1, character: 2 }, end: { line: 3, character: 4 } },
    severity: 2,
    source: "open-trestle",
    code: "fingerprint",
    message: `finding: command:evil and [text](command:evil)${warning}`,
    data: { command: "evil", deep: { arbitrary: true } },
    command: { command: "evil" },
    codeDescription: { href: "command:evil" },
    tags: [1],
    relatedInformation: [{ location: "file:///other" }],
    ...overrides,
  };
}
function full(items: unknown[] = [item()], resultId = firstId): unknown {
  return { kind: "full", resultId, items };
}
function editor(uri: vscode.Uri): vscode.TextEditor {
  return {
    document: { uri, getText: host.readText },
  } as unknown as vscode.TextEditor;
}
function show(...uris: vscode.Uri[]): void {
  host.visible = uris.map(editor);
  for (const listener of [...host.visibleListeners]) listener(host.visible);
}
function close(uri: vscode.Uri): void {
  host.visible = host.visible.filter(
    (value) => value.document.uri.toString() !== uri.toString(),
  );
  for (const listener of [...host.closeListeners])
    listener(editor(uri).document);
}
async function flush(): Promise<void> {
  for (let i = 0; i < 8; i++) await Promise.resolve();
}
function deferred(): {
  promise: Promise<unknown>;
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
} {
  let resolve!: (value: unknown) => void;
  let reject!: (reason: unknown) => void;
  return {
    promise: new Promise((yes, no) => {
      resolve = yes;
      reject = no;
    }),
    resolve,
    reject,
  };
}
function setup(pull = vi.fn(async (): Promise<unknown> => full())) {
  const failed = vi.fn(() => {
    expect(host.collection.size).toBe(0);
    expect(host.visibleListeners.size + host.closeListeners.size).toBe(0);
  });
  const diagnostics = new Diagnostics(host.folder!, { pull }, failed);
  diagnostics.start();
  return { diagnostics, pull, failed };
}
beforeEach(() => {
  vi.clearAllMocks();
  host.visible = [];
  host.visibleListeners.clear();
  host.closeListeners.clear();
  host.collection.clear();
  host.folder = {
    uri: vscode.Uri.file("/chosen/root"),
    index: 0,
    name: "root",
  };
  host.membership.mockImplementation(() => host.folder);
  host.trusted = true;
});

describe("native verified findings", () => {
  it("registers listeners before the snapshot, deduplicates and projects only inert native fields", async () => {
    const uri = vscode.Uri.file("/chosen/root/file.ts");
    host.visible = [editor(uri), editor(uri)];
    const { diagnostics, pull, failed } = setup(
      vi.fn(async () =>
        full([1, 2, 3, 4].map((severity) => item({ severity }))),
      ),
    );
    await flush();
    expect(host.collectionName).toBe("Open Trestle verified findings");
    expect(pull.mock.calls).toEqual([[uri.toString(), undefined]]);
    const values = host.collection.get(uri.toString())!;
    expect(values.map((value) => value.severity)).toEqual([0, 1, 2, 3]);
    expect(values[0]).toEqual({
      range: new vscode.Range(1, 2, 3, 4),
      severity: 0,
      message: item().message,
      source: "open-trestle",
      code: "fingerprint",
    });
    expect(host.readText).not.toHaveBeenCalled();
    expect(failed).not.toHaveBeenCalled();
    diagnostics.dispose();
  });
  it("retains hidden findings and baselines, accepts unchanged, then full empty", async () => {
    const uri = vscode.Uri.file("/chosen/root/a.ts");
    const pull = vi.fn(async (): Promise<unknown> => full());
    pull
      .mockResolvedValueOnce(full())
      .mockResolvedValueOnce({ kind: "unchanged", resultId: firstId })
      .mockResolvedValueOnce(full([], nextId));
    const { diagnostics } = setup(pull);
    show(uri);
    await flush();
    show();
    expect(host.collection.get(uri.toString())).toHaveLength(1);
    show(uri);
    await flush();
    expect(host.published).toHaveBeenCalledTimes(1);
    show();
    show(uri);
    await flush();
    expect(pull.mock.calls).toEqual([
      [uri.toString(), undefined],
      [uri.toString(), firstId],
      [uri.toString(), firstId],
    ]);
    expect(host.collection.get(uri.toString())).toEqual([]);
    close(uri);
    show(uri);
    await flush();
    expect(pull.mock.calls.at(-1)).toEqual([uri.toString(), undefined]);
    diagnostics.dispose();
  });
  it.each(["close", "dispose", "close-reopen"])(
    "invalidates a pending pull on %s",
    async (action) => {
      const uri = vscode.Uri.file("/chosen/root/a.ts");
      const pending = deferred();
      const pull = vi
        .fn(async (): Promise<unknown> => full([], nextId))
        .mockReturnValueOnce(pending.promise);
      const { diagnostics, failed } = setup(pull);
      show(uri);
      if (action === "dispose") diagnostics.dispose();
      else {
        close(uri);
        if (action === "close-reopen") show(uri);
      }
      pending.resolve(full());
      await flush();
      expect(
        host.published.mock.calls.every(([, items]) => items.length === 0),
      ).toBe(true);
      if (action === "close-reopen") {
        expect(pull.mock.calls).toEqual([
          [uri.toString(), undefined],
          [uri.toString(), undefined],
        ]);
      } else expect(host.collection.size).toBe(0);
      expect(failed).not.toHaveBeenCalled();
      diagnostics.dispose();
    },
  );
  it("keeps one pull in flight, coalesces reveal and drops hidden queued work", async () => {
    const [a, b, c] = ["a", "b", "c"].map((name) =>
      vscode.Uri.file(`/chosen/root/${name}.ts`),
    );
    const pending = deferred();
    const pull = vi
      .fn(async (): Promise<unknown> => full())
      .mockReturnValueOnce(pending.promise);
    const { diagnostics } = setup(pull);
    show(a!, b!, c!);
    show();
    show(a!, b!);
    show();
    show(a!, b!);
    expect(pull).toHaveBeenCalledTimes(1);
    pending.resolve(full());
    await flush();
    expect(pull.mock.calls).toEqual([
      [a!.toString(), undefined],
      [a!.toString(), firstId],
      [b!.toString(), undefined],
    ]);
    diagnostics.dispose();
  });
  it.each(["close", "dispose", "close-reopen"])(
    "ignores a retired pull rejection after %s",
    async (action) => {
      const uri = vscode.Uri.file("/chosen/root/a.ts");
      const pending = deferred();
      const pull = vi
        .fn(async (): Promise<unknown> => full())
        .mockReturnValueOnce(pending.promise);
      const { diagnostics, failed } = setup(pull);
      show(uri);
      if (action === "dispose") diagnostics.dispose();
      else {
        close(uri);
        if (action === "close-reopen") show(uri);
      }
      pending.reject(new Error("retired error"));
      await flush();
      expect(failed).not.toHaveBeenCalled();
      if (action === "close-reopen") {
        expect(pull.mock.calls).toEqual([
          [uri.toString(), undefined],
          [uri.toString(), undefined],
        ]);
        expect(host.collection.get(uri.toString())).toHaveLength(1);
      } else expect(host.collection.size).toBe(0);
      diagnostics.dispose();
    },
  );
  it("invalidates captured event callbacks synchronously on disposal", async () => {
    const { diagnostics, pull, failed } = setup();
    const visibility = [...host.visibleListeners][0]!;
    const closed = [...host.closeListeners][0]!;
    diagnostics.dispose();
    const uri = vscode.Uri.file("/chosen/root/a.ts");
    visibility([editor(uri)]);
    closed(editor(uri).document);
    diagnostics.start();
    await flush();
    expect(pull).not.toHaveBeenCalled();
    expect(failed).not.toHaveBeenCalled();
    expect(host.collection.size).toBe(0);
    expect(host.disposed).toHaveBeenCalledTimes(1);
  });
  it("handles rejected pulls once after invalidating and never publishes late work", async () => {
    const pending = deferred();
    const { diagnostics, failed } = setup(vi.fn(() => pending.promise));
    show(vscode.Uri.file("/chosen/root/a.ts"));
    pending.reject(new Error("untrusted secret text"));
    await flush();
    show(vscode.Uri.file("/chosen/root/b.ts"));
    expect(failed).toHaveBeenCalledTimes(1);
    expect(host.published).not.toHaveBeenCalled();
    diagnostics.dispose();
  });
});

describe("selected-root URI authority", () => {
  it.each([
    ["/chosen/root", "file:///chosen/root/space%20name%23%25%E9%9B%AA.ts"],
    ["/chosen/root", "file:///chosen/root/literal%252Fpercent.ts"],
    ["/chosen/root", "file:///chosen/root/directory%2Ffile.ts"],
    ["/chosen/root", "file:///chosen/root/.dotfile"],
    ["/C:/Work", "file:///C:/Work/space%20name.ts"],
    ["file://server/share/root", "file://server/share/root/%E9%9B%AA.ts"],
    ["/", "file:///root.ts"],
    ["/chosen/root/", "file:///chosen/root/file.ts"],
  ])("pulls host-canonical spelling under %s", async (root, raw) => {
    host.folder = {
      uri: root.startsWith("file:")
        ? vscode.Uri.parse(root)
        : vscode.Uri.file(root),
      index: 0,
      name: "root",
    };
    const uri = vscode.Uri.parse(raw);
    host.visible = [editor(uri)];
    const { diagnostics, pull, failed } = setup();
    await flush();
    expect(pull.mock.calls).toEqual([[uri.toString(), undefined]]);
    expect(failed).not.toHaveBeenCalled();
    diagnostics.dispose();
  });
  it.each([
    "file:///chosen/root",
    "file:///chosen/root/",
    "file:///chosen/root-other/a.ts",
    "file:///outside/a.ts",
    "file:///chosen/root/a/../b.ts",
    "file:///chosen/root/%2e%2e/out.ts",
    "file:///chosen/root/a//b.ts",
    "file:///chosen/root/a%2F..%2Fb.ts",
    "file:///chosen/root/a/./b.ts",
    "file:///chosen/root/file.ts?query",
    "file:///chosen/root/file.ts#fragment",
    "file://other/chosen/root/file.ts",
    "file://user@host/chosen/root/file.ts",
    "untitled:/chosen/root/file.ts",
    "vscode-notebook-cell:///chosen/root/file.ts",
  ])("skips ineligible URI %s", async (raw) => {
    host.visible = [editor(vscode.Uri.parse(raw))];
    const { diagnostics, pull, failed } = setup();
    await flush();
    expect(pull).not.toHaveBeenCalled();
    expect(failed).not.toHaveBeenCalled();
    diagnostics.dispose();
  });
  it("excludes nested workspace membership and revoked trust", async () => {
    host.membership.mockReturnValue({
      uri: vscode.Uri.file("/chosen/root/nested"),
      index: 1,
      name: "nested",
    });
    const { diagnostics, pull } = setup();
    show(vscode.Uri.file("/chosen/root/nested/file.ts"));
    host.trusted = false;
    host.membership.mockReturnValue(host.folder);
    show(vscode.Uri.file("/chosen/root/a.ts"));
    await flush();
    expect(pull).not.toHaveBeenCalled();
    diagnostics.dispose();
  });
});

describe("bounded atomic reports", () => {
  const malformed: unknown[] = [
    null,
    [],
    {},
    { kind: "partial", resultId: firstId, items: [] },
    { kind: "full", resultId: firstId, items: [], relatedDocuments: {} },
    { kind: "full", resultId: firstId, items: [], extra: true },
    { kind: "unchanged", resultId: firstId },
    { kind: "unchanged", resultId: firstId, items: [] },
    full([], "A".repeat(64)),
    full([], "0".repeat(64)),
    full([], "a".repeat(65)),
    { kind: "full", resultId: firstId, items: {} },
    full(Array.from({ length: 1001 }, () => item())),
    ...[
      { severity: 0 },
      { severity: 5 },
      { severity: 1.5 },
      { source: "other" },
      { source: "a".repeat(129) },
      { code: { value: "x", target: "command:evil" } },
      { code: "é".repeat(65) },
      { message: "no warning" },
      { message: "é".repeat(8192) + warning },
      { message: 3 },
      {
        range: {
          start: { line: -1, character: 0 },
          end: { line: 1, character: 0 },
        },
      },
      {
        range: {
          start: { line: NaN, character: 0 },
          end: { line: 1, character: 0 },
        },
      },
      {
        range: {
          start: { line: 0, character: 0 },
          end: { line: 2 ** 32, character: 0 },
        },
      },
      {
        range: {
          start: { line: 1, character: 3 },
          end: { line: 1, character: 2 },
        },
      },
      {
        range: {
          start: { line: 1, character: 1.1 },
          end: { line: 2, character: 0 },
        },
      },
      {
        range: {
          start: { line: 0, character: 0 },
          end: { line: 1, character: Infinity },
        },
      },
    ].map((overrides) => full([item(), item(overrides)])),
  ];
  it.each(malformed.map((report, index) => [index, report] as const))(
    "rejects malformed report %s without partial publication",
    async (_index, report) => {
      const { diagnostics, failed } = setup(vi.fn(async () => report));
      show(vscode.Uri.file("/chosen/root/a.ts"));
      await flush();
      expect(failed).toHaveBeenCalledTimes(1);
      expect(host.published).not.toHaveBeenCalled();
      diagnostics.dispose();
    },
  );
  it("rejects changed unchanged identity after an accepted baseline", async () => {
    const pull = vi
      .fn(async (): Promise<unknown> => full())
      .mockResolvedValueOnce(full())
      .mockResolvedValueOnce({ kind: "unchanged", resultId: nextId });
    const { diagnostics, failed } = setup(pull);
    const uri = vscode.Uri.file("/chosen/root/a.ts");
    show(uri);
    await flush();
    show();
    show(uri);
    await flush();
    expect(failed).toHaveBeenCalledTimes(1);
    expect(host.collection.size).toBe(0);
    diagnostics.dispose();
  });
  it("accepts exact item/string/range bounds without copying action metadata", async () => {
    const bounded = item({
      code: "é".repeat(64),
      message: "x".repeat(16384 - Buffer.byteLength(warning)) + warning,
      range: {
        start: { line: 0, character: 0 },
        end: { line: 2 ** 32 - 1, character: 2 ** 32 - 1 },
      },
    });
    const { diagnostics, failed } = setup(
      vi.fn(async () => full(Array.from({ length: 1000 }, () => bounded))),
    );
    const uri = vscode.Uri.file("/chosen/root/a.ts");
    show(uri);
    await flush();
    expect(host.collection.get(uri.toString())).toHaveLength(1000);
    expect(failed).not.toHaveBeenCalled();
    diagnostics.dispose();
  });
  it("fails at tracked URI capacity instead of silently dropping hidden baselines", async () => {
    const { diagnostics, pull, failed } = setup();
    for (let index = 0; index < 128; index++) {
      show(vscode.Uri.file(`/chosen/root/${index}.ts`));
      await flush();
    }
    expect(failed).not.toHaveBeenCalled();
    show(vscode.Uri.file("/chosen/root/overflow.ts"));
    await flush();
    expect(failed).toHaveBeenCalledTimes(1);
    expect(pull).toHaveBeenCalledTimes(128);
    expect(host.collection.size).toBe(0);
    diagnostics.dispose();
  });
});
