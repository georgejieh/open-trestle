import * as vscode from "vscode";

export interface DiagnosticTransport {
  pull(uri: string, previousResultId?: string): Promise<unknown>;
}

const collectionName = "Open Trestle verified findings";
const maxTrackedUris = 128;
const maxItems = 1000;
const maxMessageBytes = 16 * 1024;
const maxLabelBytes = 128;
const untrustedWarning = "\n\n[untrusted review output; verify before editing]";

interface Entry {
  readonly uri: vscode.Uri;
  resultId?: string;
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedString(value: unknown, maximum: number): value is string {
  return (
    typeof value === "string" && Buffer.byteLength(value, "utf8") <= maximum
  );
}

function uint32(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= 0 &&
    value <= 0xffffffff
  );
}

function position(
  value: unknown,
): value is { line: number; character: number } {
  return record(value) && uint32(value.line) && uint32(value.character);
}

function diagnostic(value: unknown): vscode.Diagnostic {
  if (
    !record(value) ||
    !record(value.range) ||
    !position(value.range.start) ||
    !position(value.range.end) ||
    !uint32(value.severity) ||
    value.severity < 1 ||
    value.severity > 4 ||
    !boundedString(value.source, maxLabelBytes) ||
    value.source !== "open-trestle" ||
    !boundedString(value.code, maxLabelBytes) ||
    !boundedString(value.message, maxMessageBytes) ||
    !value.message.endsWith(untrustedWarning)
  ) {
    throw new Error("Invalid diagnostic.");
  }
  const { start, end } = value.range;
  if (
    start.line > end.line ||
    (start.line === end.line && start.character > end.character)
  ) {
    throw new Error("Invalid diagnostic range.");
  }
  const severity = [
    vscode.DiagnosticSeverity.Error,
    vscode.DiagnosticSeverity.Warning,
    vscode.DiagnosticSeverity.Information,
    vscode.DiagnosticSeverity.Hint,
  ][value.severity - 1]!;
  const result = new vscode.Diagnostic(
    new vscode.Range(start.line, start.character, end.line, end.character),
    value.message,
    severity,
  );
  result.source = value.source;
  result.code = value.code;
  return result;
}

function report(
  value: unknown,
  previousResultId: string | undefined,
): {
  resultId: string;
  items?: vscode.Diagnostic[];
} {
  if (
    !record(value) ||
    typeof value.resultId !== "string" ||
    !/^[0-9a-f]{64}$/.test(value.resultId) ||
    /^0{64}$/.test(value.resultId)
  ) {
    throw new Error("Invalid diagnostic report.");
  }
  if (value.kind === "unchanged") {
    if (
      Object.keys(value).some((key) => key !== "kind" && key !== "resultId") ||
      previousResultId === undefined ||
      value.resultId !== previousResultId
    ) {
      throw new Error("Invalid unchanged diagnostic report.");
    }
    return { resultId: value.resultId };
  }
  if (
    value.kind !== "full" ||
    Object.keys(value).some(
      (key) => key !== "kind" && key !== "resultId" && key !== "items",
    ) ||
    !Array.isArray(value.items) ||
    value.items.length > maxItems
  ) {
    throw new Error("Invalid full diagnostic report.");
  }
  return { resultId: value.resultId, items: value.items.map(diagnostic) };
}

function lexicalPath(path: string, root: boolean): string | undefined {
  const candidate =
    root && path !== "/" && path.endsWith("/") ? path.slice(0, -1) : path;
  if (!candidate.startsWith("/")) return undefined;
  if (candidate === "/") return root ? candidate : undefined;
  if (
    candidate
      .slice(1)
      .split("/")
      .some((segment) => segment === "" || segment === "." || segment === "..")
  ) {
    return undefined;
  }
  return candidate;
}

function fileUri(uri: vscode.Uri): boolean {
  return (
    uri.scheme === "file" &&
    uri.query === "" &&
    uri.fragment === "" &&
    !uri.authority.includes("@")
  );
}

export class Diagnostics implements vscode.Disposable {
  private readonly collection =
    vscode.languages.createDiagnosticCollection(collectionName);
  private readonly entries = new Map<string, Entry>();
  private readonly queued = new Set<string>();
  private readonly listeners: vscode.Disposable[] = [];
  private visible = new Set<string>();
  private active = false;
  private disposed = false;
  private inFlight = false;
  private rootPath: string | undefined;

  constructor(
    private readonly folder: vscode.WorkspaceFolder,
    private readonly transport: DiagnosticTransport,
    private readonly onFailure: () => void,
  ) {}

  start(): void {
    if (this.active || this.disposed) return;
    this.active = true;
    this.rootPath = fileUri(this.folder.uri)
      ? lexicalPath(this.folder.uri.path, true)
      : undefined;
    if (this.rootPath === undefined) {
      this.fail();
      return;
    }
    this.listeners.push(
      vscode.window.onDidChangeVisibleTextEditors((editors) =>
        this.updateVisible(editors),
      ),
    );
    this.listeners.push(
      vscode.workspace.onDidCloseTextDocument((document) =>
        this.close(document.uri),
      ),
    );
    this.updateVisible(vscode.window.visibleTextEditors);
  }

  dispose(): void {
    if (this.disposed) return;
    this.active = false;
    this.disposed = true;
    this.entries.clear();
    this.queued.clear();
    this.visible.clear();
    for (const listener of this.listeners.splice(0)) listener.dispose();
    this.collection.clear();
    this.collection.dispose();
  }

  private eligible(uri: vscode.Uri): boolean {
    if (
      !this.active ||
      !vscode.workspace.isTrusted ||
      !fileUri(uri) ||
      uri.authority !== this.folder.uri.authority ||
      this.rootPath === undefined
    )
      return false;
    const owner = vscode.workspace.getWorkspaceFolder(uri);
    if (!owner || owner.uri.toString() !== this.folder.uri.toString())
      return false;
    // Uri.path is already decoded. Decoding it again would turn a literal %2F filename into a slash.
    const canonical = vscode.Uri.parse(uri.toString());
    if (canonical.path !== uri.path || canonical.authority !== uri.authority)
      return false;
    const path = lexicalPath(canonical.path, false);
    const prefix = this.rootPath === "/" ? "/" : `${this.rootPath}/`;
    return (
      path !== undefined && path !== this.rootPath && path.startsWith(prefix)
    );
  }

  private updateVisible(editors: readonly vscode.TextEditor[]): void {
    if (!this.active) return;
    try {
      const next = new Set<string>();
      for (const editor of editors) {
        const uri = editor.document.uri;
        if (!this.eligible(uri)) continue;
        const key = uri.toString();
        next.add(key);
        if (!this.entries.has(key)) {
          if (this.entries.size === maxTrackedUris) {
            this.fail();
            return;
          }
          this.entries.set(key, { uri });
        }
      }
      for (const key of this.queued)
        if (!next.has(key)) this.queued.delete(key);
      for (const key of next) if (!this.visible.has(key)) this.queued.add(key);
      this.visible = next;
      this.drain();
    } catch {
      this.fail();
    }
  }

  private close(uri: vscode.Uri): void {
    if (!this.active) return;
    const key = uri.toString();
    const entry = this.entries.get(key);
    if (!entry) return;
    this.entries.delete(key);
    this.queued.delete(key);
    this.visible.delete(key);
    this.collection.delete(entry.uri);
  }

  private drain(): void {
    if (!this.active || this.inFlight) return;
    const key = this.queued.values().next().value as string | undefined;
    if (key === undefined) return;
    this.queued.delete(key);
    const entry = this.entries.get(key);
    if (!entry || !this.visible.has(key) || !this.eligible(entry.uri)) {
      this.drain();
      return;
    }
    this.inFlight = true;
    void this.pull(key, entry);
  }

  private async pull(key: string, entry: Entry): Promise<void> {
    const previousResultId = entry.resultId;
    try {
      const value = await this.transport.pull(key, previousResultId);
      if (
        !this.active ||
        this.entries.get(key) !== entry ||
        !this.eligible(entry.uri)
      )
        return;
      const accepted = report(value, previousResultId);
      if (accepted.items !== undefined)
        this.collection.set(entry.uri, accepted.items);
      entry.resultId = accepted.resultId;
    } catch {
      if (this.active && this.entries.get(key) === entry) this.fail();
    } finally {
      this.inFlight = false;
      this.drain();
    }
  }

  private fail(): void {
    if (!this.active) return;
    this.dispose();
    this.onFailure();
  }
}
