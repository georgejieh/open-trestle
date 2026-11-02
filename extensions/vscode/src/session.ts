import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { Transform } from "node:stream";
import {
  CancellationTokenSource,
  ErrorCodes,
  NullLogger,
  ResponseError,
  StreamMessageReader,
  StreamMessageWriter,
  type CancellationToken,
  type Disposable,
} from "vscode-jsonrpc/node";
import {
  createProtocolConnection,
  DocumentDiagnosticRequest,
  ExitNotification,
  InitializedNotification,
  InitializeRequest,
  ShutdownRequest,
  type ProtocolConnection,
} from "vscode-languageserver-protocol/node";
import { buildChildEnvironment, type LaunchConfiguration } from "./config";

const stdoutBudget = 8 * 1024 * 1024;
const requestDeadline = 35_000;
const stopDeadline = 1_000;
const configurationItemLimit = 100;

function failure(): Error {
  return new Error("Open Trestle protocol session is unavailable.");
}
function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function compatible(value: unknown): boolean {
  if (!record(value) || !record(value.capabilities)) return false;
  const capabilities = value.capabilities;
  const diagnostic = capabilities.diagnosticProvider;
  return (
    capabilities.positionEncoding === "utf-16" &&
    capabilities.textDocumentSync === 0 &&
    record(diagnostic) &&
    diagnostic.identifier === "open-trestle" &&
    diagnostic.interFileDependencies === true &&
    diagnostic.workspaceDiagnostics === false
  );
}
async function bounded<T>(
  operation: Promise<T>,
  milliseconds: number,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(failure()), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export class Session {
  private child: ChildProcessWithoutNullStreams | undefined;
  private connection: ProtocolConnection | undefined;
  private guard: Transform | undefined;
  private readonly disposables: Disposable[] = [];
  private readonly pending = new Set<() => void>();
  private readonly closeWaiters = new Set<() => void>();
  private active = false;
  private initialized = false;
  private started = false;
  private closeObserved = true;
  private pulling = false;
  private stopping: Promise<boolean> | undefined;

  constructor(
    private readonly launch: LaunchConfiguration,
    private readonly rootUri: string,
    private readonly environment: NodeJS.ProcessEnv,
    private readonly onFailure: () => void,
  ) {}

  get closed(): boolean {
    return this.closeObserved;
  }

  async start(): Promise<void> {
    if (this.started) throw failure();
    this.started = true;
    this.active = true;
    this.closeObserved = false;
    try {
      this.child = spawn(this.launch.command, [...this.launch.args], {
        shell: false,
        stdio: ["pipe", "pipe", "pipe"],
        env: buildChildEnvironment(
          this.environment,
          this.launch.environment.OPEN_TRESTLE_API_TOKEN,
        ),
      });
      const child = this.child;
      child.on("error", () => this.fail());
      child.once("close", () => {
        this.closeObserved = true;
        for (const resolve of this.closeWaiters) resolve();
        this.closeWaiters.clear();
        this.fail();
        this.disposeTransport();
        child.stdin.destroy();
        child.stdout.destroy();
        child.stderr.destroy();
      });
      child.stderr.on("error", () => this.fail());
      child.stderr.resume();
      child.stdout.on("error", () => this.fail());
      child.stdin.on("error", () => this.fail());
      let admitted = 0;
      this.guard = new Transform({
        transform: (chunk: Buffer, _encoding, callback) => {
          admitted += chunk.length;
          if (admitted > stdoutBudget) {
            this.fail();
            callback();
          } else {
            callback(null, chunk);
          }
        },
      });
      this.guard.on("error", () => this.fail());
      const connection = createProtocolConnection(
        new StreamMessageReader(this.guard),
        new StreamMessageWriter(child.stdin),
        NullLogger,
      );
      this.connection = connection;
      this.installDenials(connection);
      this.disposables.push(
        connection.onError(() => this.fail()),
        connection.onClose(() => this.fail()),
        connection.onDispose(() => this.fail()),
      );
      connection.listen();
      child.stdout.pipe(this.guard);
      const result = await this.request((token) =>
        connection.sendRequest(
          InitializeRequest.type,
          {
            processId: null,
            rootUri: this.rootUri,
            workspaceFolders: [{ uri: this.rootUri, name: "Open Trestle" }],
            initializationOptions: this.launch.initializationOptions,
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
          token,
        ),
      );
      if (!this.active || !compatible(result)) throw failure();
      await this.request(() =>
        connection.sendNotification(InitializedNotification.type, {}),
      );
      if (!this.active) throw failure();
      this.initialized = true;
    } catch {
      if (!this.child) this.closeObserved = true;
      this.fail();
      throw failure();
    }
  }

  async pull(uri: string, previousResultId?: string): Promise<unknown> {
    const connection = this.connection;
    if (!this.active || !this.initialized || !connection || this.pulling)
      throw failure();
    this.pulling = true;
    try {
      return await this.request((token) =>
        connection.sendRequest(
          DocumentDiagnosticRequest.type,
          {
            textDocument: { uri },
            ...(previousResultId === undefined ? {} : { previousResultId }),
          },
          token,
        ),
      );
    } catch {
      this.fail();
      throw failure();
    } finally {
      this.pulling = false;
    }
  }

  invalidate(): void {
    this.active = false;
    for (const cancel of this.pending) cancel();
    this.pending.clear();
  }

  stop(): Promise<boolean> {
    this.invalidate();
    this.started = true;
    if (this.closeObserved) return Promise.resolve(true);
    if (this.stopping) return this.stopping;
    this.stopping = this.retire().finally(() => {
      this.stopping = undefined;
    });
    return this.stopping;
  }

  private fail(): void {
    if (!this.active) return;
    this.invalidate();
    try {
      this.onFailure();
    } catch {
      /* Caller failure cannot abandon child ownership. */
    }
    void this.stop().catch(() => undefined);
  }

  private async request<T>(
    send: (token: CancellationToken) => Promise<T>,
  ): Promise<T> {
    if (!this.active) throw failure();
    const source = new CancellationTokenSource();
    let cancel: () => void = () => undefined;
    const canceled = new Promise<never>((_, reject) => {
      cancel = () => {
        source.cancel();
        reject(failure());
      };
    });
    this.pending.add(cancel);
    try {
      const result = await bounded(
        Promise.race([send(source.token), canceled]),
        requestDeadline,
      );
      if (!this.active) throw failure();
      return result;
    } finally {
      this.pending.delete(cancel);
      source.dispose();
    }
  }

  private installDenials(connection: ProtocolConnection): void {
    this.disposables.push(
      connection.onRequest("workspace/applyEdit", () => ({
        applied: false,
        failureReason: "Open Trestle is read-only.",
      })),
      connection.onRequest("window/showDocument", () => ({ success: false })),
      connection.onRequest("client/registerCapability", () => null),
      connection.onRequest("client/unregisterCapability", () => null),
      connection.onRequest("workspace/configuration", (params: unknown) => {
        if (
          !record(params) ||
          !Array.isArray(params.items) ||
          params.items.length > configurationItemLimit ||
          !params.items.every(
            (item: unknown) =>
              record(item) &&
              (item.section === undefined ||
                typeof item.section === "string") &&
              (item.scopeUri === undefined ||
                typeof item.scopeUri === "string"),
          )
        ) {
          return new ResponseError(
            ErrorCodes.InvalidParams,
            "Invalid configuration request.",
          );
        }
        return params.items.map(() => null);
      }),
      connection.onNotification(
        "textDocument/publishDiagnostics",
        () => undefined,
      ),
    );
  }

  private async retire(): Promise<boolean> {
    const connection = this.connection;
    try {
      await bounded(
        (async () => {
          if (this.initialized && connection) {
            await connection.sendRequest(ShutdownRequest.type);
            await connection.sendNotification(ExitNotification.type);
          }
          await this.waitForClose();
        })(),
        stopDeadline,
      );
    } catch {
      /* Escalate without treating protocol completion as child closure. */
    }
    this.disposeTransport();
    for (const signal of ["SIGTERM", "SIGKILL"] as const) {
      if (this.closeObserved) break;
      try {
        this.child?.kill(signal);
      } catch {
        /* Closure remains independently observed. */
      }
      await this.waitForClose();
    }
    return this.closeObserved;
  }

  private waitForClose(): Promise<void> {
    if (this.closeObserved) return Promise.resolve();
    return new Promise((resolve) => {
      const complete = (): void => {
        clearTimeout(timer);
        this.closeWaiters.delete(complete);
        resolve();
      };
      const timer = setTimeout(complete, stopDeadline);
      this.closeWaiters.add(complete);
    });
  }

  private disposeTransport(): void {
    for (const disposable of this.disposables.splice(0)) {
      try {
        disposable.dispose();
      } catch {
        /* Teardown must still observe child closure. */
      }
    }
    try {
      this.connection?.dispose();
    } catch {
      /* Continue direct-child retirement. */
    }
    this.connection = undefined;
    if (this.guard) {
      this.child?.stdout.unpipe(this.guard);
      this.guard.destroy();
      this.guard = undefined;
      this.child?.stdout.resume();
    }
  }
}
