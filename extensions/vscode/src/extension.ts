import * as vscode from "vscode";
import {
  buildChildEnvironment,
  buildLaunchConfiguration,
  ConfigurationError,
  isValidToken,
  type ExtensionSettings,
} from "./config";
import { Session } from "./session";
import { Diagnostics } from "./diagnostics";
const secretKey = "openTrestle.apiToken";
let client: Session | undefined;
let diagnostics: Diagnostics | undefined;
let status: vscode.StatusBarItem | undefined;
let transition = Promise.resolve();
let generation = 0;
let disposed = true;
let extensionContext: vscode.ExtensionContext;
function settings(): ExtensionSettings {
  const value = vscode.workspace.getConfiguration("openTrestle");
  return {
    executable: value.get("executable", "trestle"),
    server: value.get("server", "http://127.0.0.1:8741"),
    tenant: value.get("tenant", ""),
    repository: value.get("repository", ""),
    run: value.get("run", ""),
  };
}
function setStatus(
  kind: "disconnected" | "connecting" | "connected" | "error",
) {
  if (!status || disposed) return;
  status.text = {
    disconnected: "$(debug-disconnect) Trestle: disconnected",
    connecting: "$(sync~spin) Trestle: connecting",
    connected: "$(shield) Trestle: connected",
    error: "$(warning) Trestle: attention",
  }[kind];
  status.tooltip =
    kind === "connected"
      ? "Read-only verified findings; visible-file pulls and explicit Restart refresh. Deterministic observations remain outside LSP findings. Empty findings are not clearance."
      : kind === "error"
        ? "Diagnostics unavailable. A prior process may still be stopping; no successor starts until it closes."
        : "Connect to an exact Open Trestle review run";
  status.command =
    kind === "connecting"
      ? undefined
      : kind === "connected"
        ? "openTrestle.restart"
        : "openTrestle.connect";
}
function invalidate() {
  generation++;
  client?.invalidate();
  diagnostics?.dispose();
  diagnostics = undefined;
  void vscode.commands.executeCommand(
    "setContext",
    "openTrestle.connected",
    false,
  );
}
async function stopClient(): Promise<boolean> {
  invalidate();
  const active = client;
  if (active && !(await active.stop())) {
    setStatus("error");
    return false;
  }
  if (client === active) client = undefined;
  setStatus("disconnected");
  return true;
}
function workspaceFolder(): vscode.WorkspaceFolder | undefined {
  const active = vscode.window.activeTextEditor?.document.uri;
  return active
    ? (vscode.workspace.getWorkspaceFolder(active) ??
        vscode.workspace.workspaceFolders?.[0])
    : vscode.workspace.workspaceFolders?.[0];
}
async function startClient(interactive: boolean) {
  if (disposed) return;
  if (client) {
    if (!client.closed) return;
    if (!(await stopClient())) return;
  }
  if (!vscode.workspace.isTrusted) {
    setStatus("error");
    if (interactive)
      void vscode.window.showErrorMessage(
        "Trust this workspace before starting Open Trestle diagnostics.",
      );
    return;
  }
  const folder = workspaceFolder();
  if (!folder || folder.uri.scheme !== "file") {
    setStatus("error");
    return;
  }
  const ticket = generation;
  const token = await extensionContext.secrets.get(secretKey);
  if (disposed || generation !== ticket) return;
  if (!token) {
    setStatus("disconnected");
    if (interactive)
      void vscode.window.showWarningMessage(
        "Set an API token before connecting Open Trestle diagnostics.",
      );
    return;
  }
  let launch;
  try {
    launch = buildLaunchConfiguration(settings(), token);
  } catch (error) {
    setStatus("error");
    if (interactive && error instanceof ConfigurationError)
      void vscode.window.showErrorMessage(
        "Set a safe server URL and exact tenant, repository, and run identifiers in Open Trestle settings.",
      );
    return;
  }
  const failed = () => {
    if (client !== next) return;
    invalidate();
    setStatus("error");
    void serialized(async () => {
      if (client === next) {
        await stopClient();
        setStatus("error");
      }
    });
  };
  const next = new Session(
    launch,
    folder.uri.toString(),
    buildChildEnvironment(process.env, token),
    failed,
  );
  client = next;
  setStatus("connecting");
  try {
    await next.start();
    if (disposed || generation !== ticket || client !== next) {
      await stopClient();
      return;
    }
    diagnostics = new Diagnostics(folder, next, failed);
    diagnostics.start();
    if (disposed || generation !== ticket || client !== next) return;
    await vscode.commands.executeCommand(
      "setContext",
      "openTrestle.connected",
      true,
    );
    if (generation === ticket && !disposed) setStatus("connected");
  } catch {
    if (client === next) {
      await stopClient();
      setStatus("error");
    }
    if (interactive && !disposed)
      void vscode.window.showErrorMessage(
        "Open Trestle diagnostics could not start. Check the executable, daemon readiness, and exact review scope.",
      );
  }
}
function serialized(action: () => Promise<void>) {
  transition = transition.then(action, action).catch(() => {
    invalidate();
    setStatus("error");
  });
  return transition;
}
async function restartClient(interactive: boolean) {
  if (await stopClient()) await startClient(interactive);
}
async function setToken() {
  const token = await vscode.window.showInputBox({
    title: "Open Trestle API token",
    prompt:
      "Stored in VS Code SecretStorage and passed only to the Open Trestle LSP process.",
    password: true,
    ignoreFocusOut: true,
    validateInput: (value) =>
      isValidToken(value)
        ? undefined
        : "Use a 32 to 512 character token without spaces or control characters.",
  });
  if (token === undefined || disposed) return;
  invalidate();
  if (!(await stopClient())) return;
  await extensionContext.secrets.store(secretKey, token);
  // The SecretStorage event owns restart, including token changes made in another window.
}
async function clearToken() {
  invalidate();
  await stopClient();
  await extensionContext.secrets.delete(secretKey);
}
export async function activate(context: vscode.ExtensionContext) {
  extensionContext = context;
  disposed = false;
  generation++;
  status = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    10,
  );
  status.name = "Open Trestle diagnostics";
  status.show();
  setStatus("disconnected");
  const restart = (interactive: boolean) => {
    invalidate();
    return serialized(() => restartClient(interactive));
  };
  context.subscriptions.push(
    status,
    vscode.commands.registerCommand("openTrestle.connect", () =>
      serialized(() => startClient(true)),
    ),
    vscode.commands.registerCommand("openTrestle.restart", () => restart(true)),
    vscode.commands.registerCommand("openTrestle.setToken", () =>
      serialized(setToken),
    ),
    vscode.commands.registerCommand("openTrestle.clearToken", () => {
      invalidate();
      return serialized(clearToken);
    }),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (!event.affectsConfiguration("openTrestle")) return;
      invalidate();
      if (client) void serialized(() => restartClient(false));
    }),
    context.secrets.onDidChange((event) => {
      if (event.key === secretKey) void restart(false);
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      invalidate();
      if (client) void serialized(() => restartClient(false));
    }),
  );
  if (vscode.workspace.getConfiguration("openTrestle").get("autoStart", false))
    await serialized(() => startClient(false));
}
export async function deactivate() {
  disposed = true;
  invalidate();
  await transition;
  await stopClient();
}
