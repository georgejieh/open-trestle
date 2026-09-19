import * as vscode from "vscode";
import {
  CloseAction,
  ErrorAction,
  LanguageClient,
  RevealOutputChannelOn,
  State,
  type InitializeParams,
  type LanguageClientOptions,
  type ServerOptions,
} from "vscode-languageclient/node";
import {
  buildChildEnvironment,
  buildLaunchConfiguration,
  ConfigurationError,
  isValidToken,
  type ExtensionSettings,
} from "./config";
import { readOnlyMiddleware, restrictClientCapabilities } from "./readonly";
class ReadOnlyLanguageClient extends LanguageClient {
  protected override fillInitializeParams(params: InitializeParams): void {
    super.fillInitializeParams(params);
    restrictClientCapabilities(params.capabilities);
  }
}
const secretKey = "openTrestle.apiToken";
let client: LanguageClient | undefined;
let clientStateSubscription: vscode.Disposable | undefined;
let status: vscode.StatusBarItem;
let output: vscode.LogOutputChannel;
let transition = Promise.resolve();
function settings(): ExtensionSettings {
  const value = vscode.workspace.getConfiguration("openTrestle");
  return {
    executable: value.get<string>("executable", "trestle"),
    server: value.get<string>("server", "http://127.0.0.1:8741"),
    tenant: value.get<string>("tenant", ""),
    repository: value.get<string>("repository", ""),
    run: value.get<string>("run", ""),
  };
}
function setStatus(
  kind: "disconnected" | "connecting" | "connected" | "error",
) {
  switch (kind) {
    case "connected":
      status.text = "$(verified) Trestle: connected";
      status.tooltip = "Read-only verified diagnostics are active";
      status.command = "openTrestle.restart";
      break;
    case "connecting":
      status.text = "$(sync~spin) Trestle: connecting";
      status.tooltip = "Starting the read-only diagnostics client";
      status.command = undefined;
      break;
    case "error":
      status.text = "$(warning) Trestle: attention";
      status.tooltip = "Open Trestle diagnostics could not start";
      status.command = "openTrestle.connect";
      break;
    default:
      status.text = "$(debug-disconnect) Trestle: disconnected";
      status.tooltip = "Connect to an exact Open Trestle review run";
      status.command = "openTrestle.connect";
  }
}
async function stopClient() {
  const active = client;
  client = undefined;
  if (active) {
    try {
      await active.stop();
    } catch {}
  }
  clientStateSubscription?.dispose();
  clientStateSubscription = undefined;
  await vscode.commands.executeCommand(
    "setContext",
    "openTrestle.connected",
    false,
  );
  setStatus("disconnected");
}
function workspaceFolder(): vscode.WorkspaceFolder | undefined {
  const active = vscode.window.activeTextEditor?.document.uri;
  return active
    ? (vscode.workspace.getWorkspaceFolder(active) ??
        vscode.workspace.workspaceFolders?.[0])
    : vscode.workspace.workspaceFolders?.[0];
}
async function startClient(interactive: boolean) {
  if (!vscode.workspace.isTrusted) {
    setStatus("error");
    if (interactive)
      void vscode.window.showErrorMessage(
        "Trust this workspace before starting Open Trestle diagnostics.",
      );
    return;
  }
  if (client?.state === State.Running) return;
  const folder = workspaceFolder();
  if (!folder) {
    setStatus("error");
    if (interactive)
      void vscode.window.showErrorMessage(
        "Open a workspace folder before connecting Open Trestle diagnostics.",
      );
    return;
  }
  const token = await extensionContext.secrets.get(secretKey);
  if (!token) {
    setStatus("disconnected");
    if (interactive) {
      const action = await vscode.window.showWarningMessage(
        "Set an API token before connecting Open Trestle diagnostics.",
        "Set token",
      );
      if (action === "Set token") await setToken();
    }
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
  const serverOptions: ServerOptions = {
    command: launch.command,
    args: [...launch.args],
    options: {
      env: buildChildEnvironment(
        process.env,
        launch.environment.OPEN_TRESTLE_API_TOKEN,
      ),
    },
  };
  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", pattern: "**/*" }],
    workspaceFolder: folder,
    initializationOptions: launch.initializationOptions,
    outputChannel: output,
    revealOutputChannelOn: RevealOutputChannelOn.Never,
    diagnosticCollectionName: "Open Trestle verified findings",
    middleware: readOnlyMiddleware,
    errorHandler: {
      error: () => ({ action: ErrorAction.Shutdown }),
      closed: () => ({ action: CloseAction.DoNotRestart }),
    },
  };
  const next = new ReadOnlyLanguageClient(
    "openTrestle",
    "Open Trestle",
    serverOptions,
    clientOptions,
  );
  client = next;
  clientStateSubscription?.dispose();
  clientStateSubscription = next.onDidChangeState((event) => {
    if (client === next && event.newState === State.Stopped) {
      client = undefined;
      clientStateSubscription?.dispose();
      clientStateSubscription = undefined;
      void vscode.commands.executeCommand(
        "setContext",
        "openTrestle.connected",
        false,
      );
      setStatus("error");
    }
  });
  setStatus("connecting");
  try {
    await next.start();
    if (client !== next) {
      await next.stop();
      return;
    }
    await vscode.commands.executeCommand(
      "setContext",
      "openTrestle.connected",
      true,
    );
    setStatus("connected");
  } catch {
    if (client === next) client = undefined;
    try {
      await next.stop();
    } catch {}
    await vscode.commands.executeCommand(
      "setContext",
      "openTrestle.connected",
      false,
    );
    setStatus("error");
    if (interactive)
      void vscode.window.showErrorMessage(
        "Open Trestle diagnostics could not start. Check the executable, daemon readiness, and exact review scope.",
      );
  }
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
  if (token === undefined) return;
  await extensionContext.secrets.store(secretKey, token);
  void vscode.window.showInformationMessage(
    "Open Trestle API token stored in VS Code SecretStorage.",
  );
  await restartClient(true);
}
async function clearToken() {
  await stopClient();
  await extensionContext.secrets.delete(secretKey);
  void vscode.window.showInformationMessage(
    "Open Trestle API token removed from VS Code SecretStorage.",
  );
}
async function restartClient(interactive: boolean) {
  await stopClient();
  await startClient(interactive);
}
function serialized(action: () => Promise<void>) {
  transition = transition.then(action, action).catch(() => {
    setStatus("error");
    void vscode.window.showErrorMessage(
      "Open Trestle could not complete the requested extension operation.",
    );
  });
  return transition;
}
let extensionContext: vscode.ExtensionContext;
export async function activate(context: vscode.ExtensionContext) {
  extensionContext = context;
  output = vscode.window.createOutputChannel("Open Trestle", { log: true });
  status = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    10,
  );
  status.name = "Open Trestle diagnostics";
  status.show();
  setStatus("disconnected");
  context.subscriptions.push(
    output,
    status,
    vscode.commands.registerCommand("openTrestle.connect", () =>
      serialized(() => startClient(true)),
    ),
    vscode.commands.registerCommand("openTrestle.setToken", () =>
      serialized(setToken),
    ),
    vscode.commands.registerCommand("openTrestle.clearToken", () =>
      serialized(clearToken),
    ),
    vscode.commands.registerCommand("openTrestle.restart", () =>
      serialized(() => restartClient(true)),
    ),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("openTrestle") && client)
        void serialized(() => restartClient(false));
    }),
  );
  if (
    vscode.workspace
      .getConfiguration("openTrestle")
      .get<boolean>("autoStart", false)
  )
    await serialized(() => startClient(false));
}
export async function deactivate() {
  await transition.catch(() => {});
  await stopClient();
}
