import * as vscode from "vscode";
import { childEnvironment, validExecutable } from "./config";
import {
  repositoryRoot,
  reviewArguments,
  startRun,
  type Run,
  type RunResult,
} from "./run";
import { parseReview, summary, type Finding, type Level } from "./sarif";
let output: vscode.OutputChannel | undefined;
let findings: vscode.DiagnosticCollection | undefined;
let busy = false;
let current: Run | undefined;
const severity: Record<Level, vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  note: vscode.DiagnosticSeverity.Information,
};
// target is the local folder of the active editor, else the first folder,
// with the configured executable; it says why when there is none.
function target():
  { folder: vscode.WorkspaceFolder; executable: string } | undefined {
  const active = vscode.window.activeTextEditor?.document.uri;
  const folder =
    (active && vscode.workspace.getWorkspaceFolder(active)) ??
    vscode.workspace.workspaceFolders?.[0];
  const executable = vscode.workspace
    .getConfiguration("openTrestle")
    .get<string>("executable", "trestle");
  if (!vscode.workspace.isTrusted)
    void vscode.window.showErrorMessage(
      "Trust this workspace before using Open Trestle.",
    );
  else if (!folder || folder.uri.scheme !== "file")
    void vscode.window.showErrorMessage(
      "Open a local folder of a Git repository to use Open Trestle.",
    );
  else if (!validExecutable(executable))
    void vscode.window.showErrorMessage(
      "Set openTrestle.executable to the trestle command name or its absolute path.",
    );
  else return { folder, executable };
  return undefined;
}
// offer shows a message with its buttons. A review with no result also
// offers set-up, since the usual reason is a repository with no setup yet.
async function offer(message: string, failed: boolean, setUpButton = failed) {
  const buttons = setUpButton
    ? ["Show Output", "Set Up Repository"]
    : ["Show Output"];
  const choice = failed
    ? await vscode.window.showErrorMessage(message, ...buttons)
    : await vscode.window.showInformationMessage(message, ...buttons);
  if (choice === "Show Output") output?.show(true);
  if (choice === "Set Up Repository") setUp();
}
function publish(root: string, list: Finding[]) {
  const files = new Map<string, vscode.Diagnostic[]>();
  for (const item of list) {
    const diagnostic = new vscode.Diagnostic(
      new vscode.Range(
        item.startLine - 1,
        0,
        item.endLine - 1,
        Number.MAX_SAFE_INTEGER,
      ),
      item.message,
      severity[item.level],
    );
    diagnostic.source = "open-trestle";
    diagnostic.code = item.ruleId;
    files.set(item.path, [...(files.get(item.path) ?? []), diagnostic]);
  }
  findings?.clear();
  for (const [path, diagnostics] of files)
    findings?.set(
      vscode.Uri.joinPath(vscode.Uri.file(root), ...path.split("/")),
      diagnostics,
    );
}
function finish(root: string, executable: string, result: RunResult) {
  // A refusal ends with "  -> command" lines; the reason is the line above.
  const last =
    result.stderrTail.filter((item) => !item.startsWith("  -> ")).at(-1) ?? "";
  output?.appendLine(
    `trestle review ended with exit code ${result.code ?? "none"}.`,
  );
  if (result.error?.code === "ENOENT")
    return void vscode.window.showErrorMessage(
      `Open Trestle could not start "${executable}". Install trestle, or set openTrestle.executable to its absolute path.`,
    );
  if (result.overflow)
    return void offer(
      "The review result was larger than 5 MiB and was not read.",
      true,
      false,
    );
  if (
    result.code === 2 &&
    result.stderrTail.some((item) => item.includes("stop-on-stdin-close"))
  )
    return void vscode.window.showErrorMessage(
      "This trestle is too old to review from the editor. Update trestle and try again.",
    );
  if (result.stdout.trim() === "") {
    if (result.canceled)
      return void vscode.window.showInformationMessage(
        "The review was canceled.",
      );
    return void offer(last || "The review wrote no result.", true);
  }
  let review;
  try {
    review = parseReview(result.stdout);
  } catch (error) {
    output?.appendLine(
      `The review result was rejected: ${(error as Error).message}.`,
    );
    return void offer(last || "The review result could not be read.", true);
  }
  publish(root, review.findings);
  for (const note of review.notifications) output?.appendLine(note);
  void offer(summary(review), !review.succeeded, false);
}
async function reviewBranch() {
  if (busy) {
    void vscode.window.showInformationMessage(
      "An Open Trestle review is already running.",
    );
    return;
  }
  const chosen = target();
  if (!chosen) return;
  busy = true;
  try {
    const cwd = chosen.folder.uri.fsPath;
    const env = childEnvironment(process.env);
    const root = await repositoryRoot(cwd, env);
    if (!root) {
      void vscode.window.showErrorMessage(
        "This folder is not inside a Git checkout (or git is not installed).",
      );
      return;
    }
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Open Trestle review",
        cancellable: true,
      },
      async (progress, token) => {
        current = startRun({
          command: chosen.executable,
          args: reviewArguments,
          cwd,
          env,
          onStderrLine: (line) => {
            output?.appendLine(line);
            progress.report({ message: line });
          },
        });
        token.onCancellationRequested(() => current?.cancel());
        finish(root, chosen.executable, await current.result);
      },
    );
  } finally {
    current = undefined;
    busy = false;
  }
}
function setUp() {
  const chosen = target();
  if (!chosen) return;
  vscode.window
    .createTerminal({
      name: "Open Trestle setup",
      shellPath: chosen.executable,
      shellArgs: ["init"],
      cwd: chosen.folder.uri,
    })
    .show();
}
export function activate(context: vscode.ExtensionContext) {
  output = vscode.window.createOutputChannel("Open Trestle");
  findings = vscode.languages.createDiagnosticCollection("open-trestle");
  context.subscriptions.push(
    output,
    findings,
    vscode.commands.registerCommand("openTrestle.reviewBranch", reviewBranch),
    vscode.commands.registerCommand("openTrestle.clearFindings", () =>
      findings?.clear(),
    ),
    vscode.commands.registerCommand("openTrestle.setUp", setUp),
  );
}
export function deactivate() {
  current?.cancel();
}
