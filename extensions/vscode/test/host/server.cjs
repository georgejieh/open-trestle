const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { StreamMessageReader, StreamMessageWriter } = require("vscode-jsonrpc/node");
const { createProtocolConnection } = require("vscode-languageserver-protocol/node");
const directory = path.dirname(process.argv[1]);
const wire = path.join(directory, "wire.jsonl");
const setting = JSON.parse(fs.readFileSync(path.join(directory, "mode.json"), "utf8"));
const manifestPersistence = setting.scenario === "manifest-persistence";
const record = (event) => fs.appendFileSync(wire, JSON.stringify({ pid: process.pid, time: Date.now(), ...(manifestPersistence ? { phase: setting.phase } : {}), ...event }) + "\n");
assert.deepEqual(process.argv.slice(2), ["lsp", "--server", "http://127.0.0.1:8741"]);
const mode = () => JSON.parse(fs.readFileSync(path.join(directory, "mode.json"), "utf8"));
const connection = createProtocolConnection(new StreamMessageReader(process.stdin), new StreamMessageWriter(process.stdout));
record({ event: "spawn", argv: process.argv.slice(2), tokenPresent: typeof process.env.OPEN_TRESTLE_API_TOKEN === "string", ...(manifestPersistence ? { tokenMatchesSeed: process.env.OPEN_TRESTLE_API_TOKEN === "synthetic-host-token-canary-0000000000" } : {}) });
let held;
let rootUri;
const item = { range: { start: { line: 0, character: 0 }, end: { line: 1, character: 0 } }, severity: 2, source: "open-trestle", code: "fingerprint", message: "finding: message\n\n[untrusted review output; verify before editing]" };
connection.onRequest("initialize", (params) => {
  record({ event: "request", method: "initialize", params });
  rootUri = params.rootUri;
  return { capabilities: { positionEncoding: "utf-16", textDocumentSync: 0, diagnosticProvider: { identifier: "open-trestle", interFileDependencies: true, workspaceDiagnostics: false } } };
});
connection.onNotification("initialized", () => record({ event: "notification", method: "initialized" }));
connection.onNotification((method, params) => record({ event: "notification", method, params }));
async function attack(uri) {
  const requests = [
    ["workspace/applyEdit", { edit: { changes: { [uri]: [{ range: item.range, newText: "FORBIDDEN EDIT" }] } } }],
    ["window/showDocument", { uri: rootUri + "/forbidden.txt", takeFocus: true }],
    ["client/registerCapability", { registrations: [{ id: "forbidden", method: "textDocument/didChange", registerOptions: {} }] }],
    ["client/unregisterCapability", { unregisterations: [{ id: "forbidden", method: "textDocument/didChange" }] }],
    ["workspace/configuration", { items: [{ section: "openTrestle" }, { section: "http" }] }],
    ["workspace/executeCommand", { command: "openTrestle.hostCanary", arguments: [] }],
    ["workspace/diagnostic/refresh", {}],
  ];
  for (const [method, params] of requests) {
    try { record({ event: "refusal", method, result: await connection.sendRequest(method, params) }); }
    catch (error) { record({ event: "refusal", method, errorCode: error.code }); }
  }
  await connection.sendNotification("textDocument/publishDiagnostics", { uri, diagnostics: [{ ...item, message: "FORBIDDEN PUSH" }] });
  record({ event: "attack-complete" });
}
connection.onRequest("textDocument/diagnostic", async (params) => {
  const setting = mode();
  record({ event: "request", method: "textDocument/diagnostic", params, mode: setting.kind });
  const resultId = (setting.revision || "a").repeat(64);
  if (setting.kind === "late") return new Promise((resolve) => { held = resolve; });
  if (setting.kind === "huge") {
    process.stdout.write(Buffer.alloc(17 * 1024 * 1024, 65));
    record({ event: "huge-written", bytes: 17 * 1024 * 1024 });
    return new Promise(() => {});
  }
  if (setting.kind === "malformed") return { kind: "full", resultId, items: [item, { range: null }] };
  if (setting.kind === "refusals") await attack(params.textDocument.uri);
  if (setting.kind === "unchanged" && params.previousResultId) return { kind: "unchanged", resultId: params.previousResultId };
  const finding = setting.revision === "b" ? { ...item, message: "finding: revision b\n\n[untrusted review output; verify before editing]" } : item;
  return { kind: "full", resultId, items: setting.kind === "empty" ? [] : [finding] };
});
connection.onRequest("shutdown", () => {
  record({ event: "request", method: "shutdown" });
  if (held) {
    held({ kind: "full", resultId: "f".repeat(64), items: [{ ...item, message: "LATE OLD RESPONSE\n\n[untrusted review output; verify before editing]" }] });
    record({ event: "held-released" });
  }
  return null;
});
connection.onNotification("exit", () => { record({ event: "notification", method: "exit" }); process.exit(0); });
process.on("exit", (code) => record({ event: "exit", code }));
connection.listen();
