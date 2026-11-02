const { StreamMessageReader, StreamMessageWriter } = require("vscode-jsonrpc/node");
const { createProtocolConnection } = require("vscode-languageserver-protocol/node");
const mode = process.argv[2] || "normal";
if (mode === "resist") process.on("SIGTERM", () => {});
if (mode === "stderr") process.stderr.write("untrusted-token-canary".repeat(100000));
const connection = createProtocolConnection(
  new StreamMessageReader(process.stdin),
  new StreamMessageWriter(process.stdout),
);
const received = [];
let initialize;
let refusals;
const capabilities = {
  positionEncoding: "utf-16",
  textDocumentSync: 0,
  diagnosticProvider: {
    identifier: "open-trestle",
    interFileDependencies: true,
    workspaceDiagnostics: false,
  },
};
connection.onRequest("initialize", (params) => {
  initialize = params;
  received.push({ method: "initialize", params });
  if (mode === "hang-init") return new Promise(() => {});
  if (mode === "malformed") {
    process.stdout.write("Content-Length: 1\r\n\r\n{");
    return new Promise(() => {});
  }
  if (mode === "oversize") {
    process.stdout.write(Buffer.alloc(8 * 1024 * 1024 + 1, 65));
    return new Promise(() => {});
  }
  if (mode === "wrong-encoding") capabilities.positionEncoding = "utf-8";
  if (mode === "sync") capabilities.textDocumentSync = 1;
  if (mode === "workspace-diagnostics") capabilities.diagnosticProvider.workspaceDiagnostics = true;
  if (mode === "wrong-identity") capabilities.diagnosticProvider.identifier = "other";
  if (mode === "no-interfile") capabilities.diagnosticProvider.interFileDependencies = false;
  return { capabilities };
});
connection.onNotification("initialized", (params) => {
  received.push({ method: "initialized", params });
});
connection.onRequest("textDocument/diagnostic", async (params) => {
  received.push({ method: "textDocument/diagnostic", params });
  if (mode === "hang-pull" || mode === "resist") return new Promise(() => {});
  if (mode === "late") {
    await new Promise((resolve) => setTimeout(resolve, 150));
    return { late: true };
  }
  if (mode === "denials") {
    const requests = [
      ["workspace/applyEdit", { edit: { changes: {} } }],
      ["window/showDocument", { uri: "command:evil" }],
      ["client/registerCapability", { registrations: [{ method: "textDocument/didOpen" }] }],
      ["client/unregisterCapability", { unregisterations: [{ method: "textDocument/didOpen" }] }],
      ["workspace/configuration", { items: [{ section: "secrets" }, {}] }],
      ["workspace/configuration", { items: Array(101).fill({}) }],
      ["workspace/configuration", { items: [null] }],
      ["workspace/executeCommand", { command: "evil" }],
      ["unknown/method", {}],
      ["workspace/diagnostic/refresh", {}],
    ];
    refusals = [];
    for (const [method, request] of requests) {
      try { refusals.push(await connection.sendRequest(method, request)); }
      catch (error) { refusals.push({ code: error.code }); }
    }
    await connection.sendNotification("textDocument/publishDiagnostics", {
      uri: "file:///outside", diagnostics: [{ message: "untrusted" }],
    });
    await connection.sendNotification("window/logMessage", { type: 1, message: "untrusted-token-canary" });
  }
  return {
    initialize,
    received,
    environment: {
      token: process.env.OPEN_TRESTLE_API_TOKEN,
      forbidden: process.env.AWS_SECRET_ACCESS_KEY,
    },
    refusals,
  };
});
connection.onRequest("shutdown", () => mode === "resist" ? new Promise(() => {}) : null);
connection.onNotification("exit", () => process.exit(0));
connection.listen();
