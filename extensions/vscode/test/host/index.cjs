const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const vscode = require("vscode");
const artifacts = process.env.OPEN_TRESTLE_HOST_ARTIFACTS;
const extensionRoot = process.env.OPEN_TRESTLE_HOST_EXTENSION;
const token = "synthetic-host-token-canary-0000000000";
const checks = [];
async function events() {
  try { return (await fs.readFile(path.join(artifacts, "wire.jsonl"), "utf8")).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)); }
  catch (error) { if (error.code === "ENOENT") return []; throw error; }
}
async function waitFor(label, predicate) {
  const start = Date.now();
  while (Date.now() - start < 12000) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`Timed out: ${label}`);
}
async function setMode(kind, revision = "a") {
  await fs.writeFile(path.join(artifacts, "mode.json"), JSON.stringify({ kind, revision }));
}
async function reveal(uri) {
  await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(uri), { preview: false });
}
async function runManifestPersistence() {
  const phase = process.env.OPEN_TRESTLE_HOST_PHASE;
  assert(["seed", "first-read", "persisted-read-clear", "cleared-refusal"].includes(phase));
  const productId = "open-trestle.open-trestle";
  const result = {
    status: "failed", phase,
    versions: { vscode: vscode.version, node: process.versions.node, electron: process.versions.electron },
    activation: phase === "seed" ? "Inert same-identity SecretStorage setup only; not product activation proof" : "Installed unchanged product manifest and bundle; native contributed commands; separate inert test driver",
    seedWritesAllowed: phase === "seed",
    secretStorageIdentity: productId,
    checks: [],
  };
  const phaseEvents = async () => (await events()).filter((event) => event.phase === phase);
  const spawns = async () => (await phaseEvents()).filter((event) => event.event === "spawn");
  try {
    const expectedAutoStart = ["persisted-read-clear", "cleared-refusal"].includes(phase);
    const effectiveAutoStart = vscode.workspace.getConfiguration("openTrestle").get("autoStart");
    assert.equal(effectiveAutoStart, expectedAutoStart, "Effective autoStart setting drifted");
    result.autoStart = { expected: expectedAutoStart, effective: effectiveAutoStart };
    assert.equal(vscode.workspace.isTrusted, true);
    const product = vscode.extensions.getExtension(productId);
    assert(product, "Product identity not found");
    result.extensionId = product.id;
    result.extensionPath = product.extensionPath;
    if (phase === "seed") {
      assert.equal(path.resolve(product.extensionPath), path.resolve(process.env.OPEN_TRESTLE_HOST_SEED));
      assert.equal(product.packageJSON.main, "./inactive.cjs");
      assert.deepEqual(product.packageJSON.activationEvents, ["onStartupFinished"]);
      assert.equal(product.isActive, true, "Seed setup must run after its ordinary activation completes");
      const { secrets } = await product.activate();
      assert(secrets, "Seed-only actual SecretStorage unavailable");
      assert((await secrets.get("openTrestle.apiToken")) === undefined, "Seed profile unexpectedly contains a token");
      await secrets.store("openTrestle.apiToken", token);
      assert((await secrets.get("openTrestle.apiToken")) === token, "Synthetic token readback failed");
      assert.equal((await events()).length, 0);
      result.setupOnly = true;
      result.secretStorageIdentity = productId;
      result.checks.push("Actual isolated same-product-identity SecretStorage store and read succeeded; no product activation or child");
    } else {
      assert.equal(path.resolve(product.extensionPath), path.resolve(process.env.OPEN_TRESTLE_HOST_PRODUCT));
      const sourceManifestBytes = await fs.readFile(path.join(extensionRoot, "package.json"));
      const sourceManifest = JSON.parse(sourceManifestBytes.toString("utf8"));
      const installedManifestBytes = await fs.readFile(path.join(product.extensionPath, "package.json"));
      const installedPackage = JSON.parse(installedManifestBytes.toString("utf8"));
      const originalFields = { ...installedPackage };
      delete originalFields.__metadata;
      assert.deepEqual(originalFields, sourceManifest);
      result.installedManifestByteIdentical = installedManifestBytes.equals(sourceManifestBytes);
      result.installedManifestAddedKeys = Object.keys(installedPackage).filter((key) => !(key in sourceManifest));
      assert(result.installedManifestAddedKeys.every((key) => key === "__metadata"));
      assert.equal(product.packageJSON.main, sourceManifest.main);
      assert.deepEqual(product.packageJSON.activationEvents, sourceManifest.activationEvents);
      assert.deepEqual(await fs.readFile(path.join(product.extensionPath, sourceManifest.main)), await fs.readFile(path.join(extensionRoot, sourceManifest.main)));
      const driver = vscode.extensions.getExtension("open-trestle-host.manifest-persistence-driver");
      assert(driver, "Separate inert test driver missing");
      assert.equal(path.resolve(driver.extensionPath), path.resolve(process.env.OPEN_TRESTLE_HOST_SEED));
      assert.equal(driver.packageJSON.main, "./inactive.cjs");
      assert.deepEqual(driver.packageJSON.activationEvents, ["onStartupFinished"]);
      result.main = product.packageJSON.main;
      result.checks.push("Resolved installed extension path, original main, activation events, original manifest fields (optional installer __metadata disclosed) and exact bundle match current product; separate inert driver");
      const root = vscode.workspace.workspaceFolders[0].uri;
      const uri = vscode.Uri.joinPath(root, "finding.txt");
      const native = () => vscode.languages.getDiagnostics(uri);
      await vscode.workspace.openTextDocument(vscode.Uri.joinPath(root, "background.txt"));
      await reveal(uri);
      if (phase === "cleared-refusal") {
        await waitFor("natural cleared-token product activation", () => product.isActive === true);
        assert.equal((await phaseEvents()).length, 0);
        assert.equal((await spawns()).length, 0);
        assert.equal(native().length, 0);
        result.startupObservation = { trigger: "autoStart", effectiveAutoStart, naturalActivationCompleted: true, phaseFixtureEvents: 0, phaseSpawns: 0, nativeFindings: 0, beforeProductCommands: true };
        result.checks.push("Automatic missing-token startup completed naturally with no entire-phase fixture events, child spawn, or native findings before product commands");
        const before = (await events()).length;
        await vscode.commands.executeCommand("openTrestle.connect");
        assert.equal((await events()).length, before, "Cleared-token connect emitted fixture events");
        assert.equal((await phaseEvents()).length, 0);
        assert.equal((await spawns()).length, 0);
        assert.equal(native().length, 0);
        await vscode.commands.executeCommand("openTrestle.restart");
        assert.equal((await events()).length, before, "Cleared-token restart emitted fixture events");
        assert.equal((await phaseEvents()).length, 0);
        assert.equal((await spawns()).length, 0);
        assert.equal(native().length, 0);
        result.checks.push("Fresh full host: native Connect and Restart both resolved after token clear with no entire-phase child spawn, fixture event, or accepted native diagnostic; bounded command observation, not indefinite absence");
      } else {
        if (phase === "first-read") {
          assert.equal((await phaseEvents()).length, 0);
          assert.equal((await spawns()).length, 0);
          assert.equal(native().length, 0);
          await vscode.commands.executeCommand("openTrestle.connect");
          assert.equal(product.isActive, true, "Contributed command did not activate installed product");
        }
        await waitFor("manifest native findings", () => native().length === 1);
        const diagnostic = native()[0];
        assert.equal(diagnostic.source, "open-trestle");
        assert.equal(diagnostic.code, "fingerprint");
        assert.equal(diagnostic.severity, vscode.DiagnosticSeverity.Warning);
        assert.deepEqual([diagnostic.range.start.line, diagnostic.range.start.character, diagnostic.range.end.line, diagnostic.range.end.character], [0, 0, 1, 0]);
        assert.equal(diagnostic.message, "finding: message\n\n[untrusted review output; verify before editing]");
        const captured = await phaseEvents();
        const initial = captured.find((event) => event.method === "initialize").params;
        assert.equal(initial.rootUri, root.toString());
        assert.deepEqual(initial.workspaceFolders, [{ uri: root.toString(), name: "Open Trestle" }]);
        assert.deepEqual(initial.initializationOptions, { tenant_id: "host-tenant", repository_id: "host-repository", review_run_id: "host-run" });
        const spawned = await spawns();
        assert.equal(spawned.length, 1);
        assert.equal(spawned[0].tokenMatchesSeed, true);
        const pulls = () => phaseEvents().then((values) => values.filter((event) => event.method === "textDocument/diagnostic"));
        assert((await pulls()).some((event) => event.pid === spawned[0].pid && event.params.textDocument.uri === uri.toString()));
        const outside = vscode.Uri.file(path.join(artifacts, "outside.txt"));
        const later = vscode.Uri.joinPath(root, "later.txt");
        await reveal(outside);
        await reveal(later);
        await waitFor("later in-root native findings", () => vscode.languages.getDiagnostics(later).length === 1);
        await reveal(uri);
        assert((await pulls()).every((event) => [uri.toString(), later.toString()].includes(event.params.textDocument.uri)));
        result.fixturePid = spawned[0].pid;
        result.checks.push(phase === "first-read"
          ? "Normal manifest command activation read the originally seeded token without reseeding; exact native inert diagnostic, initialize scope and selected-root visible-file pull"
          : "Automatic startup read the originally seeded token without reseeding or prior product commands; exact native inert diagnostic, initialize scope and selected-root visible-file pull");
        if (phase === "persisted-read-clear") {
          assert.equal((await spawns()).length, 1, "Automatic startup phase spawned more than one fixture");
          result.startupObservation = { trigger: "autoStart", effectiveAutoStart, findingsObservedBeforeProductCommands: true, fixturePid: spawned[0].pid };
          await vscode.commands.executeCommand("openTrestle.clearToken");
          assert.equal(native().length, 0);
          await waitFor("clear retired fixture PID", () => {
            try { process.kill(spawned[0].pid, 0); return false; }
            catch (error) { if (error.code === "ESRCH") return true; throw error; }
          });
          assert((await phaseEvents()).some((event) => event.event === "exit" && event.pid === spawned[0].pid));
          result.checks.push("Persisted token after full editor restart produced findings; contributed Clear Token resolved, cleared native findings and fixture PID absence observed");
        }
      }
      assert(!JSON.stringify(await events()).includes(token));
    }
    result.status = "passed";
  } catch (error) {
    result.error = String(error.stack || error);
    throw error;
  } finally {
    await fs.writeFile(path.join(artifacts, `tests-${phase}.json`), JSON.stringify(result, null, 2) + "\n");
  }
}
exports.run = async () => {
  if (process.env.OPEN_TRESTLE_HOST_SCENARIO === "manifest-persistence") return runManifestPersistence();
  const extension = require(path.join(extensionRoot, "dist/extension.js"));
  const harness = vscode.extensions.getExtension("open-trestle.open-trestle");
  assert(harness, "Private development extension not found");
  const { secrets } = await harness.activate();
  await secrets.store("openTrestle.apiToken", token);
  const subscriptions = [];
  const context = { subscriptions, secrets };
  const root = vscode.workspace.workspaceFolders[0].uri;
  const uri = vscode.Uri.joinPath(root, "finding.txt");
  const later = vscode.Uri.joinPath(root, "later.txt");
  const background = vscode.Uri.joinPath(root, "background.txt");
  const diagnosticEvents = [];
  const observer = vscode.languages.onDidChangeDiagnostics((event) => diagnosticEvents.push(...event.uris.map((value) => value.toString())));
  let sideEffects = 0;
  const canary = vscode.commands.registerCommand("openTrestle.hostCanary", () => { sideEffects++; });
  const result = { status: "failed", versions: { vscode: vscode.version, node: process.versions.node, electron: process.versions.electron }, activation: "exported product activate with private harness real SecretStorage and VSCode APIs; not normal product manifest activation", checks };
  const native = () => vscode.languages.getDiagnostics(uri);
  const pulls = async () => (await events()).filter((event) => event.event === "request" && event.method === "textDocument/diagnostic");
  const spawns = async () => (await events()).filter((event) => event.event === "spawn");
  async function waitClosed(pid) {
    await waitFor("owned fixture no longer live", () => {
      try { process.kill(pid, 0); return false; }
      catch (error) { if (error.code === "ESRCH") return true; throw error; }
    });
    const exitReceipt = (await events()).find((event) => event.event === "exit" && event.pid === pid);
    const observation = { event: "pid-absent", pid, observedAt: Date.now(), fixtureExitReceipt: Boolean(exitReceipt) };
    await fs.appendFile(path.join(artifacts, "closure.jsonl"), JSON.stringify(observation) + "\n");
  }
  async function restart(kind, revision = "a") {
    await setMode(kind, revision);
    const previous = (await spawns()).at(-1);
    await vscode.commands.executeCommand("openTrestle.restart");
    await waitFor("successor spawned", async () => (await spawns()).at(-1).pid !== previous.pid);
    await waitClosed(previous.pid);
    const captured = await events();
    const successor = (await spawns()).at(-1).pid;
    assert(captured.findIndex((event) => event.event === "exit" && event.pid === previous.pid) < captured.findIndex((event) => event.event === "spawn" && event.pid === successor));
    return successor;
  }
  try {
    assert.equal(vscode.workspace.isTrusted, true);
    const document = await vscode.workspace.openTextDocument(uri);
    const originalText = document.getText();
    await vscode.workspace.openTextDocument(background);
    await reveal(uri);
    await extension.activate(context);
    await vscode.commands.executeCommand("openTrestle.connect");
    await waitFor("native diagnostics", () => native().length === 1);
    await waitFor("native diagnostic event", () => diagnosticEvents.includes(uri.toString()));
    const diagnostic = native()[0];
    assert.equal(diagnostic.source, "open-trestle");
    assert.equal(diagnostic.code, "fingerprint");
    assert.equal(diagnostic.severity, vscode.DiagnosticSeverity.Warning);
    assert.deepEqual([diagnostic.range.start.line, diagnostic.range.start.character, diagnostic.range.end.line, diagnostic.range.end.character], [0, 0, 1, 0]);
    assert.equal(diagnostic.message, "finding: message\n\n[untrusted review output; verify before editing]");
    await vscode.commands.executeCommand("workbench.actions.view.problems");
    checks.push("Native diagnostic event and Problems backing service contain exact inert fields; Problems command invoked, visual rendering not asserted");
    const initial = (await events()).find((event) => event.method === "initialize").params;
    assert.equal(initial.rootUri, root.toString());
    assert.deepEqual(initial.initializationOptions, { tenant_id: "host-tenant", repository_id: "host-repository", review_run_id: "host-run" });
    assert(!(await pulls()).some((event) => event.params.textDocument.uri === background.toString()));
    const outside = vscode.Uri.file(path.join(artifacts, "outside.txt"));
    await reveal(outside);
    await new Promise((resolve) => setTimeout(resolve, 150));
    assert(!(await pulls()).some((event) => event.params.textDocument.uri === outside.toString()));
    await reveal(uri);
    checks.push("Initialize exact root/scope; background-only and visible outside-root documents are not pulled");
    await setMode("unchanged");
    await reveal(later);
    await waitFor("later native findings", () => vscode.languages.getDiagnostics(later).length === 1);
    await reveal(uri);
    await waitFor("unchanged previous ID", async () => (await pulls()).some((event) => event.mode === "unchanged" && event.params.textDocument.uri === uri.toString() && event.params.previousResultId === "a".repeat(64)));
    assert.equal(native().length, 1);
    checks.push("Visible-file pulls send accepted previousResultId and unchanged retains baseline");
    await setMode("full", "b");
    await reveal(later);
    await waitFor("new full later", async () => (await pulls()).some((event) => event.mode === "full" && event.params.textDocument.uri === later.toString() && event.params.previousResultId));
    await reveal(uri);
    await waitFor("new full accepted", () => native()[0]?.message.startsWith("finding: revision b"));
    await setMode("empty", "c");
    await reveal(later);
    await waitFor("empty later accepted", () => vscode.languages.getDiagnostics(later).length === 0);
    await reveal(uri);
    await waitFor("empty clears native findings", () => native().length === 0);
    assert((await pulls()).some((event) => event.mode === "empty" && event.params.textDocument.uri === uri.toString() && event.params.previousResultId === "b".repeat(64)));
    checks.push("New full replaces result ID; empty full clears native findings");
    await restart("refusals");
    await waitFor("refusals complete", async () => (await events()).some((event) => event.event === "attack-complete"));
    await waitFor("refusal session finding", () => native().length === 1);
    const denied = (await events()).filter((event) => event.event === "refusal");
    assert.deepEqual(denied.find((event) => event.method === "workspace/applyEdit").result.applied, false);
    assert.deepEqual(denied.find((event) => event.method === "window/showDocument").result, { success: false });
    assert.deepEqual(denied.find((event) => event.method === "workspace/configuration").result, [null, null]);
    for (const method of ["client/registerCapability", "client/unregisterCapability"]) assert.equal(denied.find((event) => event.method === method).result, null);
    for (const method of ["workspace/executeCommand", "workspace/diagnostic/refresh"]) assert.equal(denied.find((event) => event.method === method).errorCode, -32601);
    assert.equal(document.getText(), originalText);
    assert.equal(sideEffects, 0);
    assert(!vscode.workspace.textDocuments.some((value) => value.uri.path.endsWith("/forbidden.txt")));
    assert(!vscode.languages.getDiagnostics().flatMap(([, values]) => values).some((value) => value.message === "FORBIDDEN PUSH"));
    checks.push("Edit/open/register/command/configuration/refresh requests and push diagnostics cannot change native documents or findings");
    for (const action of ["restart", "token"]) {
      const oldPid = await restart("late");
      await waitFor("old pull held", async () => (await pulls()).some((event) => event.pid === oldPid && event.mode === "late"));
      if (action === "restart") await vscode.commands.executeCommand("openTrestle.restart");
      else await context.secrets.store("openTrestle.apiToken", token + "-rotated");
      assert.equal(native().length, 0);
      await waitClosed(oldPid);
      await waitFor("successor held pull", async () => {
        const successor = (await spawns()).at(-1).pid;
        return (await pulls()).some((event) => event.pid !== oldPid && event.pid === successor && event.mode === "late");
      });
      assert.equal(native().length, 0);
      await restart("full");
      await waitFor("fresh successor findings", () => native().length === 1);
      assert(!native().some((value) => value.message.includes("LATE OLD RESPONSE")));
      checks.push(`${action} invalidates native findings before retiring old held pull; late reply cannot republish`);
    }
    for (const kind of ["malformed", "huge"]) {
      const failedPid = await restart(kind);
      await waitFor(`${kind} pull reached`, async () => (await pulls()).some((event) => event.pid === failedPid && event.mode === kind));
      await waitClosed(failedPid);
      assert.equal(native().length, 0);
      checks.push(`${kind} retires child and clears native diagnostics without partial publication`);
    }
    const captured = await events();
    const methods = captured.filter((event) => event.event === "request" || event.event === "notification").map((event) => event.method);
    assert(methods.every((method) => ["initialize", "initialized", "textDocument/diagnostic", "shutdown", "exit", "$/cancelRequest"].includes(method)), JSON.stringify(methods));
    assert(!JSON.stringify(captured).includes("synthetic document content canary"));
    assert(!JSON.stringify(captured).includes(token));
    checks.push("Allowed client wire methods only; no document text or token in captured protocol");
    await setMode("full");
    await vscode.commands.executeCommand("openTrestle.restart");
    await waitFor("before clear native findings", () => native().length === 1);
    const clearedPid = (await spawns()).at(-1).pid;
    await vscode.commands.executeCommand("openTrestle.clearToken");
    assert.equal(await secrets.get("openTrestle.apiToken"), undefined);
    assert.equal(native().length, 0);
    await waitClosed(clearedPid);
    await secrets.store("openTrestle.apiToken", token);
    await waitFor("before disposal native findings", () => native().length === 1);
    checks.push("Real isolated SecretStorage clear stops findings and child; actual token change event restarts");
    const lastPid = (await spawns()).at(-1).pid;
    await extension.deactivate();
    assert.equal(native().length, 0);
    await waitClosed(lastPid);
    for (const disposable of subscriptions.splice(0)) disposable.dispose();
    const count = (await pulls()).length;
    await reveal(later);
    await reveal(uri);
    await new Promise((resolve) => setTimeout(resolve, 150));
    assert.equal((await pulls()).length, count);
    assert.equal(native().length, 0);
    checks.push("Deactivate clears native collection, retires child and removes listeners");
    result.diagnosticEventCount = diagnosticEvents.length;
    result.status = "passed";
  } catch (error) {
    result.error = String(error.stack || error);
    throw error;
  } finally {
    await extension.deactivate();
    for (const disposable of subscriptions.splice(0)) disposable.dispose();
    observer.dispose(); canary.dispose();
    await secrets.delete("openTrestle.apiToken");
    await fs.writeFile(path.join(artifacts, "tests.json"), JSON.stringify(result, null, 2) + "\n");
  }
};
