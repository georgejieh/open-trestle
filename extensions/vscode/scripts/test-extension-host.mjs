import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes, randomInt, createHash } from "node:crypto";
import { once } from "node:events";
import { createWriteStream } from "node:fs";
import {
  access,
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const extensionRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const options = Object.fromEntries(
  process.argv.slice(2).map((arg) => {
    const split = arg.indexOf("=");
    assert(split > 2, "Use --name=/absolute/path arguments");
    return [arg.slice(2, split), arg.slice(split + 1)];
  }),
);
for (const name of ["vscode", "xvfb", "artifacts"]) {
  assert(
    options[name] && path.isAbsolute(options[name]),
    `Missing absolute --${name}`,
  );
}
const scenario = options.scenario || "default";
assert(
  ["default", "manifest-persistence"].includes(scenario),
  "Unknown scenario",
);
const manifestPersistence = scenario === "manifest-persistence";
const phases = manifestPersistence
  ? ["seed", "first-read", "persisted-read-clear", "cleared-refusal"]
  : ["default"];
const artifacts = options.artifacts;
await mkdir(artifacts, { recursive: false, mode: 0o700 });
const directories = Object.fromEntries(
  [
    "home",
    "data",
    "config",
    "cache",
    "extensions",
    "user",
    "workspace",
    "development",
  ].map((name) => [name, path.join(artifacts, name)]),
);
await Promise.all(
  Object.values(directories).map((directory) =>
    mkdir(directory, { mode: 0o700 }),
  ),
);
await mkdir(path.join(directories.user, "User"));
const manifestBytes = await readFile(path.join(extensionRoot, "package.json"));
const productManifest = JSON.parse(manifestBytes.toString("utf8"));
if (manifestPersistence)
  assert(
    !Object.hasOwn(productManifest, "__metadata"),
    "Source manifest unexpectedly contains installer metadata",
  );
const productId = `${productManifest.publisher}.${productManifest.name}`;
let productDirectory = path.join(
  directories.extensions,
  `${productId}-${productManifest.version}`,
);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const manifest = structuredClone(productManifest);
manifest.activationEvents = manifestPersistence ? ["onStartupFinished"] : [];
manifest.main = "./inactive.cjs";
const phaseDriverMain = (seed) => `const vscode = require("vscode");
exports.activate = context => {
  setTimeout(async () => {
    try { await require(${JSON.stringify(path.join(extensionRoot, "test/host/index.cjs"))}).run(); }
    catch { /* The phase receipt records failure; the runner rejects missing receipts. */ }
    finally { await vscode.commands.executeCommand("workbench.action.quit"); }
  }, 0);
  return ${seed ? "{ secrets: context.secrets }" : "undefined"};
};
`;
await writeFile(
  path.join(directories.development, "package.json"),
  JSON.stringify(manifest),
);
await writeFile(
  path.join(directories.development, "inactive.cjs"),
  manifestPersistence
    ? phaseDriverMain(true)
    : "exports.activate = context => ({ secrets: context.secrets });\n",
);
await writeFile(
  path.join(directories.workspace, "finding.txt"),
  "synthetic document content canary\nsecond line\n",
);
await writeFile(
  path.join(directories.workspace, "later.txt"),
  "later visible document\n",
);
await writeFile(
  path.join(directories.workspace, "background.txt"),
  "background-only content canary\n",
);
await writeFile(
  path.join(artifacts, "outside.txt"),
  "outside selected root content canary\n",
);
const fixture = path.join(artifacts, "fixture.cjs");
await writeFile(
  fixture,
  `#!${process.execPath}\nrequire(${JSON.stringify(path.join(extensionRoot, "test/host/server.cjs"))});\n`,
  { mode: 0o700 },
);
await chmod(fixture, 0o700);
await writeFile(
  path.join(artifacts, "mode.json"),
  JSON.stringify({ kind: "full" }),
);
await writeFile(
  path.join(directories.user, "User/settings.json"),
  JSON.stringify({
    "openTrestle.executable": fixture,
    "openTrestle.server": "http://127.0.0.1:8741",
    "openTrestle.tenant": "host-tenant",
    "openTrestle.repository": "host-repository",
    "openTrestle.run": "host-run",
    "openTrestle.autoStart": false,
    "telemetry.telemetryLevel": "off",
    "update.mode": "none",
    "extensions.autoUpdate": false,
    "extensions.autoCheckUpdates": false,
    "workbench.startupEditor": "none",
    "workbench.enableExperiments": false,
    "workbench.settings.enableNaturalLanguageSearch": false,
    "extensions.ignoreRecommendations": true,
    "git.enabled": false,
    "npm.fetchOnlinePackageInfo": false,
    "security.workspace.trust.enabled": false,
  }),
);
const display = randomInt(1000, 65000);
await assert.rejects(access(`/tmp/.X11-unix/X${display}`));
await assert.rejects(access(`/tmp/.X${display}-lock`));
const cookie = randomBytes(16);
const protocol = Buffer.from("MIT-MAGIC-COOKIE-1");
const field = (value) => {
  const length = Buffer.alloc(2);
  length.writeUInt16BE(value.length);
  return Buffer.concat([length, value]);
};
const family = Buffer.alloc(2);
family.writeUInt16BE(256);
const authority = path.join(artifacts, "Xauthority");
await writeFile(
  authority,
  Buffer.concat([
    family,
    field(Buffer.from(hostname())),
    field(Buffer.from(String(display))),
    field(protocol),
    field(cookie),
  ]),
  { mode: 0o600 },
);
directories.runtime = await mkdtemp(path.join(tmpdir(), "trestle-host-"));
const environment = {
  PATH: process.env.PATH,
  HOME: directories.home,
  XDG_RUNTIME_DIR: directories.runtime,
  XDG_CONFIG_HOME: directories.config,
  XDG_DATA_HOME: directories.data,
  XDG_CACHE_HOME: directories.cache,
  DISPLAY: `:${display}`,
  XAUTHORITY: authority,
  LANG: "C.UTF-8",
  OPEN_TRESTLE_HOST_ARTIFACTS: artifacts,
  OPEN_TRESTLE_HOST_EXTENSION: extensionRoot,
  ...(manifestPersistence
    ? {
        OPEN_TRESTLE_HOST_SCENARIO: scenario,
        OPEN_TRESTLE_HOST_PRODUCT: productDirectory,
        OPEN_TRESTLE_HOST_SEED: directories.development,
      }
    : {}),
};
const children = [];
const receipts = {
  startedAt: new Date().toISOString(),
  display,
  sandboxDisabled: false,
  isolatedProfile: true,
  explicitActivationWithRealIsolatedSecrets: !manifestPersistence,
  ...(manifestPersistence
    ? {
        scenario,
        selectedPhases: phases,
        phaseCount: phases.length,
        phaseCeilingMilliseconds: 120000,
        totalHostCeilingMilliseconds: phases.length * 120000,
        installCeilingMilliseconds: 120000,
        passwordStore: "basic",
        claims:
          "Functional manifest activation and synthetic token persistence only; not manual UX, real provider/daemon, OS keychain encryption, platform parity, or release qualification",
        phases: [],
        launchSettings: [],
        installedExtensionId: productId,
        productDirectory,
        profileDirectory: directories.user,
        seedSecretStorageIdentity: productId,
        seedSetupOnly: true,
        extensionTestMode: false,
        phaseDriverActivation: "onStartupFinished",
        phaseDriverCompletion:
          "Receipt written before native workbench.action.quit; runner requires passed receipt and observed full host closure",
        sourceManifestSha256: digest(manifestBytes),
        installation:
          "Official local VSIX CLI installation in isolated profile; original manifest fields and exact bundle checked, optional installer __metadata disclosed",
        installedFiles: [],
      }
    : {}),
  runtimeDirectory: directories.runtime,
  commands: [],
};
function launch(
  command,
  args,
  name,
  stdio = ["ignore", "pipe", "pipe"],
  env = environment,
) {
  const child = spawn(command, args, {
    env,
    detached: true,
    stdio,
  });
  child.stdout.pipe(
    createWriteStream(path.join(artifacts, `${name}.stdout.log`)),
  );
  child.stderr.pipe(
    createWriteStream(path.join(artifacts, `${name}.stderr.log`)),
  );
  const closed = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  children.push({ child, closed });
  receipts.commands.push({ command, args, pid: child.pid });
  return { child, closed };
}
function signalGroup(child, signal) {
  if (!child.pid) return;
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
}
const groupAlive = (child) => {
  if (!child.pid) return false;
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch (error) {
    if (error.code === "ESRCH") return false;
    throw error;
  }
};
async function waitForGroups(milliseconds, selected = children) {
  const end = Date.now() + milliseconds;
  while (selected.some(({ child }) => groupAlive(child)) && Date.now() < end) {
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}
let deadline;
let failed = false;
try {
  const xserver = launch(
    options.xvfb,
    [
      `:${display}`,
      "-screen",
      "0",
      "1280x900x24",
      "-nolisten",
      "tcp",
      "-auth",
      authority,
      "-displayfd",
      "3",
    ],
    "xvfb",
    ["ignore", "pipe", "pipe", "pipe"],
  );
  const ready = once(xserver.child.stdio[3], "data");
  await Promise.race([
    ready,
    xserver.closed.then(() => {
      throw new Error("Xvfb exited before readiness");
    }),
    new Promise((_, reject) => {
      deadline = setTimeout(
        () => reject(new Error("Xvfb readiness deadline")),
        10000,
      );
    }),
  ]);
  clearTimeout(deadline);
  const bundle = await readFile(path.join(extensionRoot, "dist/extension.js"));
  receipts.bundleSha256 = createHash("sha256").update(bundle).digest("hex");
  for (const phase of phases) {
    let launchSettings;
    if (manifestPersistence) {
      const settingsPath = path.join(directories.user, "User/settings.json");
      const expectedAutoStart = [
        "persisted-read-clear",
        "cleared-refusal",
      ].includes(phase);
      if (phase === "persisted-read-clear") {
        const settings = JSON.parse(await readFile(settingsPath, "utf8"));
        assert.equal(settings["openTrestle.autoStart"], false);
        settings["openTrestle.autoStart"] = true;
        await writeFile(settingsPath, JSON.stringify(settings));
        assert.deepEqual(
          JSON.parse(await readFile(settingsPath, "utf8")),
          settings,
        );
      }
      const settingsBytes = await readFile(settingsPath);
      const observedAutoStart = JSON.parse(settingsBytes.toString("utf8"))[
        "openTrestle.autoStart"
      ];
      assert.equal(
        observedAutoStart,
        expectedAutoStart,
        "Prelaunch autoStart setting drifted",
      );
      launchSettings = {
        phase,
        expectedAutoStart,
        observedAutoStart,
        settingsSha256: digest(settingsBytes),
      };
      receipts.launchSettings.push(launchSettings);
      environment.OPEN_TRESTLE_HOST_PHASE = phase;
      await writeFile(
        path.join(artifacts, "mode.json"),
        JSON.stringify({ kind: "full", scenario, phase }),
      );
      if (phase === "first-read") {
        await rm(directories.development, { recursive: true });
        await mkdir(directories.development, { mode: 0o700 });
        await writeFile(
          path.join(directories.development, "package.json"),
          JSON.stringify({
            name: "manifest-persistence-driver",
            publisher: "open-trestle-host",
            version: "0.0.0",
            engines: { vscode: productManifest.engines.vscode },
            main: "./inactive.cjs",
            activationEvents: ["onStartupFinished"],
          }),
        );
        await writeFile(
          path.join(directories.development, "inactive.cjs"),
          phaseDriverMain(false),
        );
        const vsix = path.join(extensionRoot, "dist/open-trestle.vsix");
        receipts.vsixSha256 = digest(await readFile(vsix));
        const cli = launch(
          options.vscode,
          [
            path.join(path.dirname(options.vscode), "resources/app/out/cli.js"),
            `--user-data-dir=${directories.user}`,
            `--extensions-dir=${directories.extensions}`,
            `--install-extension=${vsix}`,
            "--do-not-sync",
          ],
          "install-local-vsix",
          ["ignore", "pipe", "pipe"],
          { ...environment, ELECTRON_RUN_AS_NODE: "1" },
        );
        const install = {
          pid: cli.child.pid,
          vsix,
          ceilingMilliseconds: 120000,
        };
        receipts.install = install;
        install.closed = await Promise.race([
          cli.closed,
          new Promise((_, reject) => {
            deadline = setTimeout(
              () =>
                reject(new Error("Local VSIX install exceeded 120 seconds")),
              120000,
            );
          }),
        ]);
        clearTimeout(deadline);
        install.closedAt = new Date().toISOString();
        assert.equal(
          install.closed.code,
          0,
          "Official local VSIX installation failed",
        );
        await waitForGroups(3000, [cli]);
        install.processGroupAbsent = !groupAlive(cli.child);
        assert(
          install.processGroupAbsent,
          "CLI process group remains before first-read",
        );
        const registry = JSON.parse(
          await readFile(
            path.join(directories.extensions, "extensions.json"),
            "utf8",
          ),
        );
        const entries = registry.filter(
          (entry) =>
            entry.identifier.id === productId &&
            entry.version === productManifest.version,
        );
        assert.equal(
          entries.length,
          1,
          "Exact installed product registration missing or duplicated",
        );
        const entry = entries[0];
        assert.equal(entry.location.scheme, "file");
        assert(path.isAbsolute(entry.location.path));
        productDirectory = path.resolve(entry.location.path);
        const relative = path.relative(
          directories.extensions,
          productDirectory,
        );
        assert(
          relative && !relative.startsWith("..") && !path.isAbsolute(relative),
          "Installed product path escaped private extensions directory",
        );
        environment.OPEN_TRESTLE_HOST_PRODUCT = productDirectory;
        receipts.productDirectory = productDirectory;
        receipts.installedRegistration = entry;
        async function inventoryPackageEntry(relative) {
          const location = path.join(productDirectory, relative);
          const info = await lstat(location);
          assert(
            !info.isSymbolicLink(),
            `Installed package entry must not be a symlink: ${relative}`,
          );
          if (info.isDirectory()) {
            receipts.installedFiles.push({ path: relative, type: "directory" });
            for (const name of (await readdir(location)).sort())
              await inventoryPackageEntry(path.join(relative, name));
          } else {
            assert(
              info.isFile(),
              `Installed package entry must be an ordinary file: ${relative}`,
            );
            receipts.installedFiles.push({
              path: relative,
              type: "file",
              sha256: digest(await readFile(location)),
            });
          }
        }
        await inventoryPackageEntry("");
      }
      if (phase !== "seed") {
        const installedManifest = await readFile(
          path.join(productDirectory, "package.json"),
        );
        const installedBundle = await readFile(
          path.join(productDirectory, productManifest.main),
        );
        assert.equal(
          productManifest.main,
          "./dist/extension.js",
          "Product main no longer matches official bundle",
        );
        const installedPackage = JSON.parse(installedManifest.toString("utf8"));
        const originalFields = { ...installedPackage };
        delete originalFields.__metadata;
        assert.deepEqual(
          originalFields,
          productManifest,
          "Installed original product manifest fields drifted",
        );
        receipts.installedManifestByteIdentical =
          installedManifest.equals(manifestBytes);
        receipts.installedManifestAddedKeys = Object.keys(
          installedPackage,
        ).filter((key) => !(key in productManifest));
        assert(
          receipts.installedManifestAddedKeys.every(
            (key) => key === "__metadata",
          ),
        );
        assert.deepEqual(
          installedBundle,
          bundle,
          "Installed product bundle bytes drifted",
        );
        receipts.installedManifest = JSON.parse(
          installedManifest.toString("utf8"),
        );
        receipts.installedManifestSha256 = digest(installedManifest);
        receipts.installedBundleSha256 = digest(installedBundle);
        receipts.driverManifestSha256 = digest(
          await readFile(path.join(directories.development, "package.json")),
        );
        receipts.driverMainSha256 = digest(
          await readFile(path.join(directories.development, "inactive.cjs")),
        );
      }
    }
    const host = launch(
      options.vscode,
      [
        directories.workspace,
        `--user-data-dir=${directories.user}`,
        `--extensions-dir=${directories.extensions}`,
        `--extensionDevelopmentPath=${directories.development}`,
        ...(manifestPersistence
          ? []
          : [
              `--extensionTestsPath=${path.join(extensionRoot, "test/host/index.cjs")}`,
            ]),
        "--skip-welcome",
        "--skip-release-notes",
        "--disable-updates",
        "--disable-telemetry",
        ...(manifestPersistence ? [] : ["--disable-extensions"]),
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-gpu",
        "--password-store=basic",
        "--ozone-platform=x11",
      ],
      manifestPersistence ? `vscode-${phase}` : "vscode",
    );
    const result = await Promise.race([
      host.closed,
      new Promise((_, reject) => {
        deadline = setTimeout(
          () => reject(new Error("Extension host exceeded 120 seconds")),
          120000,
        );
      }),
    ]);
    clearTimeout(deadline);
    if (manifestPersistence) {
      const receipt = {
        phase,
        launchSettings,
        hostPid: host.child.pid,
        host: result,
        hostClosedAt: new Date().toISOString(),
      };
      receipts.phases.push(receipt);
      assert.equal(result.code, 0, "VS Code extension-host process failed");
      await waitForGroups(3000, [host]);
      receipt.processGroupAbsent = !groupAlive(host.child);
      assert(
        receipt.processGroupAbsent,
        "Editor process group remains between phases",
      );
      const wire = await readFile(
        path.join(artifacts, "wire.jsonl"),
        "utf8",
      ).catch((error) => {
        if (error.code === "ENOENT") return "";
        throw error;
      });
      const fixturePids = [
        ...new Set(
          wire
            .split("\n")
            .filter(Boolean)
            .map((line) => JSON.parse(line))
            .filter((event) => event.event === "spawn")
            .map((event) => event.pid),
        ),
      ];
      receipt.fixtureClosure = fixturePids.map((pid) => {
        try {
          process.kill(pid, 0);
          return { pid, absent: false };
        } catch (error) {
          if (error.code === "ESRCH") return { pid, absent: true };
          throw error;
        }
      });
      assert(
        receipt.fixtureClosure.every((value) => value.absent),
        "Fixture remains live between phases",
      );
      receipt.tests = JSON.parse(
        await readFile(path.join(artifacts, `tests-${phase}.json`), "utf8"),
      );
      assert.equal(receipt.tests.status, "passed");
      await writeFile(
        path.join(artifacts, "phases.json"),
        JSON.stringify(receipts.phases, null, 2) + "\n",
      );
    } else {
      receipts.host = result;
      assert.equal(result.code, 0, "VS Code extension-host process failed");
      receipts.tests = JSON.parse(
        await readFile(path.join(artifacts, "tests.json"), "utf8"),
      );
      assert.equal(receipts.tests.status, "passed");
    }
  }
} catch (error) {
  failed = true;
  receipts.failure = String(error);
} finally {
  clearTimeout(deadline);
  for (const { child } of children) signalGroup(child, "SIGTERM");
  await waitForGroups(3000);
  for (const { child } of children)
    if (groupAlive(child)) signalGroup(child, "SIGKILL");
  await waitForGroups(3000);
  const remaining = children
    .filter(({ child }) => groupAlive(child))
    .map(({ child }) => child.pid);
  receipts.remainingProcessGroups = remaining;
  if (remaining.length) {
    failed = true;
    receipts.cleanupFailure =
      "Owned process groups remain after bounded SIGKILL observation";
  }
  let closeDeadline;
  receipts.closed = await Promise.race([
    Promise.allSettled(children.map(({ closed }) => closed)),
    new Promise((resolve) => {
      closeDeadline = setTimeout(
        () => resolve("close observation deadline exceeded"),
        1000,
      );
    }),
  ]);
  clearTimeout(closeDeadline);
  if (typeof receipts.closed === "string") failed = true;
  if (!remaining.length) {
    await rm(directories.runtime, { recursive: true, force: true });
    receipts.runtimeDirectoryRemoved = true;
  } else {
    receipts.runtimeDirectoryRemoved = false;
  }
  receipts.finishedAt = new Date().toISOString();
  await writeFile(
    path.join(artifacts, "runner.json"),
    JSON.stringify(receipts, null, 2) + "\n",
  );
}
console.log(
  JSON.stringify({ status: failed ? "failed" : "passed", artifacts }),
);
if (failed) process.exit(1);
