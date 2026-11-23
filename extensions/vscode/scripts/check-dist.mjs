import { readFile, stat } from "node:fs/promises";
import yauzl from "yauzl";
const root = new URL("../", import.meta.url);
const manifest = JSON.parse(
  await readFile(new URL("package.json", root), "utf8"),
);
const properties = manifest.contributes?.configuration?.properties ?? {};
if (
  manifest.license !== "Apache-2.0" ||
  manifest.capabilities?.untrustedWorkspaces?.supported !== false ||
  manifest.capabilities?.virtualWorkspaces?.supported !== false
)
  throw new Error("extension trust or license boundary changed");
if (
  JSON.stringify(Object.keys(properties)) !== '["openTrestle.executable"]' ||
  properties["openTrestle.executable"].scope !== "machine" ||
  properties["openTrestle.executable"].default !== "trestle"
)
  throw new Error("the only setting must be the machine-scoped executable");
const commands = (manifest.contributes?.commands ?? [])
  .map((entry) => entry.command)
  .sort()
  .join(",");
if (
  commands !==
  "openTrestle.clearFindings,openTrestle.reviewBranch,openTrestle.setUp"
)
  throw new Error(`unexpected commands: ${commands}`);
if (Object.keys(manifest.dependencies ?? {}).length !== 0)
  throw new Error("unexpected runtime dependency");
const bundle = new URL("dist/extension.js", root);
const archive = new URL("dist/open-trestle.vsix", root);
if (
  (await stat(bundle)).size > 1024 * 1024 ||
  (await stat(archive)).size > 1024 * 1024
)
  throw new Error("extension distribution exceeds one MiB");
const source = await readFile(bundle, "utf8");
if (source.includes("sourceMappingURL") || source.includes("/home/"))
  throw new Error("bundle contains build-host or source-map metadata");
const metadata = JSON.parse(
  await readFile(new URL("dist/bundle-meta.json", root), "utf8"),
);
const bundled = [
  ...new Set(
    Object.keys(metadata.inputs)
      .map(
        (name) =>
          name.match(
            /node_modules\/(?:\.pnpm\/[^/]+\/node_modules\/)?((?:@[^/]+\/)?[^/]+)/,
          )?.[1],
      )
      .filter(Boolean),
  ),
].sort();
if (bundled.length !== 0)
  throw new Error(`bundle includes packages: ${bundled.join(",")}`);
const expected = [
  "[Content_Types].xml",
  "extension.vsixmanifest",
  "extension/changelog.md",
  "extension/LICENSE.txt",
  "extension/NOTICE",
  "extension/readme.md",
  "extension/dist/extension.js",
  "extension/icon.png",
  "extension/package.json",
].sort();
const entries = await new Promise((resolve, reject) =>
  yauzl.open(archive, { lazyEntries: true }, (error, zip) => {
    if (error || !zip) {
      reject(error ?? new Error("open failed"));
      return;
    }
    const values = [];
    zip.on("entry", (entry) => {
      values.push({
        name: entry.fileName,
        date: entry.lastModFileDate,
        time: entry.lastModFileTime,
        mode: entry.externalFileAttributes >>> 16,
      });
      zip.readEntry();
    });
    zip.on("error", reject);
    zip.on("end", () => resolve(values));
    zip.readEntry();
  }),
);
const names = entries.map((entry) => entry.name).sort();
if (
  JSON.stringify(names) !== JSON.stringify(expected) ||
  entries.some(
    (entry) =>
      entry.date !== ((20 << 9) | (1 << 5) | 1) ||
      entry.time !== 0 ||
      entry.mode !== 0o100644,
  )
)
  throw new Error("VSIX file set, timestamps or modes are not canonical");
console.log(
  JSON.stringify({
    bundleBytes: (await stat(bundle)).size,
    vsixBytes: (await stat(archive)).size,
    files: names.length,
    reproducible: true,
  }),
);
