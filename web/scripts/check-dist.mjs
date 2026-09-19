import { lstat, readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";

async function directoryEntries(directory) {
  const root = resolve(directory);
  try {
    if (!(await lstat(root)).isDirectory()) throw new Error();
    return await readdir(root, { withFileTypes: true });
  } catch {
    throw new Error(`unexpected distribution directory: ${directory}`);
  }
}

function requireEntries(entries, expected) {
  if (
    entries.length !== Object.keys(expected).length ||
    entries.some((entry) =>
      expected[entry.name] === "directory"
        ? !entry.isDirectory()
        : expected[entry.name] !== "file" || !entry.isFile(),
    )
  )
    throw new Error("unexpected distribution file shape");
}

export async function checkDistribution(
  dist = fileURLToPath(new URL("../dist/", import.meta.url)),
  publicDirectory = fileURLToPath(new URL("../public/", import.meta.url)),
) {
  requireEntries(await directoryEntries(publicDirectory), {
    "favicon.svg": "file",
  });
  requireEntries(await directoryEntries(dist), {
    "index.html": "file",
    "favicon.svg": "file",
    assets: "directory",
  });
  const assets = join(dist, "assets");
  const entries = await directoryEntries(assets);
  const names = entries.map((entry) => entry.name).sort();
  const scripts = names.filter((name) => name.endsWith(".js"));
  const styles = names.filter((name) => name.endsWith(".css"));
  if (
    entries.some((entry) => !entry.isFile()) ||
    names.length !== 3 ||
    scripts.length !== 2 ||
    scripts.filter((name) => /^index-[A-Za-z0-9_-]+\.js$/.test(name)).length !==
      1 ||
    scripts.filter((name) => /^SetupApp-[A-Za-z0-9_-]+\.js$/.test(name))
      .length !== 1 ||
    styles.length !== 1 ||
    !/^index-[A-Za-z0-9_-]+\.css$/.test(styles[0])
  )
    throw new Error("unexpected distribution asset shape");
  const maximumTotalJavaScriptBytes = 288 * 1024;
  const maximumGzipJavaScriptBytes = 90 * 1024;
  let totalJavaScript = 0;
  let totalGzipJavaScript = 0;
  for (const name of scripts) {
    const path = join(assets, name);
    const size = (await lstat(path)).size;
    if (size > 250 * 1024)
      throw new Error(`${name} exceeds ${250 * 1024} bytes`);
    totalJavaScript += size;
    totalGzipJavaScript += gzipSync(await readFile(path), {
      level: 9,
    }).byteLength;
  }
  if (totalJavaScript > maximumTotalJavaScriptBytes)
    throw new Error(
      `JavaScript total exceeds ${maximumTotalJavaScriptBytes} bytes`,
    );
  if (totalGzipJavaScript > maximumGzipJavaScriptBytes)
    throw new Error(
      `gzip JavaScript total exceeds ${maximumGzipJavaScriptBytes} bytes`,
    );
  const styleSize = (await lstat(join(assets, styles[0]))).size;
  if (styleSize > 32 * 1024)
    throw new Error(`${styles[0]} exceeds ${32 * 1024} bytes`);
  const index = await readFile(join(dist, "index.html"), "utf8");
  if (
    /https?:\/\//i.test(index) ||
    /<script(?![^>]*\bsrc=)[^>]*>/i.test(index) ||
    /<style(?:\s|>)/i.test(index)
  )
    throw new Error("index requires an external or inline runtime asset");
  return {
    javascript: scripts,
    totalJavaScript,
    totalGzipJavaScript,
    css: styles[0],
    externalRuntimeAssets: false,
    sourceMaps: false,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  console.log(JSON.stringify(await checkDistribution()));
