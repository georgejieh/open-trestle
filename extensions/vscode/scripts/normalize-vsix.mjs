import { createWriteStream } from "node:fs";
import { readFile, rename, rm } from "node:fs/promises";
import yauzl from "yauzl";
import yazl from "yazl";
// ZIP DOS timestamps use local calendar fields; normalize in a fixed timezone.
process.env.TZ = "UTC";
const input = new URL("../dist/open-trestle.raw.vsix", import.meta.url);
const output = new URL("../dist/open-trestle.normalized.vsix", import.meta.url);
const final = new URL("../dist/open-trestle.vsix", import.meta.url);
function open() {
  return new Promise((resolve, reject) =>
    yauzl.open(input, { lazyEntries: true, autoClose: false }, (error, zip) =>
      error || !zip ? reject(error ?? new Error("open failed")) : resolve(zip),
    ),
  );
}
function streamBuffer(zip, entry) {
  return new Promise((resolve, reject) =>
    zip.openReadStream(entry, (error, stream) => {
      if (error || !stream) {
        reject(error ?? new Error("stream failed"));
        return;
      }
      const chunks = [];
      stream.on("data", (chunk) => chunks.push(chunk));
      stream.on("error", reject);
      stream.on("end", () => resolve(Buffer.concat(chunks)));
    }),
  );
}
const zip = await open();
const entries = [];
await new Promise((resolve, reject) => {
  zip.on("error", reject);
  zip.on("entry", (entry) => {
    entries.push(entry);
    zip.readEntry();
  });
  zip.on("end", resolve);
  zip.readEntry();
});
const target = new yazl.ZipFile();
const fixed = new Date("2000-01-01T00:00:00.000Z");
for (const entry of entries.sort((a, b) =>
  a.fileName < b.fileName ? -1 : a.fileName > b.fileName ? 1 : 0,
)) {
  if (entry.fileName.endsWith("/")) {
    target.addEmptyDirectory(entry.fileName, { mtime: fixed, mode: 0o755 });
    continue;
  }
  const content = await streamBuffer(zip, entry);
  const mode = (entry.externalFileAttributes >>> 16) & 0xffff;
  target.addBuffer(content, entry.fileName, {
    mtime: fixed,
    mode: mode || 0o644,
    compress: true,
  });
}
zip.close();
const completed = new Promise((resolve, reject) => {
  const destination = createWriteStream(output);
  destination.on("close", resolve);
  destination.on("error", reject);
  target.outputStream.on("error", reject);
  target.outputStream.pipe(destination);
});
target.end();
await completed;
await rm(final, { force: true });
await rename(output, final);
await rm(input, { force: true });
const bytes = (await readFile(final)).byteLength;
console.log(
  JSON.stringify({
    artifact: "dist/open-trestle.vsix",
    bytes,
    reproducibleTimestamp: "2000-01-01T00:00:00Z",
  }),
);
