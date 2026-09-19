import { writeFile } from "node:fs/promises";
import { build } from "esbuild";
const result = await build({
  entryPoints: ["src/extension.ts"],
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node22",
  external: ["vscode"],
  outfile: "dist/extension.js",
  minify: true,
  sourcemap: false,
  legalComments: "none",
  metafile: true,
});
await writeFile("dist/bundle-meta.json", JSON.stringify(result.metafile));
