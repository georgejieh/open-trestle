import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, sep } from "node:path";
import test from "node:test";
import { checkDistribution } from "./check-dist.mjs";

const expectedAssets = [
  "index-Abc_123-.js",
  "SetupApp-Xyz_987-.js",
  "index-Abc_123-.css",
];
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "trestle-dist-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const dist = join(root, "dist");
  const publicDirectory = join(root, "public");
  await mkdir(join(dist, "assets"), { recursive: true });
  await mkdir(publicDirectory);
  await writeFile(join(dist, "index.html"), '<div id="root"></div>');
  await writeFile(join(dist, "favicon.svg"), "<svg></svg>");
  await writeFile(join(publicDirectory, "favicon.svg"), "<svg></svg>");
  for (const name of expectedAssets)
    await writeFile(join(dist, "assets", name), "");
  return { root, dist, publicDirectory };
}

test("accepts only the fixed public file and three hashed build assets", async (t) => {
  const { dist, publicDirectory } = await fixture(t);
  const result = await checkDistribution(dist, publicDirectory);
  assert.deepEqual(result.javascript, [expectedAssets[1], expectedAssets[0]]);
  assert.equal(result.css, expectedAssets[2]);
});

for (const location of ["dist", "public"]) {
  for (const name of [
    "notes.txt",
    "notes.json",
    "index-Abc123.js.map",
    ".hidden",
    "assets/notes.txt",
    "assets/notes.json",
    "assets/index-Abc123.js.map",
    "assets/nested/notes.txt",
  ]) {
    test(`rejects extra ${location}/${name}`, async (t) => {
      const { dist, publicDirectory } = await fixture(t);
      const target = join(location === "dist" ? dist : publicDirectory, name);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, "harmless fixture");
      await assert.rejects(
        checkDistribution(dist, publicDirectory),
        /unexpected distribution/,
      );
    });
  }
  for (const name of ["empty", "assets/empty"]) {
    test(`rejects empty directory ${location}/${name}`, async (t) => {
      const { dist, publicDirectory } = await fixture(t);
      await mkdir(join(location === "dist" ? dist : publicDirectory, name), {
        recursive: true,
      });
      await assert.rejects(
        checkDistribution(dist, publicDirectory),
        /unexpected distribution/,
      );
    });
  }
}

for (const name of [
  "index.html",
  "favicon.svg",
  "assets",
  "assets/index-Abc_123-.js",
  "assets/SetupApp-Xyz_987-.js",
  "assets/index-Abc_123-.css",
]) {
  test(`rejects missing dist/${name}`, async (t) => {
    const { dist, publicDirectory } = await fixture(t);
    await rm(join(dist, name), { recursive: true });
    await assert.rejects(
      checkDistribution(dist, publicDirectory),
      /unexpected distribution/,
    );
  });
  test(`rejects symlink at dist/${name}`, async (t) => {
    const { root, dist, publicDirectory } = await fixture(t);
    const target = join(root, "sentinel");
    if (name === "assets") await mkdir(target);
    else await writeFile(target, "harmless fixture");
    await rm(join(dist, name), { recursive: true });
    await symlink(target, join(dist, name));
    await assert.rejects(
      checkDistribution(dist, publicDirectory),
      /unexpected distribution/,
    );
  });
}

for (const location of ["dist", "public"]) {
  test(`rejects a symlinked ${location} root`, async (t) => {
    const { root, dist, publicDirectory } = await fixture(t);
    const link = join(root, "link");
    await symlink(location === "dist" ? dist : publicDirectory, link);
    for (const path of [link, link + sep]) {
      await assert.rejects(
        checkDistribution(
          location === "dist" ? path : dist,
          location === "public" ? path : publicDirectory,
        ),
        /unexpected distribution/,
      );
    }
  });
}

test("rejects missing or symlinked public favicon", async (t) => {
  const { dist, publicDirectory } = await fixture(t);
  await rm(join(publicDirectory, "favicon.svg"));
  await assert.rejects(
    checkDistribution(dist, publicDirectory),
    /unexpected distribution/,
  );
  await symlink(
    join(dist, "favicon.svg"),
    join(publicDirectory, "favicon.svg"),
  );
  await assert.rejects(
    checkDistribution(dist, publicDirectory),
    /unexpected distribution/,
  );
});

test("rejects an additional hashed bundle", async (t) => {
  const { dist, publicDirectory } = await fixture(t);
  await writeFile(join(dist, "assets", "index-Extra123.js"), "");
  await assert.rejects(
    checkDistribution(dist, publicDirectory),
    /unexpected distribution/,
  );
});

test("keeps the existing size and inline-runtime checks", async (t) => {
  const { dist, publicDirectory } = await fixture(t);
  await writeFile(
    join(dist, "assets", expectedAssets[0]),
    "x".repeat(251 * 1024),
  );
  await assert.rejects(checkDistribution(dist, publicDirectory), /exceeds/);
  await writeFile(join(dist, "assets", expectedAssets[0]), "");
  await writeFile(join(dist, "index.html"), "<script>alert(1)</script>");
  await assert.rejects(
    checkDistribution(dist, publicDirectory),
    /inline runtime asset/,
  );
});
