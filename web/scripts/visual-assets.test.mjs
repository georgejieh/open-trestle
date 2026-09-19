import assert from "node:assert/strict";
import test from "node:test";
import { visualAssetPath } from "./visual-assets.mjs";

const assets = new Set([
  "index-AbCd1234.js",
  "SetupApp-EfGh5678.js",
  "index-IjKl9012.css",
]);

test("visual fixture never resolves outside its console allowlist", () => {
  for (const path of [
    "/outside-fixture-sentinel",
    "/console/../outside-fixture-sentinel",
    "/console/%2e%2e/outside-fixture-sentinel",
    "/console//outside-fixture-sentinel",
    "file:///outside-fixture-sentinel",
    "http://other.invalid/console/",
    "/console/assets/notes.txt",
    "/console/assets/unknown.js",
    "/console/assets/../index.html",
    "/console/assets/index-AbCd1234.js?x=1",
    "/console/assets/index-AbCd1234.js#x",
    "/console/assets/%69ndex-AbCd1234.js",
    "/console/assets/..%5coutside-fixture-sentinel",
  ])
    assert.equal(visualAssetPath(path, "GET", assets), null, path);
  assert.equal(visualAssetPath("/console/", "POST", assets), null);
});

test("visual fixture admits only known assets and read methods", () => {
  for (const method of ["GET", "HEAD"]) {
    assert.equal(visualAssetPath("/console/", method, assets), "index.html");
    assert.equal(
      visualAssetPath("/console/setup", method, assets),
      "index.html",
    );
    assert.equal(
      visualAssetPath("/console/favicon.svg", method, assets),
      "favicon.svg",
    );
    for (const name of assets)
      assert.equal(
        visualAssetPath(`/console/assets/${name}`, method, assets),
        `assets/${name}`,
      );
  }
});
