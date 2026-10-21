import assert from "node:assert/strict";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import test from "node:test";
import { chromium } from "playwright-core";
import {
  fetchExactBrowserJSON,
  fetchExactLoopbackJSON,
} from "./daemon-visual-contract.mjs";

const listen = (handler) =>
  new Promise((resolve, reject) => {
    const sockets = new Set();
    const server = createServer(handler);
    server.on("connection", (socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
    });
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve({ server, sockets }));
  });
const close = ({ server, sockets }) =>
  new Promise((resolve) => {
    for (const socket of sockets) socket.destroy();
    server.closeAllConnections();
    server.close(resolve);
  });
const origin = ({ server }) => `http://127.0.0.1:${server.address().port}`;
const json = (response, value) => {
  const body = JSON.stringify(value);
  response.writeHead(200, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    connection: "close",
  });
  response.end(body);
};

test(
  "browser identity fetch rejects redirects and preserves exact endpoint attribution",
  { timeout: 10_000 },
  async (t) => {
    const previousTemporary = process.env.TMPDIR;
    const temporary = await mkdtemp(join(tmpdir(), "otdr-"));
    await chmod(temporary, 0o700);
    process.env.TMPDIR = temporary;
    let switchReads = 0;
    let alternateReads = 0;
    let crossReads = 0;
    let loopReads = 0;
    const cross = await listen((_request, response) => {
      crossReads++;
      return json(response, { source: "cross" });
    });
    const primary = await listen((request, response) => {
      if (request.url === "/page")
        return response.end("<!doctype html><title>test</title>");
      if (request.url === "/direct")
        return json(response, { source: "direct" });
      if (request.url === "/alternate") {
        alternateReads++;
        return json(response, { source: "alternate" });
      }
      if (request.url === "/same") {
        response.writeHead(302, {
          location: "/alternate",
          connection: "close",
        });
        return response.end();
      }
      if (request.url === "/cross") {
        response.writeHead(302, {
          location: `${origin(cross)}/alternate`,
          connection: "close",
        });
        return response.end();
      }
      if (request.url === "/loop") {
        loopReads++;
        response.writeHead(302, { location: "/loop", connection: "close" });
        return response.end();
      }
      if (request.url === "/stall") {
        response.writeHead(200, {
          "content-type": "application/json",
          connection: "close",
        });
        response.write("{");
        return;
      }
      if (request.url === "/oversize") {
        response.writeHead(200, {
          "content-type": "application/json",
          connection: "close",
        });
        response.end("x".repeat((1 << 20) + 1));
        return;
      }
      if (request.url === "/switch") {
        switchReads++;
        if (switchReads === 1) return json(response, { source: "first" });
        response.writeHead(302, {
          location: "/alternate",
          connection: "close",
        });
        return response.end();
      }
      response.writeHead(404);
      response.end();
    });
    let browser;
    let page;
    t.after(async () => {
      await page?.close().catch(() => {});
      if (browser)
        await Promise.race([
          browser.close(),
          new Promise((resolve) => setTimeout(resolve, 1000)),
        ]);
      await close(primary);
      await close(cross);
      if (previousTemporary === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = previousTemporary;
      await rm(temporary, { recursive: true, force: true });
    });
    const loopbackOptions = (path) => ({
      endpoint: `${origin(primary)}${path}`,
      credential: "x".repeat(64),
      timeoutMilliseconds: 300,
      maximumBytes: 1 << 20,
    });
    assert.deepEqual(
      (await fetchExactLoopbackJSON(loopbackOptions("/direct"))).envelope,
      { source: "direct" },
    );
    for (const path of ["/same", "/cross", "/loop", "/stall", "/oversize"])
      await assert.rejects(
        fetchExactLoopbackJSON(loopbackOptions(path)),
        /deadline|redirect|status|body|size/i,
      );
    assert.equal(alternateReads, 0);
    assert.equal(crossReads, 0);
    assert.equal(loopReads, 1);
    loopReads = 0;
    browser = await chromium.launch({
      headless: true,
      executablePath: "/usr/bin/chromium",
      args: ["--disable-gpu"],
    });
    page = await browser.newPage();
    await page.goto(`${origin(primary)}/page`);
    const options = (path) => ({
      base: origin(primary),
      path,
      credential: "x".repeat(64),
      timeoutMilliseconds: 2000,
      maximumBytes: 1 << 20,
    });
    assert.deepEqual(await fetchExactBrowserJSON(page, options("/direct")), {
      source: "direct",
    });
    for (const path of ["/same", "/cross", "/loop"])
      await assert.rejects(
        fetchExactBrowserJSON(page, options(path)),
        /redirect|endpoint|fetch/i,
      );
    for (const path of ["/stall", "/oversize"])
      await assert.rejects(
        fetchExactBrowserJSON(page, {
          ...options(path),
          timeoutMilliseconds: 300,
        }),
        /abort|body|bounds|fetch|size/i,
      );
    assert.deepEqual(await fetchExactBrowserJSON(page, options("/switch")), {
      source: "first",
    });
    await assert.rejects(
      fetchExactBrowserJSON(page, options("/switch")),
      /redirect|endpoint|fetch/i,
    );
    assert.equal(alternateReads, 0);
    assert.equal(crossReads, 0);
    assert.equal(loopReads, 1);
  },
);
