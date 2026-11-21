import { createServer } from "node:http";
import { readFile, readdir } from "node:fs/promises";
import { extname, join } from "node:path";
import { visualAssetPath } from "./visual-assets.mjs";
import {
  checkTabletNavigation,
  checkMobileBrandContrast,
  checkReviewActionTargets,
} from "./navigation-layout.mjs";
import { chromium } from "playwright-core";
const root = new URL("../dist/", import.meta.url);
const visualAssets = new Set(await readdir(new URL("assets/", root)));
const digest = "a".repeat(64);
const tasks = [
  "source-base",
  "source-head",
  "change",
  "analysis",
  "memory",
  "context",
  "candidates",
  "verification",
  "readiness",
].map((key, index) => ({
  key,
  task_identity: String(index + 1).repeat(64),
  input_identity: digest,
  handler_identity: digest,
  kind: [
    "acquire_source",
    "acquire_source",
    "build_change",
    "inspect_deterministic",
    "retrieve_context",
    "assemble_context",
    "generate_candidates",
    "verify_candidates",
    "evaluate_publication",
  ][index],
  required: true,
  status: index < 7 ? "succeeded" : index === 7 ? "leased" : "pending",
  attempts: index < 8 ? 1 : 0,
  max_attempts: 1,
  lease_expires_at_milliseconds: index === 7 ? 1893456000000 : 0,
  output_identity: index < 7 ? digest : "",
  failure: "",
  retry_at_milliseconds: 0,
}));
const run = {
  contract: "open-trestle/review-run-receipt",
  schema_version: 1,
  identity: digest,
  plan_identity: digest,
  tenant_id: "tenant-a",
  repository_id: "payments-api",
  review_run_id: "pr-184",
  status: "active",
  revision: 19,
  head_identity: digest,
  last_occurred_at_milliseconds: 1788397200000,
  output_identity: "",
  failure: "",
  tasks,
};
const diagnostics = {
  contract: "open-trestle/review-diagnostic-set",
  schema_version: 5,
  identity: digest,
  tenant_id: "tenant-a",
  repository_id: "payments-api",
  review_run_id: "pr-184",
  snapshot_identity: digest,
  head_revision: "b".repeat(40),
  verified_set_identity: digest,
  coverage: {
    candidate_count: 4,
    verified_count: 2,
    rejected_count: 1,
    inconclusive_count: 1,
  },
  source_coverage: {
    verification_context_identity: "4".repeat(64),
    analyzed_count: 173,
    selected_count: 1,
    omitted_count: 172,
    omissions: [
      { reason: "selection_limit", count: 170 },
      { reason: "unsupported", count: 2 },
    ],
  },
  checks: [
    {
      identity: "5".repeat(64),
      source_check_identity: "6".repeat(64),
      analysis_result_identity: "7".repeat(64),
      change_identity: "8".repeat(64),
      key: "static_debug_output",
      rule_version: 1,
      state: "passed",
      applicable_files: 1,
      applicable_ranges: 3,
      checked_files: 1,
      checked_ranges: 3,
      matches: 0,
    },
  ],
  findings: [
    {
      identity: digest,
      source_identity: digest,
      fingerprint: digest,
      title: "Authorization check can be bypassed",
      message:
        "The new branch returns before the repository capability is verified. Move the capability check ahead of the early return.",
      severity: "error",
      path: "internal/access/policy.go",
      start_line: 84,
      end_line: 91,
      evidence_ids: ["evidence-authorization-84"],
    },
    {
      identity: "c".repeat(64),
      source_identity: "c".repeat(64),
      fingerprint: "c".repeat(64),
      title: "Cancellation is not propagated",
      message:
        "This request uses a background context, so shutdown cannot cancel the provider call.",
      severity: "warning",
      path: "runtime/dispatch.go",
      start_line: 117,
      end_line: 117,
      evidence_ids: ["evidence-context-117"],
    },
  ],
};
const runtimeStatus = {
  contract: "open-trestle/runtime-status",
  schema_version: 1,
  identity: "122a127e5ae939fa8d6582c6681945679653f5fc855721248f4a35e8e3353959",
  configuration_identity:
    "15e5f36c79b8c9cf9129ec34700067a406bf57f49086f0ffe5b39e4d965572f9",
  tenant_id: "tenant-a",
  repository_id: "payments-api",
  observed_at: "2026-09-03T19:00:00Z",
  ready: true,
  configuration: {
    tenant_id: "tenant-a",
    repository_ids: ["payments-api"],
    metadata_backend: "postgres",
    database_authority_identity: "9".repeat(64),
    artifact_backend: "s3",
    artifact_protection: "envelope_encrypted",
    notification_backend: "postgres",
    rate_limit_backend: "postgres",
    rate_limit_authority_identity: "8".repeat(64),
    review_mode: "required",
    webhook_ingress: true,
    local_workers: true,
    publication_enabled: true,
    publication_fence_verified: true,
    route_inventory_identity: "f".repeat(64),
    runtime_policy_identity: "1".repeat(64),
    route_count: 3,
    handlers: [
      { kind: "acquire_source", identity: "2".repeat(64) },
      { kind: "verify_candidates", identity: "3".repeat(64) },
    ],
  },
  components: [
    { name: "local_workers", state: "ready" },
    { name: "task_notifications", state: "ready" },
    { name: "webhook_processing", state: "ready" },
  ],
};

const server = createServer(async (request, response) => {
  const address = server.address();
  if (
    !address ||
    typeof address === "string" ||
    request.headers.host !== `127.0.0.1:${address.port}`
  ) {
    response.statusCode = 403;
    response.end();
    return;
  }
  let url;
  try {
    url = new URL(request.url ?? "/", "http://localhost");
  } catch {
    response.statusCode = 400;
    response.end();
    return;
  }
  if (url.pathname.startsWith("/api/v1/")) {
    response.setHeader("content-type", "application/json");
    if (request.headers.authorization !== `Bearer ${"x".repeat(32)}`) {
      response.statusCode = 401;
      response.end(
        JSON.stringify({
          contract: "open-trestle/api-response",
          schema_version: 1,
          request_id: "visual",
          error: { code: "unauthenticated", message: "unauthenticated" },
        }),
      );
      return;
    }
    const payload = url.pathname.endsWith("/diagnostics")
      ? {
          contract: "open-trestle/api-response",
          schema_version: 1,
          request_id: "visual",
          diagnostics,
        }
      : url.pathname.endsWith("/runtime")
        ? {
            contract: "open-trestle/runtime-status-response",
            schema_version: 1,
            request_id: "visual",
            status: runtimeStatus,
          }
        : {
            contract: "open-trestle/api-response",
            schema_version: 1,
            request_id: "visual",
            run,
          };
    response.end(JSON.stringify(payload));
    return;
  }
  const relative = visualAssetPath(request.url, request.method, visualAssets);
  if (relative === null) {
    response.statusCode = 404;
    response.setHeader("content-type", "text/html; charset=utf-8");
    const body = await readFile(new URL("not-found.html", root));
    response.end(request.method === "HEAD" ? undefined : body);
    return;
  }
  try {
    const body = await readFile(new URL(relative, root));
    const type =
      extname(relative) === ".css"
        ? "text/css"
        : extname(relative) === ".js"
          ? "text/javascript"
          : extname(relative) === ".svg"
            ? "image/svg+xml"
            : "text/html";
    response.setHeader("content-type", type);
    response.end(request.method === "HEAD" ? undefined : body);
  } catch {
    response.statusCode = 404;
    response.end();
  }
});
let browser;
let desktopOverflow = false,
  mobileOverflow = false;
const output = process.env.OPEN_TRESTLE_VISUAL_OUTPUT ?? "/tmp";
const errors = [];
try {
  await new Promise((resolve, reject) => {
    const failed = (error) => reject(error);
    server.once("error", failed);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", failed);
      resolve();
    });
  });
  const address = server.address();
  if (typeof address === "string" || address === null)
    throw new Error("listen failed");
  const base = `http://127.0.0.1:${address.port}/console/`;
  browser = await chromium.launch({
    headless: true,
    executablePath: "/usr/bin/chromium",
    env: { ...process.env, TMPDIR: process.env.TMPDIR ?? "/tmp" },
    args: ["--no-sandbox"],
  });
  async function newLocalPage(options) {
    const page = await browser.newPage(options);
    page.setDefaultTimeout(10000);
    page.setDefaultNavigationTimeout(15000);
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route("**/*", (route) => {
      if (new URL(route.request().url()).origin !== new URL(base).origin) {
        errors.push("unexpected external egress");
        return route.abort();
      }
      return route.continue();
    });
    return page;
  }
  const proof = await newLocalPage({
    viewport: { width: 960, height: 720 },
    deviceScaleFactor: 1,
  });
  const normalResponse = await proof.goto(base);
  if (normalResponse?.status() !== 200)
    throw new Error("normal fixture route failed");
  await proof.getByRole("heading", { name: "Locate a review run" }).waitFor();
  await proof.screenshot({ path: join(output, "proof-normal.png") });
  const missingResponse = await proof.goto(base + "unknown-visual-route");
  if (missingResponse?.status() !== 404)
    throw new Error("unknown fixture route did not return 404");
  await proof.getByRole("heading", { name: "Page not found" }).waitFor();
  await proof.getByRole("link", { name: "Return to review console" }).waitFor();
  await proof.screenshot({ path: join(output, "proof-404.png") });
  await proof.close();

  async function populate(page) {
    await page.goto(base);
    await page.getByLabel("Tenant").fill("tenant-a");
    await page.getByLabel("Repository").fill("payments-api");
    await page.getByLabel("Run", { exact: true }).fill("pr-184");
    await page.getByLabel("Access token").fill("x".repeat(32));
    await page.getByRole("button", { name: "Connect to run" }).click();
    await page
      .getByRole("heading", { name: "Execution in progress" })
      .waitFor();
  }
  async function expectCopyFailure(page, name) {
    await page.evaluate(() => {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async () => {
            throw new Error("fixture clipboard denied");
          },
        },
      });
    });
    await page.getByRole("button", { name }).click();
    const status = page.getByRole("status");
    await status.waitFor();
    if ((await status.textContent()) !== "Copy failed") {
      throw new Error("clipboard rejection did not produce bounded feedback");
    }
  }
  async function expandFirstFinding(page) {
    const details = page.locator("details.finding-evidence").first();
    await details.locator("summary").click();
    if (!(await details.evaluate((element) => element.open))) {
      throw new Error("finding evidence disclosure did not open");
    }
    await page
      .getByRole("button", {
        name: "Copy Evidence reference 1: evidence-authorization-84",
      })
      .waitFor();
    await expectCopyFailure(page, /Copy Diagnostic identity:/);
  }

  async function checkStatusMarks(page) {
    const marks = await page.locator(".state").evaluateAll((elements) =>
      elements.map((element) => ({
        label: element
          .querySelector(":scope > span:last-child")
          ?.textContent?.trim()
          .toLowerCase(),
        glyph: element.querySelector(".status-icon")?.textContent,
        mark: element
          .querySelector(".status-icon")
          ?.getAttribute("data-status-icon"),
      })),
    );
    for (const [label, mark] of [
      ["active", "active"],
      ["succeeded", "passed"],
      ["leased", "leased"],
      ["pending", "pending"],
    ]) {
      const entry = marks.find((value) => value.label === label);
      if (!entry || entry.mark !== mark || !entry.glyph)
        throw new Error(
          `status mark mismatch: ${label} ${JSON.stringify(entry)}`,
        );
    }
    const transientGlyphs = marks
      .filter(({ label }) => ["active", "leased", "pending"].includes(label))
      .map(({ glyph }) => glyph);
    if (new Set(transientGlyphs).size !== transientGlyphs.length)
      throw new Error("transient browser status marks are not distinct");
  }

  async function checkReducedMotion(page) {
    await page.emulateMedia({ reducedMotion: "reduce" });
    const reducedMotionPreference = await page.evaluate(
      () => matchMedia("(prefers-reduced-motion: reduce)").matches,
    );
    if (!reducedMotionPreference)
      throw new Error("reduced-motion browser preference was not applied");
    const motionStyles = await page.evaluate(() => {
      const primaryButton = document.querySelector(".secondary-button");
      const depthMarker = document.querySelector(".task-spine .depth-index");
      if (
        !(primaryButton instanceof HTMLElement) ||
        !(depthMarker instanceof HTMLElement)
      )
        throw new Error("reduced-motion state fixtures are missing");
      const buttonStyle = getComputedStyle(primaryButton);
      const markerStyle = getComputedStyle(depthMarker);
      return {
        buttonTransition: buttonStyle.transitionDuration,
        buttonAnimation: buttonStyle.animationName,
        markerTransition: markerStyle.transitionDuration,
        markerAnimation: markerStyle.animationName,
        markerDisplay: markerStyle.display,
        markerVisibility: markerStyle.visibility,
        markerOpacity: markerStyle.opacity,
      };
    });
    if (
      motionStyles.buttonTransition !== "0s" ||
      motionStyles.buttonAnimation !== "none" ||
      motionStyles.markerTransition !== "0s" ||
      motionStyles.markerAnimation !== "none"
    )
      throw new Error(
        `reduced motion retained travel: ${JSON.stringify(motionStyles)}`,
      );
    if (
      motionStyles.markerDisplay === "none" ||
      motionStyles.markerVisibility === "hidden" ||
      Number(motionStyles.markerOpacity) === 0
    )
      throw new Error("reduced motion hid the selected depth state");
    await page.getByRole("button", { name: /Tasks 9/i }).click();
    await page.getByRole("button", { name: /verification/i }).click();
    const selectedState = await page
      .getByRole("button", { name: /verification/i })
      .getAttribute("aria-current");
    if (selectedState !== "step")
      throw new Error("reduced motion hid the updated selected task state");
    await page.getByText("leased", { exact: true }).waitFor();
    await page.getByRole("button", { name: /^Overview/ }).click();
    await page.emulateMedia({ reducedMotion: "no-preference" });
  }

  const desktop = await newLocalPage({
    viewport: { width: 1440, height: 1000 },
    deviceScaleFactor: 1,
  });
  desktop.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await populate(desktop);
  await checkStatusMarks(desktop);
  await checkReducedMotion(desktop);
  await checkReviewActionTargets(desktop, [
    ".icon-button",
    ".rail-foot button",
    ".section-head button",
  ]);
  await desktop.screenshot({
    path: join(output, "open-trestle-console-desktop.png"),
    fullPage: true,
  });
  await desktop.getByRole("button", { name: /Review 2/i }).click();
  await desktop.getByRole("heading", { name: "Review coverage" }).waitFor();
  await expandFirstFinding(desktop);
  await checkReviewActionTargets(desktop, [
    ".icon-button",
    ".rail-foot button",
  ]);
  await desktop.screenshot({
    path: join(output, "open-trestle-console-findings-desktop.png"),
    fullPage: true,
  });
  await desktop.getByRole("button", { name: /Runtime ready/i }).click();
  await desktop.getByRole("heading", { name: "Runtime state" }).waitFor();
  await desktop.screenshot({
    path: join(output, "open-trestle-console-runtime.png"),
    fullPage: true,
  });
  desktopOverflow = await desktop.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await desktop.setViewportSize({ width: 800, height: 1000 });
  await checkTabletNavigation(desktop);
  await desktop.getByRole("button", { name: /^Overview/ }).focus();
  await desktop.keyboard.press("Enter");
  await desktop
    .getByRole("heading", { name: "Execution in progress" })
    .waitFor();
  await desktop.screenshot({
    path: join(output, "open-trestle-console-tablet.png"),
    fullPage: true,
  });
  if (
    await desktop.evaluate(
      () =>
        document.documentElement.scrollWidth >
        document.documentElement.clientWidth,
    )
  )
    throw new Error("tablet page overflow");
  await desktop.close();
  const mobile = await newLocalPage({
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 1,
    isMobile: true,
  });
  mobile.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await populate(mobile);
  await checkMobileBrandContrast(mobile);
  await mobile.getByRole("button", { name: "review" }).click();
  await expandFirstFinding(mobile);
  await checkReviewActionTargets(mobile, [
    ".icon-button",
    ".mobile-head button",
  ]);
  await mobile.screenshot({
    path: join(output, "open-trestle-console-mobile.png"),
    fullPage: true,
  });
  mobileOverflow = await mobile.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await mobile.close();
} finally {
  try {
    if (browser !== undefined) await browser.close();
  } finally {
    if (server.listening)
      await new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
  }
}
if (errors.length || desktopOverflow || mobileOverflow) {
  throw new Error(JSON.stringify({ errors, desktopOverflow, mobileOverflow }));
}
console.log(
  JSON.stringify({
    desktop: join(output, "open-trestle-console-desktop.png"),
    findingsDesktop: join(output, "open-trestle-console-findings-desktop.png"),
    mobile: join(output, "open-trestle-console-mobile.png"),
    runtime: join(output, "open-trestle-console-runtime.png"),
    unexpectedEgress: 0,
    consoleErrors: 0,
    horizontalOverflow: false,
    reducedMotion: true,
    statusIcons: true,
  }),
);
