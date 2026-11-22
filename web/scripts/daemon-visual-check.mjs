import { mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { chromium } from "playwright-core";
import {
  buildDaemonVisualReceipt,
  browserPhases,
  validateRuntimeEnvelope,
  fetchExactBrowserJSON,
  fetchExactLoopbackJSON,
} from "./daemon-visual-contract.mjs";

const url = process.env.OPEN_TRESTLE_DAEMON_URL;
const token = process.env.OPEN_TRESTLE_API_TOKEN;
const output = process.env.OPEN_TRESTLE_DAEMON_VISUAL_OUTPUT;
const phase = process.env.OPEN_TRESTLE_BROWSER_PHASE;
const executablePath =
  process.env.OPEN_TRESTLE_CHROMIUM_PATH ?? "/usr/bin/chromium";
const tenant = process.env.OPEN_TRESTLE_TENANT ?? "tenant-a";
const repository = process.env.OPEN_TRESTLE_REPOSITORY ?? "repository-a";
const run = process.env.OPEN_TRESTLE_RUN ?? "local-alpha";
if (
  !/^http:\/\/(?:127(?:\.\d{1,3}){3}|\[::1\]):\d+$/.test(url ?? "") ||
  !token ||
  token.length < 32 ||
  !output ||
  !browserPhases.has(phase) ||
  !executablePath.startsWith("/")
)
  throw new Error("invalid daemon visual configuration");
await mkdir(output, { recursive: false, mode: 0o700 });
const browser = await chromium.launch({
  headless: true,
  executablePath,
  args: ["--disable-gpu"],
});
const errors = [];
const captures = [];
const sha256 = (buffer) => createHash("sha256").update(buffer).digest("hex");
const pngDimensions = (buffer) => {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  if (
    buffer.length < 24 ||
    !buffer.subarray(0, 8).equals(signature) ||
    buffer.toString("ascii", 12, 16) !== "IHDR"
  )
    throw new Error("screenshot is not a PNG");
  return { width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) };
};
const filePrefix = phase.replaceAll("_", "-");
const runtimeEndpoint = `/api/v1/tenants/${encodeURIComponent(tenant)}/repositories/${encodeURIComponent(repository)}/runtime`;
const runtimeURL = new URL(runtimeEndpoint, url).href;
const equal = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const expectedRuntimeDOM = (status) => ({
  status_identity: status.identity,
  configuration_identity: status.configuration_identity,
  observed_at: status.observed_at,
  ready: status.ready,
  configuration: status.configuration,
  components: status.components,
});
const assertRuntimeDOM = async (page, status) => {
  const actual = await page.evaluate(() => {
    const heading = [...document.querySelectorAll("h2")].find(
      (item) => item.textContent?.trim() === "Runtime state",
    );
    const summarySection = heading?.closest("section");
    const authoritySection = [...document.querySelectorAll("section")].find(
      (item) =>
        item.querySelector("h2")?.textContent?.trim() === "Runtime authority",
    );
    const readinessSection = [...document.querySelectorAll("section")].find(
      (item) =>
        item.querySelector("h2")?.textContent?.trim() === "Service readiness",
    );
    const handlerSection = [...document.querySelectorAll("section")].find(
      (item) =>
        item.querySelector("h2")?.textContent?.trim() === "Handler authority",
    );
    if (
      !summarySection ||
      !authoritySection ||
      !readinessSection ||
      !handlerSection
    )
      throw new Error("runtime DOM sections are missing");
    const rows = (root) =>
      Object.fromEntries(
        [...root.querySelectorAll("dl > div")].map((row) => {
          const term = row.querySelector("dt")?.textContent?.trim();
          const value = row.querySelector("dd");
          if (!term || !value) throw new Error("runtime DOM row is malformed");
          return [term, value.textContent?.trim()];
        }),
      );
    const identities = (root) =>
      Object.fromEntries(
        [...root.querySelectorAll("dl > div")].map((row) => {
          const term = row.querySelector("dt")?.textContent?.trim();
          const value = row.querySelector("dd");
          if (!term || !value)
            throw new Error("runtime identity row is malformed");
          return [term, value.getAttribute("title") || null];
        }),
      );
    return {
      observed: summarySection
        .querySelector(".section-head p")
        ?.textContent?.trim(),
      ready: summarySection
        .querySelector(".state")
        ?.lastElementChild?.textContent?.trim(),
      summary: rows(summarySection),
      authority: identities(authoritySection),
      components: [
        ...readinessSection.querySelectorAll(".runtime-list li"),
      ].map((item) => ({
        name: item.querySelector("strong")?.textContent?.trim(),
        state: item
          .querySelector(".state")
          ?.lastElementChild?.textContent?.trim(),
      })),
      handler_count: handlerSection
        .querySelector(".section-head p")
        ?.textContent?.trim(),
      handlers: identities(handlerSection),
    };
  });
  const configuration = status.configuration;
  const observed = await page.evaluate(
    (value) => `Observed ${new Date(value).toLocaleString()}`,
    status.observed_at,
  );
  const expected = {
    observed,
    ready: status.ready ? "ready" : "starting",
    summary: {
      Metadata: configuration.metadata_backend,
      Artifacts: `${configuration.artifact_backend} · ${configuration.artifact_protection.replaceAll("_", " ")}`,
      Notifications: configuration.notification_backend.replaceAll("_", " "),
      "Rate limits": configuration.rate_limit_backend.replaceAll("_", " "),
      "Review mode": configuration.review_mode,
      "Webhook ingress": configuration.webhook_ingress
        ? "Configured"
        : "Disabled",
      "Local workers": configuration.local_workers ? "Configured" : "Disabled",
      Publication: configuration.publication_enabled
        ? configuration.publication_fence_verified
          ? "Enabled, fence verified"
          : "Unavailable"
        : "Disabled",
      "Approved routes": String(configuration.route_count),
    },
    authority: {
      Status: status.identity,
      Configuration: status.configuration_identity,
      "Route inventory": configuration.route_inventory_identity ?? null,
      "Runtime policy": configuration.runtime_policy_identity ?? null,
    },
    components: status.components.map((component) => ({
      name: component.name.replaceAll("_", " "),
      state: component.state,
    })),
    handler_count: `${configuration.handlers.length} exact handler bindings`,
    handlers: Object.fromEntries(
      configuration.handlers.map((handler) => [
        handler.kind.replaceAll("_", " "),
        handler.identity,
      ]),
    ),
  };
  if (!equal(actual, expected))
    throw new Error(
      `runtime DOM does not match authenticated response: ${JSON.stringify({ actual, expected })}`,
    );
  return expectedRuntimeDOM(status);
};
try {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    reducedMotion: "reduce",
  });
  const page = await context.newPage();
  let resolveDisplayedRuntime, rejectDisplayedRuntime;
  const displayedRuntimePromise = new Promise((resolve, reject) => {
    resolveDisplayedRuntime = resolve;
    rejectDisplayedRuntime = reject;
  });
  let displayedRuntimeSeen = false;
  const blockedRequests = [];
  const daemonOrigin = new URL(url).origin;
  await page.route("**/*", async (route) => {
    const request = route.request();
    const target = new URL(request.url());
    if (target.origin === daemonOrigin) {
      if (
        !displayedRuntimeSeen &&
        target.href === runtimeURL &&
        request.method() === "GET"
      ) {
        displayedRuntimeSeen = true;
        try {
          const captured = await fetchExactLoopbackJSON({
            endpoint: runtimeURL,
            credential: token,
          });
          validateRuntimeEnvelope(captured.envelope, { tenant, repository });
          resolveDisplayedRuntime({
            envelope: captured.envelope,
            received_at_milliseconds: Date.now(),
          });
          await route.fulfill({
            status: 200,
            headers: {
              "content-type": captured.contentType,
              "content-length": String(captured.body.length),
            },
            body: captured.body,
          });
        } catch (error) {
          rejectDisplayedRuntime(error);
          await route.abort("failed");
        }
        return;
      }
      await route.continue();
      return;
    }
    if (target.protocol === "data:" || target.protocol === "blob:") {
      await route.continue();
      return;
    }
    blockedRequests.push(target.origin);
    await route.abort("blockedbyclient");
  });
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(`${url}/console/`, { waitUntil: "networkidle" });
  await page.getByRole("textbox", { name: "Tenant", exact: true }).fill(tenant);
  await page
    .getByRole("textbox", { name: "Repository", exact: true })
    .fill(repository);
  await page.getByRole("textbox", { name: "Run", exact: true }).fill(run);
  await page.getByLabel("Access token").fill(token);
  await page.getByRole("button", { name: "Connect to run" }).click();
  await page
    .getByRole("heading", {
      level: 1,
      name: "Execution complete, review required",
    })
    .waitFor();
  await page.getByLabel("Operational run status succeeded").waitFor();
  if (
    await page.getByRole("heading", { level: 1, name: "Run succeeded" }).count()
  )
    throw new Error("operational success remains the primary review heading");
  const reviewPath = `/api/v1/tenants/${encodeURIComponent(tenant)}/repositories/${encodeURIComponent(repository)}/runs/${encodeURIComponent(run)}`;
  const [runEnvelope, diagnosticEnvelope] = await Promise.all([
    fetchExactBrowserJSON(page, {
      base: url,
      path: reviewPath,
      credential: token,
    }),
    fetchExactBrowserJSON(page, {
      base: url,
      path: reviewPath + "/diagnostics",
      credential: token,
    }),
  ]);
  const set = diagnosticEnvelope.diagnostics;
  if (
    set?.schema_version !== 6 ||
    set.checks?.length !== 1 ||
    !Array.isArray(set.observations)
  )
    throw new Error("daemon browser diagnostics are not deterministic v6");
  const observed = {
    run_identity: runEnvelope.run.identity,
    diagnostic_set_identity: set.identity,
    deterministic_check_identity: set.checks[0].identity,
    deterministic_check_state: set.checks[0].state,
    observation_count: set.observations.length,
    observation_identities: set.observations.map((item) => item.identity),
  };
  const snap = async (name, view) => {
    const viewport = page.viewportSize();
    if (!viewport) throw new Error("viewport unavailable");
    const fileName = `${filePrefix}-${name}.png`;
    const bytes = await page.screenshot({
      path: join(output, fileName),
      fullPage: true,
    });
    const image = pngDimensions(bytes);
    const capture = {
      name: fileName,
      view,
      width: viewport.width,
      height: viewport.height,
      image_width: image.width,
      image_height: image.height,
      bytes: bytes.length,
      sha256: sha256(bytes),
    };
    captures.push(capture);
    return capture;
  };
  const assertLayout = async () => {
    const overflow = await page.evaluate(
      () =>
        document.documentElement.scrollWidth -
        document.documentElement.clientWidth,
    );
    if (overflow > 0) throw new Error(`horizontal overflow: ${overflow}`);
  };
  await assertLayout();
  await snap("desktop-overview", "overview");
  await page.getByRole("button", { name: /Review 1/i }).click();
  await page
    .getByRole("heading", { name: "Deterministic rule coverage" })
    .waitFor();
  await page.getByText(/not independently verified findings/i).waitFor();
  await page.getByText(/Failed check: Static debug output failed/i).waitFor();
  await page.getByText("warning · deterministic").waitFor();
  await assertLayout();
  await snap("desktop-findings", "review");
  await page.getByRole("button", { name: /Runtime ready/i }).click();
  await page.getByRole("heading", { name: "Runtime state" }).waitFor();
  const displayedRuntime = await Promise.race([
    displayedRuntimePromise,
    new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error("runtime response was not observed")),
        5000,
      ),
    ),
  ]);
  const displayedStatus = validateRuntimeEnvelope(displayedRuntime.envelope, {
    tenant,
    repository,
  });
  const runtimeDOM = await assertRuntimeDOM(page, displayedStatus);
  await assertLayout();
  const runtimeCapture = await snap("desktop-runtime", "runtime");
  const postCaptureEnvelope = await fetchExactBrowserJSON(page, {
    base: url,
    path: runtimeEndpoint,
    credential: token,
  });
  const postCaptureReceivedAt = Date.now();
  validateRuntimeEnvelope(postCaptureEnvelope, { tenant, repository });
  const runtimeEvidence = {
    phase,
    endpoint: runtimeEndpoint,
    displayed_received_at_milliseconds:
      displayedRuntime.received_at_milliseconds,
    post_capture_received_at_milliseconds: postCaptureReceivedAt,
    displayed: displayedRuntime.envelope,
    post_capture: postCaptureEnvelope,
    dom: runtimeDOM,
    runtime_screenshot_sha256: runtimeCapture.sha256,
  };
  await page.setViewportSize({ width: 900, height: 1000 });
  await page.getByRole("button", { name: /Review/i }).click();
  await assertLayout();
  await snap("tablet-findings", "review");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: /Review/i }).click();
  await assertLayout();
  const targets = await page
    .locator("button:visible, summary:visible")
    .evaluateAll((elements) =>
      elements.map((element) => {
        const box = element.getBoundingClientRect();
        return [box.width, box.height, element.textContent?.trim()];
      }),
    );
  const undersized = targets.filter(
    ([width, height]) => Number(width) < 44 || Number(height) < 44,
  );
  if (undersized.length)
    throw new Error(
      `undersized targets: ${JSON.stringify(undersized.slice(0, 4))}`,
    );
  await page.keyboard.press("Tab");
  const focused = await page.evaluate(() => {
    const active = document.activeElement;
    if (!(active instanceof HTMLElement) || !active.matches(":focus-visible"))
      return false;
    const style = getComputedStyle(active);
    return (
      (style.outlineStyle !== "none" && parseFloat(style.outlineWidth) > 0) ||
      style.boxShadow !== "none"
    );
  });
  if (!focused) throw new Error("keyboard focus is not visibly styled");
  let disclosureFocused = false;
  let focusSteps = 0;
  for (; focusSteps < 32 && !disclosureFocused; focusSteps++) {
    await page.keyboard.press("Tab");
    disclosureFocused = await page.evaluate(
      () =>
        document.activeElement?.textContent?.includes("Inspect evidence") ===
          true && document.activeElement.matches(":focus-visible"),
    );
  }
  if (!disclosureFocused)
    throw new Error(
      "evidence disclosure is not reachable with visible keyboard focus",
    );
  await snap("mobile-390-findings", "review");
  if (blockedRequests.length)
    throw new Error(
      `unexpected egress blocked: ${blockedRequests.join(" | ")}`,
    );
  if (errors.length) throw new Error(`browser errors: ${errors.join(" | ")}`);
  const receipt = buildDaemonVisualReceipt({
    phase,
    scope: { tenant, repository, run },
    observed,
    runtime: runtimeEvidence,
    metrics: {
      reduced_motion: true,
      horizontal_overflow: false,
      keyboard_focus_visible: true,
      evidence_disclosure_focus_visible: true,
      focus_order_steps: focusSteps,
      unexpected_egress: 0,
      console_errors: 0,
      tap_targets_minimum: 44,
    },
    captures,
  });
  await writeFile(
    join(output, "receipt.json"),
    `${JSON.stringify(receipt)}\n`,
    { mode: 0o600 },
  );
} finally {
  await browser.close();
}
