import { mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { chromium } from "playwright-core";
import {
  buildDaemonVisualReceipt,
  browserPhases,
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
const filePrefix = phase.replaceAll("_", "-");
try {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    reducedMotion: "reduce",
  });
  const page = await context.newPage();
  const blockedRequests = [];
  await page.route("**/*", async (route) => {
    const target = new URL(route.request().url());
    if (
      target.origin === new URL(url).origin ||
      target.protocol === "data:" ||
      target.protocol === "blob:"
    )
      await route.continue();
    else {
      blockedRequests.push(target.origin);
      await route.abort("blockedbyclient");
    }
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
  const observed = await page.evaluate(
    async ({ base, tenantID, repositoryID, runID, credential }) => {
      const headers = {
        Accept: "application/json",
        Authorization: `Bearer ${credential}`,
      };
      const path = `/api/v1/tenants/${encodeURIComponent(tenantID)}/repositories/${encodeURIComponent(repositoryID)}/runs/${encodeURIComponent(runID)}`;
      const [runResponse, diagnosticResponse] = await Promise.all([
        fetch(base + path, { headers, credentials: "omit" }),
        fetch(base + path + "/diagnostics", { headers, credentials: "omit" }),
      ]);
      if (!runResponse.ok || !diagnosticResponse.ok)
        throw new Error("daemon browser identity fetch failed");
      const runEnvelope = await runResponse.json();
      const diagnosticEnvelope = await diagnosticResponse.json();
      const set = diagnosticEnvelope.diagnostics;
      if (
        set?.schema_version !== 6 ||
        set.checks?.length !== 1 ||
        !Array.isArray(set.observations)
      )
        throw new Error("daemon browser diagnostics are not deterministic v6");
      return {
        run_identity: runEnvelope.run.identity,
        diagnostic_set_identity: set.identity,
        deterministic_check_identity: set.checks[0].identity,
        deterministic_check_state: set.checks[0].state,
        observation_count: set.observations.length,
        observation_identities: set.observations.map((item) => item.identity),
      };
    },
    {
      base: url,
      tenantID: tenant,
      repositoryID: repository,
      runID: run,
      credential: token,
    },
  );
  const snap = async (name, view) => {
    const viewport = page.viewportSize();
    if (!viewport) throw new Error("viewport unavailable");
    const fileName = `${filePrefix}-${name}.png`;
    const bytes = await page.screenshot({
      path: join(output, fileName),
      fullPage: true,
    });
    captures.push({
      name: fileName,
      view,
      width: viewport.width,
      height: viewport.height,
      bytes: bytes.length,
      sha256: sha256(bytes),
    });
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
  await assertLayout();
  await snap("desktop-runtime", "runtime");
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
