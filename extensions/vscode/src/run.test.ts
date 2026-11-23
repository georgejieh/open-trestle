import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { childEnvironment } from "./config";
import { reviewArguments, startRun } from "./run";
const fake = resolve("test/fixtures/fake-trestle.cjs");
function run(mode: string, args: readonly string[] = []) {
  const lines: string[] = [];
  const started = startRun({
    command: process.execPath,
    args: [fake, mode, ...args],
    cwd: process.cwd(),
    env: childEnvironment(process.env),
    onStderrLine: (line) => lines.push(line),
    graceMs: 200,
  });
  return { ...started, lines };
}
describe("review runner", () => {
  it("passes the review arguments as they are, without a shell", async () => {
    const result = await run("report", [...reviewArguments, "a b; echo $HOME"])
      .result;
    expect(result.code).toBe(0);
    expect(JSON.parse(result.stdout).args).toEqual([
      "review",
      "--format",
      "sarif",
      "--stop-on-stdin-close",
      "a b; echo $HOME",
    ]);
  });
  it("gives the child only the allowlisted environment", async () => {
    const env = childEnvironment({
      PATH: process.env.PATH,
      HOME: "/home/operator",
      XDG_STATE_HOME: "/state",
      OPEN_TRESTLE_PROVIDER_OPENROUTER: "provider-key",
      OPEN_TRESTLE_API_TOKEN: "x".repeat(32),
      AWS_SECRET_ACCESS_KEY: "do-not-forward",
      OPENAI_API_KEY: "do-not-forward",
    });
    expect(env).toMatchObject({
      HOME: "/home/operator",
      XDG_STATE_HOME: "/state",
      OPEN_TRESTLE_PROVIDER_OPENROUTER: "provider-key",
      NO_COLOR: "1",
    });
    const started = startRun({
      command: process.execPath,
      args: [fake, "report"],
      cwd: process.cwd(),
      env,
      onStderrLine: () => {},
    });
    const keys: string[] = JSON.parse(
      (await started.result).stdout,
    ).environment;
    expect(keys).toContain("OPEN_TRESTLE_PROVIDER_OPENROUTER");
    expect(keys).not.toContain("OPEN_TRESTLE_API_TOKEN");
    expect(keys).not.toContain("AWS_SECRET_ACCESS_KEY");
    expect(keys).not.toContain("OPENAI_API_KEY");
  });
  it("streams standard error line by line and keeps the tail", async () => {
    const started = run("stderr");
    const result = await started.result;
    expect(started.lines).toEqual(["first line", "second line", "last line"]);
    expect(result.stderrTail.at(-1)).toBe("last line");
  });
  it("stops a child whose output passes the budget", async () => {
    const result = await run("flood").result;
    expect(result.overflow).toBe(true);
    expect(result.stdout).toBe("");
  });
  it("cancels by ending standard input", async () => {
    const started = run("wait");
    await new Promise((done) => setTimeout(done, 300));
    started.cancel();
    const result = await started.result;
    expect(result).toMatchObject({ canceled: true, code: 3 });
    expect(result.stdout).toContain("2.1.0");
    expect(started.lines).toEqual(["running", "stopped"]);
  });
  it("reports a missing executable", async () => {
    const result = await startRun({
      command: resolve("missing-trestle"),
      args: [],
      cwd: process.cwd(),
      env: childEnvironment(process.env),
      onStderrLine: () => {},
    }).result;
    expect(result.error?.code).toBe("ENOENT");
  });
});
