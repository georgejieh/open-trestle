import { describe, expect, it } from "vitest";
import {
  ConfigurationError,
  buildChildEnvironment,
  buildLaunchConfiguration,
} from "./config";
const settings = {
  executable: "trestle",
  server: "http://127.0.0.1:8741",
  tenant: "tenant-a",
  repository: "repo-a",
  run: "run-a",
};
describe("extension launch authority", () => {
  it("builds one exact read-only LSP launch", () => {
    const value = buildLaunchConfiguration(settings, "x".repeat(32));
    expect(value.command).toBe("trestle");
    expect(value.args).toEqual(["lsp", "--server", "http://127.0.0.1:8741"]);
    expect(value.initializationOptions).toEqual({
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
    });
    expect(value.environment.OPEN_TRESTLE_API_TOKEN).toBe("x".repeat(32));
  });
  it("rejects remote plaintext, URL credentials, invalid scope, and unsafe tokens", () => {
    for (const value of [
      { ...settings, server: "http://example.com" },
      { ...settings, server: "http://2130706433" },
      { ...settings, server: "http://0177.0.0.1" },
      { ...settings, server: "https://user:secret@example.com" },
      { ...settings, tenant: "../other" },
      { ...settings, executable: "./workspace/trestle" },
    ])
      expect(() => buildLaunchConfiguration(value, "x".repeat(32))).toThrow(
        ConfigurationError,
      );
    expect(() => buildLaunchConfiguration(settings, "short secret")).toThrow(
      ConfigurationError,
    );
  });
  it("passes only bounded process environment needed by the LSP client", () => {
    const environment = buildChildEnvironment(
      {
        PATH: "/usr/bin",
        HOME: "/home/operator",
        AWS_SECRET_ACCESS_KEY: "do-not-forward",
        OPENAI_API_KEY: "do-not-forward",
      },
      "x".repeat(32),
    );
    expect(environment.PATH).toBe("/usr/bin");
    expect(environment.HOME).toBe("/home/operator");
    expect(environment.OPEN_TRESTLE_API_TOKEN).toBe("x".repeat(32));
    expect(environment.AWS_SECRET_ACCESS_KEY).toBeUndefined();
    expect(environment.OPENAI_API_KEY).toBeUndefined();
  });
});
