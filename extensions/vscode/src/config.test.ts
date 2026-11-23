import { describe, expect, it } from "vitest";
import { childEnvironment, validExecutable } from "./config";
describe("settings", () => {
  it("accepts a command name or an absolute path only", () => {
    expect(validExecutable("trestle")).toBe(true);
    expect(validExecutable("/usr/local/bin/trestle")).toBe(true);
    for (const value of ["", "./workspace/trestle", "trestle --x", "a\nb", 1])
      expect(validExecutable(value)).toBe(false);
  });
  it("passes only the allowlisted environment", () => {
    const environment = childEnvironment({
      PATH: "/usr/bin",
      HOME: "/home/operator",
      APPDATA: "C:\\Users\\o\\AppData\\Roaming",
      XDG_CONFIG_HOME: "/config",
      OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD: "key",
      OPEN_TRESTLE_API_TOKEN: "x".repeat(32),
      OPEN_TRESTLE_GITHUB_API_TOKEN: "do-not-forward",
      AWS_SECRET_ACCESS_KEY: "do-not-forward",
      NO_COLOR: "0",
    });
    expect(environment).toEqual({
      PATH: "/usr/bin",
      HOME: "/home/operator",
      APPDATA: "C:\\Users\\o\\AppData\\Roaming",
      XDG_CONFIG_HOME: "/config",
      OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD: "key",
      NO_COLOR: "1",
    });
  });
});
