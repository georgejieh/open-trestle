import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const read = (relative: string) =>
  readFileSync(resolve(process.cwd(), relative), "utf8");

describe("diagnostic authority copy", () => {
  it("limits LSP and VS Code to verified findings and excludes v6 observations", () => {
    const readme = read("README.md");
    const packageDocument = JSON.parse(read("package.json")) as {
      description: string;
    };
    const source = read("src/extension.ts");
    expect(readme).toMatch(/versions 1 through 5/i);
    expect(readme).toMatch(
      /version 6 deterministic observations.*outside.*LSP/is,
    );
    expect(packageDocument.description).toMatch(/verified findings/i);
    expect(packageDocument.description).toMatch(/versions 1 through 5/i);
    expect(source).toMatch(/deterministic observations.*outside LSP findings/i);
    expect(source).not.toContain("Read-only verified diagnostics are active");
  });
});
