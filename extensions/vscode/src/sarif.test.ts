import { describe, expect, it } from "vitest";
import { parseReview, SarifError, summary, untrustedWarning } from "./sarif";
type Value = Record<string, unknown>;
function result(overrides: Value = {}, uri = "src/a%20b.go"): Value {
  return {
    ruleId: "open-trestle/correctness",
    level: "error",
    message: { text: "Division by zero: x can be 0" },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri },
          region: { startLine: 3, endLine: 5 },
        },
      },
    ],
    properties: { trestleFixGuidance: "Check x first." },
    ...overrides,
  };
}
function log(results: Value[], invocation: Value = {}, version = "2.1.0") {
  return JSON.stringify({
    version,
    runs: [
      {
        tool: { driver: { name: "Open Trestle", rules: [] } },
        invocations: [
          {
            executionSuccessful: true,
            toolExecutionNotifications: [
              {
                level: "warning",
                message: {
                  text: "Verified finding on removed base lines 4-6 of gone.go",
                },
              },
            ],
            ...invocation,
          },
        ],
        results,
        properties: {
          trestleModelReviewStatus: "findings",
          trestleRevision: "0123456789abcdef0123",
        },
      },
    ],
  });
}
describe("SARIF reading", () => {
  it("maps levels, whole-line ranges, fix guidance and the warning", () => {
    const review = parseReview(
      log([
        result(),
        result({ level: "warning", properties: {} }),
        result({ level: "note" }),
      ]),
    );
    expect(review.findings.map((item) => item.level)).toEqual([
      "error",
      "warning",
      "note",
    ]);
    expect(review.findings[0]).toEqual({
      path: "src/a b.go",
      startLine: 3,
      endLine: 5,
      level: "error",
      ruleId: "open-trestle/correctness",
      message:
        "Division by zero: x can be 0\n\nFix (unverified model guidance): Check x first." +
        untrustedWarning,
    });
    expect(review.findings[1]?.message).toBe(
      "Division by zero: x can be 0" + untrustedWarning,
    );
    expect(review.notifications).toEqual([
      "Verified finding on removed base lines 4-6 of gone.go",
    ]);
    expect(summary(review)).toBe(
      "Open Trestle: 3 findings in the review of commit 0123456789ab (findings). It describes the committed HEAD, not uncommitted edits, and is not a clearance.",
    );
  });
  it("keeps a colon file name that Go writes with ./", () => {
    expect(parseReview(log([result({}, "./a:b.go")])).findings[0]?.path).toBe(
      "a:b.go",
    );
  });
  it("summarises a run that did not finish as an error", () => {
    const review = parseReview(log([], { executionSuccessful: false }));
    expect(review.succeeded).toBe(false);
    expect(summary(review)).toMatch(/did not finish \(findings\)/);
  });
  it.each([
    ["traversal", log([result({}, "%2e%2e/etc/passwd")])],
    ["plain traversal", log([result({}, "src/../../x")])],
    ["absolute path", log([result({}, "/etc/passwd")])],
    ["encoded absolute path", log([result({}, "%2Fetc/passwd")])],
    ["backslash path", log([result({}, "\\\\server\\share")])],
    ["drive path", log([result({}, "C%3A/Windows")])],
    ["scheme", log([result({}, "file:///etc/passwd")])],
    ["empty uri", log([result({}, "")])],
    ["dot segment", log([result({}, "src/./a.go")])],
    [
      "start line zero",
      log([
        result({
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "a.go" },
                region: { startLine: 0, endLine: 1 },
              },
            },
          ],
        }),
      ]),
    ],
    [
      "end before start",
      log([
        result({
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "a.go" },
                region: { startLine: 5, endLine: 4 },
              },
            },
          ],
        }),
      ]),
    ],
    [
      "fractional line",
      log([
        result({
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "a.go" },
                region: { startLine: 1.5, endLine: 2 },
              },
            },
          ],
        }),
      ]),
    ],
    ["two locations", log([result({ locations: [{}, {}] })])],
    [
      "oversized message",
      log([result({ message: { text: "x".repeat(16 * 1024 + 1) } })]),
    ],
    [
      "oversized fix",
      log([
        result({
          properties: { trestleFixGuidance: "x".repeat(16 * 1024 + 1) },
        }),
      ]),
    ],
    ["unknown level", log([result({ level: "none" })])],
    ["missing level", log([result({ level: undefined })])],
    ["too many results", log(Array.from({ length: 1001 }, () => result()))],
    ["wrong version", log([result()], {}, "2.0.0")],
    [
      "two runs",
      JSON.stringify({
        version: "2.1.0",
        runs: [{ results: [] }, { results: [] }],
      }),
    ],
    ["not JSON", "trestle: error"],
  ])("rejects %s", (_name, source) => {
    expect(() => parseReview(source)).toThrow(SarifError);
  });
});
