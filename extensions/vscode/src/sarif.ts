// Reads the SARIF that `trestle review --format sarif` writes. A document
// that breaks a rule below is rejected as a whole.
export type Level = "error" | "warning" | "note";
export interface Finding {
  path: string;
  startLine: number;
  endLine: number;
  level: Level;
  ruleId: string;
  message: string;
}
export interface Review {
  succeeded: boolean;
  status: string;
  revision: string;
  findings: Finding[];
  notifications: string[];
}
export const untrustedWarning =
  "\n\n[untrusted review output; verify before editing]";
const maxResults = 1000;
const maxTextBytes = 16 * 1024;
const levels = new Set(["error", "warning", "note"]);
export class SarifError extends Error {}
function fail(reason: string): never {
  throw new SarifError(reason);
}
type Fields = Record<string, unknown>;
function fields(value: unknown, what: string): Fields {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    fail(`${what} is not an object`);
  return value as Fields;
}
function list(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) fail(`${what} is not a list`);
  return value;
}
function text(value: unknown, what: string): string {
  if (typeof value !== "string" || Buffer.byteLength(value) > maxTextBytes)
    fail(`${what} is missing or longer than 16 KiB`);
  return value;
}
function line(value: unknown): number {
  if (!Number.isInteger(value) || (value as number) < 1) fail("bad line");
  return value as number;
}
// relativePath accepts a repository-relative URI only.
function relativePath(value: unknown): string {
  if (typeof value !== "string" || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(value))
    fail("artifact URI is not relative");
  // Go writes "./" before a first segment that holds a colon.
  const uri = value.startsWith("./") ? value.slice(2) : value;
  let path: string;
  try {
    path = decodeURIComponent(uri);
  } catch {
    fail("artifact URI is not decodable");
  }
  const segments = path.split(/[\\/]/);
  if (
    path.includes("\u0000") ||
    /^[A-Za-z]:$/.test(segments[0] ?? "") ||
    segments.some((part) => part === "" || part === "." || part === "..")
  )
    fail(`artifact path ${JSON.stringify(path)} is not inside the repository`);
  return segments.join("/");
}
function finding(value: unknown): Finding {
  const result = fields(value, "result");
  const level = result.level;
  if (typeof level !== "string" || !levels.has(level)) fail("bad level");
  const locations = list(result.locations, "locations");
  if (locations.length !== 1) fail("a result needs exactly one location");
  const physical = fields(
    fields(locations[0], "location").physicalLocation,
    "physical location",
  );
  const region = fields(physical.region, "region");
  const startLine = line(region.startLine);
  const endLine = line(region.endLine);
  if (endLine < startLine) fail("bad line range");
  const properties = fields(result.properties ?? {}, "result properties");
  let message = text(fields(result.message, "message").text, "message");
  if (properties.trestleFixGuidance !== undefined)
    message += `\n\nFix (unverified model guidance): ${text(properties.trestleFixGuidance, "fix guidance")}`;
  return {
    path: relativePath(
      fields(physical.artifactLocation, "artifact location").uri,
    ),
    startLine,
    endLine,
    level: level as Level,
    ruleId: text(result.ruleId, "rule"),
    message: message + untrustedWarning,
  };
}
export function parseReview(source: string): Review {
  let document: unknown;
  try {
    document = JSON.parse(source);
  } catch {
    fail("the output is not JSON");
  }
  const log = fields(document, "document");
  const runs = list(log.runs, "runs");
  if (log.version !== "2.1.0" || runs.length !== 1)
    fail("not a SARIF 2.1.0 log with one run");
  const run = fields(runs[0], "run");
  const results = list(run.results, "results");
  if (results.length > maxResults) fail("more than 1000 results");
  const invocations = list(run.invocations ?? [], "invocations").map((item) =>
    fields(item, "invocation"),
  );
  const notifications = invocations.flatMap((invocation) =>
    list(invocation.toolExecutionNotifications ?? [], "notifications").map(
      (item) =>
        text(
          fields(fields(item, "notification").message, "message").text,
          "notification",
        ),
    ),
  );
  const properties = fields(run.properties ?? {}, "run properties");
  const status =
    properties.trestleModelReviewStatus ?? properties.trestleStatus;
  const revision = properties.trestleRevision;
  return {
    succeeded: invocations.every((item) => item.executionSuccessful === true),
    status: typeof status === "string" ? status.slice(0, 64) : "",
    revision: typeof revision === "string" ? revision.slice(0, 12) : "",
    findings: results.map(finding),
    notifications,
  };
}
// summary is the one line shown when a review ends.
export function summary(review: Review): string {
  const commit = review.revision ? ` of commit ${review.revision}` : "";
  const status = review.status || "unknown";
  if (!review.succeeded)
    return `Open Trestle: the review${commit} did not finish (${status}). No finding is shown; see the output for why.`;
  const count = review.findings.length;
  return `Open Trestle: ${count} finding${count === 1 ? "" : "s"} in the review${commit} (${status}). It describes the committed HEAD, not uncommitted edits, and is not a clearance.`;
}
