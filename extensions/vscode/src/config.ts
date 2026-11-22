import { isAbsolute } from "node:path";
export function validExecutable(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const bytes = Buffer.byteLength(value, "utf8");
  return (
    bytes >= 1 &&
    bytes <= 4096 &&
    !/[\u0000\r\n]/u.test(value) &&
    (isAbsolute(value) || /^[A-Za-z0-9._-]+$/.test(value))
  );
}
// What trestle and git need to find their programs, state, keys and proxies.
const inheritedKeys = [
  "PATH",
  "PATHEXT",
  "HOME",
  "USERPROFILE",
  "APPDATA",
  "LOCALAPPDATA",
  "SystemRoot",
  "WINDIR",
  "TMPDIR",
  "TMP",
  "TEMP",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "no_proxy",
] as const;
const inheritedPrefixes = ["XDG_", "OPEN_TRESTLE_PROVIDER_"] as const;
function usable(value: string | undefined): value is string {
  return (
    value !== undefined && value.length <= 32767 && !value.includes("\u0000")
  );
}
// childEnvironment is the allowlisted environment of a review; everything
// else, such as OPEN_TRESTLE_API_TOKEN, stays out.
export function childEnvironment(
  inherited: NodeJS.ProcessEnv,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const key of inheritedKeys) {
    const value = inherited[key];
    if (usable(value)) result[key] = value;
  }
  for (const [key, value] of Object.entries(inherited))
    if (
      inheritedPrefixes.some((prefix) => key.startsWith(prefix)) &&
      usable(value)
    )
      result[key] = value;
  result.NO_COLOR = "1";
  return result;
}
