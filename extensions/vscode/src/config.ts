import { isIP } from "node:net";
import { isAbsolute } from "node:path";
export interface ExtensionSettings {
  executable: string;
  server: string;
  tenant: string;
  repository: string;
  run: string;
}
export interface LaunchConfiguration {
  command: string;
  args: readonly string[];
  initializationOptions: {
    tenant_id: string;
    repository_id: string;
    review_run_id: string;
  };
  environment: { OPEN_TRESTLE_API_TOKEN: string };
}
export class ConfigurationError extends Error {
  constructor() {
    super("Open Trestle configuration is incomplete or unsafe.");
    this.name = "ConfigurationError";
  }
}
const identifier = /^[a-z0-9](?:[a-z0-9._:-]*[a-z0-9])?$/;
function validIdentifier(value: string): boolean {
  return identifier.test(value) && Buffer.byteLength(value, "utf8") <= 128;
}
function validToken(value: string): boolean {
  return (
    Buffer.byteLength(value, "utf8") >= 32 &&
    Buffer.byteLength(value, "utf8") <= 512 &&
    !/[\u0000-\u0020\u007f\ud800-\udfff]/u.test(value)
  );
}
function validExecutable(value: string): boolean {
  const bytes = Buffer.byteLength(value, "utf8");
  return (
    bytes >= 1 &&
    bytes <= 4096 &&
    !/[\u0000\r\n]/u.test(value) &&
    (isAbsolute(value) || /^[A-Za-z0-9._-]+$/.test(value))
  );
}
function validServer(value: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    (parsed.pathname !== "" && parsed.pathname !== "/") ||
    !parsed.hostname
  )
    return false;
  if (parsed.protocol === "https:") return true;
  if (parsed.protocol !== "http:") return false;
  const canonicalOrigin = `${parsed.protocol}//${parsed.host}`;
  if (value !== canonicalOrigin && value !== `${canonicalOrigin}/`)
    return false;
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
  const version = isIP(hostname);
  return (
    (version === 4 && hostname.startsWith("127.")) ||
    (version === 6 && hostname === "::1")
  );
}
export function buildLaunchConfiguration(
  settings: ExtensionSettings,
  token: string,
): LaunchConfiguration {
  if (
    !validExecutable(settings.executable) ||
    !validServer(settings.server) ||
    !validIdentifier(settings.tenant) ||
    !validIdentifier(settings.repository) ||
    !validIdentifier(settings.run) ||
    !validToken(token)
  )
    throw new ConfigurationError();
  return {
    command: settings.executable,
    args: ["lsp", "--server", settings.server],
    initializationOptions: {
      tenant_id: settings.tenant,
      repository_id: settings.repository,
      review_run_id: settings.run,
    },
    environment: { OPEN_TRESTLE_API_TOKEN: token },
  };
}
const inheritedEnvironmentKeys = [
  "PATH",
  "Path",
  "PATHEXT",
  "HOME",
  "USERPROFILE",
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
export function buildChildEnvironment(
  inherited: NodeJS.ProcessEnv,
  token: string,
): Record<string, string> {
  if (!validToken(token)) throw new ConfigurationError();
  const result: Record<string, string> = { OPEN_TRESTLE_API_TOKEN: token };
  for (const key of inheritedEnvironmentKeys) {
    const value = inherited[key];
    if (
      value !== undefined &&
      value.length <= 4096 &&
      !value.includes("\u0000")
    )
      result[key] = value;
  }
  return result;
}
export function isValidToken(value: string): boolean {
  return validToken(value);
}
