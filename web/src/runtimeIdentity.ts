// Runtime validators admit only the closed ASCII identifier, enum, digest, and UTC timestamp grammars. Within that validated grammar JSON.stringify is byte-identical to Go json.Marshal.
const runtimeSHA256 = async (
  domain: string,
  value: unknown,
): Promise<string> => {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`${domain}\0${JSON.stringify(value)}`),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
};

export interface RuntimeHandlerWire {
  kind: string;
  identity: string;
}
export interface RuntimeComponentWire {
  name: string;
  state: "starting" | "ready";
}
export interface RuntimeConfigurationWire {
  tenant_id: string;
  repository_ids: string[];
  metadata_backend: string;
  artifact_backend: string;
  artifact_protection: string;
  notification_backend: string;
  rate_limit_backend: string;
  review_mode: string;
  webhook_ingress: boolean;
  local_workers: boolean;
  publication_enabled: boolean;
  publication_fence_verified: boolean;
  route_inventory_identity?: string;
  runtime_policy_identity?: string;
  route_count: number;
  handlers: RuntimeHandlerWire[] | null;
}

export const canonicalRuntimeConfiguration = (
  value: Record<string, unknown>,
  handlers: RuntimeHandlerWire[] | null,
  keys: readonly string[],
): RuntimeConfigurationWire =>
  Object.fromEntries(
    keys.map((key) => [key, key === "handlers" ? handlers : value[key]]),
  ) as unknown as RuntimeConfigurationWire;

export const runtimeConfigurationIdentity = (
  configuration: RuntimeConfigurationWire,
) => runtimeSHA256("open-trestle/runtime-configuration/v1", configuration);

export const runtimeStatusIdentity = (value: {
  configuration_identity: string;
  tenant_id: string;
  repository_id: string;
  observed_at: string;
  ready: boolean;
  configuration: RuntimeConfigurationWire;
  components: RuntimeComponentWire[];
}) =>
  runtimeSHA256("open-trestle/runtime-status/v1", {
    contract: "open-trestle/runtime-status",
    schema_version: 1,
    identity: "",
    configuration_identity: value.configuration_identity,
    tenant_id: value.tenant_id,
    repository_id: value.repository_id,
    observed_at: value.observed_at,
    ready: value.ready,
    configuration: value.configuration,
    components: value.components,
  });
