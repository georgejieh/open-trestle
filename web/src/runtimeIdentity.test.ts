import { describe, expect, it } from "vitest";
import {
  runtimeConfigurationIdentity,
  runtimeStatusIdentity,
  type RuntimeConfigurationWire,
} from "./runtimeIdentity";

const handlers = [
  { kind: "acquire_source", identity: "a".repeat(64) },
  { kind: "build_change", identity: "b".repeat(64) },
  { kind: "inspect_deterministic", identity: "c".repeat(64) },
];

describe("Runtime Go identity parity", () => {
  it("matches the production parser Go golden", async () => {
    const configuration: RuntimeConfigurationWire = {
      tenant_id: "tenant-a",
      repository_ids: ["repo-a"],
      metadata_backend: "local",
      artifact_backend: "local",
      artifact_protection: "process_private",
      notification_backend: "process_local",
      rate_limit_backend: "process_local",
      review_mode: "disabled",
      webhook_ingress: false,
      local_workers: false,
      publication_enabled: false,
      publication_fence_verified: false,
      route_count: 0,
      handlers: null,
    };
    const configuration_identity =
      await runtimeConfigurationIdentity(configuration);
    expect(configuration_identity).toBe(
      "d625957a083abd5743f09c5ee719c15afc19b2615c144644b8394bf5b85d3256",
    );
    expect(
      await runtimeStatusIdentity({
        configuration_identity,
        tenant_id: "tenant-a",
        repository_id: "repo-a",
        observed_at: "2026-09-03T12:00:00Z",
        ready: true,
        configuration,
        components: [],
      }),
    ).toBe("5d7b86d0e18ba6c26c49d349221b99e41f0dc78994cd36477b12b6f11aab64fd");
  });

  it("matches the packaged local single-node Go golden", async () => {
    const configuration: RuntimeConfigurationWire = {
      tenant_id: "tenant-a",
      repository_ids: ["repository-a"],
      metadata_backend: "local",
      artifact_backend: "local",
      artifact_protection: "process_private",
      notification_backend: "process_local",
      rate_limit_backend: "process_local",
      review_mode: "local",
      webhook_ingress: false,
      local_workers: true,
      publication_enabled: false,
      publication_fence_verified: false,
      route_count: 0,
      handlers,
    };
    const configuration_identity =
      await runtimeConfigurationIdentity(configuration);
    expect(configuration_identity).toBe(
      "f89cbad323eb45449637dd40eba77f7eb63a987754270b85c2f9ec2db5c9be98",
    );
    expect(
      await runtimeStatusIdentity({
        configuration_identity,
        tenant_id: "tenant-a",
        repository_id: "repository-a",
        observed_at: "2026-10-03T05:00:00Z",
        ready: true,
        configuration,
        components: [
          { name: "local_workers", state: "ready" },
          { name: "task_notifications", state: "ready" },
        ],
      }),
    ).toBe("7140112d9eee5bd9287fe98dc1a2985e79ebf4c00baf33975504c8691830c576");
  });

  it("matches the empty disabled Go golden with null handlers", async () => {
    const configuration: RuntimeConfigurationWire = {
      tenant_id: "tenant-a",
      repository_ids: ["repository-a"],
      metadata_backend: "local",
      artifact_backend: "local",
      artifact_protection: "process_private",
      notification_backend: "process_local",
      rate_limit_backend: "process_local",
      review_mode: "disabled",
      webhook_ingress: false,
      local_workers: false,
      publication_enabled: false,
      publication_fence_verified: false,
      route_count: 0,
      handlers: null,
    };
    const configuration_identity =
      await runtimeConfigurationIdentity(configuration);
    expect(configuration_identity).toBe(
      "26ab6e2eb1f2b47d3c8e7f6b8eacb65c76d3594a223a7c9c73ac23f8b08b2d5a",
    );
    expect(
      await runtimeStatusIdentity({
        configuration_identity,
        tenant_id: "tenant-a",
        repository_id: "repository-a",
        observed_at: "2026-10-03T05:00:00Z",
        ready: true,
        configuration,
        components: [],
      }),
    ).toBe("8e915eaca0878ba00b7acc3c2ed907333b13e1ff1b825f60c43b8ab0832dd931");
  });
});
