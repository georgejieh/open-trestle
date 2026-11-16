import { describe, expect, it, vi } from "vitest";
import { ApiError } from "./api";
import { runSetupCheck } from "./setupApi";
import type { SetupCheckInput } from "./types";

const token = "x".repeat(32);
const identity = "a".repeat(64);
const input = {
  plan_identity: identity,
  key: "secret_backend_validated" as const,
  approve_kms_authority_identity: identity,
  kms_region: "local-1",
  kms_key_arn: "test-key",
  approved_by: "owner",
};
describe("setup check field projection", () => {
  it.each([
    { kms_region: "" },
    { kms_key_arn: "space not allowed" },
    { kms_endpoint: "" },
    { approve_kms_authority_identity: "" },
    { approved_by: "" },
    { allow_github_installation_token_creation: true },
    { approve_github_source_broker_authority_identity: identity },
  ])(
    "rejects invalid or foreign authority fields before transport: %o",
    async (patch) => {
      const fetcher = vi.fn();
      await expect(
        runSetupCheck(
          { ...input, ...patch } as SetupCheckInput,
          token,
          fetcher,
        ),
      ).rejects.toMatchObject({ code: "invalid_scope" });
      expect(fetcher).not.toHaveBeenCalled();
    },
  );
  it.each([undefined, "http://local.invalid"])(
    "copies only owned fields and preserves optional endpoint %s",
    async (kms_endpoint) => {
      let body: unknown;
      const fetcher = vi.fn(async (_path: string, init: RequestInit) => {
        body = JSON.parse(String(init.body));
        return new Response(
          JSON.stringify({
            contract: "open-trestle/setup-error",
            schema_version: 1,
            code: "check_failed",
          }),
          {
            status: 422,
            headers: { "content-type": "application/json" },
          },
        );
      });
      await expect(
        runSetupCheck(
          {
            ...input,
            kms_endpoint,
            extra: "must not be forwarded",
          } as SetupCheckInput,
          token,
          fetcher,
        ),
      ).rejects.toBeInstanceOf(ApiError);
      expect(body).toEqual({
        contract: "open-trestle/setup-check-request",
        schema_version: 1,
        confirmation: "run secret_backend_validated",
        ...input,
        ...(kms_endpoint === undefined ? {} : { kms_endpoint }),
      });
    },
  );
});
