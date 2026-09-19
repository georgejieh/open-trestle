import { createServer } from "node:http";
import { readFile, readdir } from "node:fs/promises";
import { extname, join } from "node:path";
import { visualAssetPath } from "./visual-assets.mjs";
import {
  checkTabletNavigation,
  checkMobileSetupNavigation,
  checkMobileBrandContrast,
} from "./navigation-layout.mjs";
import { chromium } from "playwright-core";
const root = new URL("../dist/", import.meta.url);
const visualAssets = new Set(await readdir(new URL("assets/", root)));
const digest = "a".repeat(64);
const tasks = [
  "source-base",
  "source-head",
  "change",
  "analysis",
  "memory",
  "context",
  "candidates",
  "verification",
  "readiness",
].map((key, index) => ({
  key,
  task_identity: String(index + 1).repeat(64),
  input_identity: digest,
  handler_identity: digest,
  kind: [
    "acquire_source",
    "acquire_source",
    "build_change",
    "inspect_deterministic",
    "retrieve_context",
    "assemble_context",
    "generate_candidates",
    "verify_candidates",
    "evaluate_publication",
  ][index],
  required: true,
  status: index < 7 ? "succeeded" : index === 7 ? "leased" : "pending",
  attempts: index < 8 ? 1 : 0,
  max_attempts: 1,
  lease_expires_at_milliseconds: index === 7 ? 1893456000000 : 0,
  output_identity: index < 7 ? digest : "",
  failure: "",
  retry_at_milliseconds: 0,
}));
const run = {
  contract: "open-trestle/review-run-receipt",
  schema_version: 1,
  identity: digest,
  plan_identity: digest,
  tenant_id: "tenant-a",
  repository_id: "payments-api",
  review_run_id: "pr-184",
  status: "active",
  revision: 19,
  head_identity: digest,
  last_occurred_at_milliseconds: 1788397200000,
  output_identity: "",
  failure: "",
  tasks,
};
const diagnostics = {
  contract: "open-trestle/review-diagnostic-set",
  schema_version: 5,
  identity: digest,
  tenant_id: "tenant-a",
  repository_id: "payments-api",
  review_run_id: "pr-184",
  snapshot_identity: digest,
  head_revision: "b".repeat(40),
  verified_set_identity: digest,
  coverage: {
    candidate_count: 4,
    verified_count: 2,
    rejected_count: 1,
    inconclusive_count: 1,
  },
  source_coverage: {
    verification_context_identity: "4".repeat(64),
    analyzed_count: 173,
    selected_count: 1,
    omitted_count: 172,
    omissions: [
      { reason: "selection_limit", count: 170 },
      { reason: "unsupported", count: 2 },
    ],
  },
  checks: [
    {
      identity: "5".repeat(64),
      source_check_identity: "6".repeat(64),
      analysis_result_identity: "7".repeat(64),
      change_identity: "8".repeat(64),
      key: "static_debug_output",
      rule_version: 1,
      state: "passed",
      applicable_files: 1,
      applicable_ranges: 3,
      checked_files: 1,
      checked_ranges: 3,
      matches: 0,
    },
  ],
  findings: [
    {
      identity: digest,
      source_identity: digest,
      fingerprint: digest,
      title: "Authorization check can be bypassed",
      message:
        "The new branch returns before the repository capability is verified. Move the capability check ahead of the early return.",
      severity: "error",
      path: "internal/access/policy.go",
      start_line: 84,
      end_line: 91,
      evidence_ids: ["evidence-authorization-84"],
    },
    {
      identity: "c".repeat(64),
      source_identity: "c".repeat(64),
      fingerprint: "c".repeat(64),
      title: "Cancellation is not propagated",
      message:
        "This request uses a background context, so shutdown cannot cancel the provider call.",
      severity: "warning",
      path: "runtime/dispatch.go",
      start_line: 117,
      end_line: 117,
      evidence_ids: ["evidence-context-117"],
    },
  ],
};
const runtimeStatus = {
  contract: "open-trestle/runtime-status",
  schema_version: 1,
  identity: "d".repeat(64),
  configuration_identity: "e".repeat(64),
  tenant_id: "tenant-a",
  repository_id: "payments-api",
  observed_at: "2026-09-03T19:00:00Z",
  ready: true,
  configuration: {
    tenant_id: "tenant-a",
    repository_ids: ["payments-api"],
    metadata_backend: "postgres",
    database_authority_identity: "9".repeat(64),
    artifact_backend: "s3",
    artifact_protection: "envelope_encrypted",
    notification_backend: "postgres",
    rate_limit_backend: "postgres",
    rate_limit_authority_identity: "8".repeat(64),
    review_mode: "required",
    webhook_ingress: true,
    local_workers: true,
    publication_enabled: true,
    publication_fence_verified: true,
    route_inventory_identity: "f".repeat(64),
    runtime_policy_identity: "1".repeat(64),
    route_count: 3,
    handlers: [
      { kind: "acquire_source", identity: "2".repeat(64) },
      { kind: "verify_candidates", identity: "3".repeat(64) },
    ],
  },
  components: [
    { name: "local_workers", state: "ready" },
    { name: "task_notifications", state: "ready" },
    { name: "webhook_processing", state: "ready" },
  ],
};

const setupKeys = [
  "backup_validated",
  "dry_run_validated",
  "local_administrator_validated",
  "local_inference_validated",
  "observer_credential_posture_validated",
  "policy_validated",
  "state_storage_posture_validated",
];
const setupAuthority = Object.fromEntries(
  setupKeys.map((key, index) => [key, String(index + 1).repeat(64)]),
);
const setupDefinitions = [
  ["profile_selected", "deterministic", "passed"],
  ["scope_valid", "deterministic", "passed"],
  ["effect_posture_locked", "deterministic", "passed"],
  ["recovery_owner_named", "deterministic", "passed"],
  ["state_storage_posture_validated", "probe", "pending"],
  ["backup_validated", "probe", "pending"],
  ["local_administrator_validated", "authorization", "pending"],
  ["observer_credential_posture_validated", "probe", "passed"],
  ["policy_validated", "authorization", "pending"],
  ["local_inference_validated", "probe", "pending"],
  ["dry_run_validated", "dry_run", "pending"],
];
const postgresSetupKeys = [
  "backup_validated",
  "dry_run_validated",
  "envelope_storage_validated",
  "integration_permissions_validated",
  "local_administrator_validated",
  "observer_credential_posture_validated",
  "policy_validated",
  "postgres_storage_validated",
  "remote_provider_authorized",
  "secret_backend_validated",
  "webhook_validated",
];
const postgresAuthority = Object.fromEntries(
  postgresSetupKeys.map((key, index) => [
    key,
    "123456789abcdef"[index].repeat(64),
  ]),
);
const postgresDefinitions = [
  ["profile_selected", "deterministic", "passed"],
  ["scope_valid", "deterministic", "passed"],
  ["effect_posture_locked", "deterministic", "passed"],
  ["recovery_owner_named", "deterministic", "passed"],
  ["postgres_storage_validated", "probe", "pending"],
  ["envelope_storage_validated", "probe", "pending"],
  ["backup_validated", "probe", "pending"],
  ["secret_backend_validated", "probe", "pending"],
  ["local_administrator_validated", "authorization", "pending"],
  ["observer_credential_posture_validated", "probe", "pending"],
  ["remote_provider_authorized", "authorization", "pending"],
  ["integration_permissions_validated", "authorization", "pending"],
  ["webhook_validated", "probe", "pending"],
  ["policy_validated", "authorization", "pending"],
  ["dry_run_validated", "dry_run", "pending"],
];
const postgresSetupPlan = {
  contract: "open-trestle/setup-plan",
  schema_version: 1,
  identity: "f".repeat(64),
  previous_identity: "",
  checker_catalog_identity: "e".repeat(64),
  checker_authorities: postgresSetupKeys.map((key) => ({
    key,
    checker_identity: postgresAuthority[key],
  })),
  revision: 1,
  tenant_id: "tenant-a",
  repository_id: "payments-api",
  recovery_owner: "platform-owner",
  profile: "controlled_hybrid",
  posture: {
    metadata_backend: "postgres",
    artifact_backend: "s3",
    artifact_protection: "envelope_encrypted",
    notification_backend: "postgres",
    inference: "approved_remote",
    egress: "allowlisted",
    integration: "least_privilege_scm",
    max_model_request_cost_micro_usd: 100000,
    retention_days: 30,
    provider_fallback_enabled: false,
    content_logging_allowed: false,
    publication_enabled: false,
    dynamic_validation_enabled: false,
  },
  requirements: postgresDefinitions.map(([key, source, state]) => ({
    key,
    source,
    state,
    checker_identity: "",
    evidence_identity: "",
    receipt_identity: "",
    recovery_action: "",
    checked_at: "",
  })),
  receipts: [],
  status: "incomplete",
  ready: false,
  created_at: "2026-09-03T12:00:00Z",
  updated_at: "2026-09-03T12:00:00Z",
};
const kubernetesSetupKeys = [
  "backup_validated",
  "dry_run_validated",
  "envelope_storage_validated",
  "integration_permissions_validated",
  "local_administrator_validated",
  "observer_credential_posture_validated",
  "policy_validated",
  "postgres_storage_validated",
  "remote_provider_authorized",
  "replica_reconciliation_validated",
  "secret_backend_validated",
  "shared_rate_limit_validated",
  "webhook_validated",
];
const kubernetesAuthority = Object.fromEntries(
  kubernetesSetupKeys.map((key, index) => [
    key,
    "123456789abcdef"[index].repeat(64),
  ]),
);
const kubernetesDefinitions = [
  ["profile_selected", "deterministic", "passed"],
  ["scope_valid", "deterministic", "passed"],
  ["effect_posture_locked", "deterministic", "passed"],
  ["recovery_owner_named", "deterministic", "passed"],
  ["postgres_storage_validated", "probe", "pending"],
  ["envelope_storage_validated", "probe", "pending"],
  ["backup_validated", "probe", "pending"],
  ["secret_backend_validated", "probe", "pending"],
  ["shared_rate_limit_validated", "probe", "pending"],
  ["replica_reconciliation_validated", "probe", "pending"],
  ["local_administrator_validated", "authorization", "pending"],
  ["observer_credential_posture_validated", "probe", "pending"],
  ["remote_provider_authorized", "authorization", "pending"],
  ["integration_permissions_validated", "authorization", "pending"],
  ["webhook_validated", "probe", "pending"],
  ["policy_validated", "authorization", "pending"],
  ["dry_run_validated", "dry_run", "pending"],
];
const kubernetesSetupPlan = {
  ...postgresSetupPlan,
  identity: "7".repeat(64),
  checker_catalog_identity: "6".repeat(64),
  checker_authorities: kubernetesSetupKeys.map((key) => ({
    key,
    checker_identity: kubernetesAuthority[key],
  })),
  profile: "kubernetes_ha",
  requirements: kubernetesDefinitions.map(([key, source, state]) => ({
    key,
    source,
    state,
    checker_identity: "",
    evidence_identity: "",
    receipt_identity: "",
    recovery_action: "",
    checked_at: "",
  })),
};

const airGappedSetupKeys = [
  "backup_validated",
  "dry_run_validated",
  "local_administrator_validated",
  "local_inference_validated",
  "no_egress_validated",
  "observer_credential_posture_validated",
  "policy_validated",
  "signed_bundle_validated",
  "state_storage_posture_validated",
];
const airGappedAuthority = Object.fromEntries(
  airGappedSetupKeys.map((key, index) => [key, "123456789"[index].repeat(64)]),
);
const airGappedDefinitions = [
  ["profile_selected", "deterministic", "passed"],
  ["scope_valid", "deterministic", "passed"],
  ["effect_posture_locked", "deterministic", "passed"],
  ["recovery_owner_named", "deterministic", "passed"],
  ["state_storage_posture_validated", "probe", "pending"],
  ["backup_validated", "probe", "pending"],
  ["local_administrator_validated", "authorization", "pending"],
  ["observer_credential_posture_validated", "probe", "pending"],
  ["signed_bundle_validated", "probe", "pending"],
  ["no_egress_validated", "probe", "pending"],
  ["policy_validated", "authorization", "pending"],
  ["local_inference_validated", "probe", "pending"],
  ["dry_run_validated", "dry_run", "pending"],
];
const airGappedSetupPlan = {
  ...kubernetesSetupPlan,
  identity: "8".repeat(64),
  checker_catalog_identity: "9".repeat(64),
  checker_authorities: airGappedSetupKeys.map((key) => ({
    key,
    checker_identity: airGappedAuthority[key],
  })),
  profile: "air_gapped",
  posture: {
    ...kubernetesSetupPlan.posture,
    metadata_backend: "local",
    artifact_backend: "local",
    artifact_protection: "process_private",
    notification_backend: "process_local",
    inference: "local_only",
    egress: "denied",
    integration: "offline_bundle",
    max_model_request_cost_micro_usd: 0,
  },
  requirements: airGappedDefinitions.map(([key, source, state]) => ({
    key,
    source,
    state,
    checker_identity: "",
    evidence_identity: "",
    receipt_identity: "",
    recovery_action: "",
    checked_at: "",
  })),
};

// PF1 display fixtures: exact root-native capture bytes, never synthetic upcasts.
// Current passed uses a trusted core probe with real Checker/Runner persistence,
// not broker/issuer evidence. Historical records keep their original roots and labels.
// current-pending.json SHA256 0fb784f7751223b3dd06248e5bcf424d73949e253ec92b6acb8bc556ed6e0e7f
const currentPendingWire = `{"contract":"open-trestle/setup-plan","schema_version":1,"identity":"13a7d1b6e3c8b103b33474b60abdc8c8ab4af95a75e578da58c4f98295222382","previous_identity":"","checker_catalog_identity":"b0b02c3a3259a984bd22e26527531e1194bc892ba3c30967135741c53e0e9037","checker_authorities":[{"key":"backup_validated","checker_identity":"03a4d428f289ba85dba8c4f1b7ddfafc74583d9309864f36cc6ef8926616b679"},{"key":"dry_run_validated","checker_identity":"10304a30edd798790388e923d73df4115b8526231641db5b13dee9d088f938df"},{"key":"envelope_storage_validated","checker_identity":"a7366f408e306dd70702319bfad8333f71e7e92b97604d69be936291a0b98ceb"},{"key":"integration_permissions_validated","checker_identity":"8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9"},{"key":"local_administrator_validated","checker_identity":"f3832f5d85d7774290f8b6c88a634ec956e68ced3198fd6fca64a9b6f99ced89"},{"key":"observer_credential_posture_validated","checker_identity":"4af5a2fcecd69ec07da6ffb696215820c2b84a225340953f68f5a126e52cf542"},{"key":"policy_validated","checker_identity":"5694cd4de9ea61bc97b9cdcfa651678c23f55e9998e564fea4570585cc8386a4"},{"key":"postgres_storage_validated","checker_identity":"df68a8e3dbe159f168d8464410a5be817e53a0d6870517edde780d374fcb17f0"},{"key":"remote_provider_authorized","checker_identity":"1999eefcbe108499aeeded297b938cbb248e5a14552ebdc697b3e69d7985f4c1"},{"key":"secret_backend_validated","checker_identity":"2ce90162ea0586ca8db04cda4e7a1ee9fc6303e7e2cc77773d36c519785839df"},{"key":"webhook_validated","checker_identity":"94b83acc748c71e3d42ce06632b4abb370f35bbfc2262d2c1e98a223d29fc14e"}],"revision":1,"tenant_id":"tenant-a","repository_id":"repo-a","recovery_owner":"owner","profile":"controlled_hybrid","posture":{"metadata_backend":"postgres","artifact_backend":"s3","artifact_protection":"envelope_encrypted","notification_backend":"postgres","inference":"approved_remote","egress":"allowlisted","integration":"least_privilege_scm","max_model_request_cost_micro_usd":100000,"retention_days":30,"provider_fallback_enabled":false,"content_logging_allowed":false,"publication_enabled":false,"dynamic_validation_enabled":false},"requirements":[{"key":"profile_selected","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"scope_valid","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"effect_posture_locked","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"recovery_owner_named","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"postgres_storage_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"envelope_storage_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"backup_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"secret_backend_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"local_administrator_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"observer_credential_posture_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"remote_provider_authorized","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"integration_permissions_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"webhook_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"policy_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"dry_run_validated","source":"dry_run","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""}],"receipts":[],"status":"incomplete","ready":false,"created_at":"2026-09-03T12:00:00Z","updated_at":"2026-09-03T12:00:00Z"}`;
// current-permission-passed.json SHA256 9f8ae573208af5f124d0a6b52305e1b8e24277b1a73cbc5bde8296849aabc145
const currentPermissionPassedWire = `{"contract":"open-trestle/setup-plan","schema_version":1,"identity":"afe02566f69710d5d7f7e7f55898d41be1001bbc9641cae81ce3b11a5a506d07","previous_identity":"13a7d1b6e3c8b103b33474b60abdc8c8ab4af95a75e578da58c4f98295222382","checker_catalog_identity":"b0b02c3a3259a984bd22e26527531e1194bc892ba3c30967135741c53e0e9037","checker_authorities":[{"key":"backup_validated","checker_identity":"03a4d428f289ba85dba8c4f1b7ddfafc74583d9309864f36cc6ef8926616b679"},{"key":"dry_run_validated","checker_identity":"10304a30edd798790388e923d73df4115b8526231641db5b13dee9d088f938df"},{"key":"envelope_storage_validated","checker_identity":"a7366f408e306dd70702319bfad8333f71e7e92b97604d69be936291a0b98ceb"},{"key":"integration_permissions_validated","checker_identity":"8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9"},{"key":"local_administrator_validated","checker_identity":"f3832f5d85d7774290f8b6c88a634ec956e68ced3198fd6fca64a9b6f99ced89"},{"key":"observer_credential_posture_validated","checker_identity":"4af5a2fcecd69ec07da6ffb696215820c2b84a225340953f68f5a126e52cf542"},{"key":"policy_validated","checker_identity":"5694cd4de9ea61bc97b9cdcfa651678c23f55e9998e564fea4570585cc8386a4"},{"key":"postgres_storage_validated","checker_identity":"df68a8e3dbe159f168d8464410a5be817e53a0d6870517edde780d374fcb17f0"},{"key":"remote_provider_authorized","checker_identity":"1999eefcbe108499aeeded297b938cbb248e5a14552ebdc697b3e69d7985f4c1"},{"key":"secret_backend_validated","checker_identity":"2ce90162ea0586ca8db04cda4e7a1ee9fc6303e7e2cc77773d36c519785839df"},{"key":"webhook_validated","checker_identity":"94b83acc748c71e3d42ce06632b4abb370f35bbfc2262d2c1e98a223d29fc14e"}],"revision":2,"tenant_id":"tenant-a","repository_id":"repo-a","recovery_owner":"owner","profile":"controlled_hybrid","posture":{"metadata_backend":"postgres","artifact_backend":"s3","artifact_protection":"envelope_encrypted","notification_backend":"postgres","inference":"approved_remote","egress":"allowlisted","integration":"least_privilege_scm","max_model_request_cost_micro_usd":100000,"retention_days":30,"provider_fallback_enabled":false,"content_logging_allowed":false,"publication_enabled":false,"dynamic_validation_enabled":false},"requirements":[{"key":"profile_selected","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"scope_valid","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"effect_posture_locked","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"recovery_owner_named","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"postgres_storage_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"envelope_storage_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"backup_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"secret_backend_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"local_administrator_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"observer_credential_posture_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"remote_provider_authorized","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"integration_permissions_validated","source":"authorization","state":"passed","checker_identity":"8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9","evidence_identity":"331e21772e9df49314d6b49093a67bdae04b091bbc9f49a18ecda64edaaddbdb","receipt_identity":"9faa2e5da98281f1460bde688dcfc881c18f69f65584cfe5e64811da5ebf8013","recovery_action":"","checked_at":"2026-09-03T12:00:01Z"},{"key":"webhook_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"policy_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"dry_run_validated","source":"dry_run","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""}],"receipts":[{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"9faa2e5da98281f1460bde688dcfc881c18f69f65584cfe5e64811da5ebf8013","plan_identity":"13a7d1b6e3c8b103b33474b60abdc8c8ab4af95a75e578da58c4f98295222382","key":"integration_permissions_validated","checker_identity":"8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9","state":"passed","evidence_identity":"331e21772e9df49314d6b49093a67bdae04b091bbc9f49a18ecda64edaaddbdb","recovery_action":"","checked_at":"2026-09-03T12:00:01Z"}],"status":"incomplete","ready":false,"created_at":"2026-09-03T12:00:00Z","updated_at":"2026-09-03T12:00:01Z"}`;
// historical-ready.json SHA256 f51df1f3eab934c87bf0bd52274d5c5cbb1813bee7d1ae2b2e82262b37b477e4
const historicalReadyWire = `{"contract":"open-trestle/setup-plan","schema_version":1,"identity":"477610992d01ff93ac5142d73969b135964efa02753db4ed203bdcdd9c852f37","previous_identity":"a75d020f83f3737c28bf47432183a5559a5498801f09dcf7e5f1886087a0559a","checker_catalog_identity":"3a88cb6db2d7a6b3b9eae8aa36e4ca2a0914e6ad5138bb9e5249607d12c49b1f","checker_authorities":[{"key":"backup_validated","checker_identity":"03a4d428f289ba85dba8c4f1b7ddfafc74583d9309864f36cc6ef8926616b679"},{"key":"dry_run_validated","checker_identity":"10304a30edd798790388e923d73df4115b8526231641db5b13dee9d088f938df"},{"key":"envelope_storage_validated","checker_identity":"a7366f408e306dd70702319bfad8333f71e7e92b97604d69be936291a0b98ceb"},{"key":"integration_permissions_validated","checker_identity":"cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b"},{"key":"local_administrator_validated","checker_identity":"f3832f5d85d7774290f8b6c88a634ec956e68ced3198fd6fca64a9b6f99ced89"},{"key":"observer_credential_posture_validated","checker_identity":"4af5a2fcecd69ec07da6ffb696215820c2b84a225340953f68f5a126e52cf542"},{"key":"policy_validated","checker_identity":"5694cd4de9ea61bc97b9cdcfa651678c23f55e9998e564fea4570585cc8386a4"},{"key":"postgres_storage_validated","checker_identity":"df68a8e3dbe159f168d8464410a5be817e53a0d6870517edde780d374fcb17f0"},{"key":"remote_provider_authorized","checker_identity":"1999eefcbe108499aeeded297b938cbb248e5a14552ebdc697b3e69d7985f4c1"},{"key":"secret_backend_validated","checker_identity":"2ce90162ea0586ca8db04cda4e7a1ee9fc6303e7e2cc77773d36c519785839df"},{"key":"webhook_validated","checker_identity":"94b83acc748c71e3d42ce06632b4abb370f35bbfc2262d2c1e98a223d29fc14e"}],"revision":12,"tenant_id":"pf1-tenant","repository_id":"pf1-repository","recovery_owner":"pf1-owner","profile":"controlled_hybrid","posture":{"metadata_backend":"postgres","artifact_backend":"s3","artifact_protection":"envelope_encrypted","notification_backend":"postgres","inference":"approved_remote","egress":"allowlisted","integration":"least_privilege_scm","max_model_request_cost_micro_usd":100000,"retention_days":30,"provider_fallback_enabled":false,"content_logging_allowed":false,"publication_enabled":false,"dynamic_validation_enabled":false},"requirements":[{"key":"profile_selected","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"scope_valid","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"effect_posture_locked","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"recovery_owner_named","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"postgres_storage_validated","source":"probe","state":"passed","checker_identity":"df68a8e3dbe159f168d8464410a5be817e53a0d6870517edde780d374fcb17f0","evidence_identity":"afdf43c9ce57573fb0831000ea91485b5788817460f415964cc862f144bcdbcd","receipt_identity":"e6ccc9cd6d623b492f70d8172bd57a34ca3b6541c5c57bb25276daaa3f8837d4","recovery_action":"","checked_at":"2026-09-06T12:00:01Z"},{"key":"envelope_storage_validated","source":"probe","state":"passed","checker_identity":"a7366f408e306dd70702319bfad8333f71e7e92b97604d69be936291a0b98ceb","evidence_identity":"97a973f85cb76a13eca66a95185da744ffa6da2e5bd2f3c4e0f8613d9e8bd1d8","receipt_identity":"bd17419c5716aeb1b5414cc8ec426491b278af538c6e6b43421ce0511b7b2cda","recovery_action":"","checked_at":"2026-09-06T12:00:01.001Z"},{"key":"backup_validated","source":"probe","state":"passed","checker_identity":"03a4d428f289ba85dba8c4f1b7ddfafc74583d9309864f36cc6ef8926616b679","evidence_identity":"60d78552e0d35c7dc13dd9cfd89e1ff76b76323f4829ab7e717277a7936082a5","receipt_identity":"f70d4f88408098e5aed8dcd3d508c89de0f659ef405f771bd9b25319d17d2d14","recovery_action":"","checked_at":"2026-09-06T12:00:01.002Z"},{"key":"secret_backend_validated","source":"probe","state":"passed","checker_identity":"2ce90162ea0586ca8db04cda4e7a1ee9fc6303e7e2cc77773d36c519785839df","evidence_identity":"82c9265bbda4030565eea12350c71c5604409cca19d50b24895de8da4a3346f2","receipt_identity":"168d52f394f9802792fe0cac82f61f085dbb279558b5793dacf36f90baa40f9a","recovery_action":"","checked_at":"2026-09-06T12:00:01.003Z"},{"key":"local_administrator_validated","source":"authorization","state":"passed","checker_identity":"f3832f5d85d7774290f8b6c88a634ec956e68ced3198fd6fca64a9b6f99ced89","evidence_identity":"0e09d600dc0b958727c51537c3d760e15fdd8f73322be300b5118342d565c9d9","receipt_identity":"080724ca251b744f12169dc9bb19445b2fa09798d9b6cb472e1b4ab69ff06fc2","recovery_action":"","checked_at":"2026-09-06T12:00:01.004Z"},{"key":"observer_credential_posture_validated","source":"probe","state":"passed","checker_identity":"4af5a2fcecd69ec07da6ffb696215820c2b84a225340953f68f5a126e52cf542","evidence_identity":"1bb95ae746cd621e886b1831c792e05977fd3dcc44c94ffb3ae44a66ca5c90af","receipt_identity":"31fe3119d38c1b0386480009334984ff588ef17cecc33ae6972c2c906b02bd01","recovery_action":"","checked_at":"2026-09-06T12:00:01.005Z"},{"key":"remote_provider_authorized","source":"authorization","state":"passed","checker_identity":"1999eefcbe108499aeeded297b938cbb248e5a14552ebdc697b3e69d7985f4c1","evidence_identity":"01db8e6c239d45b64dcc49dba8021a2f5ab7bcb5da37ce302743f3e65089b824","receipt_identity":"982fefeb83039ceaf3c64434d58a4dc443e6fa700c564590c38c14b85267a7cf","recovery_action":"","checked_at":"2026-09-06T12:00:01.006Z"},{"key":"integration_permissions_validated","source":"authorization","state":"passed","checker_identity":"cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b","evidence_identity":"764af3d0634054f2e3ab7fe1f7e748181dce796d9bc0e6f8fa64608795c18744","receipt_identity":"81ec1517b94e0a5df85a56251fe1048c243039b6e963ebd5a5b0a9358f5b35f3","recovery_action":"","checked_at":"2026-09-06T12:00:01.007Z"},{"key":"webhook_validated","source":"probe","state":"passed","checker_identity":"94b83acc748c71e3d42ce06632b4abb370f35bbfc2262d2c1e98a223d29fc14e","evidence_identity":"c80e12afbac08c60399042e84dd2fc53f95f4ca8e70eb24ff25cf4c3b3f01302","receipt_identity":"8d8c425303a6c5159eafa9588e648dbaf832bffedf0e6118c95e85f86725007e","recovery_action":"","checked_at":"2026-09-06T12:00:01.008Z"},{"key":"policy_validated","source":"authorization","state":"passed","checker_identity":"5694cd4de9ea61bc97b9cdcfa651678c23f55e9998e564fea4570585cc8386a4","evidence_identity":"53583fabf316124a6e15f929f1cfc2abd5614b35fd87b6b267dd217e477a0b64","receipt_identity":"4a884c2c4069219a5d4d6a108510c60e82402ab527f9e456cce87f6955eeea48","recovery_action":"","checked_at":"2026-09-06T12:00:01.009Z"},{"key":"dry_run_validated","source":"dry_run","state":"passed","checker_identity":"10304a30edd798790388e923d73df4115b8526231641db5b13dee9d088f938df","evidence_identity":"50a76f53896eb3cb0eed810e012cab4891dee773c6c63a31c50af6e68c61dbd0","receipt_identity":"ac91aee87a2546952f98a430df39f9b223b262b807fd2aad811e338e270dd9f0","recovery_action":"","checked_at":"2026-09-06T12:00:01.01Z"}],"receipts":[{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"e6ccc9cd6d623b492f70d8172bd57a34ca3b6541c5c57bb25276daaa3f8837d4","plan_identity":"f8ceacaddafd1bc9cbeabe52563974cf98797e47f67b3fcbf478b52830731c89","key":"postgres_storage_validated","checker_identity":"df68a8e3dbe159f168d8464410a5be817e53a0d6870517edde780d374fcb17f0","state":"passed","evidence_identity":"afdf43c9ce57573fb0831000ea91485b5788817460f415964cc862f144bcdbcd","recovery_action":"","checked_at":"2026-09-06T12:00:01Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"bd17419c5716aeb1b5414cc8ec426491b278af538c6e6b43421ce0511b7b2cda","plan_identity":"d481bdd10feda83553c2e2399fa5d826b44b01ac5a8506bbb6daa63138390254","key":"envelope_storage_validated","checker_identity":"a7366f408e306dd70702319bfad8333f71e7e92b97604d69be936291a0b98ceb","state":"passed","evidence_identity":"97a973f85cb76a13eca66a95185da744ffa6da2e5bd2f3c4e0f8613d9e8bd1d8","recovery_action":"","checked_at":"2026-09-06T12:00:01.001Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"f70d4f88408098e5aed8dcd3d508c89de0f659ef405f771bd9b25319d17d2d14","plan_identity":"2769d3661c6c5081c0992409965769b137100d76b830c6b429107502f8ccd492","key":"backup_validated","checker_identity":"03a4d428f289ba85dba8c4f1b7ddfafc74583d9309864f36cc6ef8926616b679","state":"passed","evidence_identity":"60d78552e0d35c7dc13dd9cfd89e1ff76b76323f4829ab7e717277a7936082a5","recovery_action":"","checked_at":"2026-09-06T12:00:01.002Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"168d52f394f9802792fe0cac82f61f085dbb279558b5793dacf36f90baa40f9a","plan_identity":"47b2a88dff5967bc151e88300c1bfa80a5f5b998d5bbb80c6f93f56f7d524122","key":"secret_backend_validated","checker_identity":"2ce90162ea0586ca8db04cda4e7a1ee9fc6303e7e2cc77773d36c519785839df","state":"passed","evidence_identity":"82c9265bbda4030565eea12350c71c5604409cca19d50b24895de8da4a3346f2","recovery_action":"","checked_at":"2026-09-06T12:00:01.003Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"080724ca251b744f12169dc9bb19445b2fa09798d9b6cb472e1b4ab69ff06fc2","plan_identity":"75b2d790e3e3b38a3e55b9cade48a58833571ab4279670b9f94d477127687317","key":"local_administrator_validated","checker_identity":"f3832f5d85d7774290f8b6c88a634ec956e68ced3198fd6fca64a9b6f99ced89","state":"passed","evidence_identity":"0e09d600dc0b958727c51537c3d760e15fdd8f73322be300b5118342d565c9d9","recovery_action":"","checked_at":"2026-09-06T12:00:01.004Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"31fe3119d38c1b0386480009334984ff588ef17cecc33ae6972c2c906b02bd01","plan_identity":"d6e0e5c9414dd479fd15befc8805bb75530bbafe8729d8e1ccbc852a1d489c73","key":"observer_credential_posture_validated","checker_identity":"4af5a2fcecd69ec07da6ffb696215820c2b84a225340953f68f5a126e52cf542","state":"passed","evidence_identity":"1bb95ae746cd621e886b1831c792e05977fd3dcc44c94ffb3ae44a66ca5c90af","recovery_action":"","checked_at":"2026-09-06T12:00:01.005Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"982fefeb83039ceaf3c64434d58a4dc443e6fa700c564590c38c14b85267a7cf","plan_identity":"aa4f045f2a6e955c2ce6930b3251408db81659e9758f6930a6b4eaef1bc08d7a","key":"remote_provider_authorized","checker_identity":"1999eefcbe108499aeeded297b938cbb248e5a14552ebdc697b3e69d7985f4c1","state":"passed","evidence_identity":"01db8e6c239d45b64dcc49dba8021a2f5ab7bcb5da37ce302743f3e65089b824","recovery_action":"","checked_at":"2026-09-06T12:00:01.006Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"81ec1517b94e0a5df85a56251fe1048c243039b6e963ebd5a5b0a9358f5b35f3","plan_identity":"4395e7b90fea4124a8256ca3c2ed599d447fa264807a848944172c4d6e7d8aab","key":"integration_permissions_validated","checker_identity":"cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b","state":"passed","evidence_identity":"764af3d0634054f2e3ab7fe1f7e748181dce796d9bc0e6f8fa64608795c18744","recovery_action":"","checked_at":"2026-09-06T12:00:01.007Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"8d8c425303a6c5159eafa9588e648dbaf832bffedf0e6118c95e85f86725007e","plan_identity":"96204a0eb0c85fe62f99d37e3d268b7869a7eff34ce1995aa9c1c368f7afd49a","key":"webhook_validated","checker_identity":"94b83acc748c71e3d42ce06632b4abb370f35bbfc2262d2c1e98a223d29fc14e","state":"passed","evidence_identity":"c80e12afbac08c60399042e84dd2fc53f95f4ca8e70eb24ff25cf4c3b3f01302","recovery_action":"","checked_at":"2026-09-06T12:00:01.008Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"4a884c2c4069219a5d4d6a108510c60e82402ab527f9e456cce87f6955eeea48","plan_identity":"a175e88e2983cddf6f38381c21f80a2793d711b143d55449e74941163eb2a2fc","key":"policy_validated","checker_identity":"5694cd4de9ea61bc97b9cdcfa651678c23f55e9998e564fea4570585cc8386a4","state":"passed","evidence_identity":"53583fabf316124a6e15f929f1cfc2abd5614b35fd87b6b267dd217e477a0b64","recovery_action":"","checked_at":"2026-09-06T12:00:01.009Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"ac91aee87a2546952f98a430df39f9b223b262b807fd2aad811e338e270dd9f0","plan_identity":"a75d020f83f3737c28bf47432183a5559a5498801f09dcf7e5f1886087a0559a","key":"dry_run_validated","checker_identity":"10304a30edd798790388e923d73df4115b8526231641db5b13dee9d088f938df","state":"passed","evidence_identity":"50a76f53896eb3cb0eed810e012cab4891dee773c6c63a31c50af6e68c61dbd0","recovery_action":"","checked_at":"2026-09-06T12:00:01.01Z"}],"status":"ready","ready":true,"created_at":"2026-09-06T12:00:00Z","updated_at":"2026-09-06T12:00:01.01Z"}`;
// legacy-capture/manifest.json fixtures[2].plan.bytes SHA256 b0f09483ce6e7db0ac31c389ac4cb2d430408f7ec5b0d4dec550d67479aa5766
const historicalPendingWebhookWire = `{"contract":"open-trestle/setup-plan","schema_version":1,"identity":"443a6272bcb6d541f6607834dbcbb718313f1d813f6ed0d15dcbd32a0228b0b8","previous_identity":"f8ceacaddafd1bc9cbeabe52563974cf98797e47f67b3fcbf478b52830731c89","checker_catalog_identity":"3a88cb6db2d7a6b3b9eae8aa36e4ca2a0914e6ad5138bb9e5249607d12c49b1f","checker_authorities":[{"key":"backup_validated","checker_identity":"03a4d428f289ba85dba8c4f1b7ddfafc74583d9309864f36cc6ef8926616b679"},{"key":"dry_run_validated","checker_identity":"10304a30edd798790388e923d73df4115b8526231641db5b13dee9d088f938df"},{"key":"envelope_storage_validated","checker_identity":"a7366f408e306dd70702319bfad8333f71e7e92b97604d69be936291a0b98ceb"},{"key":"integration_permissions_validated","checker_identity":"cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b"},{"key":"local_administrator_validated","checker_identity":"f3832f5d85d7774290f8b6c88a634ec956e68ced3198fd6fca64a9b6f99ced89"},{"key":"observer_credential_posture_validated","checker_identity":"4af5a2fcecd69ec07da6ffb696215820c2b84a225340953f68f5a126e52cf542"},{"key":"policy_validated","checker_identity":"5694cd4de9ea61bc97b9cdcfa651678c23f55e9998e564fea4570585cc8386a4"},{"key":"postgres_storage_validated","checker_identity":"df68a8e3dbe159f168d8464410a5be817e53a0d6870517edde780d374fcb17f0"},{"key":"remote_provider_authorized","checker_identity":"1999eefcbe108499aeeded297b938cbb248e5a14552ebdc697b3e69d7985f4c1"},{"key":"secret_backend_validated","checker_identity":"2ce90162ea0586ca8db04cda4e7a1ee9fc6303e7e2cc77773d36c519785839df"},{"key":"webhook_validated","checker_identity":"94b83acc748c71e3d42ce06632b4abb370f35bbfc2262d2c1e98a223d29fc14e"}],"revision":2,"tenant_id":"pf1-tenant","repository_id":"pf1-repository","recovery_owner":"pf1-owner","profile":"controlled_hybrid","posture":{"metadata_backend":"postgres","artifact_backend":"s3","artifact_protection":"envelope_encrypted","notification_backend":"postgres","inference":"approved_remote","egress":"allowlisted","integration":"least_privilege_scm","max_model_request_cost_micro_usd":100000,"retention_days":30,"provider_fallback_enabled":false,"content_logging_allowed":false,"publication_enabled":false,"dynamic_validation_enabled":false},"requirements":[{"key":"profile_selected","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"scope_valid","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"effect_posture_locked","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"recovery_owner_named","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"postgres_storage_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"envelope_storage_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"backup_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"secret_backend_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"local_administrator_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"observer_credential_posture_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"remote_provider_authorized","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"integration_permissions_validated","source":"authorization","state":"passed","checker_identity":"cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b","evidence_identity":"764af3d0634054f2e3ab7fe1f7e748181dce796d9bc0e6f8fa64608795c18744","receipt_identity":"732ca5ba0d984a50dbfcc4c15d38d1c7ab546115b9a811761a4a30cc6a6762ce","recovery_action":"","checked_at":"2026-09-06T12:00:01Z"},{"key":"webhook_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"policy_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"dry_run_validated","source":"dry_run","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""}],"receipts":[{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"732ca5ba0d984a50dbfcc4c15d38d1c7ab546115b9a811761a4a30cc6a6762ce","plan_identity":"f8ceacaddafd1bc9cbeabe52563974cf98797e47f67b3fcbf478b52830731c89","key":"integration_permissions_validated","checker_identity":"cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b","state":"passed","evidence_identity":"764af3d0634054f2e3ab7fe1f7e748181dce796d9bc0e6f8fa64608795c18744","recovery_action":"","checked_at":"2026-09-06T12:00:01Z"}],"status":"incomplete","ready":false,"created_at":"2026-09-06T12:00:00Z","updated_at":"2026-09-06T12:00:01Z"}`;
const pf1PlanWires = new Map([
  [`Bearer ${"n".repeat(32)}`, currentPendingWire],
  [`Bearer ${"g".repeat(32)}`, currentPermissionPassedWire],
  [`Bearer ${"r".repeat(32)}`, historicalReadyWire],
  [`Bearer ${"w".repeat(32)}`, historicalPendingWebhookWire],
]);
const currentChecker =
  "8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9";
const historicalChecker =
  "cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b";
for (const [wire, checker, permissionState] of [
  [currentPendingWire, currentChecker, "pending"],
  [currentPermissionPassedWire, currentChecker, "passed"],
  [historicalPendingWebhookWire, historicalChecker, "passed"],
]) {
  const plan = JSON.parse(wire);
  const permission = plan.requirements.find(
    (value) => value.key === "integration_permissions_validated",
  );
  const webhook = plan.requirements.find(
    (value) => value.key === "webhook_validated",
  );
  if (
    plan.checker_authorities.find((value) => value.key === permission.key)
      ?.checker_identity !== checker ||
    permission.state !== permissionState ||
    webhook.state !== "pending" ||
    webhook.receipt_identity !== "" ||
    webhook.evidence_identity !== "" ||
    (permissionState === "passed" &&
      !plan.receipts.some(
        (receipt) =>
          receipt.identity === permission.receipt_identity &&
          receipt.checker_identity === checker &&
          receipt.key === permission.key &&
          receipt.state === "passed",
      ))
  )
    throw new Error("PF1 native fixture prerequisite control failed");
}
if (!JSON.parse(historicalReadyWire).ready)
  throw new Error("historical Ready fixture control failed");

const setupReceipt = {
  contract: "open-trestle/setup-check-receipt",
  schema_version: 1,
  identity: "b".repeat(64),
  plan_identity: "4".repeat(64),
  key: "observer_credential_posture_validated",
  checker_identity: setupAuthority.observer_credential_posture_validated,
  state: "passed",
  evidence_identity: "c".repeat(64),
  recovery_action: "",
  checked_at: "2026-09-03T12:00:01Z",
};
const setupPlan = {
  contract: "open-trestle/setup-plan",
  schema_version: 1,
  identity: "d".repeat(64),
  previous_identity: setupReceipt.plan_identity,
  checker_catalog_identity: "e".repeat(64),
  checker_authorities: setupKeys.map((key) => ({
    key,
    checker_identity: setupAuthority[key],
  })),
  revision: 2,
  tenant_id: "tenant-a",
  repository_id: "payments-api",
  recovery_owner: "platform-owner",
  profile: "local_single_node",
  posture: {
    metadata_backend: "local",
    artifact_backend: "local",
    artifact_protection: "process_private",
    notification_backend: "process_local",
    inference: "local_only",
    egress: "denied",
    integration: "local",
    max_model_request_cost_micro_usd: 0,
    retention_days: 30,
    provider_fallback_enabled: false,
    content_logging_allowed: false,
    publication_enabled: false,
    dynamic_validation_enabled: false,
  },
  requirements: setupDefinitions.map(([key, source, state]) => ({
    key,
    source,
    state,
    checker_identity:
      state === "passed" && source !== "deterministic"
        ? setupReceipt.checker_identity
        : "",
    evidence_identity:
      state === "passed" && source !== "deterministic"
        ? setupReceipt.evidence_identity
        : "",
    receipt_identity:
      state === "passed" && source !== "deterministic"
        ? setupReceipt.identity
        : "",
    recovery_action: "",
    checked_at:
      state === "passed" && source !== "deterministic"
        ? setupReceipt.checked_at
        : "",
  })),
  receipts: [setupReceipt],
  status: "incomplete",
  ready: false,
  created_at: "2026-09-03T12:00:00Z",
  updated_at: setupReceipt.checked_at,
};

const server = createServer(async (request, response) => {
  const address = server.address();
  if (
    !address ||
    typeof address === "string" ||
    request.headers.host !== `127.0.0.1:${address.port}`
  ) {
    response.statusCode = 403;
    response.end();
    return;
  }
  let url;
  try {
    url = new URL(request.url ?? "/", "http://localhost");
  } catch {
    response.statusCode = 400;
    response.end();
    return;
  }
  if (url.pathname.startsWith("/api/v1/")) {
    response.setHeader("content-type", "application/json");
    if (url.pathname.startsWith("/api/v1/setup") && request.method !== "GET") {
      errors.push("unexpected setup effect request");
      response.statusCode = 405;
      response.end(
        JSON.stringify({
          contract: "open-trestle/setup-error",
          schema_version: 1,
          code: "invalid_request",
        }),
      );
      return;
    }
    if (url.pathname === "/api/v1/setup") {
      const setupAuthorization = request.headers.authorization;
      const nativeWire = pf1PlanWires.get(setupAuthorization);
      if (nativeWire !== undefined) {
        response.end(
          `{"contract":"open-trestle/setup-session","schema_version":1,"initialized":true,"plan":${nativeWire}}`,
        );
        return;
      }
      if (
        setupAuthorization !== `Bearer ${"s".repeat(32)}` &&
        setupAuthorization !== `Bearer ${"h".repeat(32)}` &&
        setupAuthorization !== `Bearer ${"a".repeat(32)}` &&
        setupAuthorization !== `Bearer ${"b".repeat(32)}`
      ) {
        response.statusCode = 401;
        response.end(
          JSON.stringify({
            contract: "open-trestle/setup-error",
            schema_version: 1,
            code: "unauthorized",
          }),
        );
        return;
      }
      response.end(
        JSON.stringify({
          contract: "open-trestle/setup-session",
          schema_version: 1,
          initialized: true,
          plan:
            setupAuthorization === `Bearer ${"h".repeat(32)}`
              ? kubernetesSetupPlan
              : setupAuthorization === `Bearer ${"a".repeat(32)}`
                ? airGappedSetupPlan
                : setupAuthorization === `Bearer ${"b".repeat(32)}`
                  ? postgresSetupPlan
                  : setupPlan,
        }),
      );
      return;
    }
    if (request.headers.authorization !== `Bearer ${"x".repeat(32)}`) {
      response.statusCode = 401;
      response.end(
        JSON.stringify({
          contract: "open-trestle/api-response",
          schema_version: 1,
          request_id: "visual",
          error: { code: "unauthenticated", message: "unauthenticated" },
        }),
      );
      return;
    }
    const payload = url.pathname.endsWith("/diagnostics")
      ? {
          contract: "open-trestle/api-response",
          schema_version: 1,
          request_id: "visual",
          diagnostics,
        }
      : url.pathname.endsWith("/runtime")
        ? {
            contract: "open-trestle/runtime-status-response",
            schema_version: 1,
            request_id: "visual",
            status: runtimeStatus,
          }
        : {
            contract: "open-trestle/api-response",
            schema_version: 1,
            request_id: "visual",
            run,
          };
    response.end(JSON.stringify(payload));
    return;
  }
  const relative = visualAssetPath(request.url, request.method, visualAssets);
  if (relative === null) {
    response.statusCode = 404;
    response.setHeader("content-type", "text/plain; charset=utf-8");
    response.end("Not found");
    return;
  }
  try {
    const body = await readFile(new URL(relative, root));
    const type =
      extname(relative) === ".css"
        ? "text/css"
        : extname(relative) === ".js"
          ? "text/javascript"
          : extname(relative) === ".svg"
            ? "image/svg+xml"
            : "text/html";
    response.setHeader("content-type", type);
    response.end(request.method === "HEAD" ? undefined : body);
  } catch {
    response.statusCode = 404;
    response.end();
  }
});
let browser;
let desktopOverflow = false,
  mobileOverflow = false,
  setupDesktopOverflow = false,
  setupMobileOverflow = false,
  setupIntegrationMobileOverflow = false,
  setupWebhookDesktopOverflow = false,
  setupWebhookMobileOverflow = false,
  setupRateLimitDesktopOverflow = false,
  setupRateLimitMobileOverflow = false,
  setupReconciliationDesktopOverflow = false,
  setupReconciliationMobileOverflow = false,
  setupSignedBundleDesktopOverflow = false,
  setupSignedBundleMobileOverflow = false;
const output = process.env.OPEN_TRESTLE_VISUAL_OUTPUT ?? "/tmp";
const errors = [];
try {
  await new Promise((resolve, reject) => {
    const failed = (error) => reject(error);
    server.once("error", failed);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", failed);
      resolve();
    });
  });
  const address = server.address();
  if (typeof address === "string" || address === null)
    throw new Error("listen failed");
  const base = `http://127.0.0.1:${address.port}/console/`;
  browser = await chromium.launch({
    headless: true,
    executablePath: "/usr/bin/chromium",
    args: ["--no-sandbox"],
  });
  async function newLocalPage(options) {
    const page = await browser.newPage(options);
    page.setDefaultTimeout(10000);
    page.setDefaultNavigationTimeout(15000);
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route("**/*", (route) => {
      if (new URL(route.request().url()).origin !== new URL(base).origin) {
        errors.push("unexpected external egress");
        return route.abort();
      }
      return route.continue();
    });
    return page;
  }
  const proof = await newLocalPage({
    viewport: { width: 960, height: 720 },
    deviceScaleFactor: 1,
  });
  const normalResponse = await proof.goto(base);
  if (normalResponse?.status() !== 200)
    throw new Error("normal fixture route failed");
  await proof.getByRole("heading", { name: "Locate a review run" }).waitFor();
  await proof.screenshot({ path: join(output, "proof-normal.png") });
  const missingResponse = await proof.goto(base + "unknown-visual-route");
  if (missingResponse?.status() !== 404)
    throw new Error("unknown fixture route did not return 404");
  await proof.getByText("Not found", { exact: true }).waitFor();
  await proof.screenshot({ path: join(output, "proof-404.png") });
  await proof.close();

  async function populate(page) {
    await page.goto(base);
    await page.getByLabel("Tenant").fill("tenant-a");
    await page.getByLabel("Repository").fill("payments-api");
    await page.getByLabel("Run", { exact: true }).fill("pr-184");
    await page.getByLabel("Access token").fill("x".repeat(32));
    await page.getByRole("button", { name: "Connect to run" }).click();
    await page.getByRole("heading", { name: "Run active" }).waitFor();
  }
  async function expectCopyFailure(page, name) {
    await page.evaluate(() => {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async () => {
            throw new Error("fixture clipboard denied");
          },
        },
      });
    });
    await page.getByRole("button", { name }).click();
    const status = page.getByRole("status");
    await status.waitFor();
    if ((await status.textContent()) !== "Copy failed") {
      throw new Error("clipboard rejection did not produce bounded feedback");
    }
  }
  async function expandFirstFinding(page) {
    const details = page.locator("details.finding-evidence").first();
    await details.locator("summary").click();
    if (!(await details.evaluate((element) => element.open))) {
      throw new Error("finding evidence disclosure did not open");
    }
    await page
      .getByRole("button", {
        name: "Copy Evidence reference 1: evidence-authorization-84",
      })
      .waitFor();
    await expectCopyFailure(page, /Copy Diagnostic identity:/);
  }

  async function populateSetup(
    page,
    heading = "local single node",
    credential = "s".repeat(32),
  ) {
    await page.goto(base + "setup");
    await page.getByLabel("Setup token").fill(credential);
    await page.getByRole("button", { name: "Inspect setup" }).click();
    await page.getByRole("heading", { name: heading }).waitFor();
  }
  async function expectNoReview(page) {
    if (
      await page
        .getByRole("button", { name: "Review receipt write", exact: true })
        .count()
    )
      throw new Error("unapproved PF1 action exposed");
  }
  async function armPF1(page, key) {
    const review = page.getByRole("button", {
      name: "Review receipt write",
      exact: true,
    });
    await review.focus();
    await page.keyboard.press("Enter");
    const confirm = page.getByRole("region", {
      name: `Write one ${key} receipt?`,
      exact: true,
    });
    await confirm.waitFor();
    const execute = page.getByRole("button", {
      name: `Run ${key}`,
      exact: true,
    });
    if (
      !(await execute.evaluate((element) => element === document.activeElement))
    )
      throw new Error("PF1 confirmation did not receive keyboard focus");
    // Never activate execute: these views cannot authorize real setup effects.
  }
  async function prepareCurrentIntegration(page) {
    await page
      .getByRole("button", { name: /integration permissions validated/i })
      .click();
    for (const name of [
      /GitHub API endpoint/i,
      /GitHub API version/i,
      /GitHub installation ID/i,
      /GitHub repository full name/i,
      /private key/i,
    ]) {
      if (await page.getByRole("textbox", { name }).count())
        throw new Error("legacy integration configuration input exposed");
    }
    for (const [name, value] of [
      [/Integration permission authority identity/i, "a".repeat(64)],
      [/GitHub source broker authority identity/i, "b".repeat(64)],
      [/Integration approved by/i, "owner"],
    ])
      await page.getByRole("textbox", { name }).fill(value);
    await expectNoReview(page);
    const consent = page.getByRole("button", {
      name: /^Allow GitHub installation token creation:/,
    });
    if ((await consent.getAttribute("aria-pressed")) !== "false")
      throw new Error("PF1 consent was not initially refused");
    await consent.focus();
    await page.keyboard.press("Space");
    await page
      .getByRole("button", {
        name: "Allow GitHub installation token creation: yes",
        exact: true,
      })
      .waitFor();
    await armPF1(page, "integration permissions validated");
    await page
      .getByText(
        "Confirm: create GitHub installation token and run integration_permissions_validated. The server independently checks host approval, current plan, actor, and authorities before any effect.",
        { exact: true },
      )
      .waitFor();
    await consent.focus();
    await page.keyboard.press("Space");
    await page
      .getByRole("button", {
        name: "Allow GitHub installation token creation: no",
        exact: true,
      })
      .waitFor();
    await page
      .getByRole("region", {
        name: "Write one integration permissions validated receipt?",
        exact: true,
      })
      .waitFor({ state: "hidden" });
    await expectNoReview(page);
    await consent.focus();
    await page.keyboard.press("Enter");
    await armPF1(page, "integration permissions validated");
    await page
      .getByRole("textbox", {
        name: /GitHub source broker authority identity/i,
      })
      .fill("c".repeat(64));
    await page
      .getByRole("region", {
        name: "Write one integration permissions validated receipt?",
        exact: true,
      })
      .waitFor({ state: "hidden" });
    await armPF1(page, "integration permissions validated");
    await page.getByRole("button", { name: "Go back", exact: true }).focus();
    await page.keyboard.press("Enter");
    await page
      .getByRole("region", {
        name: "Write one integration permissions validated receipt?",
        exact: true,
      })
      .waitFor({ state: "hidden" });
    await armPF1(page, "integration permissions validated");
  }
  async function fillWebhook(page, owner) {
    await page.getByRole("button", { name: /webhook validated/i }).click();
    for (const [name, value] of [
      [/Webhook authority identity/i, "a".repeat(64)],
      [/GitHub webhook key ID/i, "primary-2026"],
      [/Webhook approved by/i, owner],
    ]) {
      const field = page.getByRole("textbox", { name });
      await field.fill(value);
      if ((await field.inputValue()) !== value)
        throw new Error("webhook approval fixture input failed");
    }
  }
  async function captureHistoricalPF1(page, size) {
    for (const [token, label] of [
      ["r", "ready"],
      ["w", "pending-webhook"],
    ]) {
      await populateSetup(page, "controlled hybrid", token.repeat(32));
      await page
        .getByText(/Historical catalog: Ready and receipts are historical/)
        .waitFor();
      await page.getByText(/fresh protected state path/).waitFor();
      if (label === "ready") {
        await page.locator(".setup-header .state-ready").waitFor();
        await page
          .getByRole("button", { name: /integration permissions validated/i })
          .click();
        for (const [name, value] of [
          [/Integration permission authority identity/i, "a".repeat(64)],
          [/GitHub source broker authority identity/i, "b".repeat(64)],
          [/Integration approved by/i, "pf1-owner"],
        ])
          await page.getByRole("textbox", { name }).fill(value);
        await page
          .getByRole("button", {
            name: "Allow GitHub installation token creation: no",
            exact: true,
          })
          .click();
        await expectNoReview(page);
      }
      await fillWebhook(page, "pf1-owner");
      await expectNoReview(page);
      if (
        await page
          .getByRole("button", { name: "Run webhook validated", exact: true })
          .count()
      )
        throw new Error("historical webhook confirmation exposed");
      if (
        await page.evaluate(
          () =>
            document.documentElement.scrollWidth >
            document.documentElement.clientWidth,
        )
      )
        throw new Error(`historical ${label} ${size} overflow`);
      await page.screenshot({
        path: join(
          output,
          `open-trestle-setup-historical-${label}-${size}.png`,
        ),
        fullPage: true,
      });
    }
  }
  const desktop = await newLocalPage({
    viewport: { width: 1440, height: 1000 },
    deviceScaleFactor: 1,
  });
  desktop.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await populate(desktop);
  await desktop.screenshot({
    path: join(output, "open-trestle-console-desktop.png"),
    fullPage: true,
  });
  await desktop.getByRole("button", { name: /Findings 2/i }).click();
  await desktop.getByRole("heading", { name: "Review coverage" }).waitFor();
  await expandFirstFinding(desktop);
  await desktop.screenshot({
    path: join(output, "open-trestle-console-findings-desktop.png"),
    fullPage: true,
  });
  await desktop.getByRole("button", { name: /Runtime ready/i }).click();
  await desktop.getByRole("heading", { name: "Runtime state" }).waitFor();
  await desktop.screenshot({
    path: join(output, "open-trestle-console-runtime.png"),
    fullPage: true,
  });
  desktopOverflow = await desktop.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await desktop.setViewportSize({ width: 800, height: 1000 });
  await checkTabletNavigation(desktop);
  await desktop.getByRole("button", { name: /^Overview/ }).focus();
  await desktop.keyboard.press("Enter");
  await desktop.getByRole("heading", { name: "Run active" }).waitFor();
  await desktop.screenshot({
    path: join(output, "open-trestle-console-tablet.png"),
    fullPage: true,
  });
  if (
    await desktop.evaluate(
      () =>
        document.documentElement.scrollWidth >
        document.documentElement.clientWidth,
    )
  )
    throw new Error("tablet page overflow");
  await desktop.close();
  const mobile = await newLocalPage({
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 1,
    isMobile: true,
  });
  mobile.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await populate(mobile);
  await checkMobileBrandContrast(mobile);
  await mobile.getByRole("button", { name: "findings" }).click();
  await expandFirstFinding(mobile);
  await mobile.screenshot({
    path: join(output, "open-trestle-console-mobile.png"),
    fullPage: true,
  });
  mobileOverflow = await mobile.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await mobile.close();
  const setupDesktop = await newLocalPage({
    viewport: { width: 1440, height: 1000 },
    deviceScaleFactor: 1,
  });
  setupDesktop.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await populateSetup(setupDesktop, "controlled hybrid", "n".repeat(32));
  await prepareCurrentIntegration(setupDesktop);
  await expectCopyFailure(setupDesktop, /Copy Plan identity:/);
  await setupDesktop.screenshot({
    path: join(output, "open-trestle-setup-desktop.png"),
    fullPage: true,
  });
  setupDesktopOverflow = await setupDesktop.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await setupDesktop.close();
  const setupMobile = await newLocalPage({
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 1,
    isMobile: true,
  });
  setupMobile.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await populateSetup(setupMobile);
  await checkMobileSetupNavigation(setupMobile);
  await setupMobile
    .getByRole("button", { name: /local inference validated/i })
    .click();
  await setupMobile
    .getByRole("textbox", { name: /Route inventory path/i })
    .waitFor();
  await expectCopyFailure(setupMobile, /Copy Plan identity:/);
  await setupMobile.screenshot({
    path: join(output, "open-trestle-setup-mobile.png"),
    fullPage: true,
  });
  setupMobileOverflow = await setupMobile.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await setupMobile
    .getByRole("link", { name: "Review console", exact: true })
    .focus();
  await setupMobile.keyboard.press("Enter");
  await setupMobile
    .getByRole("heading", { name: "Locate a review run" })
    .waitFor();
  await setupMobile.close();
  const setupIntegrationMobile = await newLocalPage({
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 1,
    isMobile: true,
  });
  setupIntegrationMobile.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await populateSetup(
    setupIntegrationMobile,
    "controlled hybrid",
    "n".repeat(32),
  );
  await prepareCurrentIntegration(setupIntegrationMobile);
  await setupIntegrationMobile.screenshot({
    path: join(output, "open-trestle-setup-integration-mobile.png"),
    fullPage: true,
  });
  setupIntegrationMobileOverflow = await setupIntegrationMobile.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await setupIntegrationMobile.close();
  const setupWebhookDesktop = await newLocalPage({
    viewport: { width: 1440, height: 1000 },
    deviceScaleFactor: 1,
  });
  setupWebhookDesktop.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await populateSetup(setupWebhookDesktop, "controlled hybrid", "n".repeat(32));
  await fillWebhook(setupWebhookDesktop, "owner");
  await expectNoReview(setupWebhookDesktop);
  await populateSetup(setupWebhookDesktop, "controlled hybrid", "g".repeat(32));
  await fillWebhook(setupWebhookDesktop, "owner");
  await armPF1(setupWebhookDesktop, "webhook validated");
  await setupWebhookDesktop.screenshot({
    path: join(output, "open-trestle-setup-webhook-desktop.png"),
    fullPage: true,
  });
  setupWebhookDesktopOverflow = await setupWebhookDesktop.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await captureHistoricalPF1(setupWebhookDesktop, "desktop");
  await setupWebhookDesktop.close();
  const setupWebhookMobile = await newLocalPage({
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 1,
    isMobile: true,
  });
  setupWebhookMobile.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await populateSetup(setupWebhookMobile, "controlled hybrid", "n".repeat(32));
  await fillWebhook(setupWebhookMobile, "owner");
  await expectNoReview(setupWebhookMobile);
  await populateSetup(setupWebhookMobile, "controlled hybrid", "g".repeat(32));
  await fillWebhook(setupWebhookMobile, "owner");
  await armPF1(setupWebhookMobile, "webhook validated");
  await setupWebhookMobile.screenshot({
    path: join(output, "open-trestle-setup-webhook-mobile.png"),
    fullPage: true,
  });
  setupWebhookMobileOverflow = await setupWebhookMobile.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await captureHistoricalPF1(setupWebhookMobile, "mobile");
  await setupWebhookMobile.close();
  const setupRateLimitDesktop = await newLocalPage({
    viewport: { width: 1440, height: 1000 },
    deviceScaleFactor: 1,
  });
  setupRateLimitDesktop.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await populateSetup(setupRateLimitDesktop, "kubernetes ha", "h".repeat(32));
  await setupRateLimitDesktop
    .getByRole("button", { name: /shared rate limit validated/i })
    .click();
  await setupRateLimitDesktop
    .getByRole("textbox", { name: /Shared rate-limit authority identity/i })
    .waitFor();
  await setupRateLimitDesktop.screenshot({
    path: join(output, "open-trestle-setup-rate-limit-desktop.png"),
    fullPage: true,
  });
  setupRateLimitDesktopOverflow = await setupRateLimitDesktop.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await populateSetup(setupRateLimitDesktop, "kubernetes ha", "h".repeat(32));
  await setupRateLimitDesktop
    .getByRole("button", { name: /replica reconciliation validated/i })
    .click();
  await setupRateLimitDesktop
    .getByRole("textbox", {
      name: /Replica reconciliation authority identity/i,
    })
    .waitFor();
  await setupRateLimitDesktop.screenshot({
    path: join(output, "open-trestle-setup-reconciliation-desktop.png"),
    fullPage: true,
  });
  setupReconciliationDesktopOverflow = await setupRateLimitDesktop.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await populateSetup(setupRateLimitDesktop, "air gapped", "a".repeat(32));
  await setupRateLimitDesktop
    .getByRole("button", { name: /signed bundle validated/i })
    .click();
  await setupRateLimitDesktop
    .getByRole("textbox", { name: /Signed bundle authority identity/i })
    .waitFor();
  await setupRateLimitDesktop.screenshot({
    path: join(output, "open-trestle-setup-signed-bundle-desktop.png"),
    fullPage: true,
  });
  setupSignedBundleDesktopOverflow = await setupRateLimitDesktop.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await setupRateLimitDesktop.close();
  const setupRateLimitMobile = await newLocalPage({
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 1,
    isMobile: true,
  });
  setupRateLimitMobile.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await populateSetup(setupRateLimitMobile, "kubernetes ha", "h".repeat(32));
  await setupRateLimitMobile
    .getByRole("button", { name: /shared rate limit validated/i })
    .click();
  await setupRateLimitMobile
    .getByRole("textbox", { name: /Shared rate-limit authority identity/i })
    .waitFor();
  await setupRateLimitMobile.screenshot({
    path: join(output, "open-trestle-setup-rate-limit-mobile.png"),
    fullPage: true,
  });
  setupRateLimitMobileOverflow = await setupRateLimitMobile.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await populateSetup(setupRateLimitMobile, "kubernetes ha", "h".repeat(32));
  await setupRateLimitMobile
    .getByRole("button", { name: /replica reconciliation validated/i })
    .click();
  await setupRateLimitMobile
    .getByRole("textbox", {
      name: /Replica reconciliation authority identity/i,
    })
    .waitFor();
  await setupRateLimitMobile.screenshot({
    path: join(output, "open-trestle-setup-reconciliation-mobile.png"),
    fullPage: true,
  });
  setupReconciliationMobileOverflow = await setupRateLimitMobile.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await populateSetup(setupRateLimitMobile, "air gapped", "a".repeat(32));
  await setupRateLimitMobile
    .getByRole("button", { name: /signed bundle validated/i })
    .click();
  await setupRateLimitMobile
    .getByRole("textbox", { name: /Signed bundle authority identity/i })
    .waitFor();
  await setupRateLimitMobile.screenshot({
    path: join(output, "open-trestle-setup-signed-bundle-mobile.png"),
    fullPage: true,
  });
  setupSignedBundleMobileOverflow = await setupRateLimitMobile.evaluate(
    () =>
      document.documentElement.scrollWidth >
      document.documentElement.clientWidth,
  );
  await setupRateLimitMobile.close();
} finally {
  try {
    if (browser !== undefined) await browser.close();
  } finally {
    if (server.listening)
      await new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
  }
}
if (
  errors.length ||
  desktopOverflow ||
  mobileOverflow ||
  setupDesktopOverflow ||
  setupMobileOverflow ||
  setupIntegrationMobileOverflow ||
  setupWebhookDesktopOverflow ||
  setupWebhookMobileOverflow ||
  setupRateLimitDesktopOverflow ||
  setupRateLimitMobileOverflow ||
  setupReconciliationDesktopOverflow ||
  setupReconciliationMobileOverflow ||
  setupSignedBundleDesktopOverflow ||
  setupSignedBundleMobileOverflow
) {
  throw new Error(
    JSON.stringify({
      errors,
      desktopOverflow,
      mobileOverflow,
      setupDesktopOverflow,
      setupMobileOverflow,
      setupIntegrationMobileOverflow,
      setupWebhookDesktopOverflow,
      setupWebhookMobileOverflow,
      setupRateLimitDesktopOverflow,
      setupRateLimitMobileOverflow,
      setupReconciliationDesktopOverflow,
      setupReconciliationMobileOverflow,
      setupSignedBundleDesktopOverflow,
      setupSignedBundleMobileOverflow,
    }),
  );
}
console.log(
  JSON.stringify({
    desktop: join(output, "open-trestle-console-desktop.png"),
    findingsDesktop: join(output, "open-trestle-console-findings-desktop.png"),
    mobile: join(output, "open-trestle-console-mobile.png"),
    runtime: join(output, "open-trestle-console-runtime.png"),
    setupDesktop: join(output, "open-trestle-setup-desktop.png"),
    setupMobile: join(output, "open-trestle-setup-mobile.png"),
    setupIntegrationMobile: join(
      output,
      "open-trestle-setup-integration-mobile.png",
    ),
    setupWebhookDesktop: join(output, "open-trestle-setup-webhook-desktop.png"),
    setupWebhookMobile: join(output, "open-trestle-setup-webhook-mobile.png"),
    setupRateLimitDesktop: join(
      output,
      "open-trestle-setup-rate-limit-desktop.png",
    ),
    setupRateLimitMobile: join(
      output,
      "open-trestle-setup-rate-limit-mobile.png",
    ),
    setupReconciliationDesktop: join(
      output,
      "open-trestle-setup-reconciliation-desktop.png",
    ),
    setupReconciliationMobile: join(
      output,
      "open-trestle-setup-reconciliation-mobile.png",
    ),
    setupSignedBundleDesktop: join(
      output,
      "open-trestle-setup-signed-bundle-desktop.png",
    ),
    setupSignedBundleMobile: join(
      output,
      "open-trestle-setup-signed-bundle-mobile.png",
    ),
    setupHistoricalReadyDesktop: join(
      output,
      "open-trestle-setup-historical-ready-desktop.png",
    ),
    setupHistoricalReadyMobile: join(
      output,
      "open-trestle-setup-historical-ready-mobile.png",
    ),
    setupHistoricalPendingWebhookDesktop: join(
      output,
      "open-trestle-setup-historical-pending-webhook-desktop.png",
    ),
    setupHistoricalPendingWebhookMobile: join(
      output,
      "open-trestle-setup-historical-pending-webhook-mobile.png",
    ),
    setupEffectRequests: 0,
    unexpectedEgress: 0,
    consoleErrors: 0,
    horizontalOverflow: false,
  }),
);
