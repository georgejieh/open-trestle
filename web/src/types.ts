export type Scope = { tenant: string; repository: string; run: string };
export type RunStatus = "active" | "succeeded" | "failed" | "canceled";
export type TaskStatus =
  "pending" | "available" | "leased" | "succeeded" | "failed" | "skipped";
export type Failure =
  | ""
  | "transient"
  | "resource_limit"
  | "policy"
  | "invalid_input"
  | "canceled"
  | "dependency"
  | "internal";
export type TaskKind =
  | "acquire_source"
  | "build_change"
  | "inspect_deterministic"
  | "retrieve_context"
  | "assemble_context"
  | "generate_candidates"
  | "verify_candidates"
  | "evaluate_publication"
  | "publish_result";
export interface RunTask {
  key: string;
  task_identity: string;
  input_identity: string;
  handler_identity: string;
  kind: TaskKind;
  required: boolean;
  status: TaskStatus;
  attempts: number;
  max_attempts: number;
  lease_expires_at_milliseconds: number;
  output_identity: string;
  failure: Failure;
  retry_at_milliseconds: number;
}
export interface RunReceipt {
  contract: "open-trestle/review-run-receipt";
  schema_version: 1;
  identity: string;
  plan_identity: string;
  tenant_id: string;
  repository_id: string;
  review_run_id: string;
  status: RunStatus;
  revision: number;
  head_identity: string;
  last_occurred_at_milliseconds: number;
  output_identity: string;
  failure: Failure;
  tasks: RunTask[];
}
export type DiagnosticSeverity = "error" | "warning" | "information" | "hint";
export interface Diagnostic {
  identity: string;
  source_identity: string;
  fingerprint: string;
  title: string;
  message: string;
  severity: DiagnosticSeverity;
  path: string;
  start_line: number;
  end_line: number;
  evidence_ids: string[];
}
export interface DiagnosticCoverage {
  candidate_count: number;
  verified_count: number;
  rejected_count: number;
  inconclusive_count: number;
}
export interface DiagnosticSourceCoverage {
  verification_context_identity: string;
  analyzed_count: number;
  selected_count: number;
  omitted_count: number;
}
export type DiagnosticOmissionReason =
  | "authorization"
  | "resource_limit"
  | "unsupported"
  | "analysis_failure"
  | "duplicate"
  | "selection_limit";
export interface DiagnosticOmissionSummary {
  reason: DiagnosticOmissionReason;
  count: number;
}
export interface DiagnosticSourceCoverageWithOmissions extends DiagnosticSourceCoverage {
  omissions: DiagnosticOmissionSummary[];
}
export type DiagnosticCheckState =
  "passed" | "failed" | "incomplete" | "not_applicable";
export interface DiagnosticDeterministicCheck {
  identity: string;
  source_check_identity: string;
  analysis_result_identity: string;
  change_identity: string;
  key: "static_debug_output";
  rule_version: 1;
  state: DiagnosticCheckState;
  applicable_files: number;
  applicable_ranges: number;
  checked_files: number;
  checked_ranges: number;
  matches: number;
}
interface DiagnosticSetBase {
  contract: "open-trestle/review-diagnostic-set";
  identity: string;
  tenant_id: string;
  repository_id: string;
  review_run_id: string;
  snapshot_identity: string;
  head_revision: string;
  verified_set_identity: string;
  findings: Diagnostic[];
}
export type DiagnosticSet = DiagnosticSetBase &
  (
    | { schema_version: 1; coverage?: never; source_coverage?: never }
    | {
        schema_version: 2;
        coverage: DiagnosticCoverage;
        source_coverage?: never;
      }
    | {
        schema_version: 3;
        coverage: DiagnosticCoverage;
        source_coverage: DiagnosticSourceCoverage;
      }
    | {
        schema_version: 4;
        coverage: DiagnosticCoverage;
        source_coverage: DiagnosticSourceCoverageWithOmissions;
      }
    | {
        schema_version: 5;
        coverage: DiagnosticCoverage;
        source_coverage: DiagnosticSourceCoverageWithOmissions;
        checks: [DiagnosticDeterministicCheck];
      }
  );

export type RuntimeComponentState = "starting" | "ready";
export interface RuntimeHandler {
  kind: TaskKind;
  identity: string;
}
export interface RuntimeConfiguration {
  tenant_id: string;
  repository_ids: string[];
  metadata_backend: "local" | "postgres";
  database_authority_identity?: string;
  artifact_backend: "local" | "s3";
  artifact_protection: "process_private" | "envelope_encrypted";
  notification_backend: "process_local" | "postgres";
  rate_limit_backend: "process_local" | "postgres";
  rate_limit_authority_identity?: string;
  review_mode: "disabled" | "local" | "advisory" | "required";
  webhook_ingress: boolean;
  local_workers: boolean;
  publication_enabled: boolean;
  publication_fence_verified: boolean;
  route_inventory_identity?: string;
  runtime_policy_identity?: string;
  route_count: number;
  handlers: RuntimeHandler[];
}
export interface RuntimeStatus {
  contract: "open-trestle/runtime-status";
  schema_version: 1;
  identity: string;
  configuration_identity: string;
  tenant_id: string;
  repository_id: string;
  observed_at: string;
  ready: boolean;
  configuration: RuntimeConfiguration;
  components: { name: string; state: RuntimeComponentState }[];
}

export type SetupProfile =
  "local_single_node" | "controlled_hybrid" | "kubernetes_ha" | "air_gapped";
export type SetupState = "pending" | "passed" | "blocked" | "unavailable";
export type SetupSource =
  "deterministic" | "probe" | "authorization" | "dry_run";
export type SetupCheckKey =
  | "profile_selected"
  | "scope_valid"
  | "effect_posture_locked"
  | "recovery_owner_named"
  | "local_administrator_validated"
  | "state_storage_posture_validated"
  | "postgres_storage_validated"
  | "envelope_storage_validated"
  | "backup_validated"
  | "observer_credential_posture_validated"
  | "secret_backend_validated"
  | "local_inference_validated"
  | "remote_provider_authorized"
  | "integration_permissions_validated"
  | "webhook_validated"
  | "shared_rate_limit_validated"
  | "replica_reconciliation_validated"
  | "signed_bundle_validated"
  | "no_egress_validated"
  | "policy_validated"
  | "dry_run_validated";
export interface SetupPosture {
  metadata_backend: "local" | "postgres";
  artifact_backend: "local" | "s3";
  artifact_protection: "process_private" | "envelope_encrypted";
  notification_backend: "process_local" | "postgres";
  inference: "local_only" | "approved_remote";
  egress: "denied" | "allowlisted";
  integration: "local" | "least_privilege_scm" | "offline_bundle";
  max_model_request_cost_micro_usd: number;
  retention_days: 30;
  provider_fallback_enabled: false;
  content_logging_allowed: false;
  publication_enabled: false;
  dynamic_validation_enabled: false;
}
export interface SetupRequirement {
  key: SetupCheckKey;
  source: SetupSource;
  state: SetupState;
  checker_identity: string;
  evidence_identity: string;
  receipt_identity: string;
  recovery_action: string;
  checked_at: string;
}
export interface SetupReceipt {
  contract: "open-trestle/setup-check-receipt";
  schema_version: 1;
  identity: string;
  plan_identity: string;
  key: SetupCheckKey;
  checker_identity: string;
  state: Exclude<SetupState, "pending">;
  evidence_identity: string;
  recovery_action: string;
  checked_at: string;
}
export interface SetupPlan {
  contract: "open-trestle/setup-plan";
  schema_version: 1;
  identity: string;
  previous_identity: string;
  checker_catalog_identity: string;
  checker_authorities: { key: SetupCheckKey; checker_identity: string }[];
  revision: number;
  tenant_id: string;
  repository_id: string;
  recovery_owner: string;
  profile: SetupProfile;
  posture: SetupPosture;
  requirements: SetupRequirement[];
  receipts: SetupReceipt[];
  status: "incomplete" | "blocked" | "ready";
  ready: boolean;
  created_at: string;
  updated_at: string;
}
export interface SetupSession {
  contract: "open-trestle/setup-session";
  schema_version: 1;
  initialized: boolean;
  plan?: SetupPlan;
}
export interface SetupCheckResult {
  contract: "open-trestle/setup-check-result";
  schema_version: 1;
  plan: SetupPlan;
  receipt: SetupReceipt;
}
export interface SetupInitInput {
  profile: SetupProfile;
  tenant_id: string;
  repository_id: string;
  recovery_owner: string;
}
export interface SetupCheckInput {
  plan_identity: string;
  key: SetupCheckKey;
  storage_root?: string;
  backup_snapshot_path?: string;
  route_inventory_path?: string;
  runtime_policy_path?: string;
  approve_inventory_identity?: string;
  approve_runtime_policy_identity?: string;
  approve_review_policy_identity?: string;
  approve_postgres_authority_identity?: string;
  approve_kms_authority_identity?: string;
  approve_envelope_storage_authority_identity?: string;
  approve_integration_permission_authority_identity?: string;
  approve_webhook_authority_identity?: string;
  approve_shared_rate_limit_authority_identity?: string;
  approve_replica_reconciliation_authority_identity?: string;
  approve_signed_bundle_authority_identity?: string;
  bundle_path?: string;
  bundle_sha256?: string;
  bundle_bytes?: number;
  public_key?: string;
  signature?: string;
  postgres_database_authority_identity?: string;
  approve_github_source_broker_authority_identity?: string;
  allow_github_installation_token_creation?: boolean;
  github_webhook_key_id?: string;
  s3_endpoint?: string;
  s3_region?: string;
  s3_bucket?: string;
  s3_prefix?: string;
  kms_region?: string;
  kms_key_arn?: string;
  kms_endpoint?: string;
  approved_by?: string;
}
