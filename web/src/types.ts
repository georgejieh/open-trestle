export type Scope = { tenant: string; repository: string; run: string };
export type RunStatus = "active" | "succeeded" | "failed" | "canceled";
export type TaskStatus =
  "pending" | "available" | "leased" | "succeeded" | "failed" | "skipped";
export interface DeliveryRefusal {
  contract: "open-trestle/webhook-delivery-refusal";
  schema_version: 1;
  identity: string;
  tenant_id: string;
  repository_id: string;
  source: string;
  deduplication_key: string;
  delivery_identity: string;
  planner_identity: string;
  reason: string;
  refused_at_milliseconds: number;
}
export type SourceFailureReason =
  "no_merge_base" | "nothing_to_review" | "merge_base_unavailable";
export type ContextFailureReason =
  "route_context_insufficient" | "no_eligible_route";
/**
 * A model task's provider refusal, named from the HTTP status alone (a
 * request the provider rejected as invalid is provider_request_rejected), a
 * provider reply the adapter refused (provider_response_invalid), or an
 * accepted answer that was not a valid review document (model_output_invalid).
 */
export type ProviderFailureReason =
  | "provider_payment_required"
  | "provider_model_unavailable"
  | "provider_model_retired"
  | "provider_authentication_failed"
  | "provider_authorization_denied"
  | "provider_rate_limited"
  | "provider_response_invalid"
  | "model_output_invalid"
  | "provider_request_rejected";
export type FailureReason =
  SourceFailureReason | ContextFailureReason | ProviderFailureReason;
/** The counts of a route_context_insufficient refusal. */
export interface ContextShortfall {
  required_tokens: number;
  estimated_input_tokens: number;
  max_output_tokens: number;
  declared_context_tokens: number;
}
export interface ContextRefusal {
  reason: ContextFailureReason;
  context_shortfall?: ContextShortfall;
}
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
  output_kind?: "context_abstention";
  failure: Failure;
  failure_reason?: FailureReason;
  context_shortfall?: ContextShortfall;
  retry_at_milliseconds: number;
}
export interface RunReceipt {
  contract: "open-trestle/review-run-receipt";
  schema_version: 1 | 2 | 3;
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
export type ProgressState = "not_run" | "available" | "partial" | "unavailable";
interface ProgressAxis {
  state: ProgressState;
  artifact_identity?: string;
}
export interface RunProgress {
  run: RunReceipt;
  progress: {
    change: ProgressAxis & { files?: number; ranges?: number };
    deterministic: ProgressAxis & {
      applicable_files?: number;
      applicable_ranges?: number;
      checked_files?: number;
      checked_ranges?: number;
      observations?: number;
    };
    context: ProgressAxis & {
      analyzed?: number;
      selected?: number;
      omitted?: number;
    };
    verification: ProgressAxis & {
      candidates?: number;
      verified?: number;
      rejected?: number;
      inconclusive?: number;
    };
  };
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
  /** Present only in verified set v8, for removed lines of the base revision. */
  side?: "base";
  /** With side, the head line beside which the base lines were removed. */
  head_line?: number;
  evidence_ids: string[];
}
export interface DeterministicObservation extends Diagnostic {
  analysis_result_identity: string;
  check_identity: string;
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
interface DiagnosticSetCommon {
  contract: "open-trestle/review-diagnostic-set";
  identity: string;
  tenant_id: string;
  repository_id: string;
  review_run_id: string;
  snapshot_identity: string;
  head_revision: string;
}
interface VerifiedDiagnosticSetBase extends DiagnosticSetCommon {
  verified_set_identity: string;
  findings: Diagnostic[];
}
export type DiagnosticSet =
  | (VerifiedDiagnosticSetBase &
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
        | {
            /** Version 5 plus findings on removed base lines (side "base"). */
            schema_version: 8;
            coverage: DiagnosticCoverage;
            source_coverage: DiagnosticSourceCoverageWithOmissions;
            checks: [DiagnosticDeterministicCheck];
          }
      ))
  | (DiagnosticSetCommon & {
      schema_version: 6;
      analysis_result_identity: string;
      checks: [DiagnosticDeterministicCheck];
      observations: DeterministicObservation[];
      coverage?: never;
      source_coverage?: never;
      verified_set_identity?: never;
      findings?: never;
    })
  | {
      contract: "open-trestle/review-diagnostic-set";
      schema_version: 7;
      identity: string;
      tenant_id: string;
      repository_id: string;
      review_run_id: string;
      snapshot_identity: string;
      head_revision: string;
      outcome:
        "completed" | "failed" | "canceled" | "abstained" | "inconclusive";
      deterministic?: Extract<DiagnosticSet, { schema_version: 6 }>;
      verified?: Extract<DiagnosticSet, { schema_version: 5 | 8 }>;
      context_refusal?: ContextRefusal;
      /** Recorded after the evidence expired: no evidence part, journal outcome only. */
      evidence_expired?: true;
    };

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
