import { useEffect, useRef, useState } from "react";
import { ShieldCheck } from "./ShieldCheck";
import { Identity } from "./Identity";
import {
  ApiError,
  fetchSetupSession,
  hasCurrentIntegrationPermissionAuthority,
  initializeSetup,
  runSetupCheck,
  validAccessToken,
  validSetupBundlePath,
} from "./api";
import type {
  SetupCheckInput,
  SetupCheckKey,
  SetupPlan,
  SetupProfile,
  SetupRequirement,
  SetupSession,
} from "./types";

function statusIcon() {
  return <ShieldCheck aria-hidden="true" />;
}
function Status({ value }: { value: string }) {
  return (
    <span className={`state state-${value}`}>
      {statusIcon()}
      <span>{value.replaceAll("_", " ")}</span>
    </span>
  );
}
function Brand() {
  return (
    <div className="brand">
      <span className="brand-mark">
        <ShieldCheck aria-hidden="true" />
      </span>
      <span>
        <strong>Open Trestle</strong>
        <small>Setup guide</small>
      </span>
    </div>
  );
}

const setupProfiles: { value: SetupProfile; title: string; summary: string }[] =
  [
    {
      value: "local_single_node",
      title: "Local single node",
      summary: "Private local storage, local inference, and denied egress.",
    },
    {
      value: "controlled_hybrid",
      title: "Controlled hybrid",
      summary:
        "Encrypted shared storage and explicitly approved remote inference.",
    },
    {
      value: "kubernetes_ha",
      title: "Kubernetes HA",
      summary: "Shared coordination, encrypted artifacts, and replica checks.",
    },
    {
      value: "air_gapped",
      title: "Air gapped",
      summary: "Local inference, denied egress, and signed offline bundles.",
    },
  ];
const webSetupChecks = new Set<SetupCheckKey>([
  "postgres_storage_validated",
  "integration_permissions_validated",
  "webhook_validated",
  "shared_rate_limit_validated",
  "replica_reconciliation_validated",
  "signed_bundle_validated",
  "remote_provider_authorized",
  "envelope_storage_validated",
  "secret_backend_validated",
  "local_administrator_validated",
  "backup_validated",
  "state_storage_posture_validated",
  "observer_credential_posture_validated",
  "local_inference_validated",
  "policy_validated",
  "dry_run_validated",
]);
function setupOpaqueReady(value: string, maximum: number) {
  return (
    value.length > 0 &&
    value.length <= maximum &&
    !/[\u0000-\u0020\u007f]/.test(value)
  );
}
function setupLabel(value: string) {
  return value.replaceAll("_", " ");
}
function firstPending(plan: SetupPlan) {
  return (
    plan.requirements.find((requirement) => requirement.state !== "passed")
      ?.key ??
    plan.requirements[0]?.key ??
    "profile_selected"
  );
}
function SetupToken({
  busy,
  onConnect,
}: {
  busy: boolean;
  onConnect: (token: string) => void;
}) {
  const [token, setToken] = useState("");
  const ready = validAccessToken(token);
  return (
    <section
      className="locator setup-entry"
      aria-labelledby="setup-entry-title"
    >
      <div className="locator-copy">
        <ShieldCheck aria-hidden="true" />
        <div>
          <h1 id="setup-entry-title">Open protected setup</h1>
          <p>
            Connect to the local setup service. The setup token stays in this
            tab and is never saved.
          </p>
        </div>
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (ready) onConnect(token);
        }}
      >
        <label className="token-field">
          Setup token
          <span className="input-with-icon">
            <ShieldCheck aria-hidden="true" />
            <input
              type="password"
              value={token}
              minLength={32}
              maxLength={512}
              required
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => setToken(event.target.value)}
            />
          </span>
        </label>
        <button
          className="primary-button"
          type="submit"
          disabled={!ready || busy}
        >
          {busy ? <>Connecting</> : <>Inspect setup</>}
        </button>
      </form>
    </section>
  );
}
function SetupCreate({
  busy,
  onCreate,
}: {
  busy: boolean;
  onCreate: (input: {
    profile: SetupProfile;
    tenant_id: string;
    repository_id: string;
    recovery_owner: string;
  }) => void;
}) {
  const [profile, setProfile] = useState<SetupProfile>("local_single_node");
  const [tenant, setTenant] = useState("");
  const [repository, setRepository] = useState("");
  const [owner, setOwner] = useState("");
  const [confirm, setConfirm] = useState(false);
  const confirmActionRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (confirm) confirmActionRef.current?.focus();
  }, [confirm]);
  const valid =
    [tenant, repository].every(
      (value) =>
        /^[a-z0-9](?:[a-z0-9._:-]*[a-z0-9])?$/.test(value) &&
        value.length <= 128,
    ) && /^[A-Za-z0-9_.:@-]{1,128}$/.test(owner);
  return (
    <section className="setup-create" aria-labelledby="setup-create-title">
      <div className="section-head">
        <div>
          <h1 id="setup-create-title">Choose a safe baseline</h1>
          <p>
            Create one secret-free setup plan. This does not contact a provider
            or enable publication.
          </p>
        </div>
        <Status value="pending" />
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (valid) setConfirm(true);
        }}
      >
        <fieldset className="profile-fieldset">
          <legend>Deployment profile</legend>
          <div className="profile-options">
            {setupProfiles.map((option) => (
              <label
                key={option.value}
                className={
                  profile === option.value
                    ? "profile-option selected"
                    : "profile-option"
                }
              >
                <input
                  type="radio"
                  name="profile"
                  value={option.value}
                  checked={profile === option.value}
                  onChange={() => {
                    setProfile(option.value);
                    setConfirm(false);
                  }}
                />
                <span>
                  <strong>{option.title}</strong>
                  <small>{option.summary}</small>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
        <div className="setup-fields">
          <label>
            Tenant
            <input
              value={tenant}
              maxLength={128}
              required
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setTenant(event.target.value);
                setConfirm(false);
              }}
            />
          </label>
          <label>
            Repository
            <input
              value={repository}
              maxLength={128}
              required
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setRepository(event.target.value);
                setConfirm(false);
              }}
            />
          </label>
          <label>
            Recovery owner
            <input
              value={owner}
              maxLength={128}
              required
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setOwner(event.target.value);
                setConfirm(false);
              }}
            />
            <small>
              Only this exact name can approve runtime policy in this plan.
            </small>
          </label>
        </div>
        {confirm ? (
          <div
            className="confirmation-panel"
            role="region"
            aria-labelledby="create-confirm-title"
          >
            <ShieldCheck aria-hidden="true" />
            <div>
              <h2 id="create-confirm-title">Create this protected plan?</h2>
              <p>
                The profile locks publication, dynamic validation, fallback, and
                content logging off.
              </p>
              <div className="confirmation-actions">
                <button type="button" onClick={() => setConfirm(false)}>
                  Go back
                </button>
                <button
                  ref={confirmActionRef}
                  className="primary-button"
                  type="button"
                  disabled={busy}
                  onClick={() =>
                    onCreate({
                      profile,
                      tenant_id: tenant,
                      repository_id: repository,
                      recovery_owner: owner,
                    })
                  }
                >
                  {busy ? "Creating" : "Create setup plan"}
                </button>
              </div>
            </div>
          </div>
        ) : (
          <button
            className="primary-button"
            type="submit"
            disabled={!valid || busy}
          >
            Review plan creation
          </button>
        )}
      </form>
    </section>
  );
}
function SetupRequirementList({
  plan,
  selected,
  onSelect,
}: {
  plan: SetupPlan;
  selected: SetupCheckKey;
  onSelect: (key: SetupCheckKey) => void;
}) {
  return (
    <ol className="setup-requirements">
      {plan.requirements.map((requirement, index) => (
        <li key={requirement.key}>
          <button
            type="button"
            className={selected === requirement.key ? "selected" : ""}
            aria-current={selected === requirement.key ? "step" : undefined}
            onClick={() => onSelect(requirement.key)}
          >
            <span className="depth-index" aria-hidden="true">
              {String(index + 1).padStart(2, "0")}
            </span>
            <span>
              <strong>{setupLabel(requirement.key)}</strong>
              <small>{setupLabel(requirement.source)}</small>
            </span>
            <Status value={requirement.state} />
          </button>
        </li>
      ))}
    </ol>
  );
}
type PolicyDraft = {
  route_inventory_path: string;
  runtime_policy_path: string;
  approve_inventory_identity: string;
  approve_runtime_policy_identity: string;
  approve_review_policy_identity: string;
  approved_by: string;
};
function SetupCheckPanel({
  plan,
  requirement,
  busy,
  onRun,
}: {
  plan: SetupPlan;
  requirement: SetupRequirement;
  busy: boolean;
  onRun: (input: SetupCheckInput) => void;
}) {
  const [storageRoot, setStorageRoot] = useState("");
  const [backupSnapshot, setBackupSnapshot] = useState("");
  const [administratorApprovedBy, setAdministratorApprovedBy] = useState("");
  const [postgresAuthority, setPostgresAuthority] = useState("");
  const [postgresApprovedBy, setPostgresApprovedBy] = useState("");
  const [integrationPermissionAuthority, setIntegrationPermissionAuthority] =
    useState("");
  const [githubBrokerAuthority, setGitHubBrokerAuthority] = useState("");
  const [allowTokenCreation, setAllowTokenCreation] = useState(false);
  const [integrationApprovedBy, setIntegrationApprovedBy] = useState("");
  const [webhookAuthority, setWebhookAuthority] = useState("");
  const [githubWebhookKeyID, setGitHubWebhookKeyID] = useState("");
  const [webhookApprovedBy, setWebhookApprovedBy] = useState("");
  const [sharedRateLimitAuthority, setSharedRateLimitAuthority] = useState("");
  const [postgresDatabaseAuthority, setPostgresDatabaseAuthority] =
    useState("");
  const [sharedRateLimitApprovedBy, setSharedRateLimitApprovedBy] =
    useState("");
  const [replicaReconciliationAuthority, setReplicaReconciliationAuthority] =
    useState("");
  const [replicaReconciliationApprovedBy, setReplicaReconciliationApprovedBy] =
    useState("");
  const [signedBundleAuthority, setSignedBundleAuthority] = useState("");
  const [signedBundlePath, setSignedBundlePath] = useState("");
  const [signedBundleDigest, setSignedBundleDigest] = useState("");
  const [signedBundleBytes, setSignedBundleBytes] = useState("");
  const [signedBundlePublicKey, setSignedBundlePublicKey] = useState("");
  const [signedBundleSignature, setSignedBundleSignature] = useState("");
  const [signedBundleApprovedBy, setSignedBundleApprovedBy] = useState("");
  const [envelopeAuthority, setEnvelopeAuthority] = useState("");
  const [s3Endpoint, setS3Endpoint] = useState("");
  const [s3Region, setS3Region] = useState("");
  const [s3Bucket, setS3Bucket] = useState("");
  const [s3Prefix, setS3Prefix] = useState("");
  const [envelopeApprovedBy, setEnvelopeApprovedBy] = useState("");
  const [kmsAuthority, setKMSAuthority] = useState("");
  const [kmsRegion, setKMSRegion] = useState("");
  const [kmsKeyARN, setKMSKeyARN] = useState("");
  const [kmsEndpoint, setKMSEndpoint] = useState("");
  const [kmsApprovedBy, setKMSApprovedBy] = useState("");
  const [policy, setPolicy] = useState<PolicyDraft>({
    route_inventory_path: "",
    runtime_policy_path: "",
    approve_inventory_identity: "",
    approve_runtime_policy_identity: "",
    approve_review_policy_identity: "",
    approved_by: plan.recovery_owner,
  });
  const [pending, setPending] = useState(false);
  const confirmActionRef = useRef<HTMLButtonElement>(null);
  useEffect(() => setPending(false), [requirement.key, plan.identity]);
  useEffect(() => {
    if (pending) confirmActionRef.current?.focus();
  }, [pending]);
  const currentIntegration = hasCurrentIntegrationPermissionAuthority(plan);
  const supported = webSetupChecks.has(requirement.key);
  const currentAction =
    !["integration_permissions_validated", "webhook_validated"].includes(
      requirement.key,
    ) || currentIntegration;
  const inferenceCheck = requirement.key === "local_inference_validated";
  const remoteProviderCheck = requirement.key === "remote_provider_authorized";
  const policyCheck =
    remoteProviderCheck ||
    requirement.key === "policy_validated" ||
    requirement.key === "dry_run_validated" ||
    inferenceCheck;
  const postgresPassed = plan.requirements.some(
    (value) =>
      value.key === "postgres_storage_validated" && value.state === "passed",
  );
  const integrationPassed = plan.requirements.some(
    (value) =>
      value.key === "integration_permissions_validated" &&
      value.state === "passed",
  );
  const policyPassed = plan.requirements.some(
    (value) => value.key === "policy_validated" && value.state === "passed",
  );
  const digestReady = [
    policy.approve_inventory_identity,
    policy.approve_runtime_policy_identity,
    policy.approve_review_policy_identity,
  ].every((value) => /^[0-9a-f]{64}$/.test(value) && value !== "0".repeat(64));
  const configured =
    requirement.key === "state_storage_posture_validated"
      ? storageRoot.length > 0
      : requirement.key === "backup_validated"
        ? backupSnapshot.length > 0
        : requirement.key === "local_administrator_validated"
          ? administratorApprovedBy === plan.recovery_owner
          : requirement.key === "postgres_storage_validated"
            ? /^[0-9a-f]{64}$/.test(postgresAuthority) &&
              postgresAuthority !== "0".repeat(64) &&
              postgresApprovedBy === plan.recovery_owner
            : requirement.key === "shared_rate_limit_validated"
              ? postgresPassed &&
                /^[0-9a-f]{64}$/.test(sharedRateLimitAuthority) &&
                sharedRateLimitAuthority !== "0".repeat(64) &&
                /^[0-9a-f]{64}$/.test(postgresDatabaseAuthority) &&
                postgresDatabaseAuthority !== "0".repeat(64) &&
                sharedRateLimitApprovedBy === plan.recovery_owner
              : requirement.key === "replica_reconciliation_validated"
                ? postgresPassed &&
                  /^[0-9a-f]{64}$/.test(replicaReconciliationAuthority) &&
                  replicaReconciliationAuthority !== "0".repeat(64) &&
                  /^[0-9a-f]{64}$/.test(postgresDatabaseAuthority) &&
                  postgresDatabaseAuthority !== "0".repeat(64) &&
                  replicaReconciliationApprovedBy === plan.recovery_owner
                : requirement.key === "signed_bundle_validated"
                  ? /^[0-9a-f]{64}$/.test(signedBundleAuthority) &&
                    signedBundleAuthority !== "0".repeat(64) &&
                    validSetupBundlePath(signedBundlePath) &&
                    /^[0-9a-f]{64}$/.test(signedBundleDigest) &&
                    signedBundleDigest !== "0".repeat(64) &&
                    /^[1-9][0-9]{0,9}$/.test(signedBundleBytes) &&
                    Number(signedBundleBytes) <= 1073741824 &&
                    /^[0-9a-f]{64}$/.test(signedBundlePublicKey) &&
                    signedBundlePublicKey !== "0".repeat(64) &&
                    /^[0-9a-f]{128}$/.test(signedBundleSignature) &&
                    signedBundleSignature !== "0".repeat(128) &&
                    signedBundleApprovedBy === plan.recovery_owner
                  : requirement.key === "integration_permissions_validated"
                    ? /^[0-9a-f]{64}$/.test(integrationPermissionAuthority) &&
                      integrationPermissionAuthority !== "0".repeat(64) &&
                      /^[0-9a-f]{64}$/.test(githubBrokerAuthority) &&
                      githubBrokerAuthority !== "0".repeat(64) &&
                      allowTokenCreation &&
                      integrationApprovedBy === plan.recovery_owner
                    : requirement.key === "webhook_validated"
                      ? integrationPassed &&
                        /^[0-9a-f]{64}$/.test(webhookAuthority) &&
                        webhookAuthority !== "0".repeat(64) &&
                        setupOpaqueReady(githubWebhookKeyID, 128) &&
                        webhookApprovedBy === plan.recovery_owner
                      : requirement.key === "envelope_storage_validated"
                        ? /^[0-9a-f]{64}$/.test(envelopeAuthority) &&
                          envelopeAuthority !== "0".repeat(64) &&
                          setupOpaqueReady(s3Endpoint, 2048) &&
                          setupOpaqueReady(s3Region, 128) &&
                          setupOpaqueReady(s3Bucket, 128) &&
                          setupOpaqueReady(s3Prefix, 1024) &&
                          setupOpaqueReady(kmsRegion, 128) &&
                          setupOpaqueReady(kmsKeyARN, 2048) &&
                          (kmsEndpoint.length === 0 ||
                            setupOpaqueReady(kmsEndpoint, 2048)) &&
                          envelopeApprovedBy === plan.recovery_owner
                        : requirement.key === "secret_backend_validated"
                          ? /^[0-9a-f]{64}$/.test(kmsAuthority) &&
                            kmsAuthority !== "0".repeat(64) &&
                            kmsRegion.length > 0 &&
                            kmsRegion.length <= 128 &&
                            !/[\u0000-\u0020\u007f]/.test(kmsRegion) &&
                            kmsKeyARN.length > 0 &&
                            kmsKeyARN.length <= 2048 &&
                            !/[\u0000-\u0020\u007f]/.test(kmsKeyARN) &&
                            (kmsEndpoint.length === 0 ||
                              (kmsEndpoint.length <= 2048 &&
                                !/[\u0000-\u0020\u007f]/.test(kmsEndpoint))) &&
                            kmsApprovedBy === plan.recovery_owner
                          : policyCheck
                            ? policy.route_inventory_path.length > 0 &&
                              policy.runtime_policy_path.length > 0 &&
                              digestReady &&
                              policy.approved_by === plan.recovery_owner &&
                              (!inferenceCheck || policyPassed)
                            : true;
  const canRun =
    supported && currentAction && requirement.state !== "passed" && configured;
  function execute() {
    if (!canRun || busy) return;
    const input: SetupCheckInput = {
      plan_identity: plan.identity,
      key: requirement.key,
    };
    if (requirement.key === "state_storage_posture_validated")
      input.storage_root = storageRoot;
    if (requirement.key === "backup_validated")
      input.backup_snapshot_path = backupSnapshot;
    if (requirement.key === "local_administrator_validated")
      input.approved_by = administratorApprovedBy;
    if (requirement.key === "postgres_storage_validated") {
      input.approve_postgres_authority_identity = postgresAuthority;
      input.approved_by = postgresApprovedBy;
    }
    if (requirement.key === "shared_rate_limit_validated") {
      input.approve_shared_rate_limit_authority_identity =
        sharedRateLimitAuthority;
      input.postgres_database_authority_identity = postgresDatabaseAuthority;
      input.approved_by = sharedRateLimitApprovedBy;
    }
    if (requirement.key === "replica_reconciliation_validated") {
      input.approve_replica_reconciliation_authority_identity =
        replicaReconciliationAuthority;
      input.postgres_database_authority_identity = postgresDatabaseAuthority;
      input.approved_by = replicaReconciliationApprovedBy;
    }
    if (requirement.key === "signed_bundle_validated") {
      input.approve_signed_bundle_authority_identity = signedBundleAuthority;
      input.bundle_path = signedBundlePath;
      input.bundle_sha256 = signedBundleDigest;
      input.bundle_bytes = Number(signedBundleBytes);
      input.public_key = signedBundlePublicKey;
      input.signature = signedBundleSignature;
      input.approved_by = signedBundleApprovedBy;
    }
    if (requirement.key === "integration_permissions_validated") {
      input.approve_integration_permission_authority_identity =
        integrationPermissionAuthority;
      input.approve_github_source_broker_authority_identity =
        githubBrokerAuthority;
      input.allow_github_installation_token_creation = allowTokenCreation;
      input.approved_by = integrationApprovedBy;
    }
    if (requirement.key === "webhook_validated") {
      input.approve_webhook_authority_identity = webhookAuthority;
      input.github_webhook_key_id = githubWebhookKeyID;
      input.approved_by = webhookApprovedBy;
    }
    if (requirement.key === "envelope_storage_validated") {
      input.approve_envelope_storage_authority_identity = envelopeAuthority;
      input.s3_endpoint = s3Endpoint;
      input.s3_region = s3Region;
      input.s3_bucket = s3Bucket;
      input.s3_prefix = s3Prefix;
      input.kms_region = kmsRegion;
      input.kms_key_arn = kmsKeyARN;
      if (kmsEndpoint.length > 0) input.kms_endpoint = kmsEndpoint;
      input.approved_by = envelopeApprovedBy;
    }
    if (requirement.key === "secret_backend_validated") {
      input.approve_kms_authority_identity = kmsAuthority;
      input.kms_region = kmsRegion;
      input.kms_key_arn = kmsKeyARN;
      if (kmsEndpoint.length > 0) input.kms_endpoint = kmsEndpoint;
      input.approved_by = kmsApprovedBy;
    }
    if (policyCheck) Object.assign(input, policy);
    onRun(input);
    setPending(false);
  }
  return (
    <section className="setup-check-panel" aria-labelledby="setup-check-title">
      <div className="section-head">
        <div>
          <h2 id="setup-check-title">{setupLabel(requirement.key)}</h2>
          <p>{setupLabel(requirement.source)} requirement</p>
        </div>
        <Status value={requirement.state} />
      </div>
      <dl className="setup-check-meta">
        <div>
          <dt>Recovery</dt>
          <dd>
            {requirement.recovery_action
              ? setupLabel(requirement.recovery_action)
              : "None recorded"}
          </dd>
        </div>
        <Identity label="Receipt" value={requirement.receipt_identity} />
        <Identity label="Evidence" value={requirement.evidence_identity} />
      </dl>
      {requirement.key === "state_storage_posture_validated" && (
        <label>
          Private storage root
          <input
            value={storageRoot}
            maxLength={4096}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => {
              setStorageRoot(event.target.value);
              setPending(false);
            }}
          />
          <small>
            The server pins this directory and every ancestor. The path is not
            returned in setup state.
          </small>
        </label>
      )}
      {requirement.key === "postgres_storage_validated" && (
        <div className="policy-fields">
          <p className="setup-guidance">
            Run <code>trestle admin postgres identity</code> with the runtime
            database credential, then approve the returned non-secret identity.
            The confirmed check reads the DSN only on the server, verifies all
            migrations in a read-only transaction, and returns no database
            details.
          </p>
          <label>
            PostgreSQL authority identity
            <input
              className="data-input"
              value={postgresAuthority}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setPostgresAuthority(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            PostgreSQL approved by
            <input
              value={postgresApprovedBy}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setPostgresApprovedBy(event.target.value);
                setPending(false);
              }}
            />
            <small>Must exactly match {plan.recovery_owner}.</small>
          </label>
        </div>
      )}
      {requirement.key === "shared_rate_limit_validated" && (
        <div className="policy-fields">
          <p className="setup-guidance">
            Run <code>trestle admin postgres rate-limit identity</code> with
            this plan&apos;s root identity and the verified runtime database
            authority. Approve the returned shared rate-limit authority only
            after the PostgreSQL storage receipt passes.
          </p>
          <p className="setup-guidance">
            After confirmation and the stale-plan fence, the server reads the
            PostgreSQL URL and uses two independent limiter instances over one
            database. It proves shared quota exhaustion, bounded key
            cardinality, database-clock expiry, concurrent final-permit
            serialization, digest-only keys, and exact disposable-namespace
            cleanup. Database failure returns unavailable and cannot grant an
            API request. This check does not test provider quotas, cost budgets,
            webhook ingress, or Kubernetes networking.
          </p>
          <label>
            Shared rate-limit authority identity
            <input
              className="data-input"
              value={sharedRateLimitAuthority}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setSharedRateLimitAuthority(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            PostgreSQL database authority identity
            <input
              className="data-input"
              value={postgresDatabaseAuthority}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setPostgresDatabaseAuthority(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            Shared rate-limit approved by
            <input
              value={sharedRateLimitApprovedBy}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setSharedRateLimitApprovedBy(event.target.value);
                setPending(false);
              }}
            />
            <small>Must exactly match {plan.recovery_owner}.</small>
          </label>
        </div>
      )}
      {requirement.key === "replica_reconciliation_validated" && (
        <div className="policy-fields">
          <p className="setup-guidance">
            Run <code>trestle admin postgres reconciliation identity</code> with
            this plan&apos;s root identity and the verified runtime database
            authority. Approve the returned replica reconciliation authority
            only after the PostgreSQL storage receipt passes.
          </p>
          <p className="setup-guidance">
            After confirmation and the stale-plan fence, the server reads the
            PostgreSQL URL and uses two independent runtime instances over one
            database. It proves shared plan visibility, deterministic task
            notification, one current task lease, cross-instance completion,
            concurrent terminal reconciliation, and exact disposable-scope
            cleanup. This bounded check does not contact Kubernetes or prove
            physical replication, failover, capacity, latency, or future
            availability.
          </p>
          <label>
            Replica reconciliation authority identity
            <input
              className="data-input"
              value={replicaReconciliationAuthority}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setReplicaReconciliationAuthority(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            PostgreSQL database authority identity
            <input
              className="data-input"
              value={postgresDatabaseAuthority}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setPostgresDatabaseAuthority(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            Replica reconciliation approved by
            <input
              value={replicaReconciliationApprovedBy}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setReplicaReconciliationApprovedBy(event.target.value);
                setPending(false);
              }}
            />
            <small>Must exactly match {plan.recovery_owner}.</small>
          </label>
        </div>
      )}
      {requirement.key === "signed_bundle_validated" && (
        <div className="policy-fields">
          <p className="setup-guidance">
            Compute the exact file size and SHA-256 digest. Sign the canonical
            <code> open-trestle/offline-bundle-signature-statement</code> with
            the approved Ed25519 key, then run
            <code> trestle admin bundle identity</code> with those public
            values. Approve only the returned authority.
          </p>
          <p className="setup-guidance">
            After confirmation and the stale-plan fence, the server opens one
            regular file and streams the opaque file through a 64 KiB SHA-256
            buffer. It verifies the exact byte count, digest, public key, and
            signature. The one GiB bound keeps memory use constant. This check
            does not extract, import, execute, scan, or interpret bundle
            content. It does not validate archive structure, SBOM, provenance,
            release policy, malware, compatibility, key revocation, or
            installation safety.
          </p>
          <label>
            Signed bundle authority identity
            <input
              className="data-input"
              value={signedBundleAuthority}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setSignedBundleAuthority(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            Bundle path
            <input
              className="data-input"
              value={signedBundlePath}
              maxLength={4096}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setSignedBundlePath(event.target.value);
                setPending(false);
              }}
            />
            <small>Absolute path on the setup service host.</small>
          </label>
          <label>
            Bundle SHA-256
            <input
              className="data-input"
              value={signedBundleDigest}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setSignedBundleDigest(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            Bundle bytes
            <input
              className="data-input"
              value={signedBundleBytes}
              inputMode="numeric"
              maxLength={10}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setSignedBundleBytes(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            Ed25519 public key
            <input
              className="data-input"
              value={signedBundlePublicKey}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setSignedBundlePublicKey(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            Ed25519 signature
            <input
              className="data-input"
              value={signedBundleSignature}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setSignedBundleSignature(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            Signed bundle approved by
            <input
              value={signedBundleApprovedBy}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setSignedBundleApprovedBy(event.target.value);
                setPending(false);
              }}
            />
            <small>Must exactly match {plan.recovery_owner}.</small>
          </label>
        </div>
      )}
      {requirement.key === "integration_permissions_validated" && (
        <div className="policy-fields">
          <p className="setup-guidance">
            Run{" "}
            <code>
              trestle admin github permissions identity --broker-config PATH
            </code>{" "}
            on the host. Its schema 2 identities are configuration only. Approve
            the common broker and permission identities independently. The host
            cap, current plan, and exact recovery owner must also match. A setup
            bearer token alone cannot approve issuance. Keys and
            <code> OPEN_TRESTLE_GITHUB_SETUP_TOKEN</code> stay server-side.
          </p>
          <p className="setup-guidance">
            This check can create a GitHub installation token after user
            visibility checks. The native broker authenticates the installation
            and requests and verifies a grant for metadata, contents, and pull
            requests read for one repository. It retains content-free owner
            records and permits foreground demand renewal, not background
            renewal. Ownership is single_host_exclusive, including
            kubernetes_ha. Restart requires an explicit fresh generation and
            reapproval, never owner-record deletion. This grants no runtime or
            publication authority.
          </p>
          <label>
            Integration permission authority identity
            <input
              className="data-input"
              value={integrationPermissionAuthority}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setIntegrationPermissionAuthority(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            GitHub source broker authority identity
            <input
              className="data-input"
              value={githubBrokerAuthority}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setGitHubBrokerAuthority(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <button
            className="secondary-button"
            type="button"
            aria-pressed={allowTokenCreation}
            onClick={() => {
              setAllowTokenCreation(!allowTokenCreation);
              setPending(false);
            }}
          >
            Allow GitHub installation token creation:{" "}
            {allowTokenCreation ? "yes" : "no"}
          </button>
          <label>
            Integration approved by
            <input
              value={integrationApprovedBy}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setIntegrationApprovedBy(event.target.value);
                setPending(false);
              }}
            />
            <small>Must exactly match {plan.recovery_owner}.</small>
          </label>
        </div>
      )}
      {requirement.key === "webhook_validated" && (
        <div className="policy-fields">
          <p className="setup-guidance">
            Run <code>trestle admin github webhook identity</code> with this
            plan&apos;s tenant, repository, and the runtime webhook key ID.
            Approve the returned authority identity. The key ID selects a
            secret; it is not the secret itself.
          </p>
          <p className="setup-guidance">
            After the permission receipt and stale-plan checks pass, the server
            reads <code>OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET</code>, which must be
            a 64-character lowercase hexadecimal encoding of 32 CSPRNG bytes. It
            sends five fixed requests directly to the production handler without
            opening a listener: bad signature, accepted delivery, exact
            duplicate, same-ID body conflict, and ignored action. One public
            payload must be stored before acknowledgment in a disposable private
            file inbox. The inbox is removed before a passing receipt. No GitHub
            call, review run, source read, or publication occurs.
          </p>
          <label>
            Webhook authority identity
            <input
              className="data-input"
              value={webhookAuthority}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setWebhookAuthority(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            GitHub webhook key ID
            <input
              value={githubWebhookKeyID}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              placeholder="primary-2026"
              onChange={(event) => {
                setGitHubWebhookKeyID(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            Webhook approved by
            <input
              value={webhookApprovedBy}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setWebhookApprovedBy(event.target.value);
                setPending(false);
              }}
            />
            <small>Must exactly match {plan.recovery_owner}.</small>
          </label>
        </div>
      )}
      {requirement.key === "envelope_storage_validated" && (
        <div className="policy-fields">
          <p className="setup-guidance">
            Run <code>trestle admin envelope identity</code> with the exact
            tenant, S3 endpoint, region, bucket, prefix, and KMS configuration,
            then approve its non-secret identity. After confirmation, the server
            reads independently named S3 and KMS credential environments. It
            creates one fixed public artifact through client-side envelope
            encryption, proves the stored object does not contain that
            plaintext, retrieves and verifies it, deletes its exact version, and
            verifies absence. The check has a 90-second total bound. It grants
            no publication, source, model, webhook, infrastructure, or broad
            deletion authority.
          </p>
          <p className="setup-guidance">
            A partial failure can leave one encrypted object at a deterministic
            conformance key. A later confirmed run can verify and remove a valid
            exact object. A conflicting or invalid object requires the
            operator's exact-version bucket recovery. A passing receipt requires
            verified absence and stores no endpoint, bucket, prefix, key ARN,
            credential, payload, ciphertext, or object version.
          </p>
          <label>
            Envelope storage authority identity
            <input
              className="data-input"
              value={envelopeAuthority}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setEnvelopeAuthority(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            S3 endpoint
            <input
              value={s3Endpoint}
              maxLength={2048}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setS3Endpoint(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            S3 region
            <input
              value={s3Region}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setS3Region(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            S3 bucket
            <input
              value={s3Bucket}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setS3Bucket(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            S3 object prefix
            <input
              value={s3Prefix}
              maxLength={1024}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setS3Prefix(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            KMS region
            <input
              value={kmsRegion}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setKMSRegion(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            Tenant KMS key ARN
            <input
              value={kmsKeyARN}
              maxLength={2048}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setKMSKeyARN(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            KMS endpoint (optional)
            <input
              value={kmsEndpoint}
              maxLength={2048}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setKMSEndpoint(event.target.value);
                setPending(false);
              }}
            />
            <small>Leave blank for the regional AWS endpoint.</small>
          </label>
          <label>
            Envelope storage approved by
            <input
              value={envelopeApprovedBy}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setEnvelopeApprovedBy(event.target.value);
                setPending(false);
              }}
            />
            <small>Must exactly match {plan.recovery_owner}.</small>
          </label>
        </div>
      )}
      {requirement.key === "secret_backend_validated" && (
        <div className="policy-fields">
          <p className="setup-guidance">
            Run <code>trestle admin kms identity</code> with the exact tenant,
            region, and KMS key ARN, then approve its non-secret identity. The
            confirmed check reads AWS credentials only on the server, performs
            one generate and one unwrap operation, compares the plaintext keys
            in constant time, clears them, and stores no generated key material
            in setup state. Each operation permits at most three attempts inside
            a 60-second total bound. It performs no S3 operation and grants no
            effect authority.
          </p>
          <label>
            KMS authority identity
            <input
              className="data-input"
              value={kmsAuthority}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setKMSAuthority(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            KMS region
            <input
              value={kmsRegion}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setKMSRegion(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            Tenant KMS key ARN
            <input
              value={kmsKeyARN}
              maxLength={2048}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setKMSKeyARN(event.target.value);
                setPending(false);
              }}
            />
          </label>
          <label>
            KMS endpoint (optional)
            <input
              value={kmsEndpoint}
              maxLength={2048}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setKMSEndpoint(event.target.value);
                setPending(false);
              }}
            />
            <small>
              Leave blank for the regional AWS endpoint. A custom endpoint is
              part of the probe identity.
            </small>
          </label>
          <label>
            KMS approved by
            <input
              value={kmsApprovedBy}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setKMSApprovedBy(event.target.value);
                setPending(false);
              }}
            />
            <small>Must exactly match {plan.recovery_owner}.</small>
          </label>
        </div>
      )}
      {requirement.key === "local_administrator_validated" && (
        <label>
          Approved recovery owner
          <input
            value={administratorApprovedBy}
            maxLength={128}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => {
              setAdministratorApprovedBy(event.target.value);
              setPending(false);
            }}
          />
          <small>
            Enter {plan.recovery_owner} to approve this setup service's current
            operating-system identity. This does not create or elevate an
            account.
          </small>
        </label>
      )}
      {requirement.key === "backup_validated" && (
        <label>
          Backup snapshot path
          <input
            value={backupSnapshot}
            maxLength={4096}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => {
              setBackupSnapshot(event.target.value);
              setPending(false);
            }}
          />
          <small>
            Create it with <code>trestle setup backup create</code>. The check
            verifies an exact protected copy. It does not prove independent
            media or a successful disaster recovery exercise.
          </small>
        </label>
      )}
      {requirement.key === "observer_credential_posture_validated" && (
        <p className="setup-guidance">
          The setup service reads its operator and observer token environments
          only after confirmation. No credential value or credential-derived
          hash enters the receipt.
        </p>
      )}
      {policyCheck && (
        <div className="policy-fields">
          <p className="setup-guidance">
            {inferenceCheck ? (
              "This explicit check reads request-time local credentials and attempts at most two fixed probes against independently routed numeric-loopback models. A pass requires both. Each request is capped at 256 output tokens. It has a 90-second total bound, no retry or remote fallback, and cannot publish or run dynamic validation."
            ) : remoteProviderCheck ? (
              "This authorization reads only the two protected configuration files. It validates exact approved remote endpoints, credential environment references, privacy zones, disabled provider logging, cost limits, route health, and verifier independence across distinct provider, connection, endpoint-origin, and credential-reference authorities. It does not read credential values or contact a provider."
            ) : (
              <>
                Use identities reported by <code>trestle config validate</code>.
                The service reads the protected files without resolving
                credentials or contacting endpoints.
              </>
            )}
          </p>
          {inferenceCheck && !policyPassed && (
            <p className="setup-guidance">
              <ShieldCheck aria-hidden="true" />
              Pass the exact policy validation check before running local
              inference.
            </p>
          )}
          <label>
            Route inventory path
            <input
              value={policy.route_inventory_path}
              maxLength={4096}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setPolicy({
                  ...policy,
                  route_inventory_path: event.target.value,
                });
                setPending(false);
              }}
            />
          </label>
          <label>
            Runtime policy path
            <input
              value={policy.runtime_policy_path}
              maxLength={4096}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setPolicy({
                  ...policy,
                  runtime_policy_path: event.target.value,
                });
                setPending(false);
              }}
            />
          </label>
          <label>
            Inventory identity
            <input
              className="data-input"
              value={policy.approve_inventory_identity}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setPolicy({
                  ...policy,
                  approve_inventory_identity: event.target.value,
                });
                setPending(false);
              }}
            />
          </label>
          <label>
            Runtime policy identity
            <input
              className="data-input"
              value={policy.approve_runtime_policy_identity}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setPolicy({
                  ...policy,
                  approve_runtime_policy_identity: event.target.value,
                });
                setPending(false);
              }}
            />
          </label>
          <label>
            Review policy identity
            <input
              className="data-input"
              value={policy.approve_review_policy_identity}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setPolicy({
                  ...policy,
                  approve_review_policy_identity: event.target.value,
                });
                setPending(false);
              }}
            />
          </label>
          <label>
            Approved by
            <input
              value={policy.approved_by}
              maxLength={128}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setPolicy({ ...policy, approved_by: event.target.value });
                setPending(false);
              }}
            />
            <small>Must exactly match {plan.recovery_owner}.</small>
          </label>
        </div>
      )}
      {!supported && requirement.source !== "deterministic" && (
        <div className="setup-unavailable">
          <ShieldCheck aria-hidden="true" />
          <p>
            {requirement.state === "pending"
              ? "No built-in web checker is available for this requirement. Run it from another setup surface; it remains pending."
              : requirement.state === "passed"
                ? "This requirement completed through another setup surface. Its verified receipt is shown here, but this web service cannot rerun it."
                : "This requirement recorded a closed outcome through another setup surface. Follow its recovery action there or refresh after correction."}
          </p>
        </div>
      )}
      {requirement.source === "deterministic" && (
        <div className="setup-guidance">
          This fact is fixed by the protected plan and needs no environment
          check.
        </div>
      )}
      {supported && requirement.state === "passed" && (
        <p className="setup-guidance verified">
          <ShieldCheck aria-hidden="true" />
          This exact requirement has a passing receipt.
        </p>
      )}
      {canRun &&
        (pending ? (
          <div
            className="confirmation-panel compact"
            role="region"
            aria-labelledby="check-confirm-title"
          >
            <ShieldCheck aria-hidden="true" />
            <div>
              <h3 id="check-confirm-title">
                Write one {setupLabel(requirement.key)} receipt?
              </h3>
              <p>
                {requirement.key === "shared_rate_limit_validated"
                  ? "After the PostgreSQL and stale-plan fences, the server will run the bounded shared-database quota cycle, remove its disposable rows, and write only a content-free receipt."
                  : requirement.key === "replica_reconciliation_validated"
                    ? "After the PostgreSQL and stale-plan fences, the server will run the bounded shared-metadata reconciliation cycle, remove its exact disposable scope, and write only a content-free receipt."
                    : requirement.key === "signed_bundle_validated"
                      ? "After the stale-plan fence, the server will stream and verify the exact opaque file. It does not extract, import, or execute the bundle, and it writes only a content-free receipt."
                      : requirement.key === "integration_permissions_validated"
                        ? "Confirm: create GitHub installation token and run integration_permissions_validated. The server independently checks host approval, current plan, actor, and authorities before any effect."
                        : requirement.key === "webhook_validated"
                          ? "After the permission and stale-plan fences, the server will read the webhook secret, run the five-request local conformance cycle, remove its disposable inbox, and then write only a content-free receipt."
                          : requirement.key === "envelope_storage_validated"
                            ? "After the stale-plan fence, the server will perform the bounded KMS operations plus the S3 writes, reads, and exact deletion described above before it can write a content-free receipt."
                            : requirement.key === "secret_backend_validated"
                              ? "After the stale-plan fence, the server will perform the two bounded KMS operations described above and then write a content-free receipt."
                              : remoteProviderCheck
                                ? "After the stale-plan fence, the server will reread the protected configuration and write only a content-free authorization receipt. It will not read provider credentials or make a network request."
                                : "The server will reject this request if the displayed plan identity is stale."}
              </p>
              <div className="confirmation-actions">
                <button type="button" onClick={() => setPending(false)}>
                  Go back
                </button>
                <button
                  ref={confirmActionRef}
                  className="primary-button"
                  type="button"
                  disabled={busy}
                  onClick={execute}
                >
                  {busy ? "Running" : `Run ${setupLabel(requirement.key)}`}
                </button>
              </div>
            </div>
          </div>
        ) : (
          <button
            className="primary-button"
            type="button"
            disabled={busy}
            onClick={() => setPending(true)}
          >
            Review receipt write
          </button>
        ))}
    </section>
  );
}
function SetupWorkspace({
  session,
  busy,
  onRun,
  onRefresh,
  onDisconnect,
}: {
  session: SetupSession;
  busy: boolean;
  onRun: (input: SetupCheckInput) => void;
  onRefresh: () => void;
  onDisconnect: () => void;
}) {
  const plan = session.plan!;
  const [selected, setSelected] = useState<SetupCheckKey>(() =>
    firstPending(plan),
  );
  useEffect(() => {
    if (!plan.requirements.some((requirement) => requirement.key === selected))
      setSelected(firstPending(plan));
  }, [plan, selected]);
  const requirement =
    plan.requirements.find((value) => value.key === selected) ??
    plan.requirements[0]!;
  const passed = plan.requirements.filter(
    (value) => value.state === "passed",
  ).length;
  return (
    <div className="setup-workspace">
      <header className="setup-header">
        <div>
          <div className="scope-line">
            <span>{plan.tenant_id}</span>
            <span>/</span>
            <strong>{plan.repository_id}</strong>
          </div>
          <h1>{setupLabel(plan.profile)}</h1>
          <p>
            {passed} of {plan.requirements.length} requirements passed. Revision{" "}
            {plan.revision}.
          </p>
        </div>
        <div className="header-actions">
          <Status value={plan.status} />
          <button
            className="secondary-button"
            type="button"
            disabled={busy}
            onClick={onRefresh}
          >
            Refresh
          </button>
          <button
            className="secondary-button"
            type="button"
            onClick={onDisconnect}
          >
            Change token
          </button>
        </div>
      </header>
      {plan.requirements.some(
        (value) => value.key === "integration_permissions_validated",
      ) &&
        !hasCurrentIntegrationPermissionAuthority(plan) && (
          <p className="setup-guidance" role="status">
            Historical catalog: Ready and receipts are historical, not current
            integration or webhook approval. Initialize a fresh protected state
            path and current plan; rerun all nondeterministic checks. Do not
            import old receipts or overwrite this plan.
          </p>
        )}
      <div className="setup-layout">
        <aside className="setup-progress" aria-label="Setup requirements">
          <div className="setup-progress-head">
            <h2>Readiness path</h2>
            <progress
              value={passed}
              max={plan.requirements.length}
              aria-label={`${passed} of ${plan.requirements.length} setup requirements passed`}
            />
          </div>
          <SetupRequirementList
            plan={plan}
            selected={requirement.key}
            onSelect={setSelected}
          />
        </aside>
        <div className="setup-detail">
          <section className="setup-boundary">
            <div>
              <ShieldCheck aria-hidden="true" />
              <span>
                <strong>Publication remains locked</strong>
                <small>
                  Publication, fallback, content logging, and dynamic validation
                  are disabled.
                </small>
              </span>
            </div>
            <Identity label="Plan identity" value={plan.identity} />
          </section>
          <SetupCheckPanel
            key={requirement.key}
            plan={plan}
            requirement={requirement}
            busy={busy}
            onRun={onRun}
          />
          <section className="receipt-ledger">
            <div className="section-head">
              <div>
                <h2>Receipt lineage</h2>
                <p>Newest durable checks appear last.</p>
              </div>
              <span className="set-count">{plan.receipts.length} total</span>
            </div>
            {plan.receipts.length === 0 ? (
              <p className="note">No environment check has completed.</p>
            ) : (
              <ol>
                {plan.receipts.slice(-6).map((receipt) => (
                  <li key={receipt.identity}>
                    <Status value={receipt.state} />
                    <span>{setupLabel(receipt.key)}</span>
                    <Identity
                      label="Receipt identity"
                      value={receipt.identity}
                    />
                  </li>
                ))}
              </ol>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
export default function SetupConsole() {
  const [token, setToken] = useState("");
  const [session, setSession] = useState<SetupSession | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const operationRef = useRef(0);
  async function connect(value: string) {
    const operation = ++operationRef.current;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const next = await fetchSetupSession(value);
      if (operation !== operationRef.current) return;
      setSession(next);
      setToken(value);
    } catch (error) {
      if (operation === operationRef.current)
        setError(
          error instanceof ApiError
            ? error.message
            : "The setup service could not be verified.",
        );
    } finally {
      if (operation === operationRef.current) setBusy(false);
    }
  }
  async function create(input: {
    profile: SetupProfile;
    tenant_id: string;
    repository_id: string;
    recovery_owner: string;
  }) {
    const operation = ++operationRef.current;
    setBusy(true);
    setError("");
    try {
      const next = await initializeSetup(input, token);
      if (operation !== operationRef.current) return;
      setSession(next);
      setNotice("Protected setup plan created.");
    } catch (error) {
      if (operation === operationRef.current)
        setError(
          error instanceof ApiError
            ? error.message
            : "The setup plan could not be created.",
        );
    } finally {
      if (operation === operationRef.current) setBusy(false);
    }
  }
  async function runCheck(input: SetupCheckInput) {
    const operation = ++operationRef.current;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await runSetupCheck(input, token);
      if (operation !== operationRef.current) return;
      setSession({
        contract: "open-trestle/setup-session",
        schema_version: 1,
        initialized: true,
        plan: result.plan,
      });
      setNotice(`Check completed: ${setupLabel(result.receipt.state)}.`);
    } catch (error) {
      if (operation === operationRef.current)
        setError(
          error instanceof ApiError
            ? error.message
            : "The setup check could not be verified.",
        );
    } finally {
      if (operation === operationRef.current) setBusy(false);
    }
  }
  function disconnect() {
    operationRef.current++;
    setBusy(false);
    setToken("");
    setSession(null);
    setError("");
    setNotice("");
  }
  return (
    <div className="app-shell setup-shell">
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <header className="setup-top">
        <Brand />
        <a href="/console/">Review console</a>
      </header>
      <main id="main">
        {!session ? (
          <SetupToken busy={busy} onConnect={connect} />
        ) : !session.initialized ? (
          <SetupCreate busy={busy} onCreate={create} />
        ) : (
          <SetupWorkspace
            session={session}
            busy={busy}
            onRun={runCheck}
            onRefresh={() => connect(token)}
            onDisconnect={disconnect}
          />
        )}{" "}
        {notice && (
          <div className="success-banner" role="status">
            <ShieldCheck aria-hidden="true" />
            <p>{notice}</p>
          </div>
        )}
        {error && (
          <div className="error-banner" role="alert">
            <ShieldCheck aria-hidden="true" />
            <div>
              <strong>Setup request failed</strong>
              <p>{error}</p>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
