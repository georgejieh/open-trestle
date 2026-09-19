CREATE TABLE open_trestle_artifacts (
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
    repository_id text NOT NULL CHECK (octet_length(repository_id) BETWEEN 1 AND 128),
    review_run_id text NOT NULL CHECK (octet_length(review_run_id) BETWEEN 1 AND 128),
    scope_identity text NOT NULL CHECK (scope_identity ~ '^[0-9a-f]{64}$'),
    artifact_identity text NOT NULL CHECK (artifact_identity ~ '^[0-9a-f]{64}$'),
    payload_digest text NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    kind text NOT NULL CHECK (kind IN ('source_snapshot', 'change_model', 'deterministic_evidence', 'retrieval_result', 'context_packet', 'candidate_batch', 'verification_batch', 'verified_finding_set', 'publication_plan', 'run_export', 'task_input', 'webhook_delivery')),
    classification text NOT NULL CHECK (classification IN ('public', 'internal', 'confidential', 'restricted')),
    origin text NOT NULL CHECK (origin IN ('host', 'repository', 'deterministic_tool', 'model', 'independent_verifier', 'policy')),
    protection text NOT NULL CHECK (protection IN ('process_private', 'envelope_encrypted')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    registered_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, review_run_id, artifact_identity),
    UNIQUE (scope_identity, artifact_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id, scope_identity)
        REFERENCES open_trestle_review_scopes (tenant_id, repository_id, review_run_id, scope_identity),
    CHECK (expires_at > created_at)
);
CREATE INDEX open_trestle_artifacts_expiry ON open_trestle_artifacts (tenant_id, repository_id, expires_at, artifact_identity);

CREATE TABLE open_trestle_artifact_deletion_authorizations (
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    review_run_id text NOT NULL,
    scope_identity text NOT NULL CHECK (scope_identity ~ '^[0-9a-f]{64}$'),
    authorization_identity text NOT NULL CHECK (authorization_identity ~ '^[0-9a-f]{64}$'),
    artifact_identity text NOT NULL CHECK (artifact_identity ~ '^[0-9a-f]{64}$'),
    policy_identity text NOT NULL CHECK (policy_identity ~ '^[0-9a-f]{64}$'),
    principal_identity text NOT NULL CHECK (octet_length(principal_identity) BETWEEN 1 AND 128),
    hold_clearance_identity text NOT NULL CHECK (hold_clearance_identity ~ '^[0-9a-f]{64}$'),
    reason text NOT NULL CHECK (reason IN ('expired', 'tenant_erasure', 'repository_erasure')),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    registered_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, review_run_id, authorization_identity),
    UNIQUE (scope_identity, authorization_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id, scope_identity)
        REFERENCES open_trestle_review_scopes (tenant_id, repository_id, review_run_id, scope_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id, artifact_identity)
        REFERENCES open_trestle_artifacts (tenant_id, repository_id, review_run_id, artifact_identity),
    CHECK (expires_at > issued_at)
);

CREATE TABLE open_trestle_artifact_deletion_receipts (
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    review_run_id text NOT NULL,
    scope_identity text NOT NULL CHECK (scope_identity ~ '^[0-9a-f]{64}$'),
    receipt_identity text NOT NULL CHECK (receipt_identity ~ '^[0-9a-f]{64}$'),
    artifact_identity text NOT NULL CHECK (artifact_identity ~ '^[0-9a-f]{64}$'),
    payload_digest text NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    authorization_identity text NOT NULL CHECK (authorization_identity ~ '^[0-9a-f]{64}$'),
    deleted_at timestamptz NOT NULL,
    registered_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, review_run_id, receipt_identity),
    UNIQUE (tenant_id, repository_id, review_run_id, artifact_identity),
    UNIQUE (scope_identity, receipt_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id, scope_identity)
        REFERENCES open_trestle_review_scopes (tenant_id, repository_id, review_run_id, scope_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id, artifact_identity)
        REFERENCES open_trestle_artifacts (tenant_id, repository_id, review_run_id, artifact_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id, authorization_identity)
        REFERENCES open_trestle_artifact_deletion_authorizations (tenant_id, repository_id, review_run_id, authorization_identity)
);

ALTER TABLE open_trestle_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_artifacts_tenant_isolation ON open_trestle_artifacts
    USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));

ALTER TABLE open_trestle_artifact_deletion_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_artifact_deletion_authorizations FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_artifact_deletion_authorizations_tenant_isolation ON open_trestle_artifact_deletion_authorizations
    USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));

ALTER TABLE open_trestle_artifact_deletion_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_artifact_deletion_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_artifact_deletion_receipts_tenant_isolation ON open_trestle_artifact_deletion_receipts
    USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));

