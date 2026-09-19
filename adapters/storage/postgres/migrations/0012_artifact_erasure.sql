-- Admission/preparation reservation only. No physical erasure or completion state.

CREATE TABLE open_trestle_artifact_admissions (
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
    repository_id text NOT NULL CHECK (octet_length(repository_id) BETWEEN 1 AND 128),
    review_run_id text NOT NULL CHECK (octet_length(review_run_id) BETWEEN 1 AND 128),
    scope_identity text NOT NULL CHECK (scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    namespace_identity text NOT NULL CHECK (namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    artifact_identity text NOT NULL CHECK (artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    admission_identity text NOT NULL CHECK (admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    canonical_admission bytea NOT NULL CHECK (octet_length(canonical_admission) BETWEEN 1 AND 16384),
    canonical_namespace bytea NOT NULL CHECK (octet_length(canonical_namespace) BETWEEN 1 AND 4096),
    admitted_policy bytea NOT NULL CHECK (octet_length(admitted_policy) BETWEEN 1 AND 16384),
    database_authority_identity text NOT NULL CHECK (database_authority_identity ~ '^[0-9a-f]{64}$' AND database_authority_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    admitted_policy_identity text NOT NULL CHECK (admitted_policy_identity ~ '^[0-9a-f]{64}$' AND admitted_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    admitted_at_milliseconds bigint NOT NULL CHECK (admitted_at_milliseconds BETWEEN 1 AND 253402300799999),
    confirmed_version text,
    confirmed_ciphertext_digest text,
    confirmed_at_milliseconds bigint,
    PRIMARY KEY (tenant_id, repository_id, review_run_id, artifact_identity),
    UNIQUE (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity),
    UNIQUE (tenant_id, repository_id, review_run_id, namespace_identity, admission_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id, artifact_identity) REFERENCES open_trestle_artifacts (tenant_id, repository_id, review_run_id, artifact_identity) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION,
    FOREIGN KEY (tenant_id, repository_id, review_run_id, scope_identity) REFERENCES open_trestle_review_scopes (tenant_id, repository_id, review_run_id, scope_identity) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION,
    CHECK ((confirmed_version IS NULL AND confirmed_ciphertext_digest IS NULL AND confirmed_at_milliseconds IS NULL) OR (confirmed_version IS NOT NULL AND confirmed_ciphertext_digest IS NOT NULL AND confirmed_at_milliseconds IS NOT NULL AND left(confirmed_version, 8) = 'version:' AND octet_length(confirmed_version) BETWEEN 9 AND 512 AND confirmed_version <> 'version:null' AND confirmed_version !~ '[[:space:][:cntrl:]]' AND confirmed_ciphertext_digest ~ '^[0-9a-f]{64}$' AND confirmed_ciphertext_digest <> '0000000000000000000000000000000000000000000000000000000000000000' AND confirmed_at_milliseconds BETWEEN 1 AND 253402300799999 AND confirmed_at_milliseconds >= admitted_at_milliseconds))
);
CREATE INDEX open_trestle_artifact_admissions_scan ON open_trestle_artifact_admissions (tenant_id, repository_id, namespace_identity, review_run_id, artifact_identity);
ALTER TABLE open_trestle_artifact_admissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_artifact_admissions FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_artifact_admissions_tenant_isolation ON open_trestle_artifact_admissions
    FOR ALL TO PUBLIC USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));

CREATE TABLE open_trestle_artifact_erasure_operations (
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
    repository_id text NOT NULL CHECK (octet_length(repository_id) BETWEEN 1 AND 128),
    review_run_id text NOT NULL CHECK (octet_length(review_run_id) BETWEEN 1 AND 128),
    scope_identity text NOT NULL CHECK (scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    namespace_identity text NOT NULL CHECK (namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    artifact_identity text NOT NULL CHECK (artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    admission_identity text NOT NULL CHECK (admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    operation_identity text NOT NULL CHECK (operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    canonical_operation bytea NOT NULL CHECK (octet_length(canonical_operation) BETWEEN 1 AND 16384),
    canonical_authorization bytea NOT NULL CHECK (octet_length(canonical_authorization) BETWEEN 1 AND 8192),
    accepted_policy bytea NOT NULL CHECK (octet_length(accepted_policy) BETWEEN 1 AND 16384),
    authorization_identity text NOT NULL CHECK (authorization_identity ~ '^[0-9a-f]{64}$' AND authorization_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    authorization_document_digest text NOT NULL CHECK (authorization_document_digest ~ '^[0-9a-f]{64}$' AND authorization_document_digest <> '0000000000000000000000000000000000000000000000000000000000000000'),
    protected_policy_identity text NOT NULL CHECK (protected_policy_identity ~ '^[0-9a-f]{64}$' AND protected_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    database_authority_identity text NOT NULL CHECK (database_authority_identity ~ '^[0-9a-f]{64}$' AND database_authority_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    prepared_at_milliseconds bigint NOT NULL CHECK (prepared_at_milliseconds BETWEEN 1 AND 253402300799999),
    accepted_at_milliseconds bigint NOT NULL CHECK (accepted_at_milliseconds BETWEEN 1 AND 253402300799999),
    CHECK (accepted_at_milliseconds >= prepared_at_milliseconds),
    PRIMARY KEY (tenant_id, repository_id, review_run_id, namespace_identity, operation_identity),
    UNIQUE (tenant_id, repository_id, review_run_id, artifact_identity),
    UNIQUE (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity) REFERENCES open_trestle_artifact_admissions (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION
);
ALTER TABLE open_trestle_artifact_erasure_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_artifact_erasure_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_artifact_erasure_operations_tenant_isolation ON open_trestle_artifact_erasure_operations
    FOR ALL TO PUBLIC USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));
