CREATE TABLE open_trestle_diagnostic_sets (
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
    repository_id text NOT NULL CHECK (octet_length(repository_id) BETWEEN 1 AND 128),
    review_run_id text NOT NULL CHECK (octet_length(review_run_id) BETWEEN 1 AND 128),
    scope_identity text NOT NULL CHECK (scope_identity ~ '^[0-9a-f]{64}$'),
    set_identity text NOT NULL CHECK (set_identity ~ '^[0-9a-f]{64}$'),
    artifact_identity text NOT NULL CHECK (artifact_identity ~ '^[0-9a-f]{64}$'),
    expires_at timestamptz NOT NULL,
    stored_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, review_run_id),
    UNIQUE (scope_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id, scope_identity)
        REFERENCES open_trestle_review_scopes (tenant_id, repository_id, review_run_id, scope_identity)
);

ALTER TABLE open_trestle_diagnostic_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_diagnostic_sets FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_diagnostic_sets_tenant_isolation ON open_trestle_diagnostic_sets
    USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));
