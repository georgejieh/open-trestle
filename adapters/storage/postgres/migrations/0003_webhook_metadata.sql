CREATE TABLE open_trestle_webhook_deliveries (
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
    repository_id text NOT NULL CHECK (octet_length(repository_id) BETWEEN 1 AND 128),
    review_run_id text NOT NULL CHECK (octet_length(review_run_id) BETWEEN 1 AND 128),
    review_scope_identity text NOT NULL CHECK (review_scope_identity ~ '^[0-9a-f]{64}$'),
    repository_scope_identity text NOT NULL CHECK (repository_scope_identity ~ '^[0-9a-f]{64}$'),
    source text NOT NULL CHECK (source IN ('github', 'gitlab', 'bitbucket_cloud', 'gitea', 'forgejo')),
    deduplication_key text NOT NULL CHECK (deduplication_key ~ '^[0-9a-f]{64}$'),
    delivery_identity text NOT NULL CHECK (delivery_identity ~ '^[0-9a-f]{64}$'),
    artifact_identity text NOT NULL CHECK (artifact_identity ~ '^[0-9a-f]{64}$'),
    accepted_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    stored_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, source, deduplication_key),
    UNIQUE (tenant_id, repository_id, source, delivery_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id, review_scope_identity)
        REFERENCES open_trestle_review_scopes (tenant_id, repository_id, review_run_id, scope_identity),
    CHECK (expires_at > accepted_at)
);

ALTER TABLE open_trestle_webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_webhook_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_webhook_deliveries_tenant_isolation ON open_trestle_webhook_deliveries
    USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));
