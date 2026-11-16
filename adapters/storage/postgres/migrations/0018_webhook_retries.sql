CREATE TABLE open_trestle_webhook_retries (
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
    repository_id text NOT NULL CHECK (octet_length(repository_id) BETWEEN 1 AND 128),
    source text NOT NULL CHECK (source IN ('github', 'gitlab', 'bitbucket_cloud', 'gitea', 'forgejo')),
    deduplication_key text NOT NULL CHECK (deduplication_key ~ '^[0-9a-f]{64}$'),
    planner_identity text NOT NULL CHECK (planner_identity ~ '^[0-9a-f]{64}$'),
    delivery_identity text NOT NULL CHECK (delivery_identity ~ '^[0-9a-f]{64}$'),
    failures smallint NOT NULL CHECK (failures BETWEEN 1 AND 10),
    not_before_milliseconds bigint NOT NULL CHECK (not_before_milliseconds > 0),
    PRIMARY KEY (tenant_id, repository_id, source, deduplication_key),
    FOREIGN KEY (tenant_id, repository_id, source, deduplication_key)
        REFERENCES open_trestle_webhook_deliveries (tenant_id, repository_id, source, deduplication_key) ON DELETE CASCADE
);

ALTER TABLE open_trestle_webhook_retries ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_webhook_retries FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_webhook_retries_tenant_isolation ON open_trestle_webhook_retries
    USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));
