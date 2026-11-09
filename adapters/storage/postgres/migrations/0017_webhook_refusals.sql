CREATE TABLE open_trestle_webhook_refusals (
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
    repository_id text NOT NULL CHECK (octet_length(repository_id) BETWEEN 1 AND 128),
    source text NOT NULL CHECK (source IN ('github', 'gitlab', 'bitbucket_cloud', 'gitea', 'forgejo')),
    deduplication_key text NOT NULL CHECK (deduplication_key ~ '^[0-9a-f]{64}$'),
    planner_identity text NOT NULL CHECK (planner_identity ~ '^[0-9a-f]{64}$'),
    delivery_identity text NOT NULL CHECK (delivery_identity ~ '^[0-9a-f]{64}$'),
    record_identity text NOT NULL CHECK (record_identity ~ '^[0-9a-f]{64}$'),
    reason text NOT NULL CHECK (reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    refused_at_milliseconds bigint NOT NULL CHECK (refused_at_milliseconds > 0),
    PRIMARY KEY (tenant_id, repository_id, source, deduplication_key, planner_identity),
    FOREIGN KEY (tenant_id, repository_id, source, deduplication_key)
        REFERENCES open_trestle_webhook_deliveries (tenant_id, repository_id, source, deduplication_key) ON DELETE CASCADE
);

ALTER TABLE open_trestle_webhook_refusals ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_webhook_refusals FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_webhook_refusals_tenant_isolation ON open_trestle_webhook_refusals
    USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));
