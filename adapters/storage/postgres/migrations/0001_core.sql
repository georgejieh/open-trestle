CREATE TABLE open_trestle_review_scopes (
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
    repository_id text NOT NULL CHECK (octet_length(repository_id) BETWEEN 1 AND 128),
    review_run_id text NOT NULL CHECK (octet_length(review_run_id) BETWEEN 1 AND 128),
    scope_identity text NOT NULL CHECK (scope_identity ~ '^[0-9a-f]{64}$'),
    registered_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, review_run_id),
    UNIQUE (scope_identity),
    UNIQUE (tenant_id, repository_id, review_run_id, scope_identity)
);

CREATE TABLE open_trestle_run_plans (
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
    repository_id text NOT NULL CHECK (octet_length(repository_id) BETWEEN 1 AND 128),
    review_run_id text NOT NULL CHECK (octet_length(review_run_id) BETWEEN 1 AND 128),
    scope_identity text NOT NULL CHECK (scope_identity ~ '^[0-9a-f]{64}$'),
    plan_identity text NOT NULL CHECK (plan_identity ~ '^[0-9a-f]{64}$'),
    canonical_plan bytea NOT NULL CHECK (octet_length(canonical_plan) BETWEEN 1 AND 1048576),
    stored_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, review_run_id),
    UNIQUE (scope_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id, scope_identity)
        REFERENCES open_trestle_review_scopes (tenant_id, repository_id, review_run_id, scope_identity)
);

CREATE TABLE open_trestle_run_events (
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
    repository_id text NOT NULL CHECK (octet_length(repository_id) BETWEEN 1 AND 128),
    review_run_id text NOT NULL CHECK (octet_length(review_run_id) BETWEEN 1 AND 128),
    scope_identity text NOT NULL CHECK (scope_identity ~ '^[0-9a-f]{64}$'),
    plan_identity text NOT NULL CHECK (plan_identity ~ '^[0-9a-f]{64}$'),
    sequence bigint NOT NULL CHECK (sequence BETWEEN 1 AND 10000),
    event_identity text NOT NULL CHECK (event_identity ~ '^[0-9a-f]{64}$'),
    previous_identity text NOT NULL CHECK (previous_identity = '' OR previous_identity ~ '^[0-9a-f]{64}$'),
    canonical_event bytea NOT NULL CHECK (octet_length(canonical_event) BETWEEN 1 AND 1048576),
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, repository_id, review_run_id, sequence),
    UNIQUE (tenant_id, repository_id, review_run_id, event_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id, scope_identity)
        REFERENCES open_trestle_review_scopes (tenant_id, repository_id, review_run_id, scope_identity)
);
CREATE INDEX open_trestle_run_events_head ON open_trestle_run_events (tenant_id, repository_id, review_run_id, sequence DESC);

CREATE TABLE open_trestle_audit_events (
    tenant_id text NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
    repository_id text NOT NULL CHECK (octet_length(repository_id) BETWEEN 1 AND 128),
    review_run_id text NOT NULL CHECK (octet_length(review_run_id) BETWEEN 1 AND 128),
    scope_identity text NOT NULL CHECK (scope_identity ~ '^[0-9a-f]{64}$'),
    sequence bigint NOT NULL CHECK (sequence BETWEEN 1 AND 10000),
    event_identity text NOT NULL CHECK (event_identity ~ '^[0-9a-f]{64}$'),
    previous_identity text NOT NULL CHECK (previous_identity = '' OR previous_identity ~ '^[0-9a-f]{64}$'),
    canonical_event bytea NOT NULL CHECK (octet_length(canonical_event) BETWEEN 1 AND 1048576),
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, repository_id, review_run_id, sequence),
    UNIQUE (tenant_id, repository_id, review_run_id, event_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id, scope_identity)
        REFERENCES open_trestle_review_scopes (tenant_id, repository_id, review_run_id, scope_identity)
);
CREATE INDEX open_trestle_audit_events_head ON open_trestle_audit_events (tenant_id, repository_id, review_run_id, sequence DESC);

ALTER TABLE open_trestle_review_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_review_scopes FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_review_scopes_tenant_isolation ON open_trestle_review_scopes
    USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));

ALTER TABLE open_trestle_run_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_run_plans FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_run_plans_tenant_isolation ON open_trestle_run_plans
    USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));

ALTER TABLE open_trestle_run_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_run_events FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_run_events_tenant_isolation ON open_trestle_run_events
    USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));

ALTER TABLE open_trestle_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_audit_events_tenant_isolation ON open_trestle_audit_events
    USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));

