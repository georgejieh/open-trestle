CREATE TABLE open_trestle_publication_attempts (
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    review_run_id text NOT NULL,
    scope_identity text NOT NULL CHECK (scope_identity ~ '^[0-9a-f]{64}$'),
    operation_key text NOT NULL CHECK (operation_key ~ '^[0-9a-f]{64}$'),
    attempt_identity text NOT NULL CHECK (attempt_identity ~ '^[0-9a-f]{64}$'),
    request_identity text NOT NULL CHECK (request_identity ~ '^[0-9a-f]{64}$'),
    status text NOT NULL CHECK (status IN ('claimed', 'completed')),
    result_identity text CHECK (result_identity IS NULL OR result_identity ~ '^[0-9a-f]{64}$'),
    claimed_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (tenant_id, repository_id, review_run_id, operation_key),
    UNIQUE (tenant_id, repository_id, review_run_id, attempt_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id)
        REFERENCES open_trestle_review_scopes (tenant_id, repository_id, review_run_id),
    CHECK ((status = 'claimed' AND result_identity IS NULL AND completed_at IS NULL)
        OR (status = 'completed' AND result_identity IS NOT NULL AND completed_at IS NOT NULL)),
    CHECK (completed_at IS NULL OR completed_at >= claimed_at)
);

CREATE INDEX open_trestle_publication_attempts_attempt
    ON open_trestle_publication_attempts (tenant_id, repository_id, review_run_id, attempt_identity);

ALTER TABLE open_trestle_publication_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_publication_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_publication_attempts_tenant_isolation ON open_trestle_publication_attempts
    USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));
