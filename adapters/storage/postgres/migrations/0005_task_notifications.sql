CREATE TABLE open_trestle_task_notifications (
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    review_run_id text NOT NULL,
    scope_identity text NOT NULL CHECK (scope_identity ~ '^[0-9a-f]{64}$'),
    notice_identity text NOT NULL CHECK (notice_identity ~ '^[0-9a-f]{64}$'),
    plan_identity text NOT NULL CHECK (plan_identity ~ '^[0-9a-f]{64}$'),
    task_state_revision bigint NOT NULL CHECK (task_state_revision > 0),
    task_state_event_identity text NOT NULL CHECK (task_state_event_identity ~ '^[0-9a-f]{64}$'),
    task_key text NOT NULL CHECK (length(task_key) BETWEEN 1 AND 64),
    task_identity text NOT NULL CHECK (task_identity ~ '^[0-9a-f]{64}$'),
    handler_identity text NOT NULL CHECK (handler_identity ~ '^[0-9a-f]{64}$'),
    attempt smallint NOT NULL CHECK (attempt BETWEEN 1 AND 255),
    available_at timestamptz NOT NULL,
    canonical_notice bytea NOT NULL CHECK (octet_length(canonical_notice) BETWEEN 1 AND 16384),
    canonical_checksum text NOT NULL CHECK (canonical_checksum ~ '^[0-9a-f]{64}$'),
    delivery_count smallint NOT NULL DEFAULT 0 CHECK (delivery_count BETWEEN 0 AND 10),
    lease_worker_identity text,
    lease_token_identity text CHECK (lease_token_identity IS NULL OR lease_token_identity ~ '^[0-9a-f]{64}$'),
    leased_at timestamptz,
    lease_expires_at timestamptz,
    acknowledged_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, review_run_id, notice_identity),
    FOREIGN KEY (tenant_id, repository_id, review_run_id)
        REFERENCES open_trestle_review_scopes (tenant_id, repository_id, review_run_id),
    CHECK ((lease_worker_identity IS NULL) = (lease_token_identity IS NULL)),
    CHECK ((lease_token_identity IS NULL) = (leased_at IS NULL)),
    CHECK ((leased_at IS NULL) = (lease_expires_at IS NULL)),
    CHECK (lease_expires_at IS NULL OR lease_expires_at > leased_at),
    CHECK (acknowledged_at IS NULL OR lease_token_identity IS NULL)
);

CREATE INDEX open_trestle_task_notifications_claimable
    ON open_trestle_task_notifications (tenant_id, repository_id, review_run_id, available_at, notice_identity)
    WHERE acknowledged_at IS NULL AND delivery_count < 10;

ALTER TABLE open_trestle_task_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_trestle_task_notifications FORCE ROW LEVEL SECURITY;
CREATE POLICY open_trestle_task_notifications_tenant_isolation ON open_trestle_task_notifications
    USING (tenant_id = current_setting('open_trestle.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));

CREATE FUNCTION open_trestle_signal_task_notification() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    PERFORM pg_notify('open_trestle_task_notifications', '');
    RETURN NEW;
END;
$$;

CREATE TRIGGER open_trestle_task_notifications_signal
AFTER INSERT ON open_trestle_task_notifications
FOR EACH STATEMENT EXECUTE FUNCTION open_trestle_signal_task_notification();

CREATE TRIGGER open_trestle_run_events_task_notification_signal
AFTER INSERT ON open_trestle_run_events
FOR EACH STATEMENT EXECUTE FUNCTION open_trestle_signal_task_notification();
