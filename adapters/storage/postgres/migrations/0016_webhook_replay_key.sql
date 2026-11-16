ALTER TABLE open_trestle_webhook_deliveries
    ADD COLUMN replay_key text CHECK (replay_key IS NULL OR replay_key ~ '^[0-9a-f]{64}$');

ALTER TABLE open_trestle_webhook_deliveries
    ADD CONSTRAINT open_trestle_webhook_deliveries_replay_key_required
    CHECK (replay_key IS NOT NULL) NOT VALID;

CREATE UNIQUE INDEX open_trestle_webhook_deliveries_replay_key_idx
    ON open_trestle_webhook_deliveries (tenant_id, repository_id, source, replay_key)
    WHERE replay_key IS NOT NULL;
