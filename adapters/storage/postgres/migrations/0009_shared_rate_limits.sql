CREATE TABLE open_trestle_rate_limit_windows (
    namespace text NOT NULL CHECK (namespace ~ '^[a-z0-9][a-z0-9._:/-]{0,127}$'),
    key_digest text NOT NULL CHECK (key_digest ~ '^[0-9a-f]{64}$'),
    configuration_identity text NOT NULL CHECK (configuration_identity ~ '^[0-9a-f]{64}$'),
    window_started_at timestamptz NOT NULL,
    request_count integer NOT NULL CHECK (request_count > 0 AND request_count <= 10000),
    expires_at timestamptz NOT NULL CHECK (expires_at > window_started_at),
    PRIMARY KEY (namespace, key_digest)
);
CREATE INDEX open_trestle_rate_limit_windows_expiry
    ON open_trestle_rate_limit_windows (namespace, expires_at);
