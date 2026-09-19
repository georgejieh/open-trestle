CREATE TABLE open_trestle_publication_guard_authority (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    database_namespace_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    authority_identity text NOT NULL CHECK (authority_identity ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
