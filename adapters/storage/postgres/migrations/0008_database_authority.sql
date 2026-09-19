CREATE TABLE open_trestle_database_authority (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    database_namespace_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO open_trestle_database_authority (singleton)
VALUES (true)
ON CONFLICT (singleton) DO NOTHING;
