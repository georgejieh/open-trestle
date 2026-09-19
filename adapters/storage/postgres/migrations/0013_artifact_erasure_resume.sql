CREATE TABLE open_trestle_erasure_resume_allowances (
    tenant_id text NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c01 CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
    repository_id text NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c02 CHECK (octet_length(repository_id) BETWEEN 1 AND 128),
    review_run_id text NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c03 CHECK (octet_length(review_run_id) BETWEEN 1 AND 128),
    scope_identity text NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c04 CHECK (scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    namespace_identity text NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c05 CHECK (namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    artifact_identity text NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c06 CHECK (artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    admission_identity text NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c07 CHECK (admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    operation_identity text NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c08 CHECK (operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    allowance_identity text NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c09 CHECK (allowance_identity ~ '^[0-9a-f]{64}$' AND allowance_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    canonical_allowance bytea NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c10 CHECK (octet_length(canonical_allowance) BETWEEN 1 AND 4096),
    allowance_document_digest text NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c11 CHECK (allowance_document_digest ~ '^[0-9a-f]{64}$' AND allowance_document_digest <> '0000000000000000000000000000000000000000000000000000000000000000'),
    accepted_policy bytea NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c12 CHECK (octet_length(accepted_policy) BETWEEN 1 AND 16384),
    protected_policy_identity text NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c13 CHECK (protected_policy_identity ~ '^[0-9a-f]{64}$' AND protected_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    accepted_at_milliseconds bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c14 CHECK (accepted_at_milliseconds BETWEEN 1 AND 253402300799999),
    maximum_requests bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c15 CHECK (maximum_requests BETWEEN 0 AND 4096),
    maximum_mutations bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c16 CHECK (maximum_mutations BETWEEN 0 AND 2048),
    maximum_reads bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c17 CHECK (maximum_reads BETWEEN 0 AND 2048),
    maximum_lists bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c18 CHECK (maximum_lists BETWEEN 0 AND 1024),
    maximum_creates bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c19 CHECK (maximum_creates BETWEEN 0 AND 128),
    maximum_deletes bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c20 CHECK (maximum_deletes BETWEEN 0 AND 2048),
    maximum_pages bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c21 CHECK (maximum_pages BETWEEN 0 AND 1024),
    maximum_versions bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c22 CHECK (maximum_versions BETWEEN 0 AND 262144),
    maximum_response_bytes bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c23 CHECK (maximum_response_bytes BETWEEN 0 AND 1073741824),
    maximum_list_bytes bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c24 CHECK (maximum_list_bytes BETWEEN 0 AND 67108864),
    maximum_write_bytes bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c25 CHECK (maximum_write_bytes BETWEEN 0 AND 2097152),
    spent_requests bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c26 CHECK (spent_requests BETWEEN 0 AND maximum_requests),
    spent_mutations bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c27 CHECK (spent_mutations BETWEEN 0 AND maximum_mutations),
    spent_reads bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c28 CHECK (spent_reads BETWEEN 0 AND maximum_reads),
    spent_lists bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c29 CHECK (spent_lists BETWEEN 0 AND maximum_lists),
    spent_creates bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c30 CHECK (spent_creates BETWEEN 0 AND maximum_creates),
    spent_deletes bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c31 CHECK (spent_deletes BETWEEN 0 AND maximum_deletes),
    spent_pages bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c32 CHECK (spent_pages BETWEEN 0 AND maximum_pages),
    spent_versions bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c33 CHECK (spent_versions BETWEEN 0 AND maximum_versions),
    spent_response_bytes bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c34 CHECK (spent_response_bytes BETWEEN 0 AND maximum_response_bytes),
    spent_list_bytes bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c35 CHECK (spent_list_bytes BETWEEN 0 AND maximum_list_bytes),
    spent_write_bytes bigint NOT NULL CONSTRAINT open_trestle_erasure_resume_allowances_c36 CHECK (spent_write_bytes BETWEEN 0 AND maximum_write_bytes),
    CONSTRAINT open_trestle_erasure_resume_allowances_x01 CHECK (maximum_requests >= 1),
    CONSTRAINT open_trestle_erasure_resume_allowances_x02 CHECK (maximum_mutations <= maximum_requests),
    CONSTRAINT open_trestle_erasure_resume_allowances_x03 CHECK (spent_mutations <= spent_requests),
    CONSTRAINT open_trestle_erasure_resume_allowances_x04 CHECK (spent_reads + spent_lists + spent_creates + spent_deletes = spent_requests),
    CONSTRAINT open_trestle_erasure_resume_allowances_x05 CHECK (spent_mutations = spent_creates + spent_deletes),
    CONSTRAINT open_trestle_erasure_resume_allowances_x06 CHECK (spent_pages = spent_lists),
    CONSTRAINT open_trestle_erasure_resume_allowances_pkey PRIMARY KEY (tenant_id, repository_id, review_run_id, namespace_identity, operation_identity, allowance_identity),
    CONSTRAINT open_trestle_erasure_resume_allowances_u1 UNIQUE (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, allowance_identity),
    CONSTRAINT open_trestle_erasure_resume_allowances_f1 FOREIGN KEY (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity) REFERENCES open_trestle_artifact_erasure_operations (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION NOT DEFERRABLE
);

ALTER TABLE open_trestle_erasure_resume_allowances ENABLE ROW LEVEL SECURITY;

ALTER TABLE open_trestle_erasure_resume_allowances FORCE ROW LEVEL SECURITY;

CREATE POLICY open_trestle_erasure_resume_allowances_tenant_isolation ON open_trestle_erasure_resume_allowances AS PERMISSIVE FOR ALL TO PUBLIC USING (tenant_id = current_setting('open_trestle.tenant_id', true)) WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));

CREATE TABLE open_trestle_erasure_attempts (
    tenant_id text NOT NULL CONSTRAINT open_trestle_erasure_attempts_c01 CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
    repository_id text NOT NULL CONSTRAINT open_trestle_erasure_attempts_c02 CHECK (octet_length(repository_id) BETWEEN 1 AND 128),
    review_run_id text NOT NULL CONSTRAINT open_trestle_erasure_attempts_c03 CHECK (octet_length(review_run_id) BETWEEN 1 AND 128),
    scope_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempts_c04 CHECK (scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    namespace_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempts_c05 CHECK (namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    artifact_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempts_c06 CHECK (artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    admission_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempts_c07 CHECK (admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    operation_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempts_c08 CHECK (operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    allowance_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempts_c09 CHECK (allowance_identity ~ '^[0-9a-f]{64}$' AND allowance_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    reservation_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempts_c10 CHECK (reservation_identity ~ '^[0-9a-f]{64}$' AND reservation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    attempt_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempts_c11 CHECK (attempt_identity ~ '^[0-9a-f]{64}$' AND attempt_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    request_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempts_c12 CHECK (request_identity ~ '^[0-9a-f]{64}$' AND request_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    canonical_request bytea NOT NULL CONSTRAINT open_trestle_erasure_attempts_c13 CHECK (octet_length(canonical_request) BETWEEN 1 AND 8192),
    canonical_attempt bytea NOT NULL CONSTRAINT open_trestle_erasure_attempts_c14 CHECK (octet_length(canonical_attempt) BETWEEN 1 AND 1024),
    sequence bigint NOT NULL CONSTRAINT open_trestle_erasure_attempts_c15 CHECK (sequence BETWEEN 1 AND 4096),
    reserved_at_milliseconds bigint NOT NULL CONSTRAINT open_trestle_erasure_attempts_c16 CHECK (reserved_at_milliseconds BETWEEN 1 AND 253402300799999),
    cost_requests bigint NOT NULL CONSTRAINT open_trestle_erasure_attempts_c17 CHECK (cost_requests BETWEEN 0 AND 4096),
    cost_mutations bigint NOT NULL CONSTRAINT open_trestle_erasure_attempts_c18 CHECK (cost_mutations BETWEEN 0 AND 2048),
    cost_reads bigint NOT NULL CONSTRAINT open_trestle_erasure_attempts_c19 CHECK (cost_reads BETWEEN 0 AND 2048),
    cost_lists bigint NOT NULL CONSTRAINT open_trestle_erasure_attempts_c20 CHECK (cost_lists BETWEEN 0 AND 1024),
    cost_creates bigint NOT NULL CONSTRAINT open_trestle_erasure_attempts_c21 CHECK (cost_creates BETWEEN 0 AND 128),
    cost_deletes bigint NOT NULL CONSTRAINT open_trestle_erasure_attempts_c22 CHECK (cost_deletes BETWEEN 0 AND 2048),
    cost_pages bigint NOT NULL CONSTRAINT open_trestle_erasure_attempts_c23 CHECK (cost_pages BETWEEN 0 AND 1024),
    cost_versions bigint NOT NULL CONSTRAINT open_trestle_erasure_attempts_c24 CHECK (cost_versions BETWEEN 0 AND 262144),
    cost_response_bytes bigint NOT NULL CONSTRAINT open_trestle_erasure_attempts_c25 CHECK (cost_response_bytes BETWEEN 0 AND 1073741824),
    cost_list_bytes bigint NOT NULL CONSTRAINT open_trestle_erasure_attempts_c26 CHECK (cost_list_bytes BETWEEN 0 AND 67108864),
    cost_write_bytes bigint NOT NULL CONSTRAINT open_trestle_erasure_attempts_c27 CHECK (cost_write_bytes BETWEEN 0 AND 2097152),
    CONSTRAINT open_trestle_erasure_attempts_x01 CHECK (cost_requests = 1),
    CONSTRAINT open_trestle_erasure_attempts_x02 CHECK (cost_mutations = cost_creates + cost_deletes),
    CONSTRAINT open_trestle_erasure_attempts_x03 CHECK (cost_reads + cost_lists + cost_creates + cost_deletes = 1),
    CONSTRAINT open_trestle_erasure_attempts_x04 CHECK (cost_pages = cost_lists),
    CONSTRAINT open_trestle_erasure_attempts_x05 CHECK (cost_mutations BETWEEN 0 AND 1),
    CONSTRAINT open_trestle_erasure_attempts_pkey PRIMARY KEY (tenant_id, repository_id, review_run_id, namespace_identity, operation_identity, reservation_identity),
    CONSTRAINT open_trestle_erasure_attempts_u1 UNIQUE (tenant_id, repository_id, review_run_id, namespace_identity, operation_identity, attempt_identity),
    CONSTRAINT open_trestle_erasure_attempts_u2 UNIQUE (tenant_id, repository_id, review_run_id, namespace_identity, operation_identity, allowance_identity, sequence),
    CONSTRAINT open_trestle_erasure_attempts_u3 UNIQUE (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, attempt_identity),
    CONSTRAINT open_trestle_erasure_attempts_f1 FOREIGN KEY (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity) REFERENCES open_trestle_artifact_erasure_operations (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION NOT DEFERRABLE,
    CONSTRAINT open_trestle_erasure_attempts_f2 FOREIGN KEY (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, allowance_identity) REFERENCES open_trestle_erasure_resume_allowances (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, allowance_identity) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION NOT DEFERRABLE
);

ALTER TABLE open_trestle_erasure_attempts ENABLE ROW LEVEL SECURITY;

ALTER TABLE open_trestle_erasure_attempts FORCE ROW LEVEL SECURITY;

CREATE POLICY open_trestle_erasure_attempts_tenant_isolation ON open_trestle_erasure_attempts AS PERMISSIVE FOR ALL TO PUBLIC USING (tenant_id = current_setting('open_trestle.tenant_id', true)) WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));

CREATE TABLE open_trestle_erasure_attempt_evidence (
    tenant_id text NOT NULL CONSTRAINT open_trestle_erasure_attempt_evidence_c01 CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
    repository_id text NOT NULL CONSTRAINT open_trestle_erasure_attempt_evidence_c02 CHECK (octet_length(repository_id) BETWEEN 1 AND 128),
    review_run_id text NOT NULL CONSTRAINT open_trestle_erasure_attempt_evidence_c03 CHECK (octet_length(review_run_id) BETWEEN 1 AND 128),
    scope_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempt_evidence_c04 CHECK (scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    namespace_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempt_evidence_c05 CHECK (namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    artifact_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempt_evidence_c06 CHECK (artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    admission_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempt_evidence_c07 CHECK (admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    operation_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempt_evidence_c08 CHECK (operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    evidence_identity text NOT NULL CONSTRAINT open_trestle_erasure_attempt_evidence_c09 CHECK (evidence_identity ~ '^[0-9a-f]{64}$' AND evidence_identity <> '0000000000000000000000000000000000000000000000000000000000000000'),
    slot text NOT NULL CONSTRAINT open_trestle_erasure_attempt_evidence_c10 CHECK (octet_length(slot) BETWEEN 1 AND 80),
    kind text NOT NULL CONSTRAINT open_trestle_erasure_attempt_evidence_c11 CHECK (kind IN ('response', 'unknown', 'fence', 'verification', 'candidate', 'published')),
    attempt_identity text CONSTRAINT open_trestle_erasure_attempt_evidence_c12 CHECK (attempt_identity IS NULL OR (attempt_identity ~ '^[0-9a-f]{64}$' AND attempt_identity <> '0000000000000000000000000000000000000000000000000000000000000000')),
    canonical_evidence bytea NOT NULL CONSTRAINT open_trestle_erasure_attempt_evidence_c13 CHECK (octet_length(canonical_evidence) BETWEEN 1 AND 1048576),
    observed_at_milliseconds bigint NOT NULL CONSTRAINT open_trestle_erasure_attempt_evidence_c14 CHECK (observed_at_milliseconds BETWEEN 1 AND 253402300799999),
    CONSTRAINT open_trestle_erasure_attempt_evidence_x01 CHECK ((kind = 'response' AND attempt_identity IS NOT NULL AND slot = 'response:' || attempt_identity) OR (kind = 'unknown' AND attempt_identity IS NOT NULL AND slot = 'unknown:' || attempt_identity) OR (kind = 'fence' AND attempt_identity IS NULL AND slot = 'fence') OR (kind = 'verification' AND attempt_identity IS NULL AND slot ~ '^verification:[0-9a-f]{64}$') OR (kind = 'candidate' AND attempt_identity IS NULL AND slot = 'candidate') OR (kind = 'published' AND attempt_identity IS NULL AND slot = 'published')),
    CONSTRAINT open_trestle_erasure_attempt_evidence_pkey PRIMARY KEY (tenant_id, repository_id, review_run_id, namespace_identity, operation_identity, slot),
    CONSTRAINT open_trestle_erasure_attempt_evidence_u1 UNIQUE (tenant_id, repository_id, review_run_id, namespace_identity, operation_identity, evidence_identity),
    CONSTRAINT open_trestle_erasure_attempt_evidence_f1 FOREIGN KEY (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity) REFERENCES open_trestle_artifact_erasure_operations (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION NOT DEFERRABLE,
    CONSTRAINT open_trestle_erasure_attempt_evidence_f2 FOREIGN KEY (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, attempt_identity) REFERENCES open_trestle_erasure_attempts (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, attempt_identity) MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION NOT DEFERRABLE
);

CREATE INDEX open_trestle_erasure_attempt_evidence_attempt_scan ON open_trestle_erasure_attempt_evidence USING btree (tenant_id, repository_id, review_run_id, namespace_identity, operation_identity, attempt_identity, slot);

ALTER TABLE open_trestle_erasure_attempt_evidence ENABLE ROW LEVEL SECURITY;

ALTER TABLE open_trestle_erasure_attempt_evidence FORCE ROW LEVEL SECURITY;

CREATE POLICY open_trestle_erasure_attempt_evidence_tenant_isolation ON open_trestle_erasure_attempt_evidence AS PERMISSIVE FOR ALL TO PUBLIC USING (tenant_id = current_setting('open_trestle.tenant_id', true)) WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));
