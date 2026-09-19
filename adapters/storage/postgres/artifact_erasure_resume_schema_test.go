package postgres

import (
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const resumeAllowances = "open_trestle_erasure_resume_allowances"
const resumeAttempts = "open_trestle_erasure_attempts"
const resumeEvidence = "open_trestle_erasure_attempt_evidence"

var resumeNewTableNames = []string{resumeAllowances, resumeAttempts, resumeEvidence}
var resumeFixtureTableNames = append(append([]string(nil), erasureTableNames...), resumeNewTableNames...)

const resumeRegistryJSON = `{"admission_insert":{"sql":"INSERT INTO open_trestle_artifact_admissions (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, canonical_admission, canonical_namespace, admitted_policy, database_authority_identity, admitted_policy_identity, admitted_at_milliseconds, confirmed_version, confirmed_ciphertext_digest, confirmed_at_milliseconds) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULL, NULL, NULL)","parameters":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","canonical_admission:[]byte","canonical_namespace:[]byte","admitted_policy:[]byte","database_authority_identity:string","admitted_policy_identity:string","admitted_at_milliseconds:int64"],"columns":[]},"admission_lock_read":{"sql":"SELECT a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_admissions AS a LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE a.tenant_id = $1 AND a.repository_id = $2 AND a.review_run_id = $3 AND a.namespace_identity = $4 AND a.artifact_identity = $5 FOR UPDATE OF a","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","artifact_identity:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","canonical_admission:[]byte","canonical_namespace:[]byte","admitted_policy:[]byte","database_authority_identity:string","admitted_policy_identity:string","admitted_at_milliseconds:int64","confirmed_version:string|NULL","confirmed_ciphertext_digest:string|NULL","confirmed_at_milliseconds:int64|NULL","joined_scope_identity:string|NULL","metadata_scope_identity:string|NULL","metadata_artifact_identity:string|NULL","metadata_payload_digest:string|NULL","metadata_kind:string|NULL","metadata_classification:string|NULL","metadata_origin:string|NULL","metadata_protection:string|NULL","metadata_created_at:time.Time|NULL","metadata_expires_at:time.Time|NULL"]},"admission_read":{"sql":"SELECT a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_admissions AS a LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE a.tenant_id = $1 AND a.repository_id = $2 AND a.review_run_id = $3 AND a.namespace_identity = $4 AND a.artifact_identity = $5","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","artifact_identity:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","canonical_admission:[]byte","canonical_namespace:[]byte","admitted_policy:[]byte","database_authority_identity:string","admitted_policy_identity:string","admitted_at_milliseconds:int64","confirmed_version:string|NULL","confirmed_ciphertext_digest:string|NULL","confirmed_at_milliseconds:int64|NULL","joined_scope_identity:string|NULL","metadata_scope_identity:string|NULL","metadata_artifact_identity:string|NULL","metadata_payload_digest:string|NULL","metadata_kind:string|NULL","metadata_classification:string|NULL","metadata_origin:string|NULL","metadata_protection:string|NULL","metadata_created_at:time.Time|NULL","metadata_expires_at:time.Time|NULL"]},"artifact_lock":{"sql":"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))","parameters":["common_key:string"],"columns":[]},"attributes":{"sql":"SELECT a.attnum::bigint, a.attname::text, t.oid::bigint, tn.nspname::text, t.typname::text, a.atttypmod::bigint, a.attnotnull, a.attisdropped, a.attgenerated::text, a.attidentity::text, pg_catalog.pg_get_expr(d.adbin, d.adrelid, false) FROM pg_catalog.pg_attribute AS a JOIN pg_catalog.pg_type AS t ON t.oid = a.atttypid JOIN pg_catalog.pg_namespace AS tn ON tn.oid = t.typnamespace LEFT JOIN pg_catalog.pg_attrdef AS d ON d.adrelid = a.attrelid AND d.adnum = a.attnum WHERE a.attrelid = $1::oid AND a.attnum > 0 ORDER BY a.attnum ASC","parameters":["relation_oid:int64"],"columns":["attnum:int64","attname:string","type_oid:int64","type_schema:string","type_name:string","typmod:int64","not_null:bool","dropped:bool","generated:string","identity:string","default_expression:string|NULL"]},"authority_identity":{"sql":"SELECT pg_catalog.current_database(), pg_catalog.current_schema(), CURRENT_USER, database_namespace_id::text FROM open_trestle_database_authority WHERE singleton = true","parameters":[],"columns":["database_name:string","schema_name:string","role_name:string","database_namespace_id:string"]},"authority_schemas":{"sql":"SELECT pg_catalog.current_schema(), (SELECT n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = pg_catalog.to_regclass('open_trestle_schema_migrations')), (SELECT n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = pg_catalog.to_regclass('open_trestle_database_authority'))","parameters":[],"columns":["current_schema:string","migrations_schema:string|NULL","authority_schema:string|NULL"]},"confirmation_cas":{"sql":"UPDATE open_trestle_artifact_admissions AS a SET confirmed_version = $8, confirmed_ciphertext_digest = $9, confirmed_at_milliseconds = $10 WHERE a.tenant_id = $1 AND a.repository_id = $2 AND a.review_run_id = $3 AND a.scope_identity = $4 AND a.namespace_identity = $5 AND a.artifact_identity = $6 AND a.admission_identity = $7 AND a.confirmed_version IS NULL AND a.confirmed_ciphertext_digest IS NULL AND a.confirmed_at_milliseconds IS NULL AND NOT EXISTS (SELECT 1 FROM open_trestle_artifact_erasure_operations AS o WHERE o.tenant_id = a.tenant_id AND o.repository_id = a.repository_id AND o.review_run_id = a.review_run_id AND o.namespace_identity = a.namespace_identity AND o.artifact_identity = a.artifact_identity)","parameters":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","confirmed_version:string","confirmed_ciphertext_digest:string","confirmed_at_milliseconds:int64"],"columns":[]},"confirmation_privileges":{"sql":"SELECT pg_catalog.has_column_privilege($2, $1::oid, 'confirmed_version', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'confirmed_ciphertext_digest', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'confirmed_at_milliseconds', 'UPDATE')","parameters":["admission_relation_oid:int64","authority_role:string"],"columns":["version_update:bool","digest_update:bool","time_update:bool"]},"constraints":{"sql":"SELECT c.oid::bigint, c.conname::text, c.contype::text, c.convalidated, c.condeferrable, c.condeferred, c.conislocal, c.coninhcount::bigint, COALESCE(pg_catalog.array_to_string(c.conkey, ','), ''), c.confrelid::bigint, COALESCE(pg_catalog.array_to_string(c.confkey, ','), ''), CASE WHEN c.contype = 'f' THEN c.confmatchtype::text ELSE '' END, CASE WHEN c.contype = 'f' THEN c.confupdtype::text ELSE '' END, CASE WHEN c.contype = 'f' THEN c.confdeltype::text ELSE '' END, pg_catalog.pg_get_expr(c.conbin, c.conrelid, false) FROM pg_catalog.pg_constraint AS c WHERE c.conrelid = $1::oid ORDER BY c.conname ASC","parameters":["relation_oid:int64"],"columns":["constraint_oid:int64","constraint_name:string","constraint_type:string","validated:bool","deferrable:bool","initially_deferred:bool","local:bool","inherit_count:int64","key_attnums:string","foreign_relation_oid:int64","foreign_attnums:string","match_type:string","update_action:string","delete_action:string","check_expression:string|NULL"]},"indexes":{"sql":"SELECT ic.oid::bigint, ic.relname::text, am.amname::text, i.indisprimary, i.indisunique, i.indisvalid, i.indisready, i.indislive, i.indimmediate, i.indnkeyatts::bigint, i.indnatts::bigint, i.indkey::text, i.indoption::text, pg_catalog.pg_get_expr(i.indexprs, i.indrelid, false), pg_catalog.pg_get_expr(i.indpred, i.indrelid, false) FROM pg_catalog.pg_index AS i JOIN pg_catalog.pg_class AS ic ON ic.oid = i.indexrelid JOIN pg_catalog.pg_am AS am ON am.oid = ic.relam WHERE i.indrelid = $1::oid ORDER BY ic.relname ASC","parameters":["relation_oid:int64"],"columns":["index_oid:int64","index_name:string","access_method:string","primary:bool","unique:bool","valid:bool","ready:bool","live:bool","immediate:bool","key_count:int64","attribute_count:int64","ordered_attnums:string","ordered_options:string","expression:string|NULL","predicate:string|NULL"]},"key_occupancy":{"sql":"SELECT namespace_identity, admission_identity FROM open_trestle_artifact_admissions WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4","parameters":["tenant_id:string","repository_id:string","review_run_id:string","artifact_identity:string"],"columns":["namespace_identity:string","admission_identity:string"]},"legacy_lineage":{"sql":"SELECT EXISTS (SELECT 1 FROM open_trestle_artifact_deletion_authorizations WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4), EXISTS (SELECT 1 FROM open_trestle_artifact_deletion_receipts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4)","parameters":["tenant_id:string","repository_id:string","review_run_id:string","artifact_identity:string"],"columns":["has_authorization:bool","has_receipt:bool"]},"metadata_insert":{"sql":"INSERT INTO open_trestle_artifacts (tenant_id, repository_id, review_run_id, scope_identity, artifact_identity, payload_digest, kind, classification, origin, protection, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)","parameters":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","artifact_identity:string","payload_digest:string","kind:string","classification:string","origin:string","protection:string","created_at:time.Time","expires_at:time.Time"],"columns":[]},"metadata_read":{"sql":"SELECT payload_digest, kind, classification, origin, protection, created_at, expires_at FROM open_trestle_artifacts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4","parameters":["tenant_id:string","repository_id:string","review_run_id:string","artifact_identity:string"],"columns":["payload_digest:string","kind:string","classification:string","origin:string","protection:string","created_at:time.Time","expires_at:time.Time"]},"migration_rows":{"sql":"SELECT version, checksum FROM open_trestle_schema_migrations ORDER BY version ASC","parameters":[],"columns":["version:int64","checksum:string"]},"operation_insert":{"sql":"INSERT INTO open_trestle_artifact_erasure_operations (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, canonical_operation, canonical_authorization, accepted_policy, authorization_identity, authorization_document_digest, protected_policy_identity, database_authority_identity, prepared_at_milliseconds, accepted_at_milliseconds) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)","parameters":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","canonical_operation:[]byte","canonical_authorization:[]byte","accepted_policy:[]byte","authorization_identity:string","authorization_document_digest:string","protected_policy_identity:string","database_authority_identity:string","prepared_at_milliseconds:int64","accepted_at_milliseconds:int64"],"columns":[]},"operation_presence":{"sql":"SELECT operation_identity FROM open_trestle_artifact_erasure_operations WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND artifact_identity = $5","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","artifact_identity:string"],"columns":["operation_identity:string"]},"operation_read":{"sql":"SELECT o.tenant_id, o.repository_id, o.review_run_id, o.scope_identity, o.namespace_identity, o.artifact_identity, o.admission_identity, o.operation_identity, o.canonical_operation, o.canonical_authorization, o.accepted_policy, o.authorization_identity, o.authorization_document_digest, o.protected_policy_identity, o.database_authority_identity, o.prepared_at_milliseconds, o.accepted_at_milliseconds, a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_erasure_operations AS o LEFT JOIN open_trestle_artifact_admissions AS a ON a.tenant_id = o.tenant_id AND a.repository_id = o.repository_id AND a.review_run_id = o.review_run_id AND a.scope_identity = o.scope_identity AND a.namespace_identity = o.namespace_identity AND a.artifact_identity = o.artifact_identity AND a.admission_identity = o.admission_identity LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE o.tenant_id = $1 AND o.repository_id = $2 AND o.review_run_id = $3 AND o.namespace_identity = $4 AND o.artifact_identity = $5","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","artifact_identity:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","canonical_operation:[]byte","canonical_authorization:[]byte","accepted_policy:[]byte","authorization_identity:string","authorization_document_digest:string","protected_policy_identity:string","database_authority_identity:string","prepared_at_milliseconds:int64","accepted_at_milliseconds:int64","admission.tenant_id:string|NULL","admission.repository_id:string|NULL","admission.review_run_id:string|NULL","admission.scope_identity:string|NULL","admission.namespace_identity:string|NULL","admission.artifact_identity:string|NULL","admission.admission_identity:string|NULL","admission.canonical_admission:[]byte|NULL","admission.canonical_namespace:[]byte|NULL","admission.admitted_policy:[]byte|NULL","admission.database_authority_identity:string|NULL","admission.admitted_policy_identity:string|NULL","admission.admitted_at_milliseconds:int64|NULL","admission.confirmed_version:string|NULL","admission.confirmed_ciphertext_digest:string|NULL","admission.confirmed_at_milliseconds:int64|NULL","joined_scope_identity:string|NULL","metadata_scope_identity:string|NULL","metadata_artifact_identity:string|NULL","metadata_payload_digest:string|NULL","metadata_kind:string|NULL","metadata_classification:string|NULL","metadata_origin:string|NULL","metadata_protection:string|NULL","metadata_created_at:time.Time|NULL","metadata_expires_at:time.Time|NULL"]},"operation_ref_read":{"sql":"SELECT o.tenant_id, o.repository_id, o.review_run_id, o.scope_identity, o.namespace_identity, o.artifact_identity, o.admission_identity, o.operation_identity, o.canonical_operation, o.canonical_authorization, o.accepted_policy, o.authorization_identity, o.authorization_document_digest, o.protected_policy_identity, o.database_authority_identity, o.prepared_at_milliseconds, o.accepted_at_milliseconds, a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_erasure_operations AS o LEFT JOIN open_trestle_artifact_admissions AS a ON a.tenant_id = o.tenant_id AND a.repository_id = o.repository_id AND a.review_run_id = o.review_run_id AND a.scope_identity = o.scope_identity AND a.namespace_identity = o.namespace_identity AND a.artifact_identity = o.artifact_identity AND a.admission_identity = o.admission_identity LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE o.tenant_id = $1 AND o.repository_id = $2 AND o.review_run_id = $3 AND o.namespace_identity = $4 AND o.operation_identity = $5","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","canonical_operation:[]byte","canonical_authorization:[]byte","accepted_policy:[]byte","authorization_identity:string","authorization_document_digest:string","protected_policy_identity:string","database_authority_identity:string","prepared_at_milliseconds:int64","accepted_at_milliseconds:int64","admission.tenant_id:string|NULL","admission.repository_id:string|NULL","admission.review_run_id:string|NULL","admission.scope_identity:string|NULL","admission.namespace_identity:string|NULL","admission.artifact_identity:string|NULL","admission.admission_identity:string|NULL","admission.canonical_admission:[]byte|NULL","admission.canonical_namespace:[]byte|NULL","admission.admitted_policy:[]byte|NULL","admission.database_authority_identity:string|NULL","admission.admitted_policy_identity:string|NULL","admission.admitted_at_milliseconds:int64|NULL","admission.confirmed_version:string|NULL","admission.confirmed_ciphertext_digest:string|NULL","admission.confirmed_at_milliseconds:int64|NULL","joined_scope_identity:string|NULL","metadata_scope_identity:string|NULL","metadata_artifact_identity:string|NULL","metadata_payload_digest:string|NULL","metadata_kind:string|NULL","metadata_classification:string|NULL","metadata_origin:string|NULL","metadata_protection:string|NULL","metadata_created_at:time.Time|NULL","metadata_expires_at:time.Time|NULL"]},"policies":{"sql":"SELECT p.oid::bigint, p.polname::text, p.polcmd::text, p.polpermissive, pg_catalog.array_to_string(p.polroles, ','), pg_catalog.pg_get_expr(p.polqual, p.polrelid, false), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid, false) FROM pg_catalog.pg_policy AS p WHERE p.polrelid = $1::oid ORDER BY p.polname ASC","parameters":["relation_oid:int64"],"columns":["policy_oid:int64","policy_name:string","command:string","permissive:bool","role_oids:string","using_expression:string|NULL","check_expression:string|NULL"]},"relation":{"sql":"SELECT c.oid::bigint, n.oid::bigint, n.nspname::text, c.relname::text, c.relkind::text, c.relrowsecurity, c.relforcerowsecurity, pg_catalog.to_regclass($2)::oid::bigint FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2","parameters":["authority_schema:string","relation_name:string"],"columns":["relation_oid:int64","schema_oid:int64","schema_name:string","relation_name:string","relkind:string","rls_enabled:bool","rls_forced:bool","unqualified_resolved_oid:int64|NULL"]},"role":{"sql":"SELECT r.oid::bigint, r.rolname::text, r.rolsuper, r.rolbypassrls, pg_catalog.current_setting('row_security') FROM pg_catalog.pg_roles AS r WHERE r.rolname = CURRENT_USER","parameters":[],"columns":["role_oid:int64","role_name:string","rolsuper:bool","rolbypassrls:bool","row_security:string"]},"scope_insert":{"sql":"INSERT INTO open_trestle_review_scopes (tenant_id, repository_id, review_run_id, scope_identity) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING","parameters":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string"],"columns":[]},"scope_read":{"sql":"SELECT scope_identity FROM open_trestle_review_scopes WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3","parameters":["tenant_id:string","repository_id:string","review_run_id:string"],"columns":["scope_identity:string"]},"table_privileges":{"sql":"SELECT pg_catalog.has_schema_privilege($2, $3, 'USAGE'), pg_catalog.has_table_privilege($2, $1::oid, 'SELECT'), pg_catalog.has_table_privilege($2, $1::oid, 'INSERT'), pg_catalog.has_table_privilege($2, $1::oid, 'UPDATE'), pg_catalog.has_table_privilege($2, $1::oid, 'DELETE'), pg_catalog.has_table_privilege($2, $1::oid, 'TRUNCATE'), pg_catalog.has_any_column_privilege($2, $1::oid, 'UPDATE')","parameters":["relation_oid:int64","authority_role:string","authority_schema:string"],"columns":["schema_usage:bool","select:bool","insert:bool","update:bool","delete:bool","truncate:bool","any_column_update:bool"]},"tenant_guc":{"sql":"SELECT set_config('open_trestle.tenant_id', $1, true)","parameters":["tenant_id:string"],"columns":[]},"allowance_counter_privileges":{"sql":"SELECT pg_catalog.has_column_privilege($2, $1::oid, 'spent_requests', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_mutations', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_reads', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_lists', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_creates', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_deletes', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_pages', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_versions', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_response_bytes', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_list_bytes', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_write_bytes', 'UPDATE')","parameters":["relation_oid:int64","role:string"],"columns":["spent_requests:bool","spent_mutations:bool","spent_reads:bool","spent_lists:bool","spent_creates:bool","spent_deletes:bool","spent_pages:bool","spent_versions:bool","spent_response_bytes:bool","spent_list_bytes:bool","spent_write_bytes:bool"]},"allowance_immutable_privileges":{"sql":"SELECT pg_catalog.has_column_privilege($2, $1::oid, 'tenant_id', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'repository_id', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'review_run_id', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'scope_identity', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'namespace_identity', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'artifact_identity', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'admission_identity', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'operation_identity', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'allowance_identity', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'canonical_allowance', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'allowance_document_digest', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'accepted_policy', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'protected_policy_identity', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'accepted_at_milliseconds', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_requests', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_mutations', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_reads', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_lists', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_creates', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_deletes', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_pages', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_versions', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_response_bytes', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_list_bytes', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_write_bytes', 'UPDATE')","parameters":["relation_oid:int64","role:string"],"columns":["tenant_id:bool","repository_id:bool","review_run_id:bool","scope_identity:bool","namespace_identity:bool","artifact_identity:bool","admission_identity:bool","operation_identity:bool","allowance_identity:bool","canonical_allowance:bool","allowance_document_digest:bool","accepted_policy:bool","protected_policy_identity:bool","accepted_at_milliseconds:bool","maximum_requests:bool","maximum_mutations:bool","maximum_reads:bool","maximum_lists:bool","maximum_creates:bool","maximum_deletes:bool","maximum_pages:bool","maximum_versions:bool","maximum_response_bytes:bool","maximum_list_bytes:bool","maximum_write_bytes:bool"]},"allowance_insert":{"sql":"INSERT INTO open_trestle_erasure_resume_allowances (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, allowance_identity, canonical_allowance, allowance_document_digest, accepted_policy, protected_policy_identity, accepted_at_milliseconds, maximum_requests, maximum_mutations, maximum_reads, maximum_lists, maximum_creates, maximum_deletes, maximum_pages, maximum_versions, maximum_response_bytes, maximum_list_bytes, maximum_write_bytes, spent_requests, spent_mutations, spent_reads, spent_lists, spent_creates, spent_deletes, spent_pages, spent_versions, spent_response_bytes, spent_list_bytes, spent_write_bytes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36)","parameters":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","allowance_identity:string","canonical_allowance:[]byte","allowance_document_digest:string","accepted_policy:[]byte","protected_policy_identity:string","accepted_at_milliseconds:int64","maximum_requests:int64","maximum_mutations:int64","maximum_reads:int64","maximum_lists:int64","maximum_creates:int64","maximum_deletes:int64","maximum_pages:int64","maximum_versions:int64","maximum_response_bytes:int64","maximum_list_bytes:int64","maximum_write_bytes:int64","spent_requests:int64","spent_mutations:int64","spent_reads:int64","spent_lists:int64","spent_creates:int64","spent_deletes:int64","spent_pages:int64","spent_versions:int64","spent_response_bytes:int64","spent_list_bytes:int64","spent_write_bytes:int64"],"columns":[]},"allowance_lock":{"sql":"SELECT tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, allowance_identity, canonical_allowance, allowance_document_digest, accepted_policy, protected_policy_identity, accepted_at_milliseconds, maximum_requests, maximum_mutations, maximum_reads, maximum_lists, maximum_creates, maximum_deletes, maximum_pages, maximum_versions, maximum_response_bytes, maximum_list_bytes, maximum_write_bytes, spent_requests, spent_mutations, spent_reads, spent_lists, spent_creates, spent_deletes, spent_pages, spent_versions, spent_response_bytes, spent_list_bytes, spent_write_bytes FROM open_trestle_erasure_resume_allowances WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND operation_identity = $5 AND allowance_identity = $6 FOR UPDATE","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string","allowance_identity:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","allowance_identity:string","canonical_allowance:[]byte","allowance_document_digest:string","accepted_policy:[]byte","protected_policy_identity:string","accepted_at_milliseconds:int64","maximum_requests:int64","maximum_mutations:int64","maximum_reads:int64","maximum_lists:int64","maximum_creates:int64","maximum_deletes:int64","maximum_pages:int64","maximum_versions:int64","maximum_response_bytes:int64","maximum_list_bytes:int64","maximum_write_bytes:int64","spent_requests:int64","spent_mutations:int64","spent_reads:int64","spent_lists:int64","spent_creates:int64","spent_deletes:int64","spent_pages:int64","spent_versions:int64","spent_response_bytes:int64","spent_list_bytes:int64","spent_write_bytes:int64"]},"allowance_read":{"sql":"SELECT tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, allowance_identity, canonical_allowance, allowance_document_digest, accepted_policy, protected_policy_identity, accepted_at_milliseconds, maximum_requests, maximum_mutations, maximum_reads, maximum_lists, maximum_creates, maximum_deletes, maximum_pages, maximum_versions, maximum_response_bytes, maximum_list_bytes, maximum_write_bytes, spent_requests, spent_mutations, spent_reads, spent_lists, spent_creates, spent_deletes, spent_pages, spent_versions, spent_response_bytes, spent_list_bytes, spent_write_bytes FROM open_trestle_erasure_resume_allowances WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND operation_identity = $5 AND allowance_identity = $6","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string","allowance_identity:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","allowance_identity:string","canonical_allowance:[]byte","allowance_document_digest:string","accepted_policy:[]byte","protected_policy_identity:string","accepted_at_milliseconds:int64","maximum_requests:int64","maximum_mutations:int64","maximum_reads:int64","maximum_lists:int64","maximum_creates:int64","maximum_deletes:int64","maximum_pages:int64","maximum_versions:int64","maximum_response_bytes:int64","maximum_list_bytes:int64","maximum_write_bytes:int64","spent_requests:int64","spent_mutations:int64","spent_reads:int64","spent_lists:int64","spent_creates:int64","spent_deletes:int64","spent_pages:int64","spent_versions:int64","spent_response_bytes:int64","spent_list_bytes:int64","spent_write_bytes:int64"]},"allowance_spend":{"sql":"UPDATE open_trestle_erasure_resume_allowances SET spent_requests = spent_requests + $7, spent_mutations = spent_mutations + $8, spent_reads = spent_reads + $9, spent_lists = spent_lists + $10, spent_creates = spent_creates + $11, spent_deletes = spent_deletes + $12, spent_pages = spent_pages + $13, spent_versions = spent_versions + $14, spent_response_bytes = spent_response_bytes + $15, spent_list_bytes = spent_list_bytes + $16, spent_write_bytes = spent_write_bytes + $17 WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND operation_identity = $5 AND allowance_identity = $6 AND spent_requests + $7 <= maximum_requests AND spent_mutations + $8 <= maximum_mutations AND spent_reads + $9 <= maximum_reads AND spent_lists + $10 <= maximum_lists AND spent_creates + $11 <= maximum_creates AND spent_deletes + $12 <= maximum_deletes AND spent_pages + $13 <= maximum_pages AND spent_versions + $14 <= maximum_versions AND spent_response_bytes + $15 <= maximum_response_bytes AND spent_list_bytes + $16 <= maximum_list_bytes AND spent_write_bytes + $17 <= maximum_write_bytes","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string","allowance_identity:string","delta_requests:int64","delta_mutations:int64","delta_reads:int64","delta_lists:int64","delta_creates:int64","delta_deletes:int64","delta_pages:int64","delta_versions:int64","delta_response_bytes:int64","delta_list_bytes:int64","delta_write_bytes:int64"],"columns":[]},"allowance_totals":{"sql":"SELECT COUNT(*)::bigint, COALESCE(SUM(cost_requests), 0)::bigint, COALESCE(SUM(cost_mutations), 0)::bigint, COALESCE(SUM(cost_reads), 0)::bigint, COALESCE(SUM(cost_lists), 0)::bigint, COALESCE(SUM(cost_creates), 0)::bigint, COALESCE(SUM(cost_deletes), 0)::bigint, COALESCE(SUM(cost_pages), 0)::bigint, COALESCE(SUM(cost_versions), 0)::bigint, COALESCE(SUM(cost_response_bytes), 0)::bigint, COALESCE(SUM(cost_list_bytes), 0)::bigint, COALESCE(SUM(cost_write_bytes), 0)::bigint FROM open_trestle_erasure_attempts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND operation_identity = $5 AND allowance_identity = $6","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string","allowance_identity:string"],"columns":["attempt_count:int64","total_requests:int64","total_mutations:int64","total_reads:int64","total_lists:int64","total_creates:int64","total_deletes:int64","total_pages:int64","total_versions:int64","total_response_bytes:int64","total_list_bytes:int64","total_write_bytes:int64"]},"attempt_identity_read":{"sql":"SELECT tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, allowance_identity, reservation_identity, attempt_identity, request_identity, canonical_request, canonical_attempt, sequence, reserved_at_milliseconds, cost_requests, cost_mutations, cost_reads, cost_lists, cost_creates, cost_deletes, cost_pages, cost_versions, cost_response_bytes, cost_list_bytes, cost_write_bytes FROM open_trestle_erasure_attempts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND operation_identity = $5 AND attempt_identity = $6","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string","attempt_identity:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","allowance_identity:string","reservation_identity:string","attempt_identity:string","request_identity:string","canonical_request:[]byte","canonical_attempt:[]byte","sequence:int64","reserved_at_milliseconds:int64","cost_requests:int64","cost_mutations:int64","cost_reads:int64","cost_lists:int64","cost_creates:int64","cost_deletes:int64","cost_pages:int64","cost_versions:int64","cost_response_bytes:int64","cost_list_bytes:int64","cost_write_bytes:int64"]},"attempt_insert":{"sql":"INSERT INTO open_trestle_erasure_attempts (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, allowance_identity, reservation_identity, attempt_identity, request_identity, canonical_request, canonical_attempt, sequence, reserved_at_milliseconds, cost_requests, cost_mutations, cost_reads, cost_lists, cost_creates, cost_deletes, cost_pages, cost_versions, cost_response_bytes, cost_list_bytes, cost_write_bytes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)","parameters":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","allowance_identity:string","reservation_identity:string","attempt_identity:string","request_identity:string","canonical_request:[]byte","canonical_attempt:[]byte","sequence:int64","reserved_at_milliseconds:int64","cost_requests:int64","cost_mutations:int64","cost_reads:int64","cost_lists:int64","cost_creates:int64","cost_deletes:int64","cost_pages:int64","cost_versions:int64","cost_response_bytes:int64","cost_list_bytes:int64","cost_write_bytes:int64"],"columns":[]},"attempt_page":{"sql":"SELECT tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, allowance_identity, reservation_identity, attempt_identity, request_identity, canonical_request, canonical_attempt, sequence, reserved_at_milliseconds, cost_requests, cost_mutations, cost_reads, cost_lists, cost_creates, cost_deletes, cost_pages, cost_versions, cost_response_bytes, cost_list_bytes, cost_write_bytes FROM open_trestle_erasure_attempts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND operation_identity = $5 AND allowance_identity = $6 AND sequence > $7 ORDER BY sequence ASC LIMIT $8","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string","allowance_identity:string","after_sequence:int64","limit_plus_one:int64"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","allowance_identity:string","reservation_identity:string","attempt_identity:string","request_identity:string","canonical_request:[]byte","canonical_attempt:[]byte","sequence:int64","reserved_at_milliseconds:int64","cost_requests:int64","cost_mutations:int64","cost_reads:int64","cost_lists:int64","cost_creates:int64","cost_deletes:int64","cost_pages:int64","cost_versions:int64","cost_response_bytes:int64","cost_list_bytes:int64","cost_write_bytes:int64"]},"attempt_read":{"sql":"SELECT tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, allowance_identity, reservation_identity, attempt_identity, request_identity, canonical_request, canonical_attempt, sequence, reserved_at_milliseconds, cost_requests, cost_mutations, cost_reads, cost_lists, cost_creates, cost_deletes, cost_pages, cost_versions, cost_response_bytes, cost_list_bytes, cost_write_bytes FROM open_trestle_erasure_attempts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND operation_identity = $5 AND reservation_identity = $6","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string","reservation_identity:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","allowance_identity:string","reservation_identity:string","attempt_identity:string","request_identity:string","canonical_request:[]byte","canonical_attempt:[]byte","sequence:int64","reserved_at_milliseconds:int64","cost_requests:int64","cost_mutations:int64","cost_reads:int64","cost_lists:int64","cost_creates:int64","cost_deletes:int64","cost_pages:int64","cost_versions:int64","cost_response_bytes:int64","cost_list_bytes:int64","cost_write_bytes:int64"]},"evidence_attempt_read":{"sql":"SELECT tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, evidence_identity, slot, kind, attempt_identity, canonical_evidence, observed_at_milliseconds FROM open_trestle_erasure_attempt_evidence WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND operation_identity = $5 AND attempt_identity = $6 ORDER BY slot ASC LIMIT 3","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string","attempt_identity:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","evidence_identity:string","slot:string","kind:string","attempt_identity:string|NULL","canonical_evidence:[]byte","observed_at_milliseconds:int64"]},"evidence_identity_read":{"sql":"SELECT tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, evidence_identity, slot, kind, attempt_identity, canonical_evidence, observed_at_milliseconds FROM open_trestle_erasure_attempt_evidence WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND operation_identity = $5 AND evidence_identity = $6","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string","evidence_identity:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","evidence_identity:string","slot:string","kind:string","attempt_identity:string|NULL","canonical_evidence:[]byte","observed_at_milliseconds:int64"]},"evidence_insert":{"sql":"INSERT INTO open_trestle_erasure_attempt_evidence (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, evidence_identity, slot, kind, attempt_identity, canonical_evidence, observed_at_milliseconds) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)","parameters":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","evidence_identity:string","slot:string","kind:string","attempt_identity:string|NULL","canonical_evidence:[]byte","observed_at_milliseconds:int64"],"columns":[]},"evidence_slot_read":{"sql":"SELECT tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, evidence_identity, slot, kind, attempt_identity, canonical_evidence, observed_at_milliseconds FROM open_trestle_erasure_attempt_evidence WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND operation_identity = $5 AND slot = $6","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string","slot:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","evidence_identity:string","slot:string","kind:string","attempt_identity:string|NULL","canonical_evidence:[]byte","observed_at_milliseconds:int64"]},"unknown_exists":{"sql":"SELECT EXISTS (SELECT 1 FROM open_trestle_erasure_attempt_evidence WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND operation_identity = $5 AND kind = 'unknown')","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string"],"columns":["unknown_history:bool"]},"unrecorded_uncertainty_page":{"sql":"SELECT a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.operation_identity, a.allowance_identity, a.reservation_identity, a.attempt_identity, a.request_identity, a.canonical_request, a.canonical_attempt, a.sequence, a.reserved_at_milliseconds, a.cost_requests, a.cost_mutations, a.cost_reads, a.cost_lists, a.cost_creates, a.cost_deletes, a.cost_pages, a.cost_versions, a.cost_response_bytes, a.cost_list_bytes, a.cost_write_bytes FROM open_trestle_erasure_attempts AS a WHERE a.tenant_id = $1 AND a.repository_id = $2 AND a.review_run_id = $3 AND a.namespace_identity = $4 AND a.operation_identity = $5 AND a.attempt_identity > $6 AND NOT EXISTS (SELECT 1 FROM open_trestle_erasure_attempt_evidence AS e WHERE e.tenant_id = a.tenant_id AND e.repository_id = a.repository_id AND e.review_run_id = a.review_run_id AND e.namespace_identity = a.namespace_identity AND e.operation_identity = a.operation_identity AND e.attempt_identity = a.attempt_identity AND e.kind = 'response') AND NOT EXISTS (SELECT 1 FROM open_trestle_erasure_attempt_evidence AS e WHERE e.tenant_id = a.tenant_id AND e.repository_id = a.repository_id AND e.review_run_id = a.review_run_id AND e.namespace_identity = a.namespace_identity AND e.operation_identity = a.operation_identity AND e.attempt_identity = a.attempt_identity AND e.kind = 'unknown') ORDER BY a.attempt_identity ASC LIMIT $7","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string","after_attempt_identity:string","limit_plus_one:int64"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","allowance_identity:string","reservation_identity:string","attempt_identity:string","request_identity:string","canonical_request:[]byte","canonical_attempt:[]byte","sequence:int64","reserved_at_milliseconds:int64","cost_requests:int64","cost_mutations:int64","cost_reads:int64","cost_lists:int64","cost_creates:int64","cost_deletes:int64","cost_pages:int64","cost_versions:int64","cost_response_bytes:int64","cost_list_bytes:int64","cost_write_bytes:int64"]},"unresolved_exists":{"sql":"SELECT EXISTS (SELECT 1 FROM open_trestle_erasure_attempts AS a WHERE a.tenant_id = $1 AND a.repository_id = $2 AND a.review_run_id = $3 AND a.namespace_identity = $4 AND a.operation_identity = $5 AND NOT EXISTS (SELECT 1 FROM open_trestle_erasure_attempt_evidence AS e WHERE e.tenant_id = a.tenant_id AND e.repository_id = a.repository_id AND e.review_run_id = a.review_run_id AND e.namespace_identity = a.namespace_identity AND e.operation_identity = a.operation_identity AND e.attempt_identity = a.attempt_identity AND e.kind = 'response'))","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string"],"columns":["unresolved:bool"]},"user_triggers":{"sql":"SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS t WHERE t.tgrelid = $1::oid AND NOT t.tgisinternal)","parameters":["relation_oid:int64"],"columns":["has_user_triggers:bool"]}}`
const resumeDescriptorJSON = `{"open_trestle_erasure_resume_allowances":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"namespace_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"admission_identity","type":"text","nullable":false,"default_expression":null},{"name":"operation_identity","type":"text","nullable":false,"default_expression":null},{"name":"allowance_identity","type":"text","nullable":false,"default_expression":null},{"name":"canonical_allowance","type":"bytea","nullable":false,"default_expression":null},{"name":"allowance_document_digest","type":"text","nullable":false,"default_expression":null},{"name":"accepted_policy","type":"bytea","nullable":false,"default_expression":null},{"name":"protected_policy_identity","type":"text","nullable":false,"default_expression":null},{"name":"accepted_at_milliseconds","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_requests","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_mutations","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_reads","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_lists","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_creates","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_deletes","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_pages","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_versions","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_response_bytes","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_list_bytes","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_write_bytes","type":"int8","nullable":false,"default_expression":null},{"name":"spent_requests","type":"int8","nullable":false,"default_expression":null},{"name":"spent_mutations","type":"int8","nullable":false,"default_expression":null},{"name":"spent_reads","type":"int8","nullable":false,"default_expression":null},{"name":"spent_lists","type":"int8","nullable":false,"default_expression":null},{"name":"spent_creates","type":"int8","nullable":false,"default_expression":null},{"name":"spent_deletes","type":"int8","nullable":false,"default_expression":null},{"name":"spent_pages","type":"int8","nullable":false,"default_expression":null},{"name":"spent_versions","type":"int8","nullable":false,"default_expression":null},{"name":"spent_response_bytes","type":"int8","nullable":false,"default_expression":null},{"name":"spent_list_bytes","type":"int8","nullable":false,"default_expression":null},{"name":"spent_write_bytes","type":"int8","nullable":false,"default_expression":null}],"constraints":[{"kind":"CHECK","expression":"octet_length(tenant_id) BETWEEN 1 AND 128","referenced_columns":["tenant_id"]},{"kind":"CHECK","expression":"octet_length(repository_id) BETWEEN 1 AND 128","referenced_columns":["repository_id"]},{"kind":"CHECK","expression":"octet_length(review_run_id) BETWEEN 1 AND 128","referenced_columns":["review_run_id"]},{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["namespace_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["admission_identity"]},{"kind":"CHECK","expression":"operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["operation_identity"]},{"kind":"CHECK","expression":"allowance_identity ~ '^[0-9a-f]{64}$' AND allowance_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["allowance_identity"]},{"kind":"CHECK","expression":"octet_length(canonical_allowance) BETWEEN 1 AND 4096","referenced_columns":["canonical_allowance"]},{"kind":"CHECK","expression":"allowance_document_digest ~ '^[0-9a-f]{64}$' AND allowance_document_digest <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["allowance_document_digest"]},{"kind":"CHECK","expression":"octet_length(accepted_policy) BETWEEN 1 AND 16384","referenced_columns":["accepted_policy"]},{"kind":"CHECK","expression":"protected_policy_identity ~ '^[0-9a-f]{64}$' AND protected_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["protected_policy_identity"]},{"kind":"CHECK","expression":"accepted_at_milliseconds BETWEEN 1 AND 253402300799999","referenced_columns":["accepted_at_milliseconds"]},{"kind":"CHECK","expression":"maximum_requests BETWEEN 0 AND 4096","referenced_columns":["maximum_requests"]},{"kind":"CHECK","expression":"maximum_mutations BETWEEN 0 AND 2048","referenced_columns":["maximum_mutations"]},{"kind":"CHECK","expression":"maximum_reads BETWEEN 0 AND 2048","referenced_columns":["maximum_reads"]},{"kind":"CHECK","expression":"maximum_lists BETWEEN 0 AND 1024","referenced_columns":["maximum_lists"]},{"kind":"CHECK","expression":"maximum_creates BETWEEN 0 AND 128","referenced_columns":["maximum_creates"]},{"kind":"CHECK","expression":"maximum_deletes BETWEEN 0 AND 2048","referenced_columns":["maximum_deletes"]},{"kind":"CHECK","expression":"maximum_pages BETWEEN 0 AND 1024","referenced_columns":["maximum_pages"]},{"kind":"CHECK","expression":"maximum_versions BETWEEN 0 AND 262144","referenced_columns":["maximum_versions"]},{"kind":"CHECK","expression":"maximum_response_bytes BETWEEN 0 AND 1073741824","referenced_columns":["maximum_response_bytes"]},{"kind":"CHECK","expression":"maximum_list_bytes BETWEEN 0 AND 67108864","referenced_columns":["maximum_list_bytes"]},{"kind":"CHECK","expression":"maximum_write_bytes BETWEEN 0 AND 2097152","referenced_columns":["maximum_write_bytes"]},{"kind":"CHECK","expression":"spent_requests BETWEEN 0 AND maximum_requests","referenced_columns":["spent_requests"]},{"kind":"CHECK","expression":"spent_mutations BETWEEN 0 AND maximum_mutations","referenced_columns":["spent_mutations"]},{"kind":"CHECK","expression":"spent_reads BETWEEN 0 AND maximum_reads","referenced_columns":["spent_reads"]},{"kind":"CHECK","expression":"spent_lists BETWEEN 0 AND maximum_lists","referenced_columns":["spent_lists"]},{"kind":"CHECK","expression":"spent_creates BETWEEN 0 AND maximum_creates","referenced_columns":["spent_creates"]},{"kind":"CHECK","expression":"spent_deletes BETWEEN 0 AND maximum_deletes","referenced_columns":["spent_deletes"]},{"kind":"CHECK","expression":"spent_pages BETWEEN 0 AND maximum_pages","referenced_columns":["spent_pages"]},{"kind":"CHECK","expression":"spent_versions BETWEEN 0 AND maximum_versions","referenced_columns":["spent_versions"]},{"kind":"CHECK","expression":"spent_response_bytes BETWEEN 0 AND maximum_response_bytes","referenced_columns":["spent_response_bytes"]},{"kind":"CHECK","expression":"spent_list_bytes BETWEEN 0 AND maximum_list_bytes","referenced_columns":["spent_list_bytes"]},{"kind":"CHECK","expression":"spent_write_bytes BETWEEN 0 AND maximum_write_bytes","referenced_columns":["spent_write_bytes"]},{"kind":"CHECK","expression":"maximum_requests >= 1","referenced_columns":["maximum_requests"]},{"kind":"CHECK","expression":"maximum_mutations <= maximum_requests","referenced_columns":["maximum_requests","maximum_mutations"]},{"kind":"CHECK","expression":"spent_mutations <= spent_requests","referenced_columns":["spent_requests","spent_mutations"]},{"kind":"CHECK","expression":"spent_reads + spent_lists + spent_creates + spent_deletes = spent_requests","referenced_columns":["spent_requests","spent_reads","spent_lists","spent_creates","spent_deletes"]},{"kind":"CHECK","expression":"spent_mutations = spent_creates + spent_deletes","referenced_columns":["spent_mutations","spent_creates","spent_deletes"]},{"kind":"CHECK","expression":"spent_pages = spent_lists","referenced_columns":["spent_lists","spent_pages"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","allowance_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","allowance_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"],"target_table":"open_trestle_artifact_erasure_operations","target_columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"]}],"indexes":[{"name":"open_trestle_erasure_resume_allowances_pkey","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","allowance_identity"],"unique":true,"primary":true},{"name":"open_trestle_erasure_resume_allowances_u1","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","allowance_identity"],"unique":true,"primary":false}]},"open_trestle_erasure_attempts":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"namespace_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"admission_identity","type":"text","nullable":false,"default_expression":null},{"name":"operation_identity","type":"text","nullable":false,"default_expression":null},{"name":"allowance_identity","type":"text","nullable":false,"default_expression":null},{"name":"reservation_identity","type":"text","nullable":false,"default_expression":null},{"name":"attempt_identity","type":"text","nullable":false,"default_expression":null},{"name":"request_identity","type":"text","nullable":false,"default_expression":null},{"name":"canonical_request","type":"bytea","nullable":false,"default_expression":null},{"name":"canonical_attempt","type":"bytea","nullable":false,"default_expression":null},{"name":"sequence","type":"int8","nullable":false,"default_expression":null},{"name":"reserved_at_milliseconds","type":"int8","nullable":false,"default_expression":null},{"name":"cost_requests","type":"int8","nullable":false,"default_expression":null},{"name":"cost_mutations","type":"int8","nullable":false,"default_expression":null},{"name":"cost_reads","type":"int8","nullable":false,"default_expression":null},{"name":"cost_lists","type":"int8","nullable":false,"default_expression":null},{"name":"cost_creates","type":"int8","nullable":false,"default_expression":null},{"name":"cost_deletes","type":"int8","nullable":false,"default_expression":null},{"name":"cost_pages","type":"int8","nullable":false,"default_expression":null},{"name":"cost_versions","type":"int8","nullable":false,"default_expression":null},{"name":"cost_response_bytes","type":"int8","nullable":false,"default_expression":null},{"name":"cost_list_bytes","type":"int8","nullable":false,"default_expression":null},{"name":"cost_write_bytes","type":"int8","nullable":false,"default_expression":null}],"constraints":[{"kind":"CHECK","expression":"octet_length(tenant_id) BETWEEN 1 AND 128","referenced_columns":["tenant_id"]},{"kind":"CHECK","expression":"octet_length(repository_id) BETWEEN 1 AND 128","referenced_columns":["repository_id"]},{"kind":"CHECK","expression":"octet_length(review_run_id) BETWEEN 1 AND 128","referenced_columns":["review_run_id"]},{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["namespace_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["admission_identity"]},{"kind":"CHECK","expression":"operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["operation_identity"]},{"kind":"CHECK","expression":"allowance_identity ~ '^[0-9a-f]{64}$' AND allowance_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["allowance_identity"]},{"kind":"CHECK","expression":"reservation_identity ~ '^[0-9a-f]{64}$' AND reservation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["reservation_identity"]},{"kind":"CHECK","expression":"attempt_identity ~ '^[0-9a-f]{64}$' AND attempt_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["attempt_identity"]},{"kind":"CHECK","expression":"request_identity ~ '^[0-9a-f]{64}$' AND request_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["request_identity"]},{"kind":"CHECK","expression":"octet_length(canonical_request) BETWEEN 1 AND 8192","referenced_columns":["canonical_request"]},{"kind":"CHECK","expression":"octet_length(canonical_attempt) BETWEEN 1 AND 1024","referenced_columns":["canonical_attempt"]},{"kind":"CHECK","expression":"sequence BETWEEN 1 AND 4096","referenced_columns":["sequence"]},{"kind":"CHECK","expression":"reserved_at_milliseconds BETWEEN 1 AND 253402300799999","referenced_columns":["reserved_at_milliseconds"]},{"kind":"CHECK","expression":"cost_requests BETWEEN 0 AND 4096","referenced_columns":["cost_requests"]},{"kind":"CHECK","expression":"cost_mutations BETWEEN 0 AND 2048","referenced_columns":["cost_mutations"]},{"kind":"CHECK","expression":"cost_reads BETWEEN 0 AND 2048","referenced_columns":["cost_reads"]},{"kind":"CHECK","expression":"cost_lists BETWEEN 0 AND 1024","referenced_columns":["cost_lists"]},{"kind":"CHECK","expression":"cost_creates BETWEEN 0 AND 128","referenced_columns":["cost_creates"]},{"kind":"CHECK","expression":"cost_deletes BETWEEN 0 AND 2048","referenced_columns":["cost_deletes"]},{"kind":"CHECK","expression":"cost_pages BETWEEN 0 AND 1024","referenced_columns":["cost_pages"]},{"kind":"CHECK","expression":"cost_versions BETWEEN 0 AND 262144","referenced_columns":["cost_versions"]},{"kind":"CHECK","expression":"cost_response_bytes BETWEEN 0 AND 1073741824","referenced_columns":["cost_response_bytes"]},{"kind":"CHECK","expression":"cost_list_bytes BETWEEN 0 AND 67108864","referenced_columns":["cost_list_bytes"]},{"kind":"CHECK","expression":"cost_write_bytes BETWEEN 0 AND 2097152","referenced_columns":["cost_write_bytes"]},{"kind":"CHECK","expression":"cost_requests = 1","referenced_columns":["cost_requests"]},{"kind":"CHECK","expression":"cost_mutations = cost_creates + cost_deletes","referenced_columns":["cost_mutations","cost_creates","cost_deletes"]},{"kind":"CHECK","expression":"cost_reads + cost_lists + cost_creates + cost_deletes = 1","referenced_columns":["cost_reads","cost_lists","cost_creates","cost_deletes"]},{"kind":"CHECK","expression":"cost_pages = cost_lists","referenced_columns":["cost_lists","cost_pages"]},{"kind":"CHECK","expression":"cost_mutations BETWEEN 0 AND 1","referenced_columns":["cost_mutations"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","reservation_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","attempt_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","allowance_identity","sequence"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","attempt_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"],"target_table":"open_trestle_artifact_erasure_operations","target_columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","allowance_identity"],"target_table":"open_trestle_erasure_resume_allowances","target_columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","allowance_identity"]}],"indexes":[{"name":"open_trestle_erasure_attempts_pkey","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","reservation_identity"],"unique":true,"primary":true},{"name":"open_trestle_erasure_attempts_u1","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","attempt_identity"],"unique":true,"primary":false},{"name":"open_trestle_erasure_attempts_u2","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","allowance_identity","sequence"],"unique":true,"primary":false},{"name":"open_trestle_erasure_attempts_u3","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","attempt_identity"],"unique":true,"primary":false}]},"open_trestle_erasure_attempt_evidence":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"namespace_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"admission_identity","type":"text","nullable":false,"default_expression":null},{"name":"operation_identity","type":"text","nullable":false,"default_expression":null},{"name":"evidence_identity","type":"text","nullable":false,"default_expression":null},{"name":"slot","type":"text","nullable":false,"default_expression":null},{"name":"kind","type":"text","nullable":false,"default_expression":null},{"name":"attempt_identity","type":"text","nullable":true,"default_expression":null},{"name":"canonical_evidence","type":"bytea","nullable":false,"default_expression":null},{"name":"observed_at_milliseconds","type":"int8","nullable":false,"default_expression":null}],"constraints":[{"kind":"CHECK","expression":"octet_length(tenant_id) BETWEEN 1 AND 128","referenced_columns":["tenant_id"]},{"kind":"CHECK","expression":"octet_length(repository_id) BETWEEN 1 AND 128","referenced_columns":["repository_id"]},{"kind":"CHECK","expression":"octet_length(review_run_id) BETWEEN 1 AND 128","referenced_columns":["review_run_id"]},{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["namespace_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["admission_identity"]},{"kind":"CHECK","expression":"operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["operation_identity"]},{"kind":"CHECK","expression":"evidence_identity ~ '^[0-9a-f]{64}$' AND evidence_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["evidence_identity"]},{"kind":"CHECK","expression":"octet_length(slot) BETWEEN 1 AND 80","referenced_columns":["slot"]},{"kind":"CHECK","expression":"kind IN ('response', 'unknown', 'fence', 'verification', 'candidate', 'published')","referenced_columns":["kind"]},{"kind":"CHECK","expression":"attempt_identity IS NULL OR (attempt_identity ~ '^[0-9a-f]{64}$' AND attempt_identity <> '0000000000000000000000000000000000000000000000000000000000000000')","referenced_columns":["attempt_identity"]},{"kind":"CHECK","expression":"octet_length(canonical_evidence) BETWEEN 1 AND 1048576","referenced_columns":["canonical_evidence"]},{"kind":"CHECK","expression":"observed_at_milliseconds BETWEEN 1 AND 253402300799999","referenced_columns":["observed_at_milliseconds"]},{"kind":"CHECK","expression":"(kind = 'response' AND attempt_identity IS NOT NULL AND slot = 'response:' || attempt_identity) OR (kind = 'unknown' AND attempt_identity IS NOT NULL AND slot = 'unknown:' || attempt_identity) OR (kind = 'fence' AND attempt_identity IS NULL AND slot = 'fence') OR (kind = 'verification' AND attempt_identity IS NULL AND slot ~ '^verification:[0-9a-f]{64}$') OR (kind = 'candidate' AND attempt_identity IS NULL AND slot = 'candidate') OR (kind = 'published' AND attempt_identity IS NULL AND slot = 'published')","referenced_columns":["slot","kind","attempt_identity"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","slot"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","evidence_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"],"target_table":"open_trestle_artifact_erasure_operations","target_columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","attempt_identity"],"target_table":"open_trestle_erasure_attempts","target_columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","attempt_identity"]}],"indexes":[{"name":"open_trestle_erasure_attempt_evidence_pkey","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","slot"],"unique":true,"primary":true},{"name":"open_trestle_erasure_attempt_evidence_u1","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","evidence_identity"],"unique":true,"primary":false},{"name":"open_trestle_erasure_attempt_evidence_attempt_scan","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","attempt_identity","slot"],"unique":false,"primary":false}]}}`
const resumeConstraintNamesJSON = `{"open_trestle_erasure_resume_allowances":["open_trestle_erasure_resume_allowances_c01","open_trestle_erasure_resume_allowances_c02","open_trestle_erasure_resume_allowances_c03","open_trestle_erasure_resume_allowances_c04","open_trestle_erasure_resume_allowances_c05","open_trestle_erasure_resume_allowances_c06","open_trestle_erasure_resume_allowances_c07","open_trestle_erasure_resume_allowances_c08","open_trestle_erasure_resume_allowances_c09","open_trestle_erasure_resume_allowances_c10","open_trestle_erasure_resume_allowances_c11","open_trestle_erasure_resume_allowances_c12","open_trestle_erasure_resume_allowances_c13","open_trestle_erasure_resume_allowances_c14","open_trestle_erasure_resume_allowances_c15","open_trestle_erasure_resume_allowances_c16","open_trestle_erasure_resume_allowances_c17","open_trestle_erasure_resume_allowances_c18","open_trestle_erasure_resume_allowances_c19","open_trestle_erasure_resume_allowances_c20","open_trestle_erasure_resume_allowances_c21","open_trestle_erasure_resume_allowances_c22","open_trestle_erasure_resume_allowances_c23","open_trestle_erasure_resume_allowances_c24","open_trestle_erasure_resume_allowances_c25","open_trestle_erasure_resume_allowances_c26","open_trestle_erasure_resume_allowances_c27","open_trestle_erasure_resume_allowances_c28","open_trestle_erasure_resume_allowances_c29","open_trestle_erasure_resume_allowances_c30","open_trestle_erasure_resume_allowances_c31","open_trestle_erasure_resume_allowances_c32","open_trestle_erasure_resume_allowances_c33","open_trestle_erasure_resume_allowances_c34","open_trestle_erasure_resume_allowances_c35","open_trestle_erasure_resume_allowances_c36","open_trestle_erasure_resume_allowances_x01","open_trestle_erasure_resume_allowances_x02","open_trestle_erasure_resume_allowances_x03","open_trestle_erasure_resume_allowances_x04","open_trestle_erasure_resume_allowances_x05","open_trestle_erasure_resume_allowances_x06","open_trestle_erasure_resume_allowances_pkey","open_trestle_erasure_resume_allowances_u1","open_trestle_erasure_resume_allowances_f1"],"open_trestle_erasure_attempts":["open_trestle_erasure_attempts_c01","open_trestle_erasure_attempts_c02","open_trestle_erasure_attempts_c03","open_trestle_erasure_attempts_c04","open_trestle_erasure_attempts_c05","open_trestle_erasure_attempts_c06","open_trestle_erasure_attempts_c07","open_trestle_erasure_attempts_c08","open_trestle_erasure_attempts_c09","open_trestle_erasure_attempts_c10","open_trestle_erasure_attempts_c11","open_trestle_erasure_attempts_c12","open_trestle_erasure_attempts_c13","open_trestle_erasure_attempts_c14","open_trestle_erasure_attempts_c15","open_trestle_erasure_attempts_c16","open_trestle_erasure_attempts_c17","open_trestle_erasure_attempts_c18","open_trestle_erasure_attempts_c19","open_trestle_erasure_attempts_c20","open_trestle_erasure_attempts_c21","open_trestle_erasure_attempts_c22","open_trestle_erasure_attempts_c23","open_trestle_erasure_attempts_c24","open_trestle_erasure_attempts_c25","open_trestle_erasure_attempts_c26","open_trestle_erasure_attempts_c27","open_trestle_erasure_attempts_x01","open_trestle_erasure_attempts_x02","open_trestle_erasure_attempts_x03","open_trestle_erasure_attempts_x04","open_trestle_erasure_attempts_x05","open_trestle_erasure_attempts_pkey","open_trestle_erasure_attempts_u1","open_trestle_erasure_attempts_u2","open_trestle_erasure_attempts_u3","open_trestle_erasure_attempts_f1","open_trestle_erasure_attempts_f2"],"open_trestle_erasure_attempt_evidence":["open_trestle_erasure_attempt_evidence_c01","open_trestle_erasure_attempt_evidence_c02","open_trestle_erasure_attempt_evidence_c03","open_trestle_erasure_attempt_evidence_c04","open_trestle_erasure_attempt_evidence_c05","open_trestle_erasure_attempt_evidence_c06","open_trestle_erasure_attempt_evidence_c07","open_trestle_erasure_attempt_evidence_c08","open_trestle_erasure_attempt_evidence_c09","open_trestle_erasure_attempt_evidence_c10","open_trestle_erasure_attempt_evidence_c11","open_trestle_erasure_attempt_evidence_c12","open_trestle_erasure_attempt_evidence_c13","open_trestle_erasure_attempt_evidence_c14","open_trestle_erasure_attempt_evidence_x01","open_trestle_erasure_attempt_evidence_pkey","open_trestle_erasure_attempt_evidence_u1","open_trestle_erasure_attempt_evidence_f1","open_trestle_erasure_attempt_evidence_f2"]}`
const resumeMigrationDescriptorSQL = `CREATE TABLE open_trestle_erasure_resume_allowances (
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

CREATE POLICY open_trestle_erasure_attempt_evidence_tenant_isolation ON open_trestle_erasure_attempt_evidence AS PERMISSIVE FOR ALL TO PUBLIC USING (tenant_id = current_setting('open_trestle.tenant_id', true)) WITH CHECK (tenant_id = current_setting('open_trestle.tenant_id', true));`

func resumeFixtureRegistry(t *testing.T) map[string]erasureStatement {
	t.Helper()
	var out map[string]erasureStatement
	if err := json.Unmarshal([]byte(resumeRegistryJSON), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 46 {
		t.Fatal("statement inventory")
	}
	for _, st := range out {
		if len(st.Parameters) > 64 || len(st.Columns) > 64 {
			t.Fatal("typed statement bounds")
		}
	}
	return out
}
func newResumeCatalog(t *testing.T) erasureCatalog {
	t.Helper()
	c := newErasureCatalog(t)
	var tables map[string]erasureTableDescriptor
	var names map[string][]string
	if err := json.Unmarshal([]byte(resumeDescriptorJSON), &tables); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(resumeConstraintNamesJSON), &names); err != nil {
		t.Fatal(err)
	}
	for i, name := range resumeNewTableNames {
		c.Tables[name] = tables[name]
		c.OIDs[name] = int64(28001 + i)
	}
	for i, name := range resumeNewTableNames {
		oid, d := c.OIDs[name], c.Tables[name]
		c.Rows[erasureCatalogKey("relation", oid)] = [][]driver.Value{{oid, int64(2200), c.Schema, name, "r", true, true, oid}}
		for n, col := range d.Columns {
			typ := map[string]int64{"text": 25, "bytea": 17, "int8": 20}[col.Type]
			c.Rows[erasureCatalogKey("attributes", oid)] = append(c.Rows[erasureCatalogKey("attributes", oid)], []driver.Value{int64(n + 1), col.Name, typ, "pg_catalog", col.Type, int64(-1), !col.Nullable, false, "", "", nil})
		}
		for n, k := range d.Constraints {
			kind := map[string]string{"CHECK": "c", "PRIMARY KEY": "p", "UNIQUE": "u", "FOREIGN KEY": "f"}[k.Kind]
			cols := k.Columns
			var expr driver.Value
			foreign, fc, match, update, remove := int64(0), "", "", "", ""
			if kind == "c" {
				cols = k.Referenced
				expr = k.Expression
			}
			if kind == "f" {
				foreign = c.OIDs[k.Target]
				fc = erasureAttnums(c.Tables[k.Target], k.TargetColumns, ",")
				match, update, remove = "s", "a", "a"
			}
			key := erasureCatalogKey("constraints", oid)
			c.Rows[key] = append(c.Rows[key], []driver.Value{int64(30000 + i*100 + n), names[name][n], kind, true, false, false, true, int64(0), erasureAttnums(d, cols, ","), foreign, fc, match, update, remove, expr})
		}
		for n, k := range d.Indexes {
			zeros := make([]string, len(k.Columns))
			for j := range zeros {
				zeros[j] = "0"
			}
			key := erasureCatalogKey("indexes", oid)
			c.Rows[key] = append(c.Rows[key], []driver.Value{int64(31000 + i*100 + n), k.Name, "btree", k.Primary, k.Unique, true, true, true, true, int64(len(k.Columns)), int64(len(k.Columns)), erasureAttnums(d, k.Columns, " "), strings.Join(zeros, " "), nil, nil})
		}
		for _, query := range []string{"constraints", "indexes"} {
			key := erasureCatalogKey(query, oid)
			sort.Slice(c.Rows[key], func(a, b int) bool { return c.Rows[key][a][1].(string) < c.Rows[key][b][1].(string) })
		}
		c.Rows[erasureCatalogKey("policies", oid)] = [][]driver.Value{{int64(33000 + i), name + "_tenant_isolation", "*", true, "0", "tenant_id = current_setting('open_trestle.tenant_id', true)", "tenant_id = current_setting('open_trestle.tenant_id', true)"}}
		c.Rows[erasureCatalogKey("table_privileges", oid)] = [][]driver.Value{{true, true, true, false, false, false, name == resumeAllowances}}
	}
	yes, no := make([]driver.Value, 11), make([]driver.Value, 25)
	for i := range yes {
		yes[i] = true
	}
	for i := range no {
		no[i] = false
	}
	c.Rows[erasureCatalogKey("allowance_counter_privileges", c.OIDs[resumeAllowances])] = [][]driver.Value{yes}
	c.Rows[erasureCatalogKey("allowance_immutable_privileges", c.OIDs[resumeAllowances])] = [][]driver.Value{no}
	for _, name := range resumeFixtureTableNames {
		c.Rows["trigger_inventory"] = append(c.Rows["trigger_inventory"], []driver.Value{c.OIDs[name], true, "O", true})
	}
	if len(c.Rows["migration_rows"]) != 13 {
		t.Fatal("current catalog must include thirteen migration rows")
	}
	return c
}
func resumeVerifyCatalog(t *testing.T, c erasureCatalog, fault *resumeFixtureSQLFault) (*resumeFixtureSQLService, *ArtifactIndex, VerifiedBudgetedErasureIndex, error) {
	t.Helper()
	s := newResumeSQLService(t, c)
	index, err := NewArtifactIndex(s.OpenDB(t, "schema"))
	if err != nil {
		t.Fatal(err)
	}
	if fault != nil {
		if err := s.Inject(*fault); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := resumeFixtureOperationContext(t, "verify")
	defer cancel()
	w, err := VerifyBudgetedErasureIndex(ctx, index)
	s.AssertClean(t)
	return s, index, w, err
}
func TestResumeVerifierOneSnapshotAndUserTriggers(t *testing.T) {
	c := newResumeCatalog(t)
	s, _, w, err := resumeVerifyCatalog(t, c, nil)
	if err != nil || reflect.DeepEqual(w, VerifiedBudgetedErasureIndex{}) {
		t.Fatal("valid catalog", err)
	}
	var tx uint64
	seen := map[int64]bool{}
	commits := 0
	for _, e := range s.Snapshot().Events {
		if e.Kind == "begin" {
			if tx != 0 || e.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || !e.ReadOnly {
				t.Fatal("verifier snapshot")
			}
			tx = e.TransactionID
		}
		if e.TransactionID != tx {
			t.Fatal("spliced snapshots")
		}
		if e.StatementID == "user_triggers" {
			seen[e.Arguments[0].(int64)] = true
		}
		if e.StatementID == "COMMIT" && e.ReplyKnown {
			commits++
		}
	}
	if commits != 1 || len(seen) != 9 {
		t.Fatal("missing known commit or trigger observation")
	}
	for _, oid := range c.OIDs {
		if !seen[oid] {
			t.Fatal("trigger check used an unvalidated relation OID")
		}
	}
	for _, table := range resumeFixtureTableNames {
		for _, mode := range []string{"ordinary", "disabled", "constraint", "missing", "extra", "null", "text"} {
			t.Run(table+"/"+mode, func(t *testing.T) {
				c := newResumeCatalog(t)
				key := erasureCatalogKey("user_triggers", c.OIDs[table])
				switch mode {
				case "ordinary", "disabled", "constraint":
					enabled := "O"
					if mode == "disabled" {
						enabled = "D"
					}
					c.Rows["trigger_inventory"] = append(c.Rows["trigger_inventory"], []driver.Value{c.OIDs[table], false, enabled, mode == "constraint"})
				case "missing":
					c.Rows[key] = nil
				case "extra":
					c.Rows[key] = [][]driver.Value{{false}, {false}}
				case "null":
					c.Rows[key] = [][]driver.Value{{nil}}
				case "text":
					c.Rows[key] = [][]driver.Value{{"false"}}
				}
				_, _, w, err := resumeVerifyCatalog(t, c, nil)
				if err == nil || !reflect.DeepEqual(w, VerifiedBudgetedErasureIndex{}) {
					t.Fatal("trigger observation accepted")
				}
			})
		}
	}
	for _, point := range []string{"user_triggers", "COMMIT"} {
		t.Run(point+"/failure", func(t *testing.T) {
			_, _, w, err := resumeVerifyCatalog(t, newResumeCatalog(t), &resumeFixtureSQLFault{StatementID: point, Occurrence: 1, Err: io.EOF})
			if err == nil || !reflect.DeepEqual(w, VerifiedBudgetedErasureIndex{}) {
				t.Fatal("failed snapshot released witness")
			}
		})
	}
}
func TestResumeVerifierRejectsEveryDescriptorMutation(t *testing.T) {
	base := newResumeCatalog(t)
	for _, table := range resumeNewTableNames {
		for _, query := range []string{"relation", "attributes", "constraints", "indexes", "policies", "table_privileges"} {
			rows := base.Rows[erasureCatalogKey(query, base.OIDs[table])]
			for n, row := range rows {
				for field := range row {
					t.Run(fmt.Sprintf("%s/%s/%d/%d", table, query, n, field), func(t *testing.T) {
						c := newResumeCatalog(t)
						key := erasureCatalogKey(query, c.OIDs[table])
						r := c.Rows[key][n]
						// NULL violates each typed field or changes an explicitly absent expression.
						if r[field] == nil {
							r[field] = "true"
						} else {
							r[field] = nil
						}
						_, _, w, err := resumeVerifyCatalog(t, c, nil)
						if err == nil || !reflect.DeepEqual(w, VerifiedBudgetedErasureIndex{}) {
							t.Fatal("changed descriptor accepted")
						}
					})
				}
			}
			t.Run(table+"/"+query+"/extra", func(t *testing.T) {
				c := newResumeCatalog(t)
				key := erasureCatalogKey(query, c.OIDs[table])
				c.Rows[key] = append(c.Rows[key], resumeFixtureCopyRows(c.Rows[key][:1])...)
				_, _, w, err := resumeVerifyCatalog(t, c, nil)
				if err == nil || !reflect.DeepEqual(w, VerifiedBudgetedErasureIndex{}) {
					t.Fatal("duplicate descriptor accepted")
				}
			})
		}
	}
	for _, q := range []string{"allowance_counter_privileges", "allowance_immutable_privileges"} {
		rows := base.Rows[erasureCatalogKey(q, base.OIDs[resumeAllowances])]
		for col := range rows[0] {
			t.Run(q+"/"+strconv.Itoa(col), func(t *testing.T) {
				c := newResumeCatalog(t)
				r := c.Rows[erasureCatalogKey(q, c.OIDs[resumeAllowances])][0]
				r[col] = !r[col].(bool)
				_, _, w, err := resumeVerifyCatalog(t, c, nil)
				if err == nil || !reflect.DeepEqual(w, VerifiedBudgetedErasureIndex{}) {
					t.Fatal("column grant accepted")
				}
			})
		}
	}
}
func TestResumeNormalThirteenRegistry(t *testing.T) {
	if len(orderedMigrations) != 13 || orderedMigrations[12] != "migrations/0013_artifact_erasure_resume.sql" {
		t.Fatal("normal migration registry")
	}
	for i, pin := range erasureOldMigrations {
		if orderedMigrations[i] != pin.Name {
			t.Fatal("migration prefix")
		}
		raw, err := migrationFiles.ReadFile(pin.Name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != pin.Hash {
			t.Fatal("historical SQL changed")
		}
	}
	raw, err := migrationFiles.ReadFile("migrations/0012_artifact_erasure.sql")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "01ae7b861f99db41ca438b44e4e5989aa61bec32f5515d381f1798e30fe06713" {
		t.Fatal("0012 changed")
	}
	for _, mode := range []string{"only twelve", "wrong thirteen", "duplicate thirteen", "out of order", "wrong earlier"} {
		t.Run(mode, func(t *testing.T) {
			c := newResumeCatalog(t)
			rows := c.Rows["migration_rows"]
			switch mode {
			case "only twelve":
				rows = rows[:12]
			case "wrong thirteen":
				rows[12][1] = strings.Repeat("f", 64)
			case "duplicate thirteen":
				rows = append(rows, rows[12])
			case "out of order":
				rows[11], rows[12] = rows[12], rows[11]
			case "wrong earlier":
				rows[0][1] = strings.Repeat("f", 64)
			}
			c.Rows["migration_rows"] = rows
			_, _, w, err := resumeVerifyCatalog(t, c, nil)
			if !errors.Is(err, ErrMigrationConflict) || !reflect.DeepEqual(w, VerifiedBudgetedErasureIndex{}) {
				t.Fatal("migration conflict", err)
			}
		})
	}
	raw, err = migrationFiles.ReadFile(orderedMigrations[12])
	if err != nil {
		t.Fatal(err)
	}
	// Parse complete DDL tokens rather than a loose SQL pattern.
	got, err := resumeDDLTokens(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	want, err := resumeDDLTokens(resumeMigrationDescriptorSQL)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("0013 differs from exact table, constraint, index and tenant-policy descriptors")
	}
}
func resumeDDLTokens(s string) ([]string, error) {
	var out []string
	for i := 0; i < len(s); {
		if strings.ContainsRune(" \t\r\n", rune(s[i])) {
			i++
			continue
		}
		if strings.HasPrefix(s[i:], "--") {
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				break
			}
			i += j + 1
			continue
		}
		if strings.HasPrefix(s[i:], "/*") {
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				return nil, errors.New("DDL comment")
			}
			i += j + 4
			continue
		}
		j := i + 1
		if s[i] == '\'' {
			for j < len(s) {
				if s[j] == '\'' {
					j++
					if j < len(s) && s[j] == '\'' {
						j++
						continue
					}
					break
				}
				j++
			}
			if j > len(s) || s[j-1] != '\'' {
				return nil, errors.New("DDL string")
			}
		} else if (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') || s[i] == '_' || (s[i] >= '0' && s[i] <= '9') {
			for j < len(s) && ((s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= '0' && s[j] <= '9') || s[j] == '_') {
				j++
			}
		}
		token := s[i:j]
		if s[i] != '\'' {
			token = strings.ToLower(token)
		}
		out = append(out, token)
		i = j
		if len(out) > 32768 {
			return nil, errors.New("DDL token bound")
		}
	}
	return out, nil
}

func TestResumeVerifierExpressionStructureAndDiscoveredOIDs(t *testing.T) {
	for _, mode := range []string{"parentheses", "extra branch", "renumbered"} {
		t.Run(mode, func(t *testing.T) {
			c := newResumeCatalog(t)
			if mode == "renumbered" {
				mapping := map[int64]int64{}
				for table, oid := range c.OIDs {
					mapping[oid] = oid + 70000
					c.OIDs[table] = oid + 70000
				}
				rows := map[string][][]driver.Value{}
				for key, values := range c.Rows {
					values = resumeFixtureCopyRows(values)
					parts := strings.Split(key, ":")
					newKey := key
					if len(parts) == 2 {
						oid, err := strconv.ParseInt(parts[1], 10, 64)
						if err != nil {
							t.Fatal(err)
						}
						newKey = erasureCatalogKey(parts[0], mapping[oid])
					}
					switch parts[0] {
					case "relation":
						for _, r := range values {
							r[0] = mapping[r[0].(int64)]
							r[1] = int64(72000)
							r[7] = mapping[r[7].(int64)]
						}
					case "constraints":
						for _, r := range values {
							r[0] = r[0].(int64) + 70000
							if r[9].(int64) != 0 {
								r[9] = mapping[r[9].(int64)]
							}
						}
					case "indexes", "policies":
						for _, r := range values {
							r[0] = r[0].(int64) + 70000
						}
					case "trigger_inventory":
						for _, r := range values {
							r[0] = mapping[r[0].(int64)]
						}
					}
					rows[newKey] = values
				}
				c.Rows = rows
			} else {
				for _, table := range resumeNewTableNames {
					key := erasureCatalogKey("constraints", c.OIDs[table])
					for _, row := range c.Rows[key] {
						if row[2] == "c" {
							row[14] = "((" + row[14].(string) + "))"
							if mode == "extra branch" {
								row[14] = row[14].(string) + " OR true"
							}
						}
					}
				}
			}
			_, _, w, err := resumeVerifyCatalog(t, c, nil)
			if mode == "extra branch" {
				if err == nil || !reflect.DeepEqual(w, VerifiedBudgetedErasureIndex{}) {
					t.Fatal("extra expression branch accepted")
				}
			} else if err != nil || reflect.DeepEqual(w, VerifiedBudgetedErasureIndex{}) {
				t.Fatal("equivalent catalog refused", err)
			}
		})
	}
}
