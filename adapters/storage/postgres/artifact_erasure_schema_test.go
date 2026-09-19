package postgres

import (
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"time"

	"github.com/georgejieh/open-trestle/adapters/keys/awskms"
	"github.com/georgejieh/open-trestle/adapters/storage/s3"
	"github.com/georgejieh/open-trestle/artifact"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type erasureStatement struct {
	SQL        string   `json:"sql"`
	Parameters []string `json:"parameters"`
	Columns    []string `json:"columns"`
}
type erasureColumn struct {
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Nullable bool    `json:"nullable"`
	Default  *string `json:"default_expression"`
}
type erasureConstraint struct {
	Kind          string   `json:"kind"`
	Columns       []string `json:"columns"`
	Target        string   `json:"target_table"`
	TargetColumns []string `json:"target_columns"`
	Expression    string   `json:"expression"`
	Referenced    []string `json:"referenced_columns"`
}
type erasureIndexDescriptor struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
	Unique  bool     `json:"unique"`
	Primary bool     `json:"primary"`
}
type erasureTableDescriptor struct {
	Columns     []erasureColumn          `json:"columns"`
	Constraints []erasureConstraint      `json:"constraints"`
	Indexes     []erasureIndexDescriptor `json:"indexes"`
}
type erasureCatalog struct {
	Rows                              map[string][][]driver.Value
	Tables                            map[string]erasureTableDescriptor
	OIDs                              map[string]int64
	Database, Schema, Role, Namespace string
}

const erasureRegistryJSON = `{"authority_schemas":{"sql":"SELECT pg_catalog.current_schema(), (SELECT n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = pg_catalog.to_regclass('open_trestle_schema_migrations')), (SELECT n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = pg_catalog.to_regclass('open_trestle_database_authority'))","parameters":[],"columns":["current_schema:string","migrations_schema:string|NULL","authority_schema:string|NULL"]},"authority_identity":{"sql":"SELECT pg_catalog.current_database(), pg_catalog.current_schema(), CURRENT_USER, database_namespace_id::text FROM open_trestle_database_authority WHERE singleton = true","parameters":[],"columns":["database_name:string","schema_name:string","role_name:string","database_namespace_id:string"]},"migration_rows":{"sql":"SELECT version, checksum FROM open_trestle_schema_migrations ORDER BY version ASC","parameters":[],"columns":["version:int64","checksum:string"]},"artifact_lock":{"sql":"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))","parameters":["common_key:string"],"columns":[]},"scope_insert":{"sql":"INSERT INTO open_trestle_review_scopes (tenant_id, repository_id, review_run_id, scope_identity) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING","parameters":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string"],"columns":[]},"scope_read":{"sql":"SELECT scope_identity FROM open_trestle_review_scopes WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3","parameters":["tenant_id:string","repository_id:string","review_run_id:string"],"columns":["scope_identity:string"]},"metadata_insert":{"sql":"INSERT INTO open_trestle_artifacts (tenant_id, repository_id, review_run_id, scope_identity, artifact_identity, payload_digest, kind, classification, origin, protection, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)","parameters":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","artifact_identity:string","payload_digest:string","kind:string","classification:string","origin:string","protection:string","created_at:time.Time","expires_at:time.Time"],"columns":[]},"metadata_read":{"sql":"SELECT payload_digest, kind, classification, origin, protection, created_at, expires_at FROM open_trestle_artifacts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4","parameters":["tenant_id:string","repository_id:string","review_run_id:string","artifact_identity:string"],"columns":["payload_digest:string","kind:string","classification:string","origin:string","protection:string","created_at:time.Time","expires_at:time.Time"]},"tenant_guc":{"sql":"SELECT set_config('open_trestle.tenant_id', $1, true)","parameters":["tenant_id:string"],"columns":[]},"key_occupancy":{"sql":"SELECT namespace_identity, admission_identity FROM open_trestle_artifact_admissions WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4","parameters":["tenant_id:string","repository_id:string","review_run_id:string","artifact_identity:string"],"columns":["namespace_identity:string","admission_identity:string"]},"legacy_lineage":{"sql":"SELECT EXISTS (SELECT 1 FROM open_trestle_artifact_deletion_authorizations WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4), EXISTS (SELECT 1 FROM open_trestle_artifact_deletion_receipts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4)","parameters":["tenant_id:string","repository_id:string","review_run_id:string","artifact_identity:string"],"columns":["has_authorization:bool","has_receipt:bool"]},"admission_read":{"sql":"SELECT a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_admissions AS a LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE a.tenant_id = $1 AND a.repository_id = $2 AND a.review_run_id = $3 AND a.namespace_identity = $4 AND a.artifact_identity = $5","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","artifact_identity:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","canonical_admission:[]byte","canonical_namespace:[]byte","admitted_policy:[]byte","database_authority_identity:string","admitted_policy_identity:string","admitted_at_milliseconds:int64","confirmed_version:string|NULL","confirmed_ciphertext_digest:string|NULL","confirmed_at_milliseconds:int64|NULL","joined_scope_identity:string|NULL","metadata_scope_identity:string|NULL","metadata_artifact_identity:string|NULL","metadata_payload_digest:string|NULL","metadata_kind:string|NULL","metadata_classification:string|NULL","metadata_origin:string|NULL","metadata_protection:string|NULL","metadata_created_at:time.Time|NULL","metadata_expires_at:time.Time|NULL"]},"admission_lock_read":{"sql":"SELECT a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_admissions AS a LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE a.tenant_id = $1 AND a.repository_id = $2 AND a.review_run_id = $3 AND a.namespace_identity = $4 AND a.artifact_identity = $5 FOR UPDATE OF a","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","artifact_identity:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","canonical_admission:[]byte","canonical_namespace:[]byte","admitted_policy:[]byte","database_authority_identity:string","admitted_policy_identity:string","admitted_at_milliseconds:int64","confirmed_version:string|NULL","confirmed_ciphertext_digest:string|NULL","confirmed_at_milliseconds:int64|NULL","joined_scope_identity:string|NULL","metadata_scope_identity:string|NULL","metadata_artifact_identity:string|NULL","metadata_payload_digest:string|NULL","metadata_kind:string|NULL","metadata_classification:string|NULL","metadata_origin:string|NULL","metadata_protection:string|NULL","metadata_created_at:time.Time|NULL","metadata_expires_at:time.Time|NULL"]},"admission_insert":{"sql":"INSERT INTO open_trestle_artifact_admissions (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, canonical_admission, canonical_namespace, admitted_policy, database_authority_identity, admitted_policy_identity, admitted_at_milliseconds, confirmed_version, confirmed_ciphertext_digest, confirmed_at_milliseconds) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULL, NULL, NULL)","parameters":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","canonical_admission:[]byte","canonical_namespace:[]byte","admitted_policy:[]byte","database_authority_identity:string","admitted_policy_identity:string","admitted_at_milliseconds:int64"],"columns":[]},"operation_presence":{"sql":"SELECT operation_identity FROM open_trestle_artifact_erasure_operations WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND artifact_identity = $5","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","artifact_identity:string"],"columns":["operation_identity:string"]},"confirmation_cas":{"sql":"UPDATE open_trestle_artifact_admissions AS a SET confirmed_version = $8, confirmed_ciphertext_digest = $9, confirmed_at_milliseconds = $10 WHERE a.tenant_id = $1 AND a.repository_id = $2 AND a.review_run_id = $3 AND a.scope_identity = $4 AND a.namespace_identity = $5 AND a.artifact_identity = $6 AND a.admission_identity = $7 AND a.confirmed_version IS NULL AND a.confirmed_ciphertext_digest IS NULL AND a.confirmed_at_milliseconds IS NULL AND NOT EXISTS (SELECT 1 FROM open_trestle_artifact_erasure_operations AS o WHERE o.tenant_id = a.tenant_id AND o.repository_id = a.repository_id AND o.review_run_id = a.review_run_id AND o.namespace_identity = a.namespace_identity AND o.artifact_identity = a.artifact_identity)","parameters":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","confirmed_version:string","confirmed_ciphertext_digest:string","confirmed_at_milliseconds:int64"],"columns":[]},"operation_insert":{"sql":"INSERT INTO open_trestle_artifact_erasure_operations (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, canonical_operation, canonical_authorization, accepted_policy, authorization_identity, authorization_document_digest, protected_policy_identity, database_authority_identity, prepared_at_milliseconds, accepted_at_milliseconds) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)","parameters":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","canonical_operation:[]byte","canonical_authorization:[]byte","accepted_policy:[]byte","authorization_identity:string","authorization_document_digest:string","protected_policy_identity:string","database_authority_identity:string","prepared_at_milliseconds:int64","accepted_at_milliseconds:int64"],"columns":[]},"operation_read":{"sql":"SELECT o.tenant_id, o.repository_id, o.review_run_id, o.scope_identity, o.namespace_identity, o.artifact_identity, o.admission_identity, o.operation_identity, o.canonical_operation, o.canonical_authorization, o.accepted_policy, o.authorization_identity, o.authorization_document_digest, o.protected_policy_identity, o.database_authority_identity, o.prepared_at_milliseconds, o.accepted_at_milliseconds, a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_erasure_operations AS o LEFT JOIN open_trestle_artifact_admissions AS a ON a.tenant_id = o.tenant_id AND a.repository_id = o.repository_id AND a.review_run_id = o.review_run_id AND a.scope_identity = o.scope_identity AND a.namespace_identity = o.namespace_identity AND a.artifact_identity = o.artifact_identity AND a.admission_identity = o.admission_identity LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE o.tenant_id = $1 AND o.repository_id = $2 AND o.review_run_id = $3 AND o.namespace_identity = $4 AND o.artifact_identity = $5","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","artifact_identity:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","canonical_operation:[]byte","canonical_authorization:[]byte","accepted_policy:[]byte","authorization_identity:string","authorization_document_digest:string","protected_policy_identity:string","database_authority_identity:string","prepared_at_milliseconds:int64","accepted_at_milliseconds:int64","admission.tenant_id:string|NULL","admission.repository_id:string|NULL","admission.review_run_id:string|NULL","admission.scope_identity:string|NULL","admission.namespace_identity:string|NULL","admission.artifact_identity:string|NULL","admission.admission_identity:string|NULL","admission.canonical_admission:[]byte|NULL","admission.canonical_namespace:[]byte|NULL","admission.admitted_policy:[]byte|NULL","admission.database_authority_identity:string|NULL","admission.admitted_policy_identity:string|NULL","admission.admitted_at_milliseconds:int64|NULL","admission.confirmed_version:string|NULL","admission.confirmed_ciphertext_digest:string|NULL","admission.confirmed_at_milliseconds:int64|NULL","joined_scope_identity:string|NULL","metadata_scope_identity:string|NULL","metadata_artifact_identity:string|NULL","metadata_payload_digest:string|NULL","metadata_kind:string|NULL","metadata_classification:string|NULL","metadata_origin:string|NULL","metadata_protection:string|NULL","metadata_created_at:time.Time|NULL","metadata_expires_at:time.Time|NULL"]},"operation_ref_read":{"sql":"SELECT o.tenant_id, o.repository_id, o.review_run_id, o.scope_identity, o.namespace_identity, o.artifact_identity, o.admission_identity, o.operation_identity, o.canonical_operation, o.canonical_authorization, o.accepted_policy, o.authorization_identity, o.authorization_document_digest, o.protected_policy_identity, o.database_authority_identity, o.prepared_at_milliseconds, o.accepted_at_milliseconds, a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_erasure_operations AS o LEFT JOIN open_trestle_artifact_admissions AS a ON a.tenant_id = o.tenant_id AND a.repository_id = o.repository_id AND a.review_run_id = o.review_run_id AND a.scope_identity = o.scope_identity AND a.namespace_identity = o.namespace_identity AND a.artifact_identity = o.artifact_identity AND a.admission_identity = o.admission_identity LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE o.tenant_id = $1 AND o.repository_id = $2 AND o.review_run_id = $3 AND o.namespace_identity = $4 AND o.operation_identity = $5","parameters":["tenant_id:string","repository_id:string","review_run_id:string","namespace_identity:string","operation_identity:string"],"columns":["tenant_id:string","repository_id:string","review_run_id:string","scope_identity:string","namespace_identity:string","artifact_identity:string","admission_identity:string","operation_identity:string","canonical_operation:[]byte","canonical_authorization:[]byte","accepted_policy:[]byte","authorization_identity:string","authorization_document_digest:string","protected_policy_identity:string","database_authority_identity:string","prepared_at_milliseconds:int64","accepted_at_milliseconds:int64","admission.tenant_id:string|NULL","admission.repository_id:string|NULL","admission.review_run_id:string|NULL","admission.scope_identity:string|NULL","admission.namespace_identity:string|NULL","admission.artifact_identity:string|NULL","admission.admission_identity:string|NULL","admission.canonical_admission:[]byte|NULL","admission.canonical_namespace:[]byte|NULL","admission.admitted_policy:[]byte|NULL","admission.database_authority_identity:string|NULL","admission.admitted_policy_identity:string|NULL","admission.admitted_at_milliseconds:int64|NULL","admission.confirmed_version:string|NULL","admission.confirmed_ciphertext_digest:string|NULL","admission.confirmed_at_milliseconds:int64|NULL","joined_scope_identity:string|NULL","metadata_scope_identity:string|NULL","metadata_artifact_identity:string|NULL","metadata_payload_digest:string|NULL","metadata_kind:string|NULL","metadata_classification:string|NULL","metadata_origin:string|NULL","metadata_protection:string|NULL","metadata_created_at:time.Time|NULL","metadata_expires_at:time.Time|NULL"]},"role":{"sql":"SELECT r.oid::bigint, r.rolname::text, r.rolsuper, r.rolbypassrls, pg_catalog.current_setting('row_security') FROM pg_catalog.pg_roles AS r WHERE r.rolname = CURRENT_USER","parameters":[],"columns":["role_oid:int64","role_name:string","rolsuper:bool","rolbypassrls:bool","row_security:string"]},"relation":{"sql":"SELECT c.oid::bigint, n.oid::bigint, n.nspname::text, c.relname::text, c.relkind::text, c.relrowsecurity, c.relforcerowsecurity, pg_catalog.to_regclass($2)::oid::bigint FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2","parameters":["authority_schema:string","relation_name:string"],"columns":["relation_oid:int64","schema_oid:int64","schema_name:string","relation_name:string","relkind:string","rls_enabled:bool","rls_forced:bool","unqualified_resolved_oid:int64|NULL"]},"attributes":{"sql":"SELECT a.attnum::bigint, a.attname::text, t.oid::bigint, tn.nspname::text, t.typname::text, a.atttypmod::bigint, a.attnotnull, a.attisdropped, a.attgenerated::text, a.attidentity::text, pg_catalog.pg_get_expr(d.adbin, d.adrelid, false) FROM pg_catalog.pg_attribute AS a JOIN pg_catalog.pg_type AS t ON t.oid = a.atttypid JOIN pg_catalog.pg_namespace AS tn ON tn.oid = t.typnamespace LEFT JOIN pg_catalog.pg_attrdef AS d ON d.adrelid = a.attrelid AND d.adnum = a.attnum WHERE a.attrelid = $1::oid AND a.attnum > 0 ORDER BY a.attnum ASC","parameters":["relation_oid:int64"],"columns":["attnum:int64","attname:string","type_oid:int64","type_schema:string","type_name:string","typmod:int64","not_null:bool","dropped:bool","generated:string","identity:string","default_expression:string|NULL"]},"constraints":{"sql":"SELECT c.oid::bigint, c.conname::text, c.contype::text, c.convalidated, c.condeferrable, c.condeferred, c.conislocal, c.coninhcount::bigint, COALESCE(pg_catalog.array_to_string(c.conkey, ','), ''), c.confrelid::bigint, COALESCE(pg_catalog.array_to_string(c.confkey, ','), ''), CASE WHEN c.contype = 'f' THEN c.confmatchtype::text ELSE '' END, CASE WHEN c.contype = 'f' THEN c.confupdtype::text ELSE '' END, CASE WHEN c.contype = 'f' THEN c.confdeltype::text ELSE '' END, pg_catalog.pg_get_expr(c.conbin, c.conrelid, false) FROM pg_catalog.pg_constraint AS c WHERE c.conrelid = $1::oid ORDER BY c.conname ASC","parameters":["relation_oid:int64"],"columns":["constraint_oid:int64","constraint_name:string","constraint_type:string","validated:bool","deferrable:bool","initially_deferred:bool","local:bool","inherit_count:int64","key_attnums:string","foreign_relation_oid:int64","foreign_attnums:string","match_type:string","update_action:string","delete_action:string","check_expression:string|NULL"]},"indexes":{"sql":"SELECT ic.oid::bigint, ic.relname::text, am.amname::text, i.indisprimary, i.indisunique, i.indisvalid, i.indisready, i.indislive, i.indimmediate, i.indnkeyatts::bigint, i.indnatts::bigint, i.indkey::text, i.indoption::text, pg_catalog.pg_get_expr(i.indexprs, i.indrelid, false), pg_catalog.pg_get_expr(i.indpred, i.indrelid, false) FROM pg_catalog.pg_index AS i JOIN pg_catalog.pg_class AS ic ON ic.oid = i.indexrelid JOIN pg_catalog.pg_am AS am ON am.oid = ic.relam WHERE i.indrelid = $1::oid ORDER BY ic.relname ASC","parameters":["relation_oid:int64"],"columns":["index_oid:int64","index_name:string","access_method:string","primary:bool","unique:bool","valid:bool","ready:bool","live:bool","immediate:bool","key_count:int64","attribute_count:int64","ordered_attnums:string","ordered_options:string","expression:string|NULL","predicate:string|NULL"]},"policies":{"sql":"SELECT p.oid::bigint, p.polname::text, p.polcmd::text, p.polpermissive, pg_catalog.array_to_string(p.polroles, ','), pg_catalog.pg_get_expr(p.polqual, p.polrelid, false), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid, false) FROM pg_catalog.pg_policy AS p WHERE p.polrelid = $1::oid ORDER BY p.polname ASC","parameters":["relation_oid:int64"],"columns":["policy_oid:int64","policy_name:string","command:string","permissive:bool","role_oids:string","using_expression:string|NULL","check_expression:string|NULL"]},"table_privileges":{"sql":"SELECT pg_catalog.has_schema_privilege($2, $3, 'USAGE'), pg_catalog.has_table_privilege($2, $1::oid, 'SELECT'), pg_catalog.has_table_privilege($2, $1::oid, 'INSERT'), pg_catalog.has_table_privilege($2, $1::oid, 'UPDATE'), pg_catalog.has_table_privilege($2, $1::oid, 'DELETE'), pg_catalog.has_table_privilege($2, $1::oid, 'TRUNCATE'), pg_catalog.has_any_column_privilege($2, $1::oid, 'UPDATE')","parameters":["relation_oid:int64","authority_role:string","authority_schema:string"],"columns":["schema_usage:bool","select:bool","insert:bool","update:bool","delete:bool","truncate:bool","any_column_update:bool"]},"confirmation_privileges":{"sql":"SELECT pg_catalog.has_column_privilege($2, $1::oid, 'confirmed_version', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'confirmed_ciphertext_digest', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'confirmed_at_milliseconds', 'UPDATE')","parameters":["admission_relation_oid:int64","authority_role:string"],"columns":["version_update:bool","digest_update:bool","time_update:bool"]}}`
const erasureDescriptorJSON = `{"open_trestle_review_scopes":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"registered_at","type":"timestamptz","nullable":false,"default_expression":"transaction_timestamp()"}],"constraints":[{"kind":"CHECK","expression":"octet_length(tenant_id) BETWEEN 1 AND 128","referenced_columns":["tenant_id"]},{"kind":"CHECK","expression":"octet_length(repository_id) BETWEEN 1 AND 128","referenced_columns":["repository_id"]},{"kind":"CHECK","expression":"octet_length(review_run_id) BETWEEN 1 AND 128","referenced_columns":["review_run_id"]},{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["scope_identity"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id"]},{"kind":"UNIQUE","columns":["scope_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","scope_identity"]}],"indexes":[{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id"],"unique":true,"primary":true,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["scope_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","scope_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"}],"flags":{"kind":"r","enable_rls":true,"force_rls":true},"policy":{"name":"<table>_tenant_isolation","command":"*","roles":[0],"permissive":true,"using":"tenant_id = current_setting('open_trestle.tenant_id', true)","with_check":"tenant_id = current_setting('open_trestle.tenant_id', true)"}},"open_trestle_artifacts":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"payload_digest","type":"text","nullable":false,"default_expression":null},{"name":"kind","type":"text","nullable":false,"default_expression":null},{"name":"classification","type":"text","nullable":false,"default_expression":null},{"name":"origin","type":"text","nullable":false,"default_expression":null},{"name":"protection","type":"text","nullable":false,"default_expression":null},{"name":"created_at","type":"timestamptz","nullable":false,"default_expression":null},{"name":"expires_at","type":"timestamptz","nullable":false,"default_expression":null},{"name":"registered_at","type":"timestamptz","nullable":false,"default_expression":"transaction_timestamp()"}],"constraints":[{"kind":"CHECK","expression":"octet_length(tenant_id) BETWEEN 1 AND 128","referenced_columns":["tenant_id"]},{"kind":"CHECK","expression":"octet_length(repository_id) BETWEEN 1 AND 128","referenced_columns":["repository_id"]},{"kind":"CHECK","expression":"octet_length(review_run_id) BETWEEN 1 AND 128","referenced_columns":["review_run_id"]},{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"payload_digest ~ '^[0-9a-f]{64}$'","referenced_columns":["payload_digest"]},{"kind":"CHECK","expression":"kind IN ('source_snapshot', 'change_model', 'deterministic_evidence', 'retrieval_result', 'context_packet', 'candidate_batch', 'verification_batch', 'verified_finding_set', 'publication_plan', 'run_export', 'task_input', 'webhook_delivery', 'source_file', 'publication_receipt', 'investigation_turn', 'investigation_tool_result')","referenced_columns":["kind"]},{"kind":"CHECK","expression":"classification IN ('public', 'internal', 'confidential', 'restricted')","referenced_columns":["classification"]},{"kind":"CHECK","expression":"origin IN ('host', 'repository', 'deterministic_tool', 'model', 'independent_verifier', 'policy', 'memory')","referenced_columns":["origin"]},{"kind":"CHECK","expression":"protection IN ('process_private', 'envelope_encrypted')","referenced_columns":["protection"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","artifact_identity"]},{"kind":"UNIQUE","columns":["scope_identity","artifact_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity"],"target_table":"open_trestle_review_scopes","target_columns":["tenant_id","repository_id","review_run_id","scope_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"},{"kind":"CHECK","expression":"expires_at > created_at","referenced_columns":["expires_at","created_at"]}],"indexes":[{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"unique":true,"primary":true,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["scope_identity","artifact_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"},{"name":"open_trestle_artifacts_expiry","columns":["tenant_id","repository_id","expires_at","artifact_identity"],"unique":false,"primary":false,"method":"btree","order":"ASC NULLS LAST"}],"flags":{"kind":"r","enable_rls":true,"force_rls":true},"policy":{"name":"<table>_tenant_isolation","command":"*","roles":[0],"permissive":true,"using":"tenant_id = current_setting('open_trestle.tenant_id', true)","with_check":"tenant_id = current_setting('open_trestle.tenant_id', true)"}},"open_trestle_artifact_deletion_authorizations":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"authorization_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"policy_identity","type":"text","nullable":false,"default_expression":null},{"name":"principal_identity","type":"text","nullable":false,"default_expression":null},{"name":"hold_clearance_identity","type":"text","nullable":false,"default_expression":null},{"name":"reason","type":"text","nullable":false,"default_expression":null},{"name":"issued_at","type":"timestamptz","nullable":false,"default_expression":null},{"name":"expires_at","type":"timestamptz","nullable":false,"default_expression":null},{"name":"registered_at","type":"timestamptz","nullable":false,"default_expression":"transaction_timestamp()"}],"constraints":[{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"authorization_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["authorization_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"policy_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["policy_identity"]},{"kind":"CHECK","expression":"hold_clearance_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["hold_clearance_identity"]},{"kind":"CHECK","expression":"octet_length(principal_identity) BETWEEN 1 AND 128","referenced_columns":["principal_identity"]},{"kind":"CHECK","expression":"reason IN ('expired', 'tenant_erasure', 'repository_erasure')","referenced_columns":["reason"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","authorization_identity"]},{"kind":"UNIQUE","columns":["scope_identity","authorization_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity"],"target_table":"open_trestle_review_scopes","target_columns":["tenant_id","repository_id","review_run_id","scope_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"target_table":"open_trestle_artifacts","target_columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"},{"kind":"CHECK","expression":"expires_at > issued_at","referenced_columns":["expires_at","issued_at"]}],"indexes":[{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","authorization_identity"],"unique":true,"primary":true,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["scope_identity","authorization_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"}],"flags":{"kind":"r","enable_rls":true,"force_rls":true},"policy":{"name":"<table>_tenant_isolation","command":"*","roles":[0],"permissive":true,"using":"tenant_id = current_setting('open_trestle.tenant_id', true)","with_check":"tenant_id = current_setting('open_trestle.tenant_id', true)"}},"open_trestle_artifact_deletion_receipts":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"receipt_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"payload_digest","type":"text","nullable":false,"default_expression":null},{"name":"authorization_identity","type":"text","nullable":false,"default_expression":null},{"name":"deleted_at","type":"timestamptz","nullable":false,"default_expression":null},{"name":"registered_at","type":"timestamptz","nullable":false,"default_expression":"transaction_timestamp()"}],"constraints":[{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"receipt_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["receipt_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"payload_digest ~ '^[0-9a-f]{64}$'","referenced_columns":["payload_digest"]},{"kind":"CHECK","expression":"authorization_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["authorization_identity"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","receipt_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","artifact_identity"]},{"kind":"UNIQUE","columns":["scope_identity","receipt_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity"],"target_table":"open_trestle_review_scopes","target_columns":["tenant_id","repository_id","review_run_id","scope_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"target_table":"open_trestle_artifacts","target_columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","authorization_identity"],"target_table":"open_trestle_artifact_deletion_authorizations","target_columns":["tenant_id","repository_id","review_run_id","authorization_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"}],"indexes":[{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","receipt_identity"],"unique":true,"primary":true,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["scope_identity","receipt_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"}],"flags":{"kind":"r","enable_rls":true,"force_rls":true},"policy":{"name":"<table>_tenant_isolation","command":"*","roles":[0],"permissive":true,"using":"tenant_id = current_setting('open_trestle.tenant_id', true)","with_check":"tenant_id = current_setting('open_trestle.tenant_id', true)"}},"open_trestle_artifact_admissions":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"namespace_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"admission_identity","type":"text","nullable":false,"default_expression":null},{"name":"canonical_admission","type":"bytea","nullable":false,"default_expression":null},{"name":"canonical_namespace","type":"bytea","nullable":false,"default_expression":null},{"name":"admitted_policy","type":"bytea","nullable":false,"default_expression":null},{"name":"database_authority_identity","type":"text","nullable":false,"default_expression":null},{"name":"admitted_policy_identity","type":"text","nullable":false,"default_expression":null},{"name":"admitted_at_milliseconds","type":"int8","nullable":false,"default_expression":null},{"name":"confirmed_version","type":"text","nullable":true,"default_expression":null},{"name":"confirmed_ciphertext_digest","type":"text","nullable":true,"default_expression":null},{"name":"confirmed_at_milliseconds","type":"int8","nullable":true,"default_expression":null}],"constraints":[{"kind":"CHECK","expression":"octet_length(tenant_id) BETWEEN 1 AND 128","referenced_columns":["tenant_id"]},{"kind":"CHECK","expression":"octet_length(repository_id) BETWEEN 1 AND 128","referenced_columns":["repository_id"]},{"kind":"CHECK","expression":"octet_length(review_run_id) BETWEEN 1 AND 128","referenced_columns":["review_run_id"]},{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["namespace_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["admission_identity"]},{"kind":"CHECK","expression":"database_authority_identity ~ '^[0-9a-f]{64}$' AND database_authority_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["database_authority_identity"]},{"kind":"CHECK","expression":"admitted_policy_identity ~ '^[0-9a-f]{64}$' AND admitted_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["admitted_policy_identity"]},{"kind":"CHECK","expression":"octet_length(canonical_admission) BETWEEN 1 AND 16384","referenced_columns":["canonical_admission"]},{"kind":"CHECK","expression":"octet_length(canonical_namespace) BETWEEN 1 AND 4096","referenced_columns":["canonical_namespace"]},{"kind":"CHECK","expression":"octet_length(admitted_policy) BETWEEN 1 AND 16384","referenced_columns":["admitted_policy"]},{"kind":"CHECK","expression":"admitted_at_milliseconds BETWEEN 1 AND 253402300799999","referenced_columns":["admitted_at_milliseconds"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","artifact_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","namespace_identity","admission_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"target_table":"open_trestle_artifacts","target_columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity"],"target_table":"open_trestle_review_scopes","target_columns":["tenant_id","repository_id","review_run_id","scope_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"},{"kind":"CHECK","expression":"(confirmed_version IS NULL AND confirmed_ciphertext_digest IS NULL AND confirmed_at_milliseconds IS NULL) OR (confirmed_version IS NOT NULL AND confirmed_ciphertext_digest IS NOT NULL AND confirmed_at_milliseconds IS NOT NULL AND left(confirmed_version, 8) = 'version:' AND octet_length(confirmed_version) BETWEEN 9 AND 512 AND confirmed_version <> 'version:null' AND confirmed_version !~ '[[:space:][:cntrl:]]' AND confirmed_ciphertext_digest ~ '^[0-9a-f]{64}$' AND confirmed_ciphertext_digest <> '0000000000000000000000000000000000000000000000000000000000000000' AND confirmed_at_milliseconds BETWEEN 1 AND 253402300799999 AND confirmed_at_milliseconds >= admitted_at_milliseconds)","referenced_columns":["confirmed_version","confirmed_ciphertext_digest","confirmed_at_milliseconds","admitted_at_milliseconds"]}],"indexes":[{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"unique":true,"primary":true,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","namespace_identity","admission_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"},{"name":"open_trestle_artifact_admissions_scan","columns":["tenant_id","repository_id","namespace_identity","review_run_id","artifact_identity"],"unique":false,"primary":false,"method":"btree","order":"ASC NULLS LAST"}],"flags":{"kind":"r","enable_rls":true,"force_rls":true},"policy":{"name":"<table>_tenant_isolation","command":"*","roles":[0],"permissive":true,"using":"tenant_id = current_setting('open_trestle.tenant_id', true)","with_check":"tenant_id = current_setting('open_trestle.tenant_id', true)"}},"open_trestle_artifact_erasure_operations":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"namespace_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"admission_identity","type":"text","nullable":false,"default_expression":null},{"name":"operation_identity","type":"text","nullable":false,"default_expression":null},{"name":"canonical_operation","type":"bytea","nullable":false,"default_expression":null},{"name":"canonical_authorization","type":"bytea","nullable":false,"default_expression":null},{"name":"accepted_policy","type":"bytea","nullable":false,"default_expression":null},{"name":"authorization_identity","type":"text","nullable":false,"default_expression":null},{"name":"authorization_document_digest","type":"text","nullable":false,"default_expression":null},{"name":"protected_policy_identity","type":"text","nullable":false,"default_expression":null},{"name":"database_authority_identity","type":"text","nullable":false,"default_expression":null},{"name":"prepared_at_milliseconds","type":"int8","nullable":false,"default_expression":null},{"name":"accepted_at_milliseconds","type":"int8","nullable":false,"default_expression":null}],"constraints":[{"kind":"CHECK","expression":"octet_length(tenant_id) BETWEEN 1 AND 128","referenced_columns":["tenant_id"]},{"kind":"CHECK","expression":"octet_length(repository_id) BETWEEN 1 AND 128","referenced_columns":["repository_id"]},{"kind":"CHECK","expression":"octet_length(review_run_id) BETWEEN 1 AND 128","referenced_columns":["review_run_id"]},{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["namespace_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["admission_identity"]},{"kind":"CHECK","expression":"operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["operation_identity"]},{"kind":"CHECK","expression":"authorization_identity ~ '^[0-9a-f]{64}$' AND authorization_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["authorization_identity"]},{"kind":"CHECK","expression":"authorization_document_digest ~ '^[0-9a-f]{64}$' AND authorization_document_digest <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["authorization_document_digest"]},{"kind":"CHECK","expression":"protected_policy_identity ~ '^[0-9a-f]{64}$' AND protected_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["protected_policy_identity"]},{"kind":"CHECK","expression":"database_authority_identity ~ '^[0-9a-f]{64}$' AND database_authority_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["database_authority_identity"]},{"kind":"CHECK","expression":"octet_length(canonical_operation) BETWEEN 1 AND 16384","referenced_columns":["canonical_operation"]},{"kind":"CHECK","expression":"octet_length(canonical_authorization) BETWEEN 1 AND 8192","referenced_columns":["canonical_authorization"]},{"kind":"CHECK","expression":"octet_length(accepted_policy) BETWEEN 1 AND 16384","referenced_columns":["accepted_policy"]},{"kind":"CHECK","expression":"prepared_at_milliseconds BETWEEN 1 AND 253402300799999","referenced_columns":["prepared_at_milliseconds"]},{"kind":"CHECK","expression":"accepted_at_milliseconds BETWEEN 1 AND 253402300799999","referenced_columns":["accepted_at_milliseconds"]},{"kind":"CHECK","expression":"accepted_at_milliseconds >= prepared_at_milliseconds","referenced_columns":["accepted_at_milliseconds","prepared_at_milliseconds"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","artifact_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity"],"target_table":"open_trestle_artifact_admissions","target_columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"}],"indexes":[{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity"],"unique":true,"primary":true,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"}],"flags":{"kind":"r","enable_rls":true,"force_rls":true},"policy":{"name":"<table>_tenant_isolation","command":"*","roles":[0],"permissive":true,"using":"tenant_id = current_setting('open_trestle.tenant_id', true)","with_check":"tenant_id = current_setting('open_trestle.tenant_id', true)"}}}`

var erasureTableNames = []string{"open_trestle_review_scopes", "open_trestle_artifacts", "open_trestle_artifact_deletion_authorizations", "open_trestle_artifact_deletion_receipts", "open_trestle_artifact_admissions", "open_trestle_artifact_erasure_operations"}

const erasureScopes = "open_trestle_review_scopes"
const erasureMetadata = "open_trestle_artifacts"
const erasureAdmissions = "open_trestle_artifact_admissions"
const erasureOperations = "open_trestle_artifact_erasure_operations"

func erasureRegistry(t *testing.T) map[string]erasureStatement {
	t.Helper()
	var result map[string]erasureStatement
	if err := json.Unmarshal([]byte(erasureRegistryJSON), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func erasureCatalogKey(id string, oid int64) string { return id + ":" + strconv.FormatInt(oid, 10) }
func erasureAttnums(d erasureTableDescriptor, columns []string, separator string) string {
	var values []string
	for _, name := range columns {
		found := false
		for i, c := range d.Columns {
			if c.Name == name {
				values = append(values, strconv.Itoa(i+1))
				found = true
				break
			}
		}
		if !found {
			panic("unknown catalog column")
		}
	}
	return strings.Join(values, separator)
}
func newErasureCatalog(t *testing.T) erasureCatalog {
	t.Helper()
	c := erasureCatalog{Rows: map[string][][]driver.Value{}, Tables: map[string]erasureTableDescriptor{}, OIDs: map[string]int64{}, Database: "synthetic", Schema: "public", Role: "trestle_runtime", Namespace: "12345678-1234-4234-8234-123456789abc"}
	if err := json.Unmarshal([]byte(erasureDescriptorJSON), &c.Tables); err != nil {
		t.Fatal(err)
	}
	c.Rows["role"] = [][]driver.Value{{int64(17000), c.Role, false, false, "on"}}
	for i, name := range erasureTableNames {
		c.OIDs[name] = int64(18001 + i)
	}
	for i, name := range erasureTableNames {
		oid, d := c.OIDs[name], c.Tables[name]
		c.Rows[erasureCatalogKey("relation", oid)] = [][]driver.Value{{oid, int64(2200), c.Schema, name, "r", true, true, oid}}
		for n, col := range d.Columns {
			typeOID := map[string]int64{"text": 25, "bytea": 17, "int8": 20, "timestamptz": 1184}[col.Type]
			var def driver.Value
			if col.Default != nil {
				def = *col.Default
			}
			c.Rows[erasureCatalogKey("attributes", oid)] = append(c.Rows[erasureCatalogKey("attributes", oid)], []driver.Value{int64(n + 1), col.Name, typeOID, "pg_catalog", col.Type, int64(-1), !col.Nullable, false, "", "", def})
		}
		for n, k := range d.Constraints {
			kind := map[string]string{"PRIMARY KEY": "p", "UNIQUE": "u", "FOREIGN KEY": "f", "CHECK": "c"}[k.Kind]
			cols := k.Columns
			if kind == "c" {
				cols = k.Referenced
			}
			foreign, foreignCols, match, update, remove := int64(0), "", "", "", ""
			if kind == "f" {
				foreign = c.OIDs[k.Target]
				foreignCols = erasureAttnums(c.Tables[k.Target], k.TargetColumns, ",")
				match, update, remove = "s", "a", "a"
			}
			var expr driver.Value
			if kind == "c" {
				expr = k.Expression
			}
			c.Rows[erasureCatalogKey("constraints", oid)] = append(c.Rows[erasureCatalogKey("constraints", oid)], []driver.Value{int64(20000 + i*100 + n), fmt.Sprintf("constraint_%02d", n), kind, true, false, false, true, int64(0), erasureAttnums(d, cols, ","), foreign, foreignCols, match, update, remove, expr})
		}
		for n, k := range d.Indexes {
			name := k.Name
			if name == "constraint-owned-name-not-authority" {
				name = fmt.Sprintf("index_%02d", n)
			}
			options := make([]string, len(k.Columns))
			for j := range options {
				options[j] = "0"
			}
			c.Rows[erasureCatalogKey("indexes", oid)] = append(c.Rows[erasureCatalogKey("indexes", oid)], []driver.Value{int64(21000 + i*100 + n), name, "btree", k.Primary, k.Unique, true, true, true, true, int64(len(k.Columns)), int64(len(k.Columns)), erasureAttnums(d, k.Columns, " "), strings.Join(options, " "), nil, nil})
		}
		sort.Slice(c.Rows[erasureCatalogKey("indexes", oid)], func(a, b int) bool {
			return c.Rows[erasureCatalogKey("indexes", oid)][a][1].(string) < c.Rows[erasureCatalogKey("indexes", oid)][b][1].(string)
		})
		c.Rows[erasureCatalogKey("policies", oid)] = [][]driver.Value{{int64(23000 + i), name + "_tenant_isolation", "*", true, "0", "tenant_id = current_setting('open_trestle.tenant_id', true)", "tenant_id = current_setting('open_trestle.tenant_id', true)"}}
		insert := name == erasureScopes || name == erasureMetadata || name == erasureAdmissions || name == erasureOperations
		c.Rows[erasureCatalogKey("table_privileges", oid)] = [][]driver.Value{{true, true, insert, name == erasureAdmissions, false, false, name == erasureAdmissions}}
		if name == erasureAdmissions {
			c.Rows[erasureCatalogKey("confirmation_privileges", oid)] = [][]driver.Value{{true, true, true}}
		}
	}
	for i, pin := range erasureOldMigrations {
		data, err := migrationFiles.ReadFile(pin.Name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != pin.Hash {
			t.Fatal("old migration bytes changed", pin.Name)
		}
		c.Rows["migration_rows"] = append(c.Rows["migration_rows"], []driver.Value{int64(i + 1), pin.Hash})
	}
	data, err := migrationFiles.ReadFile("migrations/0012_artifact_erasure.sql")
	if err != nil {
		t.Fatal("migrations/0012_artifact_erasure.sql is missing from the checked-out migration files")
	}
	sum := sha256.Sum256(data)
	c.Rows["migration_rows"] = append(c.Rows["migration_rows"], []driver.Value{int64(12), hex.EncodeToString(sum[:])})
	for i := 12; i < len(orderedMigrations); i++ {
		data, err := migrationFiles.ReadFile(orderedMigrations[i])
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		c.Rows["migration_rows"] = append(c.Rows["migration_rows"], []driver.Value{int64(i + 1), hex.EncodeToString(sum[:])})
	}
	c.Rows["authority_schemas"] = [][]driver.Value{{c.Schema, c.Schema, c.Schema}}
	c.Rows["authority_identity"] = [][]driver.Value{{c.Database, c.Schema, c.Role, c.Namespace}}
	return c
}

var erasureOldMigrations = []struct{ Name, Hash string }{
	{"migrations/0001_core.sql", "0851e0f67a9e743b341f3ee6ec7f9fa76b8e357be760288babb343c02c97c875"},
	{"migrations/0002_diagnostic_metadata.sql", "c366087870ef9b9473ce36b0226e51b20d5909ecd9bde2c7d4c2b6af5cffb197"},
	{"migrations/0003_webhook_metadata.sql", "a0c7db325849510df8067ef84ae4ed3ad0e8fe4863902161163a91ce578a218f"},
	{"migrations/0004_artifact_metadata.sql", "966735c8949937700a2324107520977159a371314085cc1e3340da613a9e7c20"},
	{"migrations/0005_task_notifications.sql", "57c661e7233d925905d2b67583594777cf929e38d91863fbbc1270dcb55b4476"},
	{"migrations/0006_publication_attempts.sql", "054802bf6a6d8f43fbd688d56a11bd7dcfd5aff1c54f7efc466452b6df103f9e"},
	{"migrations/0007_publication_guard_authority.sql", "1f5022dccb073081833f7190e7f5feab1ee956f32ebcd69eb9c4d7ff355f97d8"},
	{"migrations/0008_database_authority.sql", "39457b6ccb1932e6af18d5dca4ce1ad701a3d9021bb607224aac6b13293dc78f"},
	{"migrations/0009_shared_rate_limits.sql", "cf4f73b98666478a3749895189011eed9e4da9ae3f216cd1e1da47e9490143f1"},
	{"migrations/0010_artifact_kinds_and_origins.sql", "b681d2cf121d9e72e5f7343e66ae27cff7488ecdeb5618ba6b24686edee135fb"},
	{"migrations/0011_investigation_artifact_kinds.sql", "905abe68b8469d782d753158d69bb2460268d95327ada7510a721dba8bf6ea98"},
}

func TestErasureSchemaReservation(t *testing.T) {
	if len(orderedMigrations) < 12 || orderedMigrations[11] != "migrations/0012_artifact_erasure.sql" {
		t.Fatal("migrations/0012_artifact_erasure.sql is missing from the ordered migration list")
	}
	for i, pin := range erasureOldMigrations {
		if orderedMigrations[i] != pin.Name {
			t.Fatal("old migration order changed")
		}
		data, err := migrationFiles.ReadFile(pin.Name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != pin.Hash {
			t.Fatal("old migration source changed", pin.Name)
		}
	}
	b, err := migrationFiles.ReadFile(orderedMigrations[11])
	if err != nil {
		t.Fatal("migrations/0012_artifact_erasure.sql is missing from the checked-in migration files")
	}
	text := string(b)
	tables := regexp.MustCompile(`(?i)CREATE\s+TABLE\s+([a-z_]+)`).FindAllStringSubmatch(text, -1)
	if len(tables) != 2 {
		t.Fatal("0012 must reserve exactly two tables")
	}
	names := []string{tables[0][1], tables[1][1]}
	sort.Strings(names)
	want := []string{erasureAdmissions, erasureOperations}
	sort.Strings(want)
	if !reflect.DeepEqual(names, want) {
		t.Fatal("unadmitted table")
	}
	if !regexp.MustCompile(`(?is)canonical_namespace\s+bytea\s+NOT\s+NULL\s+CHECK\s*\(\s*(?:pg_catalog\.)?octet_length\s*\(\s*canonical_namespace\s*\)\s+BETWEEN\s+1\s+AND\s+4096\s*\)`).MatchString(text) {
		t.Fatal("source namespace bound must be1..4096, not16384")
	}
}
func TestErasureVerifierRejectsCatalogMutations(t *testing.T) {
	type mutation struct {
		name  string
		apply func(*erasureCatalog)
	}
	cases := []mutation{
		{"role superuser", func(c *erasureCatalog) { c.Rows["role"][0][2] = true }},
		{"role bypassrls", func(c *erasureCatalog) { c.Rows["role"][0][3] = true }},
		{"row security off", func(c *erasureCatalog) { c.Rows["role"][0][4] = "off" }},
		{"role mismatch", func(c *erasureCatalog) { c.Rows["role"][0][1] = "another_role" }},
		{"authority table shadow", func(c *erasureCatalog) { c.Rows["authority_schemas"][0][2] = "shadow" }},
		{"migration checksum", func(c *erasureCatalog) { c.Rows["migration_rows"][0][1] = strings.Repeat("d", 64) }},
	}
	for _, name := range erasureTableNames {
		for _, id := range []string{"relation", "attributes", "constraints", "indexes", "policies", "table_privileges"} {
			table, query := name, id
			cases = append(cases, mutation{table + "/missing " + query, func(c *erasureCatalog) { c.Rows[erasureCatalogKey(query, c.OIDs[table])] = nil }})
		}
		table := name
		for _, field := range []int{4, 5, 6, 7} {
			field := field
			cases = append(cases, mutation{table + "/relation " + strconv.Itoa(field), func(c *erasureCatalog) {
				row := c.Rows[erasureCatalogKey("relation", c.OIDs[table])][0]
				switch field {
				case 4:
					row[field] = "v"
				case 5, 6:
					row[field] = false
				case 7:
					row[field] = int64(99999)
				}
			}})
		}
		for _, field := range []int{1, 2, 4, 5, 6} {
			field := field
			cases = append(cases, mutation{table + "/policy " + strconv.Itoa(field), func(c *erasureCatalog) {
				r := c.Rows[erasureCatalogKey("policies", c.OIDs[table])][0]
				switch field {
				case 1:
					r[field] = "other_policy"
				case 2:
					r[field] = "r"
				case 4:
					r[field] = "17000"
				case 5:
					r[field] = "true"
				case 6:
					r[field] = nil
				}
			}})
		}
		cases = append(cases, mutation{table + "/extra permissive", func(c *erasureCatalog) {
			k := erasureCatalogKey("policies", c.OIDs[table])
			c.Rows[k] = append(c.Rows[k], []driver.Value{int64(99999), "extra_permissive", "*", true, "0", "true", "true"})
		}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newErasureCatalog(t)
			tc.apply(&c)
			s := newErasureSQLService(t, c)
			db := s.OpenDB(t, "negative")
			index, err := NewArtifactIndex(db)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := erasureOperationContext(t, "verify-negative")
			defer cancel()
			w, err := VerifyArtifactErasureIndex(ctx, index)
			if err == nil || !reflect.DeepEqual(w, VerifiedErasureIndex{}) {
				t.Fatal("changed catalog minted witness")
			}
			s.AssertClean(t)
		})
	}
}
func TestErasureVerifierChecksEveryColumnConstraintAndIndex(t *testing.T) {
	base := newErasureCatalog(t)
	for _, table := range erasureTableNames {
		oid := base.OIDs[table]
		for _, id := range []string{"attributes", "constraints", "indexes"} {
			rows := base.Rows[erasureCatalogKey(id, oid)]
			for n := range rows {
				for _, mode := range []string{"missing", "changed"} {
					t.Run(table+"/"+id+"/"+strconv.Itoa(n)+"/"+mode, func(t *testing.T) {
						c := newErasureCatalog(t)
						key := erasureCatalogKey(id, c.OIDs[table])
						if mode == "missing" {
							c.Rows[key] = append(c.Rows[key][:n], c.Rows[key][n+1:]...)
						} else {
							row := c.Rows[key][n]
							switch id {
							case "attributes":
								row[2] = int64(1043)
								row[4] = "varchar"
							case "constraints":
								if row[2] == "c" {
									row[14] = "(" + row[14].(string) + ") OR true"
								} else if row[2] == "f" {
									row[10] = "1"
									row[13] = "c"
								} else {
									row[8] = "1"
									row[3] = false
								}
							case "indexes":
								row[6] = false
								row[11] = "1"
							}
						}
						s := newErasureSQLService(t, c)
						db := s.OpenDB(t, "catalog")
						index, err := NewArtifactIndex(db)
						if err != nil {
							t.Fatal(err)
						}
						ctx, cancel := erasureOperationContext(t, "verify")
						defer cancel()
						w, err := VerifyArtifactErasureIndex(ctx, index)
						if err == nil || !reflect.DeepEqual(w, VerifiedErasureIndex{}) {
							t.Fatal("missing/changed descriptor accepted")
						}
						s.AssertClean(t)
					})
				}
			}
		}
	}
	for _, table := range []string{erasureAdmissions, erasureOperations} {
		for _, mode := range []string{"extra column", "nullable required", "not-null confirmation", "DELETE", "TRUNCATE", "column UPDATE"} {
			t.Run(table+"/"+mode, func(t *testing.T) {
				if mode == "not-null confirmation" && table != erasureAdmissions {
					return
				}
				if mode == "column UPDATE" && table != erasureOperations {
					return
				}
				c := newErasureCatalog(t)
				oid := c.OIDs[table]
				switch mode {
				case "extra column":
					k := erasureCatalogKey("attributes", oid)
					c.Rows[k] = append(c.Rows[k], []driver.Value{int64(30), "hidden_state", int64(25), "pg_catalog", "text", int64(-1), false, false, "", "", nil})
				case "nullable required":
					c.Rows[erasureCatalogKey("attributes", oid)][0][6] = false
				case "not-null confirmation":
					c.Rows[erasureCatalogKey("attributes", oid)][13][6] = true
				case "DELETE":
					c.Rows[erasureCatalogKey("table_privileges", oid)][0][4] = true
				case "TRUNCATE":
					c.Rows[erasureCatalogKey("table_privileges", oid)][0][5] = true
				case "column UPDATE":
					c.Rows[erasureCatalogKey("table_privileges", oid)][0][3] = false
					c.Rows[erasureCatalogKey("table_privileges", oid)][0][6] = true
				}
				s := newErasureSQLService(t, c)
				index, err := NewArtifactIndex(s.OpenDB(t, "grant"))
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := erasureOperationContext(t, "verify")
				defer cancel()
				w, err := VerifyArtifactErasureIndex(ctx, index)
				if err == nil || !reflect.DeepEqual(w, VerifiedErasureIndex{}) {
					t.Fatal("schema/privilege mutation accepted")
				}
				s.AssertClean(t)
			})
		}
	}
}
func TestErasureIndexWitnessCannotCrossHandles(t *testing.T) {
	cases := []string{"nil index", "zero policy", "zero witness", "cross DB same authority", "same DB other index", "nil backend", "invalid concrete backend", "nil keys", "nil clock", "different policy database", "different backend configuration"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			f := newErasureFixture(t)
			w, err := VerifyArtifactErasureIndex(f.ctx, f.index)
			if err != nil {
				t.Fatal(err)
			}
			index := f.index
			p := f.policy
			deps := EnvelopeDependencies{Backend: f.external.Backend(t, "first", f.clock), Keys: f.external.Keys(t, "first"), Clock: f.clock, IndexAuthority: w}
			switch name {
			case "nil index":
				index = nil
			case "zero policy":
				p = artifact.ProtectedErasurePolicy{}
			case "zero witness":
				deps.IndexAuthority = VerifiedErasureIndex{}
			case "cross DB same authority":
				index, err = NewArtifactIndex(f.s.OpenDB(t, "different-handle"))
			case "same DB other index":
				index, err = NewArtifactIndex(f.index.store.database)
			case "nil backend":
				deps.Backend = nil
			case "invalid concrete backend":
				deps.Backend = &s3.Backend{}
			case "nil keys":
				var keys *awskms.Provider
				deps.Keys = keys
			case "nil clock":
				var clock *erasureClock
				deps.Clock = clock
			case "different policy database":
				p = erasurePolicy(t, f.s.catalog, deps.Backend, map[string]any{"database_authority_identity": strings.Repeat("c", 64)})
			case "different backend configuration":
				credentials, _ := s3.NewCredentials("SYNTHETICACCESSKEY", "synthetic-secret-material-not-a-real-key-000000", "")
				cp, _ := s3.NewStaticCredentialsProvider(credentials)
				deps.Backend, err = s3.New(s3.Config{Endpoint: "https://s3.us-east-1.amazonaws.com", Region: "us-east-1", Bucket: "other-synthetic-bucket", Credentials: cp, HTTPClient: &http.Client{Transport: erasureRoundTripper{f.external, "first"}, Timeout: 2 * time.Second}, Clock: f.clock})
			}
			if err != nil {
				t.Fatal(err)
			}
			events := len(f.s.Snapshot().Events)
			external := f.external.Counts()
			store, err := NewIndexedEnvelopeStore(index, deps, p)
			if err == nil || store != nil {
				t.Fatal("invalid local witness/dependency accepted")
			}
			if events != len(f.s.Snapshot().Events) || external != f.external.Counts() {
				t.Fatal("constructor hidden I/O")
			}
		})
	}
}
func TestErasureFreshAuthorityChangeCannotRebindOldPolicy(t *testing.T) {
	f := newErasureFixture(t)
	if err := f.s.MutateCatalog(func(c *erasureCatalog) {
		c.Namespace = "87654321-1234-4234-8234-123456789abc"
		c.Rows["authority_identity"][0][3] = c.Namespace
	}); err != nil {
		t.Fatal(err)
	}
	w, err := VerifyArtifactErasureIndex(f.ctx, f.index)
	if err != nil {
		t.Fatal("fresh internally valid authority should verify independently", err)
	}
	before := len(f.s.Snapshot().Events)
	store, err := NewIndexedEnvelopeStore(f.index, EnvelopeDependencies{Backend: f.external.Backend(t, "first", f.clock), Keys: f.external.Keys(t, "first"), Clock: f.clock, IndexAuthority: w}, f.policy)
	if err == nil || store != nil {
		t.Fatal("changed DB namespace rebound old loaded policy")
	}
	if len(f.s.Snapshot().Events) != before {
		t.Fatal("constructor queried for continuous revocation")
	}
}

func TestErasureCatalogOIDValuesAreDiscovered(t *testing.T) {
	c := newErasureCatalog(t)
	mapping := map[int64]int64{}
	for table, oid := range c.OIDs {
		mapping[oid] = oid + 40000
		c.OIDs[table] = oid + 40000
	}
	rows := map[string][][]driver.Value{}
	for key, values := range c.Rows {
		parts := strings.Split(key, ":")
		newKey := key
		if len(parts) == 2 {
			oid, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			newKey = erasureCatalogKey(parts[0], mapping[oid])
		}
		values = erasureCopyRows(values)
		switch parts[0] {
		case "relation":
			for _, r := range values {
				r[0] = mapping[r[0].(int64)]
				r[1] = int64(44000)
				r[7] = mapping[r[7].(int64)]
			}
		case "constraints":
			for _, r := range values {
				r[0] = r[0].(int64) + 40000
				if r[9].(int64) != 0 {
					r[9] = mapping[r[9].(int64)]
				}
			}
		case "indexes", "policies":
			for _, r := range values {
				r[0] = r[0].(int64) + 40000
			}
		case "role":
			values[0][0] = int64(57000)
		}
		rows[newKey] = values
	}
	c.Rows = rows
	s := newErasureSQLService(t, c)
	index, err := NewArtifactIndex(s.OpenDB(t, "renumbered"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := erasureOperationContext(t, "verify-renumbered")
	defer cancel()
	w, err := VerifyArtifactErasureIndex(ctx, index)
	if err != nil || reflect.DeepEqual(w, VerifiedErasureIndex{}) {
		t.Fatal("verifier depends on fixture OIDs", err)
	}
	s.AssertClean(t)
}
func TestErasureVerifierNeverReturnsWitnessAfterCommitError(t *testing.T) {
	c := newErasureCatalog(t)
	s := newErasureSQLService(t, c)
	index, err := NewArtifactIndex(s.OpenDB(t, "verify"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Inject(erasureSQLFault{StatementID: "COMMIT", Occurrence: 1, OperationLabel: "verify-failure", Err: io.EOF, CommitMode: erasureTestPersistThenLose}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := erasureOperationContext(t, "verify-failure")
	defer cancel()
	w, err := VerifyArtifactErasureIndex(ctx, index)
	if err == nil || !reflect.DeepEqual(w, VerifiedErasureIndex{}) {
		t.Fatal("read-only unknown commit released witness")
	}
	s.AssertClean(t)
}

func TestErasureVerifierChecksPrivilegeBitsAndIndexFlags(t *testing.T) {
	base := newErasureCatalog(t)
	for _, table := range erasureTableNames {
		for _, bit := range []int{0, 1, 2} {
			if bit == 2 && table != "open_trestle_review_scopes" && table != "open_trestle_artifacts" && table != erasureAdmissions && table != erasureOperations {
				continue
			}
			t.Run(table+"/privilege/"+strconv.Itoa(bit), func(t *testing.T) {
				c := newErasureCatalog(t)
				c.Rows[erasureCatalogKey("table_privileges", c.OIDs[table])][0][bit] = false
				erasureRejectCatalog(t, c)
			})
		}
		for n := range base.Rows[erasureCatalogKey("indexes", base.OIDs[table])] {
			for _, bit := range []int{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14} {
				t.Run(table+"/index/"+strconv.Itoa(n)+"/"+strconv.Itoa(bit), func(t *testing.T) {
					c := newErasureCatalog(t)
					r := c.Rows[erasureCatalogKey("indexes", c.OIDs[table])][n]
					switch {
					case bit >= 3 && bit <= 8:
						r[bit] = !r[bit].(bool)
					case bit == 9:
						r[bit] = int64(0)
					case bit == 10:
						r[bit] = r[bit].(int64) + 1
					case bit == 11:
						if r[bit] == "1" {
							r[bit] = "2"
						} else {
							r[bit] = "1"
						}
					case bit == 12:
						r[bit] = "1"
					case bit == 13:
						r[bit] = "lower(tenant_id)"
					case bit == 14:
						r[bit] = "true"
					}
					erasureRejectCatalog(t, c)
				})
			}
		}
	}
	for bit := 0; bit < 3; bit++ {
		t.Run("confirmation column UPDATE/"+strconv.Itoa(bit), func(t *testing.T) {
			c := newErasureCatalog(t)
			c.Rows[erasureCatalogKey("confirmation_privileges", c.OIDs[erasureAdmissions])][0][bit] = false
			erasureRejectCatalog(t, c)
		})
	}
}
func erasureRejectCatalog(t *testing.T, c erasureCatalog) {
	t.Helper()
	s := newErasureSQLService(t, c)
	index, err := NewArtifactIndex(s.OpenDB(t, "catalog-negative"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := erasureOperationContext(t, "verify-negative")
	defer cancel()
	w, err := VerifyArtifactErasureIndex(ctx, index)
	if err == nil || !reflect.DeepEqual(w, VerifiedErasureIndex{}) {
		t.Fatal("changed catalog field accepted")
	}
	s.AssertClean(t)
}

func TestErasureVerifierChecksAttributeAndForeignKeyFields(t *testing.T) {
	base := newErasureCatalog(t)
	for _, table := range erasureTableNames {
		for n := range base.Rows[erasureCatalogKey("attributes", base.OIDs[table])] {
			for _, field := range []int{0, 1, 3, 5, 6, 7, 8, 9, 10} {
				t.Run(table+"/attribute/"+strconv.Itoa(n)+"/"+strconv.Itoa(field), func(t *testing.T) {
					c := newErasureCatalog(t)
					r := c.Rows[erasureCatalogKey("attributes", c.OIDs[table])][n]
					switch field {
					case 0:
						r[field] = int64(99)
					case 1:
						r[field] = r[field].(string) + "_changed"
					case 3:
						r[field] = "public"
					case 5:
						r[field] = int64(8)
					case 6:
						r[field] = !r[field].(bool)
					case 7:
						r[field] = true
					case 8:
						r[field] = "s"
					case 9:
						r[field] = "a"
					case 10:
						r[field] = "'changed'::text"
					}
					erasureRejectCatalog(t, c)
				})
			}
		}
		for n, row := range base.Rows[erasureCatalogKey("constraints", base.OIDs[table])] {
			fields := []int{3, 4, 5, 6, 7, 8}
			if row[2] == "f" {
				fields = append(fields, 9, 10, 11, 12, 13)
			}
			for _, field := range fields {
				t.Run(table+"/constraint/"+strconv.Itoa(n)+"/"+strconv.Itoa(field), func(t *testing.T) {
					c := newErasureCatalog(t)
					r := c.Rows[erasureCatalogKey("constraints", c.OIDs[table])][n]
					switch field {
					case 3, 4, 5, 6:
						r[field] = !r[field].(bool)
					case 7:
						r[field] = int64(1)
					case 8, 10:
						r[field] = "99"
					case 9:
						r[field] = int64(99999)
					case 11:
						r[field] = "f"
					case 12, 13:
						r[field] = "c"
					}
					erasureRejectCatalog(t, c)
				})
			}
		}
	}
}
