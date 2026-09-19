package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// This verifier covers key columns/order/flags, constraints, policies and
// effective grants. Opclasses, collations and operator families are NOT proven.
// Stable trusted catalog/operator configuration is a deployment requirement.
const journalSQLAttributes = `SELECT a.attnum::bigint, a.attname::text, t.oid::bigint, tn.nspname::text, t.typname::text, a.atttypmod::bigint, a.attnotnull, a.attisdropped, a.attgenerated::text, a.attidentity::text, pg_catalog.pg_get_expr(d.adbin, d.adrelid, false) FROM pg_catalog.pg_attribute AS a JOIN pg_catalog.pg_type AS t ON t.oid = a.atttypid JOIN pg_catalog.pg_namespace AS tn ON tn.oid = t.typnamespace LEFT JOIN pg_catalog.pg_attrdef AS d ON d.adrelid = a.attrelid AND d.adnum = a.attnum WHERE a.attrelid = $1::oid AND a.attnum > 0 ORDER BY a.attnum ASC`
const journalSQLConfirmationPrivileges = `SELECT pg_catalog.has_column_privilege($2, $1::oid, 'confirmed_version', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'confirmed_ciphertext_digest', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'confirmed_at_milliseconds', 'UPDATE')`
const journalSQLConstraints = `SELECT c.oid::bigint, c.conname::text, c.contype::text, c.convalidated, c.condeferrable, c.condeferred, c.conislocal, c.coninhcount::bigint, COALESCE(pg_catalog.array_to_string(c.conkey, ','), ''), c.confrelid::bigint, COALESCE(pg_catalog.array_to_string(c.confkey, ','), ''), CASE WHEN c.contype = 'f' THEN c.confmatchtype::text ELSE '' END, CASE WHEN c.contype = 'f' THEN c.confupdtype::text ELSE '' END, CASE WHEN c.contype = 'f' THEN c.confdeltype::text ELSE '' END, pg_catalog.pg_get_expr(c.conbin, c.conrelid, false) FROM pg_catalog.pg_constraint AS c WHERE c.conrelid = $1::oid ORDER BY c.conname ASC`
const journalSQLIndexes = `SELECT ic.oid::bigint, ic.relname::text, am.amname::text, i.indisprimary, i.indisunique, i.indisvalid, i.indisready, i.indislive, i.indimmediate, i.indnkeyatts::bigint, i.indnatts::bigint, i.indkey::text, i.indoption::text, pg_catalog.pg_get_expr(i.indexprs, i.indrelid, false), pg_catalog.pg_get_expr(i.indpred, i.indrelid, false) FROM pg_catalog.pg_index AS i JOIN pg_catalog.pg_class AS ic ON ic.oid = i.indexrelid JOIN pg_catalog.pg_am AS am ON am.oid = ic.relam WHERE i.indrelid = $1::oid ORDER BY ic.relname ASC`
const journalSQLPolicies = `SELECT p.oid::bigint, p.polname::text, p.polcmd::text, p.polpermissive, pg_catalog.array_to_string(p.polroles, ','), pg_catalog.pg_get_expr(p.polqual, p.polrelid, false), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid, false) FROM pg_catalog.pg_policy AS p WHERE p.polrelid = $1::oid ORDER BY p.polname ASC`
const journalSQLRelation = `SELECT c.oid::bigint, n.oid::bigint, n.nspname::text, c.relname::text, c.relkind::text, c.relrowsecurity, c.relforcerowsecurity, pg_catalog.to_regclass($2)::oid::bigint FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2`
const journalSQLRole = `SELECT r.oid::bigint, r.rolname::text, r.rolsuper, r.rolbypassrls, pg_catalog.current_setting('row_security') FROM pg_catalog.pg_roles AS r WHERE r.rolname = CURRENT_USER`
const journalSQLTablePrivileges = `SELECT pg_catalog.has_schema_privilege($2, $3, 'USAGE'), pg_catalog.has_table_privilege($2, $1::oid, 'SELECT'), pg_catalog.has_table_privilege($2, $1::oid, 'INSERT'), pg_catalog.has_table_privilege($2, $1::oid, 'UPDATE'), pg_catalog.has_table_privilege($2, $1::oid, 'DELETE'), pg_catalog.has_table_privilege($2, $1::oid, 'TRUNCATE'), pg_catalog.has_any_column_privilege($2, $1::oid, 'UPDATE')`

type journalSchemaColumn struct {
	name, kind, defaultExpr string
	nullable                bool
}
type journalSchemaConstraint struct {
	kind          string
	columns       []string
	target        string
	targetColumns []string
	expression    string
}
type journalSchemaIndex struct {
	name            string
	columns         []string
	primary, unique bool
}
type journalSchemaTable struct {
	name        string
	columns     []journalSchemaColumn
	constraints []journalSchemaConstraint
	indexes     []journalSchemaIndex
}

// These descriptors follow immutable migrations 0001..0011 and the additive
// two-table 0012. They contain no fixture OIDs or constraint-owned index names.
func erasureSchemaDescriptors() []journalSchemaTable {
	return []journalSchemaTable{
		{name: "open_trestle_review_scopes",
			columns: []journalSchemaColumn{
				{name: "tenant_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "repository_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "review_run_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "scope_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "registered_at", kind: "timestamptz", defaultExpr: "transaction_timestamp()", nullable: false},
			},
			constraints: []journalSchemaConstraint{
				{kind: "c", columns: []string{"tenant_id"}, target: "", targetColumns: []string{}, expression: "octet_length(tenant_id) BETWEEN 1 AND 128"},
				{kind: "c", columns: []string{"repository_id"}, target: "", targetColumns: []string{}, expression: "octet_length(repository_id) BETWEEN 1 AND 128"},
				{kind: "c", columns: []string{"review_run_id"}, target: "", targetColumns: []string{}, expression: "octet_length(review_run_id) BETWEEN 1 AND 128"},
				{kind: "c", columns: []string{"scope_identity"}, target: "", targetColumns: []string{}, expression: "scope_identity ~ '^[0-9a-f]{64}$'"},
				{kind: "p", columns: []string{"tenant_id", "repository_id", "review_run_id"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "u", columns: []string{"scope_identity"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "u", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity"}, target: "", targetColumns: []string{}, expression: ""},
			},
			indexes: []journalSchemaIndex{
				{name: "", columns: []string{"tenant_id", "repository_id", "review_run_id"}, primary: true, unique: true},
				{name: "", columns: []string{"scope_identity"}, primary: false, unique: true},
				{name: "", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity"}, primary: false, unique: true},
			}},
		{name: "open_trestle_artifacts",
			columns: []journalSchemaColumn{
				{name: "tenant_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "repository_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "review_run_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "scope_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "artifact_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "payload_digest", kind: "text", defaultExpr: "", nullable: false},
				{name: "kind", kind: "text", defaultExpr: "", nullable: false},
				{name: "classification", kind: "text", defaultExpr: "", nullable: false},
				{name: "origin", kind: "text", defaultExpr: "", nullable: false},
				{name: "protection", kind: "text", defaultExpr: "", nullable: false},
				{name: "created_at", kind: "timestamptz", defaultExpr: "", nullable: false},
				{name: "expires_at", kind: "timestamptz", defaultExpr: "", nullable: false},
				{name: "registered_at", kind: "timestamptz", defaultExpr: "transaction_timestamp()", nullable: false},
			},
			constraints: []journalSchemaConstraint{
				{kind: "c", columns: []string{"tenant_id"}, target: "", targetColumns: []string{}, expression: "octet_length(tenant_id) BETWEEN 1 AND 128"},
				{kind: "c", columns: []string{"repository_id"}, target: "", targetColumns: []string{}, expression: "octet_length(repository_id) BETWEEN 1 AND 128"},
				{kind: "c", columns: []string{"review_run_id"}, target: "", targetColumns: []string{}, expression: "octet_length(review_run_id) BETWEEN 1 AND 128"},
				{kind: "c", columns: []string{"scope_identity"}, target: "", targetColumns: []string{}, expression: "scope_identity ~ '^[0-9a-f]{64}$'"},
				{kind: "c", columns: []string{"artifact_identity"}, target: "", targetColumns: []string{}, expression: "artifact_identity ~ '^[0-9a-f]{64}$'"},
				{kind: "c", columns: []string{"payload_digest"}, target: "", targetColumns: []string{}, expression: "payload_digest ~ '^[0-9a-f]{64}$'"},
				{kind: "c", columns: []string{"kind"}, target: "", targetColumns: []string{}, expression: "kind IN ('source_snapshot', 'change_model', 'deterministic_evidence', 'retrieval_result', 'context_packet', 'candidate_batch', 'verification_batch', 'verified_finding_set', 'publication_plan', 'run_export', 'task_input', 'webhook_delivery', 'source_file', 'publication_receipt', 'investigation_turn', 'investigation_tool_result')"},
				{kind: "c", columns: []string{"classification"}, target: "", targetColumns: []string{}, expression: "classification IN ('public', 'internal', 'confidential', 'restricted')"},
				{kind: "c", columns: []string{"origin"}, target: "", targetColumns: []string{}, expression: "origin IN ('host', 'repository', 'deterministic_tool', 'model', 'independent_verifier', 'policy', 'memory')"},
				{kind: "c", columns: []string{"protection"}, target: "", targetColumns: []string{}, expression: "protection IN ('process_private', 'envelope_encrypted')"},
				{kind: "p", columns: []string{"tenant_id", "repository_id", "review_run_id", "artifact_identity"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "u", columns: []string{"scope_identity", "artifact_identity"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "f", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity"}, target: "open_trestle_review_scopes", targetColumns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity"}, expression: ""},
				{kind: "c", columns: []string{"expires_at", "created_at"}, target: "", targetColumns: []string{}, expression: "expires_at > created_at"},
			},
			indexes: []journalSchemaIndex{
				{name: "", columns: []string{"tenant_id", "repository_id", "review_run_id", "artifact_identity"}, primary: true, unique: true},
				{name: "", columns: []string{"scope_identity", "artifact_identity"}, primary: false, unique: true},
				{name: "open_trestle_artifacts_expiry", columns: []string{"tenant_id", "repository_id", "expires_at", "artifact_identity"}, primary: false, unique: false},
			}},
		{name: "open_trestle_artifact_deletion_authorizations",
			columns: []journalSchemaColumn{
				{name: "tenant_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "repository_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "review_run_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "scope_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "authorization_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "artifact_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "policy_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "principal_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "hold_clearance_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "reason", kind: "text", defaultExpr: "", nullable: false},
				{name: "issued_at", kind: "timestamptz", defaultExpr: "", nullable: false},
				{name: "expires_at", kind: "timestamptz", defaultExpr: "", nullable: false},
				{name: "registered_at", kind: "timestamptz", defaultExpr: "transaction_timestamp()", nullable: false},
			},
			constraints: []journalSchemaConstraint{
				{kind: "c", columns: []string{"scope_identity"}, target: "", targetColumns: []string{}, expression: "scope_identity ~ '^[0-9a-f]{64}$'"},
				{kind: "c", columns: []string{"authorization_identity"}, target: "", targetColumns: []string{}, expression: "authorization_identity ~ '^[0-9a-f]{64}$'"},
				{kind: "c", columns: []string{"artifact_identity"}, target: "", targetColumns: []string{}, expression: "artifact_identity ~ '^[0-9a-f]{64}$'"},
				{kind: "c", columns: []string{"policy_identity"}, target: "", targetColumns: []string{}, expression: "policy_identity ~ '^[0-9a-f]{64}$'"},
				{kind: "c", columns: []string{"hold_clearance_identity"}, target: "", targetColumns: []string{}, expression: "hold_clearance_identity ~ '^[0-9a-f]{64}$'"},
				{kind: "c", columns: []string{"principal_identity"}, target: "", targetColumns: []string{}, expression: "octet_length(principal_identity) BETWEEN 1 AND 128"},
				{kind: "c", columns: []string{"reason"}, target: "", targetColumns: []string{}, expression: "reason IN ('expired', 'tenant_erasure', 'repository_erasure')"},
				{kind: "p", columns: []string{"tenant_id", "repository_id", "review_run_id", "authorization_identity"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "u", columns: []string{"scope_identity", "authorization_identity"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "f", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity"}, target: "open_trestle_review_scopes", targetColumns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity"}, expression: ""},
				{kind: "f", columns: []string{"tenant_id", "repository_id", "review_run_id", "artifact_identity"}, target: "open_trestle_artifacts", targetColumns: []string{"tenant_id", "repository_id", "review_run_id", "artifact_identity"}, expression: ""},
				{kind: "c", columns: []string{"expires_at", "issued_at"}, target: "", targetColumns: []string{}, expression: "expires_at > issued_at"},
			},
			indexes: []journalSchemaIndex{
				{name: "", columns: []string{"tenant_id", "repository_id", "review_run_id", "authorization_identity"}, primary: true, unique: true},
				{name: "", columns: []string{"scope_identity", "authorization_identity"}, primary: false, unique: true},
			}},
		{name: "open_trestle_artifact_deletion_receipts",
			columns: []journalSchemaColumn{
				{name: "tenant_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "repository_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "review_run_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "scope_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "receipt_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "artifact_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "payload_digest", kind: "text", defaultExpr: "", nullable: false},
				{name: "authorization_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "deleted_at", kind: "timestamptz", defaultExpr: "", nullable: false},
				{name: "registered_at", kind: "timestamptz", defaultExpr: "transaction_timestamp()", nullable: false},
			},
			constraints: []journalSchemaConstraint{
				{kind: "c", columns: []string{"scope_identity"}, target: "", targetColumns: []string{}, expression: "scope_identity ~ '^[0-9a-f]{64}$'"},
				{kind: "c", columns: []string{"receipt_identity"}, target: "", targetColumns: []string{}, expression: "receipt_identity ~ '^[0-9a-f]{64}$'"},
				{kind: "c", columns: []string{"artifact_identity"}, target: "", targetColumns: []string{}, expression: "artifact_identity ~ '^[0-9a-f]{64}$'"},
				{kind: "c", columns: []string{"payload_digest"}, target: "", targetColumns: []string{}, expression: "payload_digest ~ '^[0-9a-f]{64}$'"},
				{kind: "c", columns: []string{"authorization_identity"}, target: "", targetColumns: []string{}, expression: "authorization_identity ~ '^[0-9a-f]{64}$'"},
				{kind: "p", columns: []string{"tenant_id", "repository_id", "review_run_id", "receipt_identity"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "u", columns: []string{"tenant_id", "repository_id", "review_run_id", "artifact_identity"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "u", columns: []string{"scope_identity", "receipt_identity"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "f", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity"}, target: "open_trestle_review_scopes", targetColumns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity"}, expression: ""},
				{kind: "f", columns: []string{"tenant_id", "repository_id", "review_run_id", "artifact_identity"}, target: "open_trestle_artifacts", targetColumns: []string{"tenant_id", "repository_id", "review_run_id", "artifact_identity"}, expression: ""},
				{kind: "f", columns: []string{"tenant_id", "repository_id", "review_run_id", "authorization_identity"}, target: "open_trestle_artifact_deletion_authorizations", targetColumns: []string{"tenant_id", "repository_id", "review_run_id", "authorization_identity"}, expression: ""},
			},
			indexes: []journalSchemaIndex{
				{name: "", columns: []string{"tenant_id", "repository_id", "review_run_id", "receipt_identity"}, primary: true, unique: true},
				{name: "", columns: []string{"tenant_id", "repository_id", "review_run_id", "artifact_identity"}, primary: false, unique: true},
				{name: "", columns: []string{"scope_identity", "receipt_identity"}, primary: false, unique: true},
			}},
		{name: "open_trestle_artifact_admissions",
			columns: []journalSchemaColumn{
				{name: "tenant_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "repository_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "review_run_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "scope_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "namespace_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "artifact_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "admission_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "canonical_admission", kind: "bytea", defaultExpr: "", nullable: false},
				{name: "canonical_namespace", kind: "bytea", defaultExpr: "", nullable: false},
				{name: "admitted_policy", kind: "bytea", defaultExpr: "", nullable: false},
				{name: "database_authority_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "admitted_policy_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "admitted_at_milliseconds", kind: "int8", defaultExpr: "", nullable: false},
				{name: "confirmed_version", kind: "text", defaultExpr: "", nullable: true},
				{name: "confirmed_ciphertext_digest", kind: "text", defaultExpr: "", nullable: true},
				{name: "confirmed_at_milliseconds", kind: "int8", defaultExpr: "", nullable: true},
			},
			constraints: []journalSchemaConstraint{
				{kind: "c", columns: []string{"tenant_id"}, target: "", targetColumns: []string{}, expression: "octet_length(tenant_id) BETWEEN 1 AND 128"},
				{kind: "c", columns: []string{"repository_id"}, target: "", targetColumns: []string{}, expression: "octet_length(repository_id) BETWEEN 1 AND 128"},
				{kind: "c", columns: []string{"review_run_id"}, target: "", targetColumns: []string{}, expression: "octet_length(review_run_id) BETWEEN 1 AND 128"},
				{kind: "c", columns: []string{"scope_identity"}, target: "", targetColumns: []string{}, expression: "scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"namespace_identity"}, target: "", targetColumns: []string{}, expression: "namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"artifact_identity"}, target: "", targetColumns: []string{}, expression: "artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"admission_identity"}, target: "", targetColumns: []string{}, expression: "admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"database_authority_identity"}, target: "", targetColumns: []string{}, expression: "database_authority_identity ~ '^[0-9a-f]{64}$' AND database_authority_identity <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"admitted_policy_identity"}, target: "", targetColumns: []string{}, expression: "admitted_policy_identity ~ '^[0-9a-f]{64}$' AND admitted_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"canonical_admission"}, target: "", targetColumns: []string{}, expression: "octet_length(canonical_admission) BETWEEN 1 AND 16384"},
				{kind: "c", columns: []string{"canonical_namespace"}, target: "", targetColumns: []string{}, expression: "octet_length(canonical_namespace) BETWEEN 1 AND 4096"},
				{kind: "c", columns: []string{"admitted_policy"}, target: "", targetColumns: []string{}, expression: "octet_length(admitted_policy) BETWEEN 1 AND 16384"},
				{kind: "c", columns: []string{"admitted_at_milliseconds"}, target: "", targetColumns: []string{}, expression: "admitted_at_milliseconds BETWEEN 1 AND 253402300799999"},
				{kind: "p", columns: []string{"tenant_id", "repository_id", "review_run_id", "artifact_identity"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "u", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "u", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "admission_identity"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "f", columns: []string{"tenant_id", "repository_id", "review_run_id", "artifact_identity"}, target: "open_trestle_artifacts", targetColumns: []string{"tenant_id", "repository_id", "review_run_id", "artifact_identity"}, expression: ""},
				{kind: "f", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity"}, target: "open_trestle_review_scopes", targetColumns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity"}, expression: ""},
				{kind: "c", columns: []string{"confirmed_version", "confirmed_ciphertext_digest", "confirmed_at_milliseconds", "admitted_at_milliseconds"}, target: "", targetColumns: []string{}, expression: "(confirmed_version IS NULL AND confirmed_ciphertext_digest IS NULL AND confirmed_at_milliseconds IS NULL) OR (confirmed_version IS NOT NULL AND confirmed_ciphertext_digest IS NOT NULL AND confirmed_at_milliseconds IS NOT NULL AND left(confirmed_version, 8) = 'version:' AND octet_length(confirmed_version) BETWEEN 9 AND 512 AND confirmed_version <> 'version:null' AND confirmed_version !~ '[[:space:][:cntrl:]]' AND confirmed_ciphertext_digest ~ '^[0-9a-f]{64}$' AND confirmed_ciphertext_digest <> '0000000000000000000000000000000000000000000000000000000000000000' AND confirmed_at_milliseconds BETWEEN 1 AND 253402300799999 AND confirmed_at_milliseconds >= admitted_at_milliseconds)"},
			},
			indexes: []journalSchemaIndex{
				{name: "", columns: []string{"tenant_id", "repository_id", "review_run_id", "artifact_identity"}, primary: true, unique: true},
				{name: "", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity"}, primary: false, unique: true},
				{name: "", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "admission_identity"}, primary: false, unique: true},
				{name: "open_trestle_artifact_admissions_scan", columns: []string{"tenant_id", "repository_id", "namespace_identity", "review_run_id", "artifact_identity"}, primary: false, unique: false},
			}},
		{name: "open_trestle_artifact_erasure_operations",
			columns: []journalSchemaColumn{
				{name: "tenant_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "repository_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "review_run_id", kind: "text", defaultExpr: "", nullable: false},
				{name: "scope_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "namespace_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "artifact_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "admission_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "operation_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "canonical_operation", kind: "bytea", defaultExpr: "", nullable: false},
				{name: "canonical_authorization", kind: "bytea", defaultExpr: "", nullable: false},
				{name: "accepted_policy", kind: "bytea", defaultExpr: "", nullable: false},
				{name: "authorization_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "authorization_document_digest", kind: "text", defaultExpr: "", nullable: false},
				{name: "protected_policy_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "database_authority_identity", kind: "text", defaultExpr: "", nullable: false},
				{name: "prepared_at_milliseconds", kind: "int8", defaultExpr: "", nullable: false},
				{name: "accepted_at_milliseconds", kind: "int8", defaultExpr: "", nullable: false},
			},
			constraints: []journalSchemaConstraint{
				{kind: "c", columns: []string{"tenant_id"}, target: "", targetColumns: []string{}, expression: "octet_length(tenant_id) BETWEEN 1 AND 128"},
				{kind: "c", columns: []string{"repository_id"}, target: "", targetColumns: []string{}, expression: "octet_length(repository_id) BETWEEN 1 AND 128"},
				{kind: "c", columns: []string{"review_run_id"}, target: "", targetColumns: []string{}, expression: "octet_length(review_run_id) BETWEEN 1 AND 128"},
				{kind: "c", columns: []string{"scope_identity"}, target: "", targetColumns: []string{}, expression: "scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"namespace_identity"}, target: "", targetColumns: []string{}, expression: "namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"artifact_identity"}, target: "", targetColumns: []string{}, expression: "artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"admission_identity"}, target: "", targetColumns: []string{}, expression: "admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"operation_identity"}, target: "", targetColumns: []string{}, expression: "operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"authorization_identity"}, target: "", targetColumns: []string{}, expression: "authorization_identity ~ '^[0-9a-f]{64}$' AND authorization_identity <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"authorization_document_digest"}, target: "", targetColumns: []string{}, expression: "authorization_document_digest ~ '^[0-9a-f]{64}$' AND authorization_document_digest <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"protected_policy_identity"}, target: "", targetColumns: []string{}, expression: "protected_policy_identity ~ '^[0-9a-f]{64}$' AND protected_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"database_authority_identity"}, target: "", targetColumns: []string{}, expression: "database_authority_identity ~ '^[0-9a-f]{64}$' AND database_authority_identity <> '0000000000000000000000000000000000000000000000000000000000000000'"},
				{kind: "c", columns: []string{"canonical_operation"}, target: "", targetColumns: []string{}, expression: "octet_length(canonical_operation) BETWEEN 1 AND 16384"},
				{kind: "c", columns: []string{"canonical_authorization"}, target: "", targetColumns: []string{}, expression: "octet_length(canonical_authorization) BETWEEN 1 AND 8192"},
				{kind: "c", columns: []string{"accepted_policy"}, target: "", targetColumns: []string{}, expression: "octet_length(accepted_policy) BETWEEN 1 AND 16384"},
				{kind: "c", columns: []string{"prepared_at_milliseconds"}, target: "", targetColumns: []string{}, expression: "prepared_at_milliseconds BETWEEN 1 AND 253402300799999"},
				{kind: "c", columns: []string{"accepted_at_milliseconds"}, target: "", targetColumns: []string{}, expression: "accepted_at_milliseconds BETWEEN 1 AND 253402300799999"},
				{kind: "c", columns: []string{"accepted_at_milliseconds", "prepared_at_milliseconds"}, target: "", targetColumns: []string{}, expression: "accepted_at_milliseconds >= prepared_at_milliseconds"},
				{kind: "p", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "u", columns: []string{"tenant_id", "repository_id", "review_run_id", "artifact_identity"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "u", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity"}, target: "", targetColumns: []string{}, expression: ""},
				{kind: "f", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity"}, target: "open_trestle_artifact_admissions", targetColumns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity"}, expression: ""},
			},
			indexes: []journalSchemaIndex{
				{name: "", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity"}, primary: true, unique: true},
				{name: "", columns: []string{"tenant_id", "repository_id", "review_run_id", "artifact_identity"}, primary: false, unique: true},
				{name: "", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity"}, primary: false, unique: true},
			}},
	}
}

func erasureSchemaDescriptorDigest() string {
	// Exported serialization is deliberately separate from private Go fields.
	// Every descriptor member participates; this digest records what was checked,
	// but the verifier must still inspect every live structural descriptor.
	parts := []string{
		"ordinary tables; distinct discovered OIDs; exact schema and search-path resolution",
		"CURRENT_USER; non-superuser; non-BYPASSRLS; row_security=on",
		"ENABLE+FORCE RLS; one permissive ALL/PUBLIC policy; exact USING and WITH CHECK",
		"tenant_id = current_setting('open_trestle.tenant_id', true)",
		"schema USAGE; all SELECT; scopes/artifacts/journals INSERT; all confirmation-column UPDATE",
		"journals no DELETE/TRUNCATE; operations no table/column UPDATE",
		"validated local nondeferrable constraints; SIMPLE NO ACTION FKs",
		"btree valid ready live immediate; ASC NULLS LAST; no expression/predicate/INCLUDE",
		"opclass/collation/operator-family proof expressly excluded",
	}
	for _, t := range erasureSchemaDescriptors() {
		parts = append(parts, t.name)
		for _, c := range t.columns {
			parts = append(parts, c.name, c.kind, c.defaultExpr, strconv.FormatBool(c.nullable))
		}
		for _, c := range t.constraints {
			parts = append(parts, c.kind, strings.Join(c.columns, ","), c.target, strings.Join(c.targetColumns, ","), c.expression)
		}
		for _, i := range t.indexes {
			parts = append(parts, i.name, strings.Join(i.columns, ","), strconv.FormatBool(i.primary), strconv.FormatBool(i.unique))
		}
	}
	b, _ := json.Marshal(parts)
	return erasureDigest(b)
}
func journalCatalogLabel(v any) bool {
	s, ok := v.(string)
	return ok && len(s) > 0 && len(s) <= 63 && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
func journalAttributeNumbers(t journalSchemaTable, cols []string) []int64 {
	result := make([]int64, 0, len(cols))
	for _, name := range cols {
		for i, c := range t.columns {
			if c.name == name {
				result = append(result, int64(i+1))
				break
			}
		}
	}
	return result
}
func journalParseNumbers(value string, sep string) ([]int64, bool) {
	if len(value) > 256 {
		return nil, false
	}
	if value == "" {
		return []int64{}, true
	}
	parts := strings.Split(value, sep)
	if len(parts) > 32 {
		return nil, false
	}
	result := make([]int64, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.ParseInt(p, 10, 64)
		if err != nil || v < 0 || strconv.FormatInt(v, 10) != p {
			return nil, false
		}
		result = append(result, v)
	}
	return result, true
}
func journalNumbersMatch(cell any, want []int64, sep string, set bool) bool {
	text, ok := cell.(string)
	if !ok {
		return false
	}
	got, ok := journalParseNumbers(text, sep)
	if !ok || len(got) != len(want) {
		return false
	}
	expected := append([]int64{}, want...)
	if set {
		sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
		sort.Slice(expected, func(i, j int) bool { return expected[i] < expected[j] })
	}
	for i := range got {
		if got[i] != expected[i] {
			return false
		}
	}
	return true
}
func verifyArtifactErasureSchema(ctx context.Context, tx *sql.Tx, schema, role string) error {
	if nilContext(ctx) || ctx.Err() != nil || tx == nil || !validDatabaseIdentifier(schema) || !validDatabaseIdentifier(role) {
		return ErrDatabaseAuthorityMismatch
	}
	rows, err := readErasureRows(ctx, tx, journalSQLRole, 5, 1)
	if err != nil {
		return err
	}
	if len(rows) != 1 || erasureInt(rows[0], 0) <= 0 || !erasureExactText(rows[0], 1, role) || !erasureBool(rows[0], 2, false) || !erasureBool(rows[0], 3, false) || !erasureExactText(rows[0], 4, "on") {
		return ErrDatabaseAuthorityMismatch
	}
	descriptors := erasureSchemaDescriptors()
	oids := map[string]int64{}
	byName := map[string]journalSchemaTable{}
	classIDs := map[int64]bool{}
	schemaOID := int64(0)
	for _, t := range descriptors {
		rows, err := readErasureRows(ctx, tx, journalSQLRelation, 8, 1, schema, t.name)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return ErrDatabaseAuthorityMismatch
		}
		r := rows[0]
		oid, nsp := erasureInt(r, 0), erasureInt(r, 1)
		if oid <= 0 || nsp <= 0 || classIDs[oid] || schemaOID != 0 && schemaOID != nsp || !erasureExactText(r, 2, schema) || !erasureExactText(r, 3, t.name) || !erasureExactText(r, 4, "r") || !erasureBool(r, 5, true) || !erasureBool(r, 6, true) || !erasureExactInt(r, 7, oid) {
			return ErrDatabaseAuthorityMismatch
		}
		schemaOID = nsp
		classIDs[oid] = true
		oids[t.name] = oid
		byName[t.name] = t
	}
	constraintIDs, policyIDs := map[int64]bool{}, map[int64]bool{}
	for _, t := range descriptors {
		oid := oids[t.name]
		if err := verifyErasureColumns(ctx, tx, oid, t); err != nil {
			return err
		}
		if err := verifyErasureConstraints(ctx, tx, oid, t, oids, byName, constraintIDs); err != nil {
			return err
		}
		if err := verifyErasureIndexes(ctx, tx, oid, t, classIDs); err != nil {
			return err
		}
		if err := verifyErasurePolicyGrants(ctx, tx, oid, t, schema, role, policyIDs); err != nil {
			return err
		}
	}
	return nil
}
func verifyErasureColumns(ctx context.Context, tx *sql.Tx, oid int64, t journalSchemaTable) error {
	rows, err := readErasureRows(ctx, tx, journalSQLAttributes, 11, 32, oid)
	if err != nil {
		return err
	}
	if len(rows) != len(t.columns) {
		return ErrDatabaseAuthorityMismatch
	}
	types := map[string]int64{"text": 25, "bytea": 17, "int8": 20, "timestamptz": 1184}
	for i, c := range t.columns {
		r := rows[i]
		if !erasureExactInt(r, 0, int64(i+1)) || !erasureExactText(r, 1, c.name) || !erasureExactInt(r, 2, types[c.kind]) || !erasureExactText(r, 3, "pg_catalog") || !erasureExactText(r, 4, c.kind) || !erasureExactInt(r, 5, -1) || !erasureBool(r, 6, !c.nullable) || !erasureBool(r, 7, false) || !erasureExactText(r, 8, "") || !erasureExactText(r, 9, "") {
			return ErrDatabaseAuthorityMismatch
		}
		if c.defaultExpr == "" {
			if r[10] != nil {
				return ErrDatabaseAuthorityMismatch
			}
		} else {
			expression, ok := r[10].(string)
			if !ok || !journalExpressionsEqual(expression, c.defaultExpr, t) {
				return ErrDatabaseAuthorityMismatch
			}
		}
	}
	return nil
}
func verifyErasureConstraints(ctx context.Context, tx *sql.Tx, oid int64, t journalSchemaTable, oids map[string]int64, tables map[string]journalSchemaTable, seen map[int64]bool) error {
	rows, err := readErasureRows(ctx, tx, journalSQLConstraints, 15, 64, oid)
	if err != nil {
		return err
	}
	if len(rows) != len(t.constraints) {
		return ErrDatabaseAuthorityMismatch
	}
	used := make([]bool, len(t.constraints))
	names := map[string]bool{}
	for _, r := range rows {
		id, name := erasureInt(r, 0), erasureText(r, 1)
		if id <= 0 || seen[id] || !journalCatalogLabel(r[1]) || names[name] || !erasureBool(r, 3, true) || !erasureBool(r, 4, false) || !erasureBool(r, 5, false) || !erasureBool(r, 6, true) || !erasureExactInt(r, 7, 0) {
			return ErrDatabaseAuthorityMismatch
		}
		seen[id] = true
		names[name] = true
		matched := false
		for i, c := range t.constraints {
			if used[i] || !erasureExactText(r, 2, c.kind) || !journalNumbersMatch(r[8], journalAttributeNumbers(t, c.columns), ",", c.kind == "c") {
				continue
			}
			if c.kind == "f" {
				if !erasureExactInt(r, 9, oids[c.target]) || !journalNumbersMatch(r[10], journalAttributeNumbers(tables[c.target], c.targetColumns), ",", false) || !erasureExactText(r, 11, "s") || !erasureExactText(r, 12, "a") || !erasureExactText(r, 13, "a") || r[14] != nil {
					continue
				}
			} else {
				if !erasureExactInt(r, 9, 0) || !erasureExactText(r, 10, "") || !erasureExactText(r, 11, "") || !erasureExactText(r, 12, "") || !erasureExactText(r, 13, "") {
					continue
				}
				if c.kind == "c" {
					expression, ok := r[14].(string)
					if !ok || !journalExpressionsEqual(expression, c.expression, t) {
						continue
					}
				} else if r[14] != nil {
					continue
				}
			}
			used[i], matched = true, true
			break
		}
		if !matched {
			return ErrDatabaseAuthorityMismatch
		}
	}
	return nil
}
func verifyErasureIndexes(ctx context.Context, tx *sql.Tx, oid int64, t journalSchemaTable, seen map[int64]bool) error {
	rows, err := readErasureRows(ctx, tx, journalSQLIndexes, 15, 16, oid)
	if err != nil {
		return err
	}
	if len(rows) != len(t.indexes) {
		return ErrDatabaseAuthorityMismatch
	}
	used := make([]bool, len(t.indexes))
	names := map[string]bool{}
	for _, r := range rows {
		id, name := erasureInt(r, 0), erasureText(r, 1)
		if id <= 0 || seen[id] || !journalCatalogLabel(r[1]) || names[name] || !erasureExactText(r, 2, "btree") || !erasureBool(r, 5, true) || !erasureBool(r, 6, true) || !erasureBool(r, 7, true) || !erasureBool(r, 8, true) || r[13] != nil || r[14] != nil {
			return ErrDatabaseAuthorityMismatch
		}
		seen[id] = true
		names[name] = true
		matched := false
		for i, d := range t.indexes {
			n := int64(len(d.columns))
			if used[i] || d.name != "" && name != d.name || !erasureBool(r, 3, d.primary) || !erasureBool(r, 4, d.unique) || !erasureExactInt(r, 9, n) || !erasureExactInt(r, 10, n) || !journalNumbersMatch(r[11], journalAttributeNumbers(t, d.columns), " ", false) || !journalNumbersMatch(r[12], make([]int64, len(d.columns)), " ", false) {
				continue
			}
			used[i], matched = true, true
			break
		}
		if !matched {
			return ErrDatabaseAuthorityMismatch
		}
	}
	return nil
}
func verifyErasurePolicyGrants(ctx context.Context, tx *sql.Tx, oid int64, t journalSchemaTable, schema, role string, seen map[int64]bool) error {
	rows, err := readErasureRows(ctx, tx, journalSQLPolicies, 7, 1, oid)
	if err != nil {
		return err
	}
	if len(rows) != 1 {
		return ErrDatabaseAuthorityMismatch
	}
	r := rows[0]
	id := erasureInt(r, 0)
	if id <= 0 || seen[id] || !erasureExactText(r, 1, t.name+"_tenant_isolation") || !erasureExactText(r, 2, "*") || !erasureBool(r, 3, true) || !erasureExactText(r, 4, "0") {
		return ErrDatabaseAuthorityMismatch
	}
	seen[id] = true
	for _, i := range []int{5, 6} {
		expr, ok := r[i].(string)
		if !ok || !journalExpressionsEqual(expr, "tenant_id = current_setting('open_trestle.tenant_id', true)", t) {
			return ErrDatabaseAuthorityMismatch
		}
	}
	rows, err = readErasureRows(ctx, tx, journalSQLTablePrivileges, 7, 1, oid, role, schema)
	if err != nil {
		return err
	}
	if len(rows) != 1 {
		return ErrDatabaseAuthorityMismatch
	}
	r = rows[0]
	for _, cell := range r {
		if _, ok := cell.(bool); !ok {
			return ErrDatabaseAuthorityMismatch
		}
	}
	admission := t.name == "open_trestle_artifact_admissions"
	operation := t.name == "open_trestle_artifact_erasure_operations"
	needsInsert := admission || operation || t.name == "open_trestle_review_scopes" || t.name == "open_trestle_artifacts"
	if !erasureBool(r, 0, true) || !erasureBool(r, 1, true) || needsInsert && !erasureBool(r, 2, true) || (admission || operation) && (!erasureBool(r, 4, false) || !erasureBool(r, 5, false)) || operation && (!erasureBool(r, 3, false) || !erasureBool(r, 6, false)) {
		return ErrDatabaseAuthorityMismatch
	}
	if admission {
		rows, err = readErasureRows(ctx, tx, journalSQLConfirmationPrivileges, 3, 1, oid, role)
		if err != nil {
			return err
		}
		if len(rows) != 1 || !erasureBool(rows[0], 0, true) || !erasureBool(rows[0], 1, true) || !erasureBool(rows[0], 2, true) {
			return ErrDatabaseAuthorityMismatch
		}
	}
	return nil
}

// A small typed recognizer, not a SQL evaluator. Unsupported syntax fails
// closed. Parentheses are parsed; OR branches and casts are never text-deleted.
// AND/OR flattening preserves operand order and all branches. BETWEEN and IN
// normalize only to their declared comparison/ANY forms.
type journalExpr struct {
	op, typ, atom string
	args          []*journalExpr
}
type journalExprToken struct{ kind, value string }
type journalExprParser struct {
	tokens    []journalExprToken
	at, depth int
	failed    bool
	columns   map[string]string
}

func journalExpressionsEqual(actual, expected string, table journalSchemaTable) bool {
	a, ok := parseJournalExpression(actual, table)
	if !ok {
		return false
	}
	b, ok := parseJournalExpression(expected, table)
	return ok && reflect.DeepEqual(a, b)
}
func parseJournalExpression(text string, table journalSchemaTable) (*journalExpr, bool) {
	tokens, ok := lexJournalExpression(text)
	if !ok {
		return nil, false
	}
	p := journalExprParser{tokens: tokens, columns: map[string]string{}}
	for _, c := range table.columns {
		p.columns[c.name] = c.kind
	}
	node := p.or()
	return node, !p.failed && node != nil && p.at == len(tokens)
}
func lexJournalExpression(text string) ([]journalExprToken, bool) {
	if len(text) == 0 || len(text) > 8192 || !utf8.ValidString(text) {
		return nil, false
	}
	var tokens []journalExprToken
	for i := 0; i < len(text); {
		if len(tokens) >= 1024 {
			return nil, false
		}
		ch := text[i]
		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\f' {
			i++
			continue
		}
		if ch == '\'' || ch == '"' {
			quote := ch
			i++
			var b strings.Builder
			closed := false
			for i < len(text) {
				if text[i] == quote {
					i++
					if i < len(text) && text[i] == quote {
						b.WriteByte(quote)
						i++
						continue
					}
					closed = true
					break
				}
				// No E strings, backslash escapes, controls or dollar-quoted syntax.
				if text[i] == '\\' || text[i] < 32 {
					return nil, false
				}
				b.WriteByte(text[i])
				i++
			}
			if !closed {
				return nil, false
			}
			kind := "literal"
			if quote == '"' {
				kind = "identifier"
			}
			tokens = append(tokens, journalExprToken{kind, b.String()})
			continue
		}
		if ch >= '0' && ch <= '9' {
			start := i
			for i < len(text) && text[i] >= '0' && text[i] <= '9' {
				i++
			}
			tokens = append(tokens, journalExprToken{"number", text[start:i]})
			continue
		}
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '_' {
			start := i
			for i < len(text) {
				c := text[i]
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
					break
				}
				i++
			}
			word := text[start:i]
			switch strings.ToUpper(word) {
			case "AND", "OR", "BETWEEN", "IN", "IS", "NOT", "NULL", "ANY", "ARRAY", "TRUE", "FALSE":
				word = strings.ToUpper(word)
			}
			tokens = append(tokens, journalExprToken{"word", word})
			continue
		}
		if i+1 < len(text) {
			pair := text[i : i+2]
			if pair == "::" || pair == "<>" || pair == ">=" || pair == "<=" || pair == "!~" {
				tokens = append(tokens, journalExprToken{"symbol", pair})
				i += 2
				continue
			}
		}
		if strings.ContainsRune("(),.[]=~><-", rune(ch)) {
			tokens = append(tokens, journalExprToken{"symbol", string(ch)})
			i++
			continue
		}
		return nil, false
	}
	return tokens, len(tokens) > 0
}
func (p *journalExprParser) peek(value string) bool {
	return p.at < len(p.tokens) && p.tokens[p.at].value == value && p.tokens[p.at].kind != "literal" && p.tokens[p.at].kind != "identifier"
}
func (p *journalExprParser) take(value string) bool {
	if p.peek(value) {
		p.at++
		return true
	}
	return false
}
func (p *journalExprParser) require(value string) {
	if !p.take(value) {
		p.failed = true
	}
}
func journalLogic(op string, a, b *journalExpr) *journalExpr {
	if a == nil || b == nil || a.typ != "bool" || b.typ != "bool" {
		return nil
	}
	result := &journalExpr{op: op, typ: "bool"}
	for _, n := range []*journalExpr{a, b} {
		if n.op == op {
			result.args = append(result.args, n.args...)
		} else {
			result.args = append(result.args, n)
		}
	}
	return result
}
func (p *journalExprParser) or() *journalExpr {
	if p.depth >= 64 {
		p.failed = true
		return nil
	}
	p.depth++
	defer func() { p.depth-- }()
	n := p.and()
	for !p.failed && p.take("OR") {
		n = journalLogic("or", n, p.and())
		if n == nil {
			p.failed = true
		}
	}
	return n
}
func (p *journalExprParser) and() *journalExpr {
	n := p.comparison()
	for !p.failed && p.take("AND") {
		n = journalLogic("and", n, p.comparison())
		if n == nil {
			p.failed = true
		}
	}
	return n
}
func journalNumeric(t string) bool { return t == "int4" || t == "int8" || t == "number" }
func journalCompatible(a, b *journalExpr) bool {
	return a != nil && b != nil && (a.typ == b.typ || journalNumeric(a.typ) && journalNumeric(b.typ))
}
func journalCompare(op string, a, b *journalExpr) *journalExpr {
	if !journalCompatible(a, b) {
		return nil
	}
	if (op == "~" || op == "!~") && (a.typ != "text" || b.typ != "text") {
		return nil
	}
	return &journalExpr{op: op, typ: "bool", args: []*journalExpr{a, b}}
}
func (p *journalExprParser) comparison() *journalExpr {
	left := p.value()
	if p.failed || left == nil {
		p.failed = true
		return nil
	}
	if p.take("IS") {
		op := "is-null"
		if p.take("NOT") {
			op = "not-null"
		}
		p.require("NULL")
		return &journalExpr{op: op, typ: "bool", args: []*journalExpr{left}}
	}
	if p.take("BETWEEN") {
		low := p.value()
		p.require("AND")
		high := p.value()
		n := journalLogic("and", journalCompare(">=", left, low), journalCompare("<=", left, high))
		if n == nil {
			p.failed = true
		}
		return n
	}
	if p.take("IN") {
		p.require("(")
		var values []*journalExpr
		for !p.failed {
			n := p.value()
			if n == nil || n.op != "literal" || !journalCompatible(left, n) || len(values) >= 128 {
				p.failed = true
				break
			}
			values = append(values, n)
			if !p.take(",") {
				break
			}
		}
		p.require(")")
		return &journalExpr{op: "any=", typ: "bool", args: append([]*journalExpr{left}, values...)}
	}
	for _, op := range []string{"=", "<>", ">", ">=", "<", "<=", "~", "!~"} {
		if !p.take(op) {
			continue
		}
		if p.take("ANY") {
			if op != "=" {
				p.failed = true
				return nil
			}
			p.require("(")
			array := p.value()
			p.require(")")
			if array == nil || array.op != "array" || len(array.args) == 0 {
				p.failed = true
				return nil
			}
			for _, a := range array.args {
				if a.op != "literal" || !journalCompatible(left, a) {
					p.failed = true
					return nil
				}
			}
			return &journalExpr{op: "any=", typ: "bool", args: append([]*journalExpr{left}, array.args...)}
		}
		n := journalCompare(op, left, p.value())
		if n == nil {
			p.failed = true
		}
		return n
	}
	return left
}
func (p *journalExprParser) name() (string, bool) {
	if p.at >= len(p.tokens) {
		return "", false
	}
	t := p.tokens[p.at]
	if t.kind != "word" && t.kind != "identifier" {
		return "", false
	}
	p.at++
	name := t.value
	if p.take(".") {
		if name != "pg_catalog" || p.at >= len(p.tokens) {
			return "", false
		}
		t = p.tokens[p.at]
		if t.kind != "word" && t.kind != "identifier" {
			return "", false
		}
		p.at++
		name = t.value
		switch name {
		case "octet_length", "left", "current_setting", "transaction_timestamp", "text", "int4", "int8", "integer", "bigint":
		default:
			return "", false
		}
	}
	return name, true
}
func (p *journalExprParser) value() *journalExpr {
	if p.failed || p.at >= len(p.tokens) || p.depth >= 64 {
		p.failed = true
		return nil
	}
	p.depth++
	defer func() { p.depth-- }()
	var n *journalExpr
	switch {
	case p.take("("):
		n = p.or()
		p.require(")")
	case p.take("ARRAY"):
		p.require("[")
		var values []*journalExpr
		for !p.failed {
			v := p.value()
			if v == nil || v.op != "literal" || len(values) >= 128 || len(values) > 0 && !journalCompatible(values[0], v) {
				p.failed = true
				break
			}
			values = append(values, v)
			if !p.take(",") {
				break
			}
		}
		p.require("]")
		if len(values) == 0 {
			p.failed = true
			return nil
		}
		n = &journalExpr{op: "array", typ: values[0].typ + "[]", args: values}
	case p.take("TRUE"):
		n = &journalExpr{op: "literal", typ: "bool", atom: "true"}
	case p.take("FALSE"):
		n = &journalExpr{op: "literal", typ: "bool", atom: "false"}
	default:
		negative := p.take("-")
		if p.at >= len(p.tokens) {
			p.failed = true
			return nil
		}
		token := p.tokens[p.at]
		if token.kind == "literal" && !negative {
			p.at++
			n = &journalExpr{op: "literal", typ: "text", atom: token.value}
		} else if token.kind == "number" {
			p.at++
			v := token.value
			if negative {
				v = "-" + v
			}
			number, err := strconv.ParseInt(v, 10, 64)
			if err != nil || strconv.FormatInt(number, 10) != v {
				p.failed = true
				return nil
			}
			n = &journalExpr{op: "literal", typ: "number", atom: v}
		} else {
			if negative {
				p.failed = true
				return nil
			}
			name, ok := p.name()
			if !ok {
				p.failed = true
				return nil
			}
			if p.take("(") {
				var args []*journalExpr
				if !p.peek(")") {
					for !p.failed {
						a := p.or()
						if a == nil || len(args) >= 2 {
							p.failed = true
							break
						}
						args = append(args, a)
						if !p.take(",") {
							break
						}
					}
				}
				p.require(")")
				n = p.function(name, args)
			} else {
				kind, ok := p.columns[name]
				if !ok {
					p.failed = true
					return nil
				}
				n = &journalExpr{op: "column", typ: kind, atom: name}
			}
		}
	}
	for !p.failed && p.take("::") {
		name, ok := p.name()
		if !ok {
			p.failed = true
			break
		}
		switch name {
		case "integer":
			name = "int4"
		case "bigint":
			name = "int8"
		}
		if p.take("[") {
			p.require("]")
			name += "[]"
		}
		n = p.losslessCast(n, name)
	}
	if n == nil {
		p.failed = true
	}
	return n
}
func (p *journalExprParser) function(name string, args []*journalExpr) *journalExpr {
	switch name {
	case "octet_length":
		if len(args) == 1 && (args[0].typ == "text" || args[0].typ == "bytea") {
			return &journalExpr{op: name, typ: "int4", args: args}
		}
	case "left":
		if len(args) == 2 && args[0].typ == "text" && args[1].op == "literal" && journalNumeric(args[1].typ) {
			return &journalExpr{op: name, typ: "text", args: args}
		}
	case "current_setting":
		if len(args) == 2 && args[0].typ == "text" && args[0].op == "literal" && args[1].typ == "bool" && args[1].op == "literal" {
			return &journalExpr{op: name, typ: "text", args: args}
		}
	case "transaction_timestamp":
		if len(args) == 0 {
			return &journalExpr{op: name, typ: "timestamptz"}
		}
	}
	p.failed = true
	return nil
}
func (p *journalExprParser) losslessCast(n *journalExpr, to string) *journalExpr {
	if n == nil {
		p.failed = true
		return nil
	}
	if to == "text" && n.typ == "text" || to == "text[]" && n.op == "array" && n.typ == "text[]" {
		return n
	}
	if to == "int4" || to == "int8" {
		if n.op == "literal" && (journalNumeric(n.typ) || n.typ == "text") {
			number, err := strconv.ParseInt(n.atom, 10, 64)
			if err == nil && strconv.FormatInt(number, 10) == n.atom && (to == "int8" || number >= -2147483648 && number <= 2147483647) {
				return &journalExpr{op: "literal", typ: "number", atom: n.atom}
			}
		}
		// Only same-type or widening builtin integer casts of declared expressions.
		if n.typ == to || n.typ == "int4" && to == "int8" {
			return n
		}
	}
	p.failed = true
	return nil
}
