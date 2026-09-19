package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
)

const daemonBudgetedjournalSQLArtifactLock = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`
const daemonBudgetedjournalSQLAuthorityIdentity = `SELECT pg_catalog.current_database(), pg_catalog.current_schema(), CURRENT_USER, database_namespace_id::text FROM open_trestle_database_authority WHERE singleton = true`
const daemonBudgetedjournalSQLAuthoritySchemas = `SELECT pg_catalog.current_schema(), (SELECT n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = pg_catalog.to_regclass('open_trestle_schema_migrations')), (SELECT n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = pg_catalog.to_regclass('open_trestle_database_authority'))`
const daemonBudgetedjournalSQLMetadataInsert = `INSERT INTO open_trestle_artifacts (tenant_id, repository_id, review_run_id, scope_identity, artifact_identity, payload_digest, kind, classification, origin, protection, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
const daemonBudgetedjournalSQLMetadataRead = `SELECT payload_digest, kind, classification, origin, protection, created_at, expires_at FROM open_trestle_artifacts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4`
const daemonBudgetedjournalSQLMigrationRows = `SELECT version, checksum FROM open_trestle_schema_migrations ORDER BY version ASC`
const daemonBudgetedjournalSQLScopeInsert = `INSERT INTO open_trestle_review_scopes (tenant_id, repository_id, review_run_id, scope_identity) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`
const daemonBudgetedjournalSQLScopeRead = `SELECT scope_identity FROM open_trestle_review_scopes WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`
const daemonBudgetedRunPlanReadSQL = `SELECT plan_identity, canonical_plan
FROM open_trestle_run_plans
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`
const daemonBudgetedRunPlanIdentityReadSQL = `SELECT plan_identity
FROM open_trestle_run_plans
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`
const daemonBudgetedRunPlanFirstEventIdentitySQL = `SELECT plan_identity
FROM open_trestle_run_events
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3
ORDER BY sequence ASC LIMIT 1`
const daemonBudgetedRunPlanInsertSQL = `INSERT INTO open_trestle_run_plans
(tenant_id, repository_id, review_run_id, scope_identity, plan_identity, canonical_plan)
VALUES ($1, $2, $3, $4, $5, $6)`
const daemonBudgetedRunPlansListSQL = `SELECT plan_identity, canonical_plan
FROM open_trestle_run_plans
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id > $3
ORDER BY review_run_id ASC LIMIT $4`
const daemonBudgetedRunHeadSQL = `SELECT sequence, event_identity, canonical_event, count(*) OVER ()
FROM open_trestle_run_events
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3
ORDER BY sequence DESC LIMIT 1`
const daemonBudgetedRunEventsReadSQL = `SELECT sequence, event_identity, canonical_event
FROM open_trestle_run_events
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND sequence > $4
ORDER BY sequence ASC LIMIT $5`
const daemonBudgetedRunEventInsertSQL = `INSERT INTO open_trestle_run_events
(tenant_id, repository_id, review_run_id, scope_identity, plan_identity, sequence, event_identity, previous_identity, canonical_event, occurred_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
const daemonBudgetedAuditEventInsertSQL = `INSERT INTO open_trestle_audit_events
(tenant_id, repository_id, review_run_id, scope_identity, sequence, event_identity, previous_identity, canonical_event, occurred_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
const daemonBudgetedAuditEventReadSQL = `SELECT sequence, event_identity, canonical_event
FROM open_trestle_audit_events
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND sequence > $4
ORDER BY sequence ASC LIMIT $5`
const daemonBudgetedAuditEventHeadSQL = `SELECT sequence, event_identity, canonical_event, count(*) OVER ()
FROM open_trestle_audit_events
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3
ORDER BY sequence DESC LIMIT 1`
const daemonBudgetedDiagnosticMappingInsertSQL = `INSERT INTO open_trestle_diagnostic_sets
(tenant_id, repository_id, review_run_id, scope_identity, set_identity, artifact_identity, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`
const daemonBudgetedDiagnosticMappingReadSQL = `SELECT set_identity, artifact_identity, expires_at
FROM open_trestle_diagnostic_sets
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`
const daemonBudgetedWebhookMappingCountSQL = `SELECT count(*)
FROM open_trestle_webhook_deliveries
WHERE tenant_id = $1 AND repository_id = $2 AND source = $3 AND expires_at > $4`
const daemonBudgetedWebhookMappingInsertSQL = `INSERT INTO open_trestle_webhook_deliveries
(tenant_id, repository_id, review_run_id, review_scope_identity, repository_scope_identity, source, deduplication_key, delivery_identity, artifact_identity, accepted_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
const daemonBudgetedWebhookMappingReadSQL = `SELECT review_run_id, review_scope_identity, repository_scope_identity, deduplication_key, delivery_identity, artifact_identity, accepted_at, expires_at
FROM open_trestle_webhook_deliveries
WHERE tenant_id = $1 AND repository_id = $2 AND source = $3 AND deduplication_key = $4`
const daemonBudgetedWebhookMappingListSQL = `SELECT review_run_id, review_scope_identity, repository_scope_identity, deduplication_key, delivery_identity, artifact_identity, accepted_at, expires_at
FROM open_trestle_webhook_deliveries
WHERE tenant_id = $1 AND repository_id = $2 AND source = $3 AND deduplication_key > $4 AND expires_at > $6
ORDER BY deduplication_key ASC LIMIT $5`
const daemonBudgetedjournalSQLTenantGuc = `SELECT set_config('open_trestle.tenant_id', $1, true)`
const daemonBudgetedsharedRateLimitUpdateSQL = `WITH current AS (
    SELECT request_count, expires_at <= transaction_timestamp() AS expired
    FROM open_trestle_rate_limit_windows
    WHERE namespace = $1 AND key_digest = $2 AND configuration_identity = $5
    FOR UPDATE
), updated AS (
    UPDATE open_trestle_rate_limit_windows AS limits
    SET window_started_at = CASE WHEN current.expired THEN date_bin(make_interval(secs => $3 / 1000.0), transaction_timestamp(), timestamptz '2000-01-01 00:00:00+00') ELSE limits.window_started_at END,
        request_count = CASE WHEN current.expired THEN 1 WHEN current.request_count < $4 THEN current.request_count + 1 ELSE current.request_count END,
        expires_at = CASE WHEN current.expired THEN date_bin(make_interval(secs => $3 / 1000.0), transaction_timestamp(), timestamptz '2000-01-01 00:00:00+00') + make_interval(secs => $3 / 1000.0) ELSE limits.expires_at END
    FROM current
    WHERE limits.namespace = $1 AND limits.key_digest = $2 AND limits.configuration_identity = $5
    RETURNING CASE WHEN current.expired THEN true ELSE current.request_count < $4 END AS allowed
)
SELECT allowed FROM updated`
const daemonBudgetedsharedRateLimitCleanupSQL = `DELETE FROM open_trestle_rate_limit_windows WHERE namespace = $1 AND expires_at <= transaction_timestamp()`
const daemonBudgetedsharedRateLimitConflictSQL = `SELECT configuration_identity FROM open_trestle_rate_limit_windows WHERE namespace = $1 AND key_digest = $2`
const daemonBudgetedsharedRateLimitCountSQL = `SELECT count(*) FROM open_trestle_rate_limit_windows WHERE namespace = $1`
const daemonBudgetedsharedRateLimitInsertSQL = `WITH clock AS (
    SELECT date_bin(make_interval(secs => $3 / 1000.0), transaction_timestamp(), timestamptz '2000-01-01 00:00:00+00') AS window_started_at
)
INSERT INTO open_trestle_rate_limit_windows (namespace, key_digest, configuration_identity, window_started_at, request_count, expires_at)
SELECT $1, $2, $4, window_started_at, 1, window_started_at + make_interval(secs => $3 / 1000.0) FROM clock`
const daemonBudgetedsharedRateLimitAdvisoryLockSQL = `SELECT pg_advisory_xact_lock($1)`
const daemonBudgetedjournalSQLAdmissionInsert = `INSERT INTO open_trestle_artifact_admissions (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, canonical_admission, canonical_namespace, admitted_policy, database_authority_identity, admitted_policy_identity, admitted_at_milliseconds, confirmed_version, confirmed_ciphertext_digest, confirmed_at_milliseconds) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULL, NULL, NULL)`
const daemonBudgetedjournalSQLAdmissionLockRead = `SELECT a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_admissions AS a LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE a.tenant_id = $1 AND a.repository_id = $2 AND a.review_run_id = $3 AND a.namespace_identity = $4 AND a.artifact_identity = $5 FOR UPDATE OF a`
const daemonBudgetedjournalSQLAdmissionRead = `SELECT a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_admissions AS a LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE a.tenant_id = $1 AND a.repository_id = $2 AND a.review_run_id = $3 AND a.namespace_identity = $4 AND a.artifact_identity = $5`
const daemonBudgetedjournalSQLConfirmationCas = `UPDATE open_trestle_artifact_admissions AS a SET confirmed_version = $8, confirmed_ciphertext_digest = $9, confirmed_at_milliseconds = $10 WHERE a.tenant_id = $1 AND a.repository_id = $2 AND a.review_run_id = $3 AND a.scope_identity = $4 AND a.namespace_identity = $5 AND a.artifact_identity = $6 AND a.admission_identity = $7 AND a.confirmed_version IS NULL AND a.confirmed_ciphertext_digest IS NULL AND a.confirmed_at_milliseconds IS NULL AND NOT EXISTS (SELECT 1 FROM open_trestle_artifact_erasure_operations AS o WHERE o.tenant_id = a.tenant_id AND o.repository_id = a.repository_id AND o.review_run_id = a.review_run_id AND o.namespace_identity = a.namespace_identity AND o.artifact_identity = a.artifact_identity)`
const daemonBudgetedjournalSQLKeyOccupancy = `SELECT namespace_identity, admission_identity FROM open_trestle_artifact_admissions WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4`
const daemonBudgetedjournalSQLLegacyLineage = `SELECT EXISTS (SELECT 1 FROM open_trestle_artifact_deletion_authorizations WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4), EXISTS (SELECT 1 FROM open_trestle_artifact_deletion_receipts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4)`
const daemonBudgetedjournalSQLOperationPresence = `SELECT operation_identity FROM open_trestle_artifact_erasure_operations WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND artifact_identity = $5`
const daemonBudgetedjournalSQLOperationRead = `SELECT o.tenant_id, o.repository_id, o.review_run_id, o.scope_identity, o.namespace_identity, o.artifact_identity, o.admission_identity, o.operation_identity, o.canonical_operation, o.canonical_authorization, o.accepted_policy, o.authorization_identity, o.authorization_document_digest, o.protected_policy_identity, o.database_authority_identity, o.prepared_at_milliseconds, o.accepted_at_milliseconds, a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_erasure_operations AS o LEFT JOIN open_trestle_artifact_admissions AS a ON a.tenant_id = o.tenant_id AND a.repository_id = o.repository_id AND a.review_run_id = o.review_run_id AND a.scope_identity = o.scope_identity AND a.namespace_identity = o.namespace_identity AND a.artifact_identity = o.artifact_identity AND a.admission_identity = o.admission_identity LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE o.tenant_id = $1 AND o.repository_id = $2 AND o.review_run_id = $3 AND o.namespace_identity = $4 AND o.artifact_identity = $5`
const daemonBudgetedjournalSQLOperationRefRead = `SELECT o.tenant_id, o.repository_id, o.review_run_id, o.scope_identity, o.namespace_identity, o.artifact_identity, o.admission_identity, o.operation_identity, o.canonical_operation, o.canonical_authorization, o.accepted_policy, o.authorization_identity, o.authorization_document_digest, o.protected_policy_identity, o.database_authority_identity, o.prepared_at_milliseconds, o.accepted_at_milliseconds, a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_erasure_operations AS o LEFT JOIN open_trestle_artifact_admissions AS a ON a.tenant_id = o.tenant_id AND a.repository_id = o.repository_id AND a.review_run_id = o.review_run_id AND a.scope_identity = o.scope_identity AND a.namespace_identity = o.namespace_identity AND a.artifact_identity = o.artifact_identity AND a.admission_identity = o.admission_identity LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE o.tenant_id = $1 AND o.repository_id = $2 AND o.review_run_id = $3 AND o.namespace_identity = $4 AND o.operation_identity = $5`
const daemonBudgetedjournalSQLAttributes = `SELECT a.attnum::bigint, a.attname::text, t.oid::bigint, tn.nspname::text, t.typname::text, a.atttypmod::bigint, a.attnotnull, a.attisdropped, a.attgenerated::text, a.attidentity::text, pg_catalog.pg_get_expr(d.adbin, d.adrelid, false) FROM pg_catalog.pg_attribute AS a JOIN pg_catalog.pg_type AS t ON t.oid = a.atttypid JOIN pg_catalog.pg_namespace AS tn ON tn.oid = t.typnamespace LEFT JOIN pg_catalog.pg_attrdef AS d ON d.adrelid = a.attrelid AND d.adnum = a.attnum WHERE a.attrelid = $1::oid AND a.attnum > 0 ORDER BY a.attnum ASC`
const daemonBudgetedjournalSQLConfirmationPrivileges = `SELECT pg_catalog.has_column_privilege($2, $1::oid, 'confirmed_version', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'confirmed_ciphertext_digest', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'confirmed_at_milliseconds', 'UPDATE')`
const daemonBudgetedjournalSQLConstraints = `SELECT c.oid::bigint, c.conname::text, c.contype::text, c.convalidated, c.condeferrable, c.condeferred, c.conislocal, c.coninhcount::bigint, COALESCE(pg_catalog.array_to_string(c.conkey, ','), ''), c.confrelid::bigint, COALESCE(pg_catalog.array_to_string(c.confkey, ','), ''), CASE WHEN c.contype = 'f' THEN c.confmatchtype::text ELSE '' END, CASE WHEN c.contype = 'f' THEN c.confupdtype::text ELSE '' END, CASE WHEN c.contype = 'f' THEN c.confdeltype::text ELSE '' END, pg_catalog.pg_get_expr(c.conbin, c.conrelid, false) FROM pg_catalog.pg_constraint AS c WHERE c.conrelid = $1::oid ORDER BY c.conname ASC`
const daemonBudgetedjournalSQLIndexes = `SELECT ic.oid::bigint, ic.relname::text, am.amname::text, i.indisprimary, i.indisunique, i.indisvalid, i.indisready, i.indislive, i.indimmediate, i.indnkeyatts::bigint, i.indnatts::bigint, i.indkey::text, i.indoption::text, pg_catalog.pg_get_expr(i.indexprs, i.indrelid, false), pg_catalog.pg_get_expr(i.indpred, i.indrelid, false) FROM pg_catalog.pg_index AS i JOIN pg_catalog.pg_class AS ic ON ic.oid = i.indexrelid JOIN pg_catalog.pg_am AS am ON am.oid = ic.relam WHERE i.indrelid = $1::oid ORDER BY ic.relname ASC`
const daemonBudgetedjournalSQLPolicies = `SELECT p.oid::bigint, p.polname::text, p.polcmd::text, p.polpermissive, pg_catalog.array_to_string(p.polroles, ','), pg_catalog.pg_get_expr(p.polqual, p.polrelid, false), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid, false) FROM pg_catalog.pg_policy AS p WHERE p.polrelid = $1::oid ORDER BY p.polname ASC`
const daemonBudgetedjournalSQLRelation = `SELECT c.oid::bigint, n.oid::bigint, n.nspname::text, c.relname::text, c.relkind::text, c.relrowsecurity, c.relforcerowsecurity, pg_catalog.to_regclass($2)::oid::bigint FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2`
const daemonBudgetedjournalSQLRole = `SELECT r.oid::bigint, r.rolname::text, r.rolsuper, r.rolbypassrls, pg_catalog.current_setting('row_security') FROM pg_catalog.pg_roles AS r WHERE r.rolname = CURRENT_USER`
const daemonBudgetedjournalSQLTablePrivileges = `SELECT pg_catalog.has_schema_privilege($2, $3, 'USAGE'), pg_catalog.has_table_privilege($2, $1::oid, 'SELECT'), pg_catalog.has_table_privilege($2, $1::oid, 'INSERT'), pg_catalog.has_table_privilege($2, $1::oid, 'UPDATE'), pg_catalog.has_table_privilege($2, $1::oid, 'DELETE'), pg_catalog.has_table_privilege($2, $1::oid, 'TRUNCATE'), pg_catalog.has_any_column_privilege($2, $1::oid, 'UPDATE')`
const daemonBudgetedresumeSQLAllowanceCounterPrivileges = `SELECT pg_catalog.has_column_privilege($2, $1::oid, 'spent_requests', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_mutations', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_reads', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_lists', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_creates', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_deletes', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_pages', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_versions', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_response_bytes', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_list_bytes', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'spent_write_bytes', 'UPDATE')`
const daemonBudgetedresumeSQLAllowanceImmutablePrivileges = `SELECT pg_catalog.has_column_privilege($2, $1::oid, 'tenant_id', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'repository_id', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'review_run_id', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'scope_identity', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'namespace_identity', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'artifact_identity', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'admission_identity', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'operation_identity', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'allowance_identity', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'canonical_allowance', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'allowance_document_digest', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'accepted_policy', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'protected_policy_identity', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'accepted_at_milliseconds', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_requests', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_mutations', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_reads', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_lists', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_creates', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_deletes', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_pages', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_versions', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_response_bytes', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_list_bytes', 'UPDATE'), pg_catalog.has_column_privilege($2, $1::oid, 'maximum_write_bytes', 'UPDATE')`
const daemonBudgetedresumeSQLUserTriggers = `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger AS t WHERE t.tgrelid = $1::oid AND NOT t.tgisinternal)`

const daemonBudgetedErasureDescriptorJSON = `{"open_trestle_review_scopes":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"registered_at","type":"timestamptz","nullable":false,"default_expression":"transaction_timestamp()"}],"constraints":[{"kind":"CHECK","expression":"octet_length(tenant_id) BETWEEN 1 AND 128","referenced_columns":["tenant_id"]},{"kind":"CHECK","expression":"octet_length(repository_id) BETWEEN 1 AND 128","referenced_columns":["repository_id"]},{"kind":"CHECK","expression":"octet_length(review_run_id) BETWEEN 1 AND 128","referenced_columns":["review_run_id"]},{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["scope_identity"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id"]},{"kind":"UNIQUE","columns":["scope_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","scope_identity"]}],"indexes":[{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id"],"unique":true,"primary":true,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["scope_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","scope_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"}],"flags":{"kind":"r","enable_rls":true,"force_rls":true},"policy":{"name":"<table>_tenant_isolation","command":"*","roles":[0],"permissive":true,"using":"tenant_id = current_setting('open_trestle.tenant_id', true)","with_check":"tenant_id = current_setting('open_trestle.tenant_id', true)"}},"open_trestle_artifacts":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"payload_digest","type":"text","nullable":false,"default_expression":null},{"name":"kind","type":"text","nullable":false,"default_expression":null},{"name":"classification","type":"text","nullable":false,"default_expression":null},{"name":"origin","type":"text","nullable":false,"default_expression":null},{"name":"protection","type":"text","nullable":false,"default_expression":null},{"name":"created_at","type":"timestamptz","nullable":false,"default_expression":null},{"name":"expires_at","type":"timestamptz","nullable":false,"default_expression":null},{"name":"registered_at","type":"timestamptz","nullable":false,"default_expression":"transaction_timestamp()"}],"constraints":[{"kind":"CHECK","expression":"octet_length(tenant_id) BETWEEN 1 AND 128","referenced_columns":["tenant_id"]},{"kind":"CHECK","expression":"octet_length(repository_id) BETWEEN 1 AND 128","referenced_columns":["repository_id"]},{"kind":"CHECK","expression":"octet_length(review_run_id) BETWEEN 1 AND 128","referenced_columns":["review_run_id"]},{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"payload_digest ~ '^[0-9a-f]{64}$'","referenced_columns":["payload_digest"]},{"kind":"CHECK","expression":"kind IN ('source_snapshot', 'change_model', 'deterministic_evidence', 'retrieval_result', 'context_packet', 'candidate_batch', 'verification_batch', 'verified_finding_set', 'publication_plan', 'run_export', 'task_input', 'webhook_delivery', 'source_file', 'publication_receipt', 'investigation_turn', 'investigation_tool_result')","referenced_columns":["kind"]},{"kind":"CHECK","expression":"classification IN ('public', 'internal', 'confidential', 'restricted')","referenced_columns":["classification"]},{"kind":"CHECK","expression":"origin IN ('host', 'repository', 'deterministic_tool', 'model', 'independent_verifier', 'policy', 'memory')","referenced_columns":["origin"]},{"kind":"CHECK","expression":"protection IN ('process_private', 'envelope_encrypted')","referenced_columns":["protection"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","artifact_identity"]},{"kind":"UNIQUE","columns":["scope_identity","artifact_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity"],"target_table":"open_trestle_review_scopes","target_columns":["tenant_id","repository_id","review_run_id","scope_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"},{"kind":"CHECK","expression":"expires_at > created_at","referenced_columns":["expires_at","created_at"]}],"indexes":[{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"unique":true,"primary":true,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["scope_identity","artifact_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"},{"name":"open_trestle_artifacts_expiry","columns":["tenant_id","repository_id","expires_at","artifact_identity"],"unique":false,"primary":false,"method":"btree","order":"ASC NULLS LAST"}],"flags":{"kind":"r","enable_rls":true,"force_rls":true},"policy":{"name":"<table>_tenant_isolation","command":"*","roles":[0],"permissive":true,"using":"tenant_id = current_setting('open_trestle.tenant_id', true)","with_check":"tenant_id = current_setting('open_trestle.tenant_id', true)"}},"open_trestle_artifact_deletion_authorizations":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"authorization_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"policy_identity","type":"text","nullable":false,"default_expression":null},{"name":"principal_identity","type":"text","nullable":false,"default_expression":null},{"name":"hold_clearance_identity","type":"text","nullable":false,"default_expression":null},{"name":"reason","type":"text","nullable":false,"default_expression":null},{"name":"issued_at","type":"timestamptz","nullable":false,"default_expression":null},{"name":"expires_at","type":"timestamptz","nullable":false,"default_expression":null},{"name":"registered_at","type":"timestamptz","nullable":false,"default_expression":"transaction_timestamp()"}],"constraints":[{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"authorization_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["authorization_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"policy_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["policy_identity"]},{"kind":"CHECK","expression":"hold_clearance_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["hold_clearance_identity"]},{"kind":"CHECK","expression":"octet_length(principal_identity) BETWEEN 1 AND 128","referenced_columns":["principal_identity"]},{"kind":"CHECK","expression":"reason IN ('expired', 'tenant_erasure', 'repository_erasure')","referenced_columns":["reason"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","authorization_identity"]},{"kind":"UNIQUE","columns":["scope_identity","authorization_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity"],"target_table":"open_trestle_review_scopes","target_columns":["tenant_id","repository_id","review_run_id","scope_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"target_table":"open_trestle_artifacts","target_columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"},{"kind":"CHECK","expression":"expires_at > issued_at","referenced_columns":["expires_at","issued_at"]}],"indexes":[{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","authorization_identity"],"unique":true,"primary":true,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["scope_identity","authorization_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"}],"flags":{"kind":"r","enable_rls":true,"force_rls":true},"policy":{"name":"<table>_tenant_isolation","command":"*","roles":[0],"permissive":true,"using":"tenant_id = current_setting('open_trestle.tenant_id', true)","with_check":"tenant_id = current_setting('open_trestle.tenant_id', true)"}},"open_trestle_artifact_deletion_receipts":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"receipt_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"payload_digest","type":"text","nullable":false,"default_expression":null},{"name":"authorization_identity","type":"text","nullable":false,"default_expression":null},{"name":"deleted_at","type":"timestamptz","nullable":false,"default_expression":null},{"name":"registered_at","type":"timestamptz","nullable":false,"default_expression":"transaction_timestamp()"}],"constraints":[{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"receipt_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["receipt_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"payload_digest ~ '^[0-9a-f]{64}$'","referenced_columns":["payload_digest"]},{"kind":"CHECK","expression":"authorization_identity ~ '^[0-9a-f]{64}$'","referenced_columns":["authorization_identity"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","receipt_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","artifact_identity"]},{"kind":"UNIQUE","columns":["scope_identity","receipt_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity"],"target_table":"open_trestle_review_scopes","target_columns":["tenant_id","repository_id","review_run_id","scope_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"target_table":"open_trestle_artifacts","target_columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","authorization_identity"],"target_table":"open_trestle_artifact_deletion_authorizations","target_columns":["tenant_id","repository_id","review_run_id","authorization_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"}],"indexes":[{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","receipt_identity"],"unique":true,"primary":true,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["scope_identity","receipt_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"}],"flags":{"kind":"r","enable_rls":true,"force_rls":true},"policy":{"name":"<table>_tenant_isolation","command":"*","roles":[0],"permissive":true,"using":"tenant_id = current_setting('open_trestle.tenant_id', true)","with_check":"tenant_id = current_setting('open_trestle.tenant_id', true)"}},"open_trestle_artifact_admissions":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"namespace_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"admission_identity","type":"text","nullable":false,"default_expression":null},{"name":"canonical_admission","type":"bytea","nullable":false,"default_expression":null},{"name":"canonical_namespace","type":"bytea","nullable":false,"default_expression":null},{"name":"admitted_policy","type":"bytea","nullable":false,"default_expression":null},{"name":"database_authority_identity","type":"text","nullable":false,"default_expression":null},{"name":"admitted_policy_identity","type":"text","nullable":false,"default_expression":null},{"name":"admitted_at_milliseconds","type":"int8","nullable":false,"default_expression":null},{"name":"confirmed_version","type":"text","nullable":true,"default_expression":null},{"name":"confirmed_ciphertext_digest","type":"text","nullable":true,"default_expression":null},{"name":"confirmed_at_milliseconds","type":"int8","nullable":true,"default_expression":null}],"constraints":[{"kind":"CHECK","expression":"octet_length(tenant_id) BETWEEN 1 AND 128","referenced_columns":["tenant_id"]},{"kind":"CHECK","expression":"octet_length(repository_id) BETWEEN 1 AND 128","referenced_columns":["repository_id"]},{"kind":"CHECK","expression":"octet_length(review_run_id) BETWEEN 1 AND 128","referenced_columns":["review_run_id"]},{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["namespace_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["admission_identity"]},{"kind":"CHECK","expression":"database_authority_identity ~ '^[0-9a-f]{64}$' AND database_authority_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["database_authority_identity"]},{"kind":"CHECK","expression":"admitted_policy_identity ~ '^[0-9a-f]{64}$' AND admitted_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["admitted_policy_identity"]},{"kind":"CHECK","expression":"octet_length(canonical_admission) BETWEEN 1 AND 16384","referenced_columns":["canonical_admission"]},{"kind":"CHECK","expression":"octet_length(canonical_namespace) BETWEEN 1 AND 4096","referenced_columns":["canonical_namespace"]},{"kind":"CHECK","expression":"octet_length(admitted_policy) BETWEEN 1 AND 16384","referenced_columns":["admitted_policy"]},{"kind":"CHECK","expression":"admitted_at_milliseconds BETWEEN 1 AND 253402300799999","referenced_columns":["admitted_at_milliseconds"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","artifact_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","namespace_identity","admission_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"target_table":"open_trestle_artifacts","target_columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity"],"target_table":"open_trestle_review_scopes","target_columns":["tenant_id","repository_id","review_run_id","scope_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"},{"kind":"CHECK","expression":"(confirmed_version IS NULL AND confirmed_ciphertext_digest IS NULL AND confirmed_at_milliseconds IS NULL) OR (confirmed_version IS NOT NULL AND confirmed_ciphertext_digest IS NOT NULL AND confirmed_at_milliseconds IS NOT NULL AND left(confirmed_version, 8) = 'version:' AND octet_length(confirmed_version) BETWEEN 9 AND 512 AND confirmed_version <> 'version:null' AND confirmed_version !~ '[[:space:][:cntrl:]]' AND confirmed_ciphertext_digest ~ '^[0-9a-f]{64}$' AND confirmed_ciphertext_digest <> '0000000000000000000000000000000000000000000000000000000000000000' AND confirmed_at_milliseconds BETWEEN 1 AND 253402300799999 AND confirmed_at_milliseconds >= admitted_at_milliseconds)","referenced_columns":["confirmed_version","confirmed_ciphertext_digest","confirmed_at_milliseconds","admitted_at_milliseconds"]}],"indexes":[{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"unique":true,"primary":true,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","namespace_identity","admission_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"},{"name":"open_trestle_artifact_admissions_scan","columns":["tenant_id","repository_id","namespace_identity","review_run_id","artifact_identity"],"unique":false,"primary":false,"method":"btree","order":"ASC NULLS LAST"}],"flags":{"kind":"r","enable_rls":true,"force_rls":true},"policy":{"name":"<table>_tenant_isolation","command":"*","roles":[0],"permissive":true,"using":"tenant_id = current_setting('open_trestle.tenant_id', true)","with_check":"tenant_id = current_setting('open_trestle.tenant_id', true)"}},"open_trestle_artifact_erasure_operations":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"namespace_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"admission_identity","type":"text","nullable":false,"default_expression":null},{"name":"operation_identity","type":"text","nullable":false,"default_expression":null},{"name":"canonical_operation","type":"bytea","nullable":false,"default_expression":null},{"name":"canonical_authorization","type":"bytea","nullable":false,"default_expression":null},{"name":"accepted_policy","type":"bytea","nullable":false,"default_expression":null},{"name":"authorization_identity","type":"text","nullable":false,"default_expression":null},{"name":"authorization_document_digest","type":"text","nullable":false,"default_expression":null},{"name":"protected_policy_identity","type":"text","nullable":false,"default_expression":null},{"name":"database_authority_identity","type":"text","nullable":false,"default_expression":null},{"name":"prepared_at_milliseconds","type":"int8","nullable":false,"default_expression":null},{"name":"accepted_at_milliseconds","type":"int8","nullable":false,"default_expression":null}],"constraints":[{"kind":"CHECK","expression":"octet_length(tenant_id) BETWEEN 1 AND 128","referenced_columns":["tenant_id"]},{"kind":"CHECK","expression":"octet_length(repository_id) BETWEEN 1 AND 128","referenced_columns":["repository_id"]},{"kind":"CHECK","expression":"octet_length(review_run_id) BETWEEN 1 AND 128","referenced_columns":["review_run_id"]},{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["namespace_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["admission_identity"]},{"kind":"CHECK","expression":"operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["operation_identity"]},{"kind":"CHECK","expression":"authorization_identity ~ '^[0-9a-f]{64}$' AND authorization_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["authorization_identity"]},{"kind":"CHECK","expression":"authorization_document_digest ~ '^[0-9a-f]{64}$' AND authorization_document_digest <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["authorization_document_digest"]},{"kind":"CHECK","expression":"protected_policy_identity ~ '^[0-9a-f]{64}$' AND protected_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["protected_policy_identity"]},{"kind":"CHECK","expression":"database_authority_identity ~ '^[0-9a-f]{64}$' AND database_authority_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["database_authority_identity"]},{"kind":"CHECK","expression":"octet_length(canonical_operation) BETWEEN 1 AND 16384","referenced_columns":["canonical_operation"]},{"kind":"CHECK","expression":"octet_length(canonical_authorization) BETWEEN 1 AND 8192","referenced_columns":["canonical_authorization"]},{"kind":"CHECK","expression":"octet_length(accepted_policy) BETWEEN 1 AND 16384","referenced_columns":["accepted_policy"]},{"kind":"CHECK","expression":"prepared_at_milliseconds BETWEEN 1 AND 253402300799999","referenced_columns":["prepared_at_milliseconds"]},{"kind":"CHECK","expression":"accepted_at_milliseconds BETWEEN 1 AND 253402300799999","referenced_columns":["accepted_at_milliseconds"]},{"kind":"CHECK","expression":"accepted_at_milliseconds >= prepared_at_milliseconds","referenced_columns":["accepted_at_milliseconds","prepared_at_milliseconds"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","artifact_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity"],"target_table":"open_trestle_artifact_admissions","target_columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity"],"match":"SIMPLE","on_update":"NO ACTION","on_delete":"NO ACTION"}],"indexes":[{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity"],"unique":true,"primary":true,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","artifact_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"},{"name":"constraint-owned-name-not-authority","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"],"unique":true,"primary":false,"method":"btree","order":"ASC NULLS LAST"}],"flags":{"kind":"r","enable_rls":true,"force_rls":true},"policy":{"name":"<table>_tenant_isolation","command":"*","roles":[0],"permissive":true,"using":"tenant_id = current_setting('open_trestle.tenant_id', true)","with_check":"tenant_id = current_setting('open_trestle.tenant_id', true)"}}}`
const daemonBudgetedResumeDescriptorJSON = `{"open_trestle_erasure_resume_allowances":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"namespace_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"admission_identity","type":"text","nullable":false,"default_expression":null},{"name":"operation_identity","type":"text","nullable":false,"default_expression":null},{"name":"allowance_identity","type":"text","nullable":false,"default_expression":null},{"name":"canonical_allowance","type":"bytea","nullable":false,"default_expression":null},{"name":"allowance_document_digest","type":"text","nullable":false,"default_expression":null},{"name":"accepted_policy","type":"bytea","nullable":false,"default_expression":null},{"name":"protected_policy_identity","type":"text","nullable":false,"default_expression":null},{"name":"accepted_at_milliseconds","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_requests","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_mutations","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_reads","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_lists","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_creates","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_deletes","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_pages","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_versions","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_response_bytes","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_list_bytes","type":"int8","nullable":false,"default_expression":null},{"name":"maximum_write_bytes","type":"int8","nullable":false,"default_expression":null},{"name":"spent_requests","type":"int8","nullable":false,"default_expression":null},{"name":"spent_mutations","type":"int8","nullable":false,"default_expression":null},{"name":"spent_reads","type":"int8","nullable":false,"default_expression":null},{"name":"spent_lists","type":"int8","nullable":false,"default_expression":null},{"name":"spent_creates","type":"int8","nullable":false,"default_expression":null},{"name":"spent_deletes","type":"int8","nullable":false,"default_expression":null},{"name":"spent_pages","type":"int8","nullable":false,"default_expression":null},{"name":"spent_versions","type":"int8","nullable":false,"default_expression":null},{"name":"spent_response_bytes","type":"int8","nullable":false,"default_expression":null},{"name":"spent_list_bytes","type":"int8","nullable":false,"default_expression":null},{"name":"spent_write_bytes","type":"int8","nullable":false,"default_expression":null}],"constraints":[{"kind":"CHECK","expression":"octet_length(tenant_id) BETWEEN 1 AND 128","referenced_columns":["tenant_id"]},{"kind":"CHECK","expression":"octet_length(repository_id) BETWEEN 1 AND 128","referenced_columns":["repository_id"]},{"kind":"CHECK","expression":"octet_length(review_run_id) BETWEEN 1 AND 128","referenced_columns":["review_run_id"]},{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["namespace_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["admission_identity"]},{"kind":"CHECK","expression":"operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["operation_identity"]},{"kind":"CHECK","expression":"allowance_identity ~ '^[0-9a-f]{64}$' AND allowance_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["allowance_identity"]},{"kind":"CHECK","expression":"octet_length(canonical_allowance) BETWEEN 1 AND 4096","referenced_columns":["canonical_allowance"]},{"kind":"CHECK","expression":"allowance_document_digest ~ '^[0-9a-f]{64}$' AND allowance_document_digest <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["allowance_document_digest"]},{"kind":"CHECK","expression":"octet_length(accepted_policy) BETWEEN 1 AND 16384","referenced_columns":["accepted_policy"]},{"kind":"CHECK","expression":"protected_policy_identity ~ '^[0-9a-f]{64}$' AND protected_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["protected_policy_identity"]},{"kind":"CHECK","expression":"accepted_at_milliseconds BETWEEN 1 AND 253402300799999","referenced_columns":["accepted_at_milliseconds"]},{"kind":"CHECK","expression":"maximum_requests BETWEEN 0 AND 4096","referenced_columns":["maximum_requests"]},{"kind":"CHECK","expression":"maximum_mutations BETWEEN 0 AND 2048","referenced_columns":["maximum_mutations"]},{"kind":"CHECK","expression":"maximum_reads BETWEEN 0 AND 2048","referenced_columns":["maximum_reads"]},{"kind":"CHECK","expression":"maximum_lists BETWEEN 0 AND 1024","referenced_columns":["maximum_lists"]},{"kind":"CHECK","expression":"maximum_creates BETWEEN 0 AND 128","referenced_columns":["maximum_creates"]},{"kind":"CHECK","expression":"maximum_deletes BETWEEN 0 AND 2048","referenced_columns":["maximum_deletes"]},{"kind":"CHECK","expression":"maximum_pages BETWEEN 0 AND 1024","referenced_columns":["maximum_pages"]},{"kind":"CHECK","expression":"maximum_versions BETWEEN 0 AND 262144","referenced_columns":["maximum_versions"]},{"kind":"CHECK","expression":"maximum_response_bytes BETWEEN 0 AND 1073741824","referenced_columns":["maximum_response_bytes"]},{"kind":"CHECK","expression":"maximum_list_bytes BETWEEN 0 AND 67108864","referenced_columns":["maximum_list_bytes"]},{"kind":"CHECK","expression":"maximum_write_bytes BETWEEN 0 AND 2097152","referenced_columns":["maximum_write_bytes"]},{"kind":"CHECK","expression":"spent_requests BETWEEN 0 AND maximum_requests","referenced_columns":["spent_requests"]},{"kind":"CHECK","expression":"spent_mutations BETWEEN 0 AND maximum_mutations","referenced_columns":["spent_mutations"]},{"kind":"CHECK","expression":"spent_reads BETWEEN 0 AND maximum_reads","referenced_columns":["spent_reads"]},{"kind":"CHECK","expression":"spent_lists BETWEEN 0 AND maximum_lists","referenced_columns":["spent_lists"]},{"kind":"CHECK","expression":"spent_creates BETWEEN 0 AND maximum_creates","referenced_columns":["spent_creates"]},{"kind":"CHECK","expression":"spent_deletes BETWEEN 0 AND maximum_deletes","referenced_columns":["spent_deletes"]},{"kind":"CHECK","expression":"spent_pages BETWEEN 0 AND maximum_pages","referenced_columns":["spent_pages"]},{"kind":"CHECK","expression":"spent_versions BETWEEN 0 AND maximum_versions","referenced_columns":["spent_versions"]},{"kind":"CHECK","expression":"spent_response_bytes BETWEEN 0 AND maximum_response_bytes","referenced_columns":["spent_response_bytes"]},{"kind":"CHECK","expression":"spent_list_bytes BETWEEN 0 AND maximum_list_bytes","referenced_columns":["spent_list_bytes"]},{"kind":"CHECK","expression":"spent_write_bytes BETWEEN 0 AND maximum_write_bytes","referenced_columns":["spent_write_bytes"]},{"kind":"CHECK","expression":"maximum_requests >= 1","referenced_columns":["maximum_requests"]},{"kind":"CHECK","expression":"maximum_mutations <= maximum_requests","referenced_columns":["maximum_requests","maximum_mutations"]},{"kind":"CHECK","expression":"spent_mutations <= spent_requests","referenced_columns":["spent_requests","spent_mutations"]},{"kind":"CHECK","expression":"spent_reads + spent_lists + spent_creates + spent_deletes = spent_requests","referenced_columns":["spent_requests","spent_reads","spent_lists","spent_creates","spent_deletes"]},{"kind":"CHECK","expression":"spent_mutations = spent_creates + spent_deletes","referenced_columns":["spent_mutations","spent_creates","spent_deletes"]},{"kind":"CHECK","expression":"spent_pages = spent_lists","referenced_columns":["spent_lists","spent_pages"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","allowance_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","allowance_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"],"target_table":"open_trestle_artifact_erasure_operations","target_columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"]}],"indexes":[{"name":"open_trestle_erasure_resume_allowances_pkey","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","allowance_identity"],"unique":true,"primary":true},{"name":"open_trestle_erasure_resume_allowances_u1","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","allowance_identity"],"unique":true,"primary":false}]},"open_trestle_erasure_attempts":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"namespace_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"admission_identity","type":"text","nullable":false,"default_expression":null},{"name":"operation_identity","type":"text","nullable":false,"default_expression":null},{"name":"allowance_identity","type":"text","nullable":false,"default_expression":null},{"name":"reservation_identity","type":"text","nullable":false,"default_expression":null},{"name":"attempt_identity","type":"text","nullable":false,"default_expression":null},{"name":"request_identity","type":"text","nullable":false,"default_expression":null},{"name":"canonical_request","type":"bytea","nullable":false,"default_expression":null},{"name":"canonical_attempt","type":"bytea","nullable":false,"default_expression":null},{"name":"sequence","type":"int8","nullable":false,"default_expression":null},{"name":"reserved_at_milliseconds","type":"int8","nullable":false,"default_expression":null},{"name":"cost_requests","type":"int8","nullable":false,"default_expression":null},{"name":"cost_mutations","type":"int8","nullable":false,"default_expression":null},{"name":"cost_reads","type":"int8","nullable":false,"default_expression":null},{"name":"cost_lists","type":"int8","nullable":false,"default_expression":null},{"name":"cost_creates","type":"int8","nullable":false,"default_expression":null},{"name":"cost_deletes","type":"int8","nullable":false,"default_expression":null},{"name":"cost_pages","type":"int8","nullable":false,"default_expression":null},{"name":"cost_versions","type":"int8","nullable":false,"default_expression":null},{"name":"cost_response_bytes","type":"int8","nullable":false,"default_expression":null},{"name":"cost_list_bytes","type":"int8","nullable":false,"default_expression":null},{"name":"cost_write_bytes","type":"int8","nullable":false,"default_expression":null}],"constraints":[{"kind":"CHECK","expression":"octet_length(tenant_id) BETWEEN 1 AND 128","referenced_columns":["tenant_id"]},{"kind":"CHECK","expression":"octet_length(repository_id) BETWEEN 1 AND 128","referenced_columns":["repository_id"]},{"kind":"CHECK","expression":"octet_length(review_run_id) BETWEEN 1 AND 128","referenced_columns":["review_run_id"]},{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["namespace_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["admission_identity"]},{"kind":"CHECK","expression":"operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["operation_identity"]},{"kind":"CHECK","expression":"allowance_identity ~ '^[0-9a-f]{64}$' AND allowance_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["allowance_identity"]},{"kind":"CHECK","expression":"reservation_identity ~ '^[0-9a-f]{64}$' AND reservation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["reservation_identity"]},{"kind":"CHECK","expression":"attempt_identity ~ '^[0-9a-f]{64}$' AND attempt_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["attempt_identity"]},{"kind":"CHECK","expression":"request_identity ~ '^[0-9a-f]{64}$' AND request_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["request_identity"]},{"kind":"CHECK","expression":"octet_length(canonical_request) BETWEEN 1 AND 8192","referenced_columns":["canonical_request"]},{"kind":"CHECK","expression":"octet_length(canonical_attempt) BETWEEN 1 AND 1024","referenced_columns":["canonical_attempt"]},{"kind":"CHECK","expression":"sequence BETWEEN 1 AND 4096","referenced_columns":["sequence"]},{"kind":"CHECK","expression":"reserved_at_milliseconds BETWEEN 1 AND 253402300799999","referenced_columns":["reserved_at_milliseconds"]},{"kind":"CHECK","expression":"cost_requests BETWEEN 0 AND 4096","referenced_columns":["cost_requests"]},{"kind":"CHECK","expression":"cost_mutations BETWEEN 0 AND 2048","referenced_columns":["cost_mutations"]},{"kind":"CHECK","expression":"cost_reads BETWEEN 0 AND 2048","referenced_columns":["cost_reads"]},{"kind":"CHECK","expression":"cost_lists BETWEEN 0 AND 1024","referenced_columns":["cost_lists"]},{"kind":"CHECK","expression":"cost_creates BETWEEN 0 AND 128","referenced_columns":["cost_creates"]},{"kind":"CHECK","expression":"cost_deletes BETWEEN 0 AND 2048","referenced_columns":["cost_deletes"]},{"kind":"CHECK","expression":"cost_pages BETWEEN 0 AND 1024","referenced_columns":["cost_pages"]},{"kind":"CHECK","expression":"cost_versions BETWEEN 0 AND 262144","referenced_columns":["cost_versions"]},{"kind":"CHECK","expression":"cost_response_bytes BETWEEN 0 AND 1073741824","referenced_columns":["cost_response_bytes"]},{"kind":"CHECK","expression":"cost_list_bytes BETWEEN 0 AND 67108864","referenced_columns":["cost_list_bytes"]},{"kind":"CHECK","expression":"cost_write_bytes BETWEEN 0 AND 2097152","referenced_columns":["cost_write_bytes"]},{"kind":"CHECK","expression":"cost_requests = 1","referenced_columns":["cost_requests"]},{"kind":"CHECK","expression":"cost_mutations = cost_creates + cost_deletes","referenced_columns":["cost_mutations","cost_creates","cost_deletes"]},{"kind":"CHECK","expression":"cost_reads + cost_lists + cost_creates + cost_deletes = 1","referenced_columns":["cost_reads","cost_lists","cost_creates","cost_deletes"]},{"kind":"CHECK","expression":"cost_pages = cost_lists","referenced_columns":["cost_lists","cost_pages"]},{"kind":"CHECK","expression":"cost_mutations BETWEEN 0 AND 1","referenced_columns":["cost_mutations"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","reservation_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","attempt_identity"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","allowance_identity","sequence"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","attempt_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"],"target_table":"open_trestle_artifact_erasure_operations","target_columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","allowance_identity"],"target_table":"open_trestle_erasure_resume_allowances","target_columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","allowance_identity"]}],"indexes":[{"name":"open_trestle_erasure_attempts_pkey","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","reservation_identity"],"unique":true,"primary":true},{"name":"open_trestle_erasure_attempts_u1","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","attempt_identity"],"unique":true,"primary":false},{"name":"open_trestle_erasure_attempts_u2","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","allowance_identity","sequence"],"unique":true,"primary":false},{"name":"open_trestle_erasure_attempts_u3","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","attempt_identity"],"unique":true,"primary":false}]},"open_trestle_erasure_attempt_evidence":{"columns":[{"name":"tenant_id","type":"text","nullable":false,"default_expression":null},{"name":"repository_id","type":"text","nullable":false,"default_expression":null},{"name":"review_run_id","type":"text","nullable":false,"default_expression":null},{"name":"scope_identity","type":"text","nullable":false,"default_expression":null},{"name":"namespace_identity","type":"text","nullable":false,"default_expression":null},{"name":"artifact_identity","type":"text","nullable":false,"default_expression":null},{"name":"admission_identity","type":"text","nullable":false,"default_expression":null},{"name":"operation_identity","type":"text","nullable":false,"default_expression":null},{"name":"evidence_identity","type":"text","nullable":false,"default_expression":null},{"name":"slot","type":"text","nullable":false,"default_expression":null},{"name":"kind","type":"text","nullable":false,"default_expression":null},{"name":"attempt_identity","type":"text","nullable":true,"default_expression":null},{"name":"canonical_evidence","type":"bytea","nullable":false,"default_expression":null},{"name":"observed_at_milliseconds","type":"int8","nullable":false,"default_expression":null}],"constraints":[{"kind":"CHECK","expression":"octet_length(tenant_id) BETWEEN 1 AND 128","referenced_columns":["tenant_id"]},{"kind":"CHECK","expression":"octet_length(repository_id) BETWEEN 1 AND 128","referenced_columns":["repository_id"]},{"kind":"CHECK","expression":"octet_length(review_run_id) BETWEEN 1 AND 128","referenced_columns":["review_run_id"]},{"kind":"CHECK","expression":"scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["scope_identity"]},{"kind":"CHECK","expression":"namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["namespace_identity"]},{"kind":"CHECK","expression":"artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["artifact_identity"]},{"kind":"CHECK","expression":"admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["admission_identity"]},{"kind":"CHECK","expression":"operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["operation_identity"]},{"kind":"CHECK","expression":"evidence_identity ~ '^[0-9a-f]{64}$' AND evidence_identity <> '0000000000000000000000000000000000000000000000000000000000000000'","referenced_columns":["evidence_identity"]},{"kind":"CHECK","expression":"octet_length(slot) BETWEEN 1 AND 80","referenced_columns":["slot"]},{"kind":"CHECK","expression":"kind IN ('response', 'unknown', 'fence', 'verification', 'candidate', 'published')","referenced_columns":["kind"]},{"kind":"CHECK","expression":"attempt_identity IS NULL OR (attempt_identity ~ '^[0-9a-f]{64}$' AND attempt_identity <> '0000000000000000000000000000000000000000000000000000000000000000')","referenced_columns":["attempt_identity"]},{"kind":"CHECK","expression":"octet_length(canonical_evidence) BETWEEN 1 AND 1048576","referenced_columns":["canonical_evidence"]},{"kind":"CHECK","expression":"observed_at_milliseconds BETWEEN 1 AND 253402300799999","referenced_columns":["observed_at_milliseconds"]},{"kind":"CHECK","expression":"(kind = 'response' AND attempt_identity IS NOT NULL AND slot = 'response:' || attempt_identity) OR (kind = 'unknown' AND attempt_identity IS NOT NULL AND slot = 'unknown:' || attempt_identity) OR (kind = 'fence' AND attempt_identity IS NULL AND slot = 'fence') OR (kind = 'verification' AND attempt_identity IS NULL AND slot ~ '^verification:[0-9a-f]{64}$') OR (kind = 'candidate' AND attempt_identity IS NULL AND slot = 'candidate') OR (kind = 'published' AND attempt_identity IS NULL AND slot = 'published')","referenced_columns":["slot","kind","attempt_identity"]},{"kind":"PRIMARY KEY","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","slot"]},{"kind":"UNIQUE","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","evidence_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"],"target_table":"open_trestle_artifact_erasure_operations","target_columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity"]},{"kind":"FOREIGN KEY","columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","attempt_identity"],"target_table":"open_trestle_erasure_attempts","target_columns":["tenant_id","repository_id","review_run_id","scope_identity","namespace_identity","artifact_identity","admission_identity","operation_identity","attempt_identity"]}],"indexes":[{"name":"open_trestle_erasure_attempt_evidence_pkey","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","slot"],"unique":true,"primary":true},{"name":"open_trestle_erasure_attempt_evidence_u1","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","evidence_identity"],"unique":true,"primary":false},{"name":"open_trestle_erasure_attempt_evidence_attempt_scan","columns":["tenant_id","repository_id","review_run_id","namespace_identity","operation_identity","attempt_identity","slot"],"unique":false,"primary":false}]}}`
const daemonBudgetedResumeConstraintNamesJSON = `{"open_trestle_erasure_resume_allowances":["open_trestle_erasure_resume_allowances_c01","open_trestle_erasure_resume_allowances_c02","open_trestle_erasure_resume_allowances_c03","open_trestle_erasure_resume_allowances_c04","open_trestle_erasure_resume_allowances_c05","open_trestle_erasure_resume_allowances_c06","open_trestle_erasure_resume_allowances_c07","open_trestle_erasure_resume_allowances_c08","open_trestle_erasure_resume_allowances_c09","open_trestle_erasure_resume_allowances_c10","open_trestle_erasure_resume_allowances_c11","open_trestle_erasure_resume_allowances_c12","open_trestle_erasure_resume_allowances_c13","open_trestle_erasure_resume_allowances_c14","open_trestle_erasure_resume_allowances_c15","open_trestle_erasure_resume_allowances_c16","open_trestle_erasure_resume_allowances_c17","open_trestle_erasure_resume_allowances_c18","open_trestle_erasure_resume_allowances_c19","open_trestle_erasure_resume_allowances_c20","open_trestle_erasure_resume_allowances_c21","open_trestle_erasure_resume_allowances_c22","open_trestle_erasure_resume_allowances_c23","open_trestle_erasure_resume_allowances_c24","open_trestle_erasure_resume_allowances_c25","open_trestle_erasure_resume_allowances_c26","open_trestle_erasure_resume_allowances_c27","open_trestle_erasure_resume_allowances_c28","open_trestle_erasure_resume_allowances_c29","open_trestle_erasure_resume_allowances_c30","open_trestle_erasure_resume_allowances_c31","open_trestle_erasure_resume_allowances_c32","open_trestle_erasure_resume_allowances_c33","open_trestle_erasure_resume_allowances_c34","open_trestle_erasure_resume_allowances_c35","open_trestle_erasure_resume_allowances_c36","open_trestle_erasure_resume_allowances_x01","open_trestle_erasure_resume_allowances_x02","open_trestle_erasure_resume_allowances_x03","open_trestle_erasure_resume_allowances_x04","open_trestle_erasure_resume_allowances_x05","open_trestle_erasure_resume_allowances_x06","open_trestle_erasure_resume_allowances_pkey","open_trestle_erasure_resume_allowances_u1","open_trestle_erasure_resume_allowances_f1"],"open_trestle_erasure_attempts":["open_trestle_erasure_attempts_c01","open_trestle_erasure_attempts_c02","open_trestle_erasure_attempts_c03","open_trestle_erasure_attempts_c04","open_trestle_erasure_attempts_c05","open_trestle_erasure_attempts_c06","open_trestle_erasure_attempts_c07","open_trestle_erasure_attempts_c08","open_trestle_erasure_attempts_c09","open_trestle_erasure_attempts_c10","open_trestle_erasure_attempts_c11","open_trestle_erasure_attempts_c12","open_trestle_erasure_attempts_c13","open_trestle_erasure_attempts_c14","open_trestle_erasure_attempts_c15","open_trestle_erasure_attempts_c16","open_trestle_erasure_attempts_c17","open_trestle_erasure_attempts_c18","open_trestle_erasure_attempts_c19","open_trestle_erasure_attempts_c20","open_trestle_erasure_attempts_c21","open_trestle_erasure_attempts_c22","open_trestle_erasure_attempts_c23","open_trestle_erasure_attempts_c24","open_trestle_erasure_attempts_c25","open_trestle_erasure_attempts_c26","open_trestle_erasure_attempts_c27","open_trestle_erasure_attempts_x01","open_trestle_erasure_attempts_x02","open_trestle_erasure_attempts_x03","open_trestle_erasure_attempts_x04","open_trestle_erasure_attempts_x05","open_trestle_erasure_attempts_pkey","open_trestle_erasure_attempts_u1","open_trestle_erasure_attempts_u2","open_trestle_erasure_attempts_u3","open_trestle_erasure_attempts_f1","open_trestle_erasure_attempts_f2"],"open_trestle_erasure_attempt_evidence":["open_trestle_erasure_attempt_evidence_c01","open_trestle_erasure_attempt_evidence_c02","open_trestle_erasure_attempt_evidence_c03","open_trestle_erasure_attempt_evidence_c04","open_trestle_erasure_attempt_evidence_c05","open_trestle_erasure_attempt_evidence_c06","open_trestle_erasure_attempt_evidence_c07","open_trestle_erasure_attempt_evidence_c08","open_trestle_erasure_attempt_evidence_c09","open_trestle_erasure_attempt_evidence_c10","open_trestle_erasure_attempt_evidence_c11","open_trestle_erasure_attempt_evidence_c12","open_trestle_erasure_attempt_evidence_c13","open_trestle_erasure_attempt_evidence_c14","open_trestle_erasure_attempt_evidence_x01","open_trestle_erasure_attempt_evidence_pkey","open_trestle_erasure_attempt_evidence_u1","open_trestle_erasure_attempt_evidence_f1","open_trestle_erasure_attempt_evidence_f2"]}`

type daemonBudgetedSQLStatement struct {
	SQL        string   `json:"sql"`
	Parameters []string `json:"parameters"`
	Columns    []string `json:"columns"`
}

type daemonBudgetedCatalogColumn struct {
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Nullable bool    `json:"nullable"`
	Default  *string `json:"default_expression"`
}

type daemonBudgetedCatalogConstraint struct {
	Kind          string   `json:"kind"`
	Columns       []string `json:"columns"`
	Target        string   `json:"target_table"`
	TargetColumns []string `json:"target_columns"`
	Expression    string   `json:"expression"`
	Referenced    []string `json:"referenced_columns"`
}

type daemonBudgetedCatalogIndex struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
	Unique  bool     `json:"unique"`
	Primary bool     `json:"primary"`
}

type daemonBudgetedTableDescriptor struct {
	Columns     []daemonBudgetedCatalogColumn     `json:"columns"`
	Constraints []daemonBudgetedCatalogConstraint `json:"constraints"`
	Indexes     []daemonBudgetedCatalogIndex      `json:"indexes"`
}

type daemonBudgetedCatalog struct {
	Rows                              map[string][][]driver.Value
	Tables                            map[string]daemonBudgetedTableDescriptor
	OIDs                              map[string]int64
	Database, Schema, Role, Namespace string
}

type daemonBudgetedAdmissionRow struct {
	Tenant, Repository, Run, ScopeIdentity, NamespaceIdentity, ArtifactIdentity, AdmissionIdentity string
	CanonicalAdmission, CanonicalNamespace, PolicyBytes                                            []byte
	DatabaseAuthorityIdentity, PolicyIdentity                                                      string
	AdmittedMillis                                                                                 int64
	ConfirmedVersion, ConfirmedDigest                                                              string
	ConfirmedMillis                                                                                int64
}

type daemonBudgetedMetadataRow struct {
	Tenant, Repository, Run, ScopeIdentity, ArtifactIdentity string
	PayloadDigest, Kind, Classification, Origin, Protection  string
	CreatedAt, ExpiresAt                                     time.Time
}

type daemonBudgetedDiagnosticRow struct {
	Tenant, Repository, Run, ScopeIdentity string
	SetIdentity, ArtifactIdentity          string
	ExpiresAt                              time.Time
}

type daemonBudgetedWebhookRow struct {
	Tenant, Repository, Run, ReviewScopeIdentity, RepositoryScopeIdentity string
	Source, DeduplicationKey, DeliveryIdentity, ArtifactIdentity          string
	AcceptedAt, ExpiresAt                                                 time.Time
}

type daemonBudgetedRunPlanRow struct {
	Tenant, Repository, Run, ScopeIdentity, PlanIdentity string
	CanonicalPlan                                        []byte
}

type daemonBudgetedRunEventRow struct {
	Tenant, Repository, Run, ScopeIdentity, PlanIdentity string
	Sequence                                             uint64
	EventIdentity, PreviousIdentity                      string
	CanonicalEvent                                       []byte
	OccurredAt                                           time.Time
}

type daemonBudgetedAuditEventRow struct {
	Tenant, Repository, Run, ScopeIdentity string
	Sequence                               uint64
	EventIdentity, PreviousIdentity        string
	CanonicalEvent                         []byte
	OccurredAt                             time.Time
}

type daemonBudgetedRateLimitRow struct {
	Namespace, KeyDigest, ConfigurationIdentity string
	RequestCount                                int64
}

type daemonBudgetedSQLTraceEvent struct {
	Sequence              uint64
	Graph, OperationLabel string
	TransactionID         uint64
	StatementID, Kind     string
	Arguments             []driver.Value
	Isolation             driver.IsolationLevel
	ReadOnly              bool
	Persisted, ReplyKnown bool
}

type daemonBudgetedSQLService struct {
	mu                  sync.Mutex
	catalog             daemonBudgetedCatalog
	scopes              map[string]string
	metadata            map[string]daemonBudgetedMetadataRow
	diagnostics         map[string]daemonBudgetedDiagnosticRow
	webhooks            map[string]daemonBudgetedWebhookRow
	plans               map[string]daemonBudgetedRunPlanRow
	eventsByScope       map[string][]daemonBudgetedRunEventRow
	auditEventsByScope  map[string][]daemonBudgetedAuditEventRow
	admissions          map[string]daemonBudgetedAdmissionRow
	rateLimits          map[string]daemonBudgetedRateLimitRow
	next                uint64
	connections         int
	closes              int
	events              []daemonBudgetedSQLTraceEvent
	failures            []string
	forceSchemaMismatch bool
}

type daemonBudgetedSQLSnapshot struct {
	Events      []daemonBudgetedSQLTraceEvent
	Connections int
	Closes      int
	Failures    []string
	Webhooks    map[string]daemonBudgetedWebhookRow
	Plans       map[string]daemonBudgetedRunPlanRow
	RunEvents   map[string][]daemonBudgetedRunEventRow
	AuditEvents map[string][]daemonBudgetedAuditEventRow
}

func newDaemonBudgetedSQLService(t *testing.T) *daemonBudgetedSQLService {
	t.Helper()
	return &daemonBudgetedSQLService{
		catalog:            newDaemonBudgetedCatalog(t),
		scopes:             map[string]string{},
		metadata:           map[string]daemonBudgetedMetadataRow{},
		diagnostics:        map[string]daemonBudgetedDiagnosticRow{},
		webhooks:           map[string]daemonBudgetedWebhookRow{},
		plans:              map[string]daemonBudgetedRunPlanRow{},
		eventsByScope:      map[string][]daemonBudgetedRunEventRow{},
		auditEventsByScope: map[string][]daemonBudgetedAuditEventRow{},
		admissions:         map[string]daemonBudgetedAdmissionRow{},
		rateLimits:         map[string]daemonBudgetedRateLimitRow{},
	}
}

func (s *daemonBudgetedSQLService) OpenDB(t *testing.T, graph string) *sql.DB {
	t.Helper()
	if strings.TrimSpace(graph) == "" {
		t.Fatal("missing graph label")
	}
	db := sql.OpenDB(daemonBudgetedConnector{service: s, graph: graph})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func (s *daemonBudgetedSQLService) OpenPostgres(ctx context.Context, graph string, _ postgresstore.PoolOptions) (*sql.DB, error) {
	if ctx == nil || ctx.Err() != nil || strings.TrimSpace(graph) == "" {
		return nil, errors.New("invalid daemon SQL fixture open")
	}
	db := sql.OpenDB(daemonBudgetedConnector{service: s, graph: graph})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

func (s *daemonBudgetedSQLService) Snapshot() daemonBudgetedSQLSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	events := append([]daemonBudgetedSQLTraceEvent(nil), s.events...)
	for i := range events {
		events[i].Arguments = append([]driver.Value(nil), events[i].Arguments...)
	}
	return daemonBudgetedSQLSnapshot{Events: events, Connections: s.connections, Closes: s.closes, Failures: append([]string(nil), s.failures...), Webhooks: daemonBudgetedCloneWebhooks(s.webhooks), Plans: daemonBudgetedCloneRunPlans(s.plans), RunEvents: daemonBudgetedCloneRunEvents(s.eventsByScope), AuditEvents: daemonBudgetedCloneAuditEvents(s.auditEventsByScope)}
}

func (s *daemonBudgetedSQLService) setSchemaMismatch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forceSchemaMismatch = true
}

func (s *daemonBudgetedSQLService) fail(message string) error {
	s.failures = append(s.failures, message)
	return errors.New("daemon SQL fixture rejected statement")
}

func (s *daemonBudgetedSQLService) event(tx *daemonBudgetedTx, id, kind string, args []driver.Value, persisted, known bool) {
	e := daemonBudgetedSQLTraceEvent{Sequence: uint64(len(s.events) + 1), StatementID: id, Kind: kind, Arguments: daemonBudgetedCopyValues(args), Persisted: persisted, ReplyKnown: known}
	if tx != nil {
		e.Graph = tx.graph
		e.OperationLabel = tx.label
		e.TransactionID = tx.id
		e.Isolation = tx.options.Isolation
		e.ReadOnly = tx.options.ReadOnly
	}
	s.events = append(s.events, e)
}

func daemonBudgetedCopyValues(in []driver.Value) []driver.Value {
	out := make([]driver.Value, len(in))
	for i, v := range in {
		if b, ok := v.([]byte); ok {
			out[i] = append([]byte(nil), b...)
		} else {
			out[i] = v
		}
	}
	return out
}

type daemonBudgetedConnector struct {
	service *daemonBudgetedSQLService
	graph   string
}

type daemonBudgetedDriver struct{}

type daemonBudgetedConn struct {
	service *daemonBudgetedSQLService
	graph   string
	active  *daemonBudgetedTx
	closed  bool
}

type daemonBudgetedTx struct {
	conn        *daemonBudgetedConn
	id          uint64
	graph       string
	label       string
	options     driver.TxOptions
	scopes      map[string]string
	metadata    map[string]daemonBudgetedMetadataRow
	diagnostics map[string]daemonBudgetedDiagnosticRow
	webhooks    map[string]daemonBudgetedWebhookRow
	plans       map[string]daemonBudgetedRunPlanRow
	runEvents   map[string][]daemonBudgetedRunEventRow
	auditEvents map[string][]daemonBudgetedAuditEventRow
	admissions  map[string]daemonBudgetedAdmissionRow
	rateLimits  map[string]daemonBudgetedRateLimitRow
	done        bool
}

type daemonBudgetedRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
}

func (c daemonBudgetedConnector) Driver() driver.Driver { return daemonBudgetedDriver{} }
func (c daemonBudgetedConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if ctx == nil || ctx.Err() != nil || c.service == nil {
		return nil, errors.New("invalid daemon SQL connector")
	}
	c.service.mu.Lock()
	defer c.service.mu.Unlock()
	c.service.connections++
	return &daemonBudgetedConn{service: c.service, graph: c.graph}, nil
}
func (daemonBudgetedDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("use connector")
}

func (c *daemonBudgetedConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements disabled")
}
func (c *daemonBudgetedConn) Begin() (driver.Tx, error) {
	return nil, errors.New("explicit transaction options required")
}
func (c *daemonBudgetedConn) Close() error {
	c.service.mu.Lock()
	defer c.service.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.service.closes++
		if c.service.connections > 0 {
			c.service.connections--
		}
	}
	return nil
}
func (c *daemonBudgetedConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	if ctx == nil || ctx.Err() != nil || c.closed || c.active != nil {
		return nil, errors.New("invalid daemon SQL transaction")
	}
	c.service.mu.Lock()
	defer c.service.mu.Unlock()
	c.service.next++
	tx := &daemonBudgetedTx{conn: c, id: c.service.next, graph: c.graph, label: daemonBudgetedSQLLabel(ctx), options: options, scopes: daemonBudgetedCloneScopes(c.service.scopes), metadata: daemonBudgetedCloneMetadata(c.service.metadata), diagnostics: daemonBudgetedCloneDiagnostics(c.service.diagnostics), webhooks: daemonBudgetedCloneWebhooks(c.service.webhooks), plans: daemonBudgetedCloneRunPlans(c.service.plans), runEvents: daemonBudgetedCloneRunEvents(c.service.eventsByScope), auditEvents: daemonBudgetedCloneAuditEvents(c.service.auditEventsByScope), admissions: daemonBudgetedCloneAdmissions(c.service.admissions), rateLimits: daemonBudgetedCloneRateLimits(c.service.rateLimits)}
	c.active = tx
	c.service.event(tx, "BEGIN", "begin", nil, false, true)
	return tx, nil
}
func (c *daemonBudgetedConn) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	result, _, err := c.run(ctx, q, a, false)
	return result, err
}
func (c *daemonBudgetedConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	_, rows, err := c.run(ctx, q, a, true)
	return rows, err
}
func (c *daemonBudgetedConn) run(ctx context.Context, q string, named []driver.NamedValue, query bool) (driver.Result, driver.Rows, error) {
	if ctx == nil || ctx.Err() != nil || c.closed || c.active == nil || c.active.done {
		return nil, nil, errors.New("statement outside active transaction")
	}
	id := daemonBudgetedStatementID(q)
	if id == "" {
		return nil, nil, fmt.Errorf("statement not allowlisted: %s", daemonBudgetedNormalizeSQL(q))
	}
	args, err := daemonBudgetedValues(named)
	if err != nil {
		return nil, nil, err
	}
	c.service.mu.Lock()
	defer c.service.mu.Unlock()
	rows, affected, err := c.active.statement(ctx, id, args, query)
	persisted := err == nil && !query && affected > 0 && id != "artifact_lock" && id != "tenant_guc"
	c.service.event(c.active, id, map[bool]string{true: "query", false: "exec"}[query], args, persisted, err == nil)
	if err != nil {
		return nil, nil, err
	}
	if query {
		return nil, daemonBudgetedDriverRows(id, rows), nil
	}
	return driver.RowsAffected(affected), nil, nil
}

func (tx *daemonBudgetedTx) Commit() error {
	s := tx.conn.service
	s.mu.Lock()
	defer s.mu.Unlock()
	if tx.done {
		return sql.ErrTxDone
	}
	if !tx.options.ReadOnly {
		s.scopes = daemonBudgetedCloneScopes(tx.scopes)
		s.metadata = daemonBudgetedCloneMetadata(tx.metadata)
		s.diagnostics = daemonBudgetedCloneDiagnostics(tx.diagnostics)
		s.webhooks = daemonBudgetedCloneWebhooks(tx.webhooks)
		s.plans = daemonBudgetedCloneRunPlans(tx.plans)
		s.eventsByScope = daemonBudgetedCloneRunEvents(tx.runEvents)
		s.auditEventsByScope = daemonBudgetedCloneAuditEvents(tx.auditEvents)
		s.admissions = daemonBudgetedCloneAdmissions(tx.admissions)
		s.rateLimits = daemonBudgetedCloneRateLimits(tx.rateLimits)
	}
	tx.done = true
	tx.conn.active = nil
	s.event(tx, "COMMIT", "commit", nil, !tx.options.ReadOnly, true)
	return nil
}
func (tx *daemonBudgetedTx) Rollback() error {
	s := tx.conn.service
	s.mu.Lock()
	defer s.mu.Unlock()
	if tx.done {
		return sql.ErrTxDone
	}
	tx.done = true
	tx.conn.active = nil
	s.event(tx, "ROLLBACK", "rollback", nil, false, true)
	return nil
}

func (tx *daemonBudgetedTx) statement(_ context.Context, id string, a []driver.Value, query bool) ([][]driver.Value, int64, error) {
	wantQuery := map[string]bool{
		"authority_schemas": true, "authority_identity": true, "migration_rows": true, "role": true, "relation": true, "attributes": true, "constraints": true, "indexes": true, "policies": true, "table_privileges": true, "confirmation_privileges": true, "allowance_counter_privileges": true, "allowance_immutable_privileges": true, "user_triggers": true, "metadata_read": true, "scope_read": true, "run_plan_read": true, "run_plan_identity_read": true, "run_event_first_plan": true, "run_plans_list": true, "run_event_head": true, "run_events_read": true, "audit_event_head": true, "audit_events_read": true, "key_occupancy": true, "legacy_lineage": true, "admission_read": true, "admission_lock_read": true, "operation_presence": true, "operation_read": true, "operation_ref_read": true, "diagnostic_read": true, "webhook_read": true, "webhook_list": true, "webhook_count": true, "rate_limit_update": true, "rate_limit_conflict": true, "rate_limit_count": true,
	}[id]
	if query != wantQuery {
		return nil, 0, tx.conn.service.fail("query/exec mismatch for " + id)
	}
	if tx.options.ReadOnly && !query {
		return nil, 0, tx.conn.service.fail("write in read-only transaction for " + id)
	}
	switch id {
	case "authority_schemas", "authority_identity", "migration_rows", "role":
		return daemonBudgetedCopyRows(tx.conn.service.catalog.Rows[id]), 0, nil
	case "relation":
		if len(a) != 2 {
			return nil, 0, tx.conn.service.fail("relation args")
		}
		name, _ := a[1].(string)
		oid := tx.conn.service.catalog.OIDs[name]
		if tx.conn.service.forceSchemaMismatch && name == daemonBudgetedErasureAdmissions {
			oid = 0
		}
		return daemonBudgetedCopyRows(tx.conn.service.catalog.Rows[daemonBudgetedCatalogKey("relation", oid)]), 0, nil
	case "attributes", "constraints", "indexes", "policies", "table_privileges", "confirmation_privileges", "allowance_counter_privileges", "allowance_immutable_privileges", "user_triggers":
		if len(a) == 0 {
			return nil, 0, tx.conn.service.fail(id + " args")
		}
		oid, _ := daemonBudgetedInt64(a[0])
		return daemonBudgetedCopyRows(tx.conn.service.catalog.Rows[daemonBudgetedCatalogKey(id, oid)]), 0, nil
	case "tenant_guc":
		if len(a) != 1 {
			return nil, 0, tx.conn.service.fail("tenant_guc args")
		}
		return nil, 0, nil
	case "artifact_lock":
		if len(a) != 1 {
			return nil, 0, tx.conn.service.fail("artifact_lock args")
		}
		return nil, 0, nil
	case "scope_insert":
		if len(a) != 4 {
			return nil, 0, tx.conn.service.fail("scope_insert args")
		}
		key := daemonBudgetedScopeKey(a[0], a[1], a[2])
		if _, ok := tx.scopes[key]; ok {
			return nil, 0, nil
		}
		tx.scopes[key] = fmt.Sprint(a[3])
		return nil, 1, nil
	case "scope_read":
		if len(a) != 3 {
			return nil, 0, tx.conn.service.fail("scope_read args")
		}
		if v, ok := tx.scopes[daemonBudgetedScopeKey(a[0], a[1], a[2])]; ok {
			return [][]driver.Value{{v}}, 0, nil
		}
		return nil, 0, nil
	case "run_plan_read":
		if len(a) != 3 {
			return nil, 0, tx.conn.service.fail("run_plan_read args")
		}
		if row, ok := tx.plans[daemonBudgetedScopeKey(a[0], a[1], a[2])]; ok {
			return [][]driver.Value{{row.PlanIdentity, daemonBudgetedBytes(row.CanonicalPlan)}}, 0, nil
		}
		return nil, 0, nil
	case "run_plan_identity_read":
		if len(a) != 3 {
			return nil, 0, tx.conn.service.fail("run_plan_identity_read args")
		}
		if row, ok := tx.plans[daemonBudgetedScopeKey(a[0], a[1], a[2])]; ok {
			return [][]driver.Value{{row.PlanIdentity}}, 0, nil
		}
		return nil, 0, nil
	case "run_event_first_plan":
		if len(a) != 3 {
			return nil, 0, tx.conn.service.fail("run_event_first_plan args")
		}
		events := tx.runEvents[daemonBudgetedScopeKey(a[0], a[1], a[2])]
		if len(events) == 0 {
			return nil, 0, nil
		}
		return [][]driver.Value{{events[0].PlanIdentity}}, 0, nil
	case "run_plan_insert":
		if len(a) != 6 {
			return nil, 0, tx.conn.service.fail("run_plan_insert args")
		}
		key := daemonBudgetedScopeKey(a[0], a[1], a[2])
		if _, exists := tx.plans[key]; exists {
			return nil, 0, tx.conn.service.fail("run_plan_insert duplicate")
		}
		tx.plans[key] = daemonBudgetedRunPlanRow{Tenant: fmt.Sprint(a[0]), Repository: fmt.Sprint(a[1]), Run: fmt.Sprint(a[2]), ScopeIdentity: fmt.Sprint(a[3]), PlanIdentity: fmt.Sprint(a[4]), CanonicalPlan: daemonBudgetedBytes(a[5])}
		return nil, 1, nil
	case "run_plans_list":
		if len(a) != 4 {
			return nil, 0, tx.conn.service.fail("run_plans_list args")
		}
		limit, ok := daemonBudgetedInt64(a[3])
		if !ok || limit <= 0 || limit > 1000 {
			return nil, 0, tx.conn.service.fail("run_plans_list limit")
		}
		tenant, repository, after := fmt.Sprint(a[0]), fmt.Sprint(a[1]), fmt.Sprint(a[2])
		runs := make([]string, 0, len(tx.plans))
		for _, row := range tx.plans {
			if row.Tenant == tenant && row.Repository == repository && row.Run > after {
				runs = append(runs, row.Run)
			}
		}
		sort.Strings(runs)
		if int64(len(runs)) > limit {
			runs = runs[:limit]
		}
		rows := make([][]driver.Value, 0, len(runs))
		for _, run := range runs {
			row := tx.plans[daemonBudgetedScopeKey(tenant, repository, run)]
			rows = append(rows, []driver.Value{row.PlanIdentity, daemonBudgetedBytes(row.CanonicalPlan)})
		}
		return rows, 0, nil
	case "run_event_head":
		if len(a) != 3 {
			return nil, 0, tx.conn.service.fail("run_event_head args")
		}
		events := tx.runEvents[daemonBudgetedScopeKey(a[0], a[1], a[2])]
		if len(events) == 0 {
			return nil, 0, nil
		}
		row := events[len(events)-1]
		return [][]driver.Value{{int64(row.Sequence), row.EventIdentity, daemonBudgetedBytes(row.CanonicalEvent), int64(len(events))}}, 0, nil
	case "run_events_read":
		if len(a) != 5 {
			return nil, 0, tx.conn.service.fail("run_events_read args")
		}
		after, afterOK := daemonBudgetedInt64(a[3])
		limit, limitOK := daemonBudgetedInt64(a[4])
		if !afterOK || !limitOK || after < 0 || limit <= 0 || limit > 1000 {
			return nil, 0, tx.conn.service.fail("run_events_read bounds")
		}
		events := tx.runEvents[daemonBudgetedScopeKey(a[0], a[1], a[2])]
		rows := make([][]driver.Value, 0, len(events))
		for _, row := range events {
			if int64(row.Sequence) <= after {
				continue
			}
			if int64(len(rows)) >= limit {
				break
			}
			rows = append(rows, []driver.Value{int64(row.Sequence), row.EventIdentity, daemonBudgetedBytes(row.CanonicalEvent)})
		}
		return rows, 0, nil
	case "run_event_insert":
		if len(a) != 10 {
			return nil, 0, tx.conn.service.fail("run_event_insert args")
		}
		sequence, ok := daemonBudgetedInt64(a[5])
		if !ok || sequence <= 0 {
			return nil, 0, tx.conn.service.fail("run_event_insert sequence")
		}
		key := daemonBudgetedScopeKey(a[0], a[1], a[2])
		events := append([]daemonBudgetedRunEventRow(nil), tx.runEvents[key]...)
		if len(events)+1 != int(sequence) {
			return nil, 0, tx.conn.service.fail("run_event_insert sequence gap")
		}
		if sequence > 1 && events[len(events)-1].EventIdentity != fmt.Sprint(a[7]) {
			return nil, 0, tx.conn.service.fail("run_event_insert previous mismatch")
		}
		for _, existing := range events {
			if existing.EventIdentity == fmt.Sprint(a[6]) {
				return nil, 0, tx.conn.service.fail("run_event_insert duplicate")
			}
		}
		occurred, _ := a[9].(time.Time)
		events = append(events, daemonBudgetedRunEventRow{Tenant: fmt.Sprint(a[0]), Repository: fmt.Sprint(a[1]), Run: fmt.Sprint(a[2]), ScopeIdentity: fmt.Sprint(a[3]), PlanIdentity: fmt.Sprint(a[4]), Sequence: uint64(sequence), EventIdentity: fmt.Sprint(a[6]), PreviousIdentity: fmt.Sprint(a[7]), CanonicalEvent: daemonBudgetedBytes(a[8]), OccurredAt: occurred})
		tx.runEvents[key] = events
		return nil, 1, nil
	case "audit_event_head":
		if len(a) != 3 {
			return nil, 0, tx.conn.service.fail("audit_event_head args")
		}
		events := tx.auditEvents[daemonBudgetedScopeKey(a[0], a[1], a[2])]
		if len(events) == 0 {
			return nil, 0, nil
		}
		row := events[len(events)-1]
		return [][]driver.Value{{int64(row.Sequence), row.EventIdentity, daemonBudgetedBytes(row.CanonicalEvent), int64(len(events))}}, 0, nil
	case "audit_events_read":
		if len(a) != 5 {
			return nil, 0, tx.conn.service.fail("audit_events_read args")
		}
		after, afterOK := daemonBudgetedInt64(a[3])
		limit, limitOK := daemonBudgetedInt64(a[4])
		if !afterOK || !limitOK || after < 0 || limit <= 0 || limit > 1000 {
			return nil, 0, tx.conn.service.fail("audit_events_read bounds")
		}
		events := tx.auditEvents[daemonBudgetedScopeKey(a[0], a[1], a[2])]
		rows := make([][]driver.Value, 0, len(events))
		for _, row := range events {
			if int64(row.Sequence) <= after {
				continue
			}
			if int64(len(rows)) >= limit {
				break
			}
			rows = append(rows, []driver.Value{int64(row.Sequence), row.EventIdentity, daemonBudgetedBytes(row.CanonicalEvent)})
		}
		return rows, 0, nil
	case "audit_event_insert":
		if len(a) != 9 {
			return nil, 0, tx.conn.service.fail("audit_event_insert args")
		}
		sequence, ok := daemonBudgetedInt64(a[4])
		if !ok || sequence <= 0 {
			return nil, 0, tx.conn.service.fail("audit_event_insert sequence")
		}
		key := daemonBudgetedScopeKey(a[0], a[1], a[2])
		events := append([]daemonBudgetedAuditEventRow(nil), tx.auditEvents[key]...)
		if len(events)+1 != int(sequence) {
			return nil, 0, tx.conn.service.fail("audit_event_insert sequence gap")
		}
		if sequence > 1 && events[len(events)-1].EventIdentity != fmt.Sprint(a[6]) {
			return nil, 0, tx.conn.service.fail("audit_event_insert previous mismatch")
		}
		for _, existing := range events {
			if existing.EventIdentity == fmt.Sprint(a[5]) {
				return nil, 0, tx.conn.service.fail("audit_event_insert duplicate")
			}
		}
		occurred, _ := a[8].(time.Time)
		events = append(events, daemonBudgetedAuditEventRow{Tenant: fmt.Sprint(a[0]), Repository: fmt.Sprint(a[1]), Run: fmt.Sprint(a[2]), ScopeIdentity: fmt.Sprint(a[3]), Sequence: uint64(sequence), EventIdentity: fmt.Sprint(a[5]), PreviousIdentity: fmt.Sprint(a[6]), CanonicalEvent: daemonBudgetedBytes(a[7]), OccurredAt: occurred})
		tx.auditEvents[key] = events
		return nil, 1, nil
	case "metadata_read":
		if len(a) != 4 {
			return nil, 0, tx.conn.service.fail("metadata_read args")
		}
		if row, ok := tx.metadata[daemonBudgetedArtifactKey(a[0], a[1], a[2], a[3])]; ok {
			return [][]driver.Value{{row.PayloadDigest, row.Kind, row.Classification, row.Origin, row.Protection, row.CreatedAt, row.ExpiresAt}}, 0, nil
		}
		return nil, 0, nil
	case "metadata_insert":
		if len(a) != 12 {
			return nil, 0, tx.conn.service.fail("metadata_insert args")
		}
		row := daemonBudgetedMetadataRow{Tenant: fmt.Sprint(a[0]), Repository: fmt.Sprint(a[1]), Run: fmt.Sprint(a[2]), ScopeIdentity: fmt.Sprint(a[3]), ArtifactIdentity: fmt.Sprint(a[4]), PayloadDigest: fmt.Sprint(a[5]), Kind: fmt.Sprint(a[6]), Classification: fmt.Sprint(a[7]), Origin: fmt.Sprint(a[8]), Protection: fmt.Sprint(a[9])}
		row.CreatedAt, _ = a[10].(time.Time)
		row.ExpiresAt, _ = a[11].(time.Time)
		tx.metadata[daemonBudgetedArtifactKey(a[0], a[1], a[2], a[4])] = row
		return nil, 1, nil
	case "diagnostic_read":
		if len(a) != 3 {
			return nil, 0, tx.conn.service.fail("diagnostic_read args")
		}
		if row, ok := tx.diagnostics[daemonBudgetedDiagnosticKey(a[0], a[1], a[2])]; ok {
			return [][]driver.Value{{row.SetIdentity, row.ArtifactIdentity, row.ExpiresAt}}, 0, nil
		}
		return nil, 0, nil
	case "diagnostic_insert":
		if len(a) != 7 {
			return nil, 0, tx.conn.service.fail("diagnostic_insert args")
		}
		key := daemonBudgetedDiagnosticKey(a[0], a[1], a[2])
		if _, exists := tx.diagnostics[key]; exists {
			return nil, 0, tx.conn.service.fail("diagnostic_insert duplicate")
		}
		row := daemonBudgetedDiagnosticRow{Tenant: fmt.Sprint(a[0]), Repository: fmt.Sprint(a[1]), Run: fmt.Sprint(a[2]), ScopeIdentity: fmt.Sprint(a[3]), SetIdentity: fmt.Sprint(a[4]), ArtifactIdentity: fmt.Sprint(a[5])}
		row.ExpiresAt, _ = a[6].(time.Time)
		tx.diagnostics[key] = row
		return nil, 1, nil
	case "webhook_read":
		if len(a) != 4 {
			return nil, 0, tx.conn.service.fail("webhook_read args")
		}
		if row, ok := tx.webhooks[daemonBudgetedWebhookKey(a[0], a[1], a[2], a[3])]; ok {
			return [][]driver.Value{{row.Run, row.ReviewScopeIdentity, row.RepositoryScopeIdentity, row.DeduplicationKey, row.DeliveryIdentity, row.ArtifactIdentity, row.AcceptedAt, row.ExpiresAt}}, 0, nil
		}
		return nil, 0, nil
	case "webhook_list":
		if len(a) != 6 {
			return nil, 0, tx.conn.service.fail("webhook_list args")
		}
		limit, ok := daemonBudgetedInt64(a[4])
		at, _ := a[5].(time.Time)
		if !ok || limit <= 0 || limit > 100 {
			return nil, 0, tx.conn.service.fail("webhook_list limit")
		}
		tenant, repository, source, after := fmt.Sprint(a[0]), fmt.Sprint(a[1]), fmt.Sprint(a[2]), fmt.Sprint(a[3])
		keys := make([]string, 0, len(tx.webhooks))
		for _, row := range tx.webhooks {
			if row.Tenant == tenant && row.Repository == repository && row.Source == source && row.DeduplicationKey > after && row.ExpiresAt.After(at) {
				keys = append(keys, row.DeduplicationKey)
			}
		}
		sort.Strings(keys)
		if int64(len(keys)) > limit {
			keys = keys[:limit]
		}
		rows := make([][]driver.Value, 0, len(keys))
		for _, key := range keys {
			row := tx.webhooks[daemonBudgetedWebhookKey(tenant, repository, source, key)]
			rows = append(rows, []driver.Value{row.Run, row.ReviewScopeIdentity, row.RepositoryScopeIdentity, row.DeduplicationKey, row.DeliveryIdentity, row.ArtifactIdentity, row.AcceptedAt, row.ExpiresAt})
		}
		return rows, 0, nil
	case "webhook_count":
		if len(a) != 4 {
			return nil, 0, tx.conn.service.fail("webhook_count args")
		}
		at, _ := a[3].(time.Time)
		var count int64
		for _, row := range tx.webhooks {
			if row.Tenant == fmt.Sprint(a[0]) && row.Repository == fmt.Sprint(a[1]) && row.Source == fmt.Sprint(a[2]) && row.ExpiresAt.After(at) {
				count++
			}
		}
		return [][]driver.Value{{count}}, 0, nil
	case "webhook_insert":
		if len(a) != 11 {
			return nil, 0, tx.conn.service.fail("webhook_insert args")
		}
		key := daemonBudgetedWebhookKey(a[0], a[1], a[5], a[6])
		if _, exists := tx.webhooks[key]; exists {
			return nil, 0, tx.conn.service.fail("webhook_insert duplicate")
		}
		row := daemonBudgetedWebhookRow{Tenant: fmt.Sprint(a[0]), Repository: fmt.Sprint(a[1]), Run: fmt.Sprint(a[2]), ReviewScopeIdentity: fmt.Sprint(a[3]), RepositoryScopeIdentity: fmt.Sprint(a[4]), Source: fmt.Sprint(a[5]), DeduplicationKey: fmt.Sprint(a[6]), DeliveryIdentity: fmt.Sprint(a[7]), ArtifactIdentity: fmt.Sprint(a[8])}
		row.AcceptedAt, _ = a[9].(time.Time)
		row.ExpiresAt, _ = a[10].(time.Time)
		tx.webhooks[key] = row
		return nil, 1, nil
	case "key_occupancy":
		if len(a) != 4 {
			return nil, 0, tx.conn.service.fail("key_occupancy args")
		}
		prefix := strings.Join([]string{fmt.Sprint(a[0]), fmt.Sprint(a[1]), fmt.Sprint(a[2])}, "\x00") + "\x00"
		artifactID := fmt.Sprint(a[3])
		for _, row := range tx.admissions {
			if strings.HasPrefix(daemonBudgetedAdmissionKey(row.Tenant, row.Repository, row.Run, row.NamespaceIdentity, row.ArtifactIdentity), prefix) && row.ArtifactIdentity == artifactID {
				return [][]driver.Value{{row.NamespaceIdentity, row.AdmissionIdentity}}, 0, nil
			}
		}
		return nil, 0, nil
	case "legacy_lineage":
		if len(a) != 4 {
			return nil, 0, tx.conn.service.fail("legacy_lineage args")
		}
		return [][]driver.Value{{false, false}}, 0, nil
	case "admission_insert":
		if len(a) != 13 {
			return nil, 0, tx.conn.service.fail("admission_insert args")
		}
		row := daemonBudgetedAdmissionRow{Tenant: fmt.Sprint(a[0]), Repository: fmt.Sprint(a[1]), Run: fmt.Sprint(a[2]), ScopeIdentity: fmt.Sprint(a[3]), NamespaceIdentity: fmt.Sprint(a[4]), ArtifactIdentity: fmt.Sprint(a[5]), AdmissionIdentity: fmt.Sprint(a[6]), DatabaseAuthorityIdentity: fmt.Sprint(a[10]), PolicyIdentity: fmt.Sprint(a[11])}
		row.CanonicalAdmission = daemonBudgetedBytes(a[7])
		row.CanonicalNamespace = daemonBudgetedBytes(a[8])
		row.PolicyBytes = daemonBudgetedBytes(a[9])
		row.AdmittedMillis, _ = daemonBudgetedInt64(a[12])
		tx.admissions[daemonBudgetedAdmissionKey(row.Tenant, row.Repository, row.Run, row.NamespaceIdentity, row.ArtifactIdentity)] = row
		return nil, 1, nil
	case "admission_read", "admission_lock_read":
		if len(a) != 5 {
			return nil, 0, tx.conn.service.fail("admission_read args")
		}
		row, ok := tx.admissions[daemonBudgetedAdmissionKey(a[0], a[1], a[2], a[3], a[4])]
		if !ok {
			return nil, 0, nil
		}
		return [][]driver.Value{tx.joinAdmission(row)}, 0, nil
	case "confirmation_cas":
		if len(a) != 10 {
			return nil, 0, tx.conn.service.fail("confirmation_cas args")
		}
		key := daemonBudgetedAdmissionKey(a[0], a[1], a[2], a[4], a[5])
		row, ok := tx.admissions[key]
		if !ok || row.ScopeIdentity != fmt.Sprint(a[3]) || row.AdmissionIdentity != fmt.Sprint(a[6]) || row.ConfirmedVersion != "" {
			return nil, 0, nil
		}
		row.ConfirmedVersion = fmt.Sprint(a[7])
		row.ConfirmedDigest = fmt.Sprint(a[8])
		row.ConfirmedMillis, _ = daemonBudgetedInt64(a[9])
		tx.admissions[key] = row
		return nil, 1, nil
	case "operation_presence", "operation_read", "operation_ref_read":
		if len(a) != 5 {
			return nil, 0, tx.conn.service.fail(id + " args")
		}
		return nil, 0, nil
	case "rate_limit_update":
		if len(a) != 5 {
			return nil, 0, tx.conn.service.fail("rate_limit_update args")
		}
		key := daemonBudgetedRateLimitKey(a[0], a[1])
		row, ok := tx.rateLimits[key]
		if !ok || row.ConfigurationIdentity != fmt.Sprint(a[4]) {
			return nil, 0, nil
		}
		limit, ok := daemonBudgetedInt64(a[3])
		if !ok || limit <= 0 {
			return nil, 0, tx.conn.service.fail("rate_limit_update limit")
		}
		allowed := row.RequestCount < limit
		if allowed {
			row.RequestCount++
			tx.rateLimits[key] = row
		}
		return [][]driver.Value{{allowed}}, 0, nil
	case "rate_limit_advisory_lock":
		if len(a) != 1 {
			return nil, 0, tx.conn.service.fail("rate_limit_advisory_lock args")
		}
		return nil, 0, nil
	case "rate_limit_cleanup":
		if len(a) != 1 {
			return nil, 0, tx.conn.service.fail("rate_limit_cleanup args")
		}
		return nil, 0, nil
	case "rate_limit_conflict":
		if len(a) != 2 {
			return nil, 0, tx.conn.service.fail("rate_limit_conflict args")
		}
		if row, ok := tx.rateLimits[daemonBudgetedRateLimitKey(a[0], a[1])]; ok {
			return [][]driver.Value{{row.ConfigurationIdentity}}, 0, nil
		}
		return nil, 0, nil
	case "rate_limit_count":
		if len(a) != 1 {
			return nil, 0, tx.conn.service.fail("rate_limit_count args")
		}
		var count int64
		for _, row := range tx.rateLimits {
			if row.Namespace == fmt.Sprint(a[0]) {
				count++
			}
		}
		return [][]driver.Value{{count}}, 0, nil
	case "rate_limit_insert":
		if len(a) != 4 {
			return nil, 0, tx.conn.service.fail("rate_limit_insert args")
		}
		key := daemonBudgetedRateLimitKey(a[0], a[1])
		if _, exists := tx.rateLimits[key]; exists {
			return nil, 0, tx.conn.service.fail("rate_limit_insert duplicate")
		}
		tx.rateLimits[key] = daemonBudgetedRateLimitRow{Namespace: fmt.Sprint(a[0]), KeyDigest: fmt.Sprint(a[1]), ConfigurationIdentity: fmt.Sprint(a[3]), RequestCount: 1}
		return nil, 1, nil
	default:
		return nil, 0, tx.conn.service.fail("unimplemented statement " + id)
	}
}

func (tx *daemonBudgetedTx) joinAdmission(row daemonBudgetedAdmissionRow) []driver.Value {
	meta := tx.metadata[daemonBudgetedArtifactKey(row.Tenant, row.Repository, row.Run, row.ArtifactIdentity)]
	var version, digest, confirmed driver.Value
	if row.ConfirmedVersion != "" {
		version, digest, confirmed = row.ConfirmedVersion, row.ConfirmedDigest, row.ConfirmedMillis
	}
	return []driver.Value{row.Tenant, row.Repository, row.Run, row.ScopeIdentity, row.NamespaceIdentity, row.ArtifactIdentity, row.AdmissionIdentity, daemonBudgetedBytes(row.CanonicalAdmission), daemonBudgetedBytes(row.CanonicalNamespace), daemonBudgetedBytes(row.PolicyBytes), row.DatabaseAuthorityIdentity, row.PolicyIdentity, row.AdmittedMillis, version, digest, confirmed, row.ScopeIdentity, meta.ScopeIdentity, meta.ArtifactIdentity, meta.PayloadDigest, meta.Kind, meta.Classification, meta.Origin, meta.Protection, meta.CreatedAt, meta.ExpiresAt}
}

func daemonBudgetedDriverRows(id string, rows [][]driver.Value) driver.Rows {
	count := daemonBudgetedColumnCounts()[id]
	cols := make([]string, count)
	for i := range cols {
		cols[i] = "c" + strconv.Itoa(i)
	}
	return &daemonBudgetedRows{columns: cols, rows: daemonBudgetedCopyRows(rows)}
}
func (r *daemonBudgetedRows) Columns() []string { return append([]string(nil), r.columns...) }
func (r *daemonBudgetedRows) Close() error      { return nil }
func (r *daemonBudgetedRows) Next(dst []driver.Value) error {
	if r.index >= len(r.rows) {
		return io.EOF
	}
	copy(dst, r.rows[r.index])
	r.index++
	return nil
}

func daemonBudgetedStatementID(q string) string {
	return map[string]string{
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLArtifactLock):                "artifact_lock",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLAuthorityIdentity):           "authority_identity",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLAuthoritySchemas):            "authority_schemas",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLMetadataInsert):              "metadata_insert",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLMetadataRead):                "metadata_read",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLMigrationRows):               "migration_rows",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLScopeInsert):                 "scope_insert",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLScopeRead):                   "scope_read",
		daemonBudgetedNormalizeSQL(daemonBudgetedRunPlanReadSQL):                        "run_plan_read",
		daemonBudgetedNormalizeSQL(daemonBudgetedRunPlanIdentityReadSQL):                "run_plan_identity_read",
		daemonBudgetedNormalizeSQL(daemonBudgetedRunPlanFirstEventIdentitySQL):          "run_event_first_plan",
		daemonBudgetedNormalizeSQL(daemonBudgetedRunPlanInsertSQL):                      "run_plan_insert",
		daemonBudgetedNormalizeSQL(daemonBudgetedRunPlansListSQL):                       "run_plans_list",
		daemonBudgetedNormalizeSQL(daemonBudgetedRunHeadSQL):                            "run_event_head",
		daemonBudgetedNormalizeSQL(daemonBudgetedRunEventsReadSQL):                      "run_events_read",
		daemonBudgetedNormalizeSQL(daemonBudgetedRunEventInsertSQL):                     "run_event_insert",
		daemonBudgetedNormalizeSQL(daemonBudgetedAuditEventInsertSQL):                   "audit_event_insert",
		daemonBudgetedNormalizeSQL(daemonBudgetedAuditEventReadSQL):                     "audit_events_read",
		daemonBudgetedNormalizeSQL(daemonBudgetedAuditEventHeadSQL):                     "audit_event_head",
		daemonBudgetedNormalizeSQL(daemonBudgetedDiagnosticMappingInsertSQL):            "diagnostic_insert",
		daemonBudgetedNormalizeSQL(daemonBudgetedDiagnosticMappingReadSQL):              "diagnostic_read",
		daemonBudgetedNormalizeSQL(daemonBudgetedWebhookMappingCountSQL):                "webhook_count",
		daemonBudgetedNormalizeSQL(daemonBudgetedWebhookMappingInsertSQL):               "webhook_insert",
		daemonBudgetedNormalizeSQL(daemonBudgetedWebhookMappingReadSQL):                 "webhook_read",
		daemonBudgetedNormalizeSQL(daemonBudgetedWebhookMappingListSQL):                 "webhook_list",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLTenantGuc):                   "tenant_guc",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLAdmissionInsert):             "admission_insert",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLAdmissionLockRead):           "admission_lock_read",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLAdmissionRead):               "admission_read",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLConfirmationCas):             "confirmation_cas",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLKeyOccupancy):                "key_occupancy",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLLegacyLineage):               "legacy_lineage",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLOperationPresence):           "operation_presence",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLOperationRead):               "operation_read",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLOperationRefRead):            "operation_ref_read",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLAttributes):                  "attributes",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLConfirmationPrivileges):      "confirmation_privileges",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLConstraints):                 "constraints",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLIndexes):                     "indexes",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLPolicies):                    "policies",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLRelation):                    "relation",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLRole):                        "role",
		daemonBudgetedNormalizeSQL(daemonBudgetedjournalSQLTablePrivileges):             "table_privileges",
		daemonBudgetedNormalizeSQL(daemonBudgetedresumeSQLAllowanceCounterPrivileges):   "allowance_counter_privileges",
		daemonBudgetedNormalizeSQL(daemonBudgetedresumeSQLAllowanceImmutablePrivileges): "allowance_immutable_privileges",
		daemonBudgetedNormalizeSQL(daemonBudgetedresumeSQLUserTriggers):                 "user_triggers",
		daemonBudgetedNormalizeSQL(daemonBudgetedsharedRateLimitUpdateSQL):              "rate_limit_update",
		daemonBudgetedNormalizeSQL(daemonBudgetedsharedRateLimitAdvisoryLockSQL):        "rate_limit_advisory_lock",
		daemonBudgetedNormalizeSQL(daemonBudgetedsharedRateLimitCleanupSQL):             "rate_limit_cleanup",
		daemonBudgetedNormalizeSQL(daemonBudgetedsharedRateLimitConflictSQL):            "rate_limit_conflict",
		daemonBudgetedNormalizeSQL(daemonBudgetedsharedRateLimitCountSQL):               "rate_limit_count",
		daemonBudgetedNormalizeSQL(daemonBudgetedsharedRateLimitInsertSQL):              "rate_limit_insert",
	}[daemonBudgetedNormalizeSQL(q)]
}
func daemonBudgetedColumnCounts() map[string]int {
	return map[string]int{
		"admission_insert":               0,
		"admission_lock_read":            26,
		"admission_read":                 26,
		"allowance_counter_privileges":   11,
		"allowance_immutable_privileges": 25,
		"artifact_lock":                  0,
		"audit_event_head":               4,
		"audit_event_insert":             0,
		"audit_events_read":              3,
		"attributes":                     11,
		"authority_identity":             4,
		"authority_schemas":              3,
		"confirmation_cas":               0,
		"confirmation_privileges":        3,
		"diagnostic_insert":              0,
		"diagnostic_read":                3,
		"constraints":                    15,
		"indexes":                        15,
		"key_occupancy":                  2,
		"legacy_lineage":                 2,
		"metadata_insert":                0,
		"metadata_read":                  7,
		"migration_rows":                 2,
		"operation_presence":             1,
		"operation_read":                 43,
		"operation_ref_read":             43,
		"rate_limit_advisory_lock":       0,
		"rate_limit_cleanup":             0,
		"rate_limit_conflict":            1,
		"rate_limit_count":               1,
		"rate_limit_insert":              0,
		"rate_limit_update":              1,
		"policies":                       7,
		"relation":                       8,
		"role":                           5,
		"run_event_first_plan":           1,
		"run_event_head":                 4,
		"run_event_insert":               0,
		"run_events_read":                3,
		"run_plan_identity_read":         1,
		"run_plan_insert":                0,
		"run_plan_read":                  2,
		"run_plans_list":                 2,
		"scope_insert":                   0,
		"scope_read":                     1,
		"table_privileges":               7,
		"tenant_guc":                     0,
		"user_triggers":                  1,
		"webhook_count":                  1,
		"webhook_insert":                 0,
		"webhook_list":                   8,
		"webhook_read":                   8,
	}
}
func daemonBudgetedNormalizeSQL(q string) string { return strings.Join(strings.Fields(q), " ") }
func daemonBudgetedValues(named []driver.NamedValue) ([]driver.Value, error) {
	out := make([]driver.Value, len(named))
	for i, v := range named {
		if v.Ordinal != i+1 || v.Name != "" {
			return nil, errors.New("named SQL arguments disabled")
		}
		out[i] = v.Value
	}
	return out, nil
}
func daemonBudgetedSQLLabel(ctx context.Context) string {
	s, _ := ctx.Value(daemonBudgetedContextKey{}).(string)
	return s
}

type daemonBudgetedContextKey struct{}

func daemonBudgetedOperationContext(t *testing.T, label string) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.WithValue(context.Background(), daemonBudgetedContextKey{}, label), 30*time.Second)
}

func newDaemonBudgetedCatalog(t *testing.T) daemonBudgetedCatalog {
	t.Helper()
	c := daemonBudgetedCatalog{Rows: map[string][][]driver.Value{}, Tables: map[string]daemonBudgetedTableDescriptor{}, OIDs: map[string]int64{}, Database: "open_trestle", Schema: "public", Role: "trestle_runtime", Namespace: "12345678-1234-4234-8234-123456789abc"}
	var base map[string]daemonBudgetedTableDescriptor
	if err := json.Unmarshal([]byte(daemonBudgetedErasureDescriptorJSON), &base); err != nil {
		t.Fatal(err)
	}
	for name, table := range base {
		c.Tables[name] = table
	}
	var resume map[string]daemonBudgetedTableDescriptor
	if err := json.Unmarshal([]byte(daemonBudgetedResumeDescriptorJSON), &resume); err != nil {
		t.Fatal(err)
	}
	for name, table := range resume {
		c.Tables[name] = table
	}
	baseNames := []string{"open_trestle_review_scopes", "open_trestle_artifacts", "open_trestle_artifact_deletion_authorizations", "open_trestle_artifact_deletion_receipts", "open_trestle_artifact_admissions", "open_trestle_artifact_erasure_operations"}
	resumeNames := []string{daemonBudgetedResumeAllowances, daemonBudgetedResumeAttempts, daemonBudgetedResumeEvidence}
	for i, name := range baseNames {
		c.OIDs[name] = int64(18001 + i)
	}
	for i, name := range resumeNames {
		c.OIDs[name] = int64(28001 + i)
	}
	c.Rows["role"] = [][]driver.Value{{int64(17000), c.Role, false, false, "on"}}
	for i, name := range append(baseNames, resumeNames...) {
		oid := c.OIDs[name]
		d := c.Tables[name]
		c.Rows[daemonBudgetedCatalogKey("relation", oid)] = [][]driver.Value{{oid, int64(2200), c.Schema, name, "r", true, true, oid}}
		for n, col := range d.Columns {
			typeOID := map[string]int64{"text": 25, "bytea": 17, "int8": 20, "timestamptz": 1184}[col.Type]
			var def driver.Value
			if col.Default != nil {
				def = *col.Default
			}
			c.Rows[daemonBudgetedCatalogKey("attributes", oid)] = append(c.Rows[daemonBudgetedCatalogKey("attributes", oid)], []driver.Value{int64(n + 1), col.Name, typeOID, "pg_catalog", col.Type, int64(-1), !col.Nullable, false, "", "", def})
		}
		constraintNames := daemonBudgetedConstraintNames(t, name, len(d.Constraints), i)
		for n, k := range d.Constraints {
			kind := map[string]string{"PRIMARY KEY": "p", "UNIQUE": "u", "FOREIGN KEY": "f", "CHECK": "c", "p": "p", "u": "u", "f": "f", "c": "c"}[k.Kind]
			cols := k.Columns
			if kind == "c" {
				cols = k.Referenced
			}
			foreign, foreignCols, match, update, remove := int64(0), "", "", "", ""
			if kind == "f" {
				foreign = c.OIDs[k.Target]
				foreignCols = daemonBudgetedAttnums(c.Tables[k.Target], k.TargetColumns, ",")
				match, update, remove = "s", "a", "a"
			}
			var expr driver.Value
			if kind == "c" {
				expr = k.Expression
			}
			c.Rows[daemonBudgetedCatalogKey("constraints", oid)] = append(c.Rows[daemonBudgetedCatalogKey("constraints", oid)], []driver.Value{int64(30000 + i*100 + n), constraintNames[n], kind, true, false, false, true, int64(0), daemonBudgetedAttnums(d, cols, ","), foreign, foreignCols, match, update, remove, expr})
		}
		for n, k := range d.Indexes {
			nameValue := k.Name
			if nameValue == "constraint-owned-name-not-authority" {
				nameValue = fmt.Sprintf("index_%02d", n)
			}
			zeros := make([]string, len(k.Columns))
			for z := range zeros {
				zeros[z] = "0"
			}
			c.Rows[daemonBudgetedCatalogKey("indexes", oid)] = append(c.Rows[daemonBudgetedCatalogKey("indexes", oid)], []driver.Value{int64(40000 + i*100 + n), nameValue, "btree", k.Primary, k.Unique, true, true, true, true, int64(len(k.Columns)), int64(len(k.Columns)), daemonBudgetedAttnums(d, k.Columns, " "), strings.Join(zeros, " "), nil, nil})
		}
		for _, query := range []string{"constraints", "indexes"} {
			key := daemonBudgetedCatalogKey(query, oid)
			sort.Slice(c.Rows[key], func(a, b int) bool { return c.Rows[key][a][1].(string) < c.Rows[key][b][1].(string) })
		}
		c.Rows[daemonBudgetedCatalogKey("policies", oid)] = [][]driver.Value{{int64(50000 + i), name + "_tenant_isolation", "*", true, "0", "tenant_id = current_setting('open_trestle.tenant_id', true)", "tenant_id = current_setting('open_trestle.tenant_id', true)"}}
		insert := name == daemonBudgetedErasureScopes || name == daemonBudgetedErasureMetadata || name == daemonBudgetedErasureAdmissions || name == daemonBudgetedErasureOperations || name == daemonBudgetedResumeAllowances || name == daemonBudgetedResumeAttempts || name == daemonBudgetedResumeEvidence
		updateAny := name == daemonBudgetedErasureAdmissions || name == daemonBudgetedResumeAllowances
		updateTable := name == daemonBudgetedErasureAdmissions
		c.Rows[daemonBudgetedCatalogKey("table_privileges", oid)] = [][]driver.Value{{true, true, insert, updateTable, false, false, updateAny}}
		if name == daemonBudgetedErasureAdmissions {
			c.Rows[daemonBudgetedCatalogKey("confirmation_privileges", oid)] = [][]driver.Value{{true, true, true}}
		}
		if name == daemonBudgetedResumeAllowances {
			yes := make([]driver.Value, 11)
			for j := range yes {
				yes[j] = true
			}
			no := make([]driver.Value, 25)
			for j := range no {
				no[j] = false
			}
			c.Rows[daemonBudgetedCatalogKey("allowance_counter_privileges", oid)] = [][]driver.Value{yes}
			c.Rows[daemonBudgetedCatalogKey("allowance_immutable_privileges", oid)] = [][]driver.Value{no}
		}
		c.Rows[daemonBudgetedCatalogKey("user_triggers", oid)] = [][]driver.Value{{false}}
	}
	for i, hash := range daemonBudgetedMigrationHashes {
		c.Rows["migration_rows"] = append(c.Rows["migration_rows"], []driver.Value{int64(i + 1), hash})
	}
	c.Rows["authority_schemas"] = [][]driver.Value{{c.Schema, c.Schema, c.Schema}}
	c.Rows["authority_identity"] = [][]driver.Value{{c.Database, c.Schema, c.Role, c.Namespace}}
	return c
}

var daemonBudgetedMigrationHashes = []string{
	"0851e0f67a9e743b341f3ee6ec7f9fa76b8e357be760288babb343c02c97c875",
	"c366087870ef9b9473ce36b0226e51b20d5909ecd9bde2c7d4c2b6af5cffb197",
	"a0c7db325849510df8067ef84ae4ed3ad0e8fe4863902161163a91ce578a218f",
	"966735c8949937700a2324107520977159a371314085cc1e3340da613a9e7c20",
	"57c661e7233d925905d2b67583594777cf929e38d91863fbbc1270dcb55b4476",
	"054802bf6a6d8f43fbd688d56a11bd7dcfd5aff1c54f7efc466452b6df103f9e",
	"1f5022dccb073081833f7190e7f5feab1ee956f32ebcd69eb9c4d7ff355f97d8",
	"39457b6ccb1932e6af18d5dca4ce1ad701a3d9021bb607224aac6b13293dc78f",
	"cf4f73b98666478a3749895189011eed9e4da9ae3f216cd1e1da47e9490143f1",
	"b681d2cf121d9e72e5f7343e66ae27cff7488ecdeb5618ba6b24686edee135fb",
	"905abe68b8469d782d753158d69bb2460268d95327ada7510a721dba8bf6ea98",
	"01ae7b861f99db41ca438b44e4e5989aa61bec32f5515d381f1798e30fe06713",
	"1e4b1c717d8ac8dc5a5bde19ca43df203d88e2494b433ffb0d7e0e463ca49ebe",
}

const (
	daemonBudgetedErasureScopes     = "open_trestle_review_scopes"
	daemonBudgetedErasureMetadata   = "open_trestle_artifacts"
	daemonBudgetedErasureAdmissions = "open_trestle_artifact_admissions"
	daemonBudgetedErasureOperations = "open_trestle_artifact_erasure_operations"
	daemonBudgetedResumeAllowances  = "open_trestle_erasure_resume_allowances"
	daemonBudgetedResumeAttempts    = "open_trestle_erasure_attempts"
	daemonBudgetedResumeEvidence    = "open_trestle_erasure_attempt_evidence"
)

func daemonBudgetedConstraintNames(t *testing.T, table string, count, offset int) []string {
	t.Helper()
	var names map[string][]string
	if err := json.Unmarshal([]byte(daemonBudgetedResumeConstraintNamesJSON), &names); err != nil {
		t.Fatal(err)
	}
	if existing := names[table]; len(existing) == count {
		return existing
	}
	out := make([]string, count)
	for i := range out {
		out[i] = fmt.Sprintf("constraint_%02d_%02d", offset, i)
	}
	return out
}
func daemonBudgetedCatalogKey(id string, oid int64) string {
	return id + ":" + strconv.FormatInt(oid, 10)
}
func daemonBudgetedAttnums(d daemonBudgetedTableDescriptor, columns []string, separator string) string {
	values := []string{}
	for _, name := range columns {
		for i, c := range d.Columns {
			if c.Name == name {
				values = append(values, strconv.Itoa(i+1))
				break
			}
		}
	}
	return strings.Join(values, separator)
}

func daemonBudgetedScopeKey(a, b, c driver.Value) string {
	return fmt.Sprint(a) + "\x00" + fmt.Sprint(b) + "\x00" + fmt.Sprint(c)
}
func daemonBudgetedArtifactKey(a, b, c, d driver.Value) string {
	return daemonBudgetedScopeKey(a, b, c) + "\x00" + fmt.Sprint(d)
}
func daemonBudgetedDiagnosticKey(a, b, c driver.Value) string {
	return daemonBudgetedScopeKey(a, b, c)
}
func daemonBudgetedWebhookKey(a, b, source, key driver.Value) string {
	return fmt.Sprint(a) + "\x00" + fmt.Sprint(b) + "\x00" + fmt.Sprint(source) + "\x00" + fmt.Sprint(key)
}
func daemonBudgetedAdmissionKey(a, b, c, d, e driver.Value) string {
	return daemonBudgetedScopeKey(a, b, c) + "\x00" + fmt.Sprint(d) + "\x00" + fmt.Sprint(e)
}
func daemonBudgetedRateLimitKey(namespace, digest driver.Value) string {
	return fmt.Sprint(namespace) + "\x00" + fmt.Sprint(digest)
}
func daemonBudgetedBytes(v driver.Value) []byte {
	if b, ok := v.([]byte); ok {
		return append([]byte(nil), b...)
	}
	return nil
}
func daemonBudgetedInt64(v driver.Value) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	default:
		return 0, false
	}
}
func daemonBudgetedCopyRows(in [][]driver.Value) [][]driver.Value {
	out := make([][]driver.Value, len(in))
	for i := range in {
		out[i] = daemonBudgetedCopyValues(in[i])
	}
	return out
}
func daemonBudgetedCloneScopes(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func daemonBudgetedCloneMetadata(in map[string]daemonBudgetedMetadataRow) map[string]daemonBudgetedMetadataRow {
	out := map[string]daemonBudgetedMetadataRow{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func daemonBudgetedCloneDiagnostics(in map[string]daemonBudgetedDiagnosticRow) map[string]daemonBudgetedDiagnosticRow {
	out := map[string]daemonBudgetedDiagnosticRow{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func daemonBudgetedCloneWebhooks(in map[string]daemonBudgetedWebhookRow) map[string]daemonBudgetedWebhookRow {
	out := map[string]daemonBudgetedWebhookRow{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func daemonBudgetedCloneRunPlans(in map[string]daemonBudgetedRunPlanRow) map[string]daemonBudgetedRunPlanRow {
	out := make(map[string]daemonBudgetedRunPlanRow, len(in))
	for k, v := range in {
		v.CanonicalPlan = daemonBudgetedBytes(v.CanonicalPlan)
		out[k] = v
	}
	return out
}

func daemonBudgetedCloneRunEvents(in map[string][]daemonBudgetedRunEventRow) map[string][]daemonBudgetedRunEventRow {
	out := make(map[string][]daemonBudgetedRunEventRow, len(in))
	for k, rows := range in {
		cloned := make([]daemonBudgetedRunEventRow, len(rows))
		for i, v := range rows {
			v.CanonicalEvent = daemonBudgetedBytes(v.CanonicalEvent)
			cloned[i] = v
		}
		out[k] = cloned
	}
	return out
}
func daemonBudgetedCloneAuditEvents(in map[string][]daemonBudgetedAuditEventRow) map[string][]daemonBudgetedAuditEventRow {
	out := make(map[string][]daemonBudgetedAuditEventRow, len(in))
	for key, value := range in {
		rows := append([]daemonBudgetedAuditEventRow(nil), value...)
		for i := range rows {
			rows[i].CanonicalEvent = daemonBudgetedBytes(rows[i].CanonicalEvent)
		}
		out[key] = rows
	}
	return out
}

func daemonBudgetedCloneAdmissions(in map[string]daemonBudgetedAdmissionRow) map[string]daemonBudgetedAdmissionRow {
	out := map[string]daemonBudgetedAdmissionRow{}
	for k, v := range in {
		v.CanonicalAdmission = append([]byte(nil), v.CanonicalAdmission...)
		v.CanonicalNamespace = append([]byte(nil), v.CanonicalNamespace...)
		v.PolicyBytes = append([]byte(nil), v.PolicyBytes...)
		out[k] = v
	}
	return out
}
func daemonBudgetedCloneRateLimits(in map[string]daemonBudgetedRateLimitRow) map[string]daemonBudgetedRateLimitRow {
	out := map[string]daemonBudgetedRateLimitRow{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func daemonBudgetedAuthorityIdentity(c daemonBudgetedCatalog) string {
	encoded, _ := json.Marshal(struct {
		Contract  string `json:"contract"`
		Version   int    `json:"version"`
		Database  string `json:"database"`
		Schema    string `json:"schema"`
		Role      string `json:"role"`
		Namespace string `json:"namespace"`
	}{"open-trestle/postgresql-database-authority", 1, c.Database, c.Schema, c.Role, c.Namespace})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func daemonBudgetedTraceContains(events []daemonBudgetedSQLTraceEvent, id string) bool {
	for _, e := range events {
		if e.StatementID == id {
			return true
		}
	}
	return false
}
func daemonBudgetedTraceCount(events []daemonBudgetedSQLTraceEvent, id string) int {
	count := 0
	for _, e := range events {
		if e.StatementID == id {
			count++
		}
	}
	return count
}
