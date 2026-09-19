package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

func resumeSchemaDescriptors() []journalSchemaTable {
	return []journalSchemaTable{
		{name: "open_trestle_erasure_resume_allowances", columns: []journalSchemaColumn{
			{name: "tenant_id", kind: "text", nullable: false},
			{name: "repository_id", kind: "text", nullable: false},
			{name: "review_run_id", kind: "text", nullable: false},
			{name: "scope_identity", kind: "text", nullable: false},
			{name: "namespace_identity", kind: "text", nullable: false},
			{name: "artifact_identity", kind: "text", nullable: false},
			{name: "admission_identity", kind: "text", nullable: false},
			{name: "operation_identity", kind: "text", nullable: false},
			{name: "allowance_identity", kind: "text", nullable: false},
			{name: "canonical_allowance", kind: "bytea", nullable: false},
			{name: "allowance_document_digest", kind: "text", nullable: false},
			{name: "accepted_policy", kind: "bytea", nullable: false},
			{name: "protected_policy_identity", kind: "text", nullable: false},
			{name: "accepted_at_milliseconds", kind: "int8", nullable: false},
			{name: "maximum_requests", kind: "int8", nullable: false},
			{name: "maximum_mutations", kind: "int8", nullable: false},
			{name: "maximum_reads", kind: "int8", nullable: false},
			{name: "maximum_lists", kind: "int8", nullable: false},
			{name: "maximum_creates", kind: "int8", nullable: false},
			{name: "maximum_deletes", kind: "int8", nullable: false},
			{name: "maximum_pages", kind: "int8", nullable: false},
			{name: "maximum_versions", kind: "int8", nullable: false},
			{name: "maximum_response_bytes", kind: "int8", nullable: false},
			{name: "maximum_list_bytes", kind: "int8", nullable: false},
			{name: "maximum_write_bytes", kind: "int8", nullable: false},
			{name: "spent_requests", kind: "int8", nullable: false},
			{name: "spent_mutations", kind: "int8", nullable: false},
			{name: "spent_reads", kind: "int8", nullable: false},
			{name: "spent_lists", kind: "int8", nullable: false},
			{name: "spent_creates", kind: "int8", nullable: false},
			{name: "spent_deletes", kind: "int8", nullable: false},
			{name: "spent_pages", kind: "int8", nullable: false},
			{name: "spent_versions", kind: "int8", nullable: false},
			{name: "spent_response_bytes", kind: "int8", nullable: false},
			{name: "spent_list_bytes", kind: "int8", nullable: false},
			{name: "spent_write_bytes", kind: "int8", nullable: false},
		}, constraints: []journalSchemaConstraint{
			{kind: "c", columns: []string{"tenant_id"}, expression: "octet_length(tenant_id) BETWEEN 1 AND 128", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"repository_id"}, expression: "octet_length(repository_id) BETWEEN 1 AND 128", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"review_run_id"}, expression: "octet_length(review_run_id) BETWEEN 1 AND 128", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"scope_identity"}, expression: "scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"namespace_identity"}, expression: "namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"artifact_identity"}, expression: "artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"admission_identity"}, expression: "admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"operation_identity"}, expression: "operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"allowance_identity"}, expression: "allowance_identity ~ '^[0-9a-f]{64}$' AND allowance_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"canonical_allowance"}, expression: "octet_length(canonical_allowance) BETWEEN 1 AND 4096", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"allowance_document_digest"}, expression: "allowance_document_digest ~ '^[0-9a-f]{64}$' AND allowance_document_digest <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"accepted_policy"}, expression: "octet_length(accepted_policy) BETWEEN 1 AND 16384", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"protected_policy_identity"}, expression: "protected_policy_identity ~ '^[0-9a-f]{64}$' AND protected_policy_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"accepted_at_milliseconds"}, expression: "accepted_at_milliseconds BETWEEN 1 AND 253402300799999", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"maximum_requests"}, expression: "maximum_requests BETWEEN 0 AND 4096", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"maximum_mutations"}, expression: "maximum_mutations BETWEEN 0 AND 2048", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"maximum_reads"}, expression: "maximum_reads BETWEEN 0 AND 2048", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"maximum_lists"}, expression: "maximum_lists BETWEEN 0 AND 1024", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"maximum_creates"}, expression: "maximum_creates BETWEEN 0 AND 128", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"maximum_deletes"}, expression: "maximum_deletes BETWEEN 0 AND 2048", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"maximum_pages"}, expression: "maximum_pages BETWEEN 0 AND 1024", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"maximum_versions"}, expression: "maximum_versions BETWEEN 0 AND 262144", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"maximum_response_bytes"}, expression: "maximum_response_bytes BETWEEN 0 AND 1073741824", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"maximum_list_bytes"}, expression: "maximum_list_bytes BETWEEN 0 AND 67108864", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"maximum_write_bytes"}, expression: "maximum_write_bytes BETWEEN 0 AND 2097152", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_requests"}, expression: "spent_requests BETWEEN 0 AND maximum_requests", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_mutations"}, expression: "spent_mutations BETWEEN 0 AND maximum_mutations", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_reads"}, expression: "spent_reads BETWEEN 0 AND maximum_reads", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_lists"}, expression: "spent_lists BETWEEN 0 AND maximum_lists", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_creates"}, expression: "spent_creates BETWEEN 0 AND maximum_creates", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_deletes"}, expression: "spent_deletes BETWEEN 0 AND maximum_deletes", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_pages"}, expression: "spent_pages BETWEEN 0 AND maximum_pages", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_versions"}, expression: "spent_versions BETWEEN 0 AND maximum_versions", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_response_bytes"}, expression: "spent_response_bytes BETWEEN 0 AND maximum_response_bytes", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_list_bytes"}, expression: "spent_list_bytes BETWEEN 0 AND maximum_list_bytes", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_write_bytes"}, expression: "spent_write_bytes BETWEEN 0 AND maximum_write_bytes", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"maximum_requests"}, expression: "maximum_requests >= 1", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"maximum_requests", "maximum_mutations"}, expression: "maximum_mutations <= maximum_requests", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_requests", "spent_mutations"}, expression: "spent_mutations <= spent_requests", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_requests", "spent_reads", "spent_lists", "spent_creates", "spent_deletes"}, expression: "spent_reads + spent_lists + spent_creates + spent_deletes = spent_requests", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_mutations", "spent_creates", "spent_deletes"}, expression: "spent_mutations = spent_creates + spent_deletes", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"spent_lists", "spent_pages"}, expression: "spent_pages = spent_lists", target: "", targetColumns: []string{}},
			{kind: "p", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "allowance_identity"}, expression: "", target: "", targetColumns: []string{}},
			{kind: "u", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity", "allowance_identity"}, expression: "", target: "", targetColumns: []string{}},
			{kind: "f", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity"}, expression: "", target: "open_trestle_artifact_erasure_operations", targetColumns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity"}},
		}, indexes: []journalSchemaIndex{
			{name: "open_trestle_erasure_resume_allowances_pkey", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "allowance_identity"}, unique: true, primary: true},
			{name: "open_trestle_erasure_resume_allowances_u1", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity", "allowance_identity"}, unique: true, primary: false},
		}},
		{name: "open_trestle_erasure_attempts", columns: []journalSchemaColumn{
			{name: "tenant_id", kind: "text", nullable: false},
			{name: "repository_id", kind: "text", nullable: false},
			{name: "review_run_id", kind: "text", nullable: false},
			{name: "scope_identity", kind: "text", nullable: false},
			{name: "namespace_identity", kind: "text", nullable: false},
			{name: "artifact_identity", kind: "text", nullable: false},
			{name: "admission_identity", kind: "text", nullable: false},
			{name: "operation_identity", kind: "text", nullable: false},
			{name: "allowance_identity", kind: "text", nullable: false},
			{name: "reservation_identity", kind: "text", nullable: false},
			{name: "attempt_identity", kind: "text", nullable: false},
			{name: "request_identity", kind: "text", nullable: false},
			{name: "canonical_request", kind: "bytea", nullable: false},
			{name: "canonical_attempt", kind: "bytea", nullable: false},
			{name: "sequence", kind: "int8", nullable: false},
			{name: "reserved_at_milliseconds", kind: "int8", nullable: false},
			{name: "cost_requests", kind: "int8", nullable: false},
			{name: "cost_mutations", kind: "int8", nullable: false},
			{name: "cost_reads", kind: "int8", nullable: false},
			{name: "cost_lists", kind: "int8", nullable: false},
			{name: "cost_creates", kind: "int8", nullable: false},
			{name: "cost_deletes", kind: "int8", nullable: false},
			{name: "cost_pages", kind: "int8", nullable: false},
			{name: "cost_versions", kind: "int8", nullable: false},
			{name: "cost_response_bytes", kind: "int8", nullable: false},
			{name: "cost_list_bytes", kind: "int8", nullable: false},
			{name: "cost_write_bytes", kind: "int8", nullable: false},
		}, constraints: []journalSchemaConstraint{
			{kind: "c", columns: []string{"tenant_id"}, expression: "octet_length(tenant_id) BETWEEN 1 AND 128", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"repository_id"}, expression: "octet_length(repository_id) BETWEEN 1 AND 128", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"review_run_id"}, expression: "octet_length(review_run_id) BETWEEN 1 AND 128", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"scope_identity"}, expression: "scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"namespace_identity"}, expression: "namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"artifact_identity"}, expression: "artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"admission_identity"}, expression: "admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"operation_identity"}, expression: "operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"allowance_identity"}, expression: "allowance_identity ~ '^[0-9a-f]{64}$' AND allowance_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"reservation_identity"}, expression: "reservation_identity ~ '^[0-9a-f]{64}$' AND reservation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"attempt_identity"}, expression: "attempt_identity ~ '^[0-9a-f]{64}$' AND attempt_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"request_identity"}, expression: "request_identity ~ '^[0-9a-f]{64}$' AND request_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"canonical_request"}, expression: "octet_length(canonical_request) BETWEEN 1 AND 8192", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"canonical_attempt"}, expression: "octet_length(canonical_attempt) BETWEEN 1 AND 1024", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"sequence"}, expression: "sequence BETWEEN 1 AND 4096", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"reserved_at_milliseconds"}, expression: "reserved_at_milliseconds BETWEEN 1 AND 253402300799999", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_requests"}, expression: "cost_requests BETWEEN 0 AND 4096", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_mutations"}, expression: "cost_mutations BETWEEN 0 AND 2048", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_reads"}, expression: "cost_reads BETWEEN 0 AND 2048", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_lists"}, expression: "cost_lists BETWEEN 0 AND 1024", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_creates"}, expression: "cost_creates BETWEEN 0 AND 128", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_deletes"}, expression: "cost_deletes BETWEEN 0 AND 2048", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_pages"}, expression: "cost_pages BETWEEN 0 AND 1024", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_versions"}, expression: "cost_versions BETWEEN 0 AND 262144", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_response_bytes"}, expression: "cost_response_bytes BETWEEN 0 AND 1073741824", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_list_bytes"}, expression: "cost_list_bytes BETWEEN 0 AND 67108864", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_write_bytes"}, expression: "cost_write_bytes BETWEEN 0 AND 2097152", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_requests"}, expression: "cost_requests = 1", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_mutations", "cost_creates", "cost_deletes"}, expression: "cost_mutations = cost_creates + cost_deletes", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_reads", "cost_lists", "cost_creates", "cost_deletes"}, expression: "cost_reads + cost_lists + cost_creates + cost_deletes = 1", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_lists", "cost_pages"}, expression: "cost_pages = cost_lists", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"cost_mutations"}, expression: "cost_mutations BETWEEN 0 AND 1", target: "", targetColumns: []string{}},
			{kind: "p", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "reservation_identity"}, expression: "", target: "", targetColumns: []string{}},
			{kind: "u", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "attempt_identity"}, expression: "", target: "", targetColumns: []string{}},
			{kind: "u", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "allowance_identity", "sequence"}, expression: "", target: "", targetColumns: []string{}},
			{kind: "u", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity", "attempt_identity"}, expression: "", target: "", targetColumns: []string{}},
			{kind: "f", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity"}, expression: "", target: "open_trestle_artifact_erasure_operations", targetColumns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity"}},
			{kind: "f", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity", "allowance_identity"}, expression: "", target: "open_trestle_erasure_resume_allowances", targetColumns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity", "allowance_identity"}},
		}, indexes: []journalSchemaIndex{
			{name: "open_trestle_erasure_attempts_pkey", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "reservation_identity"}, unique: true, primary: true},
			{name: "open_trestle_erasure_attempts_u1", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "attempt_identity"}, unique: true, primary: false},
			{name: "open_trestle_erasure_attempts_u2", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "allowance_identity", "sequence"}, unique: true, primary: false},
			{name: "open_trestle_erasure_attempts_u3", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity", "attempt_identity"}, unique: true, primary: false},
		}},
		{name: "open_trestle_erasure_attempt_evidence", columns: []journalSchemaColumn{
			{name: "tenant_id", kind: "text", nullable: false},
			{name: "repository_id", kind: "text", nullable: false},
			{name: "review_run_id", kind: "text", nullable: false},
			{name: "scope_identity", kind: "text", nullable: false},
			{name: "namespace_identity", kind: "text", nullable: false},
			{name: "artifact_identity", kind: "text", nullable: false},
			{name: "admission_identity", kind: "text", nullable: false},
			{name: "operation_identity", kind: "text", nullable: false},
			{name: "evidence_identity", kind: "text", nullable: false},
			{name: "slot", kind: "text", nullable: false},
			{name: "kind", kind: "text", nullable: false},
			{name: "attempt_identity", kind: "text", nullable: true},
			{name: "canonical_evidence", kind: "bytea", nullable: false},
			{name: "observed_at_milliseconds", kind: "int8", nullable: false},
		}, constraints: []journalSchemaConstraint{
			{kind: "c", columns: []string{"tenant_id"}, expression: "octet_length(tenant_id) BETWEEN 1 AND 128", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"repository_id"}, expression: "octet_length(repository_id) BETWEEN 1 AND 128", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"review_run_id"}, expression: "octet_length(review_run_id) BETWEEN 1 AND 128", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"scope_identity"}, expression: "scope_identity ~ '^[0-9a-f]{64}$' AND scope_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"namespace_identity"}, expression: "namespace_identity ~ '^[0-9a-f]{64}$' AND namespace_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"artifact_identity"}, expression: "artifact_identity ~ '^[0-9a-f]{64}$' AND artifact_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"admission_identity"}, expression: "admission_identity ~ '^[0-9a-f]{64}$' AND admission_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"operation_identity"}, expression: "operation_identity ~ '^[0-9a-f]{64}$' AND operation_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"evidence_identity"}, expression: "evidence_identity ~ '^[0-9a-f]{64}$' AND evidence_identity <> '0000000000000000000000000000000000000000000000000000000000000000'", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"slot"}, expression: "octet_length(slot) BETWEEN 1 AND 80", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"kind"}, expression: "kind IN ('response', 'unknown', 'fence', 'verification', 'candidate', 'published')", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"attempt_identity"}, expression: "attempt_identity IS NULL OR (attempt_identity ~ '^[0-9a-f]{64}$' AND attempt_identity <> '0000000000000000000000000000000000000000000000000000000000000000')", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"canonical_evidence"}, expression: "octet_length(canonical_evidence) BETWEEN 1 AND 1048576", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"observed_at_milliseconds"}, expression: "observed_at_milliseconds BETWEEN 1 AND 253402300799999", target: "", targetColumns: []string{}},
			{kind: "c", columns: []string{"slot", "kind", "attempt_identity"}, expression: "(kind = 'response' AND attempt_identity IS NOT NULL AND slot = 'response:' || attempt_identity) OR (kind = 'unknown' AND attempt_identity IS NOT NULL AND slot = 'unknown:' || attempt_identity) OR (kind = 'fence' AND attempt_identity IS NULL AND slot = 'fence') OR (kind = 'verification' AND attempt_identity IS NULL AND slot ~ '^verification:[0-9a-f]{64}$') OR (kind = 'candidate' AND attempt_identity IS NULL AND slot = 'candidate') OR (kind = 'published' AND attempt_identity IS NULL AND slot = 'published')", target: "", targetColumns: []string{}},
			{kind: "p", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "slot"}, expression: "", target: "", targetColumns: []string{}},
			{kind: "u", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "evidence_identity"}, expression: "", target: "", targetColumns: []string{}},
			{kind: "f", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity"}, expression: "", target: "open_trestle_artifact_erasure_operations", targetColumns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity"}},
			{kind: "f", columns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity", "attempt_identity"}, expression: "", target: "open_trestle_erasure_attempts", targetColumns: []string{"tenant_id", "repository_id", "review_run_id", "scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity", "attempt_identity"}},
		}, indexes: []journalSchemaIndex{
			{name: "open_trestle_erasure_attempt_evidence_pkey", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "slot"}, unique: true, primary: true},
			{name: "open_trestle_erasure_attempt_evidence_u1", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "evidence_identity"}, unique: true, primary: false},
			{name: "open_trestle_erasure_attempt_evidence_attempt_scan", columns: []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "attempt_identity", "slot"}, unique: false, primary: false},
		}},
	}
}
func verifyResumeColumns(ctx context.Context, tx *sql.Tx, oid int64, t journalSchemaTable) error {
	rows, err := readErasureRows(ctx, tx, journalSQLAttributes, 11, 64, oid)
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
			if !ok || !resumeExpressionEqual(expression, c.defaultExpr, t) {
				return ErrDatabaseAuthorityMismatch
			}
		}
	}
	return nil
}
func verifyResumeConstraints(ctx context.Context, tx *sql.Tx, oid int64, t journalSchemaTable, oids map[string]int64, tables map[string]journalSchemaTable, seen map[int64]bool) error {
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
					if !ok || !resumeExpressionEqual(expression, c.expression, t) {
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
func verifyResumeIndexes(ctx context.Context, tx *sql.Tx, oid int64, t journalSchemaTable, seen map[int64]bool) error {
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

type resumeExpr struct {
	op, typ, atom string
	args          []*resumeExpr
}
type resumeExprToken struct{ kind, value string }
type resumeExprParser struct {
	tokens    []resumeExprToken
	at, depth int
	failed    bool
	columns   map[string]string
}

func resumeExpressionEqual(actual, expected string, table journalSchemaTable) bool {
	a, ok := parseResumeExpression(actual, table)
	if !ok {
		return false
	}
	b, ok := parseResumeExpression(expected, table)
	return ok && reflect.DeepEqual(a, b)
}
func parseResumeExpression(text string, table journalSchemaTable) (*resumeExpr, bool) {
	tokens, ok := lexResumeExpression(text)
	if !ok {
		return nil, false
	}
	p := resumeExprParser{tokens: tokens, columns: map[string]string{}}
	for _, c := range table.columns {
		p.columns[c.name] = c.kind
	}
	node := p.or()
	return node, !p.failed && node != nil && p.at == len(tokens)
}
func lexResumeExpression(text string) ([]resumeExprToken, bool) {
	if len(text) == 0 || len(text) > 8192 || !utf8.ValidString(text) {
		return nil, false
	}
	var tokens []resumeExprToken
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
			tokens = append(tokens, resumeExprToken{kind, b.String()})
			continue
		}
		if ch >= '0' && ch <= '9' {
			start := i
			for i < len(text) && text[i] >= '0' && text[i] <= '9' {
				i++
			}
			tokens = append(tokens, resumeExprToken{"number", text[start:i]})
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
			tokens = append(tokens, resumeExprToken{"word", word})
			continue
		}
		if i+1 < len(text) {
			pair := text[i : i+2]
			if pair == "::" || pair == "<>" || pair == ">=" || pair == "<=" || pair == "!~" || pair == "||" {
				tokens = append(tokens, resumeExprToken{"symbol", pair})
				i += 2
				continue
			}
		}
		if strings.ContainsRune("(),.[]=~><-+", rune(ch)) {
			tokens = append(tokens, resumeExprToken{"symbol", string(ch)})
			i++
			continue
		}
		return nil, false
	}
	return tokens, len(tokens) > 0
}
func (p *resumeExprParser) peek(value string) bool {
	return p.at < len(p.tokens) && p.tokens[p.at].value == value && p.tokens[p.at].kind != "literal" && p.tokens[p.at].kind != "identifier"
}
func (p *resumeExprParser) take(value string) bool {
	if p.peek(value) {
		p.at++
		return true
	}
	return false
}
func (p *resumeExprParser) require(value string) {
	if !p.take(value) {
		p.failed = true
	}
}
func resumeLogic(op string, a, b *resumeExpr) *resumeExpr {
	if a == nil || b == nil || a.typ != "bool" || b.typ != "bool" {
		return nil
	}
	result := &resumeExpr{op: op, typ: "bool"}
	for _, n := range []*resumeExpr{a, b} {
		if n.op == op {
			result.args = append(result.args, n.args...)
		} else {
			result.args = append(result.args, n)
		}
	}
	return result
}
func (p *resumeExprParser) or() *resumeExpr {
	if p.depth >= 64 {
		p.failed = true
		return nil
	}
	p.depth++
	defer func() { p.depth-- }()
	n := p.and()
	for !p.failed && p.take("OR") {
		n = resumeLogic("or", n, p.and())
		if n == nil {
			p.failed = true
		}
	}
	return n
}
func (p *resumeExprParser) and() *resumeExpr {
	n := p.comparison()
	for !p.failed && p.take("AND") {
		n = resumeLogic("and", n, p.comparison())
		if n == nil {
			p.failed = true
		}
	}
	return n
}
func resumeNumeric(t string) bool { return t == "int4" || t == "int8" || t == "number" }
func resumeCompatible(a, b *resumeExpr) bool {
	return a != nil && b != nil && (a.typ == b.typ || resumeNumeric(a.typ) && resumeNumeric(b.typ))
}
func resumeCompare(op string, a, b *resumeExpr) *resumeExpr {
	if !resumeCompatible(a, b) {
		return nil
	}
	if (op == "~" || op == "!~") && (a.typ != "text" || b.typ != "text") {
		return nil
	}
	return &resumeExpr{op: op, typ: "bool", args: []*resumeExpr{a, b}}
}
func (p *resumeExprParser) comparison() *resumeExpr {
	left := p.concat()
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
		return &resumeExpr{op: op, typ: "bool", args: []*resumeExpr{left}}
	}
	if p.take("BETWEEN") {
		low := p.concat()
		p.require("AND")
		high := p.concat()
		n := resumeLogic("and", resumeCompare(">=", left, low), resumeCompare("<=", left, high))
		if n == nil {
			p.failed = true
		}
		return n
	}
	if p.take("IN") {
		p.require("(")
		var values []*resumeExpr
		for !p.failed {
			n := p.concat()
			if n == nil || n.op != "literal" || !resumeCompatible(left, n) || len(values) >= 128 {
				p.failed = true
				break
			}
			values = append(values, n)
			if !p.take(",") {
				break
			}
		}
		p.require(")")
		return &resumeExpr{op: "any=", typ: "bool", args: append([]*resumeExpr{left}, values...)}
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
			array := p.concat()
			p.require(")")
			if array == nil || array.op != "array" || len(array.args) == 0 {
				p.failed = true
				return nil
			}
			for _, a := range array.args {
				if a.op != "literal" || !resumeCompatible(left, a) {
					p.failed = true
					return nil
				}
			}
			return &resumeExpr{op: "any=", typ: "bool", args: append([]*resumeExpr{left}, array.args...)}
		}
		n := resumeCompare(op, left, p.concat())
		if n == nil {
			p.failed = true
		}
		return n
	}
	return left
}
func (p *resumeExprParser) name() (string, bool) {
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
		case "octet_length", "left", "current_setting", "text", "int4", "int8", "integer", "bigint":
		default:
			return "", false
		}
	}
	return name, true
}
func (p *resumeExprParser) value() *resumeExpr {
	if p.failed || p.at >= len(p.tokens) || p.depth >= 64 {
		p.failed = true
		return nil
	}
	p.depth++
	defer func() { p.depth-- }()
	var n *resumeExpr
	switch {
	case p.take("("):
		n = p.or()
		p.require(")")
	case p.take("ARRAY"):
		p.require("[")
		var values []*resumeExpr
		for !p.failed {
			v := p.value()
			if v == nil || v.op != "literal" || len(values) >= 128 || len(values) > 0 && !resumeCompatible(values[0], v) {
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
		n = &resumeExpr{op: "array", typ: values[0].typ + "[]", args: values}
	case p.take("TRUE"):
		n = &resumeExpr{op: "literal", typ: "bool", atom: "true"}
	case p.take("FALSE"):
		n = &resumeExpr{op: "literal", typ: "bool", atom: "false"}
	default:
		negative := p.take("-")
		if p.at >= len(p.tokens) {
			p.failed = true
			return nil
		}
		token := p.tokens[p.at]
		if token.kind == "literal" && !negative {
			p.at++
			n = &resumeExpr{op: "literal", typ: "text", atom: token.value}
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
			n = &resumeExpr{op: "literal", typ: "number", atom: v}
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
				var args []*resumeExpr
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
				n = &resumeExpr{op: "column", typ: kind, atom: name}
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
func (p *resumeExprParser) function(name string, args []*resumeExpr) *resumeExpr {
	switch name {
	case "octet_length":
		if len(args) == 1 && (args[0].typ == "text" || args[0].typ == "bytea") {
			return &resumeExpr{op: name, typ: "int4", args: args}
		}
	case "left":
		if len(args) == 2 && args[0].typ == "text" && args[1].op == "literal" && resumeNumeric(args[1].typ) {
			return &resumeExpr{op: name, typ: "text", args: args}
		}
	case "current_setting":
		if len(args) == 2 && args[0].typ == "text" && args[0].op == "literal" && args[1].typ == "bool" && args[1].op == "literal" {
			return &resumeExpr{op: name, typ: "text", args: args}
		}

	}
	p.failed = true
	return nil
}
func (p *resumeExprParser) losslessCast(n *resumeExpr, to string) *resumeExpr {
	if n == nil {
		p.failed = true
		return nil
	}
	if to == "text" && n.typ == "text" || to == "text[]" && n.op == "array" && n.typ == "text[]" {
		return n
	}
	if to == "int4" || to == "int8" {
		if n.op == "literal" && (resumeNumeric(n.typ) || n.typ == "text") {
			number, err := strconv.ParseInt(n.atom, 10, 64)
			if err == nil && strconv.FormatInt(number, 10) == n.atom && (to == "int8" || number >= -2147483648 && number <= 2147483647) {
				return &resumeExpr{op: "literal", typ: "number", atom: n.atom}
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

func (p *resumeExprParser) addition() *resumeExpr {
	n := p.value()
	for !p.failed && p.take("+") {
		right := p.value()
		if n == nil || right == nil || !resumeNumeric(n.typ) || !resumeNumeric(right.typ) {
			p.failed = true
			return nil
		}
		typ := "int4"
		if n.typ == "int8" || right.typ == "int8" {
			typ = "int8"
		}
		n = &resumeExpr{op: "+", typ: typ, args: []*resumeExpr{n, right}}
	}
	return n
}
func (p *resumeExprParser) concat() *resumeExpr {
	n := p.addition()
	for !p.failed && p.take("||") {
		right := p.addition()
		if n == nil || right == nil || n.typ != "text" || right.typ != "text" {
			p.failed = true
			return nil
		}
		n = &resumeExpr{op: "||", typ: "text", args: []*resumeExpr{n, right}}
	}
	return n
}

func resumeSchemaDescriptorDigest() string {
	var parts []string
	parts = append(parts, "three append-only resume tables; eleven mutable allowance counters; no user triggers on nine tables")
	for _, t := range resumeSchemaDescriptors() {
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
	raw, _ := json.Marshal(parts)
	return erasureDigest(raw)
}
func verifyResumeSchema(ctx context.Context, tx *sql.Tx, schema, role string) error {
	descriptors := append(erasureSchemaDescriptors(), resumeSchemaDescriptors()...)
	oids := map[string]int64{}
	byName := map[string]journalSchemaTable{}
	seen := map[int64]bool{}
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
		if oid <= 0 || nsp <= 0 || seen[oid] || schemaOID != 0 && schemaOID != nsp || !erasureExactText(r, 2, schema) || !erasureExactText(r, 3, t.name) || !erasureExactText(r, 4, "r") || !erasureBool(r, 5, true) || !erasureBool(r, 6, true) || !erasureExactInt(r, 7, oid) {
			return ErrDatabaseAuthorityMismatch
		}
		seen[oid] = true
		schemaOID = nsp
		oids[t.name] = oid
		byName[t.name] = t
		triggers, err := readErasureRows(ctx, tx, resumeSQLUserTriggers, 1, 1, oid)
		if err != nil {
			return err
		}
		if len(triggers) != 1 || !erasureBool(triggers[0], 0, false) {
			return ErrDatabaseAuthorityMismatch
		}
	}
	constraints, policies := map[int64]bool{}, map[int64]bool{}
	for _, t := range resumeSchemaDescriptors() {
		oid := oids[t.name]
		if err := verifyResumeColumns(ctx, tx, oid, t); err != nil {
			return err
		}
		if err := verifyResumeConstraints(ctx, tx, oid, t, oids, byName, constraints); err != nil {
			return err
		}
		if err := verifyResumeIndexes(ctx, tx, oid, t, seen); err != nil {
			return err
		}
		if err := verifyResumePolicyGrants(ctx, tx, oid, t, schema, role, policies); err != nil {
			return err
		}
	}
	return nil
}
func verifyResumePolicyGrants(ctx context.Context, tx *sql.Tx, oid int64, t journalSchemaTable, schema, role string, seen map[int64]bool) error {
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
		v, ok := r[i].(string)
		if !ok || !resumeExpressionEqual(v, "tenant_id = current_setting('open_trestle.tenant_id', true)", t) {
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
	allowance := t.name == "open_trestle_erasure_resume_allowances"
	wants := []bool{true, true, true, false, false, false, allowance}
	for i, want := range wants {
		if !erasureBool(rows[0], i, want) {
			return ErrDatabaseAuthorityMismatch
		}
	}
	if allowance {
		for _, q := range []struct {
			sql   string
			count int
			want  bool
		}{{resumeSQLAllowanceCounterPrivileges, 11, true}, {resumeSQLAllowanceImmutablePrivileges, 25, false}} {
			rows, err = readErasureRows(ctx, tx, q.sql, q.count, 1, oid, role)
			if err != nil {
				return err
			}
			if len(rows) != 1 {
				return ErrDatabaseAuthorityMismatch
			}
			for i := 0; i < q.count; i++ {
				if !erasureBool(rows[0], i, q.want) {
					return ErrDatabaseAuthorityMismatch
				}
			}
		}
	}
	return nil
}
