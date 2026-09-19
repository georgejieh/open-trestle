package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

const (
	replicaReconciliationTaskKey                    = "source"
	replicaReconciliationFirstWorker                = "replica-1"
	replicaReconciliationSecondWorker               = "replica-2"
	replicaReconciliationStoreInstances             = 2
	replicaReconciliationMinimumOpenConnections     = 3
	replicaReconciliationSchedulerAttempts          = 2
	replicaReconciliationNotificationClaimAttempts  = 2
	replicaReconciliationTaskClaimAttempts          = 2
	replicaReconciliationFinalizerAttempts          = 2
	replicaReconciliationExpectedNotifications      = 1
	replicaReconciliationExpectedTaskLeases         = 1
	replicaReconciliationExpectedTerminalEvents     = 1
	replicaReconciliationExpectedRunEvents          = 5
	replicaReconciliationTaskRetryDelayMilliseconds = 100
	replicaReconciliationTaskLeaseMilliseconds      = 1000
	replicaReconciliationNotificationLease          = time.Second
	replicaReconciliationMaximumTransientAttempts   = 3
	replicaReconciliationRetryDelay                 = 10 * time.Millisecond
	replicaReconciliationOperationTimeout           = 45 * time.Second
)

var replicaReconciliationTimelineOffsets = []time.Duration{0, time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond, 4 * time.Millisecond, 5 * time.Millisecond, 6 * time.Millisecond}
var replicaReconciliationExpectedEventKinds = []string{"opened", "task_available", "task_leased", "task_succeeded", "succeeded"}
var replicaReconciliationEventOffsets = []time.Duration{0, time.Millisecond, 4 * time.Millisecond, 5 * time.Millisecond, 6 * time.Millisecond}
var replicaReconciliationWorkerIdentities = []string{replicaReconciliationFirstWorker, replicaReconciliationSecondWorker}

var (
	ErrInvalidReplicaReconciliationConformance     = errors.New("invalid replica reconciliation conformance")
	ErrReplicaReconciliationConformanceUnavailable = errors.New("replica reconciliation conformance unavailable")
	ErrReplicaReconciliationConformanceFailed      = errors.New("replica reconciliation conformance failed")
)

const replicaReconciliationInventorySQL = `SELECT
(SELECT count(*) FROM open_trestle_review_scopes WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3),
(SELECT count(*) FROM open_trestle_run_plans WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3),
(SELECT count(*) FROM open_trestle_run_events WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3),
(SELECT count(*) FROM open_trestle_task_notifications WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3),
(SELECT count(*) FROM open_trestle_audit_events WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3),
(SELECT count(*) FROM open_trestle_diagnostic_sets WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3),
(SELECT count(*) FROM open_trestle_webhook_deliveries WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3),
(SELECT count(*) FROM open_trestle_artifacts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3),
(SELECT count(*) FROM open_trestle_artifact_deletion_authorizations WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3),
(SELECT count(*) FROM open_trestle_artifact_deletion_receipts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3),
(SELECT count(*) FROM open_trestle_publication_attempts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3)`

const replicaReconciliationPlanSQL = `SELECT plan_identity, canonical_plan FROM open_trestle_run_plans WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`
const replicaReconciliationEventsSQL = `SELECT sequence, event_identity, canonical_event FROM open_trestle_run_events WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 ORDER BY sequence ASC`
const replicaReconciliationNotificationsSQL = `SELECT notice_identity, canonical_notice, canonical_checksum, delivery_count, lease_worker_identity, lease_token_identity, leased_at, lease_expires_at, acknowledged_at FROM open_trestle_task_notifications WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 ORDER BY notice_identity ASC`
const replicaReconciliationDeleteNotificationsSQL = `DELETE FROM open_trestle_task_notifications WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`
const replicaReconciliationDeleteEventsSQL = `DELETE FROM open_trestle_run_events WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`
const replicaReconciliationDeletePlanSQL = `DELETE FROM open_trestle_run_plans WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`
const replicaReconciliationDeleteScopeSQL = `DELETE FROM open_trestle_review_scopes WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`

var replicaReconciliationInventoryColumns = []string{"scopes", "plans", "events", "notifications", "audit_events", "diagnostic_sets", "webhook_deliveries", "artifacts", "deletion_authorizations", "deletion_receipts", "publication_attempts"}

type replicaReconciliationInventory struct {
	scopes, plans, events, notifications, auditEvents, diagnosticSets, webhookDeliveries, artifacts, deletionAuthorizations, deletionReceipts, publicationAttempts int
}

func (i replicaReconciliationInventory) empty() bool {
	return i == (replicaReconciliationInventory{})
}
func (i replicaReconciliationInventory) validFixtureBounds() bool {
	return i.scopes == 1 && i.plans == 1 && i.events >= 0 && i.events <= replicaReconciliationExpectedRunEvents && i.notifications >= 0 && i.notifications <= 1 && i.auditEvents == 0 && i.diagnosticSets == 0 && i.webhookDeliveries == 0 && i.artifacts == 0 && i.deletionAuthorizations == 0 && i.deletionReceipts == 0 && i.publicationAttempts == 0
}

type replicaReconciliationRuntime struct {
	journal controlplane.RunJournal
	queue   controlplane.TaskNotificationQueue
}

// ReplicaReconciliationConformanceObservation is one content-free converged run result.
type ReplicaReconciliationConformanceObservation struct {
	identity, authorityIdentity, planIdentity, notificationIdentity, terminalEventIdentity, outputIdentity string
}

func (o ReplicaReconciliationConformanceObservation) Identity() string { return o.identity }
func (o ReplicaReconciliationConformanceObservation) AuthorityIdentity() string {
	return o.authorityIdentity
}
func (o ReplicaReconciliationConformanceObservation) PlanIdentity() string   { return o.planIdentity }
func (o ReplicaReconciliationConformanceObservation) OutputIdentity() string { return o.outputIdentity }
func (o ReplicaReconciliationConformanceObservation) Validate() error {
	if !validNonzeroDigest(o.authorityIdentity) || !validNonzeroDigest(o.planIdentity) || !validNonzeroDigest(o.notificationIdentity) || !validNonzeroDigest(o.terminalEventIdentity) || !validNonzeroDigest(o.outputIdentity) || o.identity != replicaReconciliationObservationIdentity(o.authorityIdentity, o.planIdentity, o.notificationIdentity, o.terminalEventIdentity, o.outputIdentity) {
		return ErrReplicaReconciliationConformanceFailed
	}
	return nil
}
func (o ReplicaReconciliationConformanceObservation) String() string {
	return "replica reconciliation conformance observation"
}
func (o ReplicaReconciliationConformanceObservation) GoString() string {
	return "postgres.ReplicaReconciliationConformanceObservation{<redacted>}"
}
func (o ReplicaReconciliationConformanceObservation) Format(state fmt.State, verb rune) {
	value := o.String()
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = o.GoString()
	}
	_, _ = state.Write([]byte(value))
}

// ReplicaReconciliationConformanceAuthorityIdentity binds the verified database and exact disposable reconciliation proof.
func ReplicaReconciliationConformanceAuthorityIdentity(databaseAuthorityIdentity, credentialReferenceIdentity, setupRootIdentity string) (string, error) {
	if !validNonzeroDigest(databaseAuthorityIdentity) || !validNonzeroDigest(credentialReferenceIdentity) || !validNonzeroDigest(setupRootIdentity) {
		return "", ErrInvalidReplicaReconciliationConformance
	}
	plan, outputIdentity, err := replicaReconciliationFixturePlan(setupRootIdentity)
	if err != nil {
		return "", ErrInvalidReplicaReconciliationConformance
	}
	task, found := plan.Task(replicaReconciliationTaskKey)
	if !found {
		return "", ErrInvalidReplicaReconciliationConformance
	}
	encoded, err := json.Marshal(struct {
		Contract                    string   `json:"contract"`
		SchemaVersion               int      `json:"schema_version"`
		DatabaseAuthorityIdentity   string   `json:"database_authority_identity"`
		CredentialReferenceIdentity string   `json:"credential_reference_identity"`
		SetupRootIdentity           string   `json:"setup_root_identity"`
		DatabaseAuthorityVerified   bool     `json:"database_authority_verified"`
		ScopeIdentity               string   `json:"scope_identity"`
		PlanIdentity                string   `json:"plan_identity"`
		TaskKey                     string   `json:"task_key"`
		TaskIdentity                string   `json:"task_identity"`
		HandlerIdentity             string   `json:"handler_identity"`
		OutputIdentity              string   `json:"output_identity"`
		WorkerIdentities            []string `json:"worker_identities"`
		TaskRetryDelayMillis        uint32   `json:"task_retry_delay_milliseconds"`
		TaskLeaseMillis             uint32   `json:"task_lease_milliseconds"`
		NotificationLeaseMillis     int64    `json:"notification_lease_milliseconds"`
		TimelineOffsetMillis        []int64  `json:"timeline_offset_milliseconds"`
		ExpectedEventKinds          []string `json:"expected_event_kinds"`
		CrossInstanceAcknowledgment bool     `json:"cross_instance_acknowledgment"`
		CrossInstanceCompletion     bool     `json:"cross_instance_completion"`
		StoreInstances              int      `json:"store_instances"`
		MinimumOpenConnections      int      `json:"minimum_open_connections"`
		SchedulerAttempts           int      `json:"scheduler_attempts"`
		NotificationClaimAttempts   int      `json:"notification_claim_attempts"`
		TaskClaimAttempts           int      `json:"task_claim_attempts"`
		FinalizerAttempts           int      `json:"finalizer_attempts"`
		MaximumTransientAttempts    int      `json:"maximum_transient_attempts"`
		RetryDelayMillis            int64    `json:"retry_delay_milliseconds"`
		RetryFailureClass           string   `json:"retry_failure_class"`
		ExpectedNotifications       int      `json:"expected_notifications"`
		ExpectedTaskLeases          int      `json:"expected_task_leases"`
		ExpectedTerminalEvents      int      `json:"expected_terminal_events"`
		ExpectedRunEvents           int      `json:"expected_run_events"`
		DatabaseClock               string   `json:"database_clock"`
		TenantIsolation             string   `json:"tenant_isolation"`
		SessionLock                 string   `json:"session_lock"`
		ScopeLock                   string   `json:"scope_lock"`
		RetryFixtureValidation      string   `json:"retry_fixture_validation"`
		Cleanup                     string   `json:"cleanup"`
		CrashRecovery               string   `json:"crash_recovery"`
		OperationDeadlineMillis     int64    `json:"operation_deadline_milliseconds"`
		NonDatabaseRequests         int      `json:"non_database_network_requests"`
		CleanupRelations            []string `json:"cleanup_relations"`
		ForbiddenRelations          []string `json:"forbidden_relations"`
	}{
		"open-trestle/postgres-replica-reconciliation-conformance-authority", 1,
		databaseAuthorityIdentity, credentialReferenceIdentity, setupRootIdentity, true,
		plan.Scope().Identity(), plan.Identity(), task.Key(), task.Identity(), task.HandlerIdentity(), outputIdentity,
		append([]string(nil), replicaReconciliationWorkerIdentities...), replicaReconciliationTaskRetryDelayMilliseconds, replicaReconciliationTaskLeaseMilliseconds,
		replicaReconciliationNotificationLease.Milliseconds(), replicaReconciliationTimelineOffsetMilliseconds(), append([]string(nil), replicaReconciliationExpectedEventKinds...), true, true,
		replicaReconciliationStoreInstances, replicaReconciliationMinimumOpenConnections, replicaReconciliationSchedulerAttempts, replicaReconciliationNotificationClaimAttempts, replicaReconciliationTaskClaimAttempts, replicaReconciliationFinalizerAttempts,
		replicaReconciliationMaximumTransientAttempts, replicaReconciliationRetryDelay.Milliseconds(), "database_unavailable_only",
		replicaReconciliationExpectedNotifications, replicaReconciliationExpectedTaskLeases, replicaReconciliationExpectedTerminalEvents, replicaReconciliationExpectedRunEvents,
		"transaction_timestamp", "set_config_local_forced_row_level_security",
		"setup_root_and_database_derived_session_advisory_lock", "scope_identity_advisory_transaction_lock",
		"canonical_plan_exact_timeline_replayed_event_prefix_notification_and_lease_state", "validated_exact_scope_delete_and_absence", "validated_fixture_only_retry_cleanup",
		replicaReconciliationOperationTimeout.Milliseconds(), 0,
		[]string{"open_trestle_task_notifications", "open_trestle_run_events", "open_trestle_run_plans", "open_trestle_review_scopes"},
		[]string{"open_trestle_audit_events", "open_trestle_diagnostic_sets", "open_trestle_webhook_deliveries", "open_trestle_artifacts", "open_trestle_artifact_deletion_authorizations", "open_trestle_artifact_deletion_receipts", "open_trestle_publication_attempts"},
	})
	if err != nil {
		return "", ErrInvalidReplicaReconciliationConformance
	}
	return digestReplicaReconciliation(encoded), nil
}

func replicaReconciliationTimelineOffsetMilliseconds() []int64 {
	result := make([]int64, len(replicaReconciliationTimelineOffsets))
	for index, value := range replicaReconciliationTimelineOffsets {
		result[index] = value.Milliseconds()
	}
	return result
}

// VerifyReplicaReconciliationConformance runs two runtime instances against one verified database and removes its exact fixture scope.
func VerifyReplicaReconciliationConformance(ctx context.Context, database *sql.DB, expectedDatabaseAuthorityIdentity, credentialReferenceIdentity, setupRootIdentity string) (observation ReplicaReconciliationConformanceObservation, returnErr error) {
	if ctx == nil || ctx.Err() != nil || database == nil || !validNonzeroDigest(expectedDatabaseAuthorityIdentity) || !validNonzeroDigest(credentialReferenceIdentity) || !validNonzeroDigest(setupRootIdentity) {
		return observation, ErrInvalidReplicaReconciliationConformance
	}
	maximumConnections := database.Stats().MaxOpenConnections
	if maximumConnections != 0 && maximumConnections < replicaReconciliationMinimumOpenConnections {
		return observation, ErrInvalidReplicaReconciliationConformance
	}
	bounded, cancel := context.WithTimeout(ctx, replicaReconciliationOperationTimeout)
	defer cancel()
	verified, err := VerifyDatabaseStorageAuthority(bounded, database)
	if err != nil {
		if errors.Is(err, ErrDatabaseUnavailable) {
			return observation, ErrReplicaReconciliationConformanceUnavailable
		}
		return observation, ErrInvalidReplicaReconciliationConformance
	}
	if verified.Identity() != expectedDatabaseAuthorityIdentity {
		return observation, ErrInvalidReplicaReconciliationConformance
	}
	authority, err := ReplicaReconciliationConformanceAuthorityIdentity(verified.Identity(), credentialReferenceIdentity, setupRootIdentity)
	if err != nil {
		return observation, ErrInvalidReplicaReconciliationConformance
	}
	plan, outputIdentity, err := replicaReconciliationFixturePlan(setupRootIdentity)
	if err != nil {
		return observation, ErrReplicaReconciliationConformanceFailed
	}
	connection, err := database.Conn(bounded)
	if err != nil {
		return observation, ErrReplicaReconciliationConformanceUnavailable
	}
	lockID := replicaReconciliationSessionLockID(verified.Identity(), setupRootIdentity)
	locked, ownsScope := false, false
	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if cleanupReplicaReconciliationConformance(cleanupContext, connection, plan, outputIdentity, locked, ownsScope, lockID) != nil {
			observation = ReplicaReconciliationConformanceObservation{}
			returnErr = ErrReplicaReconciliationConformanceUnavailable
		}
	}()
	if _, err := connection.ExecContext(bounded, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return observation, ErrReplicaReconciliationConformanceUnavailable
	}
	locked = true
	if err := prepareReplicaReconciliationConformance(bounded, connection, plan, outputIdentity); err != nil {
		return observation, err
	}
	ownsScope = true
	var databaseTime time.Time
	if err := connection.QueryRowContext(bounded, "SELECT transaction_timestamp()").Scan(&databaseTime); err != nil || databaseTime.IsZero() {
		return observation, ErrReplicaReconciliationConformanceUnavailable
	}
	firstStore, err := New(database)
	if err != nil {
		return observation, ErrReplicaReconciliationConformanceFailed
	}
	secondStore, err := New(database)
	if err != nil {
		return observation, ErrReplicaReconciliationConformanceFailed
	}
	observation, err = runReplicaReconciliationConformance(bounded, replicaReconciliationRuntime{journal: firstStore, queue: firstStore}, replicaReconciliationRuntime{journal: secondStore, queue: secondStore}, plan, outputIdentity, authority, time.UnixMilli(databaseTime.UnixMilli()).UTC())
	if err != nil {
		return ReplicaReconciliationConformanceObservation{}, err
	}
	return observation, nil
}

func replicaReconciliationSessionLockID(databaseAuthorityIdentity, setupRootIdentity string) int64 {
	digest := sha256.Sum256([]byte("open-trestle/replica-reconciliation-session-lock/v1\x00" + databaseAuthorityIdentity + "\x00" + setupRootIdentity))
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func prepareReplicaReconciliationConformance(ctx context.Context, connection *sql.Conn, plan controlplane.ReviewRunPlan, outputIdentity string) error {
	if ctx == nil || ctx.Err() != nil || connection == nil || plan.Validate() != nil || !validNonzeroDigest(outputIdentity) {
		return ErrInvalidReplicaReconciliationConformance
	}
	tx, err := connection.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ErrReplicaReconciliationConformanceUnavailable
	}
	defer tx.Rollback()
	scope := plan.Scope()
	if _, err := tx.ExecContext(ctx, "SELECT set_config('open_trestle.tenant_id', $1, true)", scope.TenantID()); err != nil {
		return ErrReplicaReconciliationConformanceUnavailable
	}
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", scope.Identity()); err != nil {
		return ErrReplicaReconciliationConformanceUnavailable
	}
	inventory, err := readReplicaReconciliationInventory(ctx, tx, scope)
	if err != nil {
		return err
	}
	if inventory.empty() {
		if err := tx.Commit(); err != nil {
			return ErrReplicaReconciliationConformanceUnavailable
		}
		return nil
	}
	if !inventory.validFixtureBounds() {
		return ErrReplicaReconciliationConformanceFailed
	}
	var storedIdentity string
	var encoded []byte
	if err := tx.QueryRowContext(ctx, replicaReconciliationPlanSQL, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).Scan(&storedIdentity, &encoded); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrReplicaReconciliationConformanceFailed
		}
		return ErrReplicaReconciliationConformanceUnavailable
	}
	stored, err := controlplane.ParseReviewRunPlan(encoded)
	if err != nil || storedIdentity != plan.Identity() || stored.Identity() != plan.Identity() || stored.Scope().Identity() != scope.Identity() {
		return ErrReplicaReconciliationConformanceFailed
	}
	events, err := readReplicaReconciliationEvents(ctx, tx, plan, outputIdentity, inventory.events)
	if err != nil {
		return err
	}
	if err := validateReplicaReconciliationNotifications(ctx, tx, plan, events, inventory.notifications); err != nil {
		return err
	}
	for _, deletion := range []struct {
		statement string
		expected  int
	}{{replicaReconciliationDeleteNotificationsSQL, inventory.notifications}, {replicaReconciliationDeleteEventsSQL, inventory.events}, {replicaReconciliationDeletePlanSQL, inventory.plans}, {replicaReconciliationDeleteScopeSQL, inventory.scopes}} {
		result, err := tx.ExecContext(ctx, deletion.statement, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID())
		if err != nil {
			return ErrReplicaReconciliationConformanceUnavailable
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != int64(deletion.expected) {
			return ErrReplicaReconciliationConformanceUnavailable
		}
	}
	remaining, err := readReplicaReconciliationInventory(ctx, tx, scope)
	if err != nil {
		return err
	}
	if !remaining.empty() {
		return ErrReplicaReconciliationConformanceFailed
	}
	if err := tx.Commit(); err != nil {
		return ErrReplicaReconciliationConformanceUnavailable
	}
	return nil
}

func readReplicaReconciliationEvents(ctx context.Context, tx *sql.Tx, plan controlplane.ReviewRunPlan, outputIdentity string, expected int) ([]controlplane.RunEvent, error) {
	if expected == 0 {
		return nil, nil
	}
	scope := plan.Scope()
	rows, err := tx.QueryContext(ctx, replicaReconciliationEventsSQL, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID())
	if err != nil {
		return nil, ErrReplicaReconciliationConformanceUnavailable
	}
	defer rows.Close()
	events := make([]controlplane.RunEvent, 0, expected)
	previous := ""
	var previousAt time.Time
	for rows.Next() {
		var sequence uint64
		var identity string
		var encoded []byte
		if err := rows.Scan(&sequence, &identity, &encoded); err != nil {
			return nil, ErrReplicaReconciliationConformanceUnavailable
		}
		event, parseErr := controlplane.ParseRunEvent(encoded)
		if parseErr != nil || sequence != uint64(len(events)+1) || identity != event.Identity() || event.Sequence() != sequence || event.PreviousIdentity() != previous || event.PlanIdentity() != plan.Identity() || event.Scope().Identity() != scope.Identity() || !validReplicaReconciliationEvent(event, len(events), plan, outputIdentity) || !previousAt.IsZero() && event.OccurredAt().Before(previousAt) || len(events) > 0 && !event.OccurredAt().Equal(events[0].OccurredAt().Add(replicaReconciliationEventOffsets[len(events)])) {
			return nil, ErrReplicaReconciliationConformanceFailed
		}
		events = append(events, event)
		previous, previousAt = event.Identity(), event.OccurredAt()
	}
	if rows.Err() != nil {
		return nil, ErrReplicaReconciliationConformanceUnavailable
	}
	if len(events) != expected {
		return nil, ErrReplicaReconciliationConformanceFailed
	}
	if err := rows.Close(); err != nil {
		return nil, ErrReplicaReconciliationConformanceUnavailable
	}
	if _, err := controlplane.ReplayReviewRun(plan, events); err != nil {
		return nil, ErrReplicaReconciliationConformanceFailed
	}
	return events, nil
}

func validReplicaReconciliationEvent(event controlplane.RunEvent, index int, plan controlplane.ReviewRunPlan, outputIdentity string) bool {
	task, found := plan.Task(replicaReconciliationTaskKey)
	if !found {
		return false
	}
	switch index {
	case 0:
		return event.Kind() == controlplane.RunEventOpened
	case 1:
		return event.Kind() == controlplane.RunEventTaskAvailable && event.TaskKey() == task.Key() && event.TaskIdentity() == task.Identity() && event.Attempt() == 0
	case 2:
		return event.Kind() == controlplane.RunEventTaskLeased && event.TaskKey() == task.Key() && event.TaskIdentity() == task.Identity() && event.Attempt() == 1 && (event.WorkerIdentity() == replicaReconciliationFirstWorker || event.WorkerIdentity() == replicaReconciliationSecondWorker)
	case 3:
		return event.Kind() == controlplane.RunEventTaskSucceeded && event.TaskKey() == task.Key() && event.TaskIdentity() == task.Identity() && event.Attempt() == 1 && event.OutputIdentity() == outputIdentity
	case 4:
		return event.Kind() == controlplane.RunEventSucceeded && event.OutputIdentity() == outputIdentity
	default:
		return false
	}
}

func validateReplicaReconciliationNotifications(ctx context.Context, tx *sql.Tx, plan controlplane.ReviewRunPlan, events []controlplane.RunEvent, expected int) error {
	if expected == 0 {
		return nil
	}
	if expected != 1 || len(events) < 2 {
		return ErrReplicaReconciliationConformanceFailed
	}
	scope := plan.Scope()
	rows, err := tx.QueryContext(ctx, replicaReconciliationNotificationsSQL, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID())
	if err != nil {
		return ErrReplicaReconciliationConformanceUnavailable
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var identity, checksum string
		var encoded []byte
		var delivery int
		var workerIdentity, tokenIdentity sql.NullString
		var leasedAt, leaseExpiresAt, acknowledgedAt sql.NullTime
		if err := rows.Scan(&identity, &encoded, &checksum, &delivery, &workerIdentity, &tokenIdentity, &leasedAt, &leaseExpiresAt, &acknowledgedAt); err != nil {
			return ErrReplicaReconciliationConformanceUnavailable
		}
		notification, parseErr := controlplane.ParseTaskNotification(encoded)
		digest := sha256.Sum256(encoded)
		task, found := plan.Task(replicaReconciliationTaskKey)
		if parseErr != nil || !found || identity != notification.Identity() || checksum != hex.EncodeToString(digest[:]) || notification.Scope().Identity() != scope.Identity() || notification.PlanIdentity() != plan.Identity() || notification.TaskStateRevision() != 2 || notification.TaskStateEventIdentity() != events[1].Identity() || notification.TaskKey() != task.Key() || notification.TaskIdentity() != task.Identity() || notification.HandlerIdentity() != task.HandlerIdentity() || notification.Attempt() != 1 || !validReplicaReconciliationNotificationLeaseState(delivery, workerIdentity, tokenIdentity, leasedAt, leaseExpiresAt, acknowledgedAt, notification.AvailableAt()) {
			return ErrReplicaReconciliationConformanceFailed
		}
		if !bytes.Equal(encoded, mustEncodeTaskNotification(notification)) {
			return ErrReplicaReconciliationConformanceFailed
		}
		count++
	}
	if rows.Err() != nil {
		return ErrReplicaReconciliationConformanceUnavailable
	}
	if count != expected {
		return ErrReplicaReconciliationConformanceFailed
	}
	if err := rows.Close(); err != nil {
		return ErrReplicaReconciliationConformanceUnavailable
	}
	return nil
}

func validReplicaReconciliationNotificationLeaseState(delivery int, workerIdentity, tokenIdentity sql.NullString, leasedAt, leaseExpiresAt, acknowledgedAt sql.NullTime, availableAt time.Time) bool {
	if availableAt.IsZero() {
		return false
	}
	if delivery == 0 {
		return !workerIdentity.Valid && !tokenIdentity.Valid && !leasedAt.Valid && !leaseExpiresAt.Valid && !acknowledgedAt.Valid
	}
	if delivery != 1 {
		return false
	}
	if acknowledgedAt.Valid {
		return !workerIdentity.Valid && !tokenIdentity.Valid && !leasedAt.Valid && !leaseExpiresAt.Valid && acknowledgedAt.Time.Equal(availableAt.Add(replicaReconciliationTimelineOffsets[3]-replicaReconciliationTimelineOffsets[1]))
	}
	validWorker := workerIdentity.Valid && (workerIdentity.String == replicaReconciliationFirstWorker || workerIdentity.String == replicaReconciliationSecondWorker)
	return validWorker && tokenIdentity.Valid && validNonzeroDigest(tokenIdentity.String) && leasedAt.Valid && leaseExpiresAt.Valid && leasedAt.Time.Equal(availableAt.Add(replicaReconciliationTimelineOffsets[2]-replicaReconciliationTimelineOffsets[1])) && leaseExpiresAt.Time.Equal(leasedAt.Time.Add(replicaReconciliationNotificationLease))
}

func mustEncodeTaskNotification(notification controlplane.TaskNotification) []byte {
	encoded, _ := controlplane.EncodeTaskNotification(notification)
	return encoded
}

func readReplicaReconciliationInventory(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope) (replicaReconciliationInventory, error) {
	var value replicaReconciliationInventory
	err := tx.QueryRowContext(ctx, replicaReconciliationInventorySQL, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).Scan(&value.scopes, &value.plans, &value.events, &value.notifications, &value.auditEvents, &value.diagnosticSets, &value.webhookDeliveries, &value.artifacts, &value.deletionAuthorizations, &value.deletionReceipts, &value.publicationAttempts)
	if err != nil {
		return replicaReconciliationInventory{}, ErrReplicaReconciliationConformanceUnavailable
	}
	return value, nil
}

func cleanupReplicaReconciliationConformance(ctx context.Context, connection *sql.Conn, plan controlplane.ReviewRunPlan, outputIdentity string, locked, ownsScope bool, lockID int64) error {
	if connection == nil {
		return ErrReplicaReconciliationConformanceUnavailable
	}
	if !locked {
		if err := connection.Close(); err != nil {
			return ErrReplicaReconciliationConformanceUnavailable
		}
		return nil
	}
	var preparationErr error
	if ownsScope {
		preparationErr = prepareReplicaReconciliationConformance(ctx, connection, plan, outputIdentity)
	}
	var unlocked bool
	unlockErr := connection.QueryRowContext(ctx, "SELECT pg_advisory_unlock($1)", lockID).Scan(&unlocked)
	closeErr := connection.Close()
	if preparationErr != nil || unlockErr != nil || !unlocked || closeErr != nil {
		return ErrReplicaReconciliationConformanceUnavailable
	}
	return nil
}

func retryReplicaReconciliationOperation[T any](ctx context.Context, operation func() (T, error)) (T, error) {
	var zero T
	if ctx == nil || ctx.Err() != nil || operation == nil {
		return zero, ErrInvalidReplicaReconciliationConformance
	}
	var last error
	for attempt := 1; attempt <= replicaReconciliationMaximumTransientAttempts; attempt++ {
		value, err := operation()
		if err == nil {
			return value, nil
		}
		last = err
		if !errors.Is(err, ErrDatabaseUnavailable) || attempt == replicaReconciliationMaximumTransientAttempts {
			return zero, err
		}
		timer := time.NewTimer(replicaReconciliationRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
	return zero, last
}

func classifyReplicaReconciliationOperationError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx == nil || ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrDatabaseUnavailable) {
		return ErrReplicaReconciliationConformanceUnavailable
	}
	return ErrReplicaReconciliationConformanceFailed
}

func runReplicaReconciliationConformance(ctx context.Context, first, second replicaReconciliationRuntime, plan controlplane.ReviewRunPlan, outputIdentity, authorityIdentity string, at time.Time) (ReplicaReconciliationConformanceObservation, error) {
	if ctx == nil || ctx.Err() != nil || plan.Validate() != nil || !validNonzeroDigest(outputIdentity) || !validNonzeroDigest(authorityIdentity) || at.IsZero() {
		return ReplicaReconciliationConformanceObservation{}, ErrInvalidReplicaReconciliationConformance
	}
	firstCoordinator, err := controlplane.NewCoordinator(first.journal)
	if err != nil {
		return ReplicaReconciliationConformanceObservation{}, ErrInvalidReplicaReconciliationConformance
	}
	secondCoordinator, err := controlplane.NewCoordinator(second.journal)
	if err != nil {
		return ReplicaReconciliationConformanceObservation{}, ErrInvalidReplicaReconciliationConformance
	}
	firstScheduler, err := controlplane.NewTaskNotificationScheduler(first.journal, first.queue)
	if err != nil {
		return ReplicaReconciliationConformanceObservation{}, ErrInvalidReplicaReconciliationConformance
	}
	secondScheduler, err := controlplane.NewTaskNotificationScheduler(second.journal, second.queue)
	if err != nil {
		return ReplicaReconciliationConformanceObservation{}, ErrInvalidReplicaReconciliationConformance
	}
	firstFinalizer, err := controlplane.NewRunFinalizer(first.journal)
	if err != nil {
		return ReplicaReconciliationConformanceObservation{}, ErrInvalidReplicaReconciliationConformance
	}
	secondFinalizer, err := controlplane.NewRunFinalizer(second.journal)
	if err != nil {
		return ReplicaReconciliationConformanceObservation{}, ErrInvalidReplicaReconciliationConformance
	}
	if _, err := firstCoordinator.Open(ctx, plan, at); err != nil {
		return ReplicaReconciliationConformanceObservation{}, classifyReplicaReconciliationOperationError(ctx, err)
	}
	loadedPlan, state, err := secondCoordinator.Resume(ctx, plan.Scope())
	if err != nil {
		return ReplicaReconciliationConformanceObservation{}, classifyReplicaReconciliationOperationError(ctx, err)
	}
	if loadedPlan.Identity() != plan.Identity() || state.Plan().Identity() != plan.Identity() {
		return ReplicaReconciliationConformanceObservation{}, ErrReplicaReconciliationConformanceFailed
	}
	type scheduleResult struct {
		state   controlplane.ReviewRunState
		created int
		err     error
	}
	scheduleResults := make(chan scheduleResult, 2)
	var wait sync.WaitGroup
	for _, scheduler := range []*controlplane.TaskNotificationScheduler{firstScheduler, secondScheduler} {
		wait.Add(1)
		go func(value *controlplane.TaskNotificationScheduler) {
			defer wait.Done()
			result, scheduleErr := retryReplicaReconciliationOperation(ctx, func() (scheduleResult, error) {
				state, created, err := value.ReconcileRun(ctx, plan.Scope(), at.Add(replicaReconciliationTimelineOffsets[1]))
				return scheduleResult{state: state, created: created}, err
			})
			result.err = scheduleErr
			scheduleResults <- result
		}(scheduler)
	}
	wait.Wait()
	close(scheduleResults)
	created := 0
	for result := range scheduleResults {
		if result.err != nil {
			return ReplicaReconciliationConformanceObservation{}, classifyReplicaReconciliationOperationError(ctx, result.err)
		}
		if result.state.Status() != controlplane.ReviewRunActive {
			return ReplicaReconciliationConformanceObservation{}, ErrReplicaReconciliationConformanceFailed
		}
		created += result.created
	}
	if created != 1 {
		return ReplicaReconciliationConformanceObservation{}, ErrReplicaReconciliationConformanceFailed
	}
	type notificationClaimResult struct {
		lease controlplane.TaskNotificationLease
		index int
		found bool
		err   error
	}
	notificationClaims := make(chan notificationClaimResult, 2)
	for index, runtime := range []replicaReconciliationRuntime{first, second} {
		wait.Add(1)
		go func(index int, value replicaReconciliationRuntime) {
			defer wait.Done()
			result, claimErr := retryReplicaReconciliationOperation(ctx, func() (notificationClaimResult, error) {
				lease, found, err := value.queue.ClaimTaskNotification(ctx, plan.Scope(), replicaReconciliationWorkerIdentities[index], at.Add(replicaReconciliationTimelineOffsets[2]), replicaReconciliationNotificationLease)
				return notificationClaimResult{lease: lease, index: index, found: found}, err
			})
			result.err = claimErr
			notificationClaims <- result
		}(index, runtime)
	}
	wait.Wait()
	close(notificationClaims)
	var notificationLease controlplane.TaskNotificationLease
	notificationWinner, notificationPermits := -1, 0
	for result := range notificationClaims {
		if result.err != nil {
			return ReplicaReconciliationConformanceObservation{}, classifyReplicaReconciliationOperationError(ctx, result.err)
		}
		if result.found {
			notificationLease, notificationWinner = result.lease, result.index
			notificationPermits++
		}
	}
	if notificationPermits != 1 || notificationLease.Validate() != nil {
		return ReplicaReconciliationConformanceObservation{}, ErrReplicaReconciliationConformanceFailed
	}
	runtimes := []replicaReconciliationRuntime{first, second}
	if err := runtimes[1-notificationWinner].queue.AcknowledgeTaskNotification(ctx, notificationLease, at.Add(replicaReconciliationTimelineOffsets[3])); err != nil {
		return ReplicaReconciliationConformanceObservation{}, classifyReplicaReconciliationOperationError(ctx, err)
	}
	task, found := plan.Task(replicaReconciliationTaskKey)
	if !found {
		return ReplicaReconciliationConformanceObservation{}, ErrReplicaReconciliationConformanceFailed
	}
	type taskClaimResult struct {
		lease    controlplane.TaskLease
		index    int
		acquired bool
		err      error
	}
	taskClaims := make(chan taskClaimResult, 2)
	for index, coordinator := range []*controlplane.Coordinator{firstCoordinator, secondCoordinator} {
		wait.Add(1)
		go func(index int, value *controlplane.Coordinator) {
			defer wait.Done()
			result, claimErr := retryReplicaReconciliationOperation(ctx, func() (taskClaimResult, error) {
				lease, acquired, err := value.ClaimTask(ctx, plan, replicaReconciliationTaskKey, task.HandlerIdentity(), replicaReconciliationWorkerIdentities[index], at.Add(replicaReconciliationTimelineOffsets[4]))
				return taskClaimResult{lease: lease, index: index, acquired: acquired}, err
			})
			result.err = claimErr
			taskClaims <- result
		}(index, coordinator)
	}
	wait.Wait()
	close(taskClaims)
	var taskLease controlplane.TaskLease
	taskWinner, taskPermits := -1, 0
	for result := range taskClaims {
		if result.err != nil {
			return ReplicaReconciliationConformanceObservation{}, classifyReplicaReconciliationOperationError(ctx, result.err)
		}
		if result.acquired {
			taskLease, taskWinner = result.lease, result.index
			taskPermits++
		}
	}
	if taskPermits != 1 || taskLease.Validate() != nil {
		return ReplicaReconciliationConformanceObservation{}, ErrReplicaReconciliationConformanceFailed
	}
	completion, err := controlplane.NewTaskSuccess(outputIdentity)
	if err != nil {
		return ReplicaReconciliationConformanceObservation{}, ErrReplicaReconciliationConformanceFailed
	}
	coordinators := []*controlplane.Coordinator{firstCoordinator, secondCoordinator}
	if _, err := coordinators[1-taskWinner].CompleteTask(ctx, plan, taskLease, completion, at.Add(replicaReconciliationTimelineOffsets[5])); err != nil {
		return ReplicaReconciliationConformanceObservation{}, classifyReplicaReconciliationOperationError(ctx, err)
	}
	type finalizationResult struct {
		state controlplane.ReviewRunState
		err   error
	}
	finalizations := make(chan finalizationResult, 2)
	for _, finalizer := range []*controlplane.RunFinalizer{firstFinalizer, secondFinalizer} {
		wait.Add(1)
		go func(value *controlplane.RunFinalizer) {
			defer wait.Done()
			result, finalizeErr := retryReplicaReconciliationOperation(ctx, func() (finalizationResult, error) {
				state, _, err := value.ReconcileRun(ctx, plan.Scope(), at.Add(replicaReconciliationTimelineOffsets[6]))
				return finalizationResult{state: state}, err
			})
			result.err = finalizeErr
			finalizations <- result
		}(finalizer)
	}
	wait.Wait()
	close(finalizations)
	for result := range finalizations {
		if result.err != nil {
			return ReplicaReconciliationConformanceObservation{}, classifyReplicaReconciliationOperationError(ctx, result.err)
		}
		if result.state.Status() != controlplane.ReviewRunSucceeded || result.state.OutputIdentity() != outputIdentity {
			return ReplicaReconciliationConformanceObservation{}, ErrReplicaReconciliationConformanceFailed
		}
	}
	events, err := second.journal.Read(ctx, plan.Scope(), 0, 10)
	if err != nil {
		return ReplicaReconciliationConformanceObservation{}, classifyReplicaReconciliationOperationError(ctx, err)
	}
	if len(events) != replicaReconciliationExpectedRunEvents || events[4].Kind() != controlplane.RunEventSucceeded || events[4].OutputIdentity() != outputIdentity {
		return ReplicaReconciliationConformanceObservation{}, ErrReplicaReconciliationConformanceFailed
	}
	observation := ReplicaReconciliationConformanceObservation{authorityIdentity: authorityIdentity, planIdentity: plan.Identity(), notificationIdentity: notificationLease.Notification().Identity(), terminalEventIdentity: events[4].Identity(), outputIdentity: outputIdentity}
	observation.identity = replicaReconciliationObservationIdentity(observation.authorityIdentity, observation.planIdentity, observation.notificationIdentity, observation.terminalEventIdentity, observation.outputIdentity)
	if observation.Validate() != nil {
		return ReplicaReconciliationConformanceObservation{}, ErrReplicaReconciliationConformanceFailed
	}
	return observation, nil
}

func replicaReconciliationObservationIdentity(authorityIdentity, planIdentity, notificationIdentity, terminalEventIdentity, outputIdentity string) string {
	encoded, _ := json.Marshal(struct {
		Contract              string `json:"contract"`
		SchemaVersion         int    `json:"schema_version"`
		AuthorityIdentity     string `json:"authority_identity"`
		PlanIdentity          string `json:"plan_identity"`
		NotificationIdentity  string `json:"notification_identity"`
		TerminalEventIdentity string `json:"terminal_event_identity"`
		OutputIdentity        string `json:"output_identity"`
	}{"open-trestle/postgres-replica-reconciliation-conformance-observation", 1, authorityIdentity, planIdentity, notificationIdentity, terminalEventIdentity, outputIdentity})
	return digestReplicaReconciliation(encoded)
}

func replicaReconciliationFixturePlan(setupRootIdentity string) (controlplane.ReviewRunPlan, string, error) {
	if !validNonzeroDigest(setupRootIdentity) {
		return controlplane.ReviewRunPlan{}, "", ErrInvalidReplicaReconciliationConformance
	}
	suffixDigest := sha256.Sum256([]byte("open-trestle/replica-reconciliation-scope/v1\x00" + setupRootIdentity))
	suffix := hex.EncodeToString(suffixDigest[:16])
	scope, err := audit.NewReviewScope("conformance-"+suffix, "replica-reconciliation", "setup")
	if err != nil {
		return controlplane.ReviewRunPlan{}, "", ErrInvalidReplicaReconciliationConformance
	}
	inputIdentity := replicaReconciliationFixtureIdentity(setupRootIdentity, "input")
	handlerIdentity := replicaReconciliationFixtureIdentity(setupRootIdentity, "handler")
	task, err := controlplane.NewTaskDefinition(replicaReconciliationTaskKey, controlplane.TaskAcquireSource, inputIdentity, handlerIdentity, nil, 1, replicaReconciliationTaskRetryDelayMilliseconds, replicaReconciliationTaskLeaseMilliseconds, true)
	if err != nil {
		return controlplane.ReviewRunPlan{}, "", ErrInvalidReplicaReconciliationConformance
	}
	plan, err := controlplane.NewReviewRunPlan(scope, replicaReconciliationFixtureIdentity(setupRootIdentity, "snapshot"), replicaReconciliationFixtureIdentity(setupRootIdentity, "policy"), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	if err != nil {
		return controlplane.ReviewRunPlan{}, "", ErrInvalidReplicaReconciliationConformance
	}
	return plan, replicaReconciliationFixtureIdentity(setupRootIdentity, "output"), nil
}

func replicaReconciliationFixtureIdentity(setupRootIdentity, label string) string {
	digest := sha256.Sum256([]byte("open-trestle/replica-reconciliation-fixture/v1\x00" + setupRootIdentity + "\x00" + label))
	return hex.EncodeToString(digest[:])
}
func digestReplicaReconciliation(value []byte) string {
	digest := sha256.Sum256(append([]byte("open-trestle/postgres-replica-reconciliation/v1\x00"), value...))
	return hex.EncodeToString(digest[:])
}
