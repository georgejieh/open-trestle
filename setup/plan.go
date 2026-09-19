// Package setup defines secret-free, resumable installation planning contracts.
package setup

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	maxSetupRequirements = 32
	maxSetupReceipts     = 256
	maxSetupStateBytes   = 1 << 20
)

var (
	// ErrInvalidPlan identifies malformed, unsafe, or cross-wired setup state.
	ErrInvalidPlan = errors.New("invalid setup plan")
	// ErrInvalidCheckerCatalog identifies missing or ambiguous checker authority.
	ErrInvalidCheckerCatalog = errors.New("invalid setup checker catalog")
	// ErrInvalidCheckReceipt identifies malformed setup-check evidence.
	ErrInvalidCheckReceipt = errors.New("invalid setup check receipt")
	// ErrCheckNotAuthorized identifies a checker outside the approved catalog.
	ErrCheckNotAuthorized = errors.New("setup check not authorized")
	// ErrStaleCheckReceipt identifies evidence bound to an earlier setup plan.
	ErrStaleCheckReceipt = errors.New("stale setup check receipt")
)

// Profile selects one closed safe deployment baseline.
type Profile string

const (
	ProfileLocalSingleNode  Profile = "local_single_node"
	ProfileControlledHybrid Profile = "controlled_hybrid"
	ProfileKubernetesHA     Profile = "kubernetes_ha"
	ProfileAirGapped        Profile = "air_gapped"
)

// ParseProfile parses one closed deployment profile name.
func ParseProfile(value string) (Profile, error) {
	profile := Profile(value)
	if _, _, ok := profileDefaults(profile); !ok {
		return "", ErrInvalidPlan
	}
	return profile, nil
}

// MetadataBackend is a closed setup metadata posture.
type MetadataBackend string

const (
	MetadataLocal    MetadataBackend = "local"
	MetadataPostgres MetadataBackend = "postgres"
)

// ArtifactBackend is a closed setup artifact posture.
type ArtifactBackend string

const (
	ArtifactLocal ArtifactBackend = "local"
	ArtifactS3    ArtifactBackend = "s3"
)

// Protection is a closed setup artifact-protection posture.
type Protection string

const (
	ProtectionProcessPrivate    Protection = "process_private"
	ProtectionEnvelopeEncrypted Protection = "envelope_encrypted"
)

// NotificationBackend is a closed setup notification posture.
type NotificationBackend string

const (
	NotificationProcessLocal NotificationBackend = "process_local"
	NotificationPostgres     NotificationBackend = "postgres"
)

// InferencePosture is a closed setup inference boundary.
type InferencePosture string

const (
	InferenceLocalOnly      InferencePosture = "local_only"
	InferenceApprovedRemote InferencePosture = "approved_remote"
)

// EgressPosture is a closed setup network boundary.
type EgressPosture string

const (
	EgressDenied      EgressPosture = "denied"
	EgressAllowlisted EgressPosture = "allowlisted"
)

// IntegrationPosture is a closed setup integration boundary.
type IntegrationPosture string

const (
	IntegrationLocal             IntegrationPosture = "local"
	IntegrationLeastPrivilegeSCM IntegrationPosture = "least_privilege_scm"
	IntegrationOfflineBundle     IntegrationPosture = "offline_bundle"
)

// Status is the replay-derived setup readiness state.
type Status string

const (
	StatusIncomplete Status = "incomplete"
	StatusBlocked    Status = "blocked"
	StatusReady      Status = "ready"
)

// CheckState is one closed setup-check outcome.
type CheckState string

const (
	CheckPending     CheckState = "pending"
	CheckPassed      CheckState = "passed"
	CheckBlocked     CheckState = "blocked"
	CheckUnavailable CheckState = "unavailable"
)

// CheckSource identifies how a setup gate must be established.
type CheckSource string

const (
	CheckDeterministic CheckSource = "deterministic"
	CheckProbe         CheckSource = "probe"
	CheckAuthorization CheckSource = "authorization"
	CheckDryRun        CheckSource = "dry_run"
)

// RecoveryAction is a closed operator next action.
type RecoveryAction string

const (
	RecoveryNone                RecoveryAction = ""
	RecoveryConfigureDependency RecoveryAction = "configure_dependency"
	RecoveryProvideBackup       RecoveryAction = "provide_backup"
	RecoveryConfigureObserver   RecoveryAction = "configure_observer_authority"
	RecoveryConfigureIdentity   RecoveryAction = "configure_identity"
	RecoveryApproveProvider     RecoveryAction = "approve_provider"
	RecoveryCorrectPermissions  RecoveryAction = "correct_permissions"
	RecoveryVerifyWebhook       RecoveryAction = "verify_webhook"
	RecoveryImportSignedBundle  RecoveryAction = "import_signed_bundle"
	RecoveryRestoreNoEgress     RecoveryAction = "restore_no_egress"
	RecoveryRunDryRun           RecoveryAction = "run_dry_run"
	RecoveryCorrectPolicy       RecoveryAction = "correct_policy"
)

// CheckKey identifies one setup readiness gate.
type CheckKey string

const (
	CheckProfileSelected                    CheckKey = "profile_selected"
	CheckScopeValid                         CheckKey = "scope_valid"
	CheckEffectPostureLocked                CheckKey = "effect_posture_locked"
	CheckRecoveryOwnerNamed                 CheckKey = "recovery_owner_named"
	CheckLocalAdministratorValidated        CheckKey = "local_administrator_validated"
	CheckStateStoragePostureValidated       CheckKey = "state_storage_posture_validated"
	CheckPostgresStorageValidated           CheckKey = "postgres_storage_validated"
	CheckEnvelopeStorageValidated           CheckKey = "envelope_storage_validated"
	CheckBackupValidated                    CheckKey = "backup_validated"
	CheckObserverCredentialPostureValidated CheckKey = "observer_credential_posture_validated"
	CheckSecretBackendValidated             CheckKey = "secret_backend_validated"
	CheckLocalInferenceValidated            CheckKey = "local_inference_validated"
	CheckRemoteProviderAuthorized           CheckKey = "remote_provider_authorized"
	CheckIntegrationPermissionsValidated    CheckKey = "integration_permissions_validated"
	CheckWebhookValidated                   CheckKey = "webhook_validated"
	CheckSharedRateLimitValidated           CheckKey = "shared_rate_limit_validated"
	CheckReplicaReconciliationValidated     CheckKey = "replica_reconciliation_validated"
	CheckSignedBundleValidated              CheckKey = "signed_bundle_validated"
	CheckNoEgressValidated                  CheckKey = "no_egress_validated"
	CheckPolicyValidated                    CheckKey = "policy_validated"
	CheckDryRunValidated                    CheckKey = "dry_run_validated"
)

// Posture describes the effect-free storage, inference, and integration baseline.
type Posture struct {
	metadata                    MetadataBackend
	artifacts                   ArtifactBackend
	protection                  Protection
	notifications               NotificationBackend
	inference                   InferencePosture
	egress                      EgressPosture
	integration                 IntegrationPosture
	maxModelRequestCostMicroUSD uint64
	retentionDays               uint16
	providerFallback            bool
	contentLogging              bool
	publication                 bool
	dynamicValidation           bool
}

func (p Posture) MetadataBackend() MetadataBackend         { return p.metadata }
func (p Posture) ArtifactBackend() ArtifactBackend         { return p.artifacts }
func (p Posture) Protection() Protection                   { return p.protection }
func (p Posture) NotificationBackend() NotificationBackend { return p.notifications }
func (p Posture) Inference() InferencePosture              { return p.inference }
func (p Posture) Egress() EgressPosture                    { return p.egress }
func (p Posture) Integration() IntegrationPosture          { return p.integration }
func (p Posture) MaxModelRequestCostMicroUSD() uint64      { return p.maxModelRequestCostMicroUSD }
func (p Posture) RetentionDays() uint16                    { return p.retentionDays }
func (p Posture) ProviderFallbackEnabled() bool            { return p.providerFallback }
func (p Posture) ContentLoggingAllowed() bool              { return p.contentLogging }
func (p Posture) PublicationEnabled() bool                 { return p.publication }
func (p Posture) DynamicValidationEnabled() bool           { return p.dynamicValidation }

// Requirement is one readiness gate and its latest redacted result.
type Requirement struct {
	key                                                CheckKey
	source                                             CheckSource
	state                                              CheckState
	checkerIdentity, evidenceIdentity, receiptIdentity string
	recovery                                           RecoveryAction
	checkedAt                                          time.Time
}

func (r Requirement) Key() CheckKey                  { return r.key }
func (r Requirement) Source() CheckSource            { return r.source }
func (r Requirement) State() CheckState              { return r.state }
func (r Requirement) CheckerIdentity() string        { return r.checkerIdentity }
func (r Requirement) EvidenceIdentity() string       { return r.evidenceIdentity }
func (r Requirement) ReceiptIdentity() string        { return r.receiptIdentity }
func (r Requirement) RecoveryAction() RecoveryAction { return r.recovery }
func (r Requirement) CheckedAt() time.Time           { return r.checkedAt }

// Plan is one immutable revision of repository-scoped setup state.
type Plan struct {
	identity, previousIdentity, tenantID, repositoryID, recoveryOwner string
	revision                                                          uint64
	profile                                                           Profile
	posture                                                           Posture
	checkerCatalog                                                    CheckerCatalog
	requirements                                                      []Requirement
	receipts                                                          []CheckReceipt
	status                                                            Status
	ready                                                             bool
	createdAt, updatedAt                                              time.Time
}

// NewPlan creates an incomplete plan bound to the fixed checker catalog.
func NewPlan(profile Profile, tenantID, repositoryID, recoveryOwner string, at time.Time) (Plan, error) {
	catalog, err := BuiltInCheckerCatalog(profile)
	if err != nil {
		return Plan{}, ErrInvalidPlan
	}
	return NewPlanWithCheckerCatalog(profile, tenantID, repositoryID, recoveryOwner, catalog, at)
}

// NewPlanWithCheckerCatalog creates a plan bound to an exact approved checker registry.
func NewPlanWithCheckerCatalog(profile Profile, tenantID, repositoryID, recoveryOwner string, catalog CheckerCatalog, at time.Time) (Plan, error) {
	posture, keys, ok := profileDefaults(profile)
	canonicalAt, validAt := normalizeSetupTime(at)
	if !ok || !validAt || catalog.Validate() != nil || len(catalog.authorities) != len(keys) || !validSetupScope(tenantID, repositoryID) || !validSetupLabel(recoveryOwner) {
		return Plan{}, ErrInvalidPlan
	}
	for _, key := range keys {
		if _, found := catalog.Resolve(key.key); !found {
			return Plan{}, ErrInvalidPlan
		}
	}
	at = canonicalAt
	requirements := initialRequirements(keys)
	plan := Plan{checkerCatalog: catalog, tenantID: tenantID, repositoryID: repositoryID, recoveryOwner: recoveryOwner, revision: 1, profile: profile, posture: posture, requirements: requirements, status: StatusIncomplete, createdAt: at, updatedAt: at}
	plan.identity = planIdentity(plan)
	if plan.Validate() != nil {
		return Plan{}, ErrInvalidPlan
	}
	return plan, nil
}
func (p Plan) Identity() string               { return p.identity }
func (p Plan) PreviousIdentity() string       { return p.previousIdentity }
func (p Plan) CheckerCatalogIdentity() string { return p.checkerCatalog.Identity() }
func (p Plan) RootIdentity() string {
	if len(p.receipts) == 0 {
		return p.identity
	}
	return p.receipts[0].PlanIdentity()
}
func (p Plan) CheckerAuthorities() []CheckerAuthority { return p.checkerCatalog.Authorities() }
func (p Plan) Receipts() []CheckReceipt               { return append([]CheckReceipt(nil), p.receipts...) }
func (p Plan) Revision() uint64                       { return p.revision }
func (p Plan) TenantID() string                       { return p.tenantID }
func (p Plan) RepositoryID() string                   { return p.repositoryID }
func (p Plan) RecoveryOwner() string                  { return p.recoveryOwner }
func (p Plan) Profile() Profile                       { return p.profile }
func (p Plan) Posture() Posture                       { return p.posture }
func (p Plan) Requirements() []Requirement            { return append([]Requirement(nil), p.requirements...) }
func (p Plan) Status() Status                         { return p.status }
func (p Plan) Ready() bool                            { return p.ready }
func (p Plan) CreatedAt() time.Time                   { return p.createdAt }
func (p Plan) UpdatedAt() time.Time                   { return p.updatedAt }
func (p Plan) Validate() error {
	replayed, ok := replayPlan(p)
	if !ok || !reflect.DeepEqual(wirePlan(replayed, true), wirePlan(p, true)) {
		return ErrInvalidPlan
	}
	return nil
}
func replayPlan(source Plan) (Plan, bool) {
	posture, keys, ok := profileDefaults(source.profile)
	if !ok || source.posture != posture || !validSetupScope(source.tenantID, source.repositoryID) || !validSetupLabel(source.recoveryOwner) || !validSetupTime(source.createdAt) || source.checkerCatalog.Validate() != nil || len(source.checkerCatalog.authorities) != len(keys) || len(source.receipts) > maxSetupReceipts {
		return Plan{}, false
	}
	for _, key := range keys {
		if _, found := source.checkerCatalog.Resolve(key.key); !found {
			return Plan{}, false
		}
	}
	plan := Plan{tenantID: source.tenantID, repositoryID: source.repositoryID, recoveryOwner: source.recoveryOwner, revision: 1, profile: source.profile, posture: posture, checkerCatalog: source.checkerCatalog, requirements: initialRequirements(keys), status: StatusIncomplete, createdAt: source.createdAt, updatedAt: source.createdAt}
	plan.identity = planIdentity(plan)
	for _, receipt := range source.receipts {
		if receipt.Validate() != nil || receipt.planIdentity != plan.identity || !receipt.checkedAt.After(plan.updatedAt) {
			return Plan{}, false
		}
		approved, found := plan.checkerCatalog.Resolve(receipt.key)
		if !found || approved != receipt.checkerIdentity {
			return Plan{}, false
		}
		index, found := planRequirementIndex(plan, receipt.key)
		if !found || plan.requirements[index].source == CheckDeterministic {
			return Plan{}, false
		}
		if plan.requirements[index].receiptIdentity != "" {
			resetDependentRequirements(plan.requirements, receipt.key)
		}
		plan.requirements[index] = Requirement{key: receipt.key, source: plan.requirements[index].source, state: receipt.state, checkerIdentity: receipt.checkerIdentity, evidenceIdentity: receipt.evidenceIdentity, receiptIdentity: receipt.identity, recovery: receipt.recovery, checkedAt: receipt.checkedAt}
		plan.previousIdentity = plan.identity
		plan.revision++
		plan.updatedAt = receipt.checkedAt
		plan.receipts = append(plan.receipts, receipt)
		plan.status, plan.ready = deriveStatus(plan.requirements)
		plan.identity = planIdentity(plan)
	}
	return plan, true
}

// resetDependentRequirements removes current authority, not historical receipts.
// These checks consume prerequisite evidence and must run again after replacement.
func resetDependentRequirements(requirements []Requirement, prerequisite CheckKey) {
	var dependents []CheckKey
	switch prerequisite {
	case CheckPolicyValidated:
		dependents = []CheckKey{CheckLocalInferenceValidated, CheckDryRunValidated}
	case CheckPostgresStorageValidated:
		dependents = []CheckKey{CheckSharedRateLimitValidated, CheckReplicaReconciliationValidated}
	case CheckIntegrationPermissionsValidated:
		dependents = []CheckKey{CheckWebhookValidated}
	}
	for _, key := range dependents {
		for i, requirement := range requirements {
			if requirement.key == key {
				requirements[i] = Requirement{key: key, source: requirement.source, state: CheckPending}
			}
		}
	}
}

func initialRequirements(keys []requirementSpec) []Requirement {
	requirements := []Requirement{{CheckProfileSelected, CheckDeterministic, CheckPassed, "", "", "", RecoveryNone, time.Time{}}, {CheckScopeValid, CheckDeterministic, CheckPassed, "", "", "", RecoveryNone, time.Time{}}, {CheckEffectPostureLocked, CheckDeterministic, CheckPassed, "", "", "", RecoveryNone, time.Time{}}, {CheckRecoveryOwnerNamed, CheckDeterministic, CheckPassed, "", "", "", RecoveryNone, time.Time{}}}
	for _, entry := range keys {
		requirements = append(requirements, Requirement{key: entry.key, source: entry.source, state: CheckPending})
	}
	return requirements
}

type requirementSpec struct {
	key    CheckKey
	source CheckSource
}

func profileDefaults(profile Profile) (Posture, []requirementSpec, bool) {
	localIdentity := []requirementSpec{{CheckLocalAdministratorValidated, CheckAuthorization}, {CheckObserverCredentialPostureValidated, CheckProbe}}
	switch profile {
	case ProfileLocalSingleNode:
		checks := []requirementSpec{{CheckStateStoragePostureValidated, CheckProbe}, {CheckBackupValidated, CheckProbe}}
		checks = append(checks, localIdentity...)
		checks = append(checks, requirementSpec{CheckPolicyValidated, CheckAuthorization}, requirementSpec{CheckLocalInferenceValidated, CheckProbe}, requirementSpec{CheckDryRunValidated, CheckDryRun})
		return Posture{metadata: MetadataLocal, artifacts: ArtifactLocal, protection: ProtectionProcessPrivate, notifications: NotificationProcessLocal, inference: InferenceLocalOnly, egress: EgressDenied, integration: IntegrationLocal, maxModelRequestCostMicroUSD: 0, retentionDays: 30}, checks, true
	case ProfileControlledHybrid:
		checks := []requirementSpec{{CheckPostgresStorageValidated, CheckProbe}, {CheckEnvelopeStorageValidated, CheckProbe}, {CheckBackupValidated, CheckProbe}, {CheckSecretBackendValidated, CheckProbe}}
		checks = append(checks, localIdentity...)
		checks = append(checks, requirementSpec{CheckRemoteProviderAuthorized, CheckAuthorization}, requirementSpec{CheckIntegrationPermissionsValidated, CheckAuthorization}, requirementSpec{CheckWebhookValidated, CheckProbe}, requirementSpec{CheckPolicyValidated, CheckAuthorization}, requirementSpec{CheckDryRunValidated, CheckDryRun})
		return Posture{metadata: MetadataPostgres, artifacts: ArtifactS3, protection: ProtectionEnvelopeEncrypted, notifications: NotificationPostgres, inference: InferenceApprovedRemote, egress: EgressAllowlisted, integration: IntegrationLeastPrivilegeSCM, maxModelRequestCostMicroUSD: 100_000, retentionDays: 30}, checks, true
	case ProfileKubernetesHA:
		checks := []requirementSpec{{CheckPostgresStorageValidated, CheckProbe}, {CheckEnvelopeStorageValidated, CheckProbe}, {CheckBackupValidated, CheckProbe}, {CheckSecretBackendValidated, CheckProbe}, {CheckSharedRateLimitValidated, CheckProbe}, {CheckReplicaReconciliationValidated, CheckProbe}}
		checks = append(checks, localIdentity...)
		checks = append(checks, requirementSpec{CheckRemoteProviderAuthorized, CheckAuthorization}, requirementSpec{CheckIntegrationPermissionsValidated, CheckAuthorization}, requirementSpec{CheckWebhookValidated, CheckProbe}, requirementSpec{CheckPolicyValidated, CheckAuthorization}, requirementSpec{CheckDryRunValidated, CheckDryRun})
		return Posture{metadata: MetadataPostgres, artifacts: ArtifactS3, protection: ProtectionEnvelopeEncrypted, notifications: NotificationPostgres, inference: InferenceApprovedRemote, egress: EgressAllowlisted, integration: IntegrationLeastPrivilegeSCM, maxModelRequestCostMicroUSD: 100_000, retentionDays: 30}, checks, true
	case ProfileAirGapped:
		checks := []requirementSpec{{CheckStateStoragePostureValidated, CheckProbe}, {CheckBackupValidated, CheckProbe}}
		checks = append(checks, localIdentity...)
		checks = append(checks, requirementSpec{CheckSignedBundleValidated, CheckProbe}, requirementSpec{CheckNoEgressValidated, CheckProbe}, requirementSpec{CheckPolicyValidated, CheckAuthorization}, requirementSpec{CheckLocalInferenceValidated, CheckProbe}, requirementSpec{CheckDryRunValidated, CheckDryRun})
		return Posture{metadata: MetadataLocal, artifacts: ArtifactLocal, protection: ProtectionProcessPrivate, notifications: NotificationProcessLocal, inference: InferenceLocalOnly, egress: EgressDenied, integration: IntegrationOfflineBundle, maxModelRequestCostMicroUSD: 0, retentionDays: 30}, checks, true
	default:
		return Posture{}, nil, false
	}
}
func deriveStatus(requirements []Requirement) (Status, bool) {
	all := true
	for _, r := range requirements {
		if r.state == CheckBlocked || r.state == CheckUnavailable {
			return StatusBlocked, false
		}
		all = all && r.state == CheckPassed
	}
	if all {
		return StatusReady, true
	}
	return StatusIncomplete, false
}
func validSetupScope(tenant, repository string) bool {
	_, err := audit.NewReviewScope(tenant, repository, "setup-plan")
	return err == nil
}
func validSetupLabel(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r == '-' || r == '_' || r == '.' || r == ':' || r == '@' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func normalizeSetupTime(value time.Time) (time.Time, bool) {
	if value.IsZero() {
		return time.Time{}, false
	}
	value = value.UTC().Truncate(time.Millisecond)
	return value, value.Year() >= 1970 && value.Year() <= 9999
}
func validSetupTime(value time.Time) bool {
	canonical, ok := normalizeSetupTime(value)
	return ok && value.Location() == time.UTC && value.Equal(canonical)
}
func nonzeroSetupDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	for _, b := range decoded {
		if b != 0 {
			return true
		}
	}
	return false
}
