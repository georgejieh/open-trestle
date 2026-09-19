package setup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"time"
)

// CheckerAuthority approves one exact checker for one readiness gate.
type CheckerAuthority struct {
	Key             CheckKey `json:"key"`
	CheckerIdentity string   `json:"checker_identity"`
}

// CheckerCatalog is an immutable map of setup-check authority.
type CheckerCatalog struct {
	identity    string
	authorities map[CheckKey]string
}

// NewCheckerCatalog constructs an exact checker registry.
func NewCheckerCatalog(authorities []CheckerAuthority) (CheckerCatalog, error) {
	if len(authorities) == 0 || len(authorities) > maxSetupRequirements {
		return CheckerCatalog{}, ErrInvalidCheckerCatalog
	}
	copied := append([]CheckerAuthority(nil), authorities...)
	sort.Slice(copied, func(i, j int) bool { return copied[i].Key < copied[j].Key })
	catalog := CheckerCatalog{authorities: make(map[CheckKey]string, len(copied))}
	for i, a := range copied {
		if !validCheckKey(a.Key) || deterministicCheck(a.Key) || !nonzeroSetupDigest(a.CheckerIdentity) || (i > 0 && a.Key == copied[i-1].Key) {
			return CheckerCatalog{}, ErrInvalidCheckerCatalog
		}
		catalog.authorities[a.Key] = a.CheckerIdentity
	}
	catalog.identity = checkerCatalogIdentity(copied)
	return catalog, nil
}

// Identity returns the exact checker registry identity.
func (c CheckerCatalog) Identity() string { return c.identity }

// Authorities returns a canonical copy of approved checker bindings.
func (c CheckerCatalog) Authorities() []CheckerAuthority {
	values := make([]CheckerAuthority, 0, len(c.authorities))
	for key, identity := range c.authorities {
		values = append(values, CheckerAuthority{Key: key, CheckerIdentity: identity})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Key < values[j].Key })
	return values
}
func (c CheckerCatalog) Resolve(key CheckKey) (string, bool) {
	value, ok := c.authorities[key]
	return value, ok
}
func (c CheckerCatalog) Validate() error {
	if len(c.authorities) == 0 || len(c.authorities) > maxSetupRequirements {
		return ErrInvalidCheckerCatalog
	}
	values := c.Authorities()
	if c.identity != checkerCatalogIdentity(values) {
		return ErrInvalidCheckerCatalog
	}
	for k, v := range c.authorities {
		if !validCheckKey(k) || deterministicCheck(k) || !nonzeroSetupDigest(v) {
			return ErrInvalidCheckerCatalog
		}
	}
	return nil
}

// BuiltInCheckerCatalog returns the fixed checker authority for one profile.
func BuiltInCheckerCatalog(profile Profile) (CheckerCatalog, error) {
	_, checks, ok := profileDefaults(profile)
	if !ok {
		return CheckerCatalog{}, ErrInvalidCheckerCatalog
	}
	authorities := make([]CheckerAuthority, len(checks))
	for i, check := range checks {
		authorities[i] = CheckerAuthority{Key: check.key, CheckerIdentity: builtInCheckerIdentity(check.key)}
	}
	return NewCheckerCatalog(authorities)
}
func builtInCheckerIdentity(key CheckKey) string {
	sum := sha256.Sum256([]byte("open-trestle/setup-checker/v1\x00" + string(key)))
	return hex.EncodeToString(sum[:])
}
func checkerCatalogIdentity(values []CheckerAuthority) string {
	encoded, _ := json.Marshal(struct {
		Contract    string             `json:"contract"`
		Version     int                `json:"version"`
		Authorities []CheckerAuthority `json:"authorities"`
	}{"open-trestle/setup-checker-catalog", 1, values})
	sum := sha256.Sum256(append([]byte("open-trestle/setup-checker-catalog/v1\x00"), encoded...))
	return hex.EncodeToString(sum[:])
}

// CheckReceipt binds a closed outcome to one exact plan revision.
type CheckReceipt struct {
	identity, planIdentity, checkerIdentity, evidenceIdentity string
	key                                                       CheckKey
	state                                                     CheckState
	recovery                                                  RecoveryAction
	checkedAt                                                 time.Time
}

// newCheckReceipt creates redacted evidence for one setup requirement.
func newCheckReceipt(plan Plan, key CheckKey, checker string, state CheckState, evidence string, recovery RecoveryAction, at time.Time) (CheckReceipt, error) {
	canonicalAt, validAt := normalizeSetupTime(at)
	if plan.Validate() != nil || !validAt || !canonicalAt.After(plan.updatedAt) {
		return CheckReceipt{}, ErrInvalidCheckReceipt
	}
	at = canonicalAt
	requirement, found := planRequirement(plan, key)
	if !found || requirement.source == CheckDeterministic || !nonzeroSetupDigest(checker) || !nonzeroSetupDigest(evidence) || (state != CheckPassed && state != CheckBlocked && state != CheckUnavailable) || state == CheckPassed && recovery != RecoveryNone || state != CheckPassed && recovery != recoveryForKey(key) {
		return CheckReceipt{}, ErrInvalidCheckReceipt
	}
	receipt := CheckReceipt{planIdentity: plan.identity, key: key, checkerIdentity: checker, state: state, evidenceIdentity: evidence, recovery: recovery, checkedAt: at}
	receipt.identity = checkReceiptIdentity(receipt)
	return receipt, nil
}
func (r CheckReceipt) Identity() string               { return r.identity }
func (r CheckReceipt) PlanIdentity() string           { return r.planIdentity }
func (r CheckReceipt) Key() CheckKey                  { return r.key }
func (r CheckReceipt) CheckerIdentity() string        { return r.checkerIdentity }
func (r CheckReceipt) State() CheckState              { return r.state }
func (r CheckReceipt) EvidenceIdentity() string       { return r.evidenceIdentity }
func (r CheckReceipt) RecoveryAction() RecoveryAction { return r.recovery }
func (r CheckReceipt) CheckedAt() time.Time           { return r.checkedAt }
func (r CheckReceipt) Validate() error {
	if !nonzeroSetupDigest(r.planIdentity) || !validCheckKey(r.key) || deterministicCheck(r.key) || !nonzeroSetupDigest(r.checkerIdentity) || !nonzeroSetupDigest(r.evidenceIdentity) || !validSetupTime(r.checkedAt) || (r.state != CheckPassed && r.state != CheckBlocked && r.state != CheckUnavailable) || r.state == CheckPassed && r.recovery != RecoveryNone || r.state != CheckPassed && r.recovery != recoveryForKey(r.key) || r.identity != checkReceiptIdentity(r) {
		return ErrInvalidCheckReceipt
	}
	return nil
}

// applyCheckReceipt advances a plan only with current approved evidence.
func applyCheckReceipt(plan Plan, receipt CheckReceipt, catalog CheckerCatalog) (Plan, error) {
	if plan.Validate() != nil || receipt.Validate() != nil || catalog.Validate() != nil || len(plan.receipts) >= maxSetupReceipts {
		return Plan{}, ErrInvalidCheckReceipt
	}
	if receipt.planIdentity != plan.identity || !receipt.checkedAt.After(plan.updatedAt) {
		return Plan{}, ErrStaleCheckReceipt
	}
	if catalog.identity != plan.checkerCatalog.Identity() {
		return Plan{}, ErrCheckNotAuthorized
	}
	approved, ok := catalog.Resolve(receipt.key)
	if !ok || approved != receipt.checkerIdentity {
		return Plan{}, ErrCheckNotAuthorized
	}
	index, found := planRequirementIndex(plan, receipt.key)
	if !found || plan.requirements[index].source == CheckDeterministic {
		return Plan{}, ErrInvalidCheckReceipt
	}
	next := plan
	next.requirements = append([]Requirement(nil), plan.requirements...)
	if next.requirements[index].receiptIdentity != "" {
		resetDependentRequirements(next.requirements, receipt.key)
	}
	next.requirements[index] = Requirement{key: receipt.key, source: plan.requirements[index].source, state: receipt.state, checkerIdentity: receipt.checkerIdentity, evidenceIdentity: receipt.evidenceIdentity, receiptIdentity: receipt.identity, recovery: receipt.recovery, checkedAt: receipt.checkedAt}
	next.previousIdentity = plan.identity
	next.receipts = append(append([]CheckReceipt(nil), plan.receipts...), receipt)
	next.revision++
	next.updatedAt = receipt.checkedAt
	next.status, next.ready = deriveStatus(next.requirements)
	next.identity = planIdentity(next)
	if next.Validate() != nil {
		return Plan{}, ErrInvalidPlan
	}
	return next, nil
}
func planRequirement(plan Plan, key CheckKey) (Requirement, bool) {
	index, ok := planRequirementIndex(plan, key)
	if !ok {
		return Requirement{}, false
	}
	return plan.requirements[index], true
}
func planRequirementIndex(plan Plan, key CheckKey) (int, bool) {
	for i, r := range plan.requirements {
		if r.key == key {
			return i, true
		}
	}
	return 0, false
}
func deterministicCheck(key CheckKey) bool {
	return key == CheckProfileSelected || key == CheckScopeValid || key == CheckEffectPostureLocked || key == CheckRecoveryOwnerNamed
}
func validCheckKey(key CheckKey) bool {
	switch key {
	case CheckProfileSelected, CheckScopeValid, CheckEffectPostureLocked, CheckRecoveryOwnerNamed, CheckLocalAdministratorValidated, CheckStateStoragePostureValidated, CheckPostgresStorageValidated, CheckEnvelopeStorageValidated, CheckBackupValidated, CheckObserverCredentialPostureValidated, CheckSecretBackendValidated, CheckLocalInferenceValidated, CheckRemoteProviderAuthorized, CheckIntegrationPermissionsValidated, CheckWebhookValidated, CheckSharedRateLimitValidated, CheckReplicaReconciliationValidated, CheckSignedBundleValidated, CheckNoEgressValidated, CheckPolicyValidated, CheckDryRunValidated:
		return true
	}
	return false
}
func recoveryForKey(key CheckKey) RecoveryAction {
	switch key {
	case CheckBackupValidated:
		return RecoveryProvideBackup
	case CheckLocalAdministratorValidated:
		return RecoveryConfigureIdentity
	case CheckObserverCredentialPostureValidated:
		return RecoveryConfigureObserver
	case CheckRemoteProviderAuthorized:
		return RecoveryApproveProvider
	case CheckIntegrationPermissionsValidated:
		return RecoveryCorrectPermissions
	case CheckWebhookValidated:
		return RecoveryVerifyWebhook
	case CheckSignedBundleValidated:
		return RecoveryImportSignedBundle
	case CheckNoEgressValidated:
		return RecoveryRestoreNoEgress
	case CheckDryRunValidated:
		return RecoveryRunDryRun
	case CheckPolicyValidated:
		return RecoveryCorrectPolicy
	default:
		return RecoveryConfigureDependency
	}
}

type checkReceiptWire struct {
	Contract         string         `json:"contract"`
	SchemaVersion    int            `json:"schema_version"`
	Identity         string         `json:"identity"`
	PlanIdentity     string         `json:"plan_identity"`
	Key              CheckKey       `json:"key"`
	CheckerIdentity  string         `json:"checker_identity"`
	State            CheckState     `json:"state"`
	EvidenceIdentity string         `json:"evidence_identity"`
	Recovery         RecoveryAction `json:"recovery_action"`
	CheckedAt        string         `json:"checked_at"`
}

func checkReceiptIdentity(r CheckReceipt) string {
	wire := checkReceiptWire{"open-trestle/setup-check-receipt", 1, "", r.planIdentity, r.key, r.checkerIdentity, r.state, r.evidenceIdentity, r.recovery, r.checkedAt.Format(time.RFC3339Nano)}
	encoded, _ := json.Marshal(wire)
	sum := sha256.Sum256(append([]byte("open-trestle/setup-check-receipt/v1\x00"), encoded...))
	return hex.EncodeToString(sum[:])
}

// EncodeCheckReceipt returns the canonical receipt representation.
func EncodeCheckReceipt(receipt CheckReceipt) ([]byte, error) {
	if receipt.Validate() != nil {
		return nil, ErrInvalidCheckReceipt
	}
	return json.Marshal(checkReceiptWire{"open-trestle/setup-check-receipt", 1, receipt.identity, receipt.planIdentity, receipt.key, receipt.checkerIdentity, receipt.state, receipt.evidenceIdentity, receipt.recovery, receipt.checkedAt.Format(time.RFC3339Nano)})
}

// DecodeCheckReceipt strictly reconstructs a canonical receipt.
func DecodeCheckReceipt(encoded []byte) (CheckReceipt, error) {
	if len(encoded) == 0 || len(encoded) >= maxSetupStateBytes {
		return CheckReceipt{}, ErrInvalidCheckReceipt
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire checkReceiptWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Contract != "open-trestle/setup-check-receipt" || wire.SchemaVersion != 1 {
		return CheckReceipt{}, ErrInvalidCheckReceipt
	}
	checked, err := time.Parse(time.RFC3339Nano, wire.CheckedAt)
	if err != nil {
		return CheckReceipt{}, ErrInvalidCheckReceipt
	}
	receipt := CheckReceipt{identity: wire.Identity, planIdentity: wire.PlanIdentity, key: wire.Key, checkerIdentity: wire.CheckerIdentity, state: wire.State, evidenceIdentity: wire.EvidenceIdentity, recovery: wire.Recovery, checkedAt: checked}
	if receipt.Validate() != nil {
		return CheckReceipt{}, ErrInvalidCheckReceipt
	}
	canonical, _ := EncodeCheckReceipt(receipt)
	if !bytes.Equal(bytes.TrimSpace(encoded), canonical) {
		return CheckReceipt{}, ErrInvalidCheckReceipt
	}
	return receipt, nil
}
func (r CheckReceipt) MarshalJSON() ([]byte, error) { return EncodeCheckReceipt(r) }
