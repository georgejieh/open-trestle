package setup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type postureWire struct {
	Metadata                    MetadataBackend     `json:"metadata_backend"`
	Artifacts                   ArtifactBackend     `json:"artifact_backend"`
	Protection                  Protection          `json:"artifact_protection"`
	Notifications               NotificationBackend `json:"notification_backend"`
	Inference                   InferencePosture    `json:"inference"`
	Egress                      EgressPosture       `json:"egress"`
	Integration                 IntegrationPosture  `json:"integration"`
	MaxModelRequestCostMicroUSD uint64              `json:"max_model_request_cost_micro_usd"`
	RetentionDays               uint16              `json:"retention_days"`
	ProviderFallback            bool                `json:"provider_fallback_enabled"`
	ContentLogging              bool                `json:"content_logging_allowed"`
	Publication                 bool                `json:"publication_enabled"`
	DynamicValidation           bool                `json:"dynamic_validation_enabled"`
}
type requirementWire struct {
	Key              CheckKey       `json:"key"`
	Source           CheckSource    `json:"source"`
	State            CheckState     `json:"state"`
	CheckerIdentity  string         `json:"checker_identity"`
	EvidenceIdentity string         `json:"evidence_identity"`
	ReceiptIdentity  string         `json:"receipt_identity"`
	Recovery         RecoveryAction `json:"recovery_action"`
	CheckedAt        string         `json:"checked_at"`
}
type planWire struct {
	Contract               string             `json:"contract"`
	SchemaVersion          int                `json:"schema_version"`
	Identity               string             `json:"identity"`
	PreviousIdentity       string             `json:"previous_identity"`
	CheckerCatalogIdentity string             `json:"checker_catalog_identity"`
	CheckerAuthorities     []CheckerAuthority `json:"checker_authorities"`
	Revision               uint64             `json:"revision"`
	TenantID               string             `json:"tenant_id"`
	RepositoryID           string             `json:"repository_id"`
	RecoveryOwner          string             `json:"recovery_owner"`
	Profile                Profile            `json:"profile"`
	Posture                postureWire        `json:"posture"`
	Requirements           []requirementWire  `json:"requirements"`
	Receipts               []checkReceiptWire `json:"receipts"`
	Status                 Status             `json:"status"`
	Ready                  bool               `json:"ready"`
	CreatedAt              string             `json:"created_at"`
	UpdatedAt              string             `json:"updated_at"`
}

func wirePlan(plan Plan, withIdentity bool) planWire {
	requirements := make([]requirementWire, len(plan.requirements))
	for i, requirement := range plan.requirements {
		checked := ""
		if !requirement.checkedAt.IsZero() {
			checked = requirement.checkedAt.Format(time.RFC3339Nano)
		}
		requirements[i] = requirementWire{requirement.key, requirement.source, requirement.state, requirement.checkerIdentity, requirement.evidenceIdentity, requirement.receiptIdentity, requirement.recovery, checked}
	}
	receipts := make([]checkReceiptWire, len(plan.receipts))
	for i, receipt := range plan.receipts {
		receipts[i] = checkReceiptWire{"open-trestle/setup-check-receipt", 1, receipt.identity, receipt.planIdentity, receipt.key, receipt.checkerIdentity, receipt.state, receipt.evidenceIdentity, receipt.recovery, receipt.checkedAt.Format(time.RFC3339Nano)}
	}
	identity := ""
	if withIdentity {
		identity = plan.identity
	}
	posture := plan.posture
	return planWire{Contract: "open-trestle/setup-plan", SchemaVersion: 1, Identity: identity, PreviousIdentity: plan.previousIdentity, CheckerCatalogIdentity: plan.checkerCatalog.Identity(), CheckerAuthorities: plan.checkerCatalog.Authorities(), Revision: plan.revision, TenantID: plan.tenantID, RepositoryID: plan.repositoryID, RecoveryOwner: plan.recoveryOwner, Profile: plan.profile, Posture: postureWire{posture.metadata, posture.artifacts, posture.protection, posture.notifications, posture.inference, posture.egress, posture.integration, posture.maxModelRequestCostMicroUSD, posture.retentionDays, posture.providerFallback, posture.contentLogging, posture.publication, posture.dynamicValidation}, Requirements: requirements, Receipts: receipts, Status: plan.status, Ready: plan.ready, CreatedAt: plan.createdAt.Format(time.RFC3339Nano), UpdatedAt: plan.updatedAt.Format(time.RFC3339Nano)}
}
func planIdentity(plan Plan) string {
	wire := wirePlan(plan, false)
	encoded, _ := json.Marshal(wire)
	sum := sha256.Sum256(append([]byte("open-trestle/setup-plan/v1\x00"), encoded...))
	return hex.EncodeToString(sum[:])
}

// EncodePlan returns the canonical setup-plan representation.
func EncodePlan(plan Plan) ([]byte, error) {
	if plan.Validate() != nil {
		return nil, ErrInvalidPlan
	}
	return json.Marshal(wirePlan(plan, true))
}

// DecodePlan strictly reconstructs canonical secret-free setup state.
func DecodePlan(encoded []byte) (Plan, error) {
	if len(encoded) == 0 || len(encoded) >= maxSetupStateBytes {
		return Plan{}, ErrInvalidPlan
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire planWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Contract != "open-trestle/setup-plan" || wire.SchemaVersion != 1 {
		return Plan{}, ErrInvalidPlan
	}
	created, err := time.Parse(time.RFC3339Nano, wire.CreatedAt)
	if err != nil {
		return Plan{}, ErrInvalidPlan
	}
	updated, err := time.Parse(time.RFC3339Nano, wire.UpdatedAt)
	if err != nil {
		return Plan{}, ErrInvalidPlan
	}
	requirements := make([]Requirement, len(wire.Requirements))
	for i, r := range wire.Requirements {
		var checked time.Time
		if r.CheckedAt != "" {
			checked, err = time.Parse(time.RFC3339Nano, r.CheckedAt)
			if err != nil {
				return Plan{}, ErrInvalidPlan
			}
		}
		requirements[i] = Requirement{r.Key, r.Source, r.State, r.CheckerIdentity, r.EvidenceIdentity, r.ReceiptIdentity, r.Recovery, checked}
	}
	catalog, err := NewCheckerCatalog(wire.CheckerAuthorities)
	if err != nil || catalog.Identity() != wire.CheckerCatalogIdentity {
		return Plan{}, ErrInvalidPlan
	}
	receipts := make([]CheckReceipt, len(wire.Receipts))
	for i, value := range wire.Receipts {
		checked, parseErr := time.Parse(time.RFC3339Nano, value.CheckedAt)
		if parseErr != nil || value.Contract != "open-trestle/setup-check-receipt" || value.SchemaVersion != 1 {
			return Plan{}, ErrInvalidPlan
		}
		receipts[i] = CheckReceipt{identity: value.Identity, planIdentity: value.PlanIdentity, key: value.Key, checkerIdentity: value.CheckerIdentity, state: value.State, evidenceIdentity: value.EvidenceIdentity, recovery: value.Recovery, checkedAt: checked}
	}
	p := wire.Posture
	plan := Plan{identity: wire.Identity, previousIdentity: wire.PreviousIdentity, revision: wire.Revision, tenantID: wire.TenantID, repositoryID: wire.RepositoryID, recoveryOwner: wire.RecoveryOwner, profile: wire.Profile, posture: Posture{p.Metadata, p.Artifacts, p.Protection, p.Notifications, p.Inference, p.Egress, p.Integration, p.MaxModelRequestCostMicroUSD, p.RetentionDays, p.ProviderFallback, p.ContentLogging, p.Publication, p.DynamicValidation}, checkerCatalog: catalog, requirements: requirements, receipts: receipts, status: wire.Status, ready: wire.Ready, createdAt: created, updatedAt: updated}
	if plan.Validate() != nil {
		return Plan{}, ErrInvalidPlan
	}
	canonical, _ := EncodePlan(plan)
	if !bytes.Equal(bytes.TrimSpace(encoded), canonical) {
		return Plan{}, ErrInvalidPlan
	}
	return plan, nil
}
func (p Plan) MarshalJSON() ([]byte, error) { return EncodePlan(p) }
func (p Plan) String() string               { return "setup plan" }
func (p Plan) GoString() string             { return "setup.Plan{<redacted>}" }
func (p Plan) Format(state fmt.State, verb rune) {
	value := p.String()
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = p.GoString()
	}
	_, _ = state.Write([]byte(value))
}
