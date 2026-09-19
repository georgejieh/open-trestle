package webhook

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"time"
)

var (
	// ErrInvalidProcessor identifies a missing coordinator or unversioned planner.
	ErrInvalidProcessor = errors.New("invalid webhook run processor")
	// ErrRunPlanNotBound identifies a generated plan outside the exact accepted delivery lineage.
	ErrRunPlanNotBound = errors.New("webhook review run plan not bound")
	// ErrPreparedInputsExpired identifies an accepted delivery that was not opened before its input retention elapsed.
	ErrPreparedInputsExpired = errors.New("webhook prepared inputs expired")
	// ErrInvalidRunAdmissionReceipt identifies malformed intake-to-run lineage.
	ErrInvalidRunAdmissionReceipt = errors.New("invalid webhook run admission receipt")
	// ErrInvalidRunAdmissionReceiptIdentity identifies admission content inconsistent with its identity.
	ErrInvalidRunAdmissionReceiptIdentity = errors.New("invalid webhook run admission receipt identity")
)

// RunPlanner deterministically converts one accepted delivery into an immutable review plan.
type RunPlanner interface {
	Identity() string
	Plan(context.Context, StoredDelivery) (controlplane.ReviewRunPlan, error)
}

// PreparedRunPlanner returns a plan and its exact immutable root input artifacts.
type PreparedRunPlanner interface {
	Identity() string
	Prepare(context.Context, StoredDelivery) (controlplane.ReviewRunPlan, []artifact.Artifact, error)
}

// Processor opens replay-safe review runs from durable inbox records.
type Processor struct {
	coordinator     *controlplane.Coordinator
	planner         RunPlanner
	preparedPlanner PreparedRunPlanner
	artifactStore   artifact.Store
	plannerIdentity string
}

func NewProcessor(coordinator *controlplane.Coordinator, planner RunPlanner) (*Processor, error) {
	if coordinator == nil || isNilPlanner(planner) || !validWebhookDigest(planner.Identity()) {
		return nil, ErrInvalidProcessor
	}
	return &Processor{coordinator: coordinator, planner: planner, plannerIdentity: planner.Identity()}, nil
}

// NewPreparedProcessor binds plan creation to durable immutable root input storage.
func NewPreparedProcessor(journal controlplane.RunJournal, planner PreparedRunPlanner, store artifact.Store) (*Processor, error) {
	if journal == nil || isNilPreparedPlanner(planner) || isNilArtifactStore(store) || !validWebhookDigest(planner.Identity()) {
		return nil, ErrInvalidProcessor
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		return nil, ErrInvalidProcessor
	}
	return &Processor{coordinator: coordinator, preparedPlanner: planner, artifactStore: store, plannerIdentity: planner.Identity()}, nil
}

func (p *Processor) Process(ctx context.Context, stored StoredDelivery, at time.Time) (RunAdmissionReceipt, controlplane.ReviewRunReceipt, error) {
	prepared := p != nil && !isNilPreparedPlanner(p.preparedPlanner) && !isNilArtifactStore(p.artifactStore)
	plain := p != nil && !isNilPlanner(p.planner)
	if p == nil || p.coordinator == nil || prepared == plain {
		return RunAdmissionReceipt{}, controlplane.ReviewRunReceipt{}, ErrInvalidProcessor
	}
	if err := validateInboxOperation(ctx); err != nil {
		return RunAdmissionReceipt{}, controlplane.ReviewRunReceipt{}, err
	}
	if stored.Validate() != nil {
		return RunAdmissionReceipt{}, controlplane.ReviewRunReceipt{}, ErrInvalidAcceptanceReceipt
	}
	if at.Before(stored.Receipt().AcceptedAt()) {
		return RunAdmissionReceipt{}, controlplane.ReviewRunReceipt{}, ErrInvalidAcceptanceTime
	}
	currentIdentity := ""
	if prepared {
		currentIdentity = p.preparedPlanner.Identity()
	} else {
		currentIdentity = p.planner.Identity()
	}
	if currentIdentity != p.plannerIdentity {
		return RunAdmissionReceipt{}, controlplane.ReviewRunReceipt{}, ErrInvalidProcessor
	}
	var plan controlplane.ReviewRunPlan
	var inputs []artifact.Artifact
	var err error
	if prepared {
		plan, inputs, err = p.preparedPlanner.Prepare(ctx, stored)
	} else {
		plan, err = p.planner.Plan(ctx, stored)
	}
	if err != nil {
		return RunAdmissionReceipt{}, controlplane.ReviewRunReceipt{}, err
	}
	delivery := stored.Delivery()
	scope := plan.Scope()
	validPlan := plan.Validate() == nil && plan.RequestIdentity() == delivery.Identity()
	matchingRepository := scope.TenantID() == delivery.Scope().TenantID() && scope.RepositoryID() == delivery.Scope().RepositoryID()
	bound := validPlan && matchingRepository && scope.ReviewRunID() == ReviewRunIDForDelivery(delivery)
	if !bound {
		return RunAdmissionReceipt{}, controlplane.ReviewRunReceipt{}, ErrRunPlanNotBound
	}
	if prepared {
		existingPlan, existingState, resumeErr := p.coordinator.Resume(ctx, scope)
		if resumeErr == nil {
			if existingPlan.Identity() != plan.Identity() {
				return RunAdmissionReceipt{}, controlplane.ReviewRunReceipt{}, controlplane.ErrRunPlanConflict
			}
			existingState, resumeErr = p.coordinator.Advance(ctx, existingPlan, at)
			if resumeErr != nil {
				return RunAdmissionReceipt{}, controlplane.ReviewRunReceipt{}, resumeErr
			}
			runReceipt, receiptErr := controlplane.NewReviewRunReceipt(existingState)
			if receiptErr != nil {
				return RunAdmissionReceipt{}, controlplane.ReviewRunReceipt{}, receiptErr
			}
			return newRunAdmissionReceipt(stored.Receipt(), p.plannerIdentity, existingPlan.Identity()), runReceipt, nil
		}
		if !errors.Is(resumeErr, controlplane.ErrRunNotOpened) {
			return RunAdmissionReceipt{}, controlplane.ReviewRunReceipt{}, resumeErr
		}
		if err := persistPreparedInputs(ctx, p.artifactStore, stored, plan, inputs, at); err != nil {
			return RunAdmissionReceipt{}, controlplane.ReviewRunReceipt{}, err
		}
	}
	state, err := p.coordinator.Open(ctx, plan, at)
	if err == nil {
		state, err = p.coordinator.Advance(ctx, plan, at)
	}
	if err != nil {
		return RunAdmissionReceipt{}, controlplane.ReviewRunReceipt{}, err
	}
	runReceipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		return RunAdmissionReceipt{}, controlplane.ReviewRunReceipt{}, err
	}
	admission := newRunAdmissionReceipt(stored.Receipt(), p.plannerIdentity, plan.Identity())
	return admission, runReceipt, nil
}
func persistPreparedInputs(ctx context.Context, store artifact.Store, stored StoredDelivery, plan controlplane.ReviewRunPlan, inputs []artifact.Artifact, at time.Time) error {
	rootInputs := make(map[string]struct{})
	allowedInputs := make(map[string]struct{})
	for _, task := range plan.Tasks() {
		allowedInputs[task.InputIdentity()] = struct{}{}
		if len(task.Dependencies()) == 0 {
			rootInputs[task.InputIdentity()] = struct{}{}
		}
	}
	if len(rootInputs) == 0 || len(inputs) < len(rootInputs) || len(inputs) > len(allowedInputs) || len(inputs) > 16 {
		return ErrRunPlanNotBound
	}
	seen := make(map[string]struct{}, len(inputs))
	expired := false
	for _, input := range inputs {
		_, expected := allowedInputs[input.Identity()]
		provenance := input.Provenance()
		index := sort.SearchStrings(provenance, stored.Delivery().Identity())
		bound := input.Validate() == nil && expected && input.Scope().Identity() == plan.Scope().Identity() && input.Kind() == artifact.KindTaskInput && input.MediaType() == "application/json" && input.Origin() == artifact.OriginHost && input.CreatedAt().Equal(stored.Receipt().AcceptedAt()) && index < len(provenance) && provenance[index] == stored.Delivery().Identity()
		if !bound {
			return ErrRunPlanNotBound
		}
		if _, duplicate := seen[input.Identity()]; duplicate {
			return ErrRunPlanNotBound
		}
		seen[input.Identity()] = struct{}{}
		expired = expired || !input.ExpiresAt().After(at)
	}
	for identity := range rootInputs {
		if _, present := seen[identity]; !present {
			return ErrRunPlanNotBound
		}
	}
	if expired {
		return ErrPreparedInputsExpired
	}
	for _, input := range inputs {
		if _, err := store.Put(ctx, input, at); err != nil {
			return err
		}
	}
	return nil
}

func (p *Processor) String() string   { return "webhook run processor" }
func (p *Processor) GoString() string { return "webhook.Processor{<redacted>}" }
func (p *Processor) Format(state fmt.State, verb rune) {
	formatted := "webhook run processor"
	if verb == 'q' {
		formatted = `"webhook run processor"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "webhook.Processor{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}
func isNilPlanner(planner RunPlanner) bool {
	if planner == nil {
		return true
	}
	value := reflect.ValueOf(planner)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

func isNilPreparedPlanner(planner PreparedRunPlanner) bool {
	if planner == nil {
		return true
	}
	value := reflect.ValueOf(planner)
	return value.Kind() == reflect.Ptr && value.IsNil()
}
func isNilArtifactStore(store artifact.Store) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

// ReviewRunIDForDelivery returns the sole run ID permitted for one forge delivery.
func ReviewRunIDForDelivery(delivery VerifiedDelivery) string {
	if delivery.Validate() != nil {
		return ""
	}
	return "webhook-" + delivery.DeduplicationKey()
}

// RunAdmissionReceipt binds durable webhook acceptance to its deterministic run plan.
type RunAdmissionReceipt struct{ identity, acceptanceIdentity, deliveryIdentity, plannerIdentity, planIdentity string }

func newRunAdmissionReceipt(acceptance AcceptanceReceipt, plannerIdentity, planIdentity string) RunAdmissionReceipt {
	receipt := RunAdmissionReceipt{acceptanceIdentity: acceptance.Identity(), deliveryIdentity: acceptance.DeliveryIdentity(), plannerIdentity: plannerIdentity, planIdentity: planIdentity}
	receipt.identity = deriveRunAdmissionIdentity(receipt)
	return receipt
}
func (r RunAdmissionReceipt) Identity() string           { return r.identity }
func (r RunAdmissionReceipt) AcceptanceIdentity() string { return r.acceptanceIdentity }
func (r RunAdmissionReceipt) DeliveryIdentity() string   { return r.deliveryIdentity }
func (r RunAdmissionReceipt) PlannerIdentity() string    { return r.plannerIdentity }
func (r RunAdmissionReceipt) PlanIdentity() string       { return r.planIdentity }
func (r RunAdmissionReceipt) Validate() error {
	if !validWebhookDigest(r.acceptanceIdentity) || !validWebhookDigest(r.deliveryIdentity) || !validWebhookDigest(r.plannerIdentity) || !validWebhookDigest(r.planIdentity) {
		return ErrInvalidRunAdmissionReceipt
	}
	if r.identity != deriveRunAdmissionIdentity(r) {
		return ErrInvalidRunAdmissionReceiptIdentity
	}
	return nil
}
func (r RunAdmissionReceipt) String() string   { return "webhook run admission receipt" }
func (r RunAdmissionReceipt) GoString() string { return "webhook.RunAdmissionReceipt{<redacted>}" }
func deriveRunAdmissionIdentity(receipt RunAdmissionReceipt) string {
	return hashWebhookValue(struct {
		AcceptanceIdentity string `json:"acceptance_identity"`
		DeliveryIdentity   string `json:"delivery_identity"`
		PlannerIdentity    string `json:"planner_identity"`
		PlanIdentity       string `json:"plan_identity"`
	}{receipt.acceptanceIdentity, receipt.deliveryIdentity, receipt.plannerIdentity, receipt.planIdentity})
}
