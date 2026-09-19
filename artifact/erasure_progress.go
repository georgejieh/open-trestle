package artifact

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// ErasureAllowanceSnapshot contains historical metadata and reconciled totals.
type ErasureAllowanceSnapshot struct {
	Allowance           ResumeAllowance
	AcceptedPolicyBytes []byte
	AcceptedAt          time.Time
	Usage               AllowanceUsage
	AttemptCount        uint64
	TotalCost           ResumeBudget
}

// ErasureProgressOptions supplies a complete, bounded metadata closure.
// The history flags report database facts; they cannot confer authority.
type ErasureProgressOptions struct {
	Operation                                   ErasureOperation
	Admission                                   ArtifactAdmission
	Namespace                                   StorageNamespace
	OriginalAuthorization                       ErasureAuthorizationV2
	AdmissionPolicyBytes, OperationPolicyBytes  []byte
	OperationAcceptedAt                         time.Time
	ConfirmedVersion, ConfirmedCiphertextDigest string
	ConfirmedAt                                 time.Time
	AllowanceSnapshots                          []ErasureAllowanceSnapshot
	Attempts                                    []ErasureAttempt
	Evidence                                    []ErasureEvidence
	RequestedAllowanceIdentity                  string
	UnresolvedExists, UnknownExists             bool
	UnrecordedUncertainty                       []ErasureAttempt
	UncertaintyBookkeepingMore                  bool
}

// ErasureProgress is immutable historical metadata, not a result or permit.
// Its zero value is invalid and it has no serialized authority form.
type ErasureProgress struct{ data *erasureProgressData }

type erasureProgressData struct {
	options                     ErasureProgressOptions
	policies                    [][]byte
	fence, candidate, published ErasureEvidence
}

func NewErasureProgress(o ErasureProgressOptions) (ErasureProgress, error) {
	data, err := buildErasureProgress(o)
	if err != nil {
		return ErasureProgress{}, err
	}
	return ErasureProgress{data: data}, nil
}

func (p ErasureProgress) Validate() error {
	if p.data == nil {
		return ErrInvalidErasureContract
	}
	_, err := buildErasureProgress(p.data.options)
	return err
}

func (p ErasureProgress) Operation() ErasureOperation {
	if p.data == nil {
		return ErasureOperation{}
	}
	return p.data.options.Operation
}
func (p ErasureProgress) Admission() ArtifactAdmission {
	if p.data == nil {
		return ArtifactAdmission{}
	}
	a := p.data.options.Admission
	a.provenance = append([]string(nil), a.provenance...)
	return a
}
func (p ErasureProgress) Attempts() []ErasureAttempt {
	if p.data == nil {
		return nil
	}
	return append([]ErasureAttempt(nil), p.data.options.Attempts...)
}
func copyProgressEvidence(e ErasureEvidence) ErasureEvidence {
	if e.Identity() == "" {
		return ErasureEvidence{}
	}
	e.record.ParentIdentities = append([]string{}, e.record.ParentIdentities...)
	return e
}
func (p ErasureProgress) Evidence() []ErasureEvidence {
	if p.data == nil {
		return nil
	}
	out := make([]ErasureEvidence, len(p.data.options.Evidence))
	for i, e := range p.data.options.Evidence {
		out[i] = copyProgressEvidence(e)
	}
	return out
}
func (p ErasureProgress) Allowances() []ResumeAllowance {
	if p.data == nil {
		return nil
	}
	out := make([]ResumeAllowance, len(p.data.options.AllowanceSnapshots))
	for i, s := range p.data.options.AllowanceSnapshots {
		out[i] = s.Allowance
	}
	return out
}
func (p ErasureProgress) AcceptedPolicyBytes() [][]byte {
	if p.data == nil {
		return nil
	}
	out := make([][]byte, len(p.data.policies))
	for i, raw := range p.data.policies {
		out[i] = append([]byte(nil), raw...)
	}
	return out
}
func (p ErasureProgress) AllowanceUsages() []AllowanceUsage {
	if p.data == nil || p.data.options.RequestedAllowanceIdentity == "" {
		return nil
	}
	for _, s := range p.data.options.AllowanceSnapshots {
		if s.Allowance.Identity() == p.data.options.RequestedAllowanceIdentity {
			return []AllowanceUsage{s.Usage}
		}
	}
	return nil
}
func (p ErasureProgress) Fence() (ErasureEvidence, bool) {
	if p.data == nil {
		return ErasureEvidence{}, false
	}
	return copyProgressEvidence(p.data.fence), p.data.fence.Identity() != ""
}
func (p ErasureProgress) Candidate() (ErasureEvidence, bool) {
	if p.data == nil {
		return ErasureEvidence{}, false
	}
	return copyProgressEvidence(p.data.candidate), p.data.candidate.Identity() != ""
}
func (p ErasureProgress) Published() (ErasureEvidence, bool) {
	if p.data == nil {
		return ErasureEvidence{}, false
	}
	return copyProgressEvidence(p.data.published), p.data.published.Identity() != ""
}
func (p ErasureProgress) HasUnknownHistory() bool {
	return p.data != nil && (p.data.options.UnresolvedExists || p.data.options.UnknownExists)
}
func (p ErasureProgress) HasUnresolvedAttempts() bool {
	return p.data != nil && p.data.options.UnresolvedExists
}
func (p ErasureProgress) UnrecordedUncertainty() []ErasureAttempt {
	if p.data == nil {
		return nil
	}
	return append([]ErasureAttempt(nil), p.data.options.UnrecordedUncertainty...)
}
func (p ErasureProgress) UncertaintyBookkeepingMore() bool {
	return p.data != nil && p.data.options.UncertaintyBookkeepingMore
}
func (p ErasureProgress) String() string   { return "artifact erasure progress" }
func (p ErasureProgress) GoString() string { return "artifact.ErasureProgress{<redacted>}" }
func (p ErasureProgress) Format(s fmt.State, verb rune) {
	formatErasureValue(s, verb, p.String(), p.GoString())
}

// Charge each distinct canonical stored preimage once. Nested payloads are
// already charged in their evidence envelope, not again when parsed or walked.
type erasureProgressBudget struct {
	bytes   int
	records map[string][]byte
}

func (b *erasureProgressBudget) add(kind, id string, raw []byte) error {
	key := kind + ":" + id
	if old, exists := b.records[key]; exists {
		if !bytes.Equal(old, raw) {
			return ErrInvalidErasureContract
		}
		return nil
	}
	if len(raw) == 0 || len(raw) > (8<<20)-b.bytes {
		return ErrInvalidErasureContract
	}
	b.bytes += len(raw)
	b.records[key] = raw
	return nil
}
func (b *erasureProgressBudget) encode(v any) ([]byte, error) {
	var kind, id string
	var raw []byte
	var err error
	switch v := v.(type) {
	case ErasureOperation:
		kind, id = "operation", v.Identity()
		raw, err = EncodeErasureOperation(v)
	case ArtifactAdmission:
		kind, id = "admission", v.Identity()
		raw, err = EncodeArtifactAdmission(v)
	case StorageNamespace:
		kind, id = "namespace", v.Identity()
		raw, err = EncodeStorageNamespace(v)
	case ErasureAuthorizationV2:
		kind, id = "authorization", v.Identity()
		raw, err = EncodeErasureAuthorizationV2(v)
	case ResumeAllowance:
		kind, id = "allowance", v.Identity()
		raw, err = EncodeResumeAllowance(v)
	case AttemptRequest:
		kind, id = "request", v.Identity()
		raw, err = EncodeAttemptRequest(v)
	case ErasureAttempt:
		kind, id = "attempt", v.Identity()
		raw, err = EncodeErasureAttempt(v)
	case ErasureEvidence:
		kind, id = "evidence", v.Identity()
		raw, err = EncodeErasureEvidence(v)
	default:
		return nil, ErrInvalidErasureContract
	}
	if err != nil {
		return nil, err
	}
	if err := b.add(kind, id, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func buildErasureProgress(input ErasureProgressOptions) (*erasureProgressData, error) {
	if len(input.Attempts) > 256 || len(input.AllowanceSnapshots) > 192 || len(input.Evidence) > 384 ||
		len(input.UnrecordedUncertainty) > 64 || len(input.AdmissionPolicyBytes) == 0 || len(input.AdmissionPolicyBytes) > 16384 ||
		len(input.OperationPolicyBytes) == 0 || len(input.OperationPolicyBytes) > 16384 ||
		len(input.RequestedAllowanceIdentity) > 64 || input.RequestedAllowanceIdentity != "" && !validDigest(input.RequestedAllowanceIdentity) ||
		!validErasureAuthorizationV2Time(input.OperationAcceptedAt) {
		return nil, ErrInvalidErasureContract
	}
	// Inspect all externally sized collections before retaining any of them.
	for _, s := range input.AllowanceSnapshots {
		if len(s.AcceptedPolicyBytes) == 0 || len(s.AcceptedPolicyBytes) > 16384 || !validErasureAuthorizationV2Time(s.AcceptedAt) ||
			!validDigest(s.Usage.AllowanceIdentity) || s.Usage.NextSequence < 1 || s.Usage.NextSequence > 4097 {
			return nil, ErrInvalidErasureContract
		}
	}
	confirmed := input.ConfirmedVersion != "" || input.ConfirmedCiphertextDigest != "" || !input.ConfirmedAt.IsZero()
	if confirmed && (!strings.HasPrefix(input.ConfirmedVersion, "version:") ||
		!validObjectVersionID(strings.TrimPrefix(input.ConfirmedVersion, "version:")) || !validDigest(input.ConfirmedCiphertextDigest) ||
		!validErasureAuthorizationV2Time(input.ConfirmedAt)) {
		return nil, ErrInvalidErasureContract
	}
	b := &erasureProgressBudget{records: make(map[string][]byte)}
	o := input
	raw, err := b.encode(input.Operation)
	if err != nil {
		return nil, err
	}
	scope, err := cloneErasureMetadataScope(input.Operation.Scope())
	if err != nil {
		return nil, err
	}
	o.Operation, err = ParseErasureOperation(raw, scope)
	if err != nil {
		return nil, err
	}
	raw, err = b.encode(input.Admission)
	if err != nil {
		return nil, err
	}
	o.Admission, err = ParseArtifactAdmission(raw)
	if err != nil {
		return nil, err
	}
	raw, err = b.encode(input.Namespace)
	if err != nil {
		return nil, err
	}
	o.Namespace, err = ParseStorageNamespace(raw)
	if err != nil {
		return nil, err
	}
	raw, err = b.encode(input.OriginalAuthorization)
	if err != nil {
		return nil, err
	}
	o.OriginalAuthorization, err = ParseErasureAuthorizationV2(raw)
	if err != nil {
		return nil, err
	}
	o.RequestedAllowanceIdentity = strings.Clone(input.RequestedAllowanceIdentity)
	o.ConfirmedVersion = strings.Clone(input.ConfirmedVersion)
	o.ConfirmedCiphertextDigest = strings.Clone(input.ConfirmedCiphertextDigest)
	o.OperationAcceptedAt = erasureValueTime(input.OperationAcceptedAt.UnixMilli())
	if confirmed {
		o.ConfirmedAt = erasureValueTime(input.ConfirmedAt.UnixMilli())
	}
	data := &erasureProgressData{}
	policies := make(map[string]erasurePolicySnapshot)
	copyPolicy := func(raw []byte) ([]byte, erasurePolicySnapshot, error) {
		p, err := parseErasurePolicySnapshot(raw)
		if err != nil {
			return nil, erasurePolicySnapshot{}, err
		}
		key := "policy:" + p.Identity
		if old, exists := b.records[key]; exists {
			if !bytes.Equal(old, raw) {
				return nil, erasurePolicySnapshot{}, ErrInvalidErasureContract
			}
			return old, p, nil
		}
		// Charge before the copy, then retain only our immutable bytes.
		if err := b.add("policy", p.Identity, raw); err != nil {
			return nil, erasurePolicySnapshot{}, err
		}
		copied := append([]byte(nil), raw...)
		b.records[key] = copied
		data.policies = append(data.policies, copied)
		policies[p.Identity] = p
		return copied, p, nil
	}
	var admissionPolicy, originalPolicy erasurePolicySnapshot
	o.AdmissionPolicyBytes, admissionPolicy, err = copyPolicy(input.AdmissionPolicyBytes)
	if err != nil {
		return nil, err
	}
	o.OperationPolicyBytes, originalPolicy, err = copyPolicy(input.OperationPolicyBytes)
	if err != nil {
		return nil, err
	}
	if err := validateProgressOriginal(o, admissionPolicy, originalPolicy); err != nil {
		return nil, err
	}
	o.AllowanceSnapshots = make([]ErasureAllowanceSnapshot, 0, len(input.AllowanceSnapshots))
	snapshots := make(map[string]ErasureAllowanceSnapshot)
	for _, supplied := range input.AllowanceSnapshots {
		raw, err := b.encode(supplied.Allowance)
		if err != nil {
			return nil, err
		}
		if _, exists := snapshots[supplied.Allowance.Identity()]; exists {
			return nil, ErrInvalidErasureContract
		}
		a, err := ParseResumeAllowance(raw, scope)
		if err != nil {
			return nil, err
		}
		policyBytes, policy, err := copyPolicy(supplied.AcceptedPolicyBytes)
		if err != nil {
			return nil, err
		}
		s := ErasureAllowanceSnapshot{Allowance: a, AcceptedPolicyBytes: policyBytes, AcceptedAt: erasureValueTime(supplied.AcceptedAt.UnixMilli()),
			Usage: supplied.Usage, AttemptCount: supplied.AttemptCount, TotalCost: supplied.TotalCost}
		s.Usage.AllowanceIdentity = strings.Clone(s.Usage.AllowanceIdentity)
		if err := validateProgressAllowance(o, s, originalPolicy, policy); err != nil {
			return nil, err
		}
		snapshots[a.Identity()] = s
		o.AllowanceSnapshots = append(o.AllowanceSnapshots, s)
	}
	o.Attempts = make([]ErasureAttempt, 0, len(input.Attempts))
	attempts := make(map[string]ErasureAttempt)
	requests, reservations, sequences := make(map[string]bool), make(map[string]bool), make(map[string]map[uint64]bool)
	totals := make(map[string]ResumeBudget)
	for _, supplied := range input.Attempts {
		requestBytes, err := b.encode(supplied.Request())
		if err != nil {
			return nil, err
		}
		attemptBytes, err := b.encode(supplied)
		if err != nil {
			return nil, err
		}
		request, err := ParseAttemptRequest(requestBytes, scope)
		if err != nil {
			return nil, err
		}
		a, err := ParseErasureAttempt(attemptBytes, request)
		if err != nil {
			return nil, err
		}
		if _, exists := attempts[a.Identity()]; exists {
			return nil, ErrInvalidErasureContract
		}
		if requests[request.Identity()] || reservations[request.ReservationIdentity()] {
			return nil, ErrInvalidErasureContract
		}
		requests[request.Identity()], reservations[request.ReservationIdentity()] = true, true
		if sequences[request.AllowanceIdentity()] == nil {
			sequences[request.AllowanceIdentity()] = make(map[uint64]bool)
		}
		if sequences[request.AllowanceIdentity()][a.Sequence()] {
			return nil, ErrInvalidErasureContract
		}
		sequences[request.AllowanceIdentity()][a.Sequence()] = true
		s, exists := snapshots[request.AllowanceIdentity()]
		if !exists {
			return nil, ErrInvalidErasureContract
		}
		policy := policies[s.Allowance.ProtectedPolicyIdentity()]
		if err := validateProgressAttempt(o, a, s, policy); err != nil {
			return nil, err
		}
		sum, ok := addProgressBudget(totals[s.Allowance.Identity()], progressAttemptCost(request))
		if !ok || !progressBudgetWithin(sum, s.Usage.Spent) {
			return nil, ErrErasureBindingMismatch
		}
		totals[s.Allowance.Identity()] = sum
		attempts[a.Identity()] = a
		o.Attempts = append(o.Attempts, a)
	}
	for id, s := range snapshots {
		if uint64(totals[id].Requests) == s.AttemptCount && totals[id] != s.Usage.Spent {
			return nil, ErrErasureBindingMismatch
		}
	}
	o.Evidence = make([]ErasureEvidence, 0, len(input.Evidence))
	evidence := make(map[string]ErasureEvidence)
	slots := make(map[string]ErasureEvidence)
	for _, supplied := range input.Evidence {
		raw, err := b.encode(supplied)
		if err != nil {
			return nil, err
		}
		if _, exists := evidence[supplied.Identity()]; exists {
			return nil, ErrInvalidErasureContract
		}
		if _, exists := slots[supplied.Slot()]; exists {
			return nil, ErrInvalidErasureContract
		}
		if supplied.Ref() != o.Operation.Ref() {
			return nil, ErrErasureBindingMismatch
		}
		e, err := ParseErasureEvidence(raw, o.Operation.Ref())
		if err != nil {
			return nil, err
		}
		evidence[e.Identity()], slots[e.Slot()] = e, e
		o.Evidence = append(o.Evidence, e)
	}
	graph := erasureProgressGraph{o: o, attempts: attempts, snapshots: snapshots, policies: policies, evidence: evidence, slots: slots}
	if err := graph.validate(); err != nil {
		return nil, err
	}
	o.UnrecordedUncertainty = make([]ErasureAttempt, 0, len(input.UnrecordedUncertainty))
	seenUnrecorded := make(map[string]bool)
	for _, supplied := range input.UnrecordedUncertainty {
		raw, err := EncodeErasureAttempt(supplied)
		if err != nil {
			return nil, err
		}
		requestBytes, err := EncodeAttemptRequest(supplied.Request())
		if err != nil {
			return nil, err
		}
		a, exists := attempts[supplied.Identity()]
		if !exists || seenUnrecorded[supplied.Identity()] {
			return nil, ErrInvalidErasureContract
		}
		if !bytes.Equal(raw, b.records["attempt:"+a.Identity()]) || !bytes.Equal(requestBytes, b.records["request:"+a.Request().Identity()]) {
			return nil, ErrErasureBindingMismatch
		}
		if slots["response:"+a.Identity()].Identity() != "" || slots["unknown:"+a.Identity()].Identity() != "" {
			return nil, ErrErasureBindingMismatch
		}
		seenUnrecorded[a.Identity()] = true
		o.UnrecordedUncertainty = append(o.UnrecordedUncertainty, a)
	}
	if o.UncertaintyBookkeepingMore && len(o.UnrecordedUncertainty) != 64 {
		return nil, ErrErasureBindingMismatch
	}
	// Missing dependencies take precedence over a requested usage lookup.
	if o.RequestedAllowanceIdentity != "" {
		if _, exists := snapshots[o.RequestedAllowanceIdentity]; !exists {
			return nil, ErrErasureConflict
		}
	}
	data.options = o
	data.fence, data.candidate, data.published = slots["fence"], slots["candidate"], slots["published"]
	return data, nil
}
