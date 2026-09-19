package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

type resumeResolver struct {
	j                      *artifactResumeJournal
	ctx                    context.Context
	tx                     *sql.Tx
	ref                    artifact.ErasureOperationRef
	options                artifact.ErasureProgressOptions
	originalPolicy         persistedErasurePolicy
	points, canonicalBytes int
	canonical              map[string][]byte
	allowances             map[string]artifact.ErasureAllowanceSnapshot
	attempts               map[string]artifact.ErasureAttempt
	reservations           map[string]string
	evidence               map[string]artifact.ErasureEvidence
	slots                  map[string]string
	absent                 map[string]bool
	attemptEvidence        map[string]bool
	evidenceLoading        map[string]bool
	responses              map[string]artifact.AttemptResponseOptions
	parseResponseEvidence  func(artifact.ErasureEvidence, artifact.ErasureAttempt) (artifact.AttemptResponseOptions, error)
}

func newResumeResolver(j *artifactResumeJournal, ctx context.Context, tx *sql.Tx, ref artifact.ErasureOperationRef) *resumeResolver {
	return &resumeResolver{j: j, ctx: ctx, tx: tx, ref: ref, canonical: map[string][]byte{}, allowances: map[string]artifact.ErasureAllowanceSnapshot{}, attempts: map[string]artifact.ErasureAttempt{}, reservations: map[string]string{}, evidence: map[string]artifact.ErasureEvidence{}, slots: map[string]string{}, absent: map[string]bool{}, attemptEvidence: map[string]bool{}, evidenceLoading: map[string]bool{}, responses: map[string]artifact.AttemptResponseOptions{}, parseResponseEvidence: artifact.ParseAttemptResponseEvidence}
}
func (r *resumeResolver) chargePoints(n int) error {
	if n < 0 || r.points > 192-n {
		return ErrCorruptRecord
	}
	r.points += n
	return nil
}
func (r *resumeResolver) charge(kind, identity string, raw []byte) error {
	key := kind + ":" + identity
	if prior, ok := r.canonical[key]; ok {
		if !bytes.Equal(prior, raw) {
			return ErrCorruptRecord
		}
		return nil
	}
	if len(raw) == 0 || len(raw) > 8<<20-r.canonicalBytes {
		return ErrCorruptRecord
	}
	r.canonicalBytes += len(raw)
	r.canonical[key] = raw
	return nil
}
func (r *resumeResolver) rows(query string, columns, maximum int, page bool, args ...any) ([][]any, error) {
	if !page {
		if err := r.chargePoints(1); err != nil {
			return nil, err
		}
	}
	return readResumeRows(r.ctx, r.tx, query, columns, maximum, args...)
}
func (r *resumeResolver) original() (bool, error) {
	// queryOperation includes its own legacy-lineage point read when present.
	if err := r.chargePoints(1); err != nil {
		return false, err
	}
	op, found, err := r.j.queryOperation(r.ctx, r.tx, r.ref.Scope(), r.ref.NamespaceIdentity(), r.ref.OperationIdentity(), true)
	if err != nil || !found {
		return false, err
	}
	if err := r.chargePoints(2); err != nil {
		return false, err
	}
	rows, err := readErasureRows(r.ctx, r.tx, journalSQLOperationRefRead, 43, 1, erasureReadArgs(r.ref.Scope(), r.ref.NamespaceIdentity(), r.ref.OperationIdentity())...)
	if err != nil {
		return false, err
	}
	if len(rows) != 1 {
		return false, ErrCorruptRecord
	}
	row := rows[0]
	raw, ok := erasureBytes(row, 8, 16384)
	if !ok {
		return false, ErrCorruptRecord
	}
	encoded, err := artifact.EncodeErasureOperation(op)
	if err != nil || !bytes.Equal(raw, encoded) {
		return false, ErrCorruptRecord
	}
	admission, err := r.j.decodeAdmissionRow(row[17:], op.Scope(), op.NamespaceIdentity(), op.ArtifactIdentity())
	if err != nil {
		return false, err
	}
	authRaw, ok := erasureBytes(row, 9, 8192)
	if !ok {
		return false, ErrCorruptRecord
	}
	grant, err := artifact.ParseErasureAuthorizationV2(authRaw)
	if err != nil {
		return false, ErrCorruptRecord
	}
	policyRaw, ok := erasureBytes(row, 10, 16384)
	if !ok {
		return false, ErrCorruptRecord
	}
	policy, err := parsePersistedErasurePolicy(policyRaw)
	if err != nil {
		return false, ErrCorruptRecord
	}
	r.originalPolicy = policy
	r.options = artifact.ErasureProgressOptions{Operation: op, Admission: admission.admission, Namespace: admission.namespace, OriginalAuthorization: grant, AdmissionPolicyBytes: admission.policyBytes, OperationPolicyBytes: policyRaw, OperationAcceptedAt: time.UnixMilli(erasureInt(row, 16)).UTC(), ConfirmedVersion: admission.version, ConfirmedCiphertextDigest: admission.ciphertextDigest}
	if admission.confirmedAt != 0 {
		r.options.ConfirmedAt = time.UnixMilli(admission.confirmedAt).UTC()
	}
	for _, item := range []struct {
		kind, id string
		raw      []byte
	}{{"operation", op.Identity(), encoded}, {"authorization", grant.Identity(), authRaw}, {"policy", policy.Identity, policyRaw}, {"policy", admission.policy.Identity, admission.policyBytes}} {
		if err := r.charge(item.kind, item.id, item.raw); err != nil {
			return false, err
		}
	}
	aRaw, err := artifact.EncodeArtifactAdmission(admission.admission)
	if err != nil {
		return false, ErrCorruptRecord
	}
	nsRaw, err := artifact.EncodeStorageNamespace(admission.namespace)
	if err != nil {
		return false, ErrCorruptRecord
	}
	if err := r.charge("admission", admission.admission.Identity(), aRaw); err != nil {
		return false, err
	}
	if err := r.charge("namespace", admission.namespace.Identity(), nsRaw); err != nil {
		return false, err
	}
	return true, nil
}
func resumeStablePolicy(a, b persistedErasurePolicy) bool {
	a.Identity = ""
	b.Identity = ""
	a.ConfigurationEvidenceIdentity = ""
	b.ConfigurationEvidenceIdentity = ""
	a.NotBeforeMilliseconds = 0
	b.NotBeforeMilliseconds = 0
	a.NotAfterMilliseconds = 0
	b.NotAfterMilliseconds = 0
	return a == b
}
func (r *resumeResolver) allowance(identity string, lock bool) (artifact.ErasureAllowanceSnapshot, bool, error) {
	if value, ok := r.allowances[identity]; ok {
		return value, true, nil
	}
	key := "allowance:" + identity
	if r.absent[key] {
		return artifact.ErasureAllowanceSnapshot{}, false, nil
	}
	query := resumeSQLAllowanceRead
	if lock {
		query = resumeSQLAllowanceLock
	}
	rows, err := r.rows(query, 36, 1, false, resumeArgs(r.ref, identity)...)
	if err != nil {
		return artifact.ErasureAllowanceSnapshot{}, false, err
	}
	if len(rows) == 0 {
		r.absent[key] = true
		return artifact.ErasureAllowanceSnapshot{}, false, nil
	}
	value, err := resumeDecodeAllowance(rows[0], r.options.Operation, r.options.Namespace, r.j.DatabaseAuthorityIdentity(), identity)
	if err != nil {
		return artifact.ErasureAllowanceSnapshot{}, false, err
	}
	policy, err := parsePersistedErasurePolicy(value.AcceptedPolicyBytes)
	if err != nil || !resumeStablePolicy(policy, r.originalPolicy) || value.Allowance.PrincipalIdentity() != r.options.OriginalAuthorization.PrincipalIdentity() {
		return artifact.ErasureAllowanceSnapshot{}, false, ErrCorruptRecord
	}
	totals, err := r.rows(resumeSQLAllowanceTotals, 12, 1, false, resumeArgs(r.ref, identity)...)
	if err != nil {
		return artifact.ErasureAllowanceSnapshot{}, false, err
	}
	if len(totals) != 1 || !erasureExactInt(totals[0], 0, int64(value.Usage.Spent.Requests)) {
		return artifact.ErasureAllowanceSnapshot{}, false, ErrCorruptRecord
	}
	total, err := resumeReadBudget(totals[0], 1, value.Allowance.Maximum())
	if err != nil || total != value.Usage.Spent {
		return artifact.ErasureAllowanceSnapshot{}, false, ErrCorruptRecord
	}
	value.AttemptCount = uint64(value.Usage.Spent.Requests)
	value.TotalCost = total
	if len(r.allowances) >= 192 {
		return artifact.ErasureAllowanceSnapshot{}, false, ErrCorruptRecord
	}
	if err := r.charge("policy", policy.Identity, value.AcceptedPolicyBytes); err != nil {
		return artifact.ErasureAllowanceSnapshot{}, false, err
	}
	raw, err := artifact.EncodeResumeAllowance(value.Allowance)
	if err != nil {
		return artifact.ErasureAllowanceSnapshot{}, false, ErrCorruptRecord
	}
	if err := r.charge("allowance", identity, raw); err != nil {
		return artifact.ErasureAllowanceSnapshot{}, false, err
	}
	r.allowances[identity] = value
	return value, true, nil
}
func (r *resumeResolver) attempt(identity string, byReservation bool, depth int) (artifact.ErasureAttempt, bool, error) {
	key := "attempt:" + identity
	if byReservation {
		key = "reservation:" + identity
		if id, ok := r.reservations[identity]; ok {
			return r.attempts[id], true, nil
		}
	} else if a, ok := r.attempts[identity]; ok {
		return a, true, nil
	}
	if r.absent[key] {
		return artifact.ErasureAttempt{}, false, nil
	}
	query := resumeSQLAttemptIdentityRead
	if byReservation {
		query = resumeSQLAttemptRead
	}
	rows, err := r.rows(query, 27, 1, false, resumeArgs(r.ref, identity)...)
	if err != nil {
		return artifact.ErasureAttempt{}, false, err
	}
	if len(rows) == 0 {
		r.absent[key] = true
		return artifact.ErasureAttempt{}, false, nil
	}
	a, err := resumeDecodeAttempt(rows[0], r.options.Operation)
	if err != nil || byReservation && a.Request().ReservationIdentity() != identity || !byReservation && a.Identity() != identity {
		return artifact.ErasureAttempt{}, false, ErrCorruptRecord
	}
	if err := r.includeAttempt(a, false, depth); err != nil {
		return artifact.ErasureAttempt{}, false, err
	}
	return a, true, nil
}
func (r *resumeResolver) includeAttempt(a artifact.ErasureAttempt, negative bool, depth int) error {
	if old, ok := r.attempts[a.Identity()]; ok {
		x, _ := artifact.EncodeErasureAttempt(old)
		y, _ := artifact.EncodeErasureAttempt(a)
		if !bytes.Equal(x, y) {
			return ErrCorruptRecord
		}
		if negative && r.attemptEvidence[a.Identity()] {
			for _, e := range r.evidence {
				if e.AttemptIdentity() == a.Identity() {
					return ErrCorruptRecord
				}
			}
		}
		return nil
	}
	if len(r.attempts) >= 257 {
		return ErrCorruptRecord
	}
	request := a.Request()
	if prior, ok := r.reservations[request.ReservationIdentity()]; ok && prior != a.Identity() {
		return ErrCorruptRecord
	}
	allowance, found, err := r.allowance(request.AllowanceIdentity(), false)
	if err != nil {
		return err
	}
	if !found {
		return ErrCorruptRecord
	}
	if a.Sequence() > uint64(allowance.Usage.Spent.Requests) || a.ReservedAt().Before(allowance.AcceptedAt) || !allowance.Allowance.AllowsOperation(r.options.Operation, a.ReservedAt()) {
		return ErrCorruptRecord
	}
	policy, err := parsePersistedErasurePolicy(allowance.AcceptedPolicyBytes)
	if err != nil || !policy.allows(a.ReservedAt()) {
		return ErrCorruptRecord
	}
	for _, other := range r.attempts {
		if other.Request().AllowanceIdentity() == request.AllowanceIdentity() && other.Sequence() == a.Sequence() {
			return ErrCorruptRecord
		}
	}
	raw, err := artifact.EncodeErasureAttempt(a)
	if err != nil {
		return ErrCorruptRecord
	}
	if err := r.charge("attempt", a.Identity(), raw); err != nil {
		return err
	}
	requestRaw, err := artifact.EncodeAttemptRequest(request)
	if err != nil {
		return ErrCorruptRecord
	}
	if err := r.charge("request", request.Identity(), requestRaw); err != nil {
		return err
	}
	r.attempts[a.Identity()] = a
	r.reservations[request.ReservationIdentity()] = a.Identity()
	if err := r.validateRequest(request, allowance.Allowance, a.ReservedAt(), depth); err != nil {
		return err
	}
	if negative {
		r.absent["slot:response:"+a.Identity()] = true
		r.absent["slot:unknown:"+a.Identity()] = true
		return nil
	}
	return r.attemptEvidenceRows(a, depth)
}
func (r *resumeResolver) attemptEvidenceRows(a artifact.ErasureAttempt, depth int) error {
	if r.attemptEvidence[a.Identity()] {
		return nil
	}
	r.attemptEvidence[a.Identity()] = true
	rows, err := r.rows(resumeSQLEvidenceAttemptRead, 14, 3, false, resumeArgs(r.ref, a.Identity())...)
	if err != nil {
		return err
	}
	if len(rows) > 2 {
		return ErrCorruptRecord
	}
	seen := map[string]bool{}
	var values []artifact.ErasureEvidence
	for _, row := range rows {
		e, err := resumeDecodeEvidence(row, r.options.Operation)
		if err != nil || e.AttemptIdentity() != a.Identity() || (e.Kind() != "response" && e.Kind() != "unknown") || seen[e.Kind()] {
			return ErrCorruptRecord
		}
		seen[e.Kind()] = true
		values = append(values, e)
	}
	for _, kind := range []string{"response", "unknown"} {
		if !seen[kind] {
			r.absent["slot:"+kind+":"+a.Identity()] = true
		}
	}
	for _, e := range values {
		if err := r.includeEvidence(e, depth); err != nil {
			return err
		}
	}
	return r.validateUncertainty(a.Identity())
}
func resumeResponseKey(evidenceIdentity, attemptIdentity string) string {
	return evidenceIdentity + ":" + attemptIdentity
}
func (r *resumeResolver) parseResponse(e artifact.ErasureEvidence, a artifact.ErasureAttempt) (artifact.AttemptResponseOptions, error) {
	if response, ok := r.response(e.Identity(), a.Identity()); ok {
		return response, nil
	}
	parser := r.parseResponseEvidence
	if parser == nil {
		parser = artifact.ParseAttemptResponseEvidence
	}
	response, err := parser(e, a)
	if err != nil {
		return artifact.AttemptResponseOptions{}, err
	}
	r.responses[resumeResponseKey(e.Identity(), a.Identity())] = response
	return response, nil
}
func (r *resumeResolver) response(evidenceIdentity, attemptIdentity string) (artifact.AttemptResponseOptions, bool) {
	response, ok := r.responses[resumeResponseKey(evidenceIdentity, attemptIdentity)]
	return response, ok
}
func (r *resumeResolver) evidenceRead(identity string, bySlot bool, depth int) (artifact.ErasureEvidence, bool, error) {
	if depth > 6 {
		return artifact.ErasureEvidence{}, false, ErrCorruptRecord
	}
	key := "evidence:" + identity
	if bySlot {
		key = "slot:" + identity
		if id, ok := r.slots[identity]; ok {
			return r.evidence[id], true, nil
		}
	} else if e, ok := r.evidence[identity]; ok {
		return e, true, nil
	}
	if r.absent[key] {
		return artifact.ErasureEvidence{}, false, nil
	}
	query := resumeSQLEvidenceIdentityRead
	if bySlot {
		query = resumeSQLEvidenceSlotRead
	}
	rows, err := r.rows(query, 14, 1, false, resumeArgs(r.ref, identity)...)
	if err != nil {
		return artifact.ErasureEvidence{}, false, err
	}
	if len(rows) == 0 {
		r.absent[key] = true
		return artifact.ErasureEvidence{}, false, nil
	}
	e, err := resumeDecodeEvidence(rows[0], r.options.Operation)
	if err != nil || bySlot && e.Slot() != identity || !bySlot && e.Identity() != identity {
		return artifact.ErasureEvidence{}, false, ErrCorruptRecord
	}
	if err := r.includeEvidence(e, depth); err != nil {
		return artifact.ErasureEvidence{}, false, err
	}
	return e, true, nil
}
func (r *resumeResolver) includeEvidence(e artifact.ErasureEvidence, depth int) error {
	if depth > 6 {
		return ErrCorruptRecord
	}
	if old, ok := r.evidence[e.Identity()]; ok {
		a, _ := artifact.EncodeErasureEvidence(old)
		b, _ := artifact.EncodeErasureEvidence(e)
		if !bytes.Equal(a, b) {
			return ErrCorruptRecord
		}
		return nil
	}
	if len(r.evidence) >= 384 || r.absent["slot:"+e.Slot()] {
		return ErrCorruptRecord
	}
	if prior, ok := r.slots[e.Slot()]; ok && prior != e.Identity() {
		return ErrCorruptRecord
	}
	raw, err := artifact.EncodeErasureEvidence(e)
	if err != nil {
		return ErrCorruptRecord
	}
	if e.Ref() != r.ref {
		return ErrCorruptRecord
	}
	if err := r.charge("evidence", e.Identity(), raw); err != nil {
		return err
	}
	r.evidence[e.Identity()] = e
	r.slots[e.Slot()] = e.Identity()
	r.evidenceLoading[e.Identity()] = true
	defer delete(r.evidenceLoading, e.Identity())
	if e.AttemptIdentity() != "" {
		a, found, err := r.attempt(e.AttemptIdentity(), false, depth)
		if err != nil {
			return err
		}
		if !found || e.ObservedAt().Before(a.ReservedAt()) {
			return ErrCorruptRecord
		}
		if e.Kind() == "response" {
			response, err := r.parseResponse(e, a)
			if err != nil {
				return ErrCorruptRecord
			}
			if r.legacyRead(a.Request()) && (response.Code == artifact.AttemptResponsePresent || response.ContentKind != "") {
				return ErrCorruptRecord
			}
		}
	}
	for _, id := range e.ParentIdentities() {
		if r.evidenceLoading[id] {
			return ErrCorruptRecord
		}
		_, found, err := r.evidenceRead(id, false, depth+1)
		if err != nil {
			return err
		}
		if !found {
			return ErrCorruptRecord
		}
	}
	return nil
}
func (r *resumeResolver) validateUncertainty(identity string) error {
	responseID, has := r.slots["response:"+identity]
	if !has {
		return nil
	}
	a, ok := r.attempts[identity]
	if !ok {
		return ErrCorruptRecord
	}
	o, err := r.parseResponse(r.evidence[responseID], a)
	if err != nil {
		return ErrCorruptRecord
	}
	if o.Code == artifact.AttemptResponseUnavailable || o.Code == artifact.AttemptResponseMalformed {
		if _, ok := r.slots["unknown:"+identity]; !ok {
			return ErrCorruptRecord
		}
	}
	return nil
}
func (r *resumeResolver) globals() error {
	for _, slot := range []string{"fence", "candidate", "published"} {
		if _, _, err := r.evidenceRead(slot, true, 0); err != nil {
			return err
		}
	}
	for _, q := range []struct {
		query  string
		target *bool
	}{{resumeSQLUnresolvedExists, &r.options.UnresolvedExists}, {resumeSQLUnknownExists, &r.options.UnknownExists}} {
		rows, err := r.rows(q.query, 1, 1, false, erasureReadArgs(r.ref.Scope(), r.ref.NamespaceIdentity(), r.ref.OperationIdentity())...)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return ErrCorruptRecord
		}
		v, ok := rows[0][0].(bool)
		if !ok {
			return ErrCorruptRecord
		}
		*q.target = v
	}
	return nil
}
func (r *resumeResolver) progress() (artifact.ErasureProgress, error) {
	o := r.options
	o.Attempts = make([]artifact.ErasureAttempt, 0, len(r.attempts))
	o.Evidence = make([]artifact.ErasureEvidence, 0, len(r.evidence))
	o.AllowanceSnapshots = make([]artifact.ErasureAllowanceSnapshot, 0, len(r.allowances))
	for _, a := range r.attempts {
		o.Attempts = append(o.Attempts, a)
		if err := r.validateUncertainty(a.Identity()); err != nil {
			return artifact.ErasureProgress{}, err
		}
	}
	for _, e := range r.evidence {
		o.Evidence = append(o.Evidence, e)
	}
	for _, a := range r.allowances {
		o.AllowanceSnapshots = append(o.AllowanceSnapshots, a)
	}
	sort.Slice(o.Attempts, func(i, j int) bool { return o.Attempts[i].Identity() < o.Attempts[j].Identity() })
	sort.Slice(o.Evidence, func(i, j int) bool { return o.Evidence[i].Identity() < o.Evidence[j].Identity() })
	sort.Slice(o.AllowanceSnapshots, func(i, j int) bool {
		return o.AllowanceSnapshots[i].Allowance.Identity() < o.AllowanceSnapshots[j].Allowance.Identity()
	})
	p, err := artifact.NewErasureProgress(o)
	if err != nil {
		return artifact.ErasureProgress{}, ErrCorruptRecord
	}
	return p, nil
}

func (r *resumeResolver) validateRequest(request artifact.AttemptRequest, a artifact.ResumeAllowance, at time.Time, depth int) error {
	op := r.options.Operation
	key, err := artifact.NewExactObjectKey(op.NamespaceIdentity(), request.Key())
	if err != nil {
		return ErrCorruptRecord
	}
	var version artifact.ObjectVersion
	if request.Kind() == artifact.AttemptVersionDelete {
		version, err = artifact.NewObjectVersion(op.NamespaceIdentity(), request.Key(), request.VersionKind(), request.VersionID())
		if err != nil {
			return ErrCorruptRecord
		}
	}
	rebuilt, err := artifact.NewAttemptRequest(artifact.AttemptRequestOptions{ReservationIdentity: request.ReservationIdentity(), Operation: op, Allowance: a, Kind: request.Kind(), Key: key, Version: version, Cursor: artifact.VersionCursor{KeyMarker: request.KeyMarker(), VersionIDMarker: request.VersionIDMarker()}, PageLimit: request.PageLimit(), MaximumResponseBytes: request.MaximumResponseBytes(), BodyDigest: request.BodyDigest(), BodyBytes: request.BodyBytes(), ObservationIdentity: request.ObservationIdentity()})
	if err != nil {
		return ErrCorruptRecord
	}
	x, _ := artifact.EncodeAttemptRequest(rebuilt)
	y, _ := artifact.EncodeAttemptRequest(request)
	if !bytes.Equal(x, y) {
		return ErrCorruptRecord
	}
	current := r.options.Namespace.Prefix() + "/artifacts/" + op.Scope().Identity() + "/" + op.ArtifactIdentity()
	stem := r.options.Namespace.Prefix() + "/deletions/" + op.Scope().Identity() + "/" + op.ArtifactIdentity()
	want := current
	switch request.Kind() {
	case artifact.AttemptIntentRead:
		if request.Key() == stem+".intent" {
			return nil
		}
		want = stem + ".intent-v2"
	case artifact.AttemptAttestationRead:
		if request.Key() == stem+".receipt" {
			return nil
		}
		want = stem + ".attestation-v2"
	case artifact.AttemptIntentCreate:
		want = stem + ".intent-v2"
	case artifact.AttemptAttestationCreate:
		want = stem + ".attestation-v2"
	}
	if request.Key() != want {
		return ErrCorruptRecord
	}
	if request.ObservationIdentity() == "" {
		return nil
	}
	observation, found, err := r.evidenceRead(request.ObservationIdentity(), false, depth+1)
	if err != nil {
		return err
	}
	if !found || observation.Kind() != "response" || at.Before(observation.ObservedAt()) {
		return ErrCorruptRecord
	}
	observedAttempt, found, err := r.attempt(observation.AttemptIdentity(), false, depth+1)
	if err != nil {
		return err
	}
	if !found || observedAttempt.Request().Key() != request.Key() {
		return ErrCorruptRecord
	}
	response, err := r.parseResponse(observation, observedAttempt)
	if err != nil {
		return ErrCorruptRecord
	}
	switch request.Kind() {
	case artifact.AttemptIntentCreate, artifact.AttemptFenceCreate, artifact.AttemptAttestationCreate:
		expected := artifact.AttemptCurrentRead
		if request.Kind() == artifact.AttemptIntentCreate {
			expected = artifact.AttemptIntentRead
		}
		if request.Kind() == artifact.AttemptAttestationCreate {
			expected = artifact.AttemptAttestationRead
		}
		if observedAttempt.Request().Kind() != expected || response.Code != artifact.AttemptResponseAbsent {
			return ErrCorruptRecord
		}
		if request.Kind() == artifact.AttemptAttestationCreate {
			candidate, found, err := r.evidenceRead("candidate", true, depth+1)
			if err != nil {
				return err
			}
			if !found || at.Before(candidate.ObservedAt()) || request.BodyDigest() != erasureDigest(candidate.RecordBytes()) || request.BodyBytes() != uint32(len(candidate.RecordBytes())) {
				return ErrCorruptRecord
			}
		}
	case artifact.AttemptVersionDelete:
		if response.Code != artifact.AttemptResponsePresent {
			return ErrCorruptRecord
		}
		matched := false
		switch observedAttempt.Request().Kind() {
		case artifact.AttemptCurrentRead:
			matched = response.ContentKind == "ciphertext" && response.Version == version
		case artifact.AttemptVersionList:
			for _, entry := range response.Page.Entries {
				if entry.Version == version {
					matched = true
				}
			}
		}
		if !matched {
			return ErrCorruptRecord
		}
		fence, found, err := r.evidenceRead("fence", true, depth+1)
		if err != nil {
			return err
		}
		if observedAttempt.Request().Kind() == artifact.AttemptVersionList && (!found || observedAttempt.ReservedAt().Before(fence.ObservedAt())) {
			return ErrCorruptRecord
		}
		if found {
			required, err := artifact.ParseObjectVersion(fence.RecordBytes())
			if err != nil || version.VersionID() == required.VersionID() {
				return ErrCorruptRecord
			}
		}
	default:
		return ErrCorruptRecord
	}
	return nil
}

func (r *resumeResolver) legacyRead(request artifact.AttemptRequest) bool {
	op := r.options.Operation
	stem := r.options.Namespace.Prefix() + "/deletions/" + op.Scope().Identity() + "/" + op.ArtifactIdentity()
	return request.Kind() == artifact.AttemptIntentRead && request.Key() == stem+".intent" || request.Kind() == artifact.AttemptAttestationRead && request.Key() == stem+".receipt"
}
func (r *resumeResolver) evidenceDepth(e artifact.ErasureEvidence, start int) error {
	path := map[string]bool{}
	var visit func(artifact.ErasureEvidence, int) error
	visit = func(value artifact.ErasureEvidence, depth int) error {
		if depth > 6 || path[value.Identity()] {
			return ErrCorruptRecord
		}
		path[value.Identity()] = true
		defer delete(path, value.Identity())
		for _, id := range value.ParentIdentities() {
			parent, ok := r.evidence[id]
			if !ok {
				return ErrCorruptRecord
			}
			if err := visit(parent, depth+1); err != nil {
				return err
			}
		}
		if value.AttemptIdentity() != "" {
			a, ok := r.attempts[value.AttemptIdentity()]
			if !ok {
				return ErrCorruptRecord
			}
			if id := a.Request().ObservationIdentity(); id != "" {
				parent, ok := r.evidence[id]
				if !ok {
					return ErrCorruptRecord
				}
				if err := visit(parent, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return visit(e, start)
}
