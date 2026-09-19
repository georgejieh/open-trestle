package artifact

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"
)

// dispatchPermit exists only after a known, newly inserted reservation. The
// atomic value is never copied, serialized, restored, or attached to results.
type dispatchPermit struct {
	attempt  ErasureAttempt
	request  AttemptRequest
	consumed atomic.Bool
}

func (*dispatchPermit) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("artifact erasure dispatch permit{redacted}"))
}
func (p *dispatchPermit) consume(a ErasureAttempt, r AttemptRequest) bool {
	if p == nil || a.Validate() != nil || r.Validate() != nil || p.attempt.Identity() != a.Identity() ||
		p.request.Identity() != r.Identity() || a.Request().Identity() != r.Identity() {
		return false
	}
	x, err := EncodeAttemptRequest(p.request)
	if err != nil {
		return false
	}
	y, err := EncodeAttemptRequest(r)
	if err != nil || !bytes.Equal(x, y) {
		return false
	}
	x, err = EncodeErasureAttempt(p.attempt)
	if err != nil {
		return false
	}
	y, err = EncodeErasureAttempt(a)
	return err == nil && bytes.Equal(x, y) && p.consumed.CompareAndSwap(false, true)
}

type resumeObservation struct {
	attempt  ErasureAttempt
	evidence ErasureEvidence
	response AttemptResponseOptions
}

func (resumeObservation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("artifact erasure observation{redacted}"))
}

type resumeRequest struct {
	kind           AttemptKind
	key            ExactObjectKey
	version        ObjectVersion
	cursor         VersionCursor
	limit          uint16
	maximum        uint32
	body, expected []byte
	observation    *resumeObservation
	legacy         bool
	scan           *versionScan
}

func (resumeRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("artifact erasure request{redacted}"))
}

func (i *resumeInvocation) reserveAndDispatch(q resumeRequest) (resumeObservation, error) {
	at, err := i.sample(true)
	if err != nil {
		return resumeObservation{}, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil || nonce == ([32]byte{}) {
		return resumeObservation{}, ErrErasureJournalUnavailable
	}
	options := AttemptRequestOptions{ReservationIdentity: hex.EncodeToString(nonce[:]),
		Operation: i.operation, Allowance: i.allowance, Kind: q.kind, Key: q.key,
		Version: q.version, Cursor: q.cursor, PageLimit: q.limit, MaximumResponseBytes: q.maximum}
	if len(q.body) != 0 {
		if len(q.body) > 16384 {
			return resumeObservation{}, ErrInvalidErasureContract
		}
		options.BodyBytes, options.BodyDigest = uint32(len(q.body)), hashBytes(q.body)
	}
	if q.observation != nil {
		options.ObservationIdentity = q.observation.evidence.Identity()
	}
	request, err := NewAttemptRequest(options)
	if err != nil {
		return resumeObservation{}, err
	}
	if err := i.validateResumeRequestDependencies(request, q, at); err != nil {
		return resumeObservation{}, err
	}
	if err := i.precharge(request); err != nil {
		return resumeObservation{}, err
	}
	attempt, inserted, err := i.mode.journal.ReserveErasureAttempt(i.ctx, i.ref, i.allowance, request, at)
	if err != nil {
		return resumeObservation{}, resumePublicError(err)
	}
	// Replay or readback never grants permission, including an exact reservation.
	if !inserted {
		return resumeObservation{}, ErrErasureUnknownOutcome
	}
	x, xerr := EncodeAttemptRequest(attempt.Request())
	y, yerr := EncodeAttemptRequest(request)
	if attempt.Validate() != nil || xerr != nil || yerr != nil || !bytes.Equal(x, y) ||
		!attempt.ReservedAt().Equal(at) || attempt.Sequence() < i.usage.NextSequence {
		return resumeObservation{}, ErrErasureUnknownOutcome
	}
	permit := &dispatchPermit{attempt: attempt, request: request}
	next, ok := addProgressBudget(i.usage.Spent, progressAttemptCost(request))
	if !ok {
		return resumeObservation{}, ErrErasureUnknownOutcome
	}
	i.usage.Spent, i.usage.NextSequence = next, uint64(next.Requests)+1
	before, err := i.sample(true)
	if err != nil {
		// Only this branch owns proof that its permit has not been consumed.
		if validErasureAuthorizationV2Time(i.last) && !i.last.Before(attempt.ReservedAt()) && validateContext(i.ctx) == nil {
			abandoned, buildErr := NewAttemptResponseEvidence(AttemptResponseOptions{Attempt: attempt, Code: AttemptResponseAbandoned, ObservedAt: i.last})
			if buildErr != nil {
				return resumeObservation{}, ErrErasureUnknownOutcome
			}
			if _, recordErr := i.record(abandoned); recordErr != nil {
				return resumeObservation{}, recordErr
			}
		}
		return resumeObservation{}, err
	}
	deadline := before.Add(30 * time.Second)
	if i.deadline.Before(deadline) {
		deadline = i.deadline
	}
	requestCtx, cancel := context.WithDeadline(i.ctx, deadline)
	defer cancel()
	if requestCtx.Err() != nil {
		return resumeObservation{}, ErrErasureAllowanceExpired
	}
	if !permit.consume(attempt, request) {
		return resumeObservation{}, ErrErasureUnknownOutcome
	}
	// No SQL transaction, callback, generic object call, or KMS crosses dispatch.
	response := AttemptResponseOptions{Attempt: attempt}
	var dispatchErr error
	switch q.kind {
	case AttemptCurrentRead, AttemptIntentRead, AttemptAttestationRead:
		observed, callErr := i.mode.backend.ReadErasureObject(requestCtx, q.key, i.allowance.ExpectedBucketOwner(), q.maximum)
		dispatchErr = callErr
		if callErr == nil {
			response, dispatchErr = i.classifyRead(attempt, q, observed)
		}
		clear(observed.Object.Content)
	case AttemptVersionList:
		page, callErr := i.mode.backend.ListObjectVersions(requestCtx, q.key, i.allowance.ExpectedBucketOwner(), q.cursor, q.limit, q.maximum)
		dispatchErr = callErr
		if callErr == nil {
			if err := validateVersionScan(q.scan, q.key, q.cursor, q.limit, q.maximum, page); err != nil {
				dispatchErr = ErrRemoteObjectIntegrity
			} else {
				response.Code, response.Page, response.ResponseBytes = AttemptResponsePresent, page, page.ResponseBytes
			}
		}
	case AttemptIntentCreate, AttemptFenceCreate, AttemptAttestationCreate:
		created, callErr := i.mode.backend.CreateErasureObject(requestCtx, q.key, i.allowance.ExpectedBucketOwner(), q.body, request.BodyDigest())
		dispatchErr = callErr
		if callErr == nil {
			response.Code = AttemptResponseConditionLost
			if created {
				response.Code = AttemptResponseCreated
			}
		}
	case AttemptVersionDelete:
		deleted, callErr := i.mode.backend.DeleteObjectVersion(requestCtx, q.key, i.allowance.ExpectedBucketOwner(), q.version)
		dispatchErr = callErr
		if callErr == nil {
			switch deleted {
			case VersionDeleteDeleted:
				response.Code = AttemptResponseDeleted
			case VersionDeleteNotFound:
				response.Code = AttemptResponseNotFound
			default:
				dispatchErr = ErrRemoteObjectIntegrity
			}
		}
	default:
		return resumeObservation{}, ErrErasureUnknownOutcome
	}
	// The response timestamp is independent of reservation and outside retries.
	observedAt, clockErr := i.sample(false)
	if clockErr != nil {
		return resumeObservation{}, ErrErasureUnknownOutcome
	}
	if dispatchErr != nil {
		response = AttemptResponseOptions{Attempt: attempt, Code: resumeResponseCode(dispatchErr)}
	}
	response.ObservedAt = observedAt
	evidence, err := NewAttemptResponseEvidence(response)
	if err != nil {
		// Even a valid raw page may overflow the canonical response representation.
		// Drop all partial data and atomically record malformed plus unknown.
		response = AttemptResponseOptions{Attempt: attempt, Code: AttemptResponseMalformed, ObservedAt: observedAt}
		evidence, err = NewAttemptResponseEvidence(response)
		if err != nil {
			return resumeObservation{}, ErrErasureUnknownOutcome
		}
	}
	stored, err := i.record(evidence)
	if err != nil {
		if response.Code == AttemptResponseMalformed || response.Code == AttemptResponseUnavailable || validateContext(i.ctx) != nil {
			return resumeObservation{}, ErrErasureUnknownOutcome
		}
		return resumeObservation{}, err
	}
	switch response.Code {
	case AttemptResponseMalformed, AttemptResponseUnavailable:
		return resumeObservation{}, ErrErasureUnknownOutcome
	case AttemptResponseDenied:
		return resumeObservation{}, ErrErasureBlocked
	case AttemptResponseConflict:
		return resumeObservation{}, ErrErasureConflict
	}
	return resumeObservation{attempt: attempt, evidence: stored, response: response}, nil
}

func (i *resumeInvocation) record(e ErasureEvidence) (ErasureEvidence, error) {
	stored, _, err := i.mode.journal.RecordErasureEvidence(i.ctx, i.ref, e)
	if err != nil {
		return ErasureEvidence{}, resumePublicError(err)
	}
	if stored.Validate() != nil || stored.Ref() != i.ref || stored.Slot() != e.Slot() || stored.Kind() != e.Kind() {
		return ErasureEvidence{}, ErrErasureBindingMismatch
	}
	switch e.Kind() {
	case "unknown":
		if stored.AttemptIdentity() != e.AttemptIdentity() {
			return ErasureEvidence{}, ErrErasureBindingMismatch
		}
	case "fence":
		if !bytes.Equal(stored.RecordBytes(), e.RecordBytes()) {
			return ErasureEvidence{}, ErrErasureConflict
		}
	case "candidate":
		// CAS may choose another valid candidate. Full original closure is loaded
		// before its bytes can be used in an immutable proof request.
		if _, err := ParseErasureAttestationV2(stored.RecordBytes(), i.ref.Scope()); err != nil {
			return ErasureEvidence{}, err
		}
	case "published":
		parents, wanted := stored.ParentIdentities(), e.ParentIdentities()
		if len(parents) != 2 || len(wanted) != 2 || parents[0] != wanted[0] {
			return ErasureEvidence{}, ErrErasureConflict
		}
	default:
		if err := equalProgressEvidence(stored, e); err != nil {
			return ErasureEvidence{}, err
		}
	}
	return stored, nil
}
