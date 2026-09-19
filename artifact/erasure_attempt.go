package artifact

import (
	"fmt"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

// AttemptKind identifies the shape of one erasure request.
type AttemptKind uint8

const (
	AttemptCurrentRead       AttemptKind = 1
	AttemptIntentRead        AttemptKind = 2
	AttemptAttestationRead   AttemptKind = 3
	AttemptVersionList       AttemptKind = 4
	AttemptIntentCreate      AttemptKind = 5
	AttemptFenceCreate       AttemptKind = 6
	AttemptVersionDelete     AttemptKind = 7
	AttemptAttestationCreate AttemptKind = 8
)

func (k AttemptKind) String() string {
	switch k {
	case AttemptCurrentRead:
		return "current_read"
	case AttemptIntentRead:
		return "intent_read"
	case AttemptAttestationRead:
		return "attestation_read"
	case AttemptVersionList:
		return "version_list"
	case AttemptIntentCreate:
		return "intent_create"
	case AttemptFenceCreate:
		return "fence_create"
	case AttemptVersionDelete:
		return "version_delete"
	case AttemptAttestationCreate:
		return "attestation_create"
	default:
		return ""
	}
}

// AttemptRequest is immutable metadata, not authority to dispatch a request.
// Its zero value is invalid.
type AttemptRequest struct {
	identity                      string
	reservationIdentity           string
	namespaceIdentity             string
	artifactIdentity              string
	admissionIdentity             string
	operationIdentity             string
	originalAuthorizationIdentity string
	authorizationDocumentDigest   string
	allowanceIdentity             string
	allowanceDocumentDigest       string
	protectedPolicyIdentity       string
	expectedBucketOwner           string
	key                           string
	versionID                     string
	keyMarker                     string
	versionIDMarker               string
	bodyDigest                    string
	condition                     string
	observationIdentity           string
	scope                         audit.ReviewScope
	kind                          AttemptKind
	versionKind                   ObjectVersionKind
	pageLimit                     uint16
	maximumResponseBytes          uint32
	bodyBytes                     uint32
}

// AttemptRequestOptions describes request metadata and supplied lineage.
type AttemptRequestOptions struct {
	ReservationIdentity             string
	Operation                       ErasureOperation
	Allowance                       ResumeAllowance
	Kind                            AttemptKind
	Key                             ExactObjectKey
	Version                         ObjectVersion
	Cursor                          VersionCursor
	PageLimit                       uint16
	MaximumResponseBytes            uint32
	BodyDigest, ObservationIdentity string
	BodyBytes                       uint32
}

// NewAttemptRequest binds the supplied metadata without checking live authority.
func NewAttemptRequest(options AttemptRequestOptions) (AttemptRequest, error) {
	if len(options.ReservationIdentity) != 64 || len(options.BodyDigest) > 64 || len(options.ObservationIdentity) > 64 ||
		len(options.Cursor.KeyMarker) > 1024 || len(options.Cursor.VersionIDMarker) > 504 ||
		len(options.Key.Key()) == 0 || len(options.Key.Key()) > 1024 || len(options.Key.NamespaceIdentity()) != 64 ||
		len(options.Version.Key()) > 1024 || len(options.Version.VersionID()) > 504 || len(options.Version.NamespaceIdentity()) > 64 {
		return AttemptRequest{}, ErrInvalidErasureContract
	}
	if !validDigest(options.ReservationIdentity) || options.Key.Validate() != nil {
		return AttemptRequest{}, ErrInvalidErasureContract
	}
	if options.Kind != AttemptVersionDelete && options.Version != (ObjectVersion{}) {
		return AttemptRequest{}, ErrInvalidErasureContract
	}
	value := AttemptRequest{
		reservationIdentity: options.ReservationIdentity, kind: options.Kind, key: options.Key.Key(),
		versionKind: options.Version.Kind(), versionID: options.Version.VersionID(),
		keyMarker: options.Cursor.KeyMarker, versionIDMarker: options.Cursor.VersionIDMarker,
		pageLimit: options.PageLimit, maximumResponseBytes: options.MaximumResponseBytes,
		bodyDigest: options.BodyDigest, bodyBytes: options.BodyBytes, observationIdentity: options.ObservationIdentity,
	}
	switch options.Kind {
	case AttemptIntentCreate, AttemptFenceCreate, AttemptAttestationCreate:
		value.condition = "if_none_match_star"
	}
	if err := value.validateKindFields(); err != nil {
		return AttemptRequest{}, err
	}
	if options.Kind == AttemptVersionDelete {
		if err := options.Version.Validate(); err != nil {
			return AttemptRequest{}, err
		}
	}
	if err := options.Operation.Validate(); err != nil {
		return AttemptRequest{}, err
	}
	if err := options.Allowance.Validate(); err != nil {
		return AttemptRequest{}, err
	}
	operation, allowance := options.Operation, options.Allowance
	if operation.Scope() != allowance.Scope() || operation.NamespaceIdentity() != allowance.NamespaceIdentity() ||
		operation.ArtifactIdentity() != allowance.ArtifactIdentity() || operation.AdmissionIdentity() != allowance.AdmissionIdentity() ||
		operation.Identity() != allowance.OperationIdentity() || operation.OriginalAuthorizationIdentity() != allowance.OriginalAuthorizationIdentity() ||
		operation.AuthorizationDocumentDigest() != allowance.AuthorizationDocumentDigest() || options.Key.NamespaceIdentity() != operation.NamespaceIdentity() {
		return AttemptRequest{}, ErrErasureBindingMismatch
	}
	if options.Kind == AttemptVersionDelete &&
		(options.Version.NamespaceIdentity() != options.Key.NamespaceIdentity() || options.Version.Key() != options.Key.Key()) {
		return AttemptRequest{}, ErrErasureBindingMismatch
	}
	if options.Kind == AttemptIntentCreate || options.Kind == AttemptFenceCreate {
		var body []byte
		var err error
		if options.Kind == AttemptIntentCreate {
			body, err = EncodeErasureOperation(operation)
		} else {
			var fence ErasureFence
			fence, err = NewErasureFence(operation)
			if err == nil {
				body, err = EncodeErasureFence(fence)
			}
		}
		if err != nil {
			return AttemptRequest{}, err
		}
		if uint32(len(body)) != options.BodyBytes || hashBytes(body) != options.BodyDigest {
			return AttemptRequest{}, ErrErasureBindingMismatch
		}
	}
	encodedAllowance, err := EncodeResumeAllowance(allowance)
	if err != nil {
		return AttemptRequest{}, err
	}
	value.scope = operation.Scope()
	value.namespaceIdentity = operation.NamespaceIdentity()
	value.artifactIdentity = operation.ArtifactIdentity()
	value.admissionIdentity = operation.AdmissionIdentity()
	value.operationIdentity = operation.Identity()
	value.originalAuthorizationIdentity = operation.OriginalAuthorizationIdentity()
	value.authorizationDocumentDigest = operation.AuthorizationDocumentDigest()
	value.allowanceIdentity = allowance.Identity()
	value.allowanceDocumentDigest = hashBytes(encodedAllowance)
	value.protectedPolicyIdentity = allowance.ProtectedPolicyIdentity()
	value.expectedBucketOwner = allowance.ExpectedBucketOwner()
	if err := value.validateFields(); err != nil {
		return AttemptRequest{}, err
	}
	value, err = value.clone()
	if err != nil {
		return AttemptRequest{}, err
	}
	value.identity = deriveAttemptRequestIdentity(value)
	return value, nil
}

// Validate checks shape and identity, not omitted durable dependencies.
func (r AttemptRequest) Validate() error {
	if err := r.validateFields(); err != nil {
		return err
	}
	if !validDigest(r.identity) {
		return ErrInvalidErasureContract
	}
	if r.identity != deriveAttemptRequestIdentity(r) {
		return ErrErasureIdentityMismatch
	}
	return nil
}

func (r AttemptRequest) validateFields() error {
	if r.scope.Validate() != nil {
		return ErrInvalidErasureContract
	}
	for _, identity := range [...]string{
		r.reservationIdentity, r.namespaceIdentity, r.scope.Identity(), r.artifactIdentity, r.admissionIdentity,
		r.operationIdentity, r.originalAuthorizationIdentity, r.authorizationDocumentDigest,
		r.allowanceIdentity, r.allowanceDocumentDigest, r.protectedPolicyIdentity,
	} {
		if !validDigest(identity) {
			return ErrInvalidErasureContract
		}
	}
	if !validResumeBucketOwner(r.expectedBucketOwner) || !validExactObjectKey(r.key) {
		return ErrInvalidErasureContract
	}
	return r.validateKindFields()
}

func (r AttemptRequest) validateKindFields() error {
	noVersion := r.versionKind == 0 && r.versionID == ""
	noCursor := r.keyMarker == "" && r.versionIDMarker == ""
	noBody := r.bodyDigest == "" && r.bodyBytes == 0 && r.condition == ""
	switch r.kind {
	case AttemptCurrentRead, AttemptIntentRead, AttemptAttestationRead:
		if !noVersion || !noCursor || !noBody || r.pageLimit != 0 || r.observationIdentity != "" ||
			r.maximumResponseBytes < 4096 || r.maximumResponseBytes > 33554432 {
			return ErrInvalidErasureContract
		}
	case AttemptVersionList:
		if !noVersion || !noBody || r.observationIdentity != "" || r.pageLimit < 1 || r.pageLimit > 256 ||
			r.maximumResponseBytes < 4096 || r.maximumResponseBytes > 1048576 ||
			!noCursor && (r.keyMarker != r.key || !validObjectVersionID(r.versionIDMarker)) {
			return ErrInvalidErasureContract
		}
	case AttemptIntentCreate, AttemptFenceCreate, AttemptAttestationCreate:
		if !noVersion || !noCursor || r.pageLimit != 0 || r.maximumResponseBytes != 4096 ||
			!validDigest(r.bodyDigest) || !validDigest(r.observationIdentity) || r.bodyBytes < 1 || r.bodyBytes > 16384 ||
			r.condition != "if_none_match_star" {
			return ErrInvalidErasureContract
		}
	case AttemptVersionDelete:
		if !noCursor || !noBody || r.pageLimit != 0 || r.maximumResponseBytes != 4096 || !validDigest(r.observationIdentity) ||
			(r.versionKind != ObjectVersionData && r.versionKind != ObjectVersionDeleteMarker) || !validObjectVersionID(r.versionID) {
			return ErrInvalidErasureContract
		}
	default:
		return ErrInvalidErasureContract
	}
	return nil
}

func (r AttemptRequest) clone() (AttemptRequest, error) {
	scope, err := audit.NewReviewScope(r.scope.TenantID(), r.scope.RepositoryID(), r.scope.ReviewRunID())
	if err != nil {
		return AttemptRequest{}, ErrInvalidErasureContract
	}
	r.scope = scope
	r.identity = strings.Clone(r.identity)
	r.reservationIdentity = strings.Clone(r.reservationIdentity)
	r.namespaceIdentity = strings.Clone(r.namespaceIdentity)
	r.artifactIdentity = strings.Clone(r.artifactIdentity)
	r.admissionIdentity = strings.Clone(r.admissionIdentity)
	r.operationIdentity = strings.Clone(r.operationIdentity)
	r.originalAuthorizationIdentity = strings.Clone(r.originalAuthorizationIdentity)
	r.authorizationDocumentDigest = strings.Clone(r.authorizationDocumentDigest)
	r.allowanceIdentity = strings.Clone(r.allowanceIdentity)
	r.allowanceDocumentDigest = strings.Clone(r.allowanceDocumentDigest)
	r.protectedPolicyIdentity = strings.Clone(r.protectedPolicyIdentity)
	r.expectedBucketOwner = strings.Clone(r.expectedBucketOwner)
	r.key = strings.Clone(r.key)
	r.versionID = strings.Clone(r.versionID)
	r.keyMarker = strings.Clone(r.keyMarker)
	r.versionIDMarker = strings.Clone(r.versionIDMarker)
	r.bodyDigest = strings.Clone(r.bodyDigest)
	r.condition = strings.Clone(r.condition)
	r.observationIdentity = strings.Clone(r.observationIdentity)
	return r, nil
}

func (r AttemptRequest) Identity() string            { return r.identity }
func (r AttemptRequest) ReservationIdentity() string { return r.reservationIdentity }
func (r AttemptRequest) NamespaceIdentity() string   { return r.namespaceIdentity }
func (r AttemptRequest) ArtifactIdentity() string    { return r.artifactIdentity }
func (r AttemptRequest) AdmissionIdentity() string   { return r.admissionIdentity }
func (r AttemptRequest) OperationIdentity() string   { return r.operationIdentity }
func (r AttemptRequest) OriginalAuthorizationIdentity() string {
	return r.originalAuthorizationIdentity
}
func (r AttemptRequest) AuthorizationDocumentDigest() string { return r.authorizationDocumentDigest }
func (r AttemptRequest) AllowanceIdentity() string           { return r.allowanceIdentity }
func (r AttemptRequest) AllowanceDocumentDigest() string     { return r.allowanceDocumentDigest }
func (r AttemptRequest) ProtectedPolicyIdentity() string     { return r.protectedPolicyIdentity }
func (r AttemptRequest) ExpectedBucketOwner() string         { return r.expectedBucketOwner }
func (r AttemptRequest) Key() string                         { return r.key }
func (r AttemptRequest) VersionID() string                   { return r.versionID }
func (r AttemptRequest) KeyMarker() string                   { return r.keyMarker }
func (r AttemptRequest) VersionIDMarker() string             { return r.versionIDMarker }
func (r AttemptRequest) BodyDigest() string                  { return r.bodyDigest }
func (r AttemptRequest) Condition() string                   { return r.condition }
func (r AttemptRequest) ObservationIdentity() string         { return r.observationIdentity }
func (r AttemptRequest) Scope() audit.ReviewScope            { return r.scope }
func (r AttemptRequest) Kind() AttemptKind                   { return r.kind }
func (r AttemptRequest) VersionKind() ObjectVersionKind      { return r.versionKind }
func (r AttemptRequest) PageLimit() uint16                   { return r.pageLimit }
func (r AttemptRequest) MaximumResponseBytes() uint32        { return r.maximumResponseBytes }
func (r AttemptRequest) BodyBytes() uint32                   { return r.bodyBytes }
func (r AttemptRequest) ScopeIdentity() string               { return r.scope.Identity() }
func (r AttemptRequest) String() string                      { return "artifact erasure attempt request" }
func (r AttemptRequest) GoString() string                    { return "artifact.AttemptRequest{<redacted>}" }
func (r AttemptRequest) Format(state fmt.State, verb rune) {
	formatErasureValue(state, verb, r.String(), r.GoString())
}

// ErasureAttempt is immutable reservation metadata, not a dispatch permit.
// Its zero value is invalid.
type ErasureAttempt struct {
	identity         string
	request          AttemptRequest
	sequence         uint64
	reservedAtMillis int64
}

// NewErasureAttempt binds a request, bounded sequence and exact UTC milliseconds.
func NewErasureAttempt(request AttemptRequest, sequence uint64, at time.Time) (ErasureAttempt, error) {
	if sequence < 1 || sequence > 4096 || !validErasureAuthorizationV2Time(at) {
		return ErasureAttempt{}, ErrInvalidErasureContract
	}
	if err := request.Validate(); err != nil {
		return ErasureAttempt{}, err
	}
	value := ErasureAttempt{request: request, sequence: sequence, reservedAtMillis: at.UnixMilli()}
	value.identity = deriveErasureAttemptIdentity(value)
	return value, nil
}

func (a ErasureAttempt) Validate() error {
	if !validDigest(a.identity) || a.sequence < 1 || a.sequence > 4096 ||
		a.reservedAtMillis <= 0 || a.reservedAtMillis > maxArtifactUnixMilliseconds {
		return ErrInvalidErasureContract
	}
	if err := a.request.Validate(); err != nil {
		return err
	}
	if a.identity != deriveErasureAttemptIdentity(a) {
		return ErrErasureIdentityMismatch
	}
	return nil
}

func (a ErasureAttempt) Identity() string        { return a.identity }
func (a ErasureAttempt) Request() AttemptRequest { return a.request }
func (a ErasureAttempt) Sequence() uint64        { return a.sequence }
func (a ErasureAttempt) ReservedAt() time.Time   { return erasureValueTime(a.reservedAtMillis) }
func (a ErasureAttempt) String() string          { return "artifact erasure attempt" }
func (a ErasureAttempt) GoString() string        { return "artifact.ErasureAttempt{<redacted>}" }
func (a ErasureAttempt) Format(state fmt.State, verb rune) {
	formatErasureValue(state, verb, a.String(), a.GoString())
}
