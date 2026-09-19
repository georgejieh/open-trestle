package artifact

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/erasureauthority"
)

// ResumeBudget holds independent ceilings, not spent counters or effect permits.
// Zero dimensions grant no permission. Only Requests must be positive.
type ResumeBudget struct {
	Requests, Mutations, Reads, Lists, Creates, Deletes, Pages, Versions uint32
	ResponseBytes, ListBytes, WriteBytes                                 uint64
}

// ResumeAllowanceOptions describes metadata, not protected or durable authority.
type ResumeAllowanceOptions struct {
	Operation                                                ErasureOperation
	RecoveryPolicyIdentity, ProtectedPolicyIdentity          string
	PrincipalIdentity, IssuanceIdentity, ExpectedBucketOwner string
	NotBefore, NotAfter                                      time.Time
	Maximum                                                  ResumeBudget
}

// ResumeAllowance is immutable metadata with an invalid zero value. Only a
// protected file load attaches a witness. Neither form is durable acceptance,
// a budget reservation, dispatch permission or evidence of erasure.
type ResumeAllowance struct {
	identity, namespaceIdentity, artifactIdentity, admissionIdentity              string
	operationIdentity, originalAuthorizationIdentity, authorizationDocumentDigest string
	recoveryPolicyIdentity, protectedPolicyIdentity, principalIdentity            string
	issuanceIdentity, expectedBucketOwner                                         string
	scope                                                                         audit.ReviewScope
	notBeforeMillis, notAfterMillis                                               int64
	maximum                                                                       ResumeBudget
	witness                                                                       *resumeAllowanceWitness
}

// Only LoadResumeAllowance constructs this immutable, content-bound witness.
// It retains the protected snapshot, never continuing pathname authority.
type resumeAllowanceWitness struct {
	document                                          erasureauthority.Document
	documentDigest, allowanceIdentity, policyIdentity string
}

// NewResumeAllowance derives original bindings from the validated operation.
// Parsed operation metadata is valid input, but does not prove DB acceptance.
func NewResumeAllowance(options ResumeAllowanceOptions) (ResumeAllowance, error) {
	if err := options.Operation.Validate(); err != nil {
		return ResumeAllowance{}, err
	}
	if !validErasureAuthorizationV2Time(options.NotBefore) || !validErasureAuthorizationV2Time(options.NotAfter) {
		return ResumeAllowance{}, ErrInvalidErasureContract
	}
	operation := options.Operation
	value := ResumeAllowance{
		scope: operation.Scope(), namespaceIdentity: operation.NamespaceIdentity(),
		artifactIdentity: operation.ArtifactIdentity(), admissionIdentity: operation.AdmissionIdentity(),
		operationIdentity: operation.Identity(), originalAuthorizationIdentity: operation.OriginalAuthorizationIdentity(),
		authorizationDocumentDigest: operation.AuthorizationDocumentDigest(),
		recoveryPolicyIdentity:      options.RecoveryPolicyIdentity, protectedPolicyIdentity: options.ProtectedPolicyIdentity,
		principalIdentity: options.PrincipalIdentity, issuanceIdentity: options.IssuanceIdentity,
		expectedBucketOwner: options.ExpectedBucketOwner, maximum: options.Maximum,
		notBeforeMillis: options.NotBefore.UnixMilli(), notAfterMillis: options.NotAfter.UnixMilli(),
	}
	if err := value.validateFields(); err != nil {
		return ResumeAllowance{}, err
	}
	// Clone only bounded, validated strings. ReviewScope clones its components.
	scope, err := audit.NewReviewScope(value.scope.TenantID(), value.scope.RepositoryID(), value.scope.ReviewRunID())
	if err != nil {
		return ResumeAllowance{}, ErrInvalidErasureContract
	}
	value.scope = scope
	value.namespaceIdentity = strings.Clone(value.namespaceIdentity)
	value.artifactIdentity = strings.Clone(value.artifactIdentity)
	value.admissionIdentity = strings.Clone(value.admissionIdentity)
	value.operationIdentity = strings.Clone(value.operationIdentity)
	value.originalAuthorizationIdentity = strings.Clone(value.originalAuthorizationIdentity)
	value.authorizationDocumentDigest = strings.Clone(value.authorizationDocumentDigest)
	value.recoveryPolicyIdentity = strings.Clone(value.recoveryPolicyIdentity)
	value.protectedPolicyIdentity = strings.Clone(value.protectedPolicyIdentity)
	value.principalIdentity = strings.Clone(value.principalIdentity)
	value.issuanceIdentity = strings.Clone(value.issuanceIdentity)
	value.expectedBucketOwner = strings.Clone(value.expectedBucketOwner)
	value.identity = deriveResumeAllowanceIdentity(value)
	return value, nil
}

// Validate checks shape and content identity without loading authority or time.
func (a ResumeAllowance) Validate() error {
	if err := a.validateFields(); err != nil {
		return err
	}
	if !validDigest(a.identity) {
		return ErrInvalidErasureContract
	}
	if a.identity != deriveResumeAllowanceIdentity(a) {
		return ErrErasureIdentityMismatch
	}
	return nil
}

func (a ResumeAllowance) validateFields() error {
	if a.scope.Validate() != nil {
		return ErrInvalidErasureContract
	}
	for _, identity := range [...]string{
		a.namespaceIdentity, a.scope.Identity(), a.artifactIdentity, a.admissionIdentity,
		a.operationIdentity, a.originalAuthorizationIdentity, a.authorizationDocumentDigest,
		a.recoveryPolicyIdentity, a.protectedPolicyIdentity, a.principalIdentity, a.issuanceIdentity,
	} {
		if !validDigest(identity) {
			return ErrInvalidErasureContract
		}
	}
	if !validResumeBucketOwner(a.expectedBucketOwner) || !validResumeMaximum(a.maximum) {
		return ErrInvalidErasureContract
	}
	// Bound both integers before subtraction. Do not multiply untrusted times.
	if a.notBeforeMillis <= 0 || a.notBeforeMillis > maxArtifactUnixMilliseconds ||
		a.notAfterMillis <= 0 || a.notAfterMillis > maxArtifactUnixMilliseconds ||
		a.notAfterMillis <= a.notBeforeMillis || a.notAfterMillis-a.notBeforeMillis > 900000 {
		return ErrInvalidErasureContract
	}
	return nil
}

func validResumeMaximum(b ResumeBudget) bool {
	// No sum or inferred permission rule couples these independent ceilings.
	return b.Requests >= 1 && b.Requests <= 4096 && b.Mutations <= 2048 && b.Mutations <= b.Requests &&
		b.Reads <= 2048 && b.Lists <= 1024 && b.Creates <= 128 && b.Deletes <= 2048 &&
		b.Pages <= 1024 && b.Versions <= 262144 && b.ResponseBytes <= 1073741824 &&
		b.ListBytes <= 67108864 && b.WriteBytes <= 2097152
}

func validResumeBucketOwner(owner string) bool {
	if len(owner) != 12 {
		return false
	}
	nonzero := false
	for i := 0; i < len(owner); i++ {
		if owner[i] < '0' || owner[i] > '9' {
			return false
		}
		nonzero = nonzero || owner[i] != '0'
	}
	return nonzero
}

// AllowsOperation is a metadata/time predicate, also for parsed values. Current
// policy activity, original-winner/principal checks, durable budgets and provider
// state are separate obligations. Original authorization expiry is not reapplied.
func (a ResumeAllowance) AllowsOperation(operation ErasureOperation, at time.Time) bool {
	if a.Validate() != nil || operation.Validate() != nil || !validErasureAuthorizationV2Time(at) ||
		a.scope != operation.Scope() || a.namespaceIdentity != operation.NamespaceIdentity() ||
		a.artifactIdentity != operation.ArtifactIdentity() || a.admissionIdentity != operation.AdmissionIdentity() ||
		a.operationIdentity != operation.Identity() || a.originalAuthorizationIdentity != operation.OriginalAuthorizationIdentity() ||
		a.authorizationDocumentDigest != operation.AuthorizationDocumentDigest() {
		return false
	}
	milliseconds := at.UnixMilli()
	return milliseconds >= a.notBeforeMillis && milliseconds < a.notAfterMillis && !at.Before(operation.PreparedAt())
}

// LoadResumeAllowance loads a protected snapshot using the caller's full scope.
// Scope is binding input, not authority. No clock, DB or provider is consulted.
func LoadResumeAllowance(ctx context.Context, path string, policy ProtectedErasurePolicy, scope audit.ReviewScope) (ResumeAllowance, error) {
	if ctx == nil || ctx.Err() != nil {
		return ResumeAllowance{}, ErrErasureAuthorityRequired
	}
	if scope.Validate() != nil {
		return ResumeAllowance{}, ErrInvalidErasureContract
	}
	if policy.Validate() != nil {
		return ResumeAllowance{}, ErrErasureAuthorityRequired
	}
	document, err := erasureauthority.LoadDocument(ctx, path)
	if err != nil {
		return ResumeAllowance{}, ErrErasureAuthorityRequired
	}
	encoded := document.Bytes()
	// The accepted raw Document bound is 16 KiB; allowance decoding is 4 KiB.
	if len(encoded) > maxEncodedResumeAllowanceBytes {
		return ResumeAllowance{}, ErrInvalidErasureContract
	}
	value, err := ParseResumeAllowance(encoded, scope)
	if err != nil {
		return ResumeAllowance{}, err
	}
	if !value.matchesProtectedPolicy(policy) {
		return ResumeAllowance{}, ErrErasureBindingMismatch
	}
	value.witness = &resumeAllowanceWitness{
		document: document, documentDigest: document.Digest(),
		allowanceIdentity: value.identity, policyIdentity: policy.Identity(),
	}
	if ctx.Err() != nil {
		return ResumeAllowance{}, ErrErasureAuthorityRequired
	}
	return value, nil
}

func (a ResumeAllowance) matchesProtectedPolicy(policy ProtectedErasurePolicy) bool {
	return a.namespaceIdentity == policy.NamespaceIdentity() && a.recoveryPolicyIdentity == policy.RecoveryPolicyIdentity() &&
		a.protectedPolicyIdentity == policy.Identity() && policy.BackendKind() == "aws_s3_general_purpose" &&
		policy.NamespaceMode() == "protected_new_nonnull" && policy.Protocol() == erasureOperationProtocol &&
		policy.Ownership() == erasureAuthorizationV2Ownership
}

// ValidateProtected checks an existing witness and exact policy binding. It does
// not open files, sample time, refresh authority or establish durable acceptance.
func (a ResumeAllowance) ValidateProtected(policy ProtectedErasurePolicy) error {
	if a.witness == nil || policy.Validate() != nil || a.witness.document.Validate() != nil {
		return ErrErasureAuthorityRequired
	}
	if a.witness.policyIdentity != policy.Identity() || !a.matchesProtectedPolicy(policy) {
		return ErrErasureBindingMismatch
	}
	encoded, err := EncodeResumeAllowance(a)
	if err != nil || a.witness.allowanceIdentity != a.identity ||
		a.witness.documentDigest != a.witness.document.Digest() ||
		!bytes.Equal(encoded, a.witness.document.Bytes()) {
		return ErrErasureBindingMismatch
	}
	return nil
}

func (a ResumeAllowance) Identity() string          { return a.identity }
func (a ResumeAllowance) Scope() audit.ReviewScope  { return a.scope }
func (a ResumeAllowance) NamespaceIdentity() string { return a.namespaceIdentity }
func (a ResumeAllowance) ArtifactIdentity() string  { return a.artifactIdentity }
func (a ResumeAllowance) AdmissionIdentity() string { return a.admissionIdentity }
func (a ResumeAllowance) OperationIdentity() string { return a.operationIdentity }
func (a ResumeAllowance) OriginalAuthorizationIdentity() string {
	return a.originalAuthorizationIdentity
}
func (a ResumeAllowance) AuthorizationDocumentDigest() string { return a.authorizationDocumentDigest }
func (a ResumeAllowance) RecoveryPolicyIdentity() string      { return a.recoveryPolicyIdentity }
func (a ResumeAllowance) ProtectedPolicyIdentity() string     { return a.protectedPolicyIdentity }
func (a ResumeAllowance) PrincipalIdentity() string           { return a.principalIdentity }
func (a ResumeAllowance) IssuanceIdentity() string            { return a.issuanceIdentity }
func (a ResumeAllowance) ExpectedBucketOwner() string         { return a.expectedBucketOwner }
func (a ResumeAllowance) NotBefore() time.Time                { return erasureValueTime(a.notBeforeMillis) }
func (a ResumeAllowance) NotAfter() time.Time                 { return erasureValueTime(a.notAfterMillis) }
func (a ResumeAllowance) Maximum() ResumeBudget               { return a.maximum }

func (a ResumeAllowance) ProtectedDocumentDigest() string {
	if a.witness == nil {
		return ""
	}
	return a.witness.documentDigest
}

func (a ResumeAllowance) String() string   { return "artifact erasure resume allowance" }
func (a ResumeAllowance) GoString() string { return "artifact.ResumeAllowance{<redacted>}" }
func (a ResumeAllowance) Format(state fmt.State, verb rune) {
	formatErasureValue(state, verb, a.String(), a.GoString())
}
