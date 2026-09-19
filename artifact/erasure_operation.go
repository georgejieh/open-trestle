package artifact

import (
	"fmt"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

const erasureOperationProtocol = "same-key-fence-v2"

// ErasureOperationRef is an immutable full-scope reference, not an effect permit.
// Its zero value is invalid.
type ErasureOperationRef struct {
	scope                                audit.ReviewScope
	namespaceIdentity, operationIdentity string
}

func NewErasureOperationRef(scope audit.ReviewScope, namespaceIdentity, operationIdentity string) (ErasureOperationRef, error) {
	if scope.Validate() != nil || !validDigest(namespaceIdentity) || !validDigest(operationIdentity) {
		return ErasureOperationRef{}, ErrInvalidErasureContract
	}
	return ErasureOperationRef{
		scope: scope, namespaceIdentity: strings.Clone(namespaceIdentity), operationIdentity: strings.Clone(operationIdentity),
	}, nil
}

func (r ErasureOperationRef) Validate() error {
	if r.scope.Validate() != nil || !validDigest(r.namespaceIdentity) || !validDigest(r.operationIdentity) {
		return ErrInvalidErasureContract
	}
	return nil
}

func (r ErasureOperationRef) Scope() audit.ReviewScope  { return r.scope }
func (r ErasureOperationRef) NamespaceIdentity() string { return r.namespaceIdentity }
func (r ErasureOperationRef) OperationIdentity() string { return r.operationIdentity }
func (r ErasureOperationRef) String() string            { return "artifact erasure operation reference" }
func (r ErasureOperationRef) GoString() string          { return "artifact.ErasureOperationRef{<redacted>}" }
func (r ErasureOperationRef) Format(state fmt.State, verb rune) {
	formatErasureValue(state, verb, r.String(), r.GoString())
}

// ErasureOperation is immutable candidate or historical metadata. Neither form
// carries a protected witness, durable acceptance, dispatch permission or proof
// of erasure. Its zero value is invalid.
type ErasureOperation struct {
	identity, namespaceIdentity, artifactIdentity, admissionIdentity string
	originalAuthorizationIdentity, authorizationDocumentDigest       string
	policyIdentity, protectedPolicyIdentity, ownership               string
	erasureProtocol, legacyReceiptIdentity                           string
	scope                                                            audit.ReviewScope
	preparedAtMillis                                                 int64
}

// NewErasureOperationCandidate checks protected bindings and both active-time
// predicates at the supplied instant. The resulting metadata still requires
// separate durable acceptance before any effect can be considered.
func NewErasureOperationCandidate(authorization ErasureAuthorizationV2, admission ArtifactAdmission, policy ProtectedErasurePolicy, at time.Time) (ErasureOperation, error) {
	if err := authorization.ValidateProtected(policy); err != nil {
		return ErasureOperation{}, err
	}
	if admission.Validate() != nil {
		return ErasureOperation{}, ErrInvalidErasureContract
	}
	// This validator bounds calendar, UTC offset and precision before UnixMilli.
	if !validErasureAuthorizationV2Time(at) {
		return ErasureOperation{}, ErrInvalidErasureContract
	}
	if !policy.AllowsAt(at) || !authorization.AllowsAdmission(admission, at) {
		return ErasureOperation{}, ErrErasureBindingMismatch
	}
	value := ErasureOperation{
		scope: admission.Scope(), namespaceIdentity: admission.NamespaceIdentity(),
		artifactIdentity: admission.ArtifactIdentity(), admissionIdentity: admission.Identity(),
		originalAuthorizationIdentity: authorization.Identity(), authorizationDocumentDigest: authorization.ProtectedDocumentDigest(),
		policyIdentity: authorization.PolicyIdentity(), protectedPolicyIdentity: policy.Identity(),
		ownership: authorization.Ownership(), preparedAtMillis: at.UnixMilli(),
		erasureProtocol: policy.Protocol(), legacyReceiptIdentity: authorization.LegacyReceiptIdentity(),
	}
	if err := value.validateFields(); err != nil {
		return ErasureOperation{}, err
	}
	value.identity = deriveErasureOperationIdentity(value)
	return value, nil
}

// Validate checks shape and content identity only. It does not load authority,
// sample time, check a database or infer permission from a parsed shape.
func (o ErasureOperation) Validate() error {
	if err := o.validateFields(); err != nil {
		return err
	}
	if !validDigest(o.identity) {
		return ErrInvalidErasureContract
	}
	if o.identity != deriveErasureOperationIdentity(o) {
		return ErrErasureIdentityMismatch
	}
	return nil
}

func (o ErasureOperation) validateFields() error {
	if o.scope.Validate() != nil {
		return ErrInvalidErasureContract
	}
	for _, identity := range [...]string{
		o.namespaceIdentity, o.scope.Identity(), o.artifactIdentity, o.admissionIdentity,
		o.originalAuthorizationIdentity, o.authorizationDocumentDigest, o.policyIdentity, o.protectedPolicyIdentity,
	} {
		if !validDigest(identity) {
			return ErrInvalidErasureContract
		}
	}
	if o.ownership != erasureAuthorizationV2Ownership || o.erasureProtocol != erasureOperationProtocol ||
		o.legacyReceiptIdentity != "" && !validDigest(o.legacyReceiptIdentity) ||
		o.preparedAtMillis <= 0 || o.preparedAtMillis > maxArtifactUnixMilliseconds {
		return ErrInvalidErasureContract
	}
	return nil
}

func (o ErasureOperation) Identity() string          { return o.identity }
func (o ErasureOperation) Scope() audit.ReviewScope  { return o.scope }
func (o ErasureOperation) NamespaceIdentity() string { return o.namespaceIdentity }
func (o ErasureOperation) ArtifactIdentity() string  { return o.artifactIdentity }
func (o ErasureOperation) AdmissionIdentity() string { return o.admissionIdentity }
func (o ErasureOperation) OriginalAuthorizationIdentity() string {
	return o.originalAuthorizationIdentity
}
func (o ErasureOperation) AuthorizationDocumentDigest() string { return o.authorizationDocumentDigest }
func (o ErasureOperation) PolicyIdentity() string              { return o.policyIdentity }
func (o ErasureOperation) ProtectedPolicyIdentity() string     { return o.protectedPolicyIdentity }
func (o ErasureOperation) Ownership() string                   { return o.ownership }
func (o ErasureOperation) PreparedAt() time.Time               { return erasureValueTime(o.preparedAtMillis) }
func (o ErasureOperation) ErasureProtocol() string             { return o.erasureProtocol }
func (o ErasureOperation) LegacyReceiptIdentity() string       { return o.legacyReceiptIdentity }
func (o ErasureOperation) Ref() ErasureOperationRef {
	if o.Validate() != nil {
		return ErasureOperationRef{}
	}
	return ErasureOperationRef{scope: o.scope, namespaceIdentity: o.namespaceIdentity, operationIdentity: o.identity}
}
func (o ErasureOperation) String() string   { return "artifact erasure operation" }
func (o ErasureOperation) GoString() string { return "artifact.ErasureOperation{<redacted>}" }
func (o ErasureOperation) Format(state fmt.State, verb rune) {
	formatErasureValue(state, verb, o.String(), o.GoString())
}

// ErasureFence is immutable content, not backend state, permission to Create,
// durable acceptance or erasure proof. Its zero value is invalid.
type ErasureFence struct {
	identity, erasureProtocol, namespaceIdentity, scopeIdentity string
	artifactIdentity, operationIdentity                         string
	preparedAtMillis                                            int64
}

// NewErasureFence projects a valid operation shape into content-only metadata.
// No payload, raw scope, document or protected witness is copied.
func NewErasureFence(operation ErasureOperation) (ErasureFence, error) {
	if err := operation.Validate(); err != nil {
		return ErasureFence{}, err
	}
	value := ErasureFence{
		erasureProtocol: operation.erasureProtocol, namespaceIdentity: operation.namespaceIdentity,
		scopeIdentity: operation.scope.Identity(), artifactIdentity: operation.artifactIdentity,
		operationIdentity: operation.identity, preparedAtMillis: operation.preparedAtMillis,
	}
	value.identity = deriveErasureFenceIdentity(value)
	return value, nil
}

// Validate checks content shape and identity without any live-state predicate.
func (f ErasureFence) Validate() error {
	for _, identity := range [...]string{f.identity, f.namespaceIdentity, f.scopeIdentity, f.artifactIdentity, f.operationIdentity} {
		if !validDigest(identity) {
			return ErrInvalidErasureContract
		}
	}
	if f.erasureProtocol != erasureOperationProtocol || f.preparedAtMillis <= 0 || f.preparedAtMillis > maxArtifactUnixMilliseconds {
		return ErrInvalidErasureContract
	}
	if f.identity != deriveErasureFenceIdentity(f) {
		return ErrErasureIdentityMismatch
	}
	return nil
}

func (f ErasureFence) Identity() string          { return f.identity }
func (f ErasureFence) ErasureProtocol() string   { return f.erasureProtocol }
func (f ErasureFence) NamespaceIdentity() string { return f.namespaceIdentity }
func (f ErasureFence) ScopeIdentity() string     { return f.scopeIdentity }
func (f ErasureFence) ArtifactIdentity() string  { return f.artifactIdentity }
func (f ErasureFence) OperationIdentity() string { return f.operationIdentity }
func (f ErasureFence) PreparedAt() time.Time     { return erasureValueTime(f.preparedAtMillis) }
func (f ErasureFence) String() string            { return "artifact erasure fence" }
func (f ErasureFence) GoString() string          { return "artifact.ErasureFence{<redacted>}" }
func (f ErasureFence) Format(state fmt.State, verb rune) {
	formatErasureValue(state, verb, f.String(), f.GoString())
}
