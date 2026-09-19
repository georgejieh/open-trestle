package artifact

import (
	"context"
	"errors"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

// Fixed errors disclose no database, object, policy, or credential data.
var (
	ErrErasureAdmissionMissing         = errors.New("erasure admission missing")
	ErrErasureAuthorizationV2Required  = errors.New("erasure authorization v2 required")
	ErrErasureBackendUnsupported       = errors.New("erasure backend unsupported")
	ErrErasureCertificationAPIRequired = errors.New("erasure certification API required")
	ErrErasureConflict                 = errors.New("erasure conflict")
	ErrErasureConformanceV2Required    = errors.New("erasure conformance v2 required")
	ErrErasureJournalRequired          = errors.New("erasure journal required")
	ErrErasureJournalUnavailable       = errors.New("erasure journal unavailable")
	ErrErasureNamespaceUnsupported     = errors.New("erasure namespace unsupported")
	ErrErasureUnknownOutcome           = errors.New("erasure outcome unknown")
)

// artifact; new declarations only. All methods of this journal are DATABASE ONLY.
type AdmissionPreparationJournal interface {
	DatabaseAuthorityIdentity() string
	AdmitArtifact(context.Context, ArtifactAdmission) (ArtifactAdmission, bool, error)
	ReadAdmission(context.Context, audit.ReviewScope, string, string) (ArtifactAdmission, bool, error)
	// CheckAdmissionReadable requires the exact admission and no preparation in one read snapshot.
	CheckAdmissionReadable(context.Context, ArtifactAdmission) error
	ConfirmAdmission(context.Context, ArtifactAdmission, string, string, time.Time) error
	AcceptErasure(context.Context, ErasureAuthorizationV2, time.Time) (ErasureOperation, bool, error)
	ReadPreparedErasure(context.Context, ErasureOperationRef) (ErasureOperation, bool, error)
	FindPreparedErasure(context.Context, audit.ReviewScope, string, string) (ErasureOperation, bool, error)
}

// ReadAdmission/FindPrepared strings: namespace identity, artifact identity.
// Confirm strings: existing "version:" token, SHA256 of exact ciphertext object bytes.
type AdmissionPreparationStore interface {
	Store
	ReadAdmission(context.Context, audit.ReviewScope, string, string) (ArtifactAdmission, bool, error)
	PrepareErasure(context.Context, ErasureAuthorizationV2, time.Time) (ErasureOperation, error)
	ReadPreparedErasure(context.Context, ErasureOperationRef) (ErasureOperation, bool, error)
	FindPreparedErasure(context.Context, audit.ReviewScope, string, string) (ErasureOperation, bool, error)
}
type ErasureClock interface{ Now() time.Time }
type ConfiguredObjectBackend interface {
	RemoteObjectBackend
	ConfigurationIdentity() string
	Validate() error
}
type EnvelopeAdmissionPreparationOptions struct {
	Backend ConfiguredObjectBackend
	Keys    EnvelopeKeyProvider
	Journal AdmissionPreparationJournal
	Policy  ProtectedErasurePolicy
	Clock   ErasureClock
}

// These interfaces describe the admission/preparation subset only. Preparation
// reserves database state; it does not certify erasure or fence a delayed upload.
var _ AdmissionPreparationStore = (*EnvelopeStore)(nil)
