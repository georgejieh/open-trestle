package review

import (
	"context"
	"errors"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

var (
	ErrPublicationAttemptGuardConflict    = errors.New("publication attempt guard conflict")
	ErrPublicationAttemptGuardUnavailable = errors.New("publication attempt guard unavailable")
)

// PublicationAttemptGuard durably permits at most one external dispatch for an authorized attempt.
type PublicationAttemptGuard interface {
	Identity() string
	IdempotencyGuarantee() PublisherIdempotencyGuarantee
	ClaimPublicationAttempt(context.Context, audit.ReviewScope, string, string, string, time.Time) (bool, error)
	CompletePublicationAttempt(context.Context, audit.ReviewScope, string, string, time.Time) error
}
