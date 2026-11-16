package artifact

import (
	"context"
	"errors"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

var ErrInvalidTaskHandler = errors.New("invalid artifact-validating task handler")

// Reader retrieves one exact scoped artifact.
type Reader interface {
	Get(context.Context, audit.ReviewScope, string, time.Time) (Artifact, error)
}

// Clock supplies artifact retention evaluation time.
type Clock interface{ Now() time.Time }
