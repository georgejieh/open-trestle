package gateway

import (
	"errors"

	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrRouteContentLoggingNotAllowed identifies a route whose effective logging mode does not meet request policy.
	ErrRouteContentLoggingNotAllowed = errors.New("route content logging is not allowed by provider data constraints")
)

// CheckRouteContentLogging compares a declared route logging mode with request policy.
// It does not establish provider behavior, registry approval, or dispatch authority.
func CheckRouteContentLogging(input ReviewRoutingInput, mode provider.ContentLoggingMode) error {
	if err := input.Validate(); err != nil {
		return err
	}
	if err := mode.Validate(); err != nil {
		return err
	}
	if !input.ProviderDataConstraints().ContentLoggingAllowed() && mode != provider.ContentLoggingDisabled {
		return ErrRouteContentLoggingNotAllowed
	}
	return nil
}
