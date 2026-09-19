package provider

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidContentLoggingMode identifies an unknown route logging declaration.
	ErrInvalidContentLoggingMode = errors.New("invalid content logging mode")
)

// ContentLoggingMode declares whether a provider route may retain request or response content in logs.
type ContentLoggingMode uint8

const (
	ContentLoggingDisabled ContentLoggingMode = iota + 1
	ContentLoggingEnabled
	ContentLoggingUnknown
)

// String returns the stable logging mode token or an empty string for unknown values.
func (m ContentLoggingMode) String() string {
	switch m {
	case ContentLoggingDisabled:
		return "disabled"
	case ContentLoggingEnabled:
		return "enabled"
	case ContentLoggingUnknown:
		return "unknown"
	default:
		return ""
	}
}

// ParseContentLoggingMode parses one exact stable logging mode token.
func ParseContentLoggingMode(value string) (ContentLoggingMode, error) {
	switch value {
	case "disabled":
		return ContentLoggingDisabled, nil
	case "enabled":
		return ContentLoggingEnabled, nil
	case "unknown":
		return ContentLoggingUnknown, nil
	default:
		return 0, fmt.Errorf("parse content logging mode: %w", ErrInvalidContentLoggingMode)
	}
}

// Validate verifies that the logging mode is known.
func (m ContentLoggingMode) Validate() error {
	if m.String() == "" {
		return fmt.Errorf("validate content logging mode: %w", ErrInvalidContentLoggingMode)
	}
	return nil
}
