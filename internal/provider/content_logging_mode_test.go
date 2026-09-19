package provider

import (
	"errors"
	"testing"
)

func TestContentLoggingModeRoundTrips(t *testing.T) {
	modes := []struct {
		mode ContentLoggingMode
		name string
	}{
		{ContentLoggingDisabled, "disabled"},
		{ContentLoggingEnabled, "enabled"},
		{ContentLoggingUnknown, "unknown"},
	}
	for _, test := range modes {
		parsed, err := ParseContentLoggingMode(test.name)
		if err != nil || parsed != test.mode || parsed.String() != test.name || parsed.Validate() != nil {
			t.Fatalf("mode %q round trip = (%v, %v, %q)", test.name, parsed, err, parsed.String())
		}
	}
}

func TestParseContentLoggingModeRejectsUnknownTokens(t *testing.T) {
	for _, value := range []string{"", "disabled ", " enabled", "ENABLED", "possible", "true"} {
		mode, err := ParseContentLoggingMode(value)
		if !errors.Is(err, ErrInvalidContentLoggingMode) || mode != 0 {
			t.Fatalf("ParseContentLoggingMode(%q) = (%v, %v)", value, mode, err)
		}
	}
}

func TestContentLoggingModeForgedValuesFailValidation(t *testing.T) {
	for _, mode := range []ContentLoggingMode{0, 99} {
		if err := mode.Validate(); !errors.Is(err, ErrInvalidContentLoggingMode) {
			t.Fatalf("ContentLoggingMode(%d).Validate() = %v", mode, err)
		}
		if mode.String() != "" {
			t.Fatalf("ContentLoggingMode(%d).String() = %q", mode, mode.String())
		}
	}
}
