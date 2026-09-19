package runtimeconfig

import (
	"bytes"
	"context"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/review"
)

// LoadProtectedInvestigationPolicy reads immutable, explicitly selected host policy.
func LoadProtectedInvestigationPolicy(ctx context.Context, path string) (review.InvestigationPolicy, error) {
	return loadProtectedInvestigationPolicy(ctx, path, func(name string) (protectedConfigurationFile, error) {
		return fileauthority.OpenReadOnly(name)
	})
}

func loadProtectedInvestigationPolicy(ctx context.Context, path string, opener func(string) (protectedConfigurationFile, error)) (review.InvestigationPolicy, error) {
	if ctx == nil || ctx.Err() != nil || path == "" {
		return review.InvestigationPolicy{}, ErrProtectedConfiguration
	}
	encoded, err := readProtectedConfiguration(ctx, path, 4096, opener)
	if err != nil {
		return review.InvestigationPolicy{}, ErrProtectedConfiguration
	}
	value, err := review.ParseInvestigationPolicy(encoded)
	if err != nil || ctx.Err() != nil {
		return review.InvestigationPolicy{}, ErrProtectedConfiguration
	}
	again, err := readProtectedConfiguration(ctx, path, 4096, opener)
	if err != nil || !bytes.Equal(encoded, again) || ctx.Err() != nil {
		return review.InvestigationPolicy{}, ErrProtectedConfiguration
	}
	return value, nil
}
