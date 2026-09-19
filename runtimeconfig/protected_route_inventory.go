package runtimeconfig

import (
	"bytes"
	"context"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// LoadProtectedRouteInventory reads one explicit protected route inventory. No
// credential lookup, environment fallback, remote access, or policy validation
// occurs here.
func LoadProtectedRouteInventory(ctx context.Context, path string) (RouteInventory, error) {
	fail := func() (RouteInventory, error) {
		return RouteInventory{}, ErrProtectedConfiguration
	}
	if ctx == nil || ctx.Err() != nil || path == "" {
		return fail()
	}
	opener := func(path string) (protectedConfigurationFile, error) { return fileauthority.OpenReadOnly(path) }
	inventoryBytes, err := readProtectedConfiguration(ctx, path, 8<<20, opener)
	if err != nil {
		return fail()
	}
	inventory, err := DecodeRouteInventory(ctx, bytes.NewReader(inventoryBytes))
	if err != nil || ctx.Err() != nil {
		return fail()
	}
	inventoryAgain, err := readProtectedConfiguration(ctx, path, 8<<20, opener)
	if err != nil || !bytes.Equal(inventoryAgain, inventoryBytes) || ctx.Err() != nil {
		return fail()
	}
	return inventory, nil
}
