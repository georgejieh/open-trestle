package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// BindProtectedRuntimePolicy binds a protected template to two local records without approving or contacting either route.
func BindProtectedRuntimePolicy(ctx context.Context, inventoryPath, templatePath, generationAdapterID, verificationAdapterID string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || inventoryPath == "" || templatePath == "" {
		return nil, ErrProtectedConfiguration
	}
	inventoryAbsolute, inventoryErr := filepath.Abs(inventoryPath)
	templateAbsolute, templateErr := filepath.Abs(templatePath)
	if inventoryErr != nil || templateErr != nil || inventoryAbsolute == templateAbsolute {
		return nil, ErrProtectedConfiguration
	}
	opener := func(path string) (protectedConfigurationFile, error) { return fileauthority.OpenReadOnly(path) }
	inventoryBytes, err := readProtectedConfiguration(ctx, inventoryPath, 8<<20, opener)
	if err != nil || !bindingDocumentHasNoNull(inventoryBytes) {
		return nil, ErrProtectedConfiguration
	}
	templateBytes, err := readProtectedConfiguration(ctx, templatePath, 1<<20, opener)
	if err != nil {
		return nil, ErrProtectedConfiguration
	}
	inventory, err := DecodeRouteInventory(ctx, bytes.NewReader(inventoryBytes))
	if err != nil {
		return nil, ErrProtectedConfiguration
	}
	encoded, err := bindRuntimePolicy(ctx, inventory, templateBytes, generationAdapterID, verificationAdapterID)
	if err != nil {
		return nil, ErrProtectedConfiguration
	}
	inventoryAgain, err := readProtectedConfiguration(ctx, inventoryPath, 8<<20, opener)
	if err != nil || !bytes.Equal(inventoryAgain, inventoryBytes) {
		return nil, ErrProtectedConfiguration
	}
	templateAgain, err := readProtectedConfiguration(ctx, templatePath, 1<<20, opener)
	if err != nil || !bytes.Equal(templateAgain, templateBytes) || ctx.Err() != nil {
		return nil, ErrProtectedConfiguration
	}
	return encoded, nil
}

func bindRuntimePolicy(ctx context.Context, inventory RouteInventory, template []byte, generationAdapterID, verificationAdapterID string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || inventory.Validate() != nil || provider.ValidateAdapterID(generationAdapterID) != nil || provider.ValidateAdapterID(verificationAdapterID) != nil || generationAdapterID == verificationAdapterID || len(template) == 0 || len(template) >= 1<<20 || validateUniqueJSONKeys(template) != nil || !bindingDocumentHasNoNull(template) {
		return nil, ErrInvalidRouteInventory
	}
	generation, generationOK := uniqueLocalBindingRecord(inventory, generationAdapterID)
	verification, verificationOK := uniqueLocalBindingRecord(inventory, verificationAdapterID)
	generationID, verificationID := generation.Identity(), verification.Identity()
	if !generationOK || !verificationOK || generationID == verificationID {
		return nil, ErrInvalidRouteInventory
	}
	decoder := json.NewDecoder(bytes.NewReader(template))
	decoder.DisallowUnknownFields()
	var wire runtimePolicyWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || (wire.SchemaVersion != 1 && wire.SchemaVersion != 2 && wire.SchemaVersion != 6) || (wire.SchemaVersion == 1 && wire.VerificationRouteRecordIdentity != nil) || !bindingMatches(wire.InventoryIdentity, inventory.Identity()) || !bindingMatches(wire.PinnedRouteRecordIdentity, generationID) || wire.VerificationRouteRecordIdentity != nil && !bindingMatches(*wire.VerificationRouteRecordIdentity, verificationID) {
		return nil, ErrInvalidRouteInventory
	}
	if validatePolicyCredentialFields(template, wire.SchemaVersion) != nil {
		return nil, ErrInvalidRouteInventory
	}
	if wire.SchemaVersion != 6 {
		wire.SchemaVersion = 2
	}
	wire.InventoryIdentity = inventory.Identity()
	wire.PinnedRouteRecordIdentity = generationID
	wire.VerificationRouteRecordIdentity = &verificationID
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, ErrInvalidRouteInventory
	}
	policy, err := DecodeRuntimePolicy(ctx, bytes.NewReader(encoded), inventory)
	if err != nil || ctx.Err() != nil || gateway.VerifyIndependentRouteRecords(policy.Independence(), generation, verification) != nil {
		return nil, ErrInvalidRouteInventory
	}
	return encoded, nil
}

func uniqueLocalBindingRecord(inventory RouteInventory, adapterID string) (provider.RouteRegistryRecord, bool) {
	var selected provider.RouteRegistryRecord
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		reference := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		if reference.AdapterID() != adapterID {
			continue
		}
		if selected.Identity() != "" || reference.Zone() != provider.ProviderZoneLocal {
			return provider.RouteRegistryRecord{}, false
		}
		selected = record
	}
	return selected, selected.Identity() != ""
}

func bindingMatches(value, expected string) bool {
	return value == "" || value == strings.Repeat("0", 64) || value == expected
}

func bindingDocumentHasNoNull(document []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(document))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return true
		}
		if err != nil || token == nil {
			return false
		}
	}
}
