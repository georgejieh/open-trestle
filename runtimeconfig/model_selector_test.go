package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func selectorInventoryDocument(t *testing.T, model, version string) []byte {
	t.Helper()
	var wire routeInventoryWire
	if err := json.Unmarshal(encodedInventory(t), &wire); err != nil {
		t.Fatal(err)
	}
	wire.Routes[0].ModelID, wire.Routes[0].ModelVersion = model, version
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestDecodeInventoryPreservesExactTaggedModelSelectorsAndIdentity(t *testing.T) {
	for _, selector := range []string{"qwen2.5-coder:7b", "library/llama3.2:3b", "org/Model:exact-q4", "provider/model:free", "evil.example:443", "127.0.0.1:8080", "https:evil.example"} {
		t.Run(selector, func(t *testing.T) {
			document := selectorInventoryDocument(t, selector, "")
			inventory, err := DecodeRouteInventory(context.Background(), bytes.NewReader(document))
			if err != nil || inventory.Validate() != nil || len(inventory.Candidates()) != 1 {
				t.Fatalf("inventory rejected selector: %v", err)
			}
			record := inventory.Candidates()[0].ResolvedRecord().RouteRegistryRecord()
			route := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
			if route.ModelID() != selector || route.ModelVersion() != "" || record.Validate() != nil {
				t.Fatal("inventory changed selector")
			}
			again, err := DecodeRouteInventory(context.Background(), bytes.NewReader(document))
			if err != nil || again.Identity() != inventory.Identity() || again.Candidates()[0].ResolvedRecord().RouteRegistryRecord().Identity() != record.Identity() {
				t.Fatal("same exact selector changed identity")
			}
			changed, err := DecodeRouteInventory(context.Background(), bytes.NewReader(selectorInventoryDocument(t, selector+"x", "")))
			if err != nil || changed.Validate() != nil || changed.Identity() == inventory.Identity() || changed.Candidates()[0].ResolvedRecord().RouteRegistryRecord().Identity() == record.Identity() {
				t.Fatal("tag change did not change record and inventory identities")
			}
			policyDocument := runtimePolicyDocument(t, inventory)
			policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyDocument), inventory)
			if err != nil || policy.ValidateAgainstInventory(inventory) != nil {
				t.Fatalf("exact inventory policy binding failed: %v", err)
			}
			if _, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyDocument), changed); err == nil || policy.ValidateAgainstInventory(changed) == nil {
				t.Fatal("stale policy authorized changed tag")
			}
			if _, err := DecodeRouteInventory(context.Background(), bytes.NewReader(selectorInventoryDocument(t, selector, "Version"))); err == nil {
				t.Fatal("inventory accepted tagged model and conflicting version")
			}
		})
	}
}

func TestTaggedSelectorExtensionKeepsOldInventoryAndPolicyFixtures(t *testing.T) {
	inventory, err := DecodeRouteInventory(context.Background(), bytes.NewReader(encodedInventory(t)))
	if err != nil || inventory.Validate() != nil {
		t.Fatalf("old inventory failed: %v", err)
	}
	route := inventory.Candidates()[0].ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
	if route.ModelID() != "model-a" || route.ModelVersion() != "2026-01" {
		t.Fatal("old model/version pair changed")
	}
	// Reuse the independently authored historical fixture and its existing v1 pin.
	old, err := NewRouteInventory(context.Background(), []RouteDefinition{routeDefinition(t, "model-a")})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(runtimePolicyDocument(t, old)), old)
	if err != nil || policy.Identity() != "6cb218e80d4983aeaed4daa8a1a74e1717b9ff19885c56346af4ab9a3840a3d6" {
		t.Fatalf("old identity changed: %s, %v", policy.Identity(), err)
	}
}
