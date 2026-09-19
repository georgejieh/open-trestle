package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"io"
	"sort"
)

const maxRouteInventoryIdentityResultBytes = 8192

type routeInventoryIdentityResult struct {
	Contract              string   `json:"contract"`
	SchemaVersion         int      `json:"schema_version"`
	Status                string   `json:"status"`
	InventoryIdentity     string   `json:"inventory_identity"`
	RouteRecordIdentities []string `json:"route_record_identities"`
	RouteCount            int      `json:"route_count"`
}

func runConfigInventoryIdentity(args []string, stdout, stderr io.Writer) int {
	path, ok := parseConfigInventoryIdentityArgs(args)
	if !ok {
		writeConfigInventoryIdentityUsage(stderr)
		return 2
	}
	inventory, err := runtimeconfig.LoadProtectedRouteInventory(context.Background(), path)
	if err != nil {
		fmt.Fprintln(stderr, "load route inventory failed")
		return 1
	}
	identities := routeRecordIdentities(inventory)
	if len(identities) == 0 || len(identities) > 64 {
		fmt.Fprintln(stderr, "load route inventory failed")
		return 1
	}
	result := routeInventoryIdentityResult{
		Contract:              "open-trestle/route-inventory-identity-result",
		SchemaVersion:         1,
		Status:                "decoded",
		InventoryIdentity:     inventory.Identity(),
		RouteRecordIdentities: identities,
		RouteCount:            len(identities),
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded)+1 > maxRouteInventoryIdentityResultBytes {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	encoded = append(encoded, '\n')
	if written, err := stdout.Write(encoded); err != nil || written != len(encoded) {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}
func parseConfigInventoryIdentityArgs(args []string) (string, bool) {
	if len(args) != 2 || args[0] != "--route-inventory" || args[1] == "" {
		return "", false
	}
	return args[1], true
}
func routeRecordIdentities(inventory runtimeconfig.RouteInventory) []string {
	candidates := inventory.Candidates()
	identities := make([]string, len(candidates))
	for i, candidate := range candidates {
		identities[i] = candidate.ResolvedRecord().RouteRegistryRecord().Identity()
	}
	sort.Strings(identities)
	return identities
}
func writeConfigInventoryIdentityUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: trestle config inventory-identity --route-inventory PATH")
}
