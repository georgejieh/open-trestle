package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"io"
	"os"
)

func runConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeConfigUsage(stderr)
		return 2
	}
	if args[0] == "inventory-identity" {
		return runConfigInventoryIdentity(args[1:], stdout, stderr)
	}
	if args[0] != "validate" {
		writeConfigUsage(stderr)
		return 2
	}
	flags := flag.NewFlagSet("trestle config validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inventoryPath := flags.String("route-inventory", "", "runtime route inventory path")
	policyPath := flags.String("runtime-policy", "", "runtime policy path")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *inventoryPath == "" || *policyPath == "" {
		writeConfigUsage(stderr)
		return 2
	}
	inventoryFile, err := os.Open(*inventoryPath)
	if err != nil {
		fmt.Fprintf(stderr, "validate configuration: %v\n", err)
		return 1
	}
	inventory, decodeErr := runtimeconfig.DecodeRouteInventory(context.Background(), inventoryFile)
	closeErr := inventoryFile.Close()
	if decodeErr != nil || closeErr != nil {
		fmt.Fprintln(stderr, "validate configuration: invalid route inventory")
		return 1
	}
	policyFile, err := os.Open(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "validate configuration: %v\n", err)
		return 1
	}
	configuration, decodeErr := runtimeconfig.DecodeRuntimePolicy(context.Background(), policyFile, inventory)
	closeErr = policyFile.Close()
	if decodeErr != nil || closeErr != nil {
		fmt.Fprintln(stderr, "validate configuration: invalid runtime policy")
		return 1
	}
	result := struct {
		Contract              string `json:"contract"`
		SchemaVersion         int    `json:"schema_version"`
		Status                string `json:"status"`
		InventoryIdentity     string `json:"inventory_identity"`
		RuntimePolicyIdentity string `json:"runtime_policy_identity"`
		ReviewPolicyIdentity  string `json:"review_policy_identity"`
		RouteCount            int    `json:"route_count"`
		ConnectionCount       int    `json:"connection_count"`
	}{"open-trestle/runtime-configuration-validation-result", 1, "valid", inventory.Identity(), configuration.Identity(), configuration.ReviewPolicyIdentity(), len(inventory.Candidates()), len(configuration.Connections())}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(stderr, "write result: %v\n", err)
		return 1
	}
	return 0
}
func writeConfigUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: trestle config validate --route-inventory PATH --runtime-policy PATH")
}
