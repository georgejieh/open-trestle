package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func recoveryAssetFlags(t *testing.T) []string {
	t.Helper()
	args, _, _, _, _, _, _ := localFullDaemonFixture(t)
	inventory := daemonTestFlagValue(t, args, "--runtime-route-inventory")
	policy := daemonTestFlagValue(t, args, "--runtime-policy")
	dir := t.TempDir()
	flags := []string{}
	for _, role := range []string{"binary", "scanner", "scanner-worker"} {
		path := filepath.Join(dir, role)
		if err := os.WriteFile(path, []byte("pinned fixture "+role), 0o500); err != nil {
			t.Fatal(err)
		}
		flags = append(flags, "--"+role, path)
	}
	return append(flags, "--route-inventory", inventory, "--runtime-policy", policy)
}
func recoveryRecordAssets() []localRecoveryAsset {
	var assets []localRecoveryAsset
	for _, role := range []string{"binary", "scanner", "scanner-worker", "route-inventory", "runtime-policy"} {
		assets = append(assets, localRecoveryAsset{Role: role, Path: "/srv/" + role, SHA256: strings.Repeat("c", 64)})
	}
	return assets
}
