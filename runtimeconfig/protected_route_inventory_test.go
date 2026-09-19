package runtimeconfig

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestLoadProtectedRouteInventoryReturnsStableDecodedSnapshot(t *testing.T) {
	if !protectedRouteInventoryOwnershipSupported() {
		t.Skip("protected ownership is unsupported on this platform")
	}
	path := writeProtectedRouteInventoryFile(t, encodedInventory(t), 0o644)
	expected, err := DecodeRouteInventory(context.Background(), bytes.NewReader(encodedInventory(t)))
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := LoadProtectedRouteInventory(context.Background(), path)
	if err != nil {
		t.Fatalf("LoadProtectedRouteInventory() error = %v", err)
	}
	if inventory.Identity() != expected.Identity() || inventory.Validate() != nil || !reflect.DeepEqual(protectedRouteInventoryIDs(inventory), protectedRouteInventoryIDs(expected)) {
		t.Fatalf("protected route inventory = %#v, want identity %q", inventory, expected.Identity())
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, ctx := range map[string]context.Context{"nil": nil, "canceled": ctx} {
		t.Run(name, func(t *testing.T) {
			inventory, err := LoadProtectedRouteInventory(ctx, path)
			if !errors.Is(err, ErrProtectedConfiguration) || inventory.Identity() != "" {
				t.Fatalf("LoadProtectedRouteInventory(%s) = (%#v,%v), want protected refusal", name, inventory, err)
			}
		})
	}
}

func TestLoadProtectedRouteInventoryFailsClosedForInvalidInputs(t *testing.T) {
	validPath := writeProtectedRouteInventoryFile(t, encodedInventory(t), 0o600)
	missingPath := filepath.Join(t.TempDir(), "missing-route-inventory.json")
	malformedPath := writeProtectedRouteInventoryFile(t, []byte(`{"schema_version":1,"routes":[`), 0o600)
	emptyPath := writeProtectedRouteInventoryFile(t, nil, 0o600)
	oversizedPath := writeProtectedRouteInventoryFile(t, bytes.Repeat([]byte{' '}, (8<<20)+1), 0o600)
	unsafeFilePath := writeProtectedRouteInventoryFile(t, encodedInventory(t), 0o666)
	unsafeParentPath := writeProtectedRouteInventoryUnderParent(t, 0o777)
	paths := map[string]string{
		"empty path":      "",
		"missing":         missingPath,
		"malformed":       malformedPath,
		"empty file":      emptyPath,
		"oversized":       oversizedPath,
		"unsafe file":     unsafeFilePath,
		"unsafe ancestor": unsafeParentPath,
	}
	if !protectedRouteInventoryOwnershipSupported() {
		paths["supported file on unsupported platform"] = validPath
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			inventory, err := LoadProtectedRouteInventory(context.Background(), path)
			if !errors.Is(err, ErrProtectedConfiguration) || inventory.Identity() != "" {
				t.Fatalf("LoadProtectedRouteInventory(%q) = (%#v,%v), want protected refusal", path, inventory, err)
			}
			if err != nil && path != "" && strings.Contains(err.Error(), path) {
				t.Fatalf("protected refusal leaked path in %q", err.Error())
			}
		})
	}
}

func TestLoadProtectedRouteInventoryFailsClosedWhereProtectedOwnershipUnsupported(t *testing.T) {
	if protectedRouteInventoryOwnershipSupported() {
		t.Skip("protected ownership is implemented on this platform")
	}
	path := writeProtectedRouteInventoryFile(t, encodedInventory(t), 0o600)
	inventory, err := LoadProtectedRouteInventory(context.Background(), path)
	if !errors.Is(err, ErrProtectedConfiguration) || inventory.Identity() != "" {
		t.Fatalf("unsupported protected ownership result = (%#v,%v), want protected refusal", inventory, err)
	}
}

func writeProtectedRouteInventoryFile(t *testing.T, content []byte, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	protectedRouteInventoryChmod(t, dir, 0o700)
	path := filepath.Join(dir, "routes.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	protectedRouteInventoryChmod(t, path, mode)
	return path
}

func writeProtectedRouteInventoryUnderParent(t *testing.T, parentMode os.FileMode) string {
	t.Helper()
	root := t.TempDir()
	parent := filepath.Join(root, "shared")
	dir := filepath.Join(parent, "private")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "routes.json")
	if err := os.WriteFile(path, encodedInventory(t), 0o600); err != nil {
		t.Fatal(err)
	}
	protectedRouteInventoryChmod(t, path, 0o600)
	protectedRouteInventoryChmod(t, parent, parentMode)
	return path
}

func protectedRouteInventoryChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func protectedRouteInventoryIDs(inventory RouteInventory) []string {
	candidates := inventory.Candidates()
	ids := make([]string, len(candidates))
	for index, candidate := range candidates {
		ids[index] = candidate.ResolvedRecord().RouteRegistryRecord().Identity()
	}
	return ids
}

func protectedRouteInventoryOwnershipSupported() bool {
	switch runtime.GOOS {
	case "aix", "android", "darwin", "dragonfly", "freebsd", "illumos", "ios", "linux", "netbsd", "openbsd", "solaris":
		return true
	default:
		return false
	}
}
