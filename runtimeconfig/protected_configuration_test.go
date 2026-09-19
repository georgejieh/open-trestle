package runtimeconfig

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

func protectedRuntimeFixture(t *testing.T) (string, string, RouteInventory) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	encoded := encodedInventory(t)
	inventory, err := DecodeRouteInventory(context.Background(), bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	inventoryPath, policyPath := filepath.Join(dir, "inventory.json"), filepath.Join(dir, "policy.json")
	if err := os.WriteFile(inventoryPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, runtimePolicyDocument(t, inventory), 0o600); err != nil {
		t.Fatal(err)
	}
	return inventoryPath, policyPath, inventory
}

func TestLoadProtectedRuntimeConfigurationBindsActualFiles(t *testing.T) {
	inventoryPath, policyPath, expected := protectedRuntimeFixture(t)
	inventory, policy, err := LoadProtectedConfiguration(context.Background(), inventoryPath, policyPath)
	if err != nil || inventory.Identity() != expected.Identity() || policy.InventoryIdentity() != inventory.Identity() || policy.ValidateAgainstInventory(inventory) != nil {
		t.Fatal("protected runtime configuration lost content identity")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := LoadProtectedConfiguration(ctx, inventoryPath, policyPath); err == nil {
		t.Fatal("pre-canceled loader accepted execution authority")
	}
	if _, _, err := LoadProtectedConfiguration(context.Background(), inventoryPath, inventoryPath); err == nil {
		t.Fatal("inventory and policy accepted the same authority file")
	}
}

func TestLoadProtectedRuntimeConfigurationRefusesUntrustedAncestryAndContent(t *testing.T) {
	for _, mutation := range []string{"writable file", "symlink file", "writable ancestor", "symlink ancestor", "duplicate JSON", "unknown JSON", "wrong inventory", "inventory oversize", "policy oversize"} {
		t.Run(mutation, func(t *testing.T) {
			inventoryPath, policyPath, _ := protectedRuntimeFixture(t)
			switch mutation {
			case "writable file":
				if err := os.Chmod(policyPath, 0o666); err != nil {
					t.Fatal(err)
				}
			case "symlink file":
				link := filepath.Join(filepath.Dir(policyPath), "link.json")
				if err := os.Symlink(policyPath, link); err != nil {
					t.Fatal(err)
				}
				policyPath = link
			case "writable ancestor":
				if err := os.Chmod(filepath.Dir(policyPath), 0o777); err != nil {
					t.Fatal(err)
				}
			case "symlink ancestor":
				link := filepath.Join(t.TempDir(), "linked-config")
				if err := os.Symlink(filepath.Dir(policyPath), link); err != nil {
					t.Fatal(err)
				}
				policyPath = filepath.Join(link, "policy.json")
			default:
				encoded, err := os.ReadFile(policyPath)
				if err != nil {
					t.Fatal(err)
				}
				switch mutation {
				case "duplicate JSON":
					encoded = bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1)
				case "unknown JSON":
					encoded = bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":true`), 1)
				case "wrong inventory":
					encoded = bytes.Replace(encoded, []byte(`"inventory_identity":"`), []byte(`"inventory_identity":"f`), 1)
				case "inventory oversize":
					if err := os.WriteFile(inventoryPath, bytes.Repeat([]byte{' '}, (8<<20)+1), 0o600); err != nil {
						t.Fatal(err)
					}
				case "policy oversize":
					encoded = bytes.Repeat([]byte{' '}, (1<<20)+1)
				}
				if err := os.WriteFile(policyPath, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			inventory, policy, err := LoadProtectedConfiguration(context.Background(), inventoryPath, policyPath)
			if err == nil || inventory.Identity() != "" || policy.Identity() != "" {
				t.Fatal("invalid protected file produced usable runtime authority")
			}
		})
	}
}

type protectedReadProbe struct {
	*os.File
	afterRead  func()
	once       sync.Once
	closeError bool
}

func (p *protectedReadProbe) Read(value []byte) (int, error) {
	n, err := p.File.Read(value)
	if n > 0 && p.afterRead != nil {
		p.once.Do(p.afterRead)
	}
	return n, err
}
func (p *protectedReadProbe) Close() error {
	err := p.File.Close()
	if p.closeError {
		return errors.New("close failed with private path")
	}
	return err
}

func TestProtectedConfigurationReadRechecksAuthorityAndStableBytes(t *testing.T) {
	for _, mutation := range []string{"replace after first read", "mutate after first read", "permission after first read", "symlink before second open", "cancel during read", "close failure"} {
		t.Run(mutation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "configuration")
			if err := os.WriteFile(path, []byte("approved-bytes"), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opens := 0
			opener := func(name string) (protectedConfigurationFile, error) {
				opens++
				if opens == 2 && mutation == "symlink before second open" {
					other := path + ".other"
					if err := os.Rename(path, other); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(other, path); err != nil {
						t.Fatal(err)
					}
				}
				file, err := fileauthority.OpenReadOnly(name)
				if err != nil {
					return nil, err
				}
				probe := &protectedReadProbe{File: file, closeError: mutation == "close failure"}
				if opens == 1 {
					probe.afterRead = func() {
						switch mutation {
						case "replace after first read":
							other := path + ".replacement"
							if err := os.WriteFile(other, []byte("different-data"), 0o600); err != nil {
								t.Fatal(err)
							}
							if err := os.Rename(other, path); err != nil {
								t.Fatal(err)
							}
						case "mutate after first read":
							if err := os.WriteFile(path, []byte("different-data"), 0o600); err != nil {
								t.Fatal(err)
							}
						case "permission after first read":
							if err := os.Chmod(path, 0o666); err != nil {
								t.Fatal(err)
							}
						case "cancel during read":
							cancel()
						}
					}
				}
				return probe, nil
			}
			encoded, err := readProtectedConfiguration(ctx, path, 64, opener)
			if err == nil || len(encoded) != 0 {
				t.Fatal("unstable protected read produced authority bytes")
			}
			if strings.Contains(err.Error(), path) {
				t.Fatal("protected read disclosed configuration path")
			}
		})
	}
}

func TestProtectedConfigurationReadHonorsExactByteLimit(t *testing.T) {
	for _, size := range []int{16, 17} {
		path := filepath.Join(t.TempDir(), "bounded")
		if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, size), 0o600); err != nil {
			t.Fatal(err)
		}
		opens := 0
		opener := func(name string) (protectedConfigurationFile, error) {
			opens++
			return fileauthority.OpenReadOnly(name)
		}
		encoded, err := readProtectedConfiguration(context.Background(), path, 16, opener)
		if size == 16 && (err != nil || len(encoded) != 16 || opens != 2) {
			t.Fatal("exact bound did not retain two stable protected reads")
		}
		if size == 17 && (err == nil || len(encoded) != 0) {
			t.Fatal("protected file exceeded the byte limit")
		}
	}
}

var _ io.ReadCloser = (*protectedReadProbe)(nil)
