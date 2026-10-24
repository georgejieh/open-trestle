package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveryObservationRefusesWrongStoreLock(t *testing.T) {
	for _, dir := range []string{"artifacts", "diagnostics", "audit"} {
		t.Run(dir, func(t *testing.T) {
			state, repository := stoppedRestoreFixture(t)
			leaf := ".writer.lock"
			if dir == "audit" {
				leaf = ".artifact-writer.lock"
			}
			if err := os.WriteFile(filepath.Join(state, dir, leaf), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			assertSnapshotNoWrite(t, filepath.Dir(state), func() {
				if _, _, err := observeLocalRecoveryPoint(context.Background(), state, repository); err == nil {
					t.Fatal("unexpected store lock accepted")
				}
			})
		})
	}
}

func TestRecoveryInventoryReportsBound(t *testing.T) {
	dir := t.TempDir()
	file, err := os.OpenFile(filepath.Join(dir, "sparse"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(localRecoveryInventoryBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, git := range []bool{false, true} {
		if _, err := inventoryRecoveryTree(context.Background(), root, git); !errors.Is(err, errRecoveryInventoryLimit) {
			t.Fatalf("unclassified limit: %v", err)
		}
	}
}
func TestRecoveryDiffNamesAsset(t *testing.T) {
	expected := localRecoveryPoint{Assets: recoveryRecordAssets()}
	observed := expected
	observed.Assets = append([]localRecoveryAsset(nil), expected.Assets...)
	observed.Assets[1].SHA256 = strings.Repeat("d", 64)
	err := compareLocalRecoveryPoint(expected, observed)
	if err == nil || !strings.Contains(err.Error(), "scanner") || !strings.Contains(err.Error(), "/srv/scanner") {
		t.Fatalf("asset difference not named: %v", err)
	}
}
