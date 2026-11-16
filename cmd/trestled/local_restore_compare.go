package main

import (
	"fmt"
	"reflect"
)

func compareLocalRecoveryPoint(expected, observed localRecoveryPoint) error {
	if expected.StatePath != observed.StatePath || expected.OwnerIdentity != observed.OwnerIdentity {
		return fmt.Errorf("%w: owner", errRestoreObservationMismatch)
	}
	if expected.RepositoryAuthority != observed.RepositoryAuthority || !reflect.DeepEqual(expected.RepositoryNamespace, observed.RepositoryNamespace) || expected.RepositoryName != observed.RepositoryName {
		return fmt.Errorf("%w: repository", errRestoreObservationMismatch)
	}
	if expected.SetupPath != observed.SetupPath || expected.SetupIdentity != observed.SetupIdentity {
		return fmt.Errorf("%w: setup", errRestoreObservationMismatch)
	}
	for _, pair := range []struct {
		name          string
		before, after []localRecoveryEntry
	}{{"state", expected.Entries, observed.Entries}, {"git", expected.GitEntries, observed.GitEntries}} {
		i, j := 0, 0
		for i < len(pair.before) || j < len(pair.after) {
			if i >= len(pair.before) {
				return fmt.Errorf("%w: %s inventory added %q", errRestoreObservationMismatch, pair.name, pair.after[j].Path)
			}
			if j >= len(pair.after) {
				return fmt.Errorf("%w: %s inventory missing %q", errRestoreObservationMismatch, pair.name, pair.before[i].Path)
			}
			if pair.before[i] != pair.after[j] {
				return fmt.Errorf("%w: %s inventory differs at %q / %q", errRestoreObservationMismatch, pair.name, pair.before[i].Path, pair.after[j].Path)
			}
			i++
			j++
		}
	}
	if len(expected.Assets) != len(observed.Assets) {
		return fmt.Errorf("%w: retained asset set", errRestoreObservationMismatch)
	}
	for i, asset := range expected.Assets {
		if asset != observed.Assets[i] {
			return fmt.Errorf("%w: retained %s asset %q / %q", errRestoreObservationMismatch, asset.Role, asset.Path, observed.Assets[i].Path)
		}
	}
	if !reflect.DeepEqual(expected.Runs, observed.Runs) {
		return fmt.Errorf("%w: run receipt, diagnostic, or audit identity", errRestoreObservationMismatch)
	}
	if !reflect.DeepEqual(expected, observed) {
		return fmt.Errorf("%w: recovery metadata", errRestoreObservationMismatch)
	}
	return nil
}
