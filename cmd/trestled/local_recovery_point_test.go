package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestLocalRecoveryPointCanonicalComparisonRecord(t *testing.T) {
	point := localRecoveryPoint{Contract: localRecoveryPointContract, Version: 1, StatePath: "/srv/trestle/state", SetupPath: "/srv/trestle/state/setup/plan.json", RepositoryAuthority: "local.test", RepositoryNamespace: []string{"team"}, RepositoryName: "repo", OwnerIdentity: strings.Repeat("a", 64), SetupIdentity: strings.Repeat("b", 64), Entries: []localRecoveryEntry{{Path: ".run-writer.lock", Mode: 0o600, Size: 0, SHA256: localRecoveryBytesIdentity(nil)}}}
	point.Assets = recoveryRecordAssets()
	raw, err := encodeLocalRecoveryPoint(point)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseLocalRecoveryPoint(raw)
	if err != nil || parsed.StatePath != point.StatePath {
		t.Fatalf("record round trip: %v", err)
	}
	for _, changed := range [][]byte{append(bytes.Clone(raw), 'x'), bytes.Replace(raw, []byte(`"version":1,`), []byte(`"version":1,"version":1,`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1), bytes.Replace(raw, []byte(`"path":".run-writer.lock"`), []byte(`"path":"../escape"`), 1)} {
		if _, err := parseLocalRecoveryPoint(changed); !errors.Is(err, errInvalidRecoveryPoint) {
			t.Fatalf("noncanonical or unsafe record accepted: %v", err)
		}
	}
}
