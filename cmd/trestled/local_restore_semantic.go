package main

import (
	"context"
	"os"
	"strings"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
)

// inspectRestoredStoreLeaves parses every artifact/deletion and diagnostic leaf,
// not merely task outputs. The inventory caller owns all roots and writer locks.
func inspectRestoredStoreLeaves(ctx context.Context, stateRoot, artifactRoot, diagnosticRoot, auditRoot *os.Root, entries []localRecoveryEntry, receipts []controlplane.ReviewRunReceipt) error {
	scopes := make(map[string]audit.ReviewScope, len(receipts))
	for _, receipt := range receipts {
		scopes[receipt.Scope().Identity()] = receipt.Scope()
	}
	for _, entry := range entries {
		if entry.Mode == 0o700 {
			continue
		}
		var root *os.Root
		var leaf string
		switch {
		case strings.HasPrefix(entry.Path, "artifacts/"):
			root = artifactRoot
			leaf = strings.TrimPrefix(entry.Path, "artifacts/")
		case strings.HasPrefix(entry.Path, "diagnostics/"):
			root = diagnosticRoot
			leaf = strings.TrimPrefix(entry.Path, "diagnostics/")
		case strings.HasPrefix(entry.Path, "audit/"):
			root = auditRoot
			leaf = strings.TrimPrefix(entry.Path, "audit/")
		default:
			continue
		}
		if root == artifactRoot && leaf == ".artifact-writer.lock" || root == diagnosticRoot && leaf == ".diagnostic-writer.lock" || root == auditRoot && leaf == ".writer.lock" {
			continue
		}
		if strings.Contains(leaf, "/") {
			return errRestoreObservationMismatch
		}
		if root == auditRoot {
			scopeID, ok := strings.CutSuffix(leaf, ".audit.jsonl")
			scope, known := scopes[scopeID]
			if !ok || !known {
				return errRestoreObservationMismatch
			}
			if _, err := audit.ObserveFileStream(ctx, root, scope); err != nil {
				return err
			}
			continue
		}
		info, err := root.Lstat(leaf)
		if err != nil {
			return err
		}
		raw, err := physicalPacketRead(ctx, root, leaf, info, (*os.File).Close)
		if err != nil {
			return err
		}
		if root == diagnosticRoot {
			value, err := diagnostics.ParseSet(raw)
			if err != nil {
				return err
			}
			if _, known := scopes[value.Scope().Identity()]; !known || leaf != value.Scope().Identity()+".diagnostic-set.json" {
				return errRestoreObservationMismatch
			}
			continue
		}
		value, err := artifact.Parse(raw)
		if err != nil {
			return err
		}
		if _, known := scopes[value.Scope().Identity()]; !known || leaf != value.Scope().Identity()+"-"+value.Identity()+".artifact.json" {
			return errRestoreObservationMismatch
		}
	}
	return nil
}
