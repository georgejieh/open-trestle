package main

import (
	"context"
	"os"
	"strings"

	"github.com/georgejieh/open-trestle/audit"
)

type physicalExactScopeNames struct {
	prefix string
	names  map[string]struct{}
}

// observeBorrowedHistoricalExactScopeNames checks caller-asserted same-scope names
// and selected envelopes. It does not derive a closure or parse unselected names.
// Nil is provisional until the caller's owned-root postchecks and close succeed;
// it grants no startup or recovery authority.
func observeBorrowedHistoricalExactScopeNames(ctx context.Context, borrowed *os.Root, scope audit.ReviewScope, allowedArtifactIdentities []string, expected []physicalPacketExpectation) error {
	return observeBorrowedHistoricalExactScopeNamesWithClose(ctx, borrowed, scope, allowedArtifactIdentities, expected, (*os.File).Close)
}

func observeBorrowedHistoricalExactScopeNamesWithClose(ctx context.Context, borrowed *os.Root, scope audit.ReviewScope, allowedArtifactIdentities []string, expected []physicalPacketExpectation, closeFile func(*os.File) error) error {
	if scope.Validate() != nil || len(allowedArtifactIdentities) == 0 || len(allowedArtifactIdentities) >= physicalPacketEntryLimit || len(expected) == 0 || len(expected) > physicalCombinedExpectationLimit {
		return errPhysicalPacketObservationUncertain
	}
	restriction := &physicalExactScopeNames{prefix: scope.Identity() + "-", names: make(map[string]struct{}, len(allowedArtifactIdentities))}
	for _, id := range allowedArtifactIdentities {
		if !physicalPacketDigest(id) {
			return errPhysicalPacketObservationUncertain
		}
		name := restriction.prefix + id + ".artifact.json"
		if _, duplicate := restriction.names[name]; duplicate {
			return errPhysicalPacketObservationUncertain
		}
		restriction.names[name] = struct{}{}
	}
	for _, e := range expected {
		id := physicalExpectationIdentity(e)
		if e.scope != scope {
			return errPhysicalPacketObservationUncertain
		}
		if _, exists := restriction.names[restriction.prefix+id+".artifact.json"]; !exists {
			return errPhysicalPacketObservationUncertain
		}
	}
	return observeBorrowedHistoricalFilesWithRestriction(ctx, borrowed, expected, func(observations []physicalPacketObservation) error {
		for _, observation := range observations {
			if observation.kind != physicalPacketIntact {
				return errPhysicalPacketObservationUncertain
			}
		}
		return nil
	}, closeFile, restriction)
}

func (r *physicalExactScopeNames) matches(found map[string]os.FileInfo) bool {
	count := 0
	for name := range found {
		if !strings.HasPrefix(name, r.prefix) {
			continue
		}
		if _, allowed := r.names[name]; !allowed {
			return false
		}
		count++
	}
	return count == len(r.names)
}
