package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

var errGenerationRejectionPhysical = errors.New("generation rejection physical proof refused")

// observeGenerationRejectionPhysical observes supplied borrowed roots. Its caller
// must hold ownership and enclose this call in the journal and root postchecks.
// It neither activates a store nor grants startup permission.
type generationRejectionWindow struct {
	created, expires time.Time
}

func (w generationRejectionWindow) live(now time.Time) bool {
	return !w.created.IsZero() && w.created.Before(w.expires) && !now.Before(w.created) && now.Before(w.expires)
}

func observeGenerationRejectionPhysical(ctx context.Context, stateRoot, artifactRoot *os.Root, fact controlplane.HistoricalContextPacketFact, policy runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, handler string, scanner review.ScannerBinaryDigests, binding historicalRecordedSourceBinding, now time.Time) (result error) {
	_, err := observeGenerationRejectionPhysicalWindow(ctx, stateRoot, artifactRoot, fact, policy, inventory, handler, scanner, binding, now)
	return err
}

func observeGenerationRejectionPhysicalWindow(ctx context.Context, stateRoot, artifactRoot *os.Root, fact controlplane.HistoricalContextPacketFact, policy runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, handler string, scanner review.ScannerBinaryDigests, binding historicalRecordedSourceBinding, now time.Time) (window generationRejectionWindow, result error) {
	result = func() (result error) {
		if ctx == nil || ctx.Err() != nil || stateRoot == nil || artifactRoot == nil || !binding.valid() {
			return errGenerationRejectionPhysical
		}
		before, err := stateRoot.Lstat("audit")
		if err != nil || !ownerDirectoryInfo(before) {
			return errors.Join(errGenerationRejectionPhysical, err)
		}
		auditRoot, err := stateRoot.OpenRoot("audit")
		if err != nil {
			return errors.Join(errGenerationRejectionPhysical, err)
		}
		defer func() {
			opened, openedErr := auditRoot.Stat(".")
			linked, linkedErr := stateRoot.Lstat("audit")
			if openedErr != nil || linkedErr != nil || !physicalPacketRootSame(before, opened) || !physicalPacketRootSame(before, linked) {
				result = errors.Join(result, errGenerationRejectionPhysical, openedErr, linkedErr)
			}
			result = errors.Join(result, auditRoot.Close())
		}()
		opened, err := auditRoot.Stat(".")
		if err != nil || !physicalPacketRootSame(before, opened) {
			return errors.Join(errGenerationRejectionPhysical, err)
		}
		events, err := audit.ObserveFileStream(ctx, auditRoot, fact.Plan().Scope())
		if err != nil || validateGenerationRejectionJournal(fact, fact.ReplayEvents(), events, now) != nil {
			return errors.Join(errGenerationRejectionPhysical, err)
		}
		linked, ok := fact.LinkedInputEvent()
		if !ok {
			return errGenerationRejectionPhysical
		}
		descriptor := linked.InputDescriptor()
		candidate, ok := fact.Plan().Task("candidates")
		if !ok || candidate.HandlerIdentity() != handler || descriptor.ScannerLauncherDigest != scanner.LauncherSHA256 || descriptor.ScannerWorkerDigest != scanner.WorkerSHA256 {
			return errGenerationRejectionPhysical
		}
		recorded := physicalRecordedV4Derivation{fact: fact, binding: binding}
		expected, err := recorded.expectations()
		if err != nil {
			return err
		}
		scope := fact.Plan().Scope()
		expected = append(expected, physicalPacketExpectation{scope: scope, role: physicalRoleRequest, input: descriptor.Request}, physicalPacketExpectation{scope: scope, role: physicalRoleReceipt, input: descriptor.Receipt}, physicalPacketExpectation{scope: scope, role: physicalRoleInput, input: descriptor.Input}, physicalPacketExpectation{scope: scope, role: physicalRoleRecorded, recordedIdentity: events[len(events)-1].SubjectIdentity(), recordedKind: artifact.KindGenerationRejection, recordedOrigin: artifact.OriginHost})
		restriction := &physicalExactScopeNames{prefix: scope.Identity() + "-", names: make(map[string]struct{})}
		first, firstRoot, err := physicalPacketScan(ctx, artifactRoot, (*os.File).Close)
		if err != nil {
			return err
		}
		after := func(observations []physicalPacketObservation) error {
			if len(observations) != 12 {
				return errGenerationRejectionPhysical
			}
			values := make([]artifact.Artifact, len(observations))
			for i, observed := range observations {
				if observed.kind != physicalPacketIntact || !reflect.DeepEqual(observed.expectation, expected[i]) {
					return errGenerationRejectionPhysical
				}
				values[i] = observed.value
			}
			ancestors := historicalRecordedV4Artifacts{BaseInput: values[0], HeadInput: values[1], BaseSnapshot: values[2], HeadSnapshot: values[3], Change: values[4], Analysis: values[5], Memory: values[6], Packet: values[7]}
			names, err := recordedHistoricalAncestorNames(fact, ancestors, binding)
			if err != nil {
				return err
			}
			for _, value := range values {
				if now.Before(value.CreatedAt()) || !now.Before(value.ExpiresAt()) {
					return errGenerationRejectionPhysical
				}
				if window.created.IsZero() || value.CreatedAt().After(window.created) {
					window.created = value.CreatedAt()
				}
				if window.expires.IsZero() || value.ExpiresAt().Before(window.expires) {
					window.expires = value.ExpiresAt()
				}
			}
			sanitized, err := review.ParseSanitizedModelRequest(values[8].Payload())
			if err != nil {
				return err
			}
			request, err := sanitized.ProviderRequest()
			if err != nil {
				return err
			}
			pair, err := runtimecatalog.ResolveLocalGenerationRoutePair(policy, inventory)
			if err != nil {
				return err
			}
			route, err := runtimecatalog.PlanLocalGenerationRoute(ctx, scope, request, policy, inventory, pair)
			if err != nil {
				return err
			}
			input, err := modelhandler.ParseGenerationInput(values[10].Payload())
			if err != nil || !runtimecatalog.MatchesLocalGenerationAuthorization(route, input.Authorization()) {
				return errors.Join(errGenerationRejectionPhysical, err)
			}
			if err := validateGenerationRejectionAudit(events, values[11], values[10], values[7], values[8], values[9], descriptor, route, handler, now); err != nil {
				return err
			}
			for _, value := range values[8:] {
				if slices.Contains(names, value.Identity()) {
					return errGenerationRejectionPhysical
				}
				names = append(names, value.Identity())
			}
			for _, id := range names {
				restriction.names[restriction.prefix+id+".artifact.json"] = struct{}{}
			}
			return nil
		}
		// The shared observer brackets exact envelope bytes. These outer scans also
		// bind the dynamically derived complete scope name set before and after it.
		if err := observeBorrowedHistoricalFilesWithClose(ctx, artifactRoot, expected, after, (*os.File).Close); err != nil {
			return err
		}
		second, secondRoot, err := physicalPacketScan(ctx, artifactRoot, (*os.File).Close)
		if err != nil || !physicalPacketRootSame(firstRoot, secondRoot) || !physicalPacketScanEqual(first, second) || !restriction.matches(first) || !restriction.matches(second) {
			return errors.Join(errGenerationRejectionPhysical, err)
		}
		final, err := audit.ObserveFileStream(ctx, auditRoot, scope)
		if err != nil || !reflect.DeepEqual(events, final) {
			return errors.Join(errGenerationRejectionPhysical, err)
		}
		return ctx.Err()
	}()
	if result != nil {
		window = generationRejectionWindow{}
	}
	return window, result
}
