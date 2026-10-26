package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func observeTerminalModelExpiryPhysical(ctx context.Context, stateRoot, artifactRoot *os.Root, fact controlplane.HistoricalContextPacketFact, configuration runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, handler string, generationScanner, verificationScanner review.ScannerBinaryDigests, binding historicalRecordedSourceBinding, now time.Time) (window generationRejectionWindow, result error) {
	defer func() {
		if result != nil {
			window = generationRejectionWindow{}
		}
	}()
	if ctx == nil || ctx.Err() != nil || stateRoot == nil || artifactRoot == nil || !binding.valid() {
		return window, errTerminalModelExpiry
	}
	proof, err := validateTerminalModelExpiryJournal(fact, now)
	if err != nil {
		return window, err
	}
	candidateTask, ok := fact.Plan().Task("candidates")
	if !ok || candidateTask.HandlerIdentity() != handler || fact.Plan().PolicyIdentity() != configuration.ReviewPolicyIdentity() {
		return window, errTerminalModelExpiry
	}
	scope := fact.Plan().Scope()
	checkMarker := func() error {
		_, err := stateRoot.Lstat(scope.Identity() + ".scope-intent.json")
		if !errors.Is(err, os.ErrNotExist) {
			return errors.Join(errTerminalModelExpiry, err)
		}
		return nil
	}
	if err := checkMarker(); err != nil {
		return window, err
	}
	before, err := stateRoot.Lstat("audit")
	if err != nil || !ownerDirectoryInfo(before) {
		return window, errors.Join(errTerminalModelExpiry, err)
	}
	auditRoot, err := stateRoot.OpenRoot("audit")
	if err != nil {
		return window, err
	}
	defer func() {
		opened, openedErr := auditRoot.Stat(".")
		linked, linkedErr := stateRoot.Lstat("audit")
		if openedErr != nil || linkedErr != nil || !physicalPacketRootSame(before, opened) || !physicalPacketRootSame(before, linked) {
			result = errors.Join(result, errTerminalModelExpiry, openedErr, linkedErr)
		}
		result = errors.Join(result, checkMarker(), auditRoot.Close())
	}()
	opened, err := auditRoot.Stat(".")
	if err != nil || !physicalPacketRootSame(before, opened) {
		return window, errors.Join(errTerminalModelExpiry, err)
	}
	events, err := audit.ObserveFileStream(ctx, auditRoot, scope)
	count := 4
	if proof.task == "verification" {
		count = 6
	}
	if err != nil || len(events) != count {
		return window, errors.Join(errTerminalModelExpiry, err)
	}
	recorded := physicalRecordedV4Derivation{fact: fact, binding: binding}
	expected, err := recorded.expectations()
	if err != nil {
		return window, err
	}
	linked, _ := fact.LinkedInputEvent()
	descriptor := linked.InputDescriptor()
	expected = append(expected, physicalPacketExpectation{scope: scope, role: physicalRoleRequest, input: descriptor.Request}, physicalPacketExpectation{scope: scope, role: physicalRoleReceipt, input: descriptor.Receipt}, physicalPacketExpectation{scope: scope, role: physicalRoleInput, input: descriptor.Input})
	first, firstRoot, err := physicalPacketScan(ctx, artifactRoot, (*os.File).Close)
	if err != nil {
		return window, err
	}
	afterAncestors := func(observations []physicalPacketObservation) error {
		if len(observations) != 11 {
			return errTerminalModelExpiry
		}
		values := make([]artifact.Artifact, len(observations))
		for i, observed := range observations {
			if observed.kind != physicalPacketIntact || !reflect.DeepEqual(observed.expectation, expected[i]) {
				return errTerminalModelExpiry
			}
			values[i] = observed.value
		}
		ancestors := historicalRecordedV4Artifacts{BaseInput: values[0], HeadInput: values[1], BaseSnapshot: values[2], HeadSnapshot: values[3], Change: values[4], Analysis: values[5], Memory: values[6], Packet: values[7]}
		names, err := recordedHistoricalAncestorNames(fact, ancestors, binding)
		if err != nil {
			return err
		}
		restriction := &physicalExactScopeNames{prefix: scope.Identity() + "-", names: make(map[string]struct{})}
		for _, id := range names {
			restriction.names[restriction.prefix+id+".artifact.json"] = struct{}{}
		}
		for _, value := range values[8:] {
			name := restriction.prefix + value.Identity() + ".artifact.json"
			if _, duplicate := restriction.names[name]; duplicate {
				return errTerminalModelExpiry
			}
			restriction.names[name] = struct{}{}
		}
		extras := make([]string, 0, 3)
		var total int64
		for name, info := range first {
			if !strings.HasPrefix(name, restriction.prefix) {
				continue
			}
			if _, known := restriction.names[name]; known {
				continue
			}
			extras = append(extras, name)
			total += info.Size()
		}
		extraCount := 1
		if proof.task == "verification" {
			extraCount = 3
		}
		if len(extras) != extraCount || total > physicalPacketTotalLimit {
			return errTerminalModelExpiry
		}
		dynamic := make(map[artifact.Kind]physicalPacketExpectation, extraCount)
		for _, name := range extras {
			raw, err := physicalPacketRead(ctx, artifactRoot, name, first[name], (*os.File).Close)
			if err != nil {
				return err
			}
			value, err := artifact.Parse(raw)
			if err != nil || value.Scope() != scope || name != restriction.prefix+value.Identity()+".artifact.json" {
				return errTerminalModelExpiry
			}
			origin := artifact.OriginHost
			switch value.Kind() {
			case artifact.KindCandidateBatch:
				origin = artifact.OriginModel
			case artifact.KindSanitizedModelRequest, artifact.KindSanitizedEgressReceipt:
				if proof.task != "verification" {
					return errTerminalModelExpiry
				}
			default:
				return errTerminalModelExpiry
			}
			if _, duplicate := dynamic[value.Kind()]; duplicate {
				return errTerminalModelExpiry
			}
			dynamic[value.Kind()] = physicalPacketExpectation{scope: scope, role: physicalRoleRecorded, recordedIdentity: value.Identity(), recordedKind: value.Kind(), recordedOrigin: origin}
			restriction.names[name] = struct{}{}
		}
		full := append([]physicalPacketExpectation(nil), expected...)
		kinds := []artifact.Kind{artifact.KindCandidateBatch}
		if proof.task == "verification" {
			kinds = append(kinds, artifact.KindSanitizedModelRequest, artifact.KindSanitizedEgressReceipt)
		}
		for _, kind := range kinds {
			expectation, ok := dynamic[kind]
			if !ok {
				return errTerminalModelExpiry
			}
			full = append(full, expectation)
		}
		if !restriction.matches(first) {
			return errTerminalModelExpiry
		}
		after := func(observed []physicalPacketObservation) error {
			if len(observed) != len(full) {
				return errTerminalModelExpiry
			}
			all := make([]artifact.Artifact, len(full))
			for i, item := range observed {
				if item.kind != physicalPacketIntact || !reflect.DeepEqual(item.expectation, full[i]) {
					return errTerminalModelExpiry
				}
				all[i] = item.value
				if i < len(values) && item.value.Identity() != values[i].Identity() {
					return errTerminalModelExpiry
				}
				if now.Before(item.value.CreatedAt()) || !now.Before(item.value.ExpiresAt()) {
					return errTerminalModelExpiry
				}
				if window.created.IsZero() || item.value.CreatedAt().After(window.created) {
					window.created = item.value.CreatedAt()
				}
				if window.expires.IsZero() || item.value.ExpiresAt().Before(window.expires) {
					window.expires = item.value.ExpiresAt()
				}
			}
			generation, err := validateTerminalExpiryGeneration(ctx, events, fact, proof, all, configuration, inventory, generationScanner, now)
			if err != nil {
				return err
			}
			if proof.task == "verification" {
				return validateTerminalExpiryVerifier(ctx, events, fact, proof, all, generation, configuration, inventory, verificationScanner)
			}
			return nil
		}
		return observeBorrowedHistoricalFilesWithRestriction(ctx, artifactRoot, full, after, (*os.File).Close, restriction)
	}
	physicalErr := observeBorrowedHistoricalFilesWithClose(ctx, artifactRoot, expected, afterAncestors, (*os.File).Close)
	second, secondRoot, scanErr := physicalPacketScan(ctx, artifactRoot, (*os.File).Close)
	if scanErr != nil || !physicalPacketRootSame(firstRoot, secondRoot) || !physicalPacketScanEqual(first, second) {
		result = errors.Join(result, errTerminalModelExpiry, scanErr)
	}
	final, auditErr := audit.ObserveFileStream(ctx, auditRoot, scope)
	if auditErr != nil || !reflect.DeepEqual(events, final) {
		result = errors.Join(result, errTerminalModelExpiry, auditErr)
	}
	result = errors.Join(result, physicalErr, ctx.Err())
	return window, result
}
