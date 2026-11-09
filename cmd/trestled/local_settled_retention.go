package main

import (
	"context"
	"errors"
	"os"
	"slices"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
)

var errRetiredSettledInput = errors.New("retired settled context input proof refused")

// retiredSettledLinked reports a context input the journal already settled and
// whose packet retention (shared by its request, receipt and input envelopes)
// has lapsed: the owner settled the input and the run ended, or the expired
// input was terminated by a no-output policy failure. Such a scope admits no
// later owner effect that reads its artifacts, so startup proves it from the
// journal and audit without reading or deleting the expired bytes.
func retiredSettledLinked(f controlplane.HistoricalContextPacketFact, now time.Time) bool {
	linked, ok := f.LinkedInputEvent()
	// The failed-run tails check the exact recipe in their own journal proofs.
	if !ok || now.UnixMilli() < f.PreparedEvent().PacketDescriptor().ExpiresAtMilliseconds {
		return false
	}
	settled, hasSettlement := f.TaskSettlementEvent()
	terminal, hasTerminal := f.TerminalEvent()
	if !hasSettlement || settled.PreviousIdentity() != linked.Identity() {
		return false
	}
	switch settled.Kind() {
	case controlplane.RunEventContextInputSettled:
		return hasTerminal && settled.OutputIdentity() == linked.InputDescriptor().Input.ArtifactIdentity
	case controlplane.RunEventTaskFailed:
		return settled.Failure() == controlplane.RunFailurePolicy && settled.OutputIdentity() == "" && (!hasTerminal || terminal.Kind() == controlplane.RunEventFailed)
	}
	return false
}

// retiredModelAudit checks a model tail's closed audit stream without reading
// an artifact: the exact kinds in sequence, the hash chain and time order, the
// context input's route selection and its first attempt as the input recorded
// them, and every later model event caused by that attempt.
func retiredModelAudit(events []audit.Event, f controlplane.HistoricalContextPacketFact, kinds []audit.EventKind, latest time.Time) bool {
	linked, ok := f.LinkedInputEvent()
	if !ok || len(events) != len(kinds) || len(events) < 2 {
		return false
	}
	scope, d := f.Plan().Scope(), linked.InputDescriptor()
	previous, at := "", f.PreparedEvent().PacketDescriptor().CreatedAtMilliseconds
	for i, event := range events {
		if event.Validate() != nil || event.Scope() != scope || event.Sequence() != uint64(i+1) || event.PreviousIdentity() != previous || event.Kind() != kinds[i] || event.OccurredAtUnixMilliseconds() < at || event.OccurredAtUnixMilliseconds() > latest.UnixMilli() {
			return false
		}
		previous, at = event.Identity(), event.OccurredAtUnixMilliseconds()
	}
	selection, claim := events[0], events[1]
	parents := selection.CausalParentIdentities()
	if selection.SubjectIdentity() != d.SelectionReceiptIdentity || selection.OccurredAtUnixMilliseconds() > linked.OccurredAt().UnixMilli() || len(parents) != 3 || !slices.Contains(parents, d.RoutingInputIdentity) || !slices.Contains(parents, d.SelectedRecordIdentity) {
		return false
	}
	if claim.SubjectIdentity() != d.AuthorizationIdentity || !slices.Equal(claim.CausalParentIdentities(), []string{d.SelectionReceiptIdentity}) {
		return false
	}
	for _, event := range events[2:] {
		switch event.Kind() {
		case audit.EventRouteDispatchCompleted, audit.EventRouteCostReconciled:
			if !slices.Contains(event.CausalParentIdentities(), d.AuthorizationIdentity) {
				return false
			}
		case audit.EventGenerationRejected:
			if !slices.Contains(event.CausalParentIdentities(), d.Input.ArtifactIdentity) || !slices.Contains(event.CausalParentIdentities(), d.PacketArtifactIdentity) {
				return false
			}
		}
	}
	return true
}

// observeRetired proves a failed run's candidate-generation rejection or model
// lease expiry from its journal and audit alone, for a scope whose packet
// retention has lapsed. It checks the same current handler and scanner binding
// as the byte proof, but reads no artifact and returns no retention window.
func (a *localGenerationStartupAuthority) observeRetired(ctx context.Context, stateRoot *os.Root, fact controlplane.HistoricalContextPacketFact, now time.Time) (result error) {
	if a == nil || daemonNilDependency(a.sanitizer) || ctx == nil || ctx.Err() != nil || stateRoot == nil || !retiredSettledLinked(fact, now) {
		return errRetiredSettledInput
	}
	scanner := a.sanitizer.ExpectedBinaryDigests()
	handler, err := modelhandler.SanitizedGenerationHandlerIdentity(a.dispatchers, scanner)
	if err != nil {
		return err
	}
	linked, _ := fact.LinkedInputEvent()
	descriptor := linked.InputDescriptor()
	candidate, ok := fact.Plan().Task("candidates")
	if !ok || candidate.HandlerIdentity() != handler || descriptor.ScannerLauncherDigest != scanner.LauncherSHA256 || descriptor.ScannerWorkerDigest != scanner.WorkerSHA256 || fact.Plan().PolicyIdentity() != a.configuration.ReviewPolicyIdentity() {
		return errRetiredSettledInput
	}
	scope := fact.Plan().Scope()
	if _, err := stateRoot.Lstat(scope.Identity() + ".scope-intent.json"); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(errRetiredSettledInput, err)
	}
	before, err := stateRoot.Lstat("audit")
	if err != nil || !ownerDirectoryInfo(before) {
		return errors.Join(errRetiredSettledInput, err)
	}
	auditRoot, err := stateRoot.OpenRoot("audit")
	if err != nil {
		return errors.Join(errRetiredSettledInput, err)
	}
	defer func() {
		opened, openedErr := auditRoot.Stat(".")
		relinked, linkedErr := stateRoot.Lstat("audit")
		if openedErr != nil || linkedErr != nil || !physicalPacketRootSame(before, opened) || !physicalPacketRootSame(before, relinked) {
			result = errors.Join(result, errRetiredSettledInput, openedErr, linkedErr)
		}
		result = errors.Join(result, auditRoot.Close())
	}()
	events, err := audit.ObserveFileStream(ctx, auditRoot, scope)
	if err != nil {
		return errors.Join(errRetiredSettledInput, err)
	}
	terminal, _ := fact.TerminalEvent()
	model := []audit.EventKind{audit.EventRouteSelected, audit.EventRouteAttemptClaimed, audit.EventRouteDispatchCompleted, audit.EventRouteCostReconciled}
	if terminal.Failure() == controlplane.RunFailureResourceLimit {
		proof, err := validateTerminalModelExpiryJournal(fact, now)
		if err != nil {
			return err
		}
		if proof.task == "verification" {
			model = append(model, audit.EventRouteSelected, audit.EventRouteAttemptClaimed)
		}
		if !retiredModelAudit(events, fact, model, proof.failed.OccurredAt()) || proof.task == "verification" && !slices.Equal(events[5].CausalParentIdentities(), []string{events[4].SubjectIdentity()}) {
			return errRetiredSettledInput
		}
	} else {
		if err := validateGenerationRejectionJournal(fact, fact.ReplayEvents(), events, now); err != nil {
			return err
		}
		if !retiredModelAudit(events, fact, append(model, audit.EventGenerationRejected), terminal.OccurredAt()) {
			return errRetiredSettledInput
		}
	}
	final, err := audit.ObserveFileStream(ctx, auditRoot, scope)
	if err != nil || len(final) != len(events) || final[len(final)-1].Identity() != events[len(events)-1].Identity() {
		return errors.Join(errRetiredSettledInput, err)
	}
	return ctx.Err()
}
