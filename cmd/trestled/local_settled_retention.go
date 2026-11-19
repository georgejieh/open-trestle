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

// retiredModelTail is what follows the generation request in a retired model
// tail's audit: nothing for a candidate lease expiry, the rejection, or the
// verification request up to the claim its lease ended at.
type retiredModelTail uint8

const (
	retiredCandidateExpiry retiredModelTail = iota + 1
	retiredGenerationRejection
	retiredVerificationExpiry
)

// retiredModelAudit checks a model tail's closed audit stream without reading
// an artifact: the hash chain and time order, the context input's route
// selection and its first attempt as the input recorded them, the generation
// request's same-route retries after rate limits by shape, its final attempt's
// response and reconciliation, and then exactly tail.
func retiredModelAudit(events []audit.Event, f controlplane.HistoricalContextPacketFact, tail retiredModelTail, latest time.Time) bool {
	linked, ok := f.LinkedInputEvent()
	if !ok || len(events) < 4 {
		return false
	}
	scope, d := f.Plan().Scope(), linked.InputDescriptor()
	previous, at := "", f.PreparedEvent().PacketDescriptor().CreatedAtMilliseconds
	for i, event := range events {
		if event.Validate() != nil || event.Scope() != scope || event.Sequence() != uint64(i+1) || event.PreviousIdentity() != previous || event.OccurredAtUnixMilliseconds() < at || event.OccurredAtUnixMilliseconds() > latest.UnixMilli() {
			return false
		}
		previous, at = event.Identity(), event.OccurredAtUnixMilliseconds()
	}
	selection := events[0]
	parents := selection.CausalParentIdentities()
	if selection.Kind() != audit.EventRouteSelected || selection.SubjectIdentity() != d.SelectionReceiptIdentity || selection.OccurredAtUnixMilliseconds() > linked.OccurredAt().UnixMilli() || len(parents) != 3 || !slices.Contains(parents, d.RoutingInputIdentity) || !slices.Contains(parents, d.SelectedRecordIdentity) {
		return false
	}
	attempts, ok := recordedRouteAttempts(events, 1, d.SelectionReceiptIdentity)
	if !ok || events[1].SubjectIdentity() != d.AuthorizationIdentity || !respondedRouteAttempt(events, attempts[len(attempts)-1].claim) {
		return false
	}
	rest := events[attempts[len(attempts)-1].claim+3:]
	switch tail {
	case retiredCandidateExpiry:
		return len(rest) == 0
	case retiredGenerationRejection:
		return len(rest) == 1 && rest[0].Kind() == audit.EventGenerationRejected && slices.Contains(rest[0].CausalParentIdentities(), d.Input.ArtifactIdentity) && slices.Contains(rest[0].CausalParentIdentities(), d.PacketArtifactIdentity)
	case retiredVerificationExpiry:
		verification, ok := modelRequestAudit(events, len(events)-len(rest))
		return ok && verification[len(verification)-1].claim == len(events)-1
	}
	return false
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
	if !ok || candidate.HandlerIdentity() != handler || descriptor.ScannerHelperDigest != scanner.HelperSHA256 || fact.Plan().PolicyIdentity() != a.configuration.ReviewPolicyIdentity() {
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
	if terminal.Failure() == controlplane.RunFailureResourceLimit {
		proof, err := validateTerminalModelExpiryJournal(fact, now)
		if err != nil {
			return err
		}
		tail := retiredCandidateExpiry
		if proof.task == "verification" {
			tail = retiredVerificationExpiry
		}
		if !retiredModelAudit(events, fact, tail, proof.failed.OccurredAt()) {
			return errRetiredSettledInput
		}
	} else {
		if err := validateGenerationRejectionJournal(fact, fact.ReplayEvents(), events, now); err != nil {
			return err
		}
		if !retiredModelAudit(events, fact, retiredGenerationRejection, terminal.OccurredAt()) {
			return errRetiredSettledInput
		}
	}
	final, err := audit.ObserveFileStream(ctx, auditRoot, scope)
	if err != nil || len(final) != len(events) || final[len(final)-1].Identity() != events[len(events)-1].Identity() {
		return errors.Join(errRetiredSettledInput, err)
	}
	return ctx.Err()
}
