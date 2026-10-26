package main

import (
	"context"
	"os"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type localGenerationStartupAuthority struct {
	inventory             runtimeconfig.RouteInventory
	configuration         runtimeconfig.RuntimePolicy
	dispatchers           gateway.RouteDispatcherCatalog
	sanitizer             review.GenerationRequestSanitizer
	verificationSanitizer review.VerificationRequestSanitizer
}

func loadLocalGenerationStartupAuthority(ctx context.Context, inventoryPath, policyPath string, getenv func(string) string, sanitizer review.GenerationRequestSanitizer) (*localGenerationStartupAuthority, error) {
	inventory, configuration, err := loadRuntimeConfiguration(ctx, inventoryPath, policyPath)
	if err != nil {
		return nil, err
	}
	dispatchers, err := runtimecatalog.NewLocalOpenAIRouteDispatcherCatalogFromRuntimePolicy(inventory, configuration, environmentOpenAICredentialResolver{getenv: getenv})
	if err != nil || daemonNilDependency(sanitizer) {
		return nil, ErrInvalidDaemonConfiguration
	}
	return &localGenerationStartupAuthority{inventory: inventory, configuration: configuration, dispatchers: dispatchers, sanitizer: sanitizer}, nil
}

func (a *localGenerationStartupAuthority) observe(ctx context.Context, stateRoot, artifactRoot *os.Root, fact controlplane.HistoricalContextPacketFact, binding historicalRecordedSourceBinding, now time.Time) (generationRejectionWindow, error) {
	if a == nil || daemonNilDependency(a.sanitizer) {
		return generationRejectionWindow{}, errHistoricalInputIntentQuarantinedAtStartup
	}
	scanner := a.sanitizer.ExpectedBinaryDigests()
	handler, err := modelhandler.SanitizedGenerationHandlerIdentity(a.dispatchers, scanner)
	if err != nil {
		return generationRejectionWindow{}, err
	}
	terminal, hasTerminal := fact.TerminalEvent()
	if hasTerminal && terminal.Kind() == controlplane.RunEventFailed && terminal.Failure() == controlplane.RunFailureResourceLimit {
		if daemonNilDependency(a.verificationSanitizer) {
			return generationRejectionWindow{}, errTerminalModelExpiry
		}
		return observeTerminalModelExpiryPhysical(ctx, stateRoot, artifactRoot, fact, a.configuration, a.inventory, handler, scanner, a.verificationSanitizer.ExpectedBinaryDigests(), binding, now)
	}
	return observeGenerationRejectionPhysicalWindow(ctx, stateRoot, artifactRoot, fact, a.configuration, a.inventory, handler, scanner, binding, now)
}
