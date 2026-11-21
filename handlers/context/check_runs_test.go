package context

import (
	"encoding/json"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/review"
)

func checkRunsFor(t *testing.T, base, head string) review.CheckRuns {
	t.Helper()
	runs, err := review.NewCheckRuns(base, head, review.CheckRunsChangedAndDependents, []review.CheckRun{
		{Name: "go test ./calc", State: review.CheckRunRan, Tests: 2, Regressions: []string{"example.com/calc.TestDiv"}},
		{Name: "npm test", State: review.CheckRunCouldNotRun, Reason: "missing dependency: jest"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return runs
}

// assembleWithCheckRuns assembles the intent fixture's change, whose base and
// head commits are 1111... and 2222..., with runs bound.
func assembleWithCheckRuns(t *testing.T, runs review.CheckRuns) textFallbackResult {
	t.Helper()
	configureTestHandler = func(h *Handler) { h.checkRuns = runs }
	defer func() { configureTestHandler = nil }()
	return assembleTextFallback(t, map[string][]byte{"calc.go": []byte(intentBase)}, map[string][]byte{"calc.go": []byte(intentHead)})
}

func TestAssemblyCarriesTheCheckRunsOfTheReviewedChange(t *testing.T) {
	runs := checkRunsFor(t, strings.Repeat("1", 40), strings.Repeat("2", 40))
	result := assembleWithCheckRuns(t, runs)
	if result.failure != 0 {
		t.Fatalf("assembly failed: %s", result.failure)
	}
	payload := result.request.Payload()
	read, err := review.ContextCheckRuns(payload)
	if err != nil || read.Identity() != runs.Identity() {
		t.Fatalf("the context does not carry the bound outcomes: %v", err)
	}
	packet := result.assembly.Packet
	if err := review.ValidateContextPacketRequest(payload, packet.Identity(), packet.ReviewScopeIdentity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), result.assembly.Snapshot, packet.EvidenceItems()); err != nil {
		t.Fatalf("assembled context with check runs rejected: %v", err)
	}
	// The outcomes are an added object only: everything else, the system
	// channel included, is what the same change assembles without them.
	plain := assembleTextFallback(t, map[string][]byte{"calc.go": []byte(intentBase)}, map[string][]byte{"calc.go": []byte(intentHead)})
	withRuns, without := statedIntentWire(t, payload), statedIntentWire(t, plain.request.Payload())
	if _, present := without["check_runs"]; present {
		t.Fatal("a handler without check runs invented them")
	}
	delete(withRuns, "check_runs")
	if !maps.EqualFunc(withRuns, without, func(a, b json.RawMessage) bool { return string(a) == string(b) }) {
		t.Fatal("check runs changed more than their own object")
	}
	system, err := review.TrustedModelRequestInstructions(payload)
	plainSystem, plainErr := review.TrustedModelRequestInstructions(plain.request.Payload())
	if err != nil || plainErr != nil || system != plainSystem || strings.Contains(system, "jest") {
		t.Fatal("check run text changed or entered the trusted system channel")
	}
}

func TestAssemblyRefusesCheckRunsOfAnotherRange(t *testing.T) {
	for name, runs := range map[string]review.CheckRuns{
		"other base": checkRunsFor(t, strings.Repeat("3", 40), strings.Repeat("2", 40)),
		"other head": checkRunsFor(t, strings.Repeat("1", 40), strings.Repeat("3", 40)),
		"swapped":    checkRunsFor(t, strings.Repeat("2", 40), strings.Repeat("1", 40)),
	} {
		result := assembleWithCheckRuns(t, runs)
		if result.failure != controlplane.RunFailureInvalidInput || len(result.request.Payload()) != 0 || result.abstention != nil {
			t.Fatalf("%s: failure = %s, want invalid_input with nothing assembled", name, result.failure)
		}
	}
}

func TestWithCheckRunsBindsTheOutcomesIntoTheHandlerIdentity(t *testing.T) {
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 16)
	clock := contextTestClock{time.UnixMilli(230)}
	calls, requestIdentity := 0, ""
	authorizer := contextTestAuthorizer{identity: strings.Repeat("5", 64), calls: &calls, requestIdentity: &requestIdentity}
	plain, err := NewHandler(store, clock, authorizer, contextTestSanitizer{})
	if err != nil {
		t.Fatal(err)
	}
	runs := checkRunsFor(t, strings.Repeat("1", 40), strings.Repeat("2", 40))
	bound, err := plain.WithCheckRuns(runs)
	if err != nil || bound.Validate() != nil {
		t.Fatalf("WithCheckRuns() = %v", err)
	}
	if bound.HandlerIdentity() == plain.HandlerIdentity() || bound.HandlerIdentity() != deriveHandlerIdentity(authorizer.Identity(), contextTestSanitizer{}.Identity(), review.ContextSpecialist{}, "", "", review.ContextBudget{}, runs.Identity()) {
		t.Fatal("the check runs are not bound into the handler identity")
	}
	other, err := plain.WithCheckRuns(checkRunsFor(t, strings.Repeat("1", 40), strings.Repeat("4", 40)))
	if err != nil || other.HandlerIdentity() == bound.HandlerIdentity() {
		t.Fatal("different outcomes share a handler identity")
	}
	// The intent source and the outcomes bind together in either order.
	both, err := bound.WithChangeIntent(fakeIntentSource{})
	reversed, reversedErr := plain.WithChangeIntent(fakeIntentSource{})
	if err == nil && reversedErr == nil {
		reversed, reversedErr = reversed.WithCheckRuns(runs)
	}
	if err != nil || reversedErr != nil || both.Validate() != nil || both.HandlerIdentity() != reversed.HandlerIdentity() || both.HandlerIdentity() == bound.HandlerIdentity() {
		t.Fatalf("intent and check runs do not bind together: %v %v", err, reversedErr)
	}
	if !plain.checkRuns.IsZero() {
		t.Fatal("WithCheckRuns changed the receiver")
	}
	if _, err := bound.WithCheckRuns(runs); err == nil {
		t.Fatal("a second set of outcomes was bound")
	}
	if _, err := plain.WithCheckRuns(review.CheckRuns{}); err == nil {
		t.Fatal("empty outcomes were bound")
	}
	packetOnly, _ := NewPacketOnlyHandler(store, clock)
	if _, err := packetOnly.WithCheckRuns(runs); err == nil {
		t.Fatal("a packet-only handler accepted check runs")
	}
	forged := *plain
	forged.checkRuns = runs
	if forged.Validate() == nil {
		t.Fatal("check runs outside the handler identity validated")
	}
	forgedPacketOnly := *packetOnly
	forgedPacketOnly.checkRuns = runs
	if forgedPacketOnly.Validate() == nil {
		t.Fatal("a packet-only handler with check runs validated")
	}
}
