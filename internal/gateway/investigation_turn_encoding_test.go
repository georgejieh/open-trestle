package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

const turnEncodingByteLimit = 24 << 20

func turnEncodingJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal("fixture JSON encoding failed")
	}
	return encoded
}

func turnEncodingBudget(b provider.ModelCostBudget) map[string]any {
	return map[string]any{"estimated_input_tokens": b.EstimatedInputTokens(), "max_output_tokens": b.MaxOutputTokens(), "max_cost_micro_usd": b.MaxCostMicroUSD()}
}

func turnEncodingEstimate(e provider.RouteCostEstimate) map[string]any {
	return map[string]any{"input_cost_micro_usd": e.InputCostMicroUSD(), "output_cost_micro_usd": e.OutputCostMicroUSD(), "maximum_cost_micro_usd": e.MaximumCostMicroUSD()}
}

func turnEncodingUsage(u provider.RouteTokenUsage) map[string]any {
	return map[string]any{"known": u.IsKnown(), "input_tokens": u.InputTokens(), "output_tokens": u.OutputTokens(), "cached_input_tokens": u.CachedInputTokens()}
}

func turnEncodingPerformance(p provider.RoutePerformanceObservation) map[string]any {
	return map[string]any{"record_identity": p.RecordIdentity(), "observation_revision": p.ObservationRevision(), "latency_known": p.LatencyKnown(), "p95_milliseconds": p.P95LatencyMilliseconds(), "sample_count": p.SampleCount()}
}

func turnEncodingRegistry(r provider.RouteRegistryRecord) map[string]any {
	candidate := r.RouteCandidateDeclaration()
	capability := candidate.RouteCapabilityDeclaration()
	route, model := capability.RouteReference(), capability.ModelCapabilities()
	features := []string{}
	for _, feature := range model.SupportedFeatures() {
		features = append(features, feature.String())
	}
	return map[string]any{
		"identity": r.Identity(), "registry_revision": r.RegistryRevision(),
		"provider_zone": route.Zone().String(), "provider_id": route.ProviderID(), "adapter_id": route.AdapterID(),
		"connection_id": route.ConnectionID(), "model_id": route.ModelID(), "model_version": route.ModelVersion(),
		"supported_features": features, "max_context_tokens": model.MaxContextTokens(), "max_output_tokens": model.MaxOutputTokens(),
		"content_logging_mode": candidate.ContentLoggingMode().String(), "pricing_known": candidate.RoutePricing().IsKnown(),
		"input_price_micro_usd_per_million_tokens":  candidate.RoutePricing().InputMicroUSDPerMillionTokens(),
		"output_price_micro_usd_per_million_tokens": candidate.RoutePricing().OutputMicroUSDPerMillionTokens(),
		"quality_tier": candidate.RouteQualityTier().String(), "status": r.Status().String(), "evidence_manifest_digest": r.EvidenceManifestDigest(),
	}
}

func turnEncodingSelection(s RouteSelectionReceipt) map[string]any {
	scores, rejections := []any{}, []any{}
	for _, score := range s.CandidateScores() {
		rank, _ := score.PreferenceRank()
		scores = append(scores, map[string]any{
			"record_identity": score.RecordIdentity(), "operational_revision": score.OperationalRevision(),
			"performance": turnEncodingPerformance(score.Performance()), "pinned": score.IsPinned(), "preference_rank": rank,
			"quality_tier": score.QualityTier().String(), "max_context_tokens": score.MaxContextTokens(), "max_output_tokens": score.MaxOutputTokens(),
			"maximum_cost": turnEncodingEstimate(score.MaximumCost()),
		})
	}
	for _, rejected := range s.Rejections() {
		rejections = append(rejections, map[string]any{"record_identity": rejected.RecordIdentity(), "operational_revision": rejected.OperationalRevision(), "reason": rejected.Reason().String()})
	}
	return map[string]any{
		"identity": s.Identity(), "request_identity": s.RequestIdentity(), "review_scope_identity": s.ReviewScopeIdentity(),
		"routing_input_identity": s.RoutingInputIdentity(), "registry_revision": s.RegistryRevision(), "performance_revision": s.PerformanceRevision(),
		"cost_budget": turnEncodingBudget(s.CostBudget()), "ranking_policy_identity": s.RankingPolicyIdentity(),
		"selected_record_identity": s.SelectedRecordIdentity(), "candidate_scores": scores, "rejections": rejections,
	}
}

func turnEncodingRanking(r RouteRankingResult) map[string]any {
	routes := []any{}
	for _, ranked := range r.RankedRoutes() {
		resolved, state := ranked.Route().ResolvedRecord(), ranked.Route().OperationalState()
		rank, _ := ranked.PreferenceRank()
		routes = append(routes, map[string]any{
			"registry_record": turnEncodingRegistry(resolved.RouteRegistryRecord()), "evidence_manifest_size_bytes": resolved.EvidenceManifestSizeBytes(),
			"operational_state": map[string]any{"record_identity": state.RecordIdentity(), "observation_revision": state.ObservationRevision(), "health": state.Health().String(), "quota": state.Quota().String()},
			"performance":       turnEncodingPerformance(ranked.Performance()), "pinned": ranked.IsPinned(), "preference_rank": rank,
			"maximum_cost": turnEncodingEstimate(ranked.MaximumCost()),
		})
	}
	return map[string]any{
		"request_identity": r.RequestIdentity(), "review_scope_identity": r.ReviewScopeIdentity(), "routing_input_identity": r.RoutingInputIdentity(),
		"registry_revision": r.RegistryRevision(), "performance_revision": r.PerformanceRevision(), "cost_budget": turnEncodingBudget(r.CostBudget()),
		"ranking_policy_identity": r.RankingPolicyIdentity(), "ranked_routes": routes,
	}
}

func turnEncodingResponse(r provider.Response) map[string]any {
	parts := []any{}
	for _, part := range r.Parts() {
		parts = append(parts, map[string]any{"kind": part.Kind().String(), "media_type": part.MediaType(), "payload_b64": base64.StdEncoding.EncodeToString(part.Payload())})
	}
	return map[string]any{"identity": r.Identity(), "capability": r.Capability().String(), "finish_reason": r.FinishReason().String(), "parts": parts, "usage": turnEncodingUsage(r.Usage())}
}

// Existing route subdocuments retain their struct order, unlike the new objects.
func turnEncodingDocument(t *testing.T, r InvestigationTurnRecord) map[string]any {
	t.Helper()
	authorization, err := EncodeRouteAttemptAuthorization(r.authorization)
	if err != nil {
		t.Fatal("fixture authorization encoding failed")
	}
	o, c, d := r.outcome, r.reconciliation, r.dispatch
	actual := c.ActualCost()
	return map[string]any{
		"contract": "open-trestle/investigation-turn", "schema_version": 1, "identity": r.identity,
		"owner_identity": r.ownerIdentity, "session_identity": r.sessionIdentity, "policy_identity": r.policyIdentity, "scope_identity": r.scopeIdentity,
		"ordinal": r.ordinal, "role": r.role.String(), "previous_turn_identity": r.previous,
		"deadline_milliseconds": r.deadlineMillis, "started_milliseconds": r.startedMillis, "finished_milliseconds": r.finishedMillis,
		"estimate_version": r.estimateVersion, "declared_input_tokens": r.declaredInput, "max_output_tokens": r.maxOutput, "original_cap_micro_usd": r.originalCap,
		"request":   map[string]any{"identity": r.request.Identity(), "capability": r.request.Capability().String(), "media_type": r.request.MediaType(), "payload_b64": base64.StdEncoding.EncodeToString(r.request.Payload())},
		"selection": turnEncodingSelection(r.selection), "ranking": turnEncodingRanking(r.ranking), "authorization": json.RawMessage(authorization),
		"dispatch": map[string]any{"identity": d.Identity(), "authorization_identity": d.AuthorizationIdentity(), "status": d.Status().String(), "response": turnEncodingResponse(d.Response()), "usage": turnEncodingUsage(d.Usage()), "failure": d.Failure().String(), "replay_safety": d.ReplaySafety().String(), "retry_after_milliseconds": d.RetryAfterMilliseconds()},
		"outcome": routeOutcomeWire{
			Identity: o.Identity(), Status: o.Status().String(), ResponseIdentity: o.ResponseIdentity(), UsageKnown: o.Usage().IsKnown(),
			InputTokens: o.Usage().InputTokens(), OutputTokens: o.Usage().OutputTokens(), CachedInputTokens: o.Usage().CachedInputTokens(),
			Failure: o.Failure().String(), ReplaySafety: o.ReplaySafety().String(), RetryAfterMilliseconds: o.RetryAfterMilliseconds(), DurationMilliseconds: o.DurationMilliseconds(),
		},
		"reconciliation": routeReconciliationWire{
			Identity: c.Identity(), Status: c.Status().String(), ReservedCostMicroUSD: c.ReservedCostMicroUSD(), ActualKnown: actual.IsKnown(),
			ActualInputCostMicroUSD: actual.InputCostMicroUSD(), ActualOutputCostMicroUSD: actual.OutputCostMicroUSD(), ActualTotalCostMicroUSD: actual.TotalCostMicroUSD(),
			RemainingAfterReservationMicroUSD: c.RemainingAfterReservationMicroUSD(), RemainingCostMicroUSD: c.RemainingCostMicroUSD(), BudgetOverrunMicroUSD: c.BudgetOverrunMicroUSD(),
		},
		"remaining_before_micro_usd": r.authorization.RemainingCostBeforeMicroUSD(), "reserved_micro_usd": r.authorization.ReservedCostMicroUSD(),
		"actual_cost_micro_usd": actual.TotalCostMicroUSD(), "remaining_micro_usd": c.RemainingCostMicroUSD(),
	}
}

func turnEncodingPreimage(r InvestigationTurnRecord) []any {
	return []any{
		"open-trestle/investigation-turn", 1, r.ownerIdentity, r.sessionIdentity, r.policyIdentity, r.scopeIdentity,
		r.ordinal, r.role.String(), r.previous, r.deadlineMillis, r.startedMillis, r.finishedMillis,
		r.estimateVersion, r.declaredInput, r.maxOutput, r.originalCap,
		r.request.Identity(), r.selection.Identity(), r.authorization.Identity(), r.dispatch.Identity(), r.outcome.Identity(), r.reconciliation.Identity(),
		r.authorization.RemainingCostBeforeMicroUSD(), r.authorization.ReservedCostMicroUSD(), r.reconciliation.ActualCost().TotalCostMicroUSD(), r.reconciliation.RemainingCostMicroUSD(),
	}
}

func turnEncodingAssertRoundTrip(t *testing.T, r InvestigationTurnRecord) InvestigationTurnRecord {
	t.Helper()
	if r.Validate() != nil {
		t.Fatal("fixture is not a valid complete readback record")
	}
	preimage := turnEncodingPreimage(r)
	if len(preimage) != 26 {
		t.Fatal("turn identity recipe changed")
	}
	digest := sha256.Sum256(turnEncodingJSON(t, preimage))
	if hex.EncodeToString(digest[:]) != r.Identity() {
		t.Fatal("accepted ordered-array identity recipe changed")
	}
	encoded, err := EncodeInvestigationTurnRecord(r)
	if err != nil {
		t.Fatal("successful turn encoding refused")
	}
	if !bytes.Equal(encoded, turnEncodingJSON(t, turnEncodingDocument(t, r))) {
		t.Fatal("wire fields, canonical ordering or embedded v1 bytes changed")
	}
	decoded, err := ParseInvestigationTurnRecord(encoded)
	if err != nil || decoded.Validate() != nil {
		t.Fatal("canonical complete turn readback refused")
	}
	if !reflect.DeepEqual(turnEncodingPreimage(decoded), preimage) || !reflect.DeepEqual(turnEncodingRanking(decoded.ranking), turnEncodingRanking(r.ranking)) {
		t.Fatal("readback lost turn identity components or complete ranking")
	}
	if !bytes.Equal(decoded.request.Payload(), r.request.Payload()) || !reflect.DeepEqual(turnEncodingResponse(decoded.dispatch.Response()), turnEncodingResponse(r.dispatch.Response())) {
		t.Fatal("readback reinterpreted original request or actual response bytes")
	}
	reencoded, err := EncodeInvestigationTurnRecord(decoded)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		t.Fatal("readback is not exactly canonical")
	}
	for i := range encoded {
		encoded[i] = 0
	}
	payload := decoded.request.Payload()
	payload[0] ^= 1
	parts := decoded.dispatch.Response().Parts()
	partBytes := parts[0].Payload()
	partBytes[0] ^= 1
	parts[0] = provider.ResponsePart{}
	reencoded, err = EncodeInvestigationTurnRecord(decoded)
	if err != nil || !bytes.Equal(reencoded, turnEncodingJSON(t, turnEncodingDocument(t, r))) {
		t.Fatal("readback retained mutable input or output storage")
	}
	return decoded
}

func TestInvestigationTurnEncodingSharedBudgetReadbackIsNotAnEffect(t *testing.T) {
	owner, d, _, ledger := investigationOwnerFixture(t, "", 40000, 4)
	first, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "generation"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := owner.Dispatch(context.Background(), InvestigationVerificationTurn, ownerRequest(t, "verification"))
	if err != nil {
		t.Fatal(err)
	}
	if d.count() != 2 || second.PreviousTurnIdentity() != first.Identity() || second.Authorization().RemainingCostBeforeMicroUSD() != 21000 || second.Reconciliation().RemainingCostMicroUSD() != 2000 {
		t.Fatal("fixture did not use one actual shared budget")
	}
	before, events := owner.State(), investigationOwnerEvents(t, ledger, d.scope)
	turnEncodingAssertRoundTrip(t, first)
	turnEncodingAssertRoundTrip(t, second)
	if !reflect.DeepEqual(owner.State(), before) || !reflect.DeepEqual(investigationOwnerEvents(t, ledger, d.scope), events) || d.count() != 2 {
		t.Fatal("codec claimed, dispatched, settled or reset the live owner")
	}
	if _, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "third")); err == nil || d.count() != 2 {
		t.Fatal("readback restored spending authority")
	}
	for _, value := range []any{InvestigationTurnRecord{}, &InvestigationTurnRecord{}, owner} {
		kind := reflect.TypeOf(value)
		for _, name := range []string{"Restore", "Reset", "Settle", "ImportReceipt", "Credit", "SetRemainingBudget", "Claim", "AuthorizeOnly"} {
			if _, ok := kind.MethodByName(name); ok {
				t.Fatal("readback exposes execution or accounting authority")
			}
		}
	}
}

func TestInvestigationTurnEncodingPreservesOpaqueRequestBytes(t *testing.T) {
	for _, payload := range [][]byte{[]byte(" {\n  \"z\": 1, \"a\": \"<&>\"\r\n}\t"), {0, 0xff, 0xfe, 'x', '\r', '\n'}} {
		owner, _, _, _ := investigationOwnerFixture(t, "", 100000, 2)
		request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/octet-stream", payload)
		if err != nil {
			t.Fatal(err)
		}
		record, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, request)
		if err != nil {
			t.Fatal(err)
		}
		turnEncodingAssertRoundTrip(t, record)
	}
}

func turnEncodingRefuse(t *testing.T, encoded []byte) {
	t.Helper()
	r, err := ParseInvestigationTurnRecord(encoded)
	if err == nil || r.Identity() != "" || r.Validate() == nil {
		t.Fatal("invalid encoding returned usable readback")
	}
}

// Span edits retain every unaffected legacy object's field order.
type turnEncodingSpan struct {
	path       string
	start, end int
	value      any
}

func turnEncodingSpans(t *testing.T, encoded []byte) []turnEncodingSpan {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	spans := []turnEncodingSpan{}
	var walk func(string)
	walk = func(path string) {
		start := int(decoder.InputOffset())
		for start < len(encoded) && strings.ContainsRune(" \r\n\t:,", rune(encoded[start])) {
			start++
		}
		token, err := decoder.Token()
		if err != nil {
			t.Fatal("fixture span decode failed")
		}
		if delimiter, ok := token.(json.Delim); ok {
			if delimiter == '{' {
				for decoder.More() {
					key, err := decoder.Token()
					if err != nil {
						t.Fatal("fixture member decode failed")
					}
					walk(path + "/" + key.(string))
				}
			} else if delimiter == '[' {
				for i := 0; decoder.More(); i++ {
					walk(path + "/" + strconv.Itoa(i))
				}
			}
			if _, err := decoder.Token(); err != nil {
				t.Fatal("fixture delimiter decode failed")
			}
		}
		spans = append(spans, turnEncodingSpan{path, start, int(decoder.InputOffset()), token})
	}
	walk("")
	return spans
}

func turnEncodingReplace(encoded []byte, span turnEncodingSpan, replacement []byte) []byte {
	result := append([]byte(nil), encoded[:span.start]...)
	result = append(result, replacement...)
	return append(result, encoded[span.end:]...)
}

func turnEncodingAt(t *testing.T, encoded []byte, path string, replacement []byte) []byte {
	t.Helper()
	for _, span := range turnEncodingSpans(t, encoded) {
		if span.path == path {
			return turnEncodingReplace(encoded, span, replacement)
		}
	}
	t.Fatal("fixture field not found")
	return nil
}

func TestInvestigationTurnEncodingEveryScalarAndComponentIsChecked(t *testing.T) {
	r := turnEncodingRichRecord(t, false)
	encoded := turnEncodingJSON(t, turnEncodingDocument(t, r))
	for _, span := range turnEncodingSpans(t, encoded) {
		t.Run(span.path+"/null", func(t *testing.T) {
			turnEncodingRefuse(t, turnEncodingReplace(encoded, span, []byte("null")))
		})
		var replacement []byte
		switch value := span.value.(type) {
		case string:
			replacement = turnEncodingJSON(t, value+"x")
		case bool:
			replacement = turnEncodingJSON(t, !value)
		case json.Number:
			number, err := strconv.ParseUint(string(value), 10, 64)
			if err != nil {
				t.Fatal("fixture integer not unsigned")
			}
			replacement = []byte(strconv.FormatUint(number+1, 10))
			if strings.HasSuffix(span.path, "/evidence_manifest_size_bytes") {
				replacement = []byte("0")
			}
		case json.Delim:
			if value == '{' {
				replacement = append([]byte(`{"unknown_secret":0,`), encoded[span.start+1:span.end]...)
			} else {
				replacement = []byte("{}")
			}
		}
		t.Run(span.path+"/changed", func(t *testing.T) {
			turnEncodingRefuse(t, turnEncodingReplace(encoded, span, replacement))
		})
	}
}

func TestInvestigationTurnEncodingRejectsRehashedCrossWiring(t *testing.T) {
	owner, _, _, _ := investigationOwnerFixture(t, "", 100000, 3)
	first, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := owner.Dispatch(context.Background(), InvestigationVerificationTurn, ownerRequest(t, "second"))
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*InvestigationTurnRecord){
		"request":                         func(r *InvestigationTurnRecord) { r.request = first.request },
		"selection":                       func(r *InvestigationTurnRecord) { r.selection = first.selection },
		"ranking":                         func(r *InvestigationTurnRecord) { r.ranking = first.ranking },
		"authorization":                   func(r *InvestigationTurnRecord) { r.authorization = first.authorization },
		"dispatch":                        func(r *InvestigationTurnRecord) { r.dispatch = first.dispatch },
		"outcome":                         func(r *InvestigationTurnRecord) { r.outcome = first.outcome },
		"reconciliation":                  func(r *InvestigationTurnRecord) { r.reconciliation = first.reconciliation },
		"scope":                           func(r *InvestigationTurnRecord) { r.scopeIdentity = strings.Repeat("f", 64) },
		"elapsed time":                    func(r *InvestigationTurnRecord) { r.finishedMillis++ },
		"deadline equality":               func(r *InvestigationTurnRecord) { r.deadlineMillis = r.finishedMillis },
		"time inversion":                  func(r *InvestigationTurnRecord) { r.startedMillis = r.finishedMillis + 1 },
		"estimate version":                func(r *InvestigationTurnRecord) { r.estimateVersion++ },
		"output budget":                   func(r *InvestigationTurnRecord) { r.maxOutput++ },
		"declared input affects estimate": func(r *InvestigationTurnRecord) { r.declaredInput = 1000000 },
		"original cap below remaining":    func(r *InvestigationTurnRecord) { r.originalCap = 1 },
		"first ordinal with predecessor":  func(r *InvestigationTurnRecord) { r.ordinal = 1 },
		"ordinal ceiling":                 func(r *InvestigationTurnRecord) { r.ordinal = 9 },
		"missing predecessor":             func(r *InvestigationTurnRecord) { r.previous = "" },
		"unknown role":                    func(r *InvestigationTurnRecord) { r.role = 255 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := second
			change(&changed)
			changed.identity = changed.deriveIdentity()
			if changed.Validate() == nil {
				t.Fatal("test mutation is not inconsistent under accepted owner semantics")
			}
			if encoded, err := EncodeInvestigationTurnRecord(changed); err == nil || len(encoded) != 0 {
				t.Fatal("invalid in-memory record encoded")
			}
			turnEncodingRefuse(t, turnEncodingJSON(t, turnEncodingDocument(t, changed)))
		})
	}
}

func TestInvestigationTurnEncodingHashIsNotIssuerAuthority(t *testing.T) {
	owner, _, _, _ := investigationOwnerFixture(t, "", 100000, 3)
	first, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "lineage-first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := owner.Dispatch(context.Background(), InvestigationVerificationTurn, ownerRequest(t, "lineage-second"))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"owner", "session", "policy", "previous", "role", "cap", "deadline"} {
		t.Run(field, func(t *testing.T) {
			changed := second
			switch field {
			case "owner":
				changed.ownerIdentity = strings.Repeat("d", 64)
			case "session":
				changed.sessionIdentity = strings.Repeat("d", 64)
			case "policy":
				changed.policyIdentity = strings.Repeat("d", 64)
			case "previous":
				changed.previous = strings.Repeat("d", 64)
			case "role":
				changed.role = InvestigationGenerationTurn
			case "cap":
				changed.originalCap++
			case "deadline":
				changed.deadlineMillis++
			}
			changed.identity = changed.deriveIdentity()
			if changed.Identity() == second.Identity() || changed.Validate() != nil {
				t.Fatal("self-consistent different-record fixture is invalid")
			}
			decoded := turnEncodingAssertRoundTrip(t, changed)
			if decoded.Identity() == second.Identity() {
				t.Fatal("different content impersonated trusted expected identity")
			}
			if field == "previous" && decoded.PreviousTurnIdentity() == first.Identity() {
				t.Fatal("readback silently restored trusted lineage")
			}
		})
	}
}

func TestInvestigationTurnEncodingRefusesIncompleteAndUnsafeOwnerResults(t *testing.T) {
	for _, partial := range []InvestigationTurnRecord{{}, {identity: strings.Repeat("d", 64)}, {ordinal: 1, role: InvestigationGenerationTurn}} {
		if encoded, err := EncodeInvestigationTurnRecord(partial); err == nil || len(encoded) != 0 {
			t.Fatal("zero or partial record encoded")
		}
	}
	for _, mode := range []string{"unknown usage", "unknown transport", "overrun", "invalid result", "outcome persistence", "cost persistence"} {
		t.Run(mode, func(t *testing.T) {
			owner, d, _, _ := investigationOwnerFixture(t, mode, 100000, 3)
			r, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "unsafe"))
			if err == nil || r.Identity() != "" || !owner.State().Frozen() || d.count() != 1 {
				t.Fatal("unsafe effect unexpectedly produced a successful owner record")
			}
			if encoded, err := EncodeInvestigationTurnRecord(r); err == nil || len(encoded) != 0 {
				t.Fatal("unsafe effect became durable successful readback")
			}
			if mode == "overrun" && (!owner.State().UsageKnown() || owner.State().KnownCostMicroUSD() != 120000) {
				t.Fatal("known overrun accounting was weakened")
			}
		})
	}
}

func TestInvestigationTurnEncodingStrictSyntaxAndBounds(t *testing.T) {
	owner, _, _, _ := investigationOwnerFixture(t, "", 100000, 2)
	r, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "bounded-secret"))
	if err != nil {
		t.Fatal(err)
	}
	encoded := turnEncodingJSON(t, turnEncodingDocument(t, r))
	for name, invalid := range map[string][]byte{
		"empty": nil, "partial": []byte(`{"contract":"open-trestle/investigation-turn"}`), "array": []byte("[]"),
		"newline": append(append([]byte(nil), encoded...), '\n'), "space": append([]byte(" "), encoded...),
		"BOM": append([]byte{0xef, 0xbb, 0xbf}, encoded...), "trailing value": append(append([]byte(nil), encoded...), []byte("{}")...),
		"oversized":           bytes.Repeat([]byte{' '}, turnEncodingByteLimit+1),
		"version":             turnEncodingAt(t, encoded, "/schema_version", []byte("2")),
		"negative":            turnEncodingAt(t, encoded, "/ordinal", []byte("-1")),
		"fraction":            turnEncodingAt(t, encoded, "/ordinal", []byte("1.0")),
		"exponent":            turnEncodingAt(t, encoded, "/ordinal", []byte("1e0")),
		"uint8 overflow":      turnEncodingAt(t, encoded, "/ordinal", []byte("256")),
		"uint32 overflow":     turnEncodingAt(t, encoded, "/declared_input_tokens", []byte("4294967296")),
		"uint64 overflow":     turnEncodingAt(t, encoded, "/original_cap_micro_usd", []byte("18446744073709551616")),
		"int64 overflow":      turnEncodingAt(t, encoded, "/deadline_milliseconds", []byte("9223372036854775808")),
		"UTF-8":               turnEncodingAt(t, encoded, "/role", []byte{'"', 0xff, '"'}),
		"surrogate":           turnEncodingAt(t, encoded, "/role", []byte(`"\ud800"`)),
		"response UTF-8":      turnEncodingAt(t, encoded, "/dispatch/response/parts/0/payload_b64", turnEncodingJSON(t, base64.StdEncoding.EncodeToString([]byte{0xff}))),
		"base64 padding":      turnEncodingAt(t, encoded, "/request/payload_b64", []byte(`"YQ"`)),
		"base64 newline":      turnEncodingAt(t, encoded, "/request/payload_b64", []byte(`"YQ==\n"`)),
		"base64 pad bits":     turnEncodingAt(t, encoded, "/request/payload_b64", []byte(`"YR=="`)),
		"media limit":         turnEncodingAt(t, encoded, "/request/media_type", turnEncodingJSON(t, "application/"+strings.Repeat("x", 256))),
		"request limit":       turnEncodingAt(t, encoded, "/request/payload_b64", turnEncodingJSON(t, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, (8<<20)+1)))),
		"response part limit": turnEncodingAt(t, encoded, "/dispatch/response/parts/0/payload_b64", turnEncodingJSON(t, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, (2<<20)+1)))),
		"deep":                turnEncodingAt(t, encoded, "/request", []byte(strings.Repeat("[", 128)+"0"+strings.Repeat("]", 128))),
	} {
		t.Run(name, func(t *testing.T) { turnEncodingRefuse(t, invalid) })
	}
	for _, span := range turnEncodingSpans(t, encoded) {
		if delimiter, ok := span.value.(json.Delim); ok && delimiter == '{' {
			fragment := encoded[span.start:span.end]
			child := turnEncodingSpans(t, fragment)
			for _, member := range child {
				if strings.Count(member.path, "/") == 1 {
					key := turnEncodingJSON(t, strings.TrimPrefix(member.path, "/"))
					duplicate := append([]byte{'{'}, key...)
					duplicate = append(duplicate, ':')
					duplicate = append(duplicate, fragment[member.start:member.end]...)
					duplicate = append(duplicate, ',')
					duplicate = append(duplicate, fragment[1:]...)
					t.Run(span.path+member.path+"/duplicate", func(t *testing.T) { turnEncodingRefuse(t, turnEncodingReplace(encoded, span, duplicate)) })
					start, end := member.start-len(key)-1, member.end
					if end < len(fragment) && fragment[end] == ',' {
						end++
					} else if start > 0 && fragment[start-1] == ',' {
						start--
					}
					omitted := turnEncodingReplace(fragment, turnEncodingSpan{start: start, end: end}, nil)
					t.Run(span.path+member.path+"/missing", func(t *testing.T) { turnEncodingRefuse(t, turnEncodingReplace(encoded, span, omitted)) })
				}
			}
		}
	}
}

func TestInvestigationTurnEncodingRedactsErrorsAndFormatting(t *testing.T) {
	owner, _, _, _ := investigationOwnerFixture(t, "", 100000, 2)
	r, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "private-request-marker"))
	if err != nil {
		t.Fatal(err)
	}
	encoded := turnEncodingJSON(t, turnEncodingDocument(t, r))
	decoded := turnEncodingAssertRoundTrip(t, r)
	_, parseErr := ParseInvestigationTurnRecord(turnEncodingAt(t, encoded, "/role", []byte(`"private-response-marker"`)))
	invalid := r
	invalid.identity = "private-identity-marker"
	_, encodeErr := EncodeInvestigationTurnRecord(invalid)
	if parseErr == nil || encodeErr == nil {
		t.Fatal("invalid codec input did not return an error")
	}
	for _, value := range []any{decoded, decoded.request, decoded.ranking, decoded.selection, decoded.authorization, decoded.dispatch, decoded.dispatch.Response(), decoded.outcome, decoded.reconciliation, parseErr, encodeErr} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%s"} {
			text := fmt.Sprintf(verb, value)
			for _, secret := range []string{"private-request-marker", "private-response-marker", "private-identity-marker", r.Identity(), r.RequestIdentity(), r.dispatch.Response().Identity(), base64.StdEncoding.EncodeToString(r.request.Payload())} {
				if strings.Contains(text, secret) {
					t.Fatal("codec formatting or error exposed content or lineage")
				}
			}
		}
	}
}

type turnEncodingDispatcher struct {
	*investigationOwnerDispatcher
	response provider.Response
}

func (d *turnEncodingDispatcher) DispatchRoute(ctx context.Context, request RouteDispatchRequest) RouteDispatchResult {
	_ = d.investigationOwnerDispatcher.DispatchRoute(ctx, request)
	result, err := NewSuccessfulRouteDispatchResult(d.response)
	if err != nil {
		d.t.Error("fixture response refused")
	}
	return result
}

func turnEncodingRichRecord(t *testing.T, large bool) InvestigationTurnRecord {
	t.Helper()
	options, original, _, _ := investigationOwnerOptionsFixture(t, "", 30000000, 2)
	pricing, err := provider.NewRoutePricing(1000000, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	count, contextTokens := 3, uint64(140000)
	requestBytes := []byte(" { \"private-request-marker\": \"<&>\" }\r\n")
	partPayloads := [][]byte{[]byte("private-response-marker\r\n<&>"), []byte("other response part")}
	if large {
		count, contextTokens = 64, 20000000
		requestBytes = bytes.Repeat([]byte{'x'}, 8<<20)
		partPayloads = make([][]byte, 4)
		for i := range partPayloads {
			partPayloads[i] = bytes.Repeat([]byte{byte('a' + i)}, 2<<20)
		}
	}
	routes, observations := []ObservedRouteCandidate{}, []provider.RoutePerformanceObservation{}
	for i := 0; i < count; i++ {
		health := provider.RouteHealthHealthy
		if i == count-1 {
			health = provider.RouteHealthUnhealthy
		}
		route := newObservedRouteWithQuality(t, 21, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, pricing, provider.RouteQualityTier4, health, provider.RouteQuotaAvailable, contextTokens+uint64(i), 16000, provider.ModelFeatureStructuredOutput)
		routes = append(routes, route)
		observations = append(observations, routePerformance(t, route, 4, uint32(100+i)))
	}
	ranking, err := NewRouteRankingPolicy([]provider.RouteReference{observedRouteReference(routes[0])})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewInvestigationRoutePlan(21, routes, ranking, 4, observations)
	if err != nil {
		t.Fatal(err)
	}
	options.Generation, options.Verification = plan, plan
	parts := []provider.ResponsePart{}
	for _, payload := range partPayloads {
		part, err := provider.NewResponsePart(provider.ResponsePartAssistantText, "text/plain", payload)
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, part)
	}
	usage, err := provider.NewRouteTokenUsage(9000, 10000, 0)
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, parts, usage)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &turnEncodingDispatcher{original, response}
	options.Catalog, err = NewRouteDispatcherCatalog([]RouteDispatcher{dispatcher})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewInvestigationRouteOwner(options)
	if err != nil {
		t.Fatal(err)
	}
	request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/octet-stream", requestBytes)
	if err != nil {
		t.Fatal(err)
	}
	record, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, request)
	if err != nil || original.count() != 1 {
		t.Fatal("actual rich owner dispatch failed")
	}
	if len(record.selection.CandidateScores()) != count-1 || len(record.selection.Rejections()) != 1 {
		t.Fatal("fixture lost ranked candidates or actual rejection")
	}
	return record
}

func TestInvestigationTurnEncodingBoundaryPayloadsAndRouteCount(t *testing.T) {
	record := turnEncodingRichRecord(t, true)
	encoded := turnEncodingJSON(t, turnEncodingDocument(t, record))
	if len(encoded) >= turnEncodingByteLimit || len(record.request.Payload()) != 8<<20 || len(record.ranking.RankedRoutes()) != 63 {
		t.Fatal("fixture did not reach component boundaries within aggregate wire cap")
	}
	turnEncodingAssertRoundTrip(t, record)
}

func TestInvestigationTurnEncodingNestedCountsOrderingAndPayloadBindings(t *testing.T) {
	record := turnEncodingRichRecord(t, false)
	turnEncodingAssertRoundTrip(t, record)
	encoded := turnEncodingJSON(t, turnEncodingDocument(t, record))
	for _, path := range []string{"/request/payload_b64", "/dispatch/response/parts/0/payload_b64"} {
		turnEncodingRefuse(t, turnEncodingAt(t, encoded, path, turnEncodingJSON(t, base64.StdEncoding.EncodeToString([]byte("different valid payload")))))
	}
	for _, path := range []string{"/selection/candidate_scores", "/ranking/ranked_routes", "/dispatch/response/parts", "/selection/rejections"} {
		for _, span := range turnEncodingSpans(t, encoded) {
			if span.path != path {
				continue
			}
			var items []json.RawMessage
			if json.Unmarshal(encoded[span.start:span.end], &items) != nil || len(items) == 0 {
				t.Fatal("fixture array unavailable")
			}
			oversized := make([]json.RawMessage, 65)
			for i := range oversized {
				oversized[i] = items[0]
			}
			t.Run(path+"/count", func(t *testing.T) {
				turnEncodingRefuse(t, turnEncodingReplace(encoded, span, turnEncodingJSON(t, oversized)))
			})
			if len(items) > 1 {
				items[0], items[1] = items[1], items[0]
				t.Run(path+"/order", func(t *testing.T) {
					turnEncodingRefuse(t, turnEncodingReplace(encoded, span, turnEncodingJSON(t, items)))
				})
			}
		}
	}
}

// Manifest size is retained readback metadata, not a new accepted turn hash input.
func TestInvestigationTurnEncodingDoesNotInventManifestProvenanceBinding(t *testing.T) {
	record := turnEncodingRichRecord(t, false)
	changed := record
	changed.ranking.rankedRoutes = append([]RankedRoute(nil), record.ranking.rankedRoutes...)
	changed.ranking.rankedRoutes[0].route.resolvedRecord.evidenceManifestSizeBytes++
	if changed.Validate() != nil || changed.deriveIdentity() != record.Identity() {
		t.Fatal("accepted manifest metadata semantics changed")
	}
	decoded := turnEncodingAssertRoundTrip(t, changed)
	if decoded.ranking.rankedRoutes[0].route.resolvedRecord.EvidenceManifestSizeBytes() == record.ranking.rankedRoutes[0].route.resolvedRecord.EvidenceManifestSizeBytes() {
		t.Fatal("readback silently rewrote untrusted metadata")
	}
}

func TestInvestigationTurnEncodingRejectsFullyRehashedUnknownAndOverrun(t *testing.T) {
	owner, _, _, _ := investigationOwnerFixture(t, "", 100000, 2)
	actual, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "known-turn"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"unknown", "overrun"} {
		t.Run(mode, func(t *testing.T) {
			usage := provider.NewUnknownRouteTokenUsage()
			if mode == "overrun" {
				var err error
				usage, err = provider.NewRouteTokenUsage(110000, 10000, 0)
				if err != nil {
					t.Fatal(err)
				}
			}
			changed := actual
			response, err := provider.NewResponse(actual.dispatch.Response().Capability(), actual.dispatch.Response().FinishReason(), actual.dispatch.Response().Parts(), usage)
			if err != nil {
				t.Fatal(err)
			}
			changed.dispatch, err = NewSuccessfulRouteDispatchResult(response)
			if err != nil {
				t.Fatal(err)
			}
			changed.dispatch.authorizationIdentity = actual.authorization.Identity()
			changed.dispatch.identity = deriveRouteDispatchResultIdentity(changed.dispatch)
			changed.outcome, err = NewRouteAttemptOutcomeFromDispatch(changed.authorization, changed.dispatch, uint64(changed.finishedMillis-changed.startedMillis))
			if err != nil {
				t.Fatal(err)
			}
			changed.reconciliation, err = ReconcileAuthorizedRouteAttemptCost(changed.authorization, changed.outcome)
			if err != nil {
				t.Fatal(err)
			}
			changed.identity = changed.deriveIdentity()
			if changed.Validate() == nil {
				t.Fatal("unsafe component chain became a successful owner turn")
			}
			if encoded, err := EncodeInvestigationTurnRecord(changed); err == nil || len(encoded) != 0 {
				t.Fatal("unsafe rehashed record encoded")
			}
			turnEncodingRefuse(t, turnEncodingJSON(t, turnEncodingDocument(t, changed)))
		})
	}
}

func TestInvestigationTurnEncodingRawSchemaPreflight(t *testing.T) {
	record := turnEncodingRichRecord(t, false)
	encoded := turnEncodingJSON(t, turnEncodingDocument(t, record))
	if !preflightInvestigationTurn(encoded) {
		t.Fatal("canonical fixture failed raw schema preflight")
	}
	parts := make([]any, 5)
	partPayload := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, 2<<20))
	for i := range parts {
		parts[i] = map[string]any{"kind": "assistant_text", "media_type": "text/plain", "payload_b64": partPayload}
	}
	for name, invalid := range map[string][]byte{
		"oversized raw media":     turnEncodingAt(t, encoded, "/request/media_type", turnEncodingJSON(t, strings.Repeat("x", 1<<20))),
		"oversized escaped media": turnEncodingAt(t, encoded, "/request/media_type", []byte(`"`+strings.Repeat(`\u0078`, 256)+`"`)),
		"oversized model ID":      turnEncodingAt(t, encoded, "/ranking/ranked_routes/0/registry_record/model_id", turnEncodingJSON(t, strings.Repeat("x", 256))),
		"feature count":           turnEncodingAt(t, encoded, "/ranking/ranked_routes/0/registry_record/supported_features", []byte(`["vision","vision","vision","vision"]`)),
		"response aggregate":      turnEncodingAt(t, encoded, "/dispatch/response/parts", turnEncodingJSON(t, parts)),
		"unknown key":             append([]byte(`{"`+strings.Repeat("x", 1024)+`":0,`), encoded[1:]...),
	} {
		t.Run(name, func(t *testing.T) {
			if len(invalid) > turnEncodingByteLimit {
				t.Fatal("fixture bypassed field-specific checks through the outer limit")
			}
			if preflightInvestigationTurn(invalid) {
				t.Fatal("raw schema accepted an oversized field before materialization")
			}
			turnEncodingRefuse(t, invalid)
		})
	}
}
