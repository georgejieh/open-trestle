package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/provider"
)

const maximumInvestigationTurnEncodingBytes = 24 << 20

var errInvestigationTurnEncoding = errors.New("invalid investigation turn record encoding")

type investigationTurnBudgetWire struct {
	EstimatedInputTokens uint32 `json:"estimated_input_tokens"`
	MaxCostMicroUSD      uint64 `json:"max_cost_micro_usd"`
	MaxOutputTokens      uint32 `json:"max_output_tokens"`
}

type investigationTurnEstimateWire struct {
	InputCostMicroUSD   uint64 `json:"input_cost_micro_usd"`
	MaximumCostMicroUSD uint64 `json:"maximum_cost_micro_usd"`
	OutputCostMicroUSD  uint64 `json:"output_cost_micro_usd"`
}

type investigationTurnUsageWire struct {
	CachedInputTokens uint32 `json:"cached_input_tokens"`
	InputTokens       uint32 `json:"input_tokens"`
	Known             bool   `json:"known"`
	OutputTokens      uint32 `json:"output_tokens"`
}

type investigationTurnPerformanceWire struct {
	LatencyKnown        bool   `json:"latency_known"`
	ObservationRevision uint64 `json:"observation_revision"`
	P95Milliseconds     uint32 `json:"p95_milliseconds"`
	RecordIdentity      string `json:"record_identity"`
	SampleCount         uint32 `json:"sample_count"`
}

type investigationTurnRequestWire struct {
	Capability    string `json:"capability"`
	Identity      string `json:"identity"`
	MediaType     string `json:"media_type" limit:"255"`
	PayloadBase64 string `json:"payload_b64" limit:"8388608" payload:"request"`
}

type investigationTurnPartWire struct {
	Kind          string `json:"kind"`
	MediaType     string `json:"media_type" limit:"255"`
	PayloadBase64 string `json:"payload_b64" limit:"2097152" payload:"response"`
}

type investigationTurnResponseWire struct {
	Capability   string                      `json:"capability"`
	FinishReason string                      `json:"finish_reason"`
	Identity     string                      `json:"identity"`
	Parts        []investigationTurnPartWire `json:"parts" limit:"64"`
	Usage        investigationTurnUsageWire  `json:"usage"`
}

type investigationTurnDispatchWire struct {
	AuthorizationIdentity  string                        `json:"authorization_identity"`
	Failure                string                        `json:"failure"`
	Identity               string                        `json:"identity"`
	ReplaySafety           string                        `json:"replay_safety"`
	Response               investigationTurnResponseWire `json:"response"`
	RetryAfterMilliseconds uint32                        `json:"retry_after_milliseconds"`
	Status                 string                        `json:"status"`
	Usage                  investigationTurnUsageWire    `json:"usage"`
}

type investigationTurnOperationalWire struct {
	Health              string `json:"health"`
	ObservationRevision uint64 `json:"observation_revision"`
	Quota               string `json:"quota"`
	RecordIdentity      string `json:"record_identity"`
}

type investigationTurnRegistryWire struct {
	AdapterID              string   `json:"adapter_id"`
	ConnectionID           string   `json:"connection_id" limit:"128"`
	ContentLoggingMode     string   `json:"content_logging_mode"`
	EvidenceManifestDigest string   `json:"evidence_manifest_digest"`
	Identity               string   `json:"identity"`
	InputPrice             uint64   `json:"input_price_micro_usd_per_million_tokens"`
	MaxContextTokens       uint32   `json:"max_context_tokens"`
	MaxOutputTokens        uint32   `json:"max_output_tokens"`
	ModelID                string   `json:"model_id" limit:"255"`
	ModelVersion           string   `json:"model_version" limit:"128"`
	OutputPrice            uint64   `json:"output_price_micro_usd_per_million_tokens"`
	PricingKnown           bool     `json:"pricing_known"`
	ProviderID             string   `json:"provider_id"`
	ProviderZone           string   `json:"provider_zone"`
	QualityTier            string   `json:"quality_tier"`
	RegistryRevision       uint64   `json:"registry_revision"`
	Status                 string   `json:"status"`
	SupportedFeatures      []string `json:"supported_features" limit:"3"`
}

type investigationTurnRankedWire struct {
	EvidenceManifestSizeBytes uint32                           `json:"evidence_manifest_size_bytes"`
	MaximumCost               investigationTurnEstimateWire    `json:"maximum_cost"`
	OperationalState          investigationTurnOperationalWire `json:"operational_state"`
	Performance               investigationTurnPerformanceWire `json:"performance"`
	Pinned                    bool                             `json:"pinned"`
	PreferenceRank            uint8                            `json:"preference_rank"`
	RegistryRecord            investigationTurnRegistryWire    `json:"registry_record"`
}

type investigationTurnScoreWire struct {
	MaxContextTokens    uint32                           `json:"max_context_tokens"`
	MaxOutputTokens     uint32                           `json:"max_output_tokens"`
	MaximumCost         investigationTurnEstimateWire    `json:"maximum_cost"`
	OperationalRevision uint64                           `json:"operational_revision"`
	Performance         investigationTurnPerformanceWire `json:"performance"`
	Pinned              bool                             `json:"pinned"`
	PreferenceRank      uint8                            `json:"preference_rank"`
	QualityTier         string                           `json:"quality_tier"`
	RecordIdentity      string                           `json:"record_identity"`
}

type investigationTurnRejectionWire struct {
	OperationalRevision uint64 `json:"operational_revision"`
	Reason              string `json:"reason"`
	RecordIdentity      string `json:"record_identity"`
}

type investigationTurnRankingWire struct {
	CostBudget            investigationTurnBudgetWire   `json:"cost_budget"`
	PerformanceRevision   uint64                        `json:"performance_revision"`
	RankedRoutes          []investigationTurnRankedWire `json:"ranked_routes" limit:"64"`
	RankingPolicyIdentity string                        `json:"ranking_policy_identity"`
	RegistryRevision      uint64                        `json:"registry_revision"`
	RequestIdentity       string                        `json:"request_identity"`
	ReviewScopeIdentity   string                        `json:"review_scope_identity"`
	RoutingInputIdentity  string                        `json:"routing_input_identity"`
}

type investigationTurnSelectionWire struct {
	CandidateScores        []investigationTurnScoreWire     `json:"candidate_scores" limit:"64" count:"selection"`
	CostBudget             investigationTurnBudgetWire      `json:"cost_budget"`
	Identity               string                           `json:"identity"`
	PerformanceRevision    uint64                           `json:"performance_revision"`
	RankingPolicyIdentity  string                           `json:"ranking_policy_identity"`
	RegistryRevision       uint64                           `json:"registry_revision"`
	Rejections             []investigationTurnRejectionWire `json:"rejections" limit:"64" count:"selection"`
	RequestIdentity        string                           `json:"request_identity"`
	ReviewScopeIdentity    string                           `json:"review_scope_identity"`
	RoutingInputIdentity   string                           `json:"routing_input_identity"`
	SelectedRecordIdentity string                           `json:"selected_record_identity"`
}

type investigationTurnWire struct {
	ActualCostMicroUSD      uint64                         `json:"actual_cost_micro_usd"`
	Authorization           routeAuthorizationWire         `json:"authorization"`
	Contract                string                         `json:"contract"`
	DeadlineMilliseconds    int64                          `json:"deadline_milliseconds"`
	DeclaredInputTokens     uint32                         `json:"declared_input_tokens"`
	Dispatch                investigationTurnDispatchWire  `json:"dispatch"`
	EstimateVersion         uint8                          `json:"estimate_version"`
	FinishedMilliseconds    int64                          `json:"finished_milliseconds"`
	Identity                string                         `json:"identity"`
	MaxOutputTokens         uint32                         `json:"max_output_tokens"`
	Ordinal                 uint8                          `json:"ordinal"`
	OriginalCapMicroUSD     uint64                         `json:"original_cap_micro_usd"`
	Outcome                 routeOutcomeWire               `json:"outcome"`
	OwnerIdentity           string                         `json:"owner_identity"`
	PolicyIdentity          string                         `json:"policy_identity"`
	PreviousTurnIdentity    string                         `json:"previous_turn_identity"`
	Ranking                 investigationTurnRankingWire   `json:"ranking"`
	Reconciliation          routeReconciliationWire        `json:"reconciliation"`
	RemainingBeforeMicroUSD uint64                         `json:"remaining_before_micro_usd"`
	RemainingMicroUSD       uint64                         `json:"remaining_micro_usd"`
	Request                 investigationTurnRequestWire   `json:"request"`
	ReservedMicroUSD        uint64                         `json:"reserved_micro_usd"`
	Role                    string                         `json:"role"`
	SchemaVersion           int                            `json:"schema_version"`
	ScopeIdentity           string                         `json:"scope_identity"`
	Selection               investigationTurnSelectionWire `json:"selection"`
	SessionIdentity         string                         `json:"session_identity"`
	StartedMilliseconds     int64                          `json:"started_milliseconds"`
}

// The schema is built from fixed host types, never from untrusted JSON.
type investigationTurnShape struct {
	kind           reflect.Kind
	bits           int
	limit          int
	payload        string
	selectionCount bool
	fields         []investigationTurnField
	element        *investigationTurnShape
}

type investigationTurnField struct {
	prefix string
	shape  *investigationTurnShape
}

var investigationTurnEncodingShape = newInvestigationTurnShape(reflect.TypeOf(investigationTurnWire{}), "", "")

func newInvestigationTurnShape(value reflect.Type, name string, tag reflect.StructTag) *investigationTurnShape {
	shape := &investigationTurnShape{kind: value.Kind(), payload: tag.Get("payload"), selectionCount: tag.Get("count") == "selection"}
	switch value.Kind() {
	case reflect.Struct:
		shape.fields = make([]investigationTurnField, value.NumField())
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			key := field.Tag.Get("json")
			shape.fields[i] = investigationTurnField{prefix: `"` + key + `":`, shape: newInvestigationTurnShape(field.Type, key, field.Tag)}
		}
	case reflect.Slice:
		shape.element = newInvestigationTurnShape(value.Elem(), "", "")
	case reflect.String:
		shape.limit = 64
		switch name {
		case "media_type", "model_id":
			shape.limit = 255
		case "model_version", "connection_id":
			shape.limit = 128
		}
	case reflect.Int, reflect.Int64, reflect.Uint8, reflect.Uint32, reflect.Uint64:
		shape.bits = value.Bits()
	}
	if limit := tag.Get("limit"); limit != "" {
		shape.limit, _ = strconv.Atoi(limit)
	}
	return shape
}

type investigationTurnScan struct {
	input          []byte
	offset         int
	responseBytes  int
	selectionCount int
}

func preflightInvestigationTurn(encoded []byte) bool {
	if len(encoded) == 0 || len(encoded) > maximumInvestigationTurnEncodingBytes || !utf8.Valid(encoded) {
		return false
	}
	scan := investigationTurnScan{input: encoded}
	return scan.value(investigationTurnEncodingShape, 0) && scan.offset == len(encoded)
}

func (s *investigationTurnScan) take(value string) bool {
	if len(s.input)-s.offset < len(value) || !bytes.Equal(s.input[s.offset:s.offset+len(value)], []byte(value)) {
		return false
	}
	s.offset += len(value)
	return true
}

func (s *investigationTurnScan) value(shape *investigationTurnShape, depth int) bool {
	if depth > 16 || s.offset >= len(s.input) {
		return false
	}
	switch shape.kind {
	case reflect.Struct:
		if !s.take("{") {
			return false
		}
		for i, field := range shape.fields {
			if i > 0 && !s.take(",") {
				return false
			}
			if !s.take(field.prefix) || !s.value(field.shape, depth+1) {
				return false
			}
		}
		return s.take("}")
	case reflect.Slice:
		if !s.take("[") {
			return false
		}
		if s.take("]") {
			return true
		}
		for count := 0; ; count++ {
			if count >= shape.limit {
				return false
			}
			if shape.selectionCount {
				s.selectionCount++
				if s.selectionCount > maxRouteFilterCandidates {
					return false
				}
			}
			if !s.value(shape.element, depth+1) {
				return false
			}
			if s.take("]") {
				return true
			}
			if !s.take(",") {
				return false
			}
		}
	case reflect.String:
		if shape.payload != "" {
			return s.base64Payload(shape)
		}
		return s.text(shape.limit)
	case reflect.Bool:
		return s.take("true") || s.take("false")
	case reflect.Int, reflect.Int64, reflect.Uint8, reflect.Uint32, reflect.Uint64:
		start := s.offset
		signed := shape.kind == reflect.Int || shape.kind == reflect.Int64
		if signed && s.input[s.offset] == '-' {
			s.offset++
		}
		digits := s.offset
		for s.offset < len(s.input) && s.input[s.offset] >= '0' && s.input[s.offset] <= '9' {
			s.offset++
			if s.offset-start > 20 {
				return false
			}
		}
		if s.offset == digits || s.input[digits] == '0' && (s.offset-digits > 1 || digits != start) {
			return false
		}
		if signed {
			_, err := strconv.ParseInt(string(s.input[start:s.offset]), 10, shape.bits)
			return err == nil
		}
		_, err := strconv.ParseUint(string(s.input[start:s.offset]), 10, shape.bits)
		return err == nil
	}
	return false
}

func (s *investigationTurnScan) text(limit int) bool {
	if !s.take(`"`) {
		return false
	}
	start, decoded := s.offset, 0
	for s.offset < len(s.input) && s.offset-start <= 6*limit {
		value := s.input[s.offset]
		s.offset++
		if value == '"' {
			return decoded <= limit
		}
		if value < 0x20 {
			return false
		}
		if value != '\\' {
			decoded++
		} else {
			if s.offset >= len(s.input) {
				return false
			}
			escape := s.input[s.offset]
			s.offset++
			switch escape {
			case '"', '\\', 'b', 'f', 'n', 'r', 't':
				decoded++
			case 'u':
				code, ok := s.hexRune()
				if !ok {
					return false
				}
				if code >= 0xd800 && code <= 0xdbff {
					if !s.take(`\u`) {
						return false
					}
					low, ok := s.hexRune()
					if !ok || low < 0xdc00 || low > 0xdfff {
						return false
					}
					code = 0x10000 + (code-0xd800)*0x400 + low - 0xdc00
				} else if code >= 0xdc00 && code <= 0xdfff {
					return false
				}
				decoded += utf8.RuneLen(code)
			default:
				return false
			}
		}
		if decoded > limit {
			return false
		}
	}
	return false
}

func (s *investigationTurnScan) hexRune() (rune, bool) {
	if len(s.input)-s.offset < 4 {
		return 0, false
	}
	var value rune
	for i := 0; i < 4; i++ {
		char := s.input[s.offset]
		s.offset++
		var digit byte
		switch {
		case char >= '0' && char <= '9':
			digit = char - '0'
		case char >= 'a' && char <= 'f':
			digit = char - 'a' + 10
		case char >= 'A' && char <= 'F':
			digit = char - 'A' + 10
		default:
			return 0, false
		}
		value = value*16 + rune(digit)
	}
	return value, true
}

func investigationBase64Digit(value byte) int {
	switch {
	case value >= 'A' && value <= 'Z':
		return int(value - 'A')
	case value >= 'a' && value <= 'z':
		return int(value-'a') + 26
	case value >= '0' && value <= '9':
		return int(value-'0') + 52
	case value == '+':
		return 62
	case value == '/':
		return 63
	}
	return -1
}

func (s *investigationTurnScan) base64Payload(shape *investigationTurnShape) bool {
	if !s.take(`"`) {
		return false
	}
	start := s.offset
	maximum := base64.StdEncoding.EncodedLen(shape.limit)
	searchEnd := start + min(len(s.input)-start, maximum+1)
	length := bytes.IndexByte(s.input[start:searchEnd], '"')
	if length <= 0 || length%4 != 0 {
		return false
	}
	data := s.input[start : start+length]
	padding := 0
	if data[length-1] == '=' {
		padding++
		if data[length-2] == '=' {
			padding++
		}
	}
	decoded := length/4*3 - padding
	if decoded > shape.limit {
		return false
	}
	for _, value := range data[:length-padding] {
		if investigationBase64Digit(value) < 0 {
			return false
		}
	}
	last := investigationBase64Digit(data[length-padding-1])
	if padding == 1 && last&3 != 0 || padding == 2 && last&15 != 0 {
		return false
	}
	if shape.payload == "response" {
		s.responseBytes += decoded
		if s.responseBytes > 8<<20 {
			return false
		}
	}
	s.offset += length + 1
	return true
}

// EncodeInvestigationTurnRecord encodes retained readback, not issuer or execution authority.
// The pure codec limit is independent of the smaller protected artifact payload limit.
func EncodeInvestigationTurnRecord(record InvestigationTurnRecord) ([]byte, error) {
	if record.Validate() != nil {
		return nil, errInvestigationTurnEncoding
	}
	encoded, err := json.Marshal(investigationTurnWireValue(record))
	if err != nil || !preflightInvestigationTurn(encoded) {
		return nil, errInvestigationTurnEncoding
	}
	return encoded, nil
}

// ParseInvestigationTurnRecord reconstructs retained components without restoring an owner.
// Enclosing trusted evidence must establish expected identities, scope and origin.
func ParseInvestigationTurnRecord(encoded []byte) (InvestigationTurnRecord, error) {
	if !preflightInvestigationTurn(encoded) {
		return InvestigationTurnRecord{}, errInvestigationTurnEncoding
	}
	var wire investigationTurnWire
	if json.Unmarshal(encoded, &wire) != nil {
		return InvestigationTurnRecord{}, errInvestigationTurnEncoding
	}
	record, err := parseInvestigationTurnWire(wire)
	if err != nil {
		return InvestigationTurnRecord{}, errInvestigationTurnEncoding
	}
	canonical, err := EncodeInvestigationTurnRecord(record)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return InvestigationTurnRecord{}, errInvestigationTurnEncoding
	}
	return record, nil
}

func investigationTurnBudgetValue(budget provider.ModelCostBudget) investigationTurnBudgetWire {
	return investigationTurnBudgetWire{EstimatedInputTokens: budget.EstimatedInputTokens(), MaxCostMicroUSD: budget.MaxCostMicroUSD(), MaxOutputTokens: budget.MaxOutputTokens()}
}

func investigationTurnEstimateValue(estimate provider.RouteCostEstimate) investigationTurnEstimateWire {
	return investigationTurnEstimateWire{InputCostMicroUSD: estimate.InputCostMicroUSD(), MaximumCostMicroUSD: estimate.MaximumCostMicroUSD(), OutputCostMicroUSD: estimate.OutputCostMicroUSD()}
}

func investigationTurnUsageValue(usage provider.RouteTokenUsage) investigationTurnUsageWire {
	return investigationTurnUsageWire{CachedInputTokens: usage.CachedInputTokens(), InputTokens: usage.InputTokens(), Known: usage.IsKnown(), OutputTokens: usage.OutputTokens()}
}

func investigationTurnPerformanceValue(performance provider.RoutePerformanceObservation) investigationTurnPerformanceWire {
	return investigationTurnPerformanceWire{LatencyKnown: performance.LatencyKnown(), ObservationRevision: performance.ObservationRevision(), P95Milliseconds: performance.P95LatencyMilliseconds(), RecordIdentity: performance.RecordIdentity(), SampleCount: performance.SampleCount()}
}

func investigationTurnRegistryValue(record provider.RouteRegistryRecord) investigationTurnRegistryWire {
	candidate := record.RouteCandidateDeclaration()
	capability := candidate.RouteCapabilityDeclaration()
	route, model := capability.RouteReference(), capability.ModelCapabilities()
	features := make([]string, 0, 3)
	for _, feature := range model.SupportedFeatures() {
		features = append(features, feature.String())
	}
	return investigationTurnRegistryWire{
		AdapterID: route.AdapterID(), ConnectionID: route.ConnectionID(), ContentLoggingMode: candidate.ContentLoggingMode().String(),
		EvidenceManifestDigest: record.EvidenceManifestDigest(), Identity: record.Identity(), InputPrice: candidate.RoutePricing().InputMicroUSDPerMillionTokens(),
		MaxContextTokens: model.MaxContextTokens(), MaxOutputTokens: model.MaxOutputTokens(), ModelID: route.ModelID(), ModelVersion: route.ModelVersion(),
		OutputPrice: candidate.RoutePricing().OutputMicroUSDPerMillionTokens(), PricingKnown: candidate.RoutePricing().IsKnown(),
		ProviderID: route.ProviderID(), ProviderZone: route.Zone().String(), QualityTier: candidate.RouteQualityTier().String(),
		RegistryRevision: record.RegistryRevision(), Status: record.Status().String(), SupportedFeatures: features,
	}
}

func investigationTurnRankingValue(ranking RouteRankingResult) investigationTurnRankingWire {
	routes := make([]investigationTurnRankedWire, 0, len(ranking.rankedRoutes))
	for _, ranked := range ranking.rankedRoutes {
		resolved, state := ranked.route.ResolvedRecord(), ranked.route.OperationalState()
		routes = append(routes, investigationTurnRankedWire{
			EvidenceManifestSizeBytes: resolved.EvidenceManifestSizeBytes(), MaximumCost: investigationTurnEstimateValue(ranked.maximumCost),
			OperationalState: investigationTurnOperationalWire{Health: state.Health().String(), ObservationRevision: state.ObservationRevision(), Quota: state.Quota().String(), RecordIdentity: state.RecordIdentity()},
			Performance:      investigationTurnPerformanceValue(ranked.performance), Pinned: ranked.pinned, PreferenceRank: ranked.preferenceRank,
			RegistryRecord: investigationTurnRegistryValue(resolved.RouteRegistryRecord()),
		})
	}
	return investigationTurnRankingWire{
		CostBudget: investigationTurnBudgetValue(ranking.costBudget), PerformanceRevision: ranking.performanceRevision, RankedRoutes: routes,
		RankingPolicyIdentity: ranking.rankingPolicyIdentity, RegistryRevision: ranking.registryRevision,
		RequestIdentity: ranking.requestIdentity, ReviewScopeIdentity: ranking.reviewScopeIdentity, RoutingInputIdentity: ranking.routingInputIdentity,
	}
}

func investigationTurnSelectionValue(selection RouteSelectionReceipt) investigationTurnSelectionWire {
	scores := make([]investigationTurnScoreWire, 0, len(selection.candidateScores))
	for _, score := range selection.candidateScores {
		scores = append(scores, investigationTurnScoreWire{
			MaxContextTokens: score.maxContextTokens, MaxOutputTokens: score.maxOutputTokens, MaximumCost: investigationTurnEstimateValue(score.maximumCost),
			OperationalRevision: score.operationalRevision, Performance: investigationTurnPerformanceValue(score.performance), Pinned: score.pinned,
			PreferenceRank: score.preferenceRank, QualityTier: score.qualityTier.String(), RecordIdentity: score.recordIdentity,
		})
	}
	rejections := make([]investigationTurnRejectionWire, 0, len(selection.rejections))
	for _, rejection := range selection.rejections {
		rejections = append(rejections, investigationTurnRejectionWire{OperationalRevision: rejection.OperationalRevision(), Reason: rejection.Reason().String(), RecordIdentity: rejection.RecordIdentity()})
	}
	return investigationTurnSelectionWire{
		CandidateScores: scores, CostBudget: investigationTurnBudgetValue(selection.costBudget), Identity: selection.identity,
		PerformanceRevision: selection.performanceRevision, RankingPolicyIdentity: selection.rankingPolicyIdentity,
		RegistryRevision: selection.registryRevision, Rejections: rejections, RequestIdentity: selection.requestIdentity,
		ReviewScopeIdentity: selection.reviewScopeIdentity, RoutingInputIdentity: selection.routingInputIdentity, SelectedRecordIdentity: selection.selectedRecordIdentity,
	}
}

func investigationTurnResponseValue(response provider.Response) investigationTurnResponseWire {
	parts := make([]investigationTurnPartWire, 0, response.PartCount())
	for _, part := range response.Parts() {
		parts = append(parts, investigationTurnPartWire{Kind: part.Kind().String(), MediaType: part.MediaType(), PayloadBase64: base64.StdEncoding.EncodeToString(part.Payload())})
	}
	return investigationTurnResponseWire{Capability: response.Capability().String(), FinishReason: response.FinishReason().String(), Identity: response.Identity(), Parts: parts, Usage: investigationTurnUsageValue(response.Usage())}
}

func investigationTurnWireValue(record InvestigationTurnRecord) investigationTurnWire {
	dispatch, outcome, cost := record.dispatch, record.outcome, record.reconciliation
	actual := cost.ActualCost()
	return investigationTurnWire{
		ActualCostMicroUSD: actual.TotalCostMicroUSD(), Authorization: routeAuthorizationWireValue(record.authorization),
		Contract: "open-trestle/investigation-turn", DeadlineMilliseconds: record.deadlineMillis, DeclaredInputTokens: record.declaredInput,
		Dispatch: investigationTurnDispatchWire{
			AuthorizationIdentity: dispatch.AuthorizationIdentity(), Failure: dispatch.Failure().String(), Identity: dispatch.Identity(), ReplaySafety: dispatch.ReplaySafety().String(),
			Response: investigationTurnResponseValue(dispatch.Response()), RetryAfterMilliseconds: dispatch.RetryAfterMilliseconds(), Status: dispatch.Status().String(), Usage: investigationTurnUsageValue(dispatch.Usage()),
		},
		EstimateVersion: record.estimateVersion, FinishedMilliseconds: record.finishedMillis, Identity: record.identity,
		MaxOutputTokens: record.maxOutput, Ordinal: record.ordinal, OriginalCapMicroUSD: record.originalCap,
		Outcome: routeOutcomeWire{
			Identity: outcome.Identity(), Status: outcome.Status().String(), ResponseIdentity: outcome.ResponseIdentity(), UsageKnown: outcome.Usage().IsKnown(),
			InputTokens: outcome.Usage().InputTokens(), OutputTokens: outcome.Usage().OutputTokens(), CachedInputTokens: outcome.Usage().CachedInputTokens(),
			Failure: outcome.Failure().String(), ReplaySafety: outcome.ReplaySafety().String(), RetryAfterMilliseconds: outcome.RetryAfterMilliseconds(), DurationMilliseconds: outcome.DurationMilliseconds(),
		},
		OwnerIdentity: record.ownerIdentity, PolicyIdentity: record.policyIdentity, PreviousTurnIdentity: record.previous,
		Ranking: investigationTurnRankingValue(record.ranking),
		Reconciliation: routeReconciliationWire{
			Identity: cost.Identity(), Status: cost.Status().String(), ReservedCostMicroUSD: cost.ReservedCostMicroUSD(), ActualKnown: actual.IsKnown(),
			ActualInputCostMicroUSD: actual.InputCostMicroUSD(), ActualOutputCostMicroUSD: actual.OutputCostMicroUSD(), ActualTotalCostMicroUSD: actual.TotalCostMicroUSD(),
			RemainingAfterReservationMicroUSD: cost.RemainingAfterReservationMicroUSD(), RemainingCostMicroUSD: cost.RemainingCostMicroUSD(), BudgetOverrunMicroUSD: cost.BudgetOverrunMicroUSD(),
		},
		RemainingBeforeMicroUSD: record.authorization.RemainingCostBeforeMicroUSD(), RemainingMicroUSD: cost.RemainingCostMicroUSD(),
		Request:          investigationTurnRequestWire{Capability: record.request.Capability().String(), Identity: record.request.Identity(), MediaType: record.request.MediaType(), PayloadBase64: base64.StdEncoding.EncodeToString(record.request.Payload())},
		ReservedMicroUSD: record.authorization.ReservedCostMicroUSD(), Role: record.role.String(), SchemaVersion: 1, ScopeIdentity: record.scopeIdentity,
		Selection: investigationTurnSelectionValue(record.selection), SessionIdentity: record.sessionIdentity, StartedMilliseconds: record.startedMillis,
	}
}

func parseInvestigationTurnBudget(wire investigationTurnBudgetWire) (provider.ModelCostBudget, error) {
	return provider.NewModelCostBudget(uint64(wire.EstimatedInputTokens), uint64(wire.MaxOutputTokens), wire.MaxCostMicroUSD)
}

func parseInvestigationTurnUsage(wire investigationTurnUsageWire) (provider.RouteTokenUsage, error) {
	if wire.Known {
		return provider.NewRouteTokenUsage(uint64(wire.InputTokens), uint64(wire.OutputTokens), uint64(wire.CachedInputTokens))
	}
	if wire.InputTokens != 0 || wire.OutputTokens != 0 || wire.CachedInputTokens != 0 {
		return provider.RouteTokenUsage{}, errInvestigationTurnEncoding
	}
	return provider.NewUnknownRouteTokenUsage(), nil
}

func parseInvestigationTurnPerformance(wire investigationTurnPerformanceWire) (provider.RoutePerformanceObservation, error) {
	if wire.LatencyKnown {
		return provider.NewKnownRoutePerformanceObservation(wire.RecordIdentity, wire.ObservationRevision, wire.P95Milliseconds, wire.SampleCount)
	}
	if wire.P95Milliseconds != 0 || wire.SampleCount != 0 {
		return provider.RoutePerformanceObservation{}, errInvestigationTurnEncoding
	}
	return provider.NewUnknownRoutePerformanceObservation(wire.RecordIdentity, wire.ObservationRevision)
}

func parseInvestigationTurnRegistry(wire investigationTurnRegistryWire) (provider.RouteRegistryRecord, error) {
	zone, err := provider.ParseProviderZone(wire.ProviderZone)
	if err != nil {
		return provider.RouteRegistryRecord{}, err
	}
	route, err := provider.NewRouteReference(zone, wire.ProviderID, wire.AdapterID, wire.ConnectionID, wire.ModelID, wire.ModelVersion)
	if err != nil {
		return provider.RouteRegistryRecord{}, err
	}
	features := make([]provider.ModelFeature, 0, len(wire.SupportedFeatures))
	for _, token := range wire.SupportedFeatures {
		feature, err := provider.ParseModelFeature(token)
		if err != nil {
			return provider.RouteRegistryRecord{}, err
		}
		features = append(features, feature)
	}
	model, err := provider.NewModelCapabilities(uint64(wire.MaxContextTokens), uint64(wire.MaxOutputTokens), features)
	if err != nil {
		return provider.RouteRegistryRecord{}, err
	}
	capability, err := provider.NewRouteCapabilityDeclaration(route, model)
	if err != nil {
		return provider.RouteRegistryRecord{}, err
	}
	logging, err := provider.ParseContentLoggingMode(wire.ContentLoggingMode)
	if err != nil {
		return provider.RouteRegistryRecord{}, err
	}
	pricing := provider.NewUnknownRoutePricing()
	if wire.PricingKnown {
		pricing, err = provider.NewRoutePricing(wire.InputPrice, wire.OutputPrice)
		if err != nil {
			return provider.RouteRegistryRecord{}, err
		}
	} else if wire.InputPrice != 0 || wire.OutputPrice != 0 {
		return provider.RouteRegistryRecord{}, errInvestigationTurnEncoding
	}
	quality, err := provider.ParseRouteQualityTier(wire.QualityTier)
	if err != nil {
		return provider.RouteRegistryRecord{}, err
	}
	candidate, err := provider.NewRouteCandidateDeclaration(capability, logging, pricing, quality)
	if err != nil {
		return provider.RouteRegistryRecord{}, err
	}
	status, err := provider.ParseRouteRegistryStatus(wire.Status)
	if err != nil {
		return provider.RouteRegistryRecord{}, err
	}
	record, err := provider.NewRouteRegistryRecord(wire.RegistryRevision, candidate, status, wire.EvidenceManifestDigest)
	if err != nil || record.Identity() != wire.Identity {
		return provider.RouteRegistryRecord{}, errInvestigationTurnEncoding
	}
	return record, nil
}

func parseInvestigationTurnRanked(wire investigationTurnRankedWire, budget provider.ModelCostBudget) (RankedRoute, error) {
	record, err := parseInvestigationTurnRegistry(wire.RegistryRecord)
	if err != nil {
		return RankedRoute{}, err
	}
	// This metadata is retained readback, not a repeated registry lookup or manifest check.
	resolved := ResolvedRouteRegistryRecord{record: record, evidenceManifestSizeBytes: wire.EvidenceManifestSizeBytes}
	if resolved.Validate() != nil {
		return RankedRoute{}, errInvestigationTurnEncoding
	}
	health, err := provider.ParseRouteHealth(wire.OperationalState.Health)
	if err != nil {
		return RankedRoute{}, err
	}
	quota, err := provider.ParseRouteQuota(wire.OperationalState.Quota)
	if err != nil {
		return RankedRoute{}, err
	}
	state, err := provider.NewRouteOperationalState(wire.OperationalState.RecordIdentity, wire.OperationalState.ObservationRevision, health, quota)
	if err != nil {
		return RankedRoute{}, err
	}
	route, err := NewObservedRouteCandidate(resolved, state)
	if err != nil {
		return RankedRoute{}, err
	}
	performance, err := parseInvestigationTurnPerformance(wire.Performance)
	if err != nil {
		return RankedRoute{}, err
	}
	cost, err := provider.EstimateMaximumRouteCost(record.RouteCandidateDeclaration().RoutePricing(), budget)
	if err != nil || investigationTurnEstimateValue(cost) != wire.MaximumCost {
		return RankedRoute{}, errInvestigationTurnEncoding
	}
	return RankedRoute{route: route, performance: performance, pinned: wire.Pinned, preferenceRank: wire.PreferenceRank, maximumCost: cost}, nil
}

func parseInvestigationTurnRanking(wire investigationTurnRankingWire) (RouteRankingResult, error) {
	budget, err := parseInvestigationTurnBudget(wire.CostBudget)
	if err != nil {
		return RouteRankingResult{}, err
	}
	routes := make([]RankedRoute, 0, len(wire.RankedRoutes))
	for _, value := range wire.RankedRoutes {
		ranked, err := parseInvestigationTurnRanked(value, budget)
		if err != nil {
			return RouteRankingResult{}, err
		}
		routes = append(routes, ranked)
	}
	ranking := RouteRankingResult{
		requestIdentity: wire.RequestIdentity, reviewScopeIdentity: wire.ReviewScopeIdentity, routingInputIdentity: wire.RoutingInputIdentity,
		registryRevision: wire.RegistryRevision, performanceRevision: wire.PerformanceRevision, costBudget: budget,
		rankingPolicyIdentity: wire.RankingPolicyIdentity, rankedRoutes: routes,
	}
	if ranking.Validate() != nil {
		return RouteRankingResult{}, errInvestigationTurnEncoding
	}
	return ranking, nil
}

func parseInvestigationTurnSelection(wire investigationTurnSelectionWire, ranking RouteRankingResult) (RouteSelectionReceipt, error) {
	if len(wire.CandidateScores) != len(ranking.rankedRoutes) {
		return RouteSelectionReceipt{}, errInvestigationTurnEncoding
	}
	budget, err := parseInvestigationTurnBudget(wire.CostBudget)
	if err != nil {
		return RouteSelectionReceipt{}, err
	}
	scores := make([]RouteSelectionCandidateScore, 0, len(wire.CandidateScores))
	for i, value := range wire.CandidateScores {
		performance, err := parseInvestigationTurnPerformance(value.Performance)
		if err != nil {
			return RouteSelectionReceipt{}, err
		}
		quality, err := provider.ParseRouteQualityTier(value.QualityTier)
		if err != nil {
			return RouteSelectionReceipt{}, err
		}
		cost := ranking.rankedRoutes[i].maximumCost
		if investigationTurnEstimateValue(cost) != value.MaximumCost {
			return RouteSelectionReceipt{}, errInvestigationTurnEncoding
		}
		scores = append(scores, RouteSelectionCandidateScore{
			recordIdentity: value.RecordIdentity, operationalRevision: value.OperationalRevision, performance: performance,
			pinned: value.Pinned, preferenceRank: value.PreferenceRank, qualityTier: quality,
			maxContextTokens: value.MaxContextTokens, maxOutputTokens: value.MaxOutputTokens, maximumCost: cost,
		})
	}
	rejections := make([]RouteRejection, 0, len(wire.Rejections))
	for _, value := range wire.Rejections {
		reason, err := ParseRouteRejectionReason(value.Reason)
		if err != nil {
			return RouteSelectionReceipt{}, err
		}
		rejections = append(rejections, RouteRejection{recordIdentity: value.RecordIdentity, operationalRevision: value.OperationalRevision, reason: reason})
	}
	selection := RouteSelectionReceipt{
		identity: wire.Identity, requestIdentity: wire.RequestIdentity, reviewScopeIdentity: wire.ReviewScopeIdentity,
		routingInputIdentity: wire.RoutingInputIdentity, registryRevision: wire.RegistryRevision, performanceRevision: wire.PerformanceRevision,
		costBudget: budget, rankingPolicyIdentity: wire.RankingPolicyIdentity, selectedRecordIdentity: wire.SelectedRecordIdentity,
		candidateScores: scores, rejections: rejections,
	}
	if selection.Validate() != nil || !fallbackSelectionMatchesRanking(selection, ranking) {
		return RouteSelectionReceipt{}, errInvestigationTurnEncoding
	}
	return selection, nil
}

func parseInvestigationTurnRequest(wire investigationTurnRequestWire) (provider.Request, error) {
	capability, err := provider.ParseCapability(wire.Capability)
	if err != nil {
		return provider.Request{}, err
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(wire.PayloadBase64)
	if err != nil {
		return provider.Request{}, err
	}
	request, err := provider.NewRequest(capability, wire.MediaType, payload)
	if err != nil || request.Identity() != wire.Identity {
		return provider.Request{}, errInvestigationTurnEncoding
	}
	return request, nil
}

func parseInvestigationTurnResponse(wire investigationTurnResponseWire) (provider.Response, error) {
	capability, err := provider.ParseCapability(wire.Capability)
	if err != nil {
		return provider.Response{}, err
	}
	finish, err := provider.ParseResponseFinishReason(wire.FinishReason)
	if err != nil {
		return provider.Response{}, err
	}
	usage, err := parseInvestigationTurnUsage(wire.Usage)
	if err != nil {
		return provider.Response{}, err
	}
	parts := make([]provider.ResponsePart, 0, len(wire.Parts))
	for _, value := range wire.Parts {
		kind, err := provider.ParseResponsePartKind(value.Kind)
		if err != nil {
			return provider.Response{}, err
		}
		payload, err := base64.StdEncoding.Strict().DecodeString(value.PayloadBase64)
		if err != nil {
			return provider.Response{}, err
		}
		part, err := provider.NewResponsePart(kind, value.MediaType, payload)
		if err != nil {
			return provider.Response{}, err
		}
		parts = append(parts, part)
	}
	response, err := provider.NewResponse(capability, finish, parts, usage)
	if err != nil || response.Identity() != wire.Identity {
		return provider.Response{}, errInvestigationTurnEncoding
	}
	return response, nil
}

func parseInvestigationTurnDispatch(wire investigationTurnDispatchWire) (RouteDispatchResult, error) {
	if wire.Status != RouteDispatchSucceeded.String() || wire.Failure != "" || wire.ReplaySafety != "" || wire.RetryAfterMilliseconds != 0 {
		return RouteDispatchResult{}, errInvestigationTurnEncoding
	}
	response, err := parseInvestigationTurnResponse(wire.Response)
	if err != nil {
		return RouteDispatchResult{}, err
	}
	usage, err := parseInvestigationTurnUsage(wire.Usage)
	if err != nil || usage != response.Usage() {
		return RouteDispatchResult{}, errInvestigationTurnEncoding
	}
	dispatch, err := NewSuccessfulRouteDispatchResult(response)
	if err != nil {
		return RouteDispatchResult{}, err
	}
	dispatch.authorizationIdentity = wire.AuthorizationIdentity
	dispatch.identity = deriveRouteDispatchResultIdentity(dispatch)
	if dispatch.Validate() != nil || dispatch.Identity() != wire.Identity {
		return RouteDispatchResult{}, errInvestigationTurnEncoding
	}
	return dispatch, nil
}

func parseInvestigationTurnWire(wire investigationTurnWire) (InvestigationTurnRecord, error) {
	if wire.Contract != "open-trestle/investigation-turn" || wire.SchemaVersion != 1 {
		return InvestigationTurnRecord{}, errInvestigationTurnEncoding
	}
	var role InvestigationTurnRole
	switch wire.Role {
	case InvestigationGenerationTurn.String():
		role = InvestigationGenerationTurn
	case InvestigationVerificationTurn.String():
		role = InvestigationVerificationTurn
	default:
		return InvestigationTurnRecord{}, errInvestigationTurnEncoding
	}
	request, err := parseInvestigationTurnRequest(wire.Request)
	if err != nil {
		return InvestigationTurnRecord{}, err
	}
	ranking, err := parseInvestigationTurnRanking(wire.Ranking)
	if err != nil {
		return InvestigationTurnRecord{}, err
	}
	selection, err := parseInvestigationTurnSelection(wire.Selection, ranking)
	if err != nil {
		return InvestigationTurnRecord{}, err
	}
	authorizationBytes, err := json.Marshal(wire.Authorization)
	if err != nil {
		return InvestigationTurnRecord{}, err
	}
	authorization, err := ParseRouteAttemptAuthorization(authorizationBytes)
	if err != nil {
		return InvestigationTurnRecord{}, err
	}
	dispatch, err := parseInvestigationTurnDispatch(wire.Dispatch)
	if err != nil {
		return InvestigationTurnRecord{}, err
	}
	outcome, err := parseRouteOutcomeWire(authorization, wire.Outcome)
	if err != nil {
		return InvestigationTurnRecord{}, err
	}
	cost, err := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	if err != nil || !reconciliationWireMatches(wire.Reconciliation, cost) {
		return InvestigationTurnRecord{}, errInvestigationTurnEncoding
	}
	if wire.ActualCostMicroUSD != cost.ActualCost().TotalCostMicroUSD() || wire.RemainingBeforeMicroUSD != authorization.RemainingCostBeforeMicroUSD() || wire.RemainingMicroUSD != cost.RemainingCostMicroUSD() || wire.ReservedMicroUSD != authorization.ReservedCostMicroUSD() {
		return InvestigationTurnRecord{}, errInvestigationTurnEncoding
	}
	record := InvestigationTurnRecord{
		identity: wire.Identity, ownerIdentity: wire.OwnerIdentity, sessionIdentity: wire.SessionIdentity, policyIdentity: wire.PolicyIdentity, scopeIdentity: wire.ScopeIdentity,
		ordinal: wire.Ordinal, role: role, previous: wire.PreviousTurnIdentity,
		deadlineMillis: wire.DeadlineMilliseconds, startedMillis: wire.StartedMilliseconds, finishedMillis: wire.FinishedMilliseconds,
		estimateVersion: wire.EstimateVersion, declaredInput: wire.DeclaredInputTokens, maxOutput: wire.MaxOutputTokens, originalCap: wire.OriginalCapMicroUSD,
		request: request, selection: selection, ranking: ranking, authorization: authorization, dispatch: dispatch, outcome: outcome, reconciliation: cost,
	}
	// Existing validation recomputes initial authority, dispatch outcome, cost and the 26-element hash.
	if record.Validate() != nil {
		return InvestigationTurnRecord{}, errInvestigationTurnEncoding
	}
	return record, nil
}
