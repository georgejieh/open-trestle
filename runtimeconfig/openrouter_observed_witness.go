package runtimeconfig

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// OpenRouterZDRChatV2Profile is the OpenRouter Chat contract whose privacy
// witness setup records from OpenRouter's public API instead of an operator
// review. Every request sets provider.zdr, so OpenRouter itself refuses to
// route it to an endpoint outside its zero-data-retention list. When setup
// detected or was given provider slugs, the request is also limited to them.
// There is no review window: the witness states what the API reported at one
// time, and enforcement happens on each request, not in the witness.
//
// The profile is admitted only by runtime policy schema version 8, whose
// brokered_route_authority has exactly route_record_identity,
// evidence_manifest_digest, tenant_id, repository_id and provider_slugs.
const OpenRouterZDRChatV2Profile = "openrouter_zdr_chat_v2"

// OpenRouterZDREndpointsURL and OpenRouterModelsURL are the two public,
// credential-free API addresses setup reads for the witness observation.
const (
	OpenRouterZDREndpointsURL = "https://openrouter.ai/api/v1/endpoints/zdr"
	OpenRouterModelsURL       = "https://openrouter.ai/api/v1/models"
)

// MaxOpenRouterProviderSlugs bounds the provider slugs one route may pin.
const MaxOpenRouterProviderSlugs = 32

const (
	openRouterObservedPolicyVersion  = 8
	openRouterObservedWitnessVersion = 3
	maxOpenRouterSafetyExclusions    = 64
	maxOpenRouterPriceMicroUSD       = 1 << 40
)

// Slug sources: detected from the API, given by the operator, or none, in
// which case the request requires zero data retention without pinning.
const (
	openRouterSlugSourceAPI      = "openrouter_api"
	openRouterSlugSourceOperator = "operator"
	openRouterSlugSourceNone     = "none"
)

type openRouterObservedEndpoint struct {
	Tag                 string `json:"tag"`
	ProviderName        string `json:"provider_name"`
	ContextLength       uint64 `json:"context_length"`
	MaxPromptTokens     uint64 `json:"max_prompt_tokens"`
	MaxCompletionTokens uint64 `json:"max_completion_tokens"`
	PromptMicroUSD      uint64 `json:"prompt_micro_usd_per_million_tokens"`
	CompletionMicroUSD  uint64 `json:"completion_micro_usd_per_million_tokens"`
	StructuredOutputs   bool   `json:"structured_outputs"`
	// Reasoning is an endpoint that accepts the reasoning request parameter.
	// A witness saved without the member records false.
	Reasoning bool `json:"reasoning"`
}

// openRouterOutputExcludedEndpoint is a ZDR endpoint setup could otherwise
// pin but left out because it allows fewer output tokens than the review
// output allowance setup chose.
type openRouterOutputExcludedEndpoint struct {
	Tag                 string `json:"tag"`
	MaxCompletionTokens uint64 `json:"max_completion_tokens"`
}

type openRouterObservation struct {
	AuthorityLabel          string                             `json:"authority_label"`
	RetrievedAt             string                             `json:"retrieved_at"`
	Sources                 []openRouterPrivacySource          `json:"sources"`
	ZDREndpoints            []openRouterObservedEndpoint       `json:"zdr_endpoints"`
	SafetyRetentionExcluded []string                           `json:"safety_retention_endpoints_excluded"`
	OutputLimitExcluded     []openRouterOutputExcludedEndpoint `json:"output_limit_endpoints_excluded"`
}

type openRouterObservedWitness struct {
	Contract                    string                 `json:"contract"`
	SchemaVersion               int                    `json:"schema_version"`
	Route                       openRouterPrivacyRoute `json:"route"`
	Endpoint                    string                 `json:"endpoint"`
	RequestProfile              string                 `json:"request_profile"`
	Protocol                    string                 `json:"protocol"`
	CredentialMode              string                 `json:"credential_mode"`
	CredentialReferenceIdentity string                 `json:"credential_reference_identity"`
	TenantID                    string                 `json:"tenant_id"`
	RepositoryID                string                 `json:"repository_id"`
	ZeroDataRetention           string                 `json:"zero_data_retention"`
	ProviderSlugs               []string               `json:"provider_slugs"`
	ProviderSlugSource          string                 `json:"provider_slug_source"`
	Observation                 *openRouterObservation `json:"observation"`
}

// openRouterObservedProjection keeps only the comparable binding of a valid
// version 3 witness; the witness itself was fully validated when extracted.
type openRouterObservedProjection struct {
	record, evidence, credential, tenant, repository, slugs string
	slugSource, observedAt, label                           string
	outputExcluded                                          int
	reasoning, structured                                   bool
	route                                                   provider.RouteReference
}

var openRouterObservedWitnessKeys = []string{"contract", "schema_version", "route", "endpoint", "request_profile", "protocol", "credential_mode", "credential_reference_identity", "tenant_id", "repository_id", "zero_data_retention", "provider_slugs", "provider_slug_source", "observation"}

var openRouterObservationKeys = []string{"authority_label", "retrieved_at", "sources", "zdr_endpoints", "safety_retention_endpoints_excluded", "output_limit_endpoints_excluded"}

// requireExactKeys reports whether encoded is a JSON object with exactly the
// named members, none of them null except those in nullable.
func requireExactKeys(encoded []byte, keys []string, nullable ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		value, ok := fields[key]
		if !ok {
			return false
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !containsString(nullable, key) {
			return false
		}
	}
	return true
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// joinOpenRouterSlugs encodes a valid slug list in one comparable string.
// A slug never contains a newline.
func joinOpenRouterSlugs(slugs []string) string { return strings.Join(slugs, "\n") }

func splitOpenRouterSlugs(joined string) []string {
	if joined == "" {
		return nil
	}
	return strings.Split(joined, "\n")
}

// validOpenRouterSlugList accepts at most MaxOpenRouterProviderSlugs distinct
// valid slugs; an empty list is valid.
func validOpenRouterSlugList(slugs []string) bool {
	if len(slugs) > MaxOpenRouterProviderSlugs {
		return false
	}
	seen := map[string]bool{}
	for _, slug := range slugs {
		if !validBrokeredSlug(slug) || seen[slug] {
			return false
		}
		seen[slug] = true
	}
	return true
}

func (e openRouterObservedEndpoint) valid() bool {
	return validBrokeredSlug(e.Tag) && validPrivacyLabel(e.ProviderName) && e.ContextLength >= 8192 && e.ContextLength <= 1<<31 &&
		(e.MaxPromptTokens == 0 || e.MaxPromptTokens <= e.ContextLength) && e.MaxCompletionTokens >= 4096 && e.MaxCompletionTokens <= e.ContextLength &&
		e.PromptMicroUSD <= maxOpenRouterPriceMicroUSD && e.CompletionMicroUSD <= maxOpenRouterPriceMicroUSD
}

func (o openRouterObservation) valid() bool {
	retrieved, ok := canonicalPrivacyTime(o.RetrievedAt)
	if !ok || !validPrivacyLabel(o.AuthorityLabel) || !strings.Contains(o.AuthorityLabel, o.RetrievedAt) || len(o.Sources) != 2 || o.Sources[0].URL != OpenRouterZDREndpointsURL || o.Sources[1].URL != OpenRouterModelsURL {
		return false
	}
	for _, source := range o.Sources {
		at, _ := canonicalPrivacyTime(source.RetrievedAt)
		if !source.valid() || at.Before(retrieved) {
			return false
		}
	}
	if len(o.ZDREndpoints) > MaxOpenRouterProviderSlugs || len(o.SafetyRetentionExcluded) > maxOpenRouterSafetyExclusions || o.OutputLimitExcluded == nil || len(o.OutputLimitExcluded) > maxOpenRouterSafetyExclusions {
		return false
	}
	tags := map[string]bool{}
	leastPinnedOutput := uint64(1 << 63)
	for _, endpoint := range o.ZDREndpoints {
		if !endpoint.valid() || tags[endpoint.Tag] {
			return false
		}
		tags[endpoint.Tag] = true
		leastPinnedOutput = min(leastPinnedOutput, endpoint.MaxCompletionTokens)
	}
	excluded := map[string]bool{}
	for _, tag := range o.SafetyRetentionExcluded {
		if !validBrokeredSlug(tag) || excluded[tag] || tags[tag] {
			return false
		}
		excluded[tag] = true
	}
	// An endpoint left out for its output limit allows less than every pinned
	// endpoint, and is neither pinned nor left out for Safety Retention.
	if len(o.OutputLimitExcluded) != 0 && len(o.ZDREndpoints) == 0 {
		return false
	}
	for _, endpoint := range o.OutputLimitExcluded {
		if !validBrokeredSlug(endpoint.Tag) || excluded[endpoint.Tag] || tags[endpoint.Tag] || endpoint.MaxCompletionTokens < 4096 || endpoint.MaxCompletionTokens >= leastPinnedOutput {
			return false
		}
		excluded[endpoint.Tag] = true
	}
	return true
}

// reasoning reports whether every one of slugs, and at least one, is an
// observed endpoint that accepts the reasoning request parameter.
func (o openRouterObservation) reasoning(slugs []string) bool {
	for _, slug := range slugs {
		if !slices.ContainsFunc(o.ZDREndpoints, func(e openRouterObservedEndpoint) bool { return e.Tag == slug && e.Reasoning }) {
			return false
		}
	}
	return len(slugs) != 0
}

// structuredOutputs reports whether every one of slugs, and at least one, is
// an observed endpoint that supports structured outputs.
func (o openRouterObservation) structuredOutputs(slugs []string) bool {
	for _, slug := range slugs {
		if !slices.ContainsFunc(o.ZDREndpoints, func(e openRouterObservedEndpoint) bool { return e.Tag == slug && e.StructuredOutputs }) {
			return false
		}
	}
	return len(slugs) != 0
}

func (w openRouterObservedWitness) valid() bool {
	if w.Contract != "open-trestle/openrouter-privacy-witness" || w.SchemaVersion != openRouterObservedWitnessVersion || w.Endpoint != "https://openrouter.ai/api/v1" || w.RequestProfile != OpenRouterZDRChatV2Profile || w.Protocol != "openai_chat_completions" || w.CredentialMode != "bearer" || !nonzeroDigest(w.CredentialReferenceIdentity) || w.ZeroDataRetention != "required_per_request" || w.ProviderSlugs == nil || !validOpenRouterSlugList(w.ProviderSlugs) {
		return false
	}
	if _, err := audit.NewReviewScope(w.TenantID, w.RepositoryID, "profile-validation"); err != nil {
		return false
	}
	if _, valid := w.Route.reference(); !valid {
		return false
	}
	if w.Observation != nil && !w.Observation.valid() {
		return false
	}
	// Only endpoints setup chose from the API are chosen by output limit.
	if w.Observation != nil && len(w.Observation.OutputLimitExcluded) != 0 && w.ProviderSlugSource != openRouterSlugSourceAPI {
		return false
	}
	switch w.ProviderSlugSource {
	case openRouterSlugSourceAPI:
		if w.Observation == nil || len(w.ProviderSlugs) == 0 || len(w.ProviderSlugs) != len(w.Observation.ZDREndpoints) {
			return false
		}
		for i, endpoint := range w.Observation.ZDREndpoints {
			if w.ProviderSlugs[i] != endpoint.Tag {
				return false
			}
		}
	case openRouterSlugSourceOperator:
		if len(w.ProviderSlugs) == 0 {
			return false
		}
	case openRouterSlugSourceNone:
		if len(w.ProviderSlugs) != 0 {
			return false
		}
	default:
		return false
	}
	return true
}

// reference returns the route the witness names and whether its effective
// selector matches it.
func (r openRouterPrivacyRoute) reference() (provider.RouteReference, bool) {
	if r.Zone != "brokered_remote" || r.ProviderID != "openrouter" {
		return provider.RouteReference{}, false
	}
	route, err := provider.NewRouteReference(provider.ProviderZoneBrokeredRemote, r.ProviderID, r.AdapterID, r.ConnectionID, r.ModelID, r.ModelVersion)
	selector := r.ModelVersion
	if selector == "" {
		selector = r.ModelID
	}
	return route, err == nil && r.EffectiveSelector == selector
}

// extractOpenRouterObserved returns the binding of a valid version 3 witness
// for an OpenRouter brokered record, or the zero projection. The caller has
// already scanned the whole manifest for duplicate and noncanonical keys.
func extractOpenRouterObserved(member json.RawMessage, record provider.RouteRegistryRecord) openRouterObservedProjection {
	if !requireExactKeys(member, openRouterObservedWitnessKeys, "observation") {
		return openRouterObservedProjection{}
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(member, &fields)
	if observation := fields["observation"]; !bytes.Equal(bytes.TrimSpace(observation), []byte("null")) {
		if !requireExactKeys(observation, openRouterObservationKeys) {
			return openRouterObservedProjection{}
		}
		var parts map[string]json.RawMessage
		_ = json.Unmarshal(observation, &parts)
		var endpoints []json.RawMessage
		if json.Unmarshal(parts["zdr_endpoints"], &endpoints) != nil {
			return openRouterObservedProjection{}
		}
		keys := []string{"tag", "provider_name", "context_length", "max_prompt_tokens", "max_completion_tokens", "prompt_micro_usd_per_million_tokens", "completion_micro_usd_per_million_tokens", "structured_outputs"}
		for _, endpoint := range endpoints {
			if !requireExactKeys(endpoint, keys) && !requireExactKeys(endpoint, append(keys, "reasoning")) {
				return openRouterObservedProjection{}
			}
		}
		var outputExcluded []json.RawMessage
		if json.Unmarshal(parts["output_limit_endpoints_excluded"], &outputExcluded) != nil {
			return openRouterObservedProjection{}
		}
		for _, endpoint := range outputExcluded {
			if !requireExactKeys(endpoint, []string{"tag", "max_completion_tokens"}) {
				return openRouterObservedProjection{}
			}
		}
	}
	var witness openRouterObservedWitness
	if decodeOpenRouterPrivacyJSON(member, &witness) != nil || !witness.valid() {
		return openRouterObservedProjection{}
	}
	route, _ := witness.Route.reference()
	projection := openRouterObservedProjection{record: record.Identity(), evidence: record.EvidenceManifestDigest(), credential: witness.CredentialReferenceIdentity, tenant: witness.TenantID, repository: witness.RepositoryID, slugs: joinOpenRouterSlugs(witness.ProviderSlugs), slugSource: witness.ProviderSlugSource, route: route}
	if witness.Observation != nil {
		projection.observedAt, projection.label, projection.outputExcluded = witness.Observation.RetrievedAt, witness.Observation.AuthorityLabel, len(witness.Observation.OutputLimitExcluded)
		projection.reasoning = witness.Observation.reasoning(witness.ProviderSlugs)
		projection.structured = witness.Observation.structuredOutputs(witness.ProviderSlugs)
	}
	if !projection.matchesRecord(record) {
		return openRouterObservedProjection{}
	}
	return projection
}

func (p openRouterObservedProjection) matchesRecord(record provider.RouteRegistryRecord) bool {
	return record.Validate() == nil && p.record != "" && p.record == record.Identity() && p.evidence == record.EvidenceManifestDigest() && p.route == record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
}

func (p openRouterObservedProjection) matchesConnection(c ProviderConnection) bool {
	a := c.brokeredAuthority
	return a.observed && p.record == a.record && p.evidence == a.evidence && c.endpoint == "https://openrouter.ai/api/v1" && c.requestProfile == OpenRouterZDRChatV2Profile && c.implementation == "openai_chat_completions" && c.credentialMode == "bearer" && p.credential == c.credentialIdentity && p.tenant == a.tenant && p.repository == a.repository && p.slugs == a.slugs
}

// extractOpenRouterObservedManifest applies the same whole-manifest scan as
// the version 2 witness before reading a version 3 reserved member.
func extractOpenRouterObservedManifest(manifest []byte, record provider.RouteRegistryRecord) openRouterObservedProjection {
	route := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
	if route.Zone() != provider.ProviderZoneBrokeredRemote || route.ProviderID() != "openrouter" || !utf8.Valid(manifest) || validateUniqueJSONKeys(manifest) != nil {
		return openRouterObservedProjection{}
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(manifest, &members) != nil || members == nil || openRouterWitnessVersion(members["openrouter_privacy"]) != openRouterObservedWitnessVersion {
		return openRouterObservedProjection{}
	}
	return extractOpenRouterObserved(members["openrouter_privacy"], record)
}

// openRouterWitnessVersion reads the schema_version of the reserved member, or 0.
func openRouterWitnessVersion(member json.RawMessage) int {
	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if len(member) == 0 || !utf8.Valid(member) || json.Unmarshal(member, &header) != nil {
		return 0
	}
	return header.SchemaVersion
}

func validObservedOpenRouterConnection(c ProviderConnection, version int) bool {
	return version == openRouterObservedPolicyVersion && c.requestProfile == OpenRouterZDRChatV2Profile && c.brokeredAuthority.observed && c.brokeredAuthority.valid() && c.openCodeGoAuthority == (OpenCodeGoRouteAuthority{}) && c.openCodeConsoleAuthority == (OpenCodeConsoleRouteAuthority{}) && !c.localStructuredOutput && c.implementation == "openai_chat_completions" && c.credentialMode == "bearer" && c.endpoint == "https://openrouter.ai/api/v1"
}

func validObservedOpenRouterInventoryBinding(c ProviderConnection, inventory RouteInventory) bool {
	count := 0
	for index, observed := range inventory.candidates {
		record := observed.ResolvedRecord().RouteRegistryRecord()
		declaration := record.RouteCandidateDeclaration()
		route := declaration.RouteCapabilityDeclaration().RouteReference()
		if route.AdapterID() != c.adapterID {
			continue
		}
		count++
		if index >= len(inventory.openRouterObserved) || !inventory.openRouterObserved[index].matchesRecord(record) || !inventory.openRouterObserved[index].matchesConnection(c) {
			return false
		}
		if record.Status() != provider.RouteRegistryApproved || route.Zone() != provider.ProviderZoneBrokeredRemote || route.ProviderID() != "openrouter" || declaration.ContentLoggingMode() != provider.ContentLoggingDisabled {
			return false
		}
	}
	return count == 1
}

// validateV8PolicyProfileFields admits generic connections and the
// openrouter_zdr_chat_v2 profile with its exact five-member authority.
func validateV8PolicyProfileFields(encoded []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil {
		return false
	}
	var connections []map[string]json.RawMessage
	if json.Unmarshal(fields["connections"], &connections) != nil {
		return false
	}
	for _, c := range connections {
		for key := range c {
			lower := strings.ToLower(key)
			if (lower == "request_profile" || lower == "brokered_route_authority") && key != lower || lower == "opencode_go_authority" || lower == "opencode_console_authority" || lower == "local_structured_output" {
				return false
			}
		}
		profileRaw, profilePresent := c["request_profile"]
		authorityRaw, authorityPresent := c["brokered_route_authority"]
		if !profilePresent && !authorityPresent {
			continue
		}
		var profile string
		if !profilePresent || !authorityPresent || json.Unmarshal(profileRaw, &profile) != nil || profile != OpenRouterZDRChatV2Profile || !requireExactKeys(authorityRaw, []string{"route_record_identity", "evidence_manifest_digest", "tenant_id", "repository_id", "provider_slugs"}) {
			return false
		}
	}
	return true
}

// OpenRouterObservedWitnessFields is the decoded, valid version 3 witness of
// one inventory record, for setup and review surfaces that show it. The
// observation is what OpenRouter's API reported; nothing in it was reviewed.
type OpenRouterObservedWitnessFields struct {
	ProviderSlugs      []string
	ProviderSlugSource string
	Observed           bool
	ObservedAt         time.Time
	AuthorityLabel     string
	// OutputLimitExcluded counts the ZDR endpoints left out because they
	// allow fewer output tokens than the review output allowance.
	OutputLimitExcluded int
	// Reasoning reports that every pinned endpoint accepts the reasoning
	// request parameter, so requests ask for low reasoning effort.
	Reasoning bool
	// StructuredOutputs reports that every pinned endpoint supports
	// structured outputs.
	StructuredOutputs bool
}

// OpenRouterObservedWitness returns the version 3 witness facts of a record,
// or ok false when the record has none.
func (i RouteInventory) OpenRouterObservedWitness(recordIdentity string) (OpenRouterObservedWitnessFields, bool) {
	if i.Validate() != nil {
		return OpenRouterObservedWitnessFields{}, false
	}
	for index, candidate := range i.candidates {
		projection := i.openRouterObserved[index]
		if candidate.ResolvedRecord().RouteRegistryRecord().Identity() != recordIdentity || projection == (openRouterObservedProjection{}) {
			continue
		}
		fields := OpenRouterObservedWitnessFields{ProviderSlugs: splitOpenRouterSlugs(projection.slugs), ProviderSlugSource: projection.slugSource, AuthorityLabel: projection.label, OutputLimitExcluded: projection.outputExcluded, Reasoning: projection.reasoning, StructuredOutputs: projection.structured}
		if projection.observedAt != "" {
			fields.Observed = true
			fields.ObservedAt, _ = canonicalPrivacyTime(projection.observedAt)
		}
		return fields, true
	}
	return OpenRouterObservedWitnessFields{}, false
}
