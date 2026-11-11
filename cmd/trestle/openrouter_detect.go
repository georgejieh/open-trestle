package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/modelcatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// OpenRouter detection for setup. Setup reads two public OpenRouter API lists
// with one bounded, credential-free GET each, through the same public-only
// client as the evidence fetch: the model list and the list of endpoints that
// OpenRouter routes to when a request requires zero data retention (ZDR).
// From them it fills in, for each chosen model, its ZDR endpoints and their
// routing slugs, its context and output limits, its prices and whether it
// reports structured output. Everything is recorded as reported by the API at
// the retrieval time, with the exact SHA-256 of each response; none of it is
// a review or verification by the operator.

const (
	openRouterDocsZDR = "https://openrouter.ai/docs/guides/features/zdr"
	// A review needs at least this much context and output.
	openRouterMinContext = 8192
	openRouterMinOutput  = remoteReviewMaxOutputTokens
)

type openRouterSource struct {
	url, digest string
	retrievedAt time.Time
}

func (s openRouterSource) evidence() remoteEvidence {
	return remoteEvidence{URL: s.url, RetrievedAt: s.retrievedAt.Format(time.RFC3339Nano), ContentSHA256: s.digest}
}

// openRouterEndpoint is one endpoint of the ZDR list, reduced to the facts
// setup uses. Prices are micro-USD per million tokens, rounded up.
type openRouterEndpoint struct {
	tag, providerName                     string
	context, maxPrompt, maxCompletion     uint64
	promptMicro, completionMicro          uint64
	pricesKnown, structured, maxTokens    bool
	safetyRetention, safetyRetentionKnown bool
}

// usable reports whether Open Trestle can pin the endpoint for a review: it
// does not keep prompts for Safety Retention, accepts max_tokens (requests set
// require_parameters), has known prices and fits a review.
func (e openRouterEndpoint) usable() bool {
	return e.safetyRetentionKnown && !e.safetyRetention && e.maxTokens && e.pricesKnown && e.inputLimit() >= openRouterMinContext && e.maxCompletion >= openRouterMinOutput && e.maxCompletion <= e.context
}

// inputLimit is the context, or the smaller prompt limit when one is listed.
func (e openRouterEndpoint) inputLimit() uint64 {
	if e.maxPrompt > 0 && e.maxPrompt < e.context {
		return e.maxPrompt
	}
	return e.context
}

type openRouterListedModel struct {
	context, maxCompletion       uint64
	promptMicro, completionMicro uint64
	pricesKnown, structured      bool
}

// openRouterObservation is the result of reading both lists once. A failed
// read keeps its reason so the bootstrap does not try again with a
// different outcome than the wizard showed.
type openRouterObservation struct {
	retrievedAt   time.Time
	zdr, models   openRouterSource
	endpoints     map[string][]openRouterEndpoint
	listed        map[string]openRouterListedModel
	catalog       []modelcatalog.Model
	err           error
	zdrModelCount int
}

// openRouterModelFacts are the facts setup records for one chosen model.
type openRouterModelFacts struct {
	model string
	// zdr are the endpoints Open Trestle pins, cheapest first.
	zdr []openRouterEndpoint
	// safetyExcluded are ZDR endpoints left out because they may keep
	// prompts for Safety Retention (or do not say).
	safetyExcluded []string
	listed         bool
	listedFacts    openRouterListedModel
}

func (f openRouterModelFacts) hasZDR() bool { return len(f.zdr) != 0 }

func (f openRouterModelFacts) slugs() []string {
	slugs := []string{}
	for _, endpoint := range f.zdr {
		slugs = append(slugs, endpoint.tag)
	}
	return slugs
}

// capacity returns the context and output every pinned endpoint (with ZDR)
// or the listed model (without) supports, and whether they are known.
func (f openRouterModelFacts) capacity(zdr bool) (uint64, uint64, bool) {
	if !zdr {
		return f.listedFacts.context, f.listedFacts.maxCompletion, f.listed && f.listedFacts.context > 0 && f.listedFacts.maxCompletion > 0
	}
	if !f.hasZDR() {
		return 0, 0, false
	}
	context, output := uint64(1<<63), uint64(1<<63)
	for _, endpoint := range f.zdr {
		context, output = min(context, endpoint.inputLimit()), min(output, endpoint.maxCompletion)
	}
	return context, output, true
}

// prices returns the highest input and output price the route can be
// charged: across the pinned endpoints with ZDR, or the listed price and any
// ZDR endpoint price without it (OpenRouter may route to any provider then).
func (f openRouterModelFacts) prices(zdr bool) (uint64, uint64, bool) {
	input, output := uint64(0), uint64(0)
	if zdr {
		for _, endpoint := range f.zdr {
			input, output = max(input, endpoint.promptMicro), max(output, endpoint.completionMicro)
		}
		return input, output, f.hasZDR()
	}
	if !f.listed || !f.listedFacts.pricesKnown {
		return 0, 0, false
	}
	input, output = f.listedFacts.promptMicro, f.listedFacts.completionMicro
	for _, endpoint := range f.zdr {
		input, output = max(input, endpoint.promptMicro), max(output, endpoint.completionMicro)
	}
	return input, output, true
}

func (f openRouterModelFacts) structured(zdr bool) bool {
	if !zdr {
		return f.listed && f.listedFacts.structured
	}
	for _, endpoint := range f.zdr {
		if !endpoint.structured {
			return false
		}
	}
	return f.hasZDR()
}

type openRouterObservationKey struct{}

// withOpenRouterObservation lets the in-process bootstrap that `trestle init`
// runs reuse the exact responses the wizard showed, so both record the same
// bytes, digests and time and no second request is made.
func withOpenRouterObservation(ctx context.Context, observation *openRouterObservation) context.Context {
	return context.WithValue(ctx, openRouterObservationKey{}, observation)
}

// observeOpenRouter returns the observation attached to ctx, or reads both
// lists now.
func observeOpenRouter(ctx context.Context, clock setupClock) *openRouterObservation {
	if observation, ok := ctx.Value(openRouterObservationKey{}).(*openRouterObservation); ok && observation != nil {
		return observation
	}
	return readOpenRouterObservation(ctx, clock)
}

func readOpenRouterObservation(ctx context.Context, clock setupClock) *openRouterObservation {
	observation := &openRouterObservation{retrievedAt: clock.Now().UTC().Truncate(time.Second)}
	fail := func(err error) *openRouterObservation {
		observation.err = err
		return observation
	}
	zdrBody, zdr, err := openRouterFetch(ctx, clock, runtimeconfig.OpenRouterZDREndpointsURL)
	if err != nil {
		return fail(fmt.Errorf("could not read %s: %v", runtimeconfig.OpenRouterZDREndpointsURL, err))
	}
	modelBody, models, err := openRouterFetch(ctx, clock, runtimeconfig.OpenRouterModelsURL)
	if err != nil {
		return fail(fmt.Errorf("could not read %s: %v", runtimeconfig.OpenRouterModelsURL, err))
	}
	observation.zdr, observation.models = zdr, models
	if observation.endpoints, err = parseOpenRouterZDR(zdrBody); err != nil {
		return fail(fmt.Errorf("%s answered with an unexpected format", runtimeconfig.OpenRouterZDREndpointsURL))
	}
	if observation.listed, observation.catalog, err = parseOpenRouterModels(modelBody); err != nil {
		return fail(fmt.Errorf("%s answered with an unexpected format", runtimeconfig.OpenRouterModelsURL))
	}
	for model := range observation.endpoints {
		if observation.facts(model).hasZDR() {
			observation.zdrModelCount++
		}
	}
	// The model picker notes which listed models have usable ZDR endpoints.
	for i, model := range observation.catalog {
		listed := observation.listed[model.Selector]
		metadata, _ := json.Marshal(map[string]uint64{"context_length": listed.context, "max_completion_tokens": listed.maxCompletion, "zero_data_retention_endpoints": uint64(len(observation.facts(model.Selector).zdr))})
		observation.catalog[i].Metadata = metadata
	}
	return observation
}

// openRouterFetch performs one bounded, credential-free GET and returns the
// exact bytes with their digest and retrieval time.
func openRouterFetch(ctx context.Context, clock setupClock, location string) ([]byte, openRouterSource, error) {
	body, final, err := initFetchBody(ctx, location, "application/json")
	if err != nil {
		return nil, openRouterSource{}, err
	}
	if final != location {
		return nil, openRouterSource{}, errors.New("the API redirected to another address")
	}
	sum := sha256.Sum256(body)
	return body, openRouterSource{url: location, digest: hex.EncodeToString(sum[:]), retrievedAt: clock.Now().UTC().Truncate(time.Second)}, nil
}

// openRouterMicroUSD converts a USD-per-token decimal string to integer
// micro-USD per million tokens, rounded up. It refuses negative, exponent
// and other non-decimal forms (OpenRouter writes -1 for variable pricing).
func openRouterMicroUSD(value string) (uint64, bool) {
	if value == "" || len(value) > 40 || strings.Trim(value, "0123456789.") != "" || strings.Count(value, ".") > 1 {
		return 0, false
	}
	rate, ok := new(big.Rat).SetString(value)
	if !ok || rate.Sign() < 0 {
		return 0, false
	}
	rate.Mul(rate, new(big.Rat).SetInt64(1_000_000_000_000))
	quotient, remainder := new(big.Int).QuoRem(rate.Num(), rate.Denom(), new(big.Int))
	if remainder.Sign() != 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if !quotient.IsUint64() || quotient.Uint64() > 1<<40 {
		return 0, false
	}
	return quotient.Uint64(), true
}

type openRouterPricingWire struct {
	Prompt     *string `json:"prompt"`
	Completion *string `json:"completion"`
}

func (p openRouterPricingWire) micro() (uint64, uint64, bool) {
	if p.Prompt == nil || p.Completion == nil {
		return 0, 0, false
	}
	prompt, okPrompt := openRouterMicroUSD(*p.Prompt)
	completion, okCompletion := openRouterMicroUSD(*p.Completion)
	return prompt, completion, okPrompt && okCompletion
}

func openRouterStructured(parameters []string) bool {
	return slices.Contains(parameters, "structured_outputs") || slices.Contains(parameters, "response_format")
}

func parseOpenRouterZDR(body []byte) (map[string][]openRouterEndpoint, error) {
	var wire struct {
		Data []struct {
			ModelID             string                `json:"model_id"`
			Tag                 string                `json:"tag"`
			ProviderName        string                `json:"provider_name"`
			ContextLength       *uint64               `json:"context_length"`
			MaxPromptTokens     *uint64               `json:"max_prompt_tokens"`
			MaxCompletionTokens *uint64               `json:"max_completion_tokens"`
			Pricing             openRouterPricingWire `json:"pricing"`
			SupportedParameters []string              `json:"supported_parameters"`
			SafetyRetention     *bool                 `json:"safety_retention"`
		} `json:"data"`
	}
	if json.NewDecoder(bytes.NewReader(body)).Decode(&wire) != nil || wire.Data == nil {
		return nil, errors.New("unexpected ZDR list")
	}
	endpoints := map[string][]openRouterEndpoint{}
	for _, entry := range wire.Data {
		if initValidSelector(entry.ModelID) != nil || !remoteValidSlug(entry.Tag) {
			continue
		}
		endpoint := openRouterEndpoint{tag: entry.Tag, providerName: initPrintable(entry.ProviderName, entry.Tag), structured: openRouterStructured(entry.SupportedParameters), maxTokens: slices.Contains(entry.SupportedParameters, "max_tokens")}
		if entry.ContextLength != nil {
			endpoint.context = *entry.ContextLength
		}
		if entry.MaxPromptTokens != nil {
			endpoint.maxPrompt = *entry.MaxPromptTokens
		}
		if entry.MaxCompletionTokens != nil {
			endpoint.maxCompletion = *entry.MaxCompletionTokens
		}
		if endpoint.context > 1<<31 {
			endpoint.context = 1 << 31
		}
		if endpoint.maxPrompt >= endpoint.context {
			endpoint.maxPrompt = 0
		}
		endpoint.promptMicro, endpoint.completionMicro, endpoint.pricesKnown = entry.Pricing.micro()
		if entry.SafetyRetention != nil {
			endpoint.safetyRetention, endpoint.safetyRetentionKnown = *entry.SafetyRetention, true
		}
		if !slices.ContainsFunc(endpoints[entry.ModelID], func(e openRouterEndpoint) bool { return e.tag == entry.Tag }) {
			endpoints[entry.ModelID] = append(endpoints[entry.ModelID], endpoint)
		}
	}
	return endpoints, nil
}

func parseOpenRouterModels(body []byte) (map[string]openRouterListedModel, []modelcatalog.Model, error) {
	var wire struct {
		Data []struct {
			ID            string                `json:"id"`
			ContextLength *uint64               `json:"context_length"`
			Pricing       openRouterPricingWire `json:"pricing"`
			TopProvider   struct {
				ContextLength       *uint64 `json:"context_length"`
				MaxCompletionTokens *uint64 `json:"max_completion_tokens"`
			} `json:"top_provider"`
			SupportedParameters []string `json:"supported_parameters"`
		} `json:"data"`
	}
	if json.NewDecoder(bytes.NewReader(body)).Decode(&wire) != nil || wire.Data == nil {
		return nil, nil, errors.New("unexpected model list")
	}
	listed := map[string]openRouterListedModel{}
	catalog := []modelcatalog.Model{}
	for _, entry := range wire.Data {
		if initValidSelector(entry.ID) != nil {
			continue
		}
		model := openRouterListedModel{structured: openRouterStructured(entry.SupportedParameters)}
		if entry.TopProvider.ContextLength != nil {
			model.context = *entry.TopProvider.ContextLength
		} else if entry.ContextLength != nil {
			model.context = *entry.ContextLength
		}
		if entry.TopProvider.MaxCompletionTokens != nil {
			model.maxCompletion = *entry.TopProvider.MaxCompletionTokens
		}
		model.context = min(model.context, 1<<31)
		model.promptMicro, model.completionMicro, model.pricesKnown = entry.Pricing.micro()
		if _, seen := listed[entry.ID]; seen {
			continue
		}
		listed[entry.ID] = model
		catalog = append(catalog, modelcatalog.Model{Selector: entry.ID})
	}
	return listed, catalog, nil
}

// facts returns what the observation says about one model. Pinned endpoints
// are the usable ZDR endpoints, cheapest first, at most
// runtimeconfig.MaxOpenRouterProviderSlugs.
func (o *openRouterObservation) facts(model string) openRouterModelFacts {
	facts := openRouterModelFacts{model: model}
	if o == nil || o.err != nil {
		return facts
	}
	facts.listedFacts, facts.listed = o.listed[model]
	for _, endpoint := range o.endpoints[model] {
		switch {
		case endpoint.usable():
			facts.zdr = append(facts.zdr, endpoint)
		case !endpoint.safetyRetentionKnown || endpoint.safetyRetention:
			if len(facts.safetyExcluded) < 64 {
				facts.safetyExcluded = append(facts.safetyExcluded, endpoint.tag)
			}
		}
	}
	slices.SortFunc(facts.zdr, func(a, b openRouterEndpoint) int {
		if cost := (a.promptMicro + a.completionMicro); cost != b.promptMicro+b.completionMicro {
			if cost < b.promptMicro+b.completionMicro {
				return -1
			}
			return 1
		}
		return strings.Compare(a.tag, b.tag)
	})
	if len(facts.zdr) > runtimeconfig.MaxOpenRouterProviderSlugs {
		facts.zdr = facts.zdr[:runtimeconfig.MaxOpenRouterProviderSlugs]
	}
	slices.Sort(facts.safetyExcluded)
	return facts
}

// label is the fixed wording every record and surface uses for these facts.
func (o *openRouterObservation) label() string {
	return "as reported by OpenRouter's API at " + o.retrievedAt.Format(time.RFC3339) + "; not reviewed or verified by the operator"
}

// witnessObservation is the observation member of a version 3 witness.
func (o *openRouterObservation) witnessObservation(facts openRouterModelFacts) map[string]any {
	endpoints := []map[string]any{}
	for _, endpoint := range facts.zdr {
		endpoints = append(endpoints, map[string]any{"tag": endpoint.tag, "provider_name": endpoint.providerName, "context_length": endpoint.context, "max_prompt_tokens": endpoint.maxPrompt, "max_completion_tokens": endpoint.maxCompletion, "prompt_micro_usd_per_million_tokens": endpoint.promptMicro, "completion_micro_usd_per_million_tokens": endpoint.completionMicro, "structured_outputs": endpoint.structured})
	}
	excluded := append([]string{}, facts.safetyExcluded...)
	return map[string]any{"authority_label": o.label(), "retrieved_at": o.retrievedAt.Format(time.RFC3339Nano), "sources": []remoteEvidence{o.zdr.evidence(), o.models.evidence()}, "zdr_endpoints": endpoints, "safety_retention_endpoints_excluded": excluded}
}

// initPrintable returns value when it is a short printable label, else fallback.
func initPrintable(value, fallback string) string {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fallback
	}
	return value
}

// openRouterPlan is what the bootstrap records for one OpenRouter setup.
type openRouterPlan struct {
	zdr         bool
	observation *openRouterObservation
	facts       map[string]openRouterModelFacts // by role
	slugs       map[string][]string             // by role; with ZDR only
	slugSource  map[string]string               // by role; with ZDR only
}

func (p openRouterPlan) observed() bool { return p.observation != nil && p.observation.err == nil }

// parseOpenRouterSlugs reads a --*-provider-slug value: one slug or several
// separated by commas.
func parseOpenRouterSlugs(flagName, value string) ([]string, error) {
	slugs := []string{}
	for _, slug := range strings.Split(value, ",") {
		if !remoteValidSlug(slug) || slices.Contains(slugs, slug) {
			return nil, fmt.Errorf("--%s must be one or more distinct lowercase OpenRouter provider slugs separated by commas, such as amazon-bedrock,google-vertex/global", flagName)
		}
		slugs = append(slugs, slug)
	}
	if len(slugs) > runtimeconfig.MaxOpenRouterProviderSlugs {
		return nil, fmt.Errorf("--%s names more than %d provider slugs", flagName, runtimeconfig.MaxOpenRouterProviderSlugs)
	}
	return slugs, nil
}

// planOpenRouter fills every route fact the operator did not give as a flag
// from the observation, and decides the slugs a ZDR route pins. It never
// invents a fact: a value the API did not report and no flag gave is an error
// that names the flag.
func planOpenRouter(observation *openRouterObservation, zdr bool, models, slugFlags map[string]string, given map[string]bool, numbers map[string]*uint64) (openRouterPlan, error) {
	plan := openRouterPlan{zdr: zdr, observation: observation, facts: map[string]openRouterModelFacts{}, slugs: map[string][]string{}, slugSource: map[string]string{}}
	at := ""
	if plan.observed() {
		at = " (" + observation.label() + ")"
	}
	allGiven := given["context-tokens"] && given["output-tokens"] && given["input-micro-usd-per-million-tokens"] && given["output-micro-usd-per-million-tokens"]
	for _, role := range []string{"generation", "verification"} {
		facts := observation.facts(models[role])
		plan.facts[role] = facts
		if plan.observed() && !allGiven && !facts.listed && len(observation.endpoints[models[role]]) == 0 {
			return plan, fmt.Errorf("OpenRouter's API does not list the model %s%s; copy the exact ID from https://openrouter.ai/models", models[role], at)
		}
		if !zdr {
			continue
		}
		switch {
		case slugFlags[role] != "":
			slugs, err := parseOpenRouterSlugs(role+"-provider-slug", slugFlags[role])
			if err != nil {
				return plan, err
			}
			plan.slugs[role], plan.slugSource[role] = slugs, "operator"
		case !plan.observed():
			plan.slugs[role], plan.slugSource[role] = []string{}, "none"
		case facts.hasZDR():
			plan.slugs[role], plan.slugSource[role] = facts.slugs(), "openrouter_api"
		default:
			return plan, fmt.Errorf("the model %s has no zero-data-retention endpoint Open Trestle can use%s; choose a model that lists one, or use --provider openrouter to set it up without zero data retention", models[role], at)
		}
	}
	missing := []string{}
	fill := func(flagName string, value func(openRouterModelFacts) (uint64, bool), combine func(uint64, uint64) uint64) {
		if given[flagName] {
			return
		}
		first, firstOK := value(plan.facts["generation"])
		second, secondOK := value(plan.facts["verification"])
		if !firstOK || !secondOK {
			missing = append(missing, "--"+flagName)
			return
		}
		*numbers[flagName] = combine(first, second)
	}
	fill("context-tokens", func(f openRouterModelFacts) (uint64, bool) { c, _, ok := f.capacity(zdr); return c, ok }, minUint)
	fill("output-tokens", func(f openRouterModelFacts) (uint64, bool) { _, o, ok := f.capacity(zdr); return o, ok }, minUint)
	fill("input-micro-usd-per-million-tokens", func(f openRouterModelFacts) (uint64, bool) { i, _, ok := f.prices(zdr); return i, ok }, maxUint)
	fill("output-micro-usd-per-million-tokens", func(f openRouterModelFacts) (uint64, bool) { _, o, ok := f.prices(zdr); return o, ok }, maxUint)
	if len(missing) != 0 {
		reason := "OpenRouter's API does not report them for the chosen models" + at
		if observation != nil && observation.err != nil {
			reason = "OpenRouter's API could not be read (" + observation.err.Error() + ")"
		}
		return plan, fmt.Errorf("%s; pass %s", reason, strings.Join(missing, ", "))
	}
	if !given["output-tokens"] && *numbers["output-tokens"] > *numbers["context-tokens"] {
		*numbers["output-tokens"] = *numbers["context-tokens"]
	}
	return plan, nil
}

func minUint(a, b uint64) uint64 { return min(a, b) }
func maxUint(a, b uint64) uint64 { return max(a, b) }

// witness returns the version 3 privacy witness member for one role of a
// ZDR plan.
func (p openRouterPlan) witness(role string, route remoteWitnessRoute, credentialIdentity, tenant, repository string) map[string]any {
	var observation any
	if p.observed() {
		observation = p.observation.witnessObservation(p.facts[role])
	}
	return map[string]any{
		"contract": "open-trestle/openrouter-privacy-witness", "schema_version": 3, "route": route, "endpoint": "https://openrouter.ai/api/v1", "request_profile": runtimeconfig.OpenRouterZDRChatV2Profile, "protocol": "openai_chat_completions", "credential_mode": "bearer",
		"credential_reference_identity": credentialIdentity, "tenant_id": tenant, "repository_id": repository, "zero_data_retention": "required_per_request",
		"provider_slugs": p.slugs[role], "provider_slug_source": p.slugSource[role], "observation": observation,
	}
}

// routeObservation is the informational manifest member of a route that
// does not require zero data retention. It states only what Open Trestle
// requires, never what a provider retains.
func (p openRouterPlan) routeObservation(role string) map[string]any {
	member := map[string]any{"contract": "open-trestle/openrouter-route-observation", "schema_version": 1, "zero_data_retention": "not_required_by_open_trestle",
		"statement": "Open Trestle does not require zero data retention for this route; OpenRouter account or key settings may still enforce it", "zdr_endpoints_listed": nil, "observation": nil}
	if p.observed() {
		member["zdr_endpoints_listed"] = len(p.facts[role].zdr)
		member["observation"] = map[string]any{"authority_label": p.observation.label(), "retrieved_at": p.observation.retrievedAt.Format(time.RFC3339Nano), "sources": []remoteEvidence{p.observation.zdr.evidence(), p.observation.models.evidence()}}
	}
	return member
}
