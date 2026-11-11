package openai

import (
	"bytes"
	"encoding/json"
	"math"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// openRouterChatResponseWire is the part of an OpenRouter reply that carries
// the answer: its identity, the choice and the usage. It is decoded strictly;
// an unknown member inside it is refused. OpenRouter's routing metadata around
// it (provider, openrouter_metadata, alignment, safeguard_results and members
// it adds later) is read only by validateOpenRouterEnvelope.
type openRouterChatResponseWire struct {
	chatResponseWire
	Choices []openRouterChatChoiceWire `json:"choices"`
	Usage   *openRouterChatUsageWire   `json:"usage"`
}

// openRouterCoreMembers are the top-level members decoded strictly.
var openRouterCoreMembers = []string{"id", "object", "created", "model", "choices", "usage", "system_fingerprint", "service_tier", "timings"}

type openRouterChatChoiceWire struct {
	chatChoiceWire
	Message            openRouterChatMessageWire `json:"message"`
	NativeFinishReason *string                   `json:"native_finish_reason"`
	Error              json.RawMessage           `json:"error"`
}

type openRouterChatMessageWire struct {
	chatMessageWire
	Reasoning        *string           `json:"reasoning"`
	ReasoningDetails []json.RawMessage `json:"reasoning_details"`
	Images           []json.RawMessage `json:"images"`
	Model            *string           `json:"model"`
	Name             *string           `json:"name"`
}

type openRouterDeferredToolsWire struct {
	Turns            *uint64 `json:"turns"`
	PromptTokens     *uint64 `json:"prompt_tokens"`
	CompletionTokens *uint64 `json:"completion_tokens"`
	TotalTokens      *uint64 `json:"total_tokens"`
}

type openRouterChatUsageWire struct {
	PromptTokens            *uint64                             `json:"prompt_tokens"`
	CompletionTokens        *uint64                             `json:"completion_tokens"`
	TotalTokens             *uint64                             `json:"total_tokens"`
	PromptTokensDetails     *openRouterPromptDetailsWire        `json:"prompt_tokens_details"`
	CompletionTokensDetails *openRouterCompletionDetailsWire    `json:"completion_tokens_details"`
	Cost                    json.RawMessage                     `json:"cost"`
	CostDetails             *openRouterCostDetailsWire          `json:"cost_details"`
	IsBYOK                  json.RawMessage                     `json:"is_byok"`
	ServerToolUseDetails    *openRouterServerToolUseDetailsWire `json:"server_tool_use_details"`
	DeferredToolsDetails    *openRouterDeferredToolsWire        `json:"deferred_tools_details"`
}

type openRouterPromptDetailsWire struct {
	CachedTokens     openRouterPromptCount `json:"cached_tokens"`
	CacheWriteTokens openRouterPromptCount `json:"cache_write_tokens"`
	AudioTokens      openRouterPromptCount `json:"audio_tokens"`
	VideoTokens      openRouterPromptCount `json:"video_tokens"`
}

type openRouterPromptCount uint64

func (c *openRouterPromptCount) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ErrInvalidConfig
	}
	var count uint64
	if err := json.Unmarshal(raw, &count); err != nil {
		return err
	}
	*c = openRouterPromptCount(count)
	return nil
}

type openRouterCompletionDetailsWire struct {
	ReasoningTokens          *uint64 `json:"reasoning_tokens"`
	AudioTokens              *uint64 `json:"audio_tokens"`
	ImageTokens              *uint64 `json:"image_tokens"`
	AcceptedPredictionTokens *uint64 `json:"accepted_prediction_tokens"`
	RejectedPredictionTokens *uint64 `json:"rejected_prediction_tokens"`
}

type openRouterCostDetailsWire struct {
	UpstreamInferencePromptCost      json.RawMessage `json:"upstream_inference_prompt_cost"`
	UpstreamInferenceCompletionsCost json.RawMessage `json:"upstream_inference_completions_cost"`
	UpstreamInferenceCost            json.RawMessage `json:"upstream_inference_cost"`
	ServerToolCost                   json.RawMessage `json:"server_tool_cost"`
}

type openRouterServerToolUseDetailsWire struct {
	ToolCallsRequested *uint64 `json:"tool_calls_requested"`
	ToolCallsExecuted  *uint64 `json:"tool_calls_executed"`
	WebSearchRequests  *uint64 `json:"web_search_requests"`
}

func (a *Adapter) normalizeProviderResponse(content []byte, route provider.RouteReference) (provider.Response, error) {
	if a.protocol != ProtocolChatCompletions {
		return normalizeResponse(content, route)
	}
	// A generic connection to OpenRouter gets the same usage extension
	// (cost, BYOK and tool counts) and the same checks as the profiles.
	if a.openRouterProfile() || a.endpoint != nil && a.endpoint.String() == openRouterEndpoint {
		return normalizeOpenRouterChatResponse(content, route)
	}
	return normalizeChatResponse(content, route)
}

func normalizeOpenRouterChatResponse(content []byte, route provider.RouteReference) (provider.Response, error) {
	// Reject invalid UTF-8 before decoding: the decoder would replace it with U+FFFD and
	// the re-marshaled generic body would then pass normalizeChatResponse's own check.
	if len(content) == 0 || len(content) > maximumResponseBytes || !utf8.Valid(content) || validateChatJSONShape(content) != nil {
		return provider.Response{}, ErrInvalidConfig
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(content, &envelope) != nil || envelope == nil || validateOpenRouterEnvelope(envelope) != nil {
		return provider.Response{}, ErrInvalidConfig
	}
	core := make(map[string]json.RawMessage, len(openRouterCoreMembers))
	for _, member := range openRouterCoreMembers {
		if raw, ok := envelope[member]; ok {
			core[member] = raw
		}
	}
	coreBody, err := json.Marshal(core)
	if err != nil {
		return provider.Response{}, ErrInvalidConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(coreBody))
	decoder.DisallowUnknownFields()
	var wire openRouterChatResponseWire
	if decoder.Decode(&wire) != nil || requireJSONEOF(decoder) != nil {
		return provider.Response{}, ErrInvalidConfig
	}
	usage, err := normalizeOpenRouterChatUsage(wire.Usage)
	if err != nil {
		return provider.Response{}, err
	}
	wire.chatResponseWire.Usage = usage
	wire.chatResponseWire.Choices = make([]chatChoiceWire, len(wire.Choices))
	for i, choice := range wire.Choices {
		if !validOpenRouterChoice(choice) {
			return provider.Response{}, ErrInvalidConfig
		}
		// The reasoning trace and OpenRouter's choice metadata are validated
		// and discarded, never treated as output.
		choice.chatChoiceWire.Message = choice.Message.chatMessageWire
		wire.chatResponseWire.Choices[i] = choice.chatChoiceWire
	}
	// Reuse the unchanged generic response/content and integer-usage checks.
	generic, err := json.Marshal(wire.chatResponseWire)
	if err != nil {
		return provider.Response{}, ErrInvalidConfig
	}
	return normalizeChatResponse(generic, route)
}

// validateOpenRouterEnvelope checks the routing metadata OpenRouter puts
// around the answer. The upstream provider's name must be a short printable
// string. A request pipeline stage other than an account guardrail (a plugin,
// server tool, response healing or context compression) changed what the
// model saw or what it answered, so the reply is refused. Other envelope
// members carry no answer and are not read.
func validateOpenRouterEnvelope(envelope map[string]json.RawMessage) error {
	if raw, ok := envelope["provider"]; ok && !nullOrAbsent(raw) {
		var name string
		if json.Unmarshal(raw, &name) != nil || !validOpenRouterLabel(name, 128) {
			return ErrInvalidConfig
		}
	}
	if raw, ok := envelope["openrouter_metadata"]; ok && !nullOrAbsent(raw) {
		var metadata struct {
			Pipeline []struct {
				Type string `json:"type"`
			} `json:"pipeline"`
		}
		if json.Unmarshal(raw, &metadata) != nil {
			return ErrInvalidConfig
		}
		for _, stage := range metadata.Pipeline {
			if stage.Type != "guardrail" {
				return ErrInvalidConfig
			}
		}
	}
	return nil
}

// validOpenRouterChoice checks OpenRouter's additions to a choice and its
// message. A choice that reports a provider error, returns images or ran a
// server tool during reasoning is refused; reasoning text and summaries are
// bounded and dropped.
func validOpenRouterChoice(choice openRouterChatChoiceWire) bool {
	if !nullOrAbsent(choice.Error) || choice.NativeFinishReason != nil && !validOpenRouterLabel(*choice.NativeFinishReason, 64) {
		return false
	}
	message := choice.Message
	if message.Reasoning != nil && len(*message.Reasoning) > maximumResponseBytes || len(message.Images) != 0 ||
		message.Model != nil && !validOpenRouterLabel(*message.Model, 512) || message.Name != nil && !validOpenRouterLabel(*message.Name, 512) ||
		len(message.ReasoningDetails) > maximumOutputItems {
		return false
	}
	for _, raw := range message.ReasoningDetails {
		var detail struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &detail) != nil {
			return false
		}
		switch detail.Type {
		case "reasoning.summary", "reasoning.encrypted", "reasoning.text":
		default:
			return false
		}
	}
	return true
}

// validOpenRouterLabel accepts a non-empty printable ASCII label of at most
// limit bytes.
func validOpenRouterLabel(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func normalizeOpenRouterChatUsage(wire *openRouterChatUsageWire) (*chatUsageWire, error) {
	if wire == nil {
		return nil, nil
	}
	if wire.PromptTokens == nil || wire.CompletionTokens == nil || wire.TotalTokens == nil || len(wire.IsBYOK) != 0 && !bytes.Equal(bytes.TrimSpace(wire.IsBYOK), []byte("false")) || !validOpenRouterCost(wire.Cost, false, false) {
		return nil, ErrInvalidConfig
	}
	if details := wire.CostDetails; details != nil {
		if !validOpenRouterCost(details.UpstreamInferencePromptCost, true, false) || !validOpenRouterCost(details.UpstreamInferenceCompletionsCost, true, false) || !validOpenRouterCost(details.UpstreamInferenceCost, false, false) || !validOpenRouterCost(details.ServerToolCost, false, true) {
			return nil, ErrInvalidConfig
		}
	}
	if deferred := wire.DeferredToolsDetails; deferred != nil {
		for _, count := range []*uint64{deferred.Turns, deferred.PromptTokens, deferred.CompletionTokens, deferred.TotalTokens} {
			if count != nil && *count != 0 {
				return nil, ErrInvalidConfig
			}
		}
	}
	if tools := wire.ServerToolUseDetails; tools != nil {
		for _, count := range []*uint64{tools.ToolCallsRequested, tools.ToolCallsExecuted, tools.WebSearchRequests} {
			if count != nil && *count != 0 {
				return nil, ErrInvalidConfig
			}
		}
	}
	generic := &chatUsageWire{PromptTokens: wire.PromptTokens, CompletionTokens: wire.CompletionTokens, TotalTokens: wire.TotalTokens}
	if details := wire.PromptTokensDetails; details != nil {
		for _, count := range []openRouterPromptCount{details.CachedTokens, details.CacheWriteTokens, details.AudioTokens, details.VideoTokens} {
			if uint64(count) > *wire.PromptTokens {
				return nil, ErrInvalidConfig
			}
		}
		generic.PromptTokensDetails = &chatPromptDetailsWire{CachedTokens: uint64(details.CachedTokens), AudioTokens: uint64(details.AudioTokens)}
	}
	// The completion breakdown (reasoning, audio, image and prediction counts)
	// is decoded as unsigned integers and then dropped: settlement uses only
	// the prompt, completion and total counts. It is not compared with the
	// completion count, because upstream providers report it inconsistently
	// (on 2026-11-11 a reply billed for 95 completion tokens reported 99
	// reasoning tokens), and a breakdown nothing reads must not void an answer.
	return generic, nil
}

func validOpenRouterCost(raw json.RawMessage, required, zeroOnly bool) bool {
	if nullOrAbsent(raw) {
		return !required
	}
	if len(raw) > 64 || bytes.HasPrefix(bytes.TrimSpace(raw), []byte("-")) {
		return false
	}
	var cost float64
	if json.Unmarshal(raw, &cost) != nil || math.IsNaN(cost) || math.IsInf(cost, 0) || cost < 0 || zeroOnly && cost != 0 {
		return false
	}
	if zeroOnly {
		for _, digit := range bytes.TrimSpace(raw) {
			if digit == 'e' || digit == 'E' {
				break
			}
			if digit >= '1' && digit <= '9' {
				return false
			}
		}
	}
	return true
}
