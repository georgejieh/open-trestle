package openai

import (
	"bytes"
	"encoding/json"
	"math"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/provider"
)

type openRouterChatResponseWire struct {
	chatResponseWire
	Usage *openRouterChatUsageWire `json:"usage"`
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
	if a.requestProfile == RequestProfileOpenRouterZDRChatV1 {
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
	decoder := json.NewDecoder(bytes.NewReader(content))
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
	// Reuse the unchanged generic response/content and integer-usage checks.
	generic, err := json.Marshal(wire.chatResponseWire)
	if err != nil {
		return provider.Response{}, ErrInvalidConfig
	}
	return normalizeChatResponse(generic, route)
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
	if details := wire.CompletionTokensDetails; details != nil {
		counts := []*uint64{details.ReasoningTokens, details.AudioTokens, details.AcceptedPredictionTokens, details.RejectedPredictionTokens}
		for _, count := range counts {
			if count != nil && *count > *wire.CompletionTokens {
				return nil, ErrInvalidConfig
			}
		}
	}
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
