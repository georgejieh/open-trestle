package openai

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

type chatRequestWire struct {
	ResponseFormat *chatResponseFormat  `json:"response_format,omitempty"`
	Model          string               `json:"model"`
	Messages       []chatRequestMessage `json:"messages"`
	MaxTokens      uint32               `json:"max_tokens"`
	Stream         bool                 `json:"stream"`
}

type chatResponseFormat struct {
	Type       string         `json:"type"`
	JSONSchema chatJSONSchema `json:"json_schema"`
}

type chatJSONSchema struct {
	Name   string          `json:"name"`
	Strict bool            `json:"strict"`
	Schema json.RawMessage `json:"schema"`
}

func localStructuredResponseFormat(payload []byte) (*chatResponseFormat, error) {
	schema, err := review.TrustedModelRequestOutputSchema(payload)
	if err != nil {
		return nil, err
	}
	return &chatResponseFormat{Type: "json_schema", JSONSchema: chatJSONSchema{Name: "open_trestle_review", Strict: true, Schema: schema}}, nil
}

type chatRequestMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponseWire struct {
	ID                string           `json:"id"`
	Object            string           `json:"object"`
	Created           *uint64          `json:"created"`
	Model             string           `json:"model"`
	Choices           []chatChoiceWire `json:"choices"`
	Usage             *chatUsageWire   `json:"usage"`
	SystemFingerprint *string          `json:"system_fingerprint"`
	ServiceTier       *string          `json:"service_tier"`
	Timings           *chatTimingsWire `json:"timings"`
}

// llama.cpp reports timings separately from authoritative token usage.
type chatTimingsWire struct {
	CacheTokens           uint64  `json:"cache_n"`
	PromptTokens          uint64  `json:"prompt_n"`
	PromptMilliseconds    float64 `json:"prompt_ms"`
	PromptPerToken        float64 `json:"prompt_per_token_ms"`
	PromptPerSecond       float64 `json:"prompt_per_second"`
	PredictedTokens       uint64  `json:"predicted_n"`
	PredictedMilliseconds float64 `json:"predicted_ms"`
	PredictedPerToken     float64 `json:"predicted_per_token_ms"`
	PredictedPerSecond    float64 `json:"predicted_per_second"`
}

func (t *chatTimingsWire) valid() bool {
	return t == nil || t.PromptMilliseconds >= 0 && t.PromptPerToken >= 0 && t.PromptPerSecond >= 0 && t.PredictedMilliseconds >= 0 && t.PredictedPerToken >= 0 && t.PredictedPerSecond >= 0
}

type chatChoiceWire struct {
	Index        *uint32         `json:"index"`
	Message      chatMessageWire `json:"message"`
	FinishReason string          `json:"finish_reason"`
	Logprobs     json.RawMessage `json:"logprobs"`
}

type chatMessageWire struct {
	Role             string            `json:"role"`
	Content          *string           `json:"content"`
	ReasoningContent *string           `json:"reasoning_content"`
	Refusal          *string           `json:"refusal"`
	Annotations      []json.RawMessage `json:"annotations"`
	ToolCalls        []json.RawMessage `json:"tool_calls"`
	FunctionCall     json.RawMessage   `json:"function_call"`
	Audio            json.RawMessage   `json:"audio"`
}

type chatUsageWire struct {
	PromptTokens            *uint64                    `json:"prompt_tokens"`
	CompletionTokens        *uint64                    `json:"completion_tokens"`
	TotalTokens             *uint64                    `json:"total_tokens"`
	PromptTokensDetails     *chatPromptDetailsWire     `json:"prompt_tokens_details"`
	CompletionTokensDetails *chatCompletionDetailsWire `json:"completion_tokens_details"`
}

type chatPromptDetailsWire struct {
	CachedTokens uint64 `json:"cached_tokens"`
	AudioTokens  uint64 `json:"audio_tokens"`
}

type chatCompletionDetailsWire struct {
	ReasoningTokens          uint64 `json:"reasoning_tokens"`
	AudioTokens              uint64 `json:"audio_tokens"`
	AcceptedPredictionTokens uint64 `json:"accepted_prediction_tokens"`
	RejectedPredictionTokens uint64 `json:"rejected_prediction_tokens"`
}

func normalizeChatResponse(content []byte, route provider.RouteReference) (provider.Response, error) {
	if len(content) == 0 || len(content) > maximumResponseBytes || !utf8.Valid(content) || validateChatJSONShape(content) != nil {
		return provider.Response{}, ErrInvalidConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var wire chatResponseWire
	if decoder.Decode(&wire) != nil || requireJSONEOF(decoder) != nil || wire.ID == "" || len(wire.ID) > 512 || wire.Object != "chat.completion" || wire.Model != modelSelector(route) || !wire.Timings.valid() || len(wire.Choices) != 1 || wire.SystemFingerprint != nil && len(*wire.SystemFingerprint) > 512 || wire.ServiceTier != nil && len(*wire.ServiceTier) > 64 {
		return provider.Response{}, ErrInvalidConfig
	}
	choice := wire.Choices[0]
	if choice.Index == nil || *choice.Index != 0 || !nullOrAbsent(choice.Logprobs) {
		return provider.Response{}, ErrInvalidConfig
	}
	finish, err := provider.ParseResponseFinishReason(choice.FinishReason)
	if err != nil || finish == provider.ResponseFinishToolCalls {
		return provider.Response{}, ErrInvalidConfig
	}
	message := choice.Message
	if message.Role != "assistant" || message.ReasoningContent != nil && (!utf8.ValidString(*message.ReasoningContent) || len(*message.ReasoningContent) > maximumResponseBytes) || len(message.Annotations) != 0 || len(message.ToolCalls) != 0 || !nullOrAbsent(message.FunctionCall) || !nullOrAbsent(message.Audio) {
		return provider.Response{}, ErrInvalidConfig
	}
	if finish == provider.ResponseFinishLength && (message.Refusal == nil || *message.Refusal == "") && (message.Content == nil || strings.TrimSpace(*message.Content) == "") {
		return provider.Response{}, exhaustedWithUsage(normalizeChatUsage(wire.Usage))
	}
	item := messageContentWire{Type: "output_text"}
	if message.Content != nil {
		item.Text = *message.Content
	}
	if message.Refusal != nil && *message.Refusal != "" {
		item.Type = "refusal"
		item.Refusal = *message.Refusal
	}
	part, err := normalizeContent(item)
	if err != nil {
		return provider.Response{}, err
	}
	usage, err := normalizeChatUsage(wire.Usage)
	if err != nil {
		return provider.Response{}, err
	}
	return provider.NewResponse(provider.CapabilityReviewV1, finish, []provider.ResponsePart{part}, usage)
}

func normalizeChatUsage(wire *chatUsageWire) (provider.RouteTokenUsage, error) {
	if wire == nil {
		return provider.NewUnknownRouteTokenUsage(), nil
	}
	if wire.PromptTokens == nil || wire.CompletionTokens == nil || wire.TotalTokens == nil {
		return provider.RouteTokenUsage{}, ErrInvalidConfig
	}
	cached := uint64(0)
	if details := wire.PromptTokensDetails; details != nil {
		cached = details.CachedTokens
		if cached > *wire.PromptTokens || details.AudioTokens > *wire.PromptTokens {
			return provider.RouteTokenUsage{}, ErrInvalidConfig
		}
	}
	if details := wire.CompletionTokensDetails; details != nil {
		for _, count := range []uint64{details.ReasoningTokens, details.AudioTokens, details.AcceptedPredictionTokens, details.RejectedPredictionTokens} {
			if count > *wire.CompletionTokens {
				return provider.RouteTokenUsage{}, ErrInvalidConfig
			}
		}
	}
	return normalizeUsage(&usageWire{InputTokens: *wire.PromptTokens, OutputTokens: *wire.CompletionTokens, TotalTokens: *wire.TotalTokens, InputTokenDetails: &inputTokenDetailsWire{CachedTokens: cached}})
}

func validateChatJSONShape(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := scanJSONValueWithKeys(decoder, func(key string) bool {
		if !canonicalResponseKey(key) {
			return false
		}
		for _, value := range key {
			if value > 0x7e {
				return false
			}
		}
		return true
	}); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func nullOrAbsent(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
