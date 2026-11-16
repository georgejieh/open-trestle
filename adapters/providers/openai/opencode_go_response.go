package openai

import (
	"bytes"
	"encoding/json"
	"math"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/provider"
)

type openCodeGoResponseWire struct {
	chatResponseWire
	Choices []openCodeGoChoiceWire `json:"choices"`
	Usage   *openCodeGoUsageWire   `json:"usage"`
}
type openCodeGoChoiceWire struct {
	chatChoiceWire
	Message openCodeGoMessageWire `json:"message"`
}
type openCodeGoMessageWire struct {
	chatMessageWire
	ReasoningContent *string `json:"reasoning_content"`
}
type openCodeGoUsageWire struct {
	PromptTokens            *uint64                    `json:"prompt_tokens"`
	CompletionTokens        *uint64                    `json:"completion_tokens"`
	TotalTokens             json.RawMessage            `json:"total_tokens"`
	PromptTokensDetails     *chatPromptDetailsWire     `json:"prompt_tokens_details"`
	CompletionTokensDetails *chatCompletionDetailsWire `json:"completion_tokens_details"`
	Cost                    json.RawMessage            `json:"cost"`
	OpenCode                json.RawMessage            `json:"opencode"`
}
type openCodeGoBillingWire struct {
	BillingSource string                  `json:"billing_source"`
	ListCost      json.RawMessage         `json:"list_cost"`
	Allowance     json.RawMessage         `json:"allowance"`
	Estimated     json.RawMessage         `json:"estimated"`
	Tokens        *openCodeGoBilledTokens `json:"tokens"`
}
type openCodeGoBilledTokens struct {
	Input        *uint64 `json:"input"`
	Output       *uint64 `json:"output"`
	Reasoning    *uint64 `json:"reasoning"`
	CacheRead    *uint64 `json:"cache_read"`
	CacheWrite5m *uint64 `json:"cache_write_5m"`
	CacheWrite1h *uint64 `json:"cache_write_1h"`
}

func normalizeOpenCodeGoResponse(content []byte, route provider.RouteReference) (provider.Response, error) {
	if len(content) == 0 || len(content) > maximumResponseBytes || !utf8.Valid(content) || validateChatJSONShape(content) != nil {
		return provider.Response{}, ErrInvalidConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var wire openCodeGoResponseWire
	if decoder.Decode(&wire) != nil || requireJSONEOF(decoder) != nil {
		return provider.Response{}, ErrInvalidConfig
	}
	usage, err := normalizeOpenCodeGoUsage(wire.Usage)
	if err != nil {
		return provider.Response{}, err
	}
	wire.chatResponseWire.Usage = usage
	wire.chatResponseWire.Choices = make([]chatChoiceWire, len(wire.Choices))
	for i, choice := range wire.Choices {
		if reasoning := choice.Message.ReasoningContent; reasoning != nil && (!utf8.ValidString(*reasoning) || len(*reasoning) > maximumResponseBytes) {
			return provider.Response{}, ErrInvalidConfig
		}
		choice.chatChoiceWire.Message = choice.Message.chatMessageWire
		wire.chatResponseWire.Choices[i] = choice.chatChoiceWire
	}
	generic, err := json.Marshal(wire.chatResponseWire)
	if err != nil {
		return provider.Response{}, ErrInvalidConfig
	}
	return normalizeChatResponse(generic, route)
}

func normalizeOpenCodeGoUsage(w *openCodeGoUsageWire) (*chatUsageWire, error) {
	if w == nil {
		return nil, nil
	}
	if w.PromptTokens == nil || w.CompletionTokens == nil || *w.PromptTokens > ^uint64(0)-*w.CompletionTokens || !validOpenCodeGoMoney(w.Cost, false, true) {
		return nil, ErrInvalidConfig
	}
	total := *w.PromptTokens + *w.CompletionTokens
	if len(w.TotalTokens) != 0 {
		var provided *uint64
		if json.Unmarshal(w.TotalTokens, &provided) != nil || provided == nil || *provided != total {
			return nil, ErrInvalidConfig
		}
	}
	if len(w.OpenCode) != 0 {
		var b *openCodeGoBillingWire
		decoder := json.NewDecoder(bytes.NewReader(w.OpenCode))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&b) != nil || requireJSONEOF(decoder) != nil || b == nil {
			return nil, ErrInvalidConfig
		}
		if b.BillingSource != "go" || !validOpenCodeGoMoney(b.ListCost, true, false) || !validOpenCodeGoMoney(b.Allowance, true, false) || len(b.Estimated) != 0 && !bytes.Equal(bytes.TrimSpace(b.Estimated), []byte("false")) || !validOpenCodeGoBilledTokens(b.Tokens) {
			return nil, ErrInvalidConfig
		}
	}
	return &chatUsageWire{PromptTokens: w.PromptTokens, CompletionTokens: w.CompletionTokens, TotalTokens: &total, PromptTokensDetails: w.PromptTokensDetails, CompletionTokensDetails: w.CompletionTokensDetails}, nil
}

func validOpenCodeGoBilledTokens(w *openCodeGoBilledTokens) bool {
	if w == nil || w.Input == nil || w.Output == nil || w.Reasoning == nil || w.CacheRead == nil || w.CacheWrite5m == nil || w.CacheWrite1h == nil || *w.Reasoning > *w.Output {
		return false
	}
	input := *w.Input
	for _, count := range []uint64{*w.CacheRead, *w.CacheWrite5m, *w.CacheWrite1h} {
		if input > ^uint64(0)-count {
			return false
		}
		input += count
	}
	_, err := provider.NewRouteTokenUsage(input, *w.Output, *w.CacheRead)
	return err == nil
}

func validOpenCodeGoMoney(raw json.RawMessage, required, zeroOnly bool) bool {
	if nullOrAbsent(raw) {
		return !required
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) > 64 || bytes.HasPrefix(raw, []byte("-")) {
		return false
	}
	var value float64
	if json.Unmarshal(raw, &value) != nil || math.IsInf(value, 0) || math.IsNaN(value) || value < 0 || zeroOnly && value != 0 {
		return false
	}
	if zeroOnly {
		for _, digit := range raw {
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
