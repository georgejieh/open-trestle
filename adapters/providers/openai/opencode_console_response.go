package openai

import (
	"bytes"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/provider"
)

type openCodeConsoleBillingWire struct {
	BillingSource string                  `json:"billing_source"`
	ListCost      json.RawMessage         `json:"list_cost"`
	Estimated     json.RawMessage         `json:"estimated"`
	Tokens        *openCodeGoBilledTokens `json:"tokens"`
}

func normalizeOpenCodeConsoleResponse(content []byte, route provider.RouteReference) (provider.Response, error) {
	if len(content) == 0 || len(content) > maximumResponseBytes || !utf8.Valid(content) || validateChatJSONShape(content) != nil {
		return provider.Response{}, ErrInvalidConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var wire openCodeGoResponseWire
	if decoder.Decode(&wire) != nil || requireJSONEOF(decoder) != nil {
		return provider.Response{}, ErrInvalidConfig
	}
	usage, err := normalizeOpenCodeConsoleUsage(wire.Usage)
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
	response, err := normalizeChatResponse(generic, route)
	if err != nil {
		return provider.Response{}, err
	}
	// The neutral two-rate contract cannot represent Console's billed counters or
	// provisional charge. Unknown usage keeps its existing budget reservation.
	return provider.NewResponse(response.Capability(), response.FinishReason(), response.Parts(), provider.NewUnknownRouteTokenUsage())
}

func normalizeOpenCodeConsoleUsage(w *openCodeGoUsageWire) (*chatUsageWire, error) {
	if w == nil {
		return nil, nil
	}
	if w.PromptTokens == nil || w.CompletionTokens == nil || *w.PromptTokens > ^uint64(0)-*w.CompletionTokens {
		return nil, ErrInvalidConfig
	}
	if !nullOrAbsent(w.Cost) {
		if _, err := parseOpenCodeConsoleMicroUSD(w.Cost); err != nil {
			return nil, err
		}
	}
	total := *w.PromptTokens + *w.CompletionTokens
	if len(w.TotalTokens) != 0 {
		var provided *uint64
		if json.Unmarshal(w.TotalTokens, &provided) != nil || provided == nil || *provided != total {
			return nil, ErrInvalidConfig
		}
	}
	if len(w.OpenCode) != 0 {
		var billing *openCodeConsoleBillingWire
		decoder := json.NewDecoder(bytes.NewReader(w.OpenCode))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&billing) != nil || requireJSONEOF(decoder) != nil || billing == nil || billing.BillingSource != "balance" || !validOpenCodeGoBilledTokens(billing.Tokens) || len(billing.Estimated) != 0 && !bytes.Equal(bytes.TrimSpace(billing.Estimated), []byte("false")) {
			return nil, ErrInvalidConfig
		}
		if _, err := parseOpenCodeConsoleMicroUSD(billing.ListCost); err != nil {
			return nil, err
		}
	}
	return &chatUsageWire{PromptTokens: w.PromptTokens, CompletionTokens: w.CompletionTokens, TotalTokens: &total, PromptTokensDetails: w.PromptTokensDetails, CompletionTokensDetails: w.CompletionTokensDetails}, nil
}

// parseOpenCodeConsoleMicroUSD rounds a bounded reported dollar amount upward.
func parseOpenCodeConsoleMicroUSD(raw json.RawMessage) (uint64, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > 64 || raw[0] < '0' || raw[0] > '9' || !json.Valid(raw) {
		return 0, ErrInvalidConfig
	}
	text := string(raw)
	if i := strings.IndexAny(text, "eE"); i >= 0 {
		exponent, err := strconv.Atoi(text[i+1:])
		if err != nil || exponent < -64 || exponent > 64 {
			return 0, ErrInvalidConfig
		}
	}
	amount, ok := new(big.Rat).SetString(text)
	if !ok || amount.Sign() < 0 {
		return 0, ErrInvalidConfig
	}
	amount.Mul(amount, big.NewRat(1000000, 1))
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(amount.Num(), amount.Denom(), remainder)
	if remainder.Sign() != 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if !quotient.IsUint64() {
		return 0, ErrInvalidConfig
	}
	return quotient.Uint64(), nil
}
