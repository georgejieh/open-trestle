package openai

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// Ollama's OpenAI-compatible endpoint differs from the generic Chat shape in
// two observed ways: reasoning models return their trace as message.reasoning,
// and a relayed cloud model answers with its remote name (gpt-oss:120b for
// gpt-oss:120b-cloud, deepseek-v4-pro:0813 for deepseek-v4-pro:cloud).
type ollamaSigninResponseWire struct {
	chatResponseWire
	Choices []ollamaSigninChoiceWire `json:"choices"`
}

type ollamaSigninChoiceWire struct {
	chatChoiceWire
	Message ollamaSigninMessageWire `json:"message"`
}

type ollamaSigninMessageWire struct {
	chatMessageWire
	Reasoning *string `json:"reasoning"`
}

func normalizeOllamaSigninResponse(content []byte, route provider.RouteReference) (provider.Response, error) {
	if len(content) == 0 || len(content) > maximumResponseBytes || !utf8.Valid(content) || validateChatJSONShape(content) != nil {
		return provider.Response{}, ErrInvalidConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var wire ollamaSigninResponseWire
	if decoder.Decode(&wire) != nil || requireJSONEOF(decoder) != nil || !ollamaRelayedModelMatches(modelSelector(route), wire.Model) {
		return provider.Response{}, ErrInvalidConfig
	}
	// The generic normalizer binds the response to the requested selector; the
	// relayed name was checked above, so restore the requested one.
	wire.chatResponseWire.Model = modelSelector(route)
	wire.chatResponseWire.Choices = make([]chatChoiceWire, len(wire.Choices))
	for i, choice := range wire.Choices {
		// The reasoning trace is validated and discarded, never treated as output.
		if reasoning := choice.Message.Reasoning; reasoning != nil && (!utf8.ValidString(*reasoning) || len(*reasoning) > maximumResponseBytes) {
			return provider.Response{}, ErrInvalidConfig
		}
		message := choice.Message.chatMessageWire
		if message.Content != nil {
			unfenced := unwrapOllamaJSONFence(*message.Content)
			message.Content = &unfenced
		}
		choice.chatChoiceWire.Message = message
		wire.chatResponseWire.Choices[i] = choice.chatChoiceWire
	}
	generic, err := json.Marshal(wire.chatResponseWire)
	if err != nil {
		return provider.Response{}, ErrInvalidConfig
	}
	return normalizeChatResponse(generic, route)
}

// unwrapOllamaJSONFence removes exactly one outer Markdown code fence. Ollama
// ignores response_format for relayed cloud models, and some of them fence
// their JSON despite the contract. The unwrapped text still goes through the
// same strict output validation; anything other than a single outer fence is
// returned unchanged and refused there.
func unwrapOllamaJSONFence(content string) string {
	trimmed := strings.TrimSpace(content)
	body, found := strings.CutPrefix(trimmed, "```")
	if !found {
		return content
	}
	newline := strings.IndexByte(body, '\n')
	if newline < 0 {
		return content
	}
	if language := strings.TrimSpace(body[:newline]); language != "" && language != "json" {
		return content
	}
	body, found = strings.CutSuffix(body[newline+1:], "```")
	if !found || strings.Contains(body, "```") {
		return content
	}
	return strings.TrimSpace(body)
}

// ollamaRelayedModelMatches accepts the requested cloud selector itself or the
// remote name Ollama reports for it: "name:tag-cloud" answers as "name:tag",
// and "name:cloud" answers as "name" or "name:<version>".
func ollamaRelayedModelMatches(requested, reported string) bool {
	if reported == requested {
		return true
	}
	if !ollamaCloudSelector(requested) || reported == "" || len(reported) > 1024 || strings.ContainsAny(reported, " \t\r\n/") {
		return false
	}
	index := strings.LastIndex(requested, ":")
	name, tag := requested[:index], requested[index+1:]
	if tag == "cloud" {
		if reported == name {
			return true
		}
		version, found := strings.CutPrefix(reported, name+":")
		return found && version != "" && !strings.Contains(version, ":")
	}
	return reported == name+":"+strings.TrimSuffix(tag, "-cloud")
}
