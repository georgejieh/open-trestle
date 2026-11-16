package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestRuntimePolicyChatCompletionsIsExplicitAndIdentityBound(t *testing.T) {
	inventory := bindingInventory(t, bindingInventoryDocument(t))
	original, err := bindRuntimePolicy(context.Background(), inventory, bindingTemplate(t), "adapter-a", "adapter-b")
	if err != nil {
		t.Fatal(err)
	}
	responses, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(original), inventory)
	if err != nil {
		t.Fatal(err)
	}
	chatDocument := bytes.ReplaceAll(original, []byte("openai_responses"), []byte("openai_chat_completions"))
	chat, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(chatDocument), inventory)
	if err != nil || chat.Validate() != nil || chat.ValidateAgainstInventory(inventory) != nil || chat.Connections()[0].Implementation() != "openai_chat_completions" || chat.Identity() == responses.Identity() {
		t.Fatalf("chat policy=%#v err=%v", chat, err)
	}
	for _, invalid := range []string{"", "chat_completions", "OpenAI_Chat_Completions", "openrouter_chat_completions", "subscription_oauth"} {
		document := bytes.ReplaceAll(original, []byte("openai_responses"), []byte(invalid))
		if _, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(document), inventory); err == nil {
			t.Fatalf("accepted implementation %q", invalid)
		}
	}
	var wire runtimePolicyWire
	if err := json.Unmarshal(original, &wire); err != nil {
		t.Fatal(err)
	}
	wire.SchemaVersion = 1
	wire.VerificationRouteRecordIdentity = nil
	v1 := bindingMarshal(t, wire)
	if _, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(v1), inventory); err != nil {
		t.Fatal(err)
	}
	v1Chat := bytes.ReplaceAll(v1, []byte("openai_responses"), []byte("openai_chat_completions"))
	if _, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(v1Chat), inventory); err == nil {
		t.Fatal("v1 admitted new protocol")
	}
}
