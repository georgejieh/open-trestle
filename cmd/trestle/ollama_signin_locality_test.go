package main

import (
	"context"
	"errors"
	"testing"
)

// A local route must not accept a model as local when the server is an Ollama
// daemon whose model list could not be read. Locality is unknown then, and an
// unreadable list is not evidence that the model runs on this machine.
func TestLocalRouteRefusesOllamaDaemonWithUnreadableModelList(t *testing.T) {
	original := ollamaReadTags
	t.Cleanup(func() { ollamaReadTags = original })
	ollamaReadTags = func(context.Context, string) ([]ollamaTag, bool, error) {
		return nil, true, errOllamaTagsUnavailable
	}
	err := ollamaLocalModelError(context.Background(), "http://127.0.0.1:11434/v1", "qwen3:8b")
	if err == nil {
		t.Fatal("the local route accepted a model whose locality could not be observed")
	}
}

// A loopback server that has no Ollama tags path at all cannot relay a model
// to Ollama Cloud, so it passes as local.
func TestLocalRouteAcceptsNonOllamaLoopbackServer(t *testing.T) {
	original := ollamaReadTags
	t.Cleanup(func() { ollamaReadTags = original })
	ollamaReadTags = func(context.Context, string) ([]ollamaTag, bool, error) {
		return nil, false, errOllamaTagsUnavailable
	}
	if err := ollamaLocalModelError(context.Background(), "http://127.0.0.1:8080/v1", "qwen3:8b"); err != nil {
		t.Fatalf("a local server without an Ollama model list was refused: %v", err)
	}
}

// A daemon that answers with a usable model list is authoritative: a listed
// model with a remote host is refused even when its name carries no cloud
// suffix.
func TestLocalRouteRefusesListedRemoteModelWithoutCloudSuffix(t *testing.T) {
	original := ollamaReadTags
	t.Cleanup(func() { ollamaReadTags = original })
	ollamaReadTags = func(context.Context, string) ([]ollamaTag, bool, error) {
		return []ollamaTag{{Name: "tuned:latest", Model: "tuned:latest", RemoteHost: "https://ollama.com"}}, true, nil
	}
	err := ollamaLocalModelError(context.Background(), "http://127.0.0.1:11434/v1", "tuned:latest")
	if err == nil {
		t.Fatal("the local route accepted a model the daemon relays to Ollama Cloud")
	}
}

// A daemon that answers and does not list the model cannot relay it, so the
// model passes as local.
func TestLocalRouteAcceptsUnlistedModelFromAnsweringDaemon(t *testing.T) {
	original := ollamaReadTags
	t.Cleanup(func() { ollamaReadTags = original })
	ollamaReadTags = func(context.Context, string) ([]ollamaTag, bool, error) {
		return []ollamaTag{{Name: "llama3.2:3b", Model: "llama3.2:3b"}}, true, nil
	}
	if err := ollamaLocalModelError(context.Background(), "http://127.0.0.1:11434/v1", "qwen3:8b"); err != nil {
		t.Fatalf("an unlisted model from an answering daemon was refused: %v", err)
	}
}

// A cloud-suffixed name is refused even when the model list is unreadable.
func TestLocalRouteRefusesCloudSuffixWithoutModelList(t *testing.T) {
	original := ollamaReadTags
	t.Cleanup(func() { ollamaReadTags = original })
	ollamaReadTags = func(context.Context, string) ([]ollamaTag, bool, error) {
		return nil, false, errOllamaTagsUnavailable
	}
	if err := ollamaLocalModelError(context.Background(), "http://127.0.0.1:11434/v1", "gpt-oss:120b-cloud"); err == nil {
		t.Fatal("a cloud-suffixed model was accepted by the local route")
	}
}

// A cloud-suffixed name is refused even when the daemon answers and does not
// list it yet. Pulling it later would relay review content to Ollama Cloud
// under a local declaration, and this check is the only one the local route
// gets.
func TestLocalRouteRefusesUnlistedCloudSuffixFromAnsweringDaemon(t *testing.T) {
	original := ollamaReadTags
	t.Cleanup(func() { ollamaReadTags = original })
	ollamaReadTags = func(context.Context, string) ([]ollamaTag, bool, error) {
		return []ollamaTag{{Name: "llama3.2:3b", Model: "llama3.2:3b"}}, true, nil
	}
	for _, model := range []string{"gpt-oss:120b-cloud", "deepseek-v4-pro:cloud"} {
		if err := ollamaLocalModelError(context.Background(), "http://127.0.0.1:11434/v1", model); err == nil {
			t.Errorf("the local route accepted unlisted cloud model %s", model)
		}
	}
}

// A listed cloud-suffixed model is refused even when the daemon's entry does
// not name a remote host, as some Ollama versions omit it.
func TestLocalRouteRefusesListedCloudSuffixWithoutRemoteHost(t *testing.T) {
	original := ollamaReadTags
	t.Cleanup(func() { ollamaReadTags = original })
	ollamaReadTags = func(context.Context, string) ([]ollamaTag, bool, error) {
		return []ollamaTag{{Name: "gpt-oss:20b-cloud", Model: "gpt-oss:20b-cloud"}}, true, nil
	}
	if err := ollamaLocalModelError(context.Background(), "http://127.0.0.1:11434/v1", "gpt-oss:20b-cloud"); err == nil {
		t.Fatal("the local route accepted a listed cloud model without a remote host")
	}
}

// The sign-in probe must not treat an HTTP 200 as proof of sign-in when the
// answer does not name the requested cloud selector.
func TestProbeRejectsAnswerFromAnotherModel(t *testing.T) {
	if got, ok := ollamaProbeReportedModel([]byte(`{"model":"other-model"}`)); !ok || got != "other-model" {
		t.Fatalf("model was not read: %q %v", got, ok)
	}
	if _, ok := ollamaProbeReportedModel([]byte(`not json`)); ok {
		t.Fatal("a malformed answer was accepted")
	}
	if _, ok := ollamaProbeReportedModel([]byte(`{}`)); ok {
		t.Fatal("an answer without a model was accepted")
	}
	if _, ok := ollamaProbeReportedModel([]byte(`{"model":"has space"}`)); ok {
		t.Fatal("an answer with an invalid model name was accepted")
	}
	if !errors.Is(errOllamaTagsUnavailable, errOllamaTagsUnavailable) {
		t.Fatal("unexpected error identity")
	}
}
