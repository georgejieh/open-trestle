package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestInitModelFamilyRecognizesCommonNames(t *testing.T) {
	for selector, want := range map[string]string{
		"qwen3.5:397b":                           "Qwen",
		"qwen/qwen3-coder":                       "Qwen",
		"accounts/fireworks/models/qwen3-235b":   "Qwen",
		"deepseek/deepseek-r1-distill-qwen-32b":  "Qwen",
		"deepseek/deepseek-chat-v3":              "DeepSeek",
		"gemma4:31b":                             "Gemma",
		"meta-llama/llama-3.3-70b-instruct":      "Llama",
		"nvidia/llama-3.1-nemotron-70b-instruct": "Llama",
		"openai/gpt-oss-120b":                    "GPT",
		"openai/o3":                              "GPT",
		"z-ai/glm-4.6":                           "GLM",
		"moonshotai/kimi-k2":                     "Kimi",
		"mistralai/devstral-small":               "Mistral",
		"my-finetune-v2":                         "",
		"fireworks/unknownmodel":                 "",
	} {
		if got := initModelFamily(selector); got != want {
			t.Errorf("initModelFamily(%q) = %q, want %q", selector, got, want)
		}
	}
	if got := initSameFamily("qwen3-coder:30b", "qwen3.5:397b"); got != "Qwen" {
		t.Fatalf("same family = %q", got)
	}
	if got := initSameFamily("qwen3-coder:30b", "gemma4:31b"); got != "" {
		t.Fatalf("different families reported as %q", got)
	}
	if got := initSameFamily("custom-a", "custom-b"); got != "" {
		t.Fatalf("unknown families reported as %q", got)
	}
}

func TestInitRecommendsACheckerFromAnotherFamily(t *testing.T) {
	remoteScannerInstalled(t)
	initFakeModelList(t, "qwen3-coder:30b", "qwen3.5:397b", "gemma4:31b")
	checkout := remoteBootstrapCheckout(t)
	args := []string{"--base", "refs/heads/base", "--head", "refs/heads/review", "--credential-env", "OPEN_TRESTLE_PROVIDER_UNSET_FOR_TEST"}

	// Enter keeps a same-family checker: the choice is recommended, not enforced.
	kept := runInitScript(t, checkout, append([]string{"--directory", filepath.Join(t.TempDir(), "setup")}, args...),
		"2", "1", "2", "", "128000", "8192", "n", "n", "5")
	keptText := initUnboxed(kept.stdout)
	if kept.code != initExitRefused || !initHas(keptText, "A model from a different family is recommended") ||
		!initHas(keptText, "both Qwen models") || !strings.Contains(kept.stdout, "Keep this checker?") ||
		!initHas(keptText, "same Qwen family as the finder") {
		t.Fatalf("kept same-family checker: exit=%d\n%s\n%s", kept.code, kept.stdout, kept.stderr)
	}

	// n picks again; a checker from another family gets no remark.
	changed := runInitScript(t, checkout, append([]string{"--directory", filepath.Join(t.TempDir(), "setup")}, args...),
		"2", "1", "2", "n", "3", "128000", "8192", "n", "n", "5")
	changedText := initUnboxed(changed.stdout)
	if changed.code != initExitRefused || strings.Count(changed.stdout, "both Qwen models") != 1 ||
		initHas(changedText, "same Qwen family as the finder") || !initHas(changedText, "Checker gemma4:31b") {
		t.Fatalf("re-picked checker: exit=%d\n%s\n%s", changed.code, changed.stdout, changed.stderr)
	}
}

// initUnboxed removes the settings panel's side borders so that wrapped panel
// text can be matched as one line.
func initUnboxed(text string) string {
	return strings.ReplaceAll(text, "│", " ")
}
