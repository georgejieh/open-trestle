package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The per-request review output allowance defaults to 4096 and can be raised
// within the declared output capacity, for example for a reasoning verifier
// that would otherwise exhaust its allowance before answering.

func TestSetupBootstrapLocalMaxOutputTokens(t *testing.T) {
	args, dir, _, _ := bootstrapFixture(t)
	bootstrapInvoke(t, args, 3)
	if template := stringMustRead(t, filepath.Join(dir, "policy-template.json")); !strings.Contains(template, `"max_output_tokens":4096`) {
		t.Fatalf("default allowance changed: %s", template)
	}
	raised, raisedDir, _, _ := bootstrapFixture(t)
	bootstrapInvoke(t, append(raised, "--max-output-tokens", "8192"), 3)
	if template := stringMustRead(t, filepath.Join(raisedDir, "policy-template.json")); !strings.Contains(template, `"max_output_tokens":8192`) {
		t.Fatalf("raised allowance not written: %s", template)
	}
	for _, value := range []string{"8193", "4095"} {
		refused, _, _, _ := bootstrapFixture(t)
		var out, errOut bytes.Buffer
		if code := runSetupWithClock(append([]string{"bootstrap"}, append(refused, "--max-output-tokens", value)...), &out, &errOut, fixedSetupClock{setupTimeCLI()}); code != 2 {
			t.Fatalf("--max-output-tokens %s accepted: code=%d", value, code)
		}
	}
}

func TestSetupBootstrapRemoteMaxOutputTokens(t *testing.T) {
	// The test binary has no injected secret scanner, so init reports the
	// scanner check as refused; it still writes the derived policy.
	invoke := func(args []string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"setup", "bootstrap"}, args...), &stdout, &stderr)
		return code, stdout.String() + stderr.String()
	}
	args, dir := remoteBootstrapArgs(t, "ollama-cloud")
	invoke(args)
	if policy := stringMustRead(t, filepath.Join(dir, "policy.json")); !strings.Contains(policy, `"max_output_tokens":4096`) {
		t.Fatalf("default allowance changed: %s", policy)
	}
	raised, raisedDir := remoteBootstrapArgs(t, "ollama-cloud")
	invoke(append(raised, "--max-output-tokens", "8192"))
	if policy := stringMustRead(t, filepath.Join(raisedDir, "policy.json")); !strings.Contains(policy, `"max_output_tokens":8192`) {
		t.Fatalf("raised allowance not written: %s", policy)
	}
	refused, refusedDir := remoteBootstrapArgs(t, "ollama-cloud")
	code, output := invoke(append(refused, "--max-output-tokens", "8193"))
	if code == 0 || !strings.Contains(output, "--max-output-tokens must be from 4096 to the declared --output-tokens (8192)") {
		t.Fatalf("out-of-capacity allowance code=%d output=%s", code, output)
	}
	if _, err := os.Stat(filepath.Join(refusedDir, "policy.json")); !os.IsNotExist(err) {
		t.Fatal("refused allowance still wrote a policy")
	}
}

func TestInitWizardPassesMaxOutputTokensOnlyWhenGiven(t *testing.T) {
	for _, provider := range []string{"local", "ollama-cloud"} {
		plain := &initWizard{flags: map[string]string{}}
		plain.a.provider = initProviderInfo{key: provider}
		if strings.Contains(strings.Join(plain.bootstrapArgs(), " "), "--max-output-tokens") || plain.reviewOutputTokens() != 4096 {
			t.Fatalf("%s: default wizard arguments changed", provider)
		}
		raised := &initWizard{flags: map[string]string{"max-output-tokens": "8192"}}
		raised.a.provider = initProviderInfo{key: provider}
		if !strings.Contains(strings.Join(raised.bootstrapArgs(), " "), "--max-output-tokens 8192") || raised.reviewOutputTokens() != 8192 {
			t.Fatalf("%s: --max-output-tokens not passed to bootstrap", provider)
		}
	}
}
