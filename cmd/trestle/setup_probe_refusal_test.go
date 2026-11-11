package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/routehint"
)

// setupProbeRefusalArgs initializes a direct-review local bootstrap over the
// wizard's loopback model servers, whose finder answers the setup probe as
// mode says.
func setupProbeRefusalArgs(t *testing.T, mode string) (string, []string) {
	t.Helper()
	checkout, generation, verification, _ := initLocalModelServers(t, false, mode)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, []string{"init", "--directory", dir, "--scope", "direct-review", "--tenant", "tenant-local", "--repository", "repository-local", "--recovery-owner", "owner", "--checkout", checkout, "--base", "refs/heads/base", "--head", "refs/heads/review", "--repository-authority", "example.test", "--repository-namespace", "private/team", "--repository-name", "sample", "--generation-endpoint", generation, "--generation-model", "model-a", "--verification-endpoint", verification, "--verification-model", "model-b", "--transport", "openai_chat_completions", "--context-tokens", "128000", "--output-tokens", "8192", "--declare-local-capabilities"}
}

// A model server that refuses the synthetic probe with a provider refusal is
// named with the review's fixed detail and hint; the server's own message
// text is never repeated. A probe that fails otherwise keeps its plain
// refusal, and a probe that was not run names nothing.
func TestSetupBootstrapCheckNamesTheProbeRefusal(t *testing.T) {
	_, payment, _ := routehint.ProviderRefusal(gateway.RouteFailurePaymentRequired)
	_, retired, _ := routehint.ProviderRefusal(gateway.RouteFailureModelRetired)
	_, missing, _ := routehint.ProviderRefusal(gateway.RouteFailureModelUnavailable)
	for _, test := range []struct {
		mode, want string
	}{
		{"probe_refuse_402", "local_inference_validated: provider_payment_required: " + payment},
		{"probe_refuse_404", "local_inference_validated: provider_model_unavailable: " + missing},
		{"probe_refuse_410", "local_inference_validated: provider_model_retired: " + retired},
	} {
		t.Run(test.mode, func(t *testing.T) {
			dir, args := setupProbeRefusalArgs(t, test.mode)
			if initial := bootstrapInvoke(t, args, 3); len(initial.Messages) != 0 {
				t.Fatalf("init carried messages: %v", initial.Messages)
			}
			unprobed := bootstrapInvoke(t, []string{"check", "--directory", dir, "--approved-by", "owner"}, 0)
			if len(unprobed.Messages) != 0 {
				t.Fatalf("a check without the probe carried messages: %v", unprobed.Messages)
			}
			var out, errOut bytes.Buffer
			code := runSetupWithClock([]string{"bootstrap", "check", "--directory", dir, "--approved-by", "owner", "--allow-local-probe"}, &out, &errOut, fixedSetupClock{setupTimeCLI()})
			var result setupBootstrapResult
			if code != 4 || errOut.Len() != 0 || json.Unmarshal(out.Bytes(), &result) != nil {
				t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
			}
			if result.Ready || result.Status != "refused" || !slices.Contains(result.Pending, "local_inference_validated") || !slices.Equal(result.Messages, []string{test.want}) {
				t.Fatalf("refused probe result: %+v", result)
			}
			for _, forbidden := range []string{localModelRefusalText, "usage credits", "retired on", "not found, try pulling"} {
				if strings.Contains(out.String(), forbidden) {
					t.Fatalf("bootstrap check repeated the server's message %q", forbidden)
				}
			}
		})
	}
	// A probe the server rejects as a bad request is refused as before,
	// without a provider reason.
	dir, args := setupProbeRefusalArgs(t, "probe_refuse_400")
	bootstrapInvoke(t, args, 3)
	if rejected := bootstrapInvoke(t, []string{"check", "--directory", dir, "--approved-by", "owner", "--allow-local-probe"}, 4); rejected.Status != "refused" || len(rejected.Messages) != 0 {
		t.Fatalf("a rejected probe named a provider refusal: %+v", rejected)
	}
}

// The init wizard shows the bootstrap check's reason for a refused test
// request instead of its generic advice.
func TestInitLocalShowsTheProbeRefusalReason(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "")
	t.Setenv("OPEN_TRESTLE_OBSERVER_TOKEN", "")
	checkout, generation, verification, _ := initLocalModelServers(t, false, "probe_refuse_410")
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"},
		"4",             // a model server on this machine
		"5", generation, // another address
		"1",
		"5", verification,
		"1",
		"",    // use the settings shown
		"yes", // local capabilities
		"y",   // send the synthetic test requests
	)
	output := strings.Join(strings.Fields(result.stdout), " ")
	_, retired, _ := routehint.ProviderRefusal(gateway.RouteFailureModelRetired)
	if result.code != 4 || !strings.Contains(output, "A model server refused the test request (provider_model_retired): "+retired+".") || strings.Contains(output, "in the expected format. Check that both servers") {
		t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	if initHas(result.stdout+result.stderr, localModelRefusalText) {
		t.Fatal("the wizard repeated the server's message")
	}
}
