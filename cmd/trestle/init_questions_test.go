package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/modelcatalog"
)

// All servers, models and remotes below are synthetic offline fixtures.

func TestInitRemoteIdentityReadsHostNamespaceAndNameOnly(t *testing.T) {
	for raw, want := range map[string][3]string{
		"https://github.com/GeorgeJieh/Open-Trestle.git":         {"github.com", "georgejieh", "open-trestle"},
		"git@gitlab.example.com:group/sub/project.git":           {"gitlab.example.com", "group/sub", "project"},
		"ssh://git@host.example:2222/team/repo":                  {"host.example", "team", "repo"},
		"https://user:secret-token@github.com/owner/project.git": {"github.com", "owner", "project"},
		"https://x-access-token:ghp_fixture@github.com/o/r":      {"github.com", "o", "r"},
	} {
		authority, namespace, name, ok := initRemoteIdentity(raw)
		if !ok || [3]string{authority, namespace, name} != want {
			t.Fatalf("%s = (%q, %q, %q, %t), want %v", raw, authority, namespace, name, ok, want)
		}
		if strings.Contains(authority+namespace+name, "secret") || strings.Contains(authority+namespace+name, "ghp_") {
			t.Fatalf("%s leaked a credential into a label", raw)
		}
	}
	for _, raw := range []string{"", "/srv/git/project.git", "file:///srv/git/project.git", "../project", "https://github.com/only-one"} {
		if _, _, _, ok := initRemoteIdentity(raw); ok {
			t.Fatalf("%q produced labels", raw)
		}
	}
}

// initQuestionCount runs the wizard with exactly the given answers, which must
// finish, and with one fewer, which must run out of input: the path asks
// exactly that many questions.
func initQuestionCount(t *testing.T, checkout string, args []string, answers ...string) initRun {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "setup")
	full := runInitScript(t, checkout, append([]string{"--directory", dir}, args...), answers...)
	if full.code != initExitDone {
		t.Fatalf("with %d answers: exit=%d\n%s\n%s", len(answers), full.code, full.stdout, full.stderr)
	}
	short := runInitScript(t, checkout, append([]string{"--directory", filepath.Join(t.TempDir(), "setup")}, args...), answers[:len(answers)-1]...)
	if short.code != initExitUsage || !initHas(short.stderr, "input ended") {
		t.Fatalf("with %d answers the wizard did not need another: exit=%d\n%s", len(answers)-1, short.code, short.stderr)
	}
	return full
}

func initLocalServerWithModels(t *testing.T, f *localModelFixture) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/models" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": []any{map[string]any{"id": f.generation.model, "object": "model"}, map[string]any{"id": f.verification.model, "object": "model"}}})
			return
		}
		if strings.Contains(r.URL.Path, "chat") {
			http.Error(w, "not used", http.StatusTeapot)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL + "/v1"
}

func TestInitAsksOnlyWhatOnlyTheUserKnows(t *testing.T) {
	remoteScannerInstalled(t)
	t.Run("openrouter", func(t *testing.T) {
		t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
		fakeOpenRouter(t, initOpenRouterModels()...)
		result := initQuestionCount(t, remoteBootstrapCheckout(t), []string{"--base", "refs/heads/base", "--head", "refs/heads/review", "--generation-model", "vendor/generator", "--verification-model", "other/verifier"},
			"1", "", "", "", "yes", "n") // provider, ZDR, cost cap, settings, consent, review
		for _, unasked := range []string{"Review these changes?", "Environment variable that holds the key", "Keep these names?", "Context window", "provider slug"} {
			if initHas(result.stdout, unasked) {
				t.Fatalf("asked %q:\n%s", unasked, result.stdout)
			}
		}
	})
	t.Run("ollama cloud", func(t *testing.T) {
		t.Setenv("OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD", remoteTestKey)
		initFakeModelList(t, "gemma4:31b", "qwen3.5:397b")
		// The model list states no limits, so they are asked; the plan is the user's.
		initQuestionCount(t, remoteBootstrapCheckout(t), []string{"--base", "refs/heads/base", "--head", "refs/heads/review"},
			"2", "1", "2", "128000", "8192", "n", "", "yes", "n")
	})
	t.Run("local server found on this machine", func(t *testing.T) {
		f := newLocalModelFixture(t, localModelFixtureOptions{noAuth: true, chatCompletions: true})
		endpoint := initLocalServerWithModels(t, f)
		initFakeLocalServers = []initLocalServer{{name: "Ollama", endpoint: endpoint, models: []modelcatalog.Model{{Selector: f.generation.model}, {Selector: f.verification.model}}}}
		t.Cleanup(func() { initFakeLocalServers = nil })
		checkout, _, _, _ := initLocalModelServers(t, false)
		result := initQuestionCount(t, checkout, []string{"--base", "refs/heads/base", "--head", "refs/heads/review"},
			"4", "1", "2", "", "yes", "n", "n") // provider, finder, checker, settings, consent, test requests, review
		for _, want := range []string{"Found Ollama at " + endpoint, "Limits: context 32768 and output 4096 tokens", "No key: requests to your local server are sent without one."} {
			if !initHas(result.stdout, want) {
				t.Fatalf("output lacks %q:\n%s", want, result.stdout)
			}
		}
		for _, unasked := range []string{"Which server are you running?", "Is the checker model on the same server?", "Does your local server require an API key?"} {
			if initHas(result.stdout, unasked) {
				t.Fatalf("asked %q:\n%s", unasked, result.stdout)
			}
		}
	})
}

func TestInitNamesComeFromTheGitRemoteAndCanBeChanged(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	t.Setenv("USER", "fixture-user")
	fakeOpenRouter(t, initOpenRouterModels()...)
	checkout := remoteBootstrapCheckout(t)
	checkoutGit(t, checkout, "config", "remote.origin.url", "https://fixture:token@git.example.test/team-a/widget.git")
	args := []string{"--base", "refs/heads/base", "--head", "refs/heads/review", "--generation-model", "vendor/generator", "--verification-model", "other/verifier"}
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, append([]string{"--directory", dir}, args...),
		"1", "", "",
		"n", "2", // change the names
		"", "work", "", "", "", "", // keep each proposed name except the tenant
		"", // use the settings shown
		"yes", "n",
	)
	if result.code != initExitDone {
		t.Fatalf("exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	for _, want := range []string{"Source   git.example.test/team-a/widget", "fixture-user", "tenant work · repository widget"} {
		if !initHas(result.stdout, want) {
			t.Fatalf("summary lacks %q:\n%s", want, result.stdout)
		}
	}
	saved := stringMustRead(t, filepath.Join(dir, "bootstrap.json"))
	for _, want := range []string{`"--repository-authority","git.example.test"`, `"--repository-namespace","team-a"`, `"--repository-name","widget"`, `"--tenant","work"`} {
		if !strings.Contains(saved, want) {
			t.Fatalf("saved review command lacks %s:\n%s", want, saved)
		}
	}
	if strings.Contains(result.stdout+saved, "token@") {
		t.Fatal("the remote's credential was shown or saved")
	}
}
