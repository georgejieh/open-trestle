package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// The ollama-signin route sends review requests to a local Ollama daemon that
// relays Ollama Cloud models with the operator's own `ollama signin` account.
// Setup asks that daemon, with one bounded loopback GET of /api/tags, which
// models it relays to Ollama Cloud. The same read lets the local route refuse a
// cloud model that would otherwise pass as "local".

const (
	ollamaSigninProvider       = "ollama-signin"
	ollamaSigninDefaultBaseURL = "http://127.0.0.1:11434/v1"
	ollamaCloudRemoteHost      = "https://ollama.com"
	ollamaTagsMaxBytes         = 4 << 20
	ollamaTagsTimeout          = 5 * time.Second
	ollamaProbeTimeout         = 90 * time.Second
	ollamaProbeMaxBytes        = 1 << 20
	// ollamaCloudLocalRefusal is the fixed reason the local route gives for a
	// model the daemon relays to Ollama Cloud.
	ollamaCloudLocalRefusal = "this model runs on Ollama Cloud, not on this machine; use --provider ollama-signin"
	// ollamaSigninProbePrompt is the only content the sign-in check sends.
	ollamaSigninProbePrompt = "Reply with OK"
)

// ollamaTag is one /api/tags entry, reduced to the fields setup relies on.
type ollamaTag struct {
	Name, Model, RemoteModel, RemoteHost string
	ContextLength                        uint64
}

// errOllamaTagsUnavailable means no Ollama model list could be read at that
// address: nothing is listening, it is not an Ollama daemon, or it answered
// with something other than a bounded tags document.
var errOllamaTagsUnavailable = errors.New("no Ollama model list could be read")

// Tests replace these seams; production uses the bounded loopback requests below.
var (
	ollamaReadTags       = readOllamaDaemonTags
	ollamaSigninProbe    = probeOllamaSignin
	ollamaLookPath       = func() (string, error) { return exec.LookPath("ollama") }
	ollamaRunSigninChild = runOllamaSigninChild
)

// ollamaDaemonOrigin returns http://HOST:PORT for a numeric loopback HTTP base URL.
func ollamaDaemonOrigin(endpoint string) (string, error) {
	parsed, err := provider.ParseServiceEndpoint(endpoint)
	if err != nil || parsed.Scheme != "http" {
		return "", errOllamaTagsUnavailable
	}
	locality, err := provider.ClassifyServiceEndpoint(endpoint)
	if err != nil || locality != provider.ServiceEndpointLoopback {
		return "", errOllamaTagsUnavailable
	}
	return "http://" + parsed.Host, nil
}

// ollamaLoopbackClient never uses a proxy, never follows a redirect and dials
// only canonical numeric loopback addresses.
func ollamaLoopbackClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10, ResponseHeaderTimeout: timeout, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() || ip.String() != host {
			return nil, errOllamaTagsUnavailable
		}
		return dialer.DialContext(ctx, network, address)
	}}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// readOllamaDaemonTags performs one bounded GET of ORIGIN/api/tags. It sends no
// credential and no repository content.
//
// It also reports whether the server answered the Ollama tags path at all.
// A server that answers the path with something that is not a usable model
// list is an Ollama daemon whose list could not be read, which is different
// from a server that has no such path. The caller uses that distinction to
// refuse a local route when it cannot observe where a model runs.
func readOllamaDaemonTags(ctx context.Context, endpoint string) ([]ollamaTag, bool, error) {
	origin, err := ollamaDaemonOrigin(endpoint)
	if err != nil {
		return nil, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, ollamaTagsTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/api/tags", nil)
	if err != nil {
		return nil, false, errOllamaTagsUnavailable
	}
	request.Header.Set("Accept", "application/json")
	response, err := ollamaLoopbackClient(ollamaTagsTimeout).Do(request)
	if err != nil {
		return nil, false, errOllamaTagsUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, ollamaTagsMaxBytes+1))
	if response.StatusCode != http.StatusOK {
		// A server that does not answer the tags path is not an Ollama
		// daemon. It cannot relay a model to Ollama Cloud.
		return nil, false, errOllamaTagsUnavailable
	}
	answered := true
	if err != nil || len(body) > ollamaTagsMaxBytes {
		return nil, answered, errOllamaTagsUnavailable
	}
	var wire struct {
		Models *[]struct {
			Name        string `json:"name"`
			Model       string `json:"model"`
			RemoteModel string `json:"remote_model"`
			RemoteHost  string `json:"remote_host"`
			Details     struct {
				ContextLength uint64 `json:"context_length"`
			} `json:"details"`
		} `json:"models"`
	}
	if json.Unmarshal(body, &wire) != nil || wire.Models == nil || len(*wire.Models) > 4096 {
		return nil, answered, errOllamaTagsUnavailable
	}
	tags := make([]ollamaTag, 0, len(*wire.Models))
	for _, entry := range *wire.Models {
		tags = append(tags, ollamaTag{Name: entry.Name, Model: entry.Model, RemoteModel: entry.RemoteModel, RemoteHost: entry.RemoteHost, ContextLength: entry.Details.ContextLength})
	}
	return tags, answered, nil
}

func ollamaFindTag(tags []ollamaTag, model string) (ollamaTag, bool) {
	names := []string{model}
	if !strings.Contains(model, ":") {
		names = append(names, model+":latest")
	}
	for _, name := range names {
		for _, tag := range tags {
			if tag.Name == name || tag.Model == name {
				return tag, true
			}
		}
	}
	return ollamaTag{}, false
}

// ollamaCloudTag reports whether the daemon relays this entry to Ollama Cloud.
func ollamaCloudTag(tag ollamaTag) bool {
	return tag.RemoteHost == ollamaCloudRemoteHost && runtimeconfig.OllamaCloudModelID(tag.Name)
}

// ollamaCloudNameSuffix reports whether a model name carries the Ollama cloud
// suffix. The local route refuses such a name whatever the tags list says.
func ollamaCloudNameSuffix(model string) bool {
	return strings.HasSuffix(model, ":cloud") || strings.HasSuffix(model, "-cloud")
}

// ollamaLocalModelError refuses, for the local route, a model the daemon at
// endpoint relays to Ollama Cloud.
//
// A name with the Ollama cloud suffix is refused first, before the tags list
// is consulted. The list is a point-in-time observation: a cloud model that is
// not listed yet can be pulled later, and some daemon versions omit the remote
// host from a listed cloud entry. Nothing at review time stops a local route
// from using such a model, so this check must not let one through.
//
// The local bootstrap also accepts other loopback servers (llama.cpp, vLLM, LM
// Studio), which have no /api/tags document at all. Such a server cannot relay
// a model to Ollama Cloud, so a missing tags document is not by itself a
// reason to refuse them.
//
// The distinction comes from the tags read itself, never from a second
// request: readOllamaDaemonTags reports separately whether the server
// answered the Ollama tags path and whether the answer was a usable model
// list. A server that answers the path with an unusable list is an Ollama
// daemon whose list could not be read, so where the model runs is unknown and
// the local route refuses. A server that does not answer the path at all is
// not an Ollama daemon and passes.
func ollamaLocalModelError(ctx context.Context, endpoint, model string) error {
	if ollamaCloudNameSuffix(model) {
		return fmt.Errorf("%s: %s", model, ollamaCloudLocalRefusal)
	}
	tags, answered, err := ollamaReadTags(ctx, endpoint)
	if err == nil {
		if tag, found := ollamaFindTag(tags, model); found {
			if tag.RemoteHost != "" {
				return fmt.Errorf("%s: %s", model, ollamaCloudLocalRefusal)
			}
			return nil
		}
		// The daemon answered and does not list this name, which has no cloud
		// suffix, so it cannot be one of the daemon's cloud relays.
		return nil
	}
	if answered {
		// This is an Ollama daemon and its model list could not be read, so
		// where the model runs is unknown. The local route must not guess.
		return fmt.Errorf("%s: could not confirm that this model runs on this machine: %w at %s; start Ollama on this machine (ollama serve) and check the address, then retry", model, errOllamaTagsUnavailable, endpoint)
	}
	// A loopback server with no Ollama tags document cannot relay to Ollama
	// Cloud, so it passes as local.
	return nil
}

// checkOllamaSigninModels requires the daemon at endpoint to list every model
// with the Ollama cloud suffix and remote_host https://ollama.com. An
// unreachable daemon is reported as errOllamaTagsUnavailable.
func checkOllamaSigninModels(ctx context.Context, endpoint string, models ...string) ([]ollamaTag, error) {
	tags, _, err := ollamaReadTags(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w at %s: start Ollama on this machine (ollama serve) and check the address", errOllamaTagsUnavailable, endpoint)
	}
	found := []ollamaTag{}
	for _, model := range models {
		if !runtimeconfig.OllamaCloudModelID(model) {
			return nil, fmt.Errorf("%s is not an Ollama Cloud model: --provider ollama-signin sends only models whose tag is cloud or ends in -cloud (such as gpt-oss:120b-cloud); a model that runs on this machine belongs to the local bootstrap", model)
		}
		tag, ok := ollamaFindTag(tags, model)
		if !ok {
			return nil, fmt.Errorf("%s is not listed by the Ollama daemon at %s; run `ollama pull %s` first", model, endpoint, model)
		}
		if !ollamaCloudTag(tag) {
			return nil, fmt.Errorf("%s is listed by the Ollama daemon, but not as an Ollama Cloud model (remote host %q, want %s)", model, tag.RemoteHost, ollamaCloudRemoteHost)
		}
		found = append(found, tag)
	}
	return found, nil
}

// ollamaProbeOutcome is the result of the one synthetic sign-in request.
type ollamaProbeOutcome int

const (
	ollamaProbeFailed ollamaProbeOutcome = iota
	ollamaProbeSignedIn
	ollamaProbeNotSignedIn
)

// probeOllamaSignin sends one fixed synthetic Chat Completions request
// ("Reply with OK") to the chosen cloud model through the loopback daemon. It
// never carries repository content. HTTP 401 or 403 means the daemon is not
// signed in to Ollama Cloud.
//
// An HTTP 200 is accepted only when the answer names the requested cloud
// selector (or the remote name Ollama reports for it), exactly as dispatch
// binds the model of a real response. A 200 from a different model does not
// prove the cloud path is live.
func probeOllamaSignin(ctx context.Context, endpoint, model string) (ollamaProbeOutcome, string) {
	if !runtimeconfig.ValidOllamaSigninEndpoint(endpoint) || !runtimeconfig.OllamaCloudModelID(model) {
		return ollamaProbeFailed, "not an Ollama sign-in address and cloud model"
	}
	body, _ := json.Marshal(map[string]any{"model": model, "messages": []any{map[string]string{"role": "user", "content": ollamaSigninProbePrompt}}, "max_tokens": 16, "stream": false})
	ctx, cancel := context.WithTimeout(ctx, ollamaProbeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return ollamaProbeFailed, "the request could not be built"
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := ollamaLoopbackClient(ollamaProbeTimeout).Do(request)
	if err != nil {
		return ollamaProbeFailed, "no answer from the local Ollama daemon"
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode == http.StatusOK:
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, ollamaProbeMaxBytes))
		if readErr != nil {
			return ollamaProbeFailed, "the answer could not be read"
		}
		reported, ok := ollamaProbeReportedModel(payload)
		if !ok {
			return ollamaProbeFailed, "the answer did not name a model"
		}
		if !openai.OllamaRelayedModelMatches(model, reported) {
			return ollamaProbeFailed, "the answer came from " + reported + " rather than " + model
		}
		return ollamaProbeSignedIn, ""
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return ollamaProbeNotSignedIn, fmt.Sprintf("HTTP %d", response.StatusCode)
	}
	return ollamaProbeFailed, fmt.Sprintf("HTTP %d", response.StatusCode)
}

// ollamaProbeReportedModel reads the model name from a Chat Completions
// answer. It accepts only a bounded, valid JSON object with a string model
// field; anything else is not a usable answer.
func ollamaProbeReportedModel(payload []byte) (string, bool) {
	if len(payload) == 0 || len(payload) > ollamaProbeMaxBytes || !utf8.Valid(payload) {
		return "", false
	}
	var wire struct {
		Model string `json:"model"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if decoder.Decode(&wire) != nil {
		return "", false
	}
	if wire.Model == "" || len(wire.Model) > 1024 || strings.ContainsAny(wire.Model, " 	\r\n/") {
		return "", false
	}
	return wire.Model, true
}

// runOllamaSigninChild runs the fixed command `ollama signin`, resolved from
// PATH, with this terminal attached so the operator can follow its sign-in
// link. Open Trestle passes no other argument and reads none of its output.
func runOllamaSigninChild(ctx context.Context) error {
	command := exec.CommandContext(ctx, "ollama", "signin")
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}

// checkOllamaSigninBootstrap re-reads the daemon's model list for `setup
// bootstrap check`: a daemon that is not running is pending; a model it no
// longer relays to Ollama Cloud is refused.
func checkOllamaSigninBootstrap(ctx context.Context, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy, pending, refused func(key, message string)) {
	endpoint := ""
	for _, connection := range policy.Connections() {
		if connection.RequestProfile() != runtimeconfig.OllamaSigninChatProfile || endpoint != "" && connection.Endpoint() != endpoint {
			refused("ollama_cloud_models_listed", "the saved configuration does not name one local Ollama sign-in address")
			return
		}
		endpoint = connection.Endpoint()
	}
	models := []string{}
	for _, candidate := range inventory.Candidates() {
		models = append(models, candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().ModelID())
	}
	if _, err := checkOllamaSigninModels(ctx, endpoint, models...); err != nil {
		if errors.Is(err, errOllamaTagsUnavailable) {
			pending("ollama_cloud_models_listed", err.Error())
			return
		}
		refused("ollama_cloud_models_listed", err.Error())
	}
}
