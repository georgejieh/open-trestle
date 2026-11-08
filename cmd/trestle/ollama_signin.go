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
func readOllamaDaemonTags(ctx context.Context, endpoint string) ([]ollamaTag, error) {
	origin, err := ollamaDaemonOrigin(endpoint)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, ollamaTagsTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/api/tags", nil)
	if err != nil {
		return nil, errOllamaTagsUnavailable
	}
	request.Header.Set("Accept", "application/json")
	response, err := ollamaLoopbackClient(ollamaTagsTimeout).Do(request)
	if err != nil {
		return nil, errOllamaTagsUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, ollamaTagsMaxBytes+1))
	if err != nil || response.StatusCode != http.StatusOK || len(body) > ollamaTagsMaxBytes {
		return nil, errOllamaTagsUnavailable
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
		return nil, errOllamaTagsUnavailable
	}
	tags := make([]ollamaTag, 0, len(*wire.Models))
	for _, entry := range *wire.Models {
		tags = append(tags, ollamaTag{Name: entry.Name, Model: entry.Model, RemoteModel: entry.RemoteModel, RemoteHost: entry.RemoteHost, ContextLength: entry.Details.ContextLength})
	}
	return tags, nil
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

// ollamaCloudNameSuffix is the name-only fallback used when no tags list is available.
func ollamaCloudNameSuffix(model string) bool {
	return strings.HasSuffix(model, ":cloud") || strings.HasSuffix(model, "-cloud")
}

// ollamaLocalModelError refuses, for the local route, a model the daemon at
// endpoint relays to Ollama Cloud. Without a readable tags list it refuses
// names with the Ollama cloud suffix. Other servers and models pass.
func ollamaLocalModelError(ctx context.Context, endpoint, model string) error {
	tags, err := ollamaReadTags(ctx, endpoint)
	if err == nil {
		if tag, found := ollamaFindTag(tags, model); found {
			if tag.RemoteHost != "" {
				return fmt.Errorf("%s: %s", model, ollamaCloudLocalRefusal)
			}
			return nil
		}
	}
	if ollamaCloudNameSuffix(model) {
		return fmt.Errorf("%s: %s", model, ollamaCloudLocalRefusal)
	}
	return nil
}

// checkOllamaSigninModels requires the daemon at endpoint to list every model
// with the Ollama cloud suffix and remote_host https://ollama.com. An
// unreachable daemon is reported as errOllamaTagsUnavailable.
func checkOllamaSigninModels(ctx context.Context, endpoint string, models ...string) ([]ollamaTag, error) {
	tags, err := ollamaReadTags(ctx, endpoint)
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
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, ollamaProbeMaxBytes))
	switch {
	case response.StatusCode == http.StatusOK:
		return ollamaProbeSignedIn, ""
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return ollamaProbeNotSignedIn, fmt.Sprintf("HTTP %d", response.StatusCode)
	}
	return ollamaProbeFailed, fmt.Sprintf("HTTP %d", response.StatusCode)
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
